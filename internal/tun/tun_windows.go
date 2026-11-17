//go:build windows

// Package tun captures all system traffic with a Wintun adapter and a gVisor
// user-space TCP/IP stack (from tun2socks), and hands every TCP connection
// to the SSH dialer and every UDP flow to udpgw.
package tun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	wtun "github.com/xjasonlyu/tun2socks/v2/core/device/tun"

	"sshtunnel/internal/proxy"
	"sshtunnel/internal/udpgw"
)

var (
	tunAddr4  = netip.MustParsePrefix("198.18.0.1/16")
	tunAddr6  = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
	tunDNS    = []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}
	split4    = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	split6    = []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
	iphlpapi  = windows.NewLazySystemDLL("iphlpapi.dll")
	pBestRoute = iphlpapi.NewProc("GetBestRoute2")
)

// Route is the physical path to a destination (found before TUN is up).
type Route struct {
	IfIndex uint32
	NextHop netip.Addr
	LUID    uint64
}

// BestRoute asks Windows which interface/gateway currently reaches dst.
func BestRoute(dst netip.Addr) (Route, error) {
	var d, src winipcfg.RawSockaddrInet
	if err := d.SetAddr(dst); err != nil {
		return Route{}, err
	}
	var row winipcfg.MibIPforwardRow2
	r, _, _ := pBestRoute.Call(0, 0, 0, uintptr(unsafe.Pointer(&d)), 0,
		uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&src)))
	if r != 0 {
		return Route{}, fmt.Errorf("GetBestRoute2: %w", syscall.Errno(r))
	}
	return Route{IfIndex: row.InterfaceIndex, NextHop: row.NextHop.Addr(), LUID: uint64(row.InterfaceLUID)}, nil
}

// BoundDialer returns a dialer whose sockets are pinned to the given
// interface (IP_UNICAST_IF), so they bypass the TUN default routes.
func BoundDialer(ifIndex uint32) *net.Dialer {
	return &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				h := windows.Handle(fd)
				if network == "tcp6" || network == "udp6" {
					serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, 31 /* IPV6_UNICAST_IF */, int(ifIndex))
				} else {
					// IP_UNICAST_IF takes the index in network byte order.
					var b [4]byte
					b[0], b[1], b[2], b[3] = byte(ifIndex>>24), byte(ifIndex>>16), byte(ifIndex>>8), byte(ifIndex)
					serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, 31 /* IP_UNICAST_IF */, int(*(*uint32)(unsafe.Pointer(&b[0]))))
				}
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
}

// Engine is a running TUN capture.
type Engine struct {
	Name   string
	MTU    uint32
	Dial   proxy.DialFunc // through the SSH tunnel
	Direct func(host string) bool
	Relay  *udpgw.Relay
	Logf   func(string, ...any)
	// StatePath stores host routes so a crash can be cleaned up on next start.
	StatePath string

	phys       Route
	dev        device.Device
	st         *stack.Stack
	hostRoutes []hostRoute
	mu         sync.Mutex
	closed     bool
	direct     *net.Dialer
}

type hostRoute struct {
	LUID    uint64 `json:"luid"`
	Prefix  string `json:"prefix"`
	NextHop string `json:"nextHop"`
}

func (e *Engine) logf(f string, a ...any) {
	if e.Logf != nil {
		e.Logf(f, a...)
	}
}

// Start creates the adapter, routes everything into it except serverIPs
// (which keep using the physical gateway), and starts the stack.
func (e *Engine) Start(serverIPs []netip.Addr, phys Route) (err error) {
	if e.Name == "" {
		e.Name = "SSHTunnel"
	}
	if e.MTU == 0 {
		e.MTU = 1500
	}
	e.phys = phys
	e.direct = BoundDialer(phys.IfIndex)
	defer func() {
		if err != nil {
			e.Stop()
		}
	}()

	// Host routes for the SSH server via the real gateway (avoid a loop).
	physLUID := winipcfg.LUID(phys.LUID)
	for _, ip := range serverIPs {
		if !ip.Is4() || !phys.NextHop.Is4() {
			continue
		}
		pfx := netip.PrefixFrom(ip, 32)
		if err := physLUID.AddRoute(pfx, phys.NextHop, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("host route %s: %w", pfx, err)
		}
		e.hostRoutes = append(e.hostRoutes, hostRoute{LUID: phys.LUID, Prefix: pfx.String(), NextHop: phys.NextHop.String()})
	}
	e.saveState()

	dev, err := wtun.Open(e.Name, e.MTU)
	if err != nil {
		return fmt.Errorf("wintun: %w", err)
	}
	e.dev = dev
	st, err := core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: e})
	if err != nil {
		return fmt.Errorf("stack: %w", err)
	}
	e.st = st

	luid, err := adapterLUID(e.Name)
	if err != nil {
		return err
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{tunAddr4}); err != nil {
		return fmt.Errorf("set address: %w", err)
	}
	ipv6 := luid.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{tunAddr6}) == nil
	for _, p := range split4 {
		if err := luid.AddRoute(p, netip.IPv4Unspecified(), 0); err != nil {
			return fmt.Errorf("route %s: %w", p, err)
		}
	}
	if ipv6 {
		for _, p := range split6 {
			_ = luid.AddRoute(p, netip.IPv6Unspecified(), 0)
		}
	}
	if err := luid.SetDNS(windows.AF_INET, tunDNS, nil); err != nil {
		e.logf("tun: set DNS: %v", err)
	}
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if row, err := luid.IPInterface(fam); err == nil {
			row.UseAutomaticMetric = false
			row.Metric = 0
			row.NLMTU = e.MTU
			_ = row.Set()
		}
	}
	e.logf("tun: %s up (%s), all traffic routed through the tunnel; server via %s if %d",
		e.Name, tunAddr4, phys.NextHop, phys.IfIndex)
	return nil
}

func adapterLUID(name string) (winipcfg.LUID, error) {
	var lastErr error
	for i := 0; i < 50; i++ {
		ifc, err := net.InterfaceByName(name)
		if err == nil {
			return winipcfg.LUIDFromIndex(uint32(ifc.Index))
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return 0, fmt.Errorf("adapter %q not found: %v", name, lastErr)
}

// Stop removes the adapter (its routes go with it) and the host routes.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.mu.Unlock()
	if e.st != nil {
		e.st.Close()
	}
	if e.dev != nil {
		e.dev.Close()
	}
	removeHostRoutes(e.hostRoutes)
	if e.StatePath != "" {
		_ = os.Remove(e.StatePath)
	}
	e.logf("tun: stopped")
}

func (e *Engine) saveState() {
	if e.StatePath == "" {
		return
	}
	b, _ := json.Marshal(e.hostRoutes)
	_ = os.WriteFile(e.StatePath, b, 0o600)
}

func removeHostRoutes(rs []hostRoute) {
	for _, r := range rs {
		p, err1 := netip.ParsePrefix(r.Prefix)
		nh, err2 := netip.ParseAddr(r.NextHop)
		if err1 == nil && err2 == nil {
			_ = winipcfg.LUID(r.LUID).DeleteRoute(p, nh)
		}
	}
}

// Recover removes host routes left by a crashed run (the adapter itself
// disappears with the process).
func Recover(statePath string) bool {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return false
	}
	var rs []hostRoute
	_ = json.Unmarshal(b, &rs)
	removeHostRoutes(rs)
	_ = os.Remove(statePath)
	return len(rs) > 0
}

// ---- adapter.TransportHandler ----

func addrPort(a []byte, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a)
	return netip.AddrPortFrom(ip.Unmap(), port)
}

func (e *Engine) HandleTCP(c adapter.TCPConn) {
	id := c.ID()
	dst := addrPort(id.LocalAddress.AsSlice(), id.LocalPort)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var (
			out net.Conn
			err error
		)
		if e.Direct != nil && e.Direct(dst.Addr().String()) {
			out, err = e.direct.DialContext(ctx, "tcp", dst.String())
		} else {
			out, err = e.Dial(ctx, "tcp", dst.String())
		}
		if err != nil {
			c.Close()
			return
		}
		proxy.Pipe(c, out)
	}()
}

func (e *Engine) HandleUDP(c adapter.UDPConn) {
	id := c.ID()
	dst := addrPort(id.LocalAddress.AsSlice(), id.LocalPort)
	if !dst.Addr().IsGlobalUnicast() || dst.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		c.Close() // broadcast / multicast / link-local stay local
		return
	}
	if e.Relay == nil {
		c.Close()
		return
	}
	go func() {
		defer c.Close()
		flow := e.Relay.NewFlow(dst, func(_ netip.AddrPort, p []byte) { _, _ = c.Write(p) })
		defer flow.Close()
		idle := 2 * time.Minute
		if dst.Port() == 53 {
			idle = 20 * time.Second
		}
		buf := make([]byte, 65535)
		for {
			_ = c.SetReadDeadline(time.Now().Add(idle))
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if err := flow.Send(append([]byte(nil), buf[:n]...)); err != nil {
				return
			}
		}
	}()
}
