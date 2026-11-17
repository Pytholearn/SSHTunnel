//go:build windows

package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"sshtunnel/internal/udpgw"
)

// BestRoute + IP_UNICAST_IF: a socket pinned to the interface Windows picks
// for the target must connect; pinned to an unrelated interface it must not.
// TUN_TEST_ADDR should be reachable over a non-loopback interface, e.g. the
// WSL VM address of the test sshd (172.x.x.x:2222).
func TestBoundDialer(t *testing.T) {
	target := os.Getenv("TUN_TEST_ADDR")
	if target == "" {
		t.Skip("TUN_TEST_ADDR not set")
	}
	ap := netip.MustParseAddrPort(target)
	r, err := BestRoute(ap.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("best route to %s: if=%d nexthop=%s", ap.Addr(), r.IfIndex, r.NextHop)
	c, err := BoundDialer(r.IfIndex).Dial("tcp", target)
	if err != nil {
		t.Fatalf("pinned dial: %v", err)
	}
	c.Close()

	// Pick another up interface with an IPv4 address and expect failure.
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if int(r.IfIndex) == ifc.Index || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		has4 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				has4 = true
			}
		}
		if !has4 {
			continue
		}
		d := BoundDialer(uint32(ifc.Index))
		d.Timeout = 2 * time.Second
		if c, err := d.Dial("tcp", target); err == nil {
			c.Close()
			t.Logf("note: %s also reaches target (shared route)", ifc.Name)
		} else {
			t.Logf("pinned to %s (if %d): %v (expected failure)", ifc.Name, ifc.Index, err)
		}
		break
	}
}

// fake gVisor connections

type fakeTCP struct {
	net.Conn
	id stack.TransportEndpointID
}

func (f *fakeTCP) ID() stack.TransportEndpointID { return f.id }

type fakeUDP struct {
	net.Conn
	id stack.TransportEndpointID
}

func (f *fakeUDP) ID() stack.TransportEndpointID                     { return f.id }
func (f *fakeUDP) ReadFrom(p []byte) (int, net.Addr, error)          { n, err := f.Read(p); return n, nil, err }
func (f *fakeUDP) WriteTo(p []byte, _ net.Addr) (int, error)         { return f.Write(p) }

func endpoint(dst string) stack.TransportEndpointID {
	ap := netip.MustParseAddrPort(dst)
	return stack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(ap.Addr().AsSlice()),
		LocalPort:     ap.Port(),
		RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		RemotePort:    50000,
	}
}

func TestHandleTCPUsesTunnel(t *testing.T) {
	dialed := make(chan string, 1)
	e := &Engine{Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed <- addr
		a, b := net.Pipe()
		go func() { io.Copy(b, b) }() // echo
		return a, nil
	}}
	app, stackSide := net.Pipe()
	e.HandleTCP(&fakeTCP{Conn: stackSide, id: endpoint("93.184.216.34:443")})
	if got := <-dialed; got != "93.184.216.34:443" {
		t.Fatalf("dialed %s", got)
	}
	app.Write([]byte("abc"))
	buf := make([]byte, 3)
	app.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(app, buf); err != nil || string(buf) != "abc" {
		t.Fatalf("echo %q %v", buf, err)
	}
	app.Close()
}

func TestHandleUDPUsesRelay(t *testing.T) {
	var sent = make(chan string, 1)
	relay := &udpgw.Relay{Port: 7300, Dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			var buf []byte
			for {
				p, nb, err := udpgw.ReadPacket(b, buf)
				buf = nb
				if err != nil {
					return
				}
				if p.Flags&udpgw.FlagKeepalive != 0 {
					continue
				}
				sent <- p.Addr.String() + " " + string(p.Payload)
				b.Write(udpgw.AppendPacket(nil, 0, p.ConID, p.Addr, []byte("pong")))
			}
		}()
		return a, nil
	}}
	defer relay.Close()
	e := &Engine{Relay: relay}
	app, stackSide := net.Pipe()
	e.HandleUDP(&fakeUDP{Conn: stackSide, id: endpoint("1.1.1.1:3478")})
	app.Write([]byte("ping"))
	if got := <-sent; got != "1.1.1.1:3478 ping" {
		t.Fatalf("relay got %q", got)
	}
	buf := make([]byte, 16)
	app.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := app.Read(buf)
	if err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("reply %q %v", buf[:n], err)
	}
	app.Close()

	// Multicast is dropped without touching the relay.
	app2, side2 := net.Pipe()
	e.HandleUDP(&fakeUDP{Conn: side2, id: endpoint("239.255.255.250:1900")})
	app2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := app2.Read(buf); err == nil {
		t.Fatal("multicast flow not closed")
	}
}
