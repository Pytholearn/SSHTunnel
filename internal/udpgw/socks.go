package udpgw

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"sshtunnel/internal/proxy"
)

// Resolver resolves a domain name (through the tunnel) for UDP targets given
// as names, since udpgw only accepts IP addresses.
type Resolver func(ctx context.Context, host string) (netip.Addr, error)

// TunnelResolver returns a Resolver that sends DNS over TCP through dial to
// the given server (e.g. "8.8.8.8:53"), so no query leaks to the local network.
func TunnelResolver(dial DialFunc, server string) Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, "tcp", server) // stream conn => TCP DNS framing
		},
	}
	return func(ctx context.Context, host string) (netip.Addr, error) {
		ips, err := r.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			ips, err = r.LookupNetIP(ctx, "ip", host)
		}
		if err != nil {
			return netip.Addr{}, err
		}
		if len(ips) == 0 {
			return netip.Addr{}, &net.DNSError{Err: "no address", Name: host}
		}
		return ips[0], nil
	}
}

// ServeSOCKS relays a SOCKS5 UDP ASSOCIATE session on pc until ctx ends.
func (r *Relay) ServeSOCKS(ctx context.Context, pc net.PacketConn, resolve Resolver) {
	type entry struct {
		flow *Flow
		used time.Time
	}
	var (
		mu     sync.Mutex
		flows  = map[string]*entry{}
		client net.Addr
	)
	defer func() {
		mu.Lock()
		for _, e := range flows {
			e.flow.Close()
		}
		mu.Unlock()
	}()
	go func() { // idle sweeper
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				pc.Close()
				return
			case <-t.C:
				mu.Lock()
				for k, e := range flows {
					if time.Since(e.used) > 2*time.Minute {
						e.flow.Close()
						delete(flows, k)
					}
				}
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Only the first sender (the SOCKS client) may use this association.
		if client == nil {
			client = from
		} else if client.String() != from.String() {
			continue
		}
		pkt := buf[:n]
		if len(pkt) < 4 || pkt[2] != 0 { // fragmentation unsupported
			continue
		}
		rd := bytes.NewReader(pkt[3:])
		dst, err := proxy.ReadSOCKSAddr(rd)
		if err != nil {
			continue
		}
		payload := pkt[len(pkt)-rd.Len():]
		host, ps, _ := net.SplitHostPort(dst)
		port, _ := strconv.Atoi(ps)
		ip, err := netip.ParseAddr(host)
		if err != nil {
			if resolve == nil {
				continue
			}
			rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			ip, err = resolve(rctx, host)
			cancel()
			if err != nil {
				r.logf("udp: resolve %s: %v", host, err)
				continue
			}
		}
		ap := netip.AddrPortFrom(ip.Unmap(), uint16(port))
		mu.Lock()
		e := flows[ap.String()]
		if e == nil {
			e = &entry{flow: r.NewFlow(ap, func(src netip.AddrPort, p []byte) {
				hdr, err := proxy.AppendSOCKSAddr([]byte{0, 0, 0}, src.String())
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(append(hdr, p...), client)
			})}
			flows[ap.String()] = e
		}
		e.used = time.Now()
		mu.Unlock()
		if err := e.flow.Send(append([]byte(nil), payload...)); err != nil {
			r.logf("udp %s: %v", ap, err)
		}
	}
}
