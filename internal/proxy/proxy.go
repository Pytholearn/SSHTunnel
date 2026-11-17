// Package proxy implements local SOCKS5 and HTTP(S) proxies whose outgoing
// connections go through a Dial function (the SSH tunnel).
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DialFunc opens a TCP connection to addr ("host:port").
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// UDPHandler serves a SOCKS5 UDP ASSOCIATE session on pc (bound to the
// client's loopback). It returns when ctx ends.
type UDPHandler func(ctx context.Context, pc net.PacketConn)

// Server is a SOCKS5 + HTTP proxy front-end.
type Server struct {
	Dial DialFunc
	// Direct, if non-nil and returns true for host, the connection bypasses
	// the tunnel.
	Direct func(host string) bool
	UDP    UDPHandler
	Logf   func(format string, args ...any)

	DialTimeout time.Duration

	mu        sync.Mutex
	listeners []net.Listener
	conns     map[net.Conn]struct{}
	transport *http.Transport
}

func (s *Server) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

func (s *Server) dial(ctx context.Context, addr string) (net.Conn, error) {
	to := s.DialTimeout
	if to == 0 {
		to = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	host, _, _ := net.SplitHostPort(addr)
	if s.Direct != nil && s.Direct(host) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return s.Dial(ctx, "tcp", addr)
}

// ListenSOCKS starts the SOCKS5 server on addr.
func (s *Server) ListenSOCKS(addr string) error { return s.listen(addr, s.serveSOCKS) }

// ListenHTTP starts the HTTP proxy on addr.
func (s *Server) ListenHTTP(addr string) error { return s.listen(addr, s.serveHTTP) }

func (s *Server) listen(addr string, h func(net.Conn)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.track(c, true)
			go func() {
				defer s.track(c, false)
				defer c.Close()
				h(c)
			}()
		}
	}()
	return nil
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		return
	}
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// Addrs returns listener addresses in the order they were started.
func (s *Server) Addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, l := range s.listeners {
		out = append(out, l.Addr().String())
	}
	return out
}

// Close stops all listeners and closes client connections.
func (s *Server) Close() {
	s.mu.Lock()
	lns, conns := s.listeners, s.conns
	s.listeners, s.conns = nil, nil
	tr := s.transport
	s.mu.Unlock()
	for _, l := range lns {
		l.Close()
	}
	for c := range conns {
		c.Close()
	}
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

// Pipe copies both directions with half-close and returns when both end.
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// ---- SOCKS5 ----

const (
	socksVer      = 5
	cmdConnect    = 1
	cmdUDP        = 3
	atypIPv4      = 1
	atypDomain    = 3
	atypIPv6      = 4
	repOK         = 0
	repFail       = 1
	repNetUnreach = 3
	repHostUnr    = 4
	repCmdUnsup   = 7
)

func (s *Server) serveSOCKS(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != socksVer {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// Only "no auth" (0) is offered; listener is loopback-only.
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
		}
	}
	if !ok {
		_, _ = c.Write([]byte{socksVer, 0xff})
		return
	}
	if _, err := c.Write([]byte{socksVer, 0}); err != nil {
		return
	}
	var req [3]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != socksVer {
		return
	}
	addr, err := ReadSOCKSAddr(br)
	if err != nil {
		return
	}
	switch req[1] {
	case cmdConnect:
		target, err := s.dial(context.Background(), addr)
		if err != nil {
			s.logf("socks: %s: %v", addr, err)
			_, _ = c.Write(socksReply(repFail, nil))
			return
		}
		if _, err := c.Write(socksReply(repOK, nil)); err != nil {
			target.Close()
			return
		}
		_ = c.SetDeadline(time.Time{})
		Pipe(&bufConn{Conn: c, r: br}, target)
	case cmdUDP:
		if s.UDP == nil {
			_, _ = c.Write(socksReply(repCmdUnsup, nil))
			return
		}
		host, _, _ := net.SplitHostPort(c.LocalAddr().String())
		pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			_, _ = c.Write(socksReply(repFail, nil))
			return
		}
		defer pc.Close()
		if _, err := c.Write(socksReply(repOK, pc.LocalAddr().(*net.UDPAddr))); err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { // the association lives as long as the TCP control conn
			_, _ = io.Copy(io.Discard, br)
			cancel()
			pc.Close()
		}()
		s.UDP(ctx, pc)
		cancel()
	default:
		_, _ = c.Write(socksReply(repCmdUnsup, nil))
	}
}

// ReadSOCKSAddr reads ATYP + address + port and returns "host:port".
func ReadSOCKSAddr(r io.Reader) (string, error) {
	var at [1]byte
	if _, err := io.ReadFull(r, at[:]); err != nil {
		return "", err
	}
	var host string
	switch at[0] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", fmt.Errorf("bad atyp %d", at[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// AppendSOCKSAddr appends ATYP+addr+port for host:port.
func AppendSOCKSAddr(b []byte, addr string) ([]byte, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(append(b, atypIPv4), v4...)
		} else {
			b = append(append(b, atypIPv6), ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("host too long")
		}
		b = append(append(b, atypDomain, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func socksReply(rep byte, bind *net.UDPAddr) []byte {
	b := []byte{socksVer, rep, 0}
	if bind == nil {
		return append(b, atypIPv4, 0, 0, 0, 0, 0, 0)
	}
	b, _ = AppendSOCKSAddr(b, bind.String())
	return b
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// ---- HTTP ----

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (s *Server) httpTransport() *http.Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transport == nil {
		s.transport = &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return s.dial(ctx, addr)
			},
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			DisableCompression:    true,
		}
	}
	return s.transport
}

func (s *Server) serveHTTP(c net.Conn) {
	br := bufio.NewReader(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		if req.Method == http.MethodConnect {
			addr := req.Host
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = net.JoinHostPort(addr, "443")
			}
			target, err := s.dial(req.Context(), addr)
			if err != nil {
				s.logf("http CONNECT %s: %v", addr, err)
				_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
				return
			}
			if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				target.Close()
				return
			}
			Pipe(&bufConn{Conn: c, r: br}, target)
			return
		}
		if req.URL.Host == "" {
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
		closeAfter := req.Close || strings.EqualFold(req.Header.Get("Proxy-Connection"), "close")
		for _, h := range hopHeaders {
			req.Header.Del(h)
		}
		req.RequestURI = ""
		resp, err := s.httpTransport().RoundTrip(req)
		if err != nil {
			s.logf("http %s %s: %v", req.Method, req.URL.Host, err)
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		for _, h := range hopHeaders {
			if h != "Transfer-Encoding" {
				resp.Header.Del(h)
			}
		}
		if closeAfter {
			resp.Close = true
		}
		err = resp.Write(c)
		resp.Body.Close()
		if err != nil || closeAfter || resp.Close {
			return
		}
	}
}
