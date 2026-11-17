package udpgw

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"sshtunnel/internal/proxy"
)

func TestSOCKSUDPAssociate(t *testing.T) {
	r := &Relay{Port: 7300, Dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go (&fakeServer{}).serve(b)
		return a, nil
	}}
	defer r.Close()
	resolve := func(_ context.Context, host string) (netip.Addr, error) {
		return netip.MustParseAddr("5.6.7.8"), nil
	}
	ps := &proxy.Server{UDP: func(ctx context.Context, pc net.PacketConn) { r.ServeSOCKS(ctx, pc, resolve) }}
	if err := ps.ListenSOCKS("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	c, err := net.Dial("tcp", ps.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	var m [2]byte
	io.ReadFull(c, m[:])
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) // UDP ASSOCIATE 0.0.0.0:0
	var hdr [3]byte
	io.ReadFull(c, hdr[:])
	if hdr[1] != 0 {
		t.Fatalf("associate rep=%d", hdr[1])
	}
	bind, err := proxy.ReadSOCKSAddr(c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := net.Dial("udp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	send := func(dst string, data string) {
		b, _ := proxy.AppendSOCKSAddr([]byte{0, 0, 0}, dst)
		u.Write(append(b, data...))
	}
	recv := func() (string, string) {
		u.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		n, err := u.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		rd := bytes.NewReader(buf[3:n])
		a, _ := proxy.ReadSOCKSAddr(rd)
		return a, string(buf[n-rd.Len() : n])
	}
	send("1.2.3.4:9000", "ping")
	if a, d := recv(); a != "1.2.3.4:9000" || d != "PING" {
		t.Fatalf("got %s %q", a, d)
	}
	send("example.com:53", "q") // domain -> resolved through tunnel resolver
	if a, d := recv(); a != "5.6.7.8:53" || d != "Q" {
		t.Fatalf("got %s %q", a, d)
	}
}
