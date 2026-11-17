package udpgw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEncodeKnownBytes(t *testing.T) {
	// Captured layout: len=11 LE | flags REBIND|DNS | conid 0x0102 LE | 8.8.8.8 | port 53 BE | "ab"
	got := AppendPacket(nil, FlagRebind|FlagDNS, 0x0102, netip.MustParseAddrPort("8.8.8.8:53"), []byte("ab"))
	want, _ := hex.DecodeString("0b00" + "06" + "0201" + "08080808" + "0035" + "6162")
	if !bytes.Equal(got, want) {
		t.Fatalf("ipv4:\n got %x\nwant %x", got, want)
	}
	if ka := KeepalivePacket(); !bytes.Equal(ka, []byte{3, 0, 1, 0, 0}) {
		t.Fatalf("keepalive %x", ka)
	}
	// IPv6 sets flag 0x08 and uses 16-byte address.
	got = AppendPacket(nil, 0, 7, netip.MustParseAddrPort("[2001:db8::1]:443"), []byte{0xff})
	want, _ = hex.DecodeString("1600" + "08" + "0700" + "20010db8000000000000000000000001" + "01bb" + "ff")
	if !bytes.Equal(got, want) {
		t.Fatalf("ipv6:\n got %x\nwant %x", got, want)
	}
	// IPv4-mapped IPv6 is sent as IPv4.
	got = AppendPacket(nil, 0, 0, netip.MustParseAddrPort("[::ffff:1.2.3.4]:80"), nil)
	if got[2]&FlagIPv6 != 0 || len(got) != 2+3+6 {
		t.Fatalf("mapped: %x", got)
	}
}

func TestParseRoundTrip(t *testing.T) {
	for _, a := range []string{"1.2.3.4:5", "[2001:db8::2]:65535"} {
		pkt := AppendPacket(nil, FlagDNS, 0xbeef, netip.MustParseAddrPort(a), []byte("payload"))
		p, _, err := ReadPacket(bytes.NewReader(pkt), nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.ConID != 0xbeef || p.Addr.String() != a || string(p.Payload) != "payload" || p.Flags&FlagDNS == 0 {
			t.Fatalf("%s: %+v", a, p)
		}
	}
	if _, err := ParseBody([]byte{0, 1}); err == nil {
		t.Fatal("short header accepted")
	}
	if _, err := ParseBody([]byte{0, 1, 0, 1, 2}); err == nil {
		t.Fatal("short address accepted")
	}
}

// fakeServer behaves like badvpn-udpgw: replies on the same conid with the
// remote address, upper-casing the payload.
type fakeServer struct {
	mu      sync.Mutex
	flags   []byte
	kaCount int
}

func (s *fakeServer) serve(c net.Conn) {
	br := bufio.NewReader(c)
	var buf []byte
	for {
		p, b, err := ReadPacket(br, buf)
		buf = b
		if err != nil {
			return
		}
		s.mu.Lock()
		if p.Flags&FlagKeepalive != 0 {
			s.kaCount++
			s.mu.Unlock()
			continue
		}
		s.flags = append(s.flags, p.Flags)
		s.mu.Unlock()
		reply := AppendPacket(nil, 0, p.ConID, p.Addr, []byte(strings.ToUpper(string(p.Payload))))
		c.Write(reply)
	}
}

func TestRelayEndToEnd(t *testing.T) {
	srv := &fakeServer{}
	var dialed string
	r := &Relay{
		Port:      7300,
		Keepalive: 50 * time.Millisecond,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed = addr
			a, b := net.Pipe()
			go srv.serve(b)
			return a, nil
		},
	}
	defer r.Close()
	got := make(chan string, 4)
	f1 := r.NewFlow(netip.MustParseAddrPort("9.9.9.9:1000"), func(from netip.AddrPort, p []byte) { got <- from.String() + " " + string(p) })
	f2 := r.NewFlow(netip.MustParseAddrPort("[2001:db8::5]:2000"), func(from netip.AddrPort, p []byte) { got <- from.String() + " " + string(p) })
	if err := f1.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := f2.Send([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if err := f1.Send([]byte("again")); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"9.9.9.9:1000 HELLO": true, "[2001:db8::5]:2000 WORLD": true, "9.9.9.9:1000 AGAIN": true}
	for i := 0; i < 3; i++ {
		select {
		case s := <-got:
			if !want[s] {
				t.Fatalf("unexpected reply %q", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	}
	if dialed != "127.0.0.1:7300" {
		t.Errorf("dialed %s", dialed)
	}
	time.Sleep(150 * time.Millisecond)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.flags) != 3 || srv.flags[0]&FlagRebind == 0 || srv.flags[1]&FlagRebind == 0 || srv.flags[2]&FlagRebind != 0 {
		t.Errorf("flags = %v (first packet per conid must carry REBIND)", srv.flags)
	}
	if srv.flags[1]&FlagIPv6 == 0 {
		t.Errorf("ipv6 flag missing")
	}
	if srv.kaCount == 0 {
		t.Errorf("no keepalives sent")
	}
}

func TestDNSFallbackOverTCP(t *testing.T) {
	// No udpgw: DNS must go over TCP (2-byte BE length framing) to dst:53.
	r := &Relay{Port: 0, Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		if addr != "1.1.1.1:53" {
			t.Errorf("dialed %s", addr)
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			var l [2]byte
			b.Read(l[:])
			q := make([]byte, int(l[0])<<8|int(l[1]))
			b.Read(q)
			b.Write(append([]byte{0, byte(len(q) + 1)}, append(q, '!')...))
		}()
		return a, nil
	}}
	got := make(chan string, 1)
	f := r.NewFlow(netip.MustParseAddrPort("1.1.1.1:53"), func(_ netip.AddrPort, p []byte) { got <- string(p) })
	if err := f.Send([]byte("query")); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "query!" {
			t.Fatalf("got %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	// Non-DNS without udpgw is an error.
	if err := r.NewFlow(netip.MustParseAddrPort("1.1.1.1:443"), nil).Send([]byte("x")); err == nil {
		t.Fatal("expected error")
	}
}

func TestConidEviction(t *testing.T) {
	r := &Relay{Port: 7300, MaxConns: 2, Dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go (&fakeServer{}).serve(b)
		return a, nil
	}}
	defer r.Close()
	var flows []*Flow
	for i := 0; i < 3; i++ {
		f := r.NewFlow(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(100+i)), func(netip.AddrPort, []byte) {})
		if err := f.Send([]byte("x")); err != nil {
			t.Fatal(err)
		}
		flows = append(flows, f)
	}
	if len(r.cli.slots) != 2 {
		t.Fatalf("slots = %d", len(r.cli.slots))
	}
	// The evicted (first) flow re-registers transparently.
	if err := flows[0].Send([]byte("y")); err != nil {
		t.Fatal(err)
	}
}
