//go:build integration

// Integration test against a real OpenSSH server (see README: WSL/Docker setup).
//
//	SSHT_ADDR=127.0.0.1:2222 SSHT_USER=tunneltest SSHT_PASS=... SSHT_HK="ssh-ed25519 AAAA..." \
//	SSHT_RESTART="wsl -d Ubuntu-20.04 -u root -- ..." go test -tags integration -v ./integration
package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	xproxy "golang.org/x/net/proxy"

	"sshtunnel/internal/links"
	"sshtunnel/internal/proxy"
	"sshtunnel/internal/sysproxy"
	"sshtunnel/internal/tunnel"
	"sshtunnel/internal/udpgw"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func waitState(t *testing.T, tn *tunnel.Tunnel, want tunnel.State, d time.Duration) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if s, _ := tn.State(); s == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s, _ := tn.State()
	t.Fatalf("state %s, want %s", s, want)
}

func get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func shell(t *testing.T, cmdline string) {
	t.Helper()
	if cmdline == "" {
		return
	}
	out, err := exec.Command("cmd", "/C", cmdline).CombinedOutput()
	t.Logf("$ %s\n%s", cmdline, out)
	if err != nil {
		t.Logf("(exit: %v)", err)
	}
}

func TestOpenSSH(t *testing.T) {
	addr := env("SSHT_ADDR", "127.0.0.1:2222")
	user, pass := env("SSHT_USER", "tunneltest"), os.Getenv("SSHT_PASS")
	hk := os.Getenv("SSHT_HK")
	target := env("SSHT_TARGET", "http://127.0.0.1:8088/") // URL reachable from the server side
	if pass == "" {
		t.Skip("SSHT_PASS not set")
	}
	host, port, _ := net.SplitHostPort(addr)

	// Build a real link and import it the way the app does.
	link := fmt.Sprintf("ssh://%s:%s@%s:%s/?hk=%s#%s", url.PathEscape(user), url.QueryEscape(pass), host, port,
		url.QueryEscape(hk), url.PathEscape("integration | test"))
	p, err := links.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if p.PinnedHostKey != hk || p.Password != pass {
		t.Fatalf("link round trip failed: %+v", p)
	}

	pol := tunnel.HostKeyPolicy{Pinned: p.PinnedHostKey}
	lat, err := tunnel.TestLatency(context.Background(), tunnel.Options{Addr: p.Address(), User: p.Username, Password: p.Password,
		HostKeyCallback: pol.Callback(), HostKeyAlgorithms: pol.Algorithms()})
	if err != nil {
		t.Fatalf("latency test: %v", err)
	}
	t.Logf("latency test: %v", lat)

	tn := tunnel.New(tunnel.Options{
		Addr: p.Address(), User: p.Username, Password: p.Password,
		HostKeyCallback: pol.Callback(), HostKeyAlgorithms: pol.Algorithms(),
		KeepaliveInterval: time.Second, KeepaliveTimeout: 2 * time.Second,
		Logf: func(f string, a ...any) { t.Logf("tunnel: "+f, a...) },
	})
	tn.Start()
	defer tn.Stop()
	waitState(t, tn, tunnel.StateConnected, 15*time.Second)

	px := &proxy.Server{Dial: tn.Dial, Logf: func(f string, a ...any) { t.Logf("proxy: "+f, a...) }}
	if err := px.ListenSOCKS("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := px.ListenHTTP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	socksAddr, httpAddr := px.Addrs()[0], px.Addrs()[1]

	d, _ := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	socks := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: d.(xproxy.ContextDialer).DialContext}}
	pu, _ := url.Parse("http://" + httpAddr)
	hp := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	if got := get(t, socks, target); got == "" {
		t.Fatal("empty body via SOCKS")
	} else {
		t.Logf("via SOCKS5: %q", got)
	}
	if got := get(t, hp, target); got == "" {
		t.Fatal("empty body via HTTP proxy")
	} else {
		t.Logf("via HTTP proxy: %q", got)
	}

	// Keepalives against real OpenSSH (it answers keepalive@openssh.com with failure).
	time.Sleep(2500 * time.Millisecond)
	if s, _ := tn.State(); s != tunnel.StateConnected {
		t.Fatalf("dropped after keepalives: %s", s)
	}
	_, _, ms := tn.Stats()
	t.Logf("keepalive RTT: %d ms", ms)

	// Optional: the public IP seen through the tunnel (needs internet on the server).
	if out, err := exec.Command("curl.exe", "-s", "-m", "15", "-x", "socks5h://"+socksAddr, "https://ifconfig.me").Output(); err == nil {
		t.Logf("curl -x socks5h://%s https://ifconfig.me -> %s", socksAddr, out)
	} else {
		t.Logf("curl ifconfig.me through tunnel failed (server may have no internet): %v", err)
	}

	// Server restart -> auto-reconnect.
	if rs := os.Getenv("SSHT_STOP"); rs != "" {
		shell(t, rs)
		waitState(t, tn, tunnel.StateReconnecting, 60*time.Second)
		shell(t, os.Getenv("SSHT_START"))
		waitState(t, tn, tunnel.StateConnected, 60*time.Second)
		socks.CloseIdleConnections()
		if got := get(t, socks, target); got == "" {
			t.Fatal("empty body after reconnect")
		}
		t.Log("reconnected after server restart and fetched again")
	}
}

// TestSystemProxyRestore changes the real WinINet proxy for a moment and
// verifies it is restored byte-for-byte.
func TestSystemProxyRestore(t *testing.T) {
	if os.Getenv("SSHT_SYSPROXY") != "1" {
		t.Skip("set SSHT_SYSPROXY=1 to touch the real system proxy")
	}
	before, err := sysproxy.Read()
	if err != nil {
		t.Fatal(err)
	}
	m := &sysproxy.Manager{BackupPath: t.TempDir() + "/backup.json"}
	if err := m.Enable("127.0.0.1:18809"); err != nil {
		t.Fatal(err)
	}
	mid, _ := sysproxy.Read()
	restored, rerr := m.Restore()
	after, _ := sysproxy.Read()
	if mid.ProxyEnable != 1 || mid.ProxyServer != "127.0.0.1:18809" || !strings.Contains(mid.ProxyOverride, "<local>") {
		t.Errorf("enable did not apply: %+v", mid)
	}
	if rerr != nil || !restored {
		t.Fatalf("restore: %v %v", restored, rerr)
	}
	if after != before {
		t.Fatalf("not restored:\nbefore %+v\nafter  %+v", before, after)
	}
	t.Logf("system proxy restored: %+v", after)

	// Crash recovery: a backup file left behind is restored by a new Manager.
	m1 := &sysproxy.Manager{BackupPath: t.TempDir() + "/crash.json"}
	if err := m1.Enable("127.0.0.1:18809"); err != nil {
		t.Fatal(err)
	}
	m2 := &sysproxy.Manager{BackupPath: m1.BackupPath} // "next start"
	if ok, err := m2.Restore(); err != nil || !ok {
		t.Fatalf("crash recovery: %v %v", ok, err)
	}
	if after2, _ := sysproxy.Read(); after2 != before {
		t.Fatalf("crash recovery mismatch: %+v", after2)
	}
}

// TestUDPGW sends UDP through a real badvpn-udpgw on the server
// (127.0.0.1:7300): an echo server and a DNS query with the DNS flag.
func TestUDPGW(t *testing.T) {
	addr := env("SSHT_ADDR", "127.0.0.1:2222")
	pass := os.Getenv("SSHT_PASS")
	echo := env("SSHT_UDP_ECHO", "127.0.0.1:9999")
	if pass == "" {
		t.Skip("SSHT_PASS not set")
	}
	tn := tunnel.New(tunnel.Options{Addr: addr, User: env("SSHT_USER", "tunneltest"), Password: pass})
	tn.Start()
	defer tn.Stop()
	waitState(t, tn, tunnel.StateConnected, 15*time.Second)

	relay := &udpgw.Relay{Dial: tn.Dial, Port: 7300, TransparentDNS: true,
		Logf: func(f string, a ...any) { t.Logf("udpgw: "+f, a...) }}
	defer relay.Close()

	// 1) plain UDP echo via the relay
	got := make(chan string, 1)
	f := relay.NewFlow(netip.MustParseAddrPort(echo), func(_ netip.AddrPort, p []byte) { got <- string(p) })
	if err := f.Send([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "echo:hi" {
			t.Fatalf("echo got %q", s)
		}
		t.Logf("udp echo through udpgw: %q", s)
	case <-time.After(5 * time.Second):
		t.Fatal("no udp echo reply")
	}

	// 2) DNS with the DNS flag (server uses its own resolver)
	q := dnsQuery(t, 0x4242, "example.com.")
	dnsGot := make(chan []byte, 1)
	df := relay.NewFlow(netip.MustParseAddrPort("8.8.8.8:53"), func(_ netip.AddrPort, p []byte) { dnsGot <- p })
	if err := df.Send(q); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-dnsGot:
		var m dnsmessage.Message
		if err := m.Unpack(p); err != nil || m.ID != 0x4242 {
			t.Fatalf("bad dns reply: %v id=%x", err, m.ID)
		}
		t.Logf("dns via udpgw: rcode=%v answers=%d", m.RCode, len(m.Answers))
	case <-time.After(8 * time.Second):
		t.Fatal("no dns reply")
	}

	// 3) SOCKS5 UDP ASSOCIATE end to end
	px := &proxy.Server{Dial: tn.Dial, UDP: func(ctx context.Context, pc net.PacketConn) { relay.ServeSOCKS(ctx, pc, nil) }}
	if err := px.ListenSOCKS("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	c, err := net.Dial("tcp", px.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	hdr := make([]byte, 3)
	io.ReadFull(c, hdr)
	bind, err := proxy.ReadSOCKSAddr(c)
	if err != nil || hdr[1] != 0 {
		t.Fatalf("associate: %v rep=%d", err, hdr[1])
	}
	u, _ := net.Dial("udp", bind)
	defer u.Close()
	pkt, _ := proxy.AppendSOCKSAddr([]byte{0, 0, 0}, echo)
	u.Write(append(pkt, "socks"...))
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(buf[:n]), "echo:socks") {
		t.Fatalf("socks udp got %q", buf[:n])
	}
	t.Log("SOCKS5 UDP ASSOCIATE through udpgw OK")
}

func dnsQuery(t *testing.T, id uint16, name string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
