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
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"sshtunnel/internal/links"
	"sshtunnel/internal/proxy"
	"sshtunnel/internal/sysproxy"
	"sshtunnel/internal/tunnel"
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
