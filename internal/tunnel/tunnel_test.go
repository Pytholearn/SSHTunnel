package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	tproxy "sshtunnel/internal/proxy"
)

func waitState(t *testing.T, tn *Tunnel, want State, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s, _ := tn.State(); s == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s, _ := tn.State()
	t.Fatalf("state = %s, want %s", s, want)
}

func fetchVia(t *testing.T, client *http.Client, u string) string {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestEndToEndAndReconnect(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello "+r.URL.Path)
	}))
	defer web.Close()

	srv := newTestServer(t, "127.0.0.1:0", nil)
	addr := srv.addr

	var learned atomic.Value
	pol := HostKeyPolicy{Learn: func(k string) { learned.Store(k) }}
	tn := New(Options{
		Addr: addr, User: "tester", Password: "secret",
		HostKeyCallback:   pol.Callback(),
		KeepaliveInterval: 200 * time.Millisecond,
		KeepaliveTimeout:  200 * time.Millisecond,
		Backoff:           []time.Duration{100 * time.Millisecond},
	})
	tn.Start()
	defer tn.Stop()
	waitState(t, tn, StateConnected, 5*time.Second)
	if learned.Load() == nil {
		t.Fatal("host key not learned (TOFU)")
	}

	ps := &tproxy.Server{Dial: tn.Dial}
	if err := ps.ListenSOCKS("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := ps.ListenHTTP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	socksAddr := ps.Addrs()[0]
	httpAddr := ps.Addrs()[1]

	d, _ := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	socksClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return d.(proxy.ContextDialer).DialContext(ctx, n, a) },
	}, Timeout: 5 * time.Second}
	pu, _ := url.Parse("http://" + httpAddr)
	httpClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}

	if got := fetchVia(t, socksClient, web.URL+"/socks"); got != "hello /socks" {
		t.Fatalf("socks got %q", got)
	}
	if got := fetchVia(t, httpClient, web.URL+"/http"); got != "hello /http" {
		t.Fatalf("http got %q", got)
	}
	// HTTPS via CONNECT.
	tlsWeb := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tls ok") }))
	defer tlsWeb.Close()
	tr := tlsWeb.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(pu)
	if got := fetchVia(t, &http.Client{Transport: tr, Timeout: 5 * time.Second}, tlsWeb.URL); got != "tls ok" {
		t.Fatalf("connect got %q", got)
	}
	up, down, _ := tn.Stats()
	if up == 0 || down == 0 {
		t.Errorf("stats up=%d down=%d", up, down)
	}

	// Server restart -> auto-reconnect.
	srv.stop()
	waitState(t, tn, StateReconnecting, 5*time.Second)
	srv2 := newTestServer(t, addr, srv.signer)
	defer srv2.stop()
	waitState(t, tn, StateConnected, 10*time.Second)
	socksClient.CloseIdleConnections()
	if got := fetchVia(t, socksClient, web.URL+"/again"); got != "hello /again" {
		t.Fatalf("after reconnect got %q", got)
	}
	if srv.sessionsRequested+srv2.sessionsRequested != 0 {
		t.Fatal("client requested a session channel")
	}
}

func TestHostKeyMismatchRejected(t *testing.T) {
	srv := newTestServer(t, "127.0.0.1:0", nil)
	defer srv.stop()
	other := newTestServer(t, "127.0.0.1:0", nil)
	other.stop()
	asked := false
	pol := HostKeyPolicy{
		Known:   KeyLine(other.signer.PublicKey()),
		Confirm: func(string, string, string) bool { asked = true; return false },
	}
	tn := New(Options{Addr: srv.addr, User: "tester", Password: "secret", HostKeyCallback: pol.Callback()})
	tn.Start()
	defer tn.Stop()
	waitState(t, tn, StateError, 5*time.Second)
	if !asked {
		t.Fatal("user was not asked")
	}
}

func TestPinnedHostKey(t *testing.T) {
	srv := newTestServer(t, "127.0.0.1:0", nil)
	defer srv.stop()
	pol := HostKeyPolicy{Pinned: KeyLine(srv.signer.PublicKey())}
	d, err := TestLatency(context.Background(), Options{Addr: srv.addr, User: "tester", Password: "secret",
		HostKeyCallback: pol.Callback(), HostKeyAlgorithms: pol.Algorithms()})
	if err != nil || d <= 0 {
		t.Fatalf("latency %v %v", d, err)
	}
}

func TestWrongPasswordIsFatal(t *testing.T) {
	srv := newTestServer(t, "127.0.0.1:0", nil)
	defer srv.stop()
	tn := New(Options{Addr: srv.addr, User: "tester", Password: "nope"})
	tn.Start()
	defer tn.Stop()
	waitState(t, tn, StateError, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := tn.Dial(ctx, "tcp", "127.0.0.1:1"); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial err = %v", err)
	}
}
