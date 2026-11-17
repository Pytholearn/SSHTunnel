package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"sshtunnel/internal/config"
	"sshtunnel/internal/proxy"
	"sshtunnel/internal/subs"
	"sshtunnel/internal/tun"
	"sshtunnel/internal/tunnel"
	"sshtunnel/internal/udpgw"
)

//go:embed assets/wintun/wintun.dll
var wintunDLL []byte

// sessionExtras holds per-connection Phase 2 components.
type sessionExtras struct {
	relay  *udpgw.Relay
	engine *tun.Engine
}

func (e sessionExtras) tunActive() bool { return e.engine != nil }
func (e sessionExtras) udpActive() bool { return e.relay != nil && e.relay.Active() }

func (e sessionExtras) stop(logf func(string, ...any)) {
	if e.engine != nil {
		e.engine.Stop()
	}
	if e.relay != nil {
		e.relay.Close()
	}
}

var physMu sync.Mutex
var physRoute *tun.Route // set while TUN is active

// physicalDialer returns a dial function pinned to the physical interface
// while TUN mode is active (nil otherwise).
func physicalDialer() func(context.Context, string) (net.Conn, error) {
	physMu.Lock()
	r := physRoute
	physMu.Unlock()
	if r == nil {
		return nil
	}
	d := tun.BoundDialer(r.IfIndex)
	return func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
}

func tunStatePath(dir string) string { return filepath.Join(dir, "tun-routes.json") }

func recoverTunRoutes(dir string, logf func(string, ...any)) {
	if tun.Recover(tunStatePath(dir)) {
		logf("removed routes left by a previous TUN session")
	}
}

// newRelay builds the UDP relay for a profile (nil when udpgw is disabled).
func (a *App) newRelay(p *config.Profile, tn *tunnel.Tunnel) *udpgw.Relay {
	return &udpgw.Relay{
		Dial:           tn.Dial,
		Port:           p.UDPGWPort,
		TransparentDNS: p.UDPGWTransparentDNS,
		Logf:           a.logs.Printf,
	}
}

// prepareTUN resolves the server and finds the physical route before any
// TUN route exists. It returns the dialer that must be used for the SSH
// connection itself.
func prepareTUN(p *config.Profile) ([]netip.Addr, tun.Route, func(context.Context, string) (net.Conn, error), error) {
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(p.Host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		all, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", p.Host)
		if err != nil || len(all) == 0 {
			return nil, tun.Route{}, nil, fmt.Errorf("resolve %s: %v", p.Host, err)
		}
		for _, ip := range all {
			ips = append(ips, ip.Unmap())
		}
	}
	route, err := tun.BestRoute(ips[0])
	if err != nil {
		return nil, tun.Route{}, nil, err
	}
	d := tun.BoundDialer(route.IfIndex)
	target := netip.AddrPortFrom(ips[0], uint16(p.Port)).String()
	dial := func(ctx context.Context, _ string) (net.Conn, error) { return d.DialContext(ctx, "tcp", target) }
	return ips, route, dial, nil
}

func ensureWintun() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if st, err := os.Stat(path); err == nil && st.Size() == int64(len(wintunDLL)) {
		return nil
	}
	return os.WriteFile(path, wintunDLL, 0o644)
}

// startTUN brings the TUN engine up for the current session.
func (a *App) startTUN(ips []netip.Addr, route tun.Route, tn *tunnel.Tunnel, relay *udpgw.Relay, st config.Settings) (*tun.Engine, error) {
	if err := ensureWintun(); err != nil {
		return nil, fmt.Errorf("extract wintun.dll: %w", err)
	}
	eng := &tun.Engine{
		Name:      "SSHTunnel",
		Dial:      tn.Dial,
		Direct:    proxy.NewMatcher(st.BypassList),
		Relay:     relay,
		Logf:      a.logs.Printf,
		StatePath: tunStatePath(a.dir),
	}
	if err := eng.Start(ips, route); err != nil {
		return nil, err
	}
	physMu.Lock()
	physRoute = &route
	physMu.Unlock()
	return eng, nil
}

func clearPhys() {
	physMu.Lock()
	physRoute = nil
	physMu.Unlock()
}

// ---- elevation ----

// relaunchElevated starts this exe as administrator to connect profile id in
// TUN mode, then quits this instance.
func (a *App) relaunchElevated(id string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := fmt.Sprintf("--wait-pid=%d --connect=%s", os.Getpid(), id)
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	if err := windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("administrator rights are needed for TUN mode: %w", err)
	}
	a.logs.Printf("restarting as administrator for TUN mode")
	go func() {
		time.Sleep(300 * time.Millisecond)
		a.Quit()
	}()
	return nil
}

// argValue returns --name=value from the command line.
func argValue(name string) string {
	for _, a := range os.Args[1:] {
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v
		}
	}
	return ""
}

// waitForParent blocks until the previous (non-elevated) instance has exited,
// so the single-instance lock is free.
func waitForParent() {
	pid, err := strconv.Atoi(argValue("wait-pid"))
	if err != nil || pid <= 0 {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_, _ = windows.WaitForSingleObject(h, 15000)
}

// ---- subscriptions ----

func (a *App) httpClients() []*http.Client {
	direct := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}
	a.mu.Lock()
	tn := a.tun
	a.mu.Unlock()
	if tn == nil {
		return []*http.Client{direct}
	}
	via := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy:       nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return tn.Dial(ctx, "tcp", addr) },
	}}
	return []*http.Client{via, direct}
}

func (a *App) fetchSub(url string) (*subs.Result, error) {
	var lastErr error
	for _, c := range a.httpClients() {
		res, err := subs.Fetch(context.Background(), c, url)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// AddSubscription stores a subscription URL and imports its configs.
func (a *App) AddSubscription(url string) (string, error) {
	url = strings.TrimSpace(url)
	if _, err := subs.FetchURL(url); err != nil {
		return "", err
	}
	var existing string
	a.store.View(func(d *config.Data) {
		for _, s := range d.Subscriptions {
			if s.URL == url {
				existing = s.ID
			}
		}
	})
	if existing != "" {
		return existing, a.UpdateSubscription(existing)
	}
	id := config.NewID()
	if err := a.store.Update(func(d *config.Data) error {
		d.Subscriptions = append(d.Subscriptions, &config.Subscription{ID: id, Name: subs.DefaultName(url), URL: url})
		return nil
	}); err != nil {
		return "", err
	}
	if err := a.UpdateSubscription(id); err != nil {
		return id, err
	}
	return id, nil
}

// UpdateSubscription re-downloads a subscription and replaces its configs.
func (a *App) UpdateSubscription(id string) error {
	var url string
	a.store.View(func(d *config.Data) {
		for _, s := range d.Subscriptions {
			if s.ID == id {
				url = s.URL
			}
		}
	})
	if url == "" {
		return errors.New("subscription not found")
	}
	res, err := a.fetchSub(url)
	if err != nil {
		a.logs.Printf("subscription %s: %v", subs.DefaultName(url), err)
		a.emitProfiles()
		return err
	}
	for _, p := range res.Links.Profiles {
		p.SubscriptionID = id
	}
	var added, updated, removed int
	err = a.store.Update(func(d *config.Data) error {
		keep := map[string]bool{}
		for _, p := range res.Links.Profiles {
			keep[p.Key()] = true
		}
		out := d.Profiles[:0]
		for _, p := range d.Profiles {
			if p.SubscriptionID == id && !keep[p.Key()] {
				removed++
				continue
			}
			out = append(out, p)
		}
		d.Profiles = out
		added, updated = d.Merge(res.Links.Profiles)
		for _, s := range d.Subscriptions {
			if s.ID == id {
				s.UpdatedAt = time.Now().Unix()
				s.Upload, s.Download, s.Total, s.Expire = res.Info.Upload, res.Info.Download, res.Info.Total, res.Info.Expire
				if res.Title != "" {
					s.Name = res.Title
				}
			}
		}
		return nil
	})
	a.logs.Printf("subscription %s: %d added, %d updated, %d removed, %d non-SSH lines skipped",
		subs.DefaultName(url), added, updated, removed, res.Links.Skipped)
	a.emitProfiles()
	return err
}

// RemoveSubscription deletes a subscription and its configs.
func (a *App) RemoveSubscription(id string) error {
	err := a.store.Update(func(d *config.Data) error {
		out := d.Profiles[:0]
		for _, p := range d.Profiles {
			if p.SubscriptionID != id {
				out = append(out, p)
			}
		}
		d.Profiles = out
		subsOut := d.Subscriptions[:0]
		for _, s := range d.Subscriptions {
			if s.ID != id {
				subsOut = append(subsOut, s)
			}
		}
		d.Subscriptions = subsOut
		return nil
	})
	a.emitProfiles()
	return err
}
