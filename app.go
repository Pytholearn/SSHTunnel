package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"sshtunnel/internal/config"
	"sshtunnel/internal/links"
	"sshtunnel/internal/proxy"
	"sshtunnel/internal/sysproxy"
	"sshtunnel/internal/tun"
	"sshtunnel/internal/tunnel"
	"sshtunnel/internal/udpgw"
)

const appVersion = "1.0.0"

// App is bound to the frontend; exported methods are callable from JS.
type App struct {
	ctx   context.Context
	store *config.Store
	logs  *LogBuffer
	sp    *sysproxy.Manager
	dir   string

	mu        sync.Mutex
	tun       *tunnel.Tunnel
	px        *proxy.Server
	extra     sessionExtras // phase 2 pieces (udpgw, tun) owned by the session
	activeID  string
	state     tunnel.State
	detail    string
	stopStats chan struct{}
	lastUp    int64
	lastDown  int64
	speedUp   int64
	speedDown int64
	quitting  bool

	trayUpdate func(connected bool, tip string)
}

// ---- views sent to the UI ----

type ProfileView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	LatencyMs  int    `json:"latencyMs"`
	Format     string `json:"format"`
	SubID      string `json:"subId"`
	HostKey    bool   `json:"hostKey"`
	UDPGWPort  int    `json:"udpgwPort"`
	ConfigType string `json:"configType"`
}

type ProfileEdit struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"privateKey"`
	HostKey    string `json:"hostKey"` // pinned key (authorized_keys line)
	UDPGWPort  int    `json:"udpgwPort"`
}

type StatusView struct {
	State       string `json:"state"`
	Detail      string `json:"detail"`
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName"`
	UptimeSec   int64  `json:"uptimeSec"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
	UpSpeed     int64  `json:"upSpeed"`
	DownSpeed   int64  `json:"downSpeed"`
	LatencyMs   int64  `json:"latencyMs"`
	SocksAddr   string `json:"socksAddr"`
	HTTPAddr    string `json:"httpAddr"`
	SystemProxy bool   `json:"systemProxy"`
	TunActive   bool   `json:"tunActive"`
	UDPActive   bool   `json:"udpActive"`
}

type Snapshot struct {
	Profiles      []ProfileView          `json:"profiles"`
	Subscriptions []*config.Subscription `json:"subscriptions"`
	Settings      config.Settings        `json:"settings"`
	Status        StatusView             `json:"status"`
	Logs          []string               `json:"logs"`
	Version       string                 `json:"version"`
	IsAdmin       bool                   `json:"isAdmin"`
}

type ImportResult struct {
	Added         int      `json:"added"`
	Updated       int      `json:"updated"`
	Skipped       int      `json:"skipped"`
	Errors        []string `json:"errors"`
	Subscriptions int      `json:"subscriptions"`
	FirstID       string   `json:"firstId"`
}

func NewApp() (*App, error) {
	dir, err := config.AppDir()
	if err != nil {
		return nil, err
	}
	st, err := config.Open(filepath.Join(dir, "config.json"))
	if err != nil {
		// Keep a copy of the broken file and start fresh rather than refuse to run.
		_ = os.Rename(filepath.Join(dir, "config.json"), filepath.Join(dir, fmt.Sprintf("config.broken-%d.json", time.Now().Unix())))
		st, err = config.Open(filepath.Join(dir, "config.json"))
		if err != nil {
			return nil, err
		}
	}
	return &App{
		store: st,
		logs:  NewLogBuffer(500),
		sp:    &sysproxy.Manager{BackupPath: filepath.Join(dir, "proxy-backup.json")},
		dir:   dir,
		state: tunnel.StateDisconnected,
	}, nil
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	logFile, _ := os.Create(filepath.Join(a.dir, "app.log")) // last session's log, for support
	a.logs.SetSink(func(line string) {
		runtime.EventsEmit(ctx, "log", line)
		if logFile != nil {
			_, _ = logFile.WriteString(line + string([]byte{13, 10}))
		}
	})
	if v, err := strconv.Atoi(argValue("quit-after")); err == nil && v > 0 { // used by automated tests
		go func() {
			time.Sleep(time.Duration(v) * time.Second)
			a.logs.Printf("quit-after %ds reached, exiting", v)
			a.Quit()
		}()
	}
	a.logs.Printf("SSHTunnel %s started", appVersion)
	// Crash recovery: a backup left behind means the last run did not restore.
	if ok, err := a.sp.Restore(); err != nil {
		a.logs.Printf("restore system proxy: %v", err)
	} else if ok {
		a.logs.Printf("restored system proxy settings left by a previous run")
	}
	recoverTunRoutes(a.dir, a.logs.Printf)
	st := a.store.Settings()
	target := ""
	if id := argValue("connect"); id != "" { // relaunched elevated for TUN mode
		target = id
	} else if st.ConnectOnStart {
		target = st.LastSelected
	}
	if target != "" && a.store.Profile(target) != nil {
		go func() {
			if err := a.Connect(target); err != nil {
				a.logs.Printf("connect on start: %v", err)
			}
		}()
	}
}

func (a *App) shutdown(context.Context) {
	a.Disconnect()
	if _, err := a.sp.Restore(); err != nil {
		a.logs.Printf("restore system proxy: %v", err)
	}
}

// beforeClose hides to tray instead of quitting, unless Exit was chosen.
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.Lock()
	q := a.quitting
	a.mu.Unlock()
	if q {
		return false
	}
	runtime.WindowHide(ctx)
	return true
}

func (a *App) Quit() {
	a.mu.Lock()
	a.quitting = true
	a.mu.Unlock()
	runtime.Quit(a.ctx)
}

func (a *App) ShowWindow() {
	runtime.WindowShow(a.ctx)
	runtime.WindowUnminimise(a.ctx)
	runtime.WindowSetAlwaysOnTop(a.ctx, true)
	runtime.WindowSetAlwaysOnTop(a.ctx, false)
}

// ---- snapshot / views ----

func (a *App) profileViews() []ProfileView {
	var out []ProfileView
	a.store.View(func(d *config.Data) {
		for _, p := range d.Profiles {
			out = append(out, ProfileView{
				ID: p.ID, Name: p.Name, Host: p.Host, Port: p.Port, Username: p.Username,
				LatencyMs: p.LastLatencyMs, Format: p.Format, SubID: p.SubscriptionID,
				HostKey: p.PinnedHostKey != "" || p.KnownHostKey != "", UDPGWPort: p.UDPGWPort,
				ConfigType: p.SSHConfigType,
			})
		}
	})
	return out
}

func (a *App) subscriptions() []*config.Subscription {
	var out []*config.Subscription
	a.store.View(func(d *config.Data) {
		for _, s := range d.Subscriptions {
			c := *s
			out = append(out, &c)
		}
	})
	return out
}

func (a *App) Init() Snapshot {
	return Snapshot{
		Profiles:      a.profileViews(),
		Subscriptions: a.subscriptions(),
		Settings:      a.store.Settings(),
		Status:        a.Status(),
		Logs:          a.logs.Lines(),
		Version:       appVersion,
		IsAdmin:       isAdmin(),
	}
}

func (a *App) emitProfiles() {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "profiles", a.profileViews())
		runtime.EventsEmit(a.ctx, "subscriptions", a.subscriptions())
	}
}

func (a *App) emitStatus() {
	s := a.Status()
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "status", s)
	}
	if a.trayUpdate != nil {
		tip := "SSHTunnel – " + s.State
		if s.ProfileName != "" {
			tip += " – " + s.ProfileName
		}
		a.trayUpdate(s.State == string(tunnel.StateConnected), tip)
	}
}

func (a *App) Status() StatusView {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.store.Settings()
	v := StatusView{
		State: string(a.state), Detail: a.detail, ProfileID: a.activeID,
		UpSpeed: a.speedUp, DownSpeed: a.speedDown,
		SystemProxy: a.sp.Active(),
		TunActive:   a.extra.tunActive(),
		UDPActive:   a.extra.udpActive(),
	}
	if p := a.store.Profile(a.activeID); p != nil {
		v.ProfileName = p.Name
	}
	if a.tun != nil {
		v.Up, v.Down, v.LatencyMs = a.tun.Stats()
		if s, since := a.tun.State(); s == tunnel.StateConnected {
			v.UptimeSec = int64(time.Since(since).Seconds())
		}
		v.SocksAddr = "127.0.0.1:" + strconv.Itoa(st.SocksPort)
		v.HTTPAddr = "127.0.0.1:" + strconv.Itoa(st.HTTPPort)
	}
	return v
}

// ---- import / edit ----

func (a *App) ImportClipboard() (ImportResult, error) {
	text, err := runtime.ClipboardGetText(a.ctx)
	if err != nil {
		return ImportResult{}, err
	}
	return a.ImportText(text)
}

func (a *App) ImportText(text string) (ImportResult, error) {
	r := links.ParseText(text)
	res := ImportResult{Skipped: r.Skipped, Errors: r.Errors}
	if len(r.Profiles) > 0 {
		err := a.store.Update(func(d *config.Data) error {
			res.Added, res.Updated = d.Merge(r.Profiles)
			return nil
		})
		if err != nil {
			return res, err
		}
		res.FirstID = r.Profiles[0].ID
	}
	for _, u := range r.Subscriptions {
		if _, err := a.AddSubscription(u); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("subscription: %v", err))
		} else {
			res.Subscriptions++
		}
	}
	a.logs.Printf("import: %d added, %d updated, %d skipped, %d subscriptions", res.Added, res.Updated, res.Skipped, res.Subscriptions)
	for _, e := range res.Errors {
		a.logs.Printf("import error: %s", e)
	}
	a.emitProfiles()
	return res, nil
}

func (a *App) DeleteProfile(id string) error {
	a.mu.Lock()
	active := a.activeID == id && a.tun != nil
	a.mu.Unlock()
	if active {
		a.Disconnect()
	}
	err := a.store.Update(func(d *config.Data) error {
		for i, p := range d.Profiles {
			if p.ID == id {
				d.Profiles = append(d.Profiles[:i], d.Profiles[i+1:]...)
				return nil
			}
		}
		return errors.New("not found")
	})
	a.emitProfiles()
	return err
}

func (a *App) RenameProfile(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("empty name")
	}
	err := a.store.Update(func(d *config.Data) error {
		for _, p := range d.Profiles {
			if p.ID == id {
				p.Name = name
				return nil
			}
		}
		return errors.New("not found")
	})
	a.emitProfiles()
	return err
}

func (a *App) GetProfile(id string) (ProfileEdit, error) {
	p := a.store.Profile(id)
	if p == nil {
		return ProfileEdit{}, errors.New("not found")
	}
	return ProfileEdit{ID: p.ID, Name: p.Name, Host: p.Host, Port: p.Port, Username: p.Username,
		Password: p.Password, PrivateKey: p.PrivateKey, HostKey: p.PinnedHostKey, UDPGWPort: p.UDPGWPort}, nil
}

// SaveProfile creates (empty ID) or updates a profile from the edit form.
func (a *App) SaveProfile(e ProfileEdit) (string, error) {
	e.Host = strings.TrimSpace(e.Host)
	e.Username = strings.TrimSpace(e.Username)
	if e.Host == "" || e.Username == "" || e.Port <= 0 || e.Port > 65535 {
		return "", errors.New("host, port and username are required")
	}
	if e.Name = strings.TrimSpace(e.Name); e.Name == "" {
		e.Name = fmt.Sprintf("%s@%s", e.Username, e.Host)
	}
	if e.HostKey = strings.TrimSpace(e.HostKey); e.HostKey != "" {
		if _, err := tunnel.ParseKeyLine(e.HostKey); err != nil {
			return "", fmt.Errorf("host key: %v", err)
		}
	}
	id := e.ID
	err := a.store.Update(func(d *config.Data) error {
		var p *config.Profile
		for _, x := range d.Profiles {
			if x.ID == e.ID {
				p = x
			}
		}
		if p == nil {
			p = &config.Profile{ID: config.NewID(), Format: "manual", AuthMethod: "PASSWORD"}
			d.Profiles = append(d.Profiles, p)
			id = p.ID
		}
		if p.Host != e.Host || p.Port != e.Port {
			p.KnownHostKey = "" // different server: learn again
		}
		p.Name, p.Host, p.Port, p.Username = e.Name, e.Host, e.Port, e.Username
		p.Password, p.PrivateKey, p.PinnedHostKey, p.UDPGWPort = e.Password, e.PrivateKey, e.HostKey, e.UDPGWPort
		if p.PrivateKey != "" && p.Password == "" {
			p.AuthMethod = "KEY"
		}
		return nil
	})
	a.emitProfiles()
	return id, err
}

// ForgetHostKey clears the learned (TOFU) key of a profile.
func (a *App) ForgetHostKey(id string) error {
	err := a.store.Update(func(d *config.Data) error {
		for _, p := range d.Profiles {
			if p.ID == id {
				p.KnownHostKey = ""
			}
		}
		return nil
	})
	a.emitProfiles()
	return err
}

func (a *App) SelectProfile(id string) {
	_ = a.store.Update(func(d *config.Data) error { d.Settings.LastSelected = id; return nil })
}

func (a *App) GetLogs() []string { return a.logs.Lines() }

func (a *App) SaveSettings(s config.Settings) error {
	if s.SocksPort <= 0 || s.SocksPort > 65535 || s.HTTPPort <= 0 || s.HTTPPort > 65535 || s.SocksPort == s.HTTPPort {
		return errors.New("invalid ports")
	}
	old := a.store.Settings()
	if err := a.store.Update(func(d *config.Data) error {
		s.LastSelected = d.Settings.LastSelected
		d.Settings = s
		return nil
	}); err != nil {
		return err
	}
	if old.StartWithWindows != s.StartWithWindows {
		if err := setAutostart(s.StartWithWindows); err != nil {
			a.logs.Printf("autostart: %v", err)
			return err
		}
	}
	// Apply the system-proxy toggle live while connected.
	a.mu.Lock()
	connected := a.tun != nil
	a.mu.Unlock()
	if connected && old.SystemProxy != s.SystemProxy {
		if s.SystemProxy {
			if err := a.sp.Enable("127.0.0.1:" + strconv.Itoa(s.HTTPPort)); err != nil {
				a.logs.Printf("system proxy: %v", err)
			} else {
				a.logs.Printf("system proxy enabled")
			}
		} else if _, err := a.sp.Restore(); err == nil {
			a.logs.Printf("system proxy restored")
		}
	}
	if connected && (old.SocksPort != s.SocksPort || old.HTTPPort != s.HTTPPort || old.TunMode != s.TunMode) {
		a.logs.Printf("port/TUN changes apply on next connect")
	}
	if connected {
		a.mu.Lock()
		if a.px != nil {
			a.px.Direct = proxy.NewMatcher(s.BypassList)
		}
		a.mu.Unlock()
	}
	a.emitStatus()
	return nil
}

// ---- connect / disconnect ----

func (a *App) hostKeyPolicy(p *config.Profile) tunnel.HostKeyPolicy {
	id := p.ID
	return tunnel.HostKeyPolicy{
		Pinned: p.PinnedHostKey,
		Known:  p.KnownHostKey,
		Confirm: func(host, want, got string) bool {
			a.logs.Printf("HOST KEY MISMATCH for %s: expected %s, got %s", host, want, got)
			if a.ctx == nil {
				return false
			}
			fa := a.store.Settings().Language != "en"
			title, msg := "Host key changed", fmt.Sprintf(
				"The server key for %s does not match the saved one.\n\nSaved:  %s\nServer: %s\n\nThis can mean the server was reinstalled, or someone is intercepting the connection.\n\nAccept the new key and connect?", host, want, got)
			if fa {
				title, msg = "کلید سرور تغییر کرده", fmt.Sprintf(
					"کلید سرور %s با کلید ذخیره‌شده یکی نیست.\n\nذخیره‌شده:  %s\nسرور: %s\n\nممکن است سرور دوباره نصب شده باشد یا کسی ارتباط را شنود کند.\n\nکلید جدید پذیرفته شود و وصل شویم؟", host, want, got)
			}
			ans, err := runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
				Type: runtime.QuestionDialog, Title: title, Message: msg,
				Buttons: []string{"Yes", "No"}, DefaultButton: "No", CancelButton: "No",
			})
			return err == nil && ans == "Yes"
		},
		Learn: func(line string) {
			_ = a.store.Update(func(d *config.Data) error {
				for _, x := range d.Profiles {
					if x.ID == id {
						if x.PinnedHostKey != "" && x.PinnedHostKey != line {
							x.PinnedHostKey = "" // user accepted a key that differs from the link's pin
						}
						if x.PinnedHostKey == "" {
							x.KnownHostKey = line
						}
					}
				}
				return nil
			})
			a.logs.Printf("host key saved for %s", p.Name)
			a.emitProfiles()
		},
	}
}

func tunnelOptions(p *config.Profile) tunnel.Options {
	return tunnel.Options{
		Addr: p.Address(), User: p.Username, Password: p.Password,
		PrivateKey: p.PrivateKey, Passphrase: p.PrivateKeyPassphrase,
	}
}

func (a *App) Connect(id string) error {
	p := a.store.Profile(id)
	if p == nil {
		return errors.New("profile not found")
	}
	if strings.ToUpper(p.SSHConfigType) != "" && !strings.EqualFold(p.SSHConfigType, "SSH-Direct") {
		a.logs.Printf("note: config type %q is connected as SSH-Direct", p.SSHConfigType)
	}
	a.Disconnect()
	a.SelectProfile(id)
	st := a.store.Settings()

	if st.TunMode && !isAdmin() {
		return a.relaunchElevated(id)
	}
	// TUN: resolve the server and find the physical route before routes change.
	var (
		tunIPs   []netip.Addr
		tunRoute tun.Route
		tunDial  func(context.Context, string) (net.Conn, error)
	)
	if st.TunMode {
		var err error
		if tunIPs, tunRoute, tunDial, err = prepareTUN(p); err != nil {
			return fmt.Errorf("TUN: %w", err)
		}
	}

	px := &proxy.Server{Logf: a.logs.Printf, Direct: proxy.NewMatcher(st.BypassList)}
	socksAddr := "127.0.0.1:" + strconv.Itoa(st.SocksPort)
	httpAddr := "127.0.0.1:" + strconv.Itoa(st.HTTPPort)
	if err := px.ListenSOCKS(socksAddr); err != nil {
		return fmt.Errorf("SOCKS port %d: %w", st.SocksPort, err)
	}
	if err := px.ListenHTTP(httpAddr); err != nil {
		px.Close()
		return fmt.Errorf("HTTP port %d: %w", st.HTTPPort, err)
	}

	pol := a.hostKeyPolicy(p)
	opt := tunnelOptions(p)
	opt.HostKeyCallback = pol.Callback()
	opt.HostKeyAlgorithms = pol.Algorithms()
	opt.Logf = a.logs.Printf
	var tn *tunnel.Tunnel
	opt.OnState = func(s tunnel.State, detail string) { a.onTunnelState(tn, s, detail) }
	if st.TunMode {
		opt.DialServer = tunDial
	}
	tn = tunnel.New(opt)
	px.Dial = tn.Dial
	relay := a.newRelay(p, tn)
	resolver := udpgw.TunnelResolver(tn.Dial, "8.8.8.8:53")
	px.UDP = func(ctx context.Context, pc net.PacketConn) { relay.ServeSOCKS(ctx, pc, resolver) }

	a.mu.Lock()
	a.tun, a.px, a.activeID = tn, px, id
	a.extra = sessionExtras{relay: relay}
	a.state, a.detail = tunnel.StateConnecting, ""
	a.lastUp, a.lastDown, a.speedUp, a.speedDown = 0, 0, 0, 0
	a.stopStats = make(chan struct{})
	stop := a.stopStats
	a.mu.Unlock()

	a.logs.Printf("connecting to %s (%s) - SOCKS %s, HTTP %s", p.Name, p.Address(), socksAddr, httpAddr)
	tn.Start()
	if st.TunMode {
		eng, err := a.startTUN(tunIPs, tunRoute, tn, relay, st)
		if err != nil {
			a.logs.Printf("TUN failed, staying in proxy mode: %v", err)
		} else {
			a.mu.Lock()
			if a.tun == tn {
				a.extra.engine = eng
			} else {
				eng.Stop()
			}
			a.mu.Unlock()
		}
	}
	if p.UDPGWPort > 0 {
		go func() { // open the udpgw channel early so the UI shows UDP status
			for i := 0; i < 60; i++ {
				if s, _ := tn.State(); s == tunnel.StateConnected {
					relay.Warmup()
					return
				} else if s == tunnel.StateError || s == tunnel.StateDisconnected && i > 0 {
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}
	if st.SystemProxy && !a.extra.tunActive() {
		if err := a.sp.Enable(httpAddr); err != nil {
			a.logs.Printf("system proxy: %v", err)
		} else {
			a.logs.Printf("system proxy set to %s", httpAddr)
		}
	}
	go a.statsLoop(stop)
	a.emitStatus()
	return nil
}

func (a *App) onTunnelState(tn *tunnel.Tunnel, s tunnel.State, detail string) {
	a.mu.Lock()
	if a.tun != tn || tn == nil {
		a.mu.Unlock()
		return
	}
	a.state, a.detail = s, detail
	a.mu.Unlock()
	if s == tunnel.StateError {
		a.logs.Printf("stopped: %s", detail)
		go func() {
			a.disconnect(false)
			a.mu.Lock()
			a.state, a.detail = tunnel.StateError, detail
			a.mu.Unlock()
			a.emitStatus()
		}()
	}
	a.emitStatus()
}

func (a *App) statsLoop(stop chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.mu.Lock()
			if a.tun != nil {
				up, down, _ := a.tun.Stats()
				a.speedUp, a.speedDown = up-a.lastUp, down-a.lastDown
				a.lastUp, a.lastDown = up, down
			}
			a.mu.Unlock()
			a.emitStatus()
		}
	}
}

func (a *App) Disconnect() { a.disconnect(true) }

func (a *App) disconnect(log bool) {
	a.mu.Lock()
	tn, px, stop := a.tun, a.px, a.stopStats
	extra := a.extra
	a.tun, a.px, a.stopStats = nil, nil, nil
	a.extra = sessionExtras{}
	a.mu.Unlock()
	if tn == nil && px == nil {
		return
	}
	if stop != nil {
		close(stop)
	}
	extra.stop(a.logs.Printf)
	clearPhys()
	if ok, err := a.sp.Restore(); err != nil {
		a.logs.Printf("restore system proxy: %v", err)
	} else if ok {
		a.logs.Printf("system proxy restored")
	}
	if px != nil {
		px.Close()
	}
	if tn != nil {
		tn.Stop()
	}
	a.mu.Lock()
	a.state, a.detail, a.speedUp, a.speedDown = tunnel.StateDisconnected, "", 0, 0
	a.mu.Unlock()
	if log {
		a.logs.Printf("disconnected")
	}
	a.emitStatus()
}

// ToggleConnection connects the last selected profile or disconnects.
func (a *App) ToggleConnection() {
	a.mu.Lock()
	on := a.tun != nil
	a.mu.Unlock()
	if on {
		a.Disconnect()
		return
	}
	id := a.store.Settings().LastSelected
	if id == "" {
		a.ShowWindow()
		return
	}
	if err := a.Connect(id); err != nil {
		a.logs.Printf("connect: %v", err)
	}
}

// ---- latency ----

func (a *App) TestLatency(id string) (int, error) {
	p := a.store.Profile(id)
	if p == nil {
		return 0, errors.New("not found")
	}
	opt := tunnelOptions(p)
	pol := tunnel.HostKeyPolicy{Pinned: p.PinnedHostKey, Known: p.KnownHostKey}
	opt.HostKeyAlgorithms = pol.Algorithms()
	// Latency test never changes trust; a mismatch is reported as failure.
	opt.HostKeyCallback = pol.Callback()
	if pol.Pinned == "" && pol.Known == "" {
		opt.HostKeyCallback = nil // InsecureIgnoreHostKey: nothing to verify yet
	}
	if a.store.Settings().TunMode {
		opt.DialServer = physicalDialer()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d, err := tunnel.TestLatency(ctx, opt)
	ms := int(d.Milliseconds())
	if ms == 0 && err == nil {
		ms = 1
	}
	if err != nil {
		ms = -1
		a.logs.Printf("latency %s: %v", p.Name, err)
	} else {
		a.logs.Printf("latency %s: %d ms", p.Name, ms)
	}
	_ = a.store.Update(func(d *config.Data) error {
		for _, x := range d.Profiles {
			if x.ID == id {
				x.LastLatencyMs = ms
			}
		}
		return nil
	})
	a.emitProfiles()
	return ms, err
}

// TestAllLatency tests every profile, 8 at a time.
func (a *App) TestAllLatency() {
	views := a.profileViews()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, v := range views {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			_, _ = a.TestLatency(id)
		}(v.ID)
	}
	wg.Wait()
}

// SortByLatency reorders profiles: fastest first, failures last.
func (a *App) SortByLatency() {
	_ = a.store.Update(func(d *config.Data) error {
		rank := func(ms int) int {
			switch {
			case ms > 0:
				return ms
			case ms == 0:
				return 1 << 29
			default:
				return 1 << 30
			}
		}
		sort.SliceStable(d.Profiles, func(i, j int) bool {
			return rank(d.Profiles[i].LastLatencyMs) < rank(d.Profiles[j].LastLatencyMs)
		})
		return nil
	})
	a.emitProfiles()
}

// PortFree reports whether a local TCP port can be bound (UI hint).
func (a *App) PortFree(port int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
