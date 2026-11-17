// Package tunnel keeps one SSH connection alive (keepalive + auto-reconnect)
// and opens direct-tcpip channels through it. It never requests a session,
// shell or pty.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// State of the tunnel.
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateError        State = "error"
)

// ErrHostKeyRejected is returned by a HostKeyCallback when the user refused
// the server key; it stops reconnecting.
var ErrHostKeyRejected = errors.New("host key rejected")

// Options configures a Tunnel.
type Options struct {
	Addr       string // host:port
	User       string
	Password   string
	PrivateKey string // PEM/OpenSSH, optional
	Passphrase string

	HostKeyCallback   ssh.HostKeyCallback
	HostKeyAlgorithms []string

	KeepaliveInterval time.Duration // default 15s
	KeepaliveTimeout  time.Duration // default 10s
	KeepaliveMaxFail  int           // default 3
	DialTimeout       time.Duration // default 15s
	Backoff           []time.Duration

	// DialServer, if set, replaces net.Dial for the TCP connection to the SSH
	// server (used by TUN mode to bind to the physical interface, and by
	// Phase 3 TLS/payload modes).
	DialServer func(ctx context.Context, addr string) (net.Conn, error)

	Logf    func(format string, args ...any)
	OnState func(s State, detail string)
}

// Tunnel is a self-healing SSH connection.
type Tunnel struct {
	opt Options

	mu      sync.Mutex
	client  *ssh.Client
	ready   chan struct{} // closed while connected
	state   State
	since   time.Time
	cancel  context.CancelFunc
	done    chan struct{}
	stopped bool

	up, down  atomic.Int64
	latencyMs atomic.Int64
	serverIP  atomic.Value // string
}

// New creates a Tunnel; call Start to connect.
func New(opt Options) *Tunnel {
	if opt.KeepaliveInterval == 0 {
		opt.KeepaliveInterval = 15 * time.Second
	}
	if opt.KeepaliveTimeout == 0 {
		opt.KeepaliveTimeout = 10 * time.Second
	}
	if opt.KeepaliveMaxFail == 0 {
		opt.KeepaliveMaxFail = 3
	}
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 15 * time.Second
	}
	if len(opt.Backoff) == 0 {
		opt.Backoff = []time.Duration{1 * time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second}
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.OnState == nil {
		opt.OnState = func(State, string) {}
	}
	if opt.HostKeyCallback == nil {
		opt.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	return &Tunnel{opt: opt, ready: make(chan struct{}), state: StateDisconnected}
}

// Start launches the connect/reconnect loop in the background.
func (t *Tunnel) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.cancel = cancel
	t.done = make(chan struct{})
	t.mu.Unlock()
	go t.loop(ctx)
}

// Stop closes the connection and stops reconnecting. It waits for the loop.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	t.stopped = true
	cancel, done, c := t.cancel, t.done, t.client
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c != nil {
		c.Close()
	}
	if done != nil {
		<-done
	}
}

// State returns the current state and when it was entered.
func (t *Tunnel) State() (State, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state, t.since
}

// Stats returns total bytes sent/received through channels and last RTT.
func (t *Tunnel) Stats() (up, down, latencyMs int64) {
	return t.up.Load(), t.down.Load(), t.latencyMs.Load()
}

// ServerIP is the resolved IP of the SSH server of the current connection.
func (t *Tunnel) ServerIP() string {
	s, _ := t.serverIP.Load().(string)
	return s
}

func (t *Tunnel) setState(s State, detail string) {
	t.mu.Lock()
	if t.state != s {
		t.since = time.Now()
	}
	t.state = s
	t.mu.Unlock()
	t.opt.OnState(s, detail)
}

func (t *Tunnel) loop(ctx context.Context) {
	defer close(t.done)
	attempt := 0
	everConnected := false
	for {
		if ctx.Err() != nil {
			t.setState(StateDisconnected, "")
			return
		}
		if attempt == 0 && !everConnected {
			t.setState(StateConnecting, t.opt.Addr)
		}
		c, err := t.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				t.setState(StateDisconnected, "")
				return
			}
			fatal := errors.Is(err, ErrHostKeyRejected) || (!everConnected && isAuthError(err))
			t.opt.Logf("connect failed: %v", err)
			if fatal {
				t.setState(StateError, err.Error())
				return
			}
			d := t.opt.Backoff[min(attempt, len(t.opt.Backoff)-1)]
			attempt++
			t.setState(StateReconnecting, fmt.Sprintf("retry in %s: %v", d, err))
			select {
			case <-ctx.Done():
				t.setState(StateDisconnected, "")
				return
			case <-time.After(d):
			}
			continue
		}
		attempt = 0
		everConnected = true
		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			c.Close()
			t.setState(StateDisconnected, "")
			return
		}
		t.client = c
		close(t.ready)
		t.mu.Unlock()
		t.opt.Logf("connected to %s (%s)", t.opt.Addr, string(c.ServerVersion()))
		t.setState(StateConnected, "")

		reason := t.supervise(ctx, c)

		t.mu.Lock()
		t.client = nil
		t.ready = make(chan struct{})
		t.mu.Unlock()
		c.Close()
		if ctx.Err() != nil {
			t.setState(StateDisconnected, "")
			return
		}
		t.opt.Logf("connection lost: %s", reason)
		t.setState(StateReconnecting, reason)
	}
}

// supervise sends keepalives until the connection dies or ctx ends.
func (t *Tunnel) supervise(ctx context.Context, c *ssh.Client) string {
	dead := make(chan error, 1)
	go func() { dead <- c.Wait() }()
	tick := time.NewTicker(t.opt.KeepaliveInterval)
	defer tick.Stop()
	fails := 0
	// Measure once right away so the UI has a latency number.
	if rtt, err := t.ping(c); err == nil {
		t.latencyMs.Store(max(1, rtt.Milliseconds()))
	}
	for {
		select {
		case <-ctx.Done():
			return "stopped"
		case err := <-dead:
			if err == nil {
				return "server closed connection"
			}
			return err.Error()
		case <-tick.C:
			rtt, err := t.ping(c)
			if err != nil {
				fails++
				t.opt.Logf("keepalive failed (%d/%d): %v", fails, t.opt.KeepaliveMaxFail, err)
				if fails >= t.opt.KeepaliveMaxFail {
					return "keepalive timeout"
				}
				continue
			}
			fails = 0
			t.latencyMs.Store(max(1, rtt.Milliseconds()))
		}
	}
}

func (t *Tunnel) ping(c *ssh.Client) (time.Duration, error) {
	start := time.Now()
	res := make(chan error, 1)
	go func() {
		// OpenSSH answers unknown global requests with failure; any answer
		// proves the connection is alive.
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		res <- err
	}()
	select {
	case err := <-res:
		return time.Since(start), err
	case <-time.After(t.opt.KeepaliveTimeout):
		return 0, errors.New("no reply")
	}
}

func (t *Tunnel) connect(ctx context.Context) (*ssh.Client, error) {
	cfg, err := ClientConfig(t.opt)
	if err != nil {
		return nil, err
	}
	c, ip, err := DialSSH(ctx, t.opt, cfg)
	if err != nil {
		return nil, err
	}
	t.serverIP.Store(ip)
	return c, nil
}

// ClientConfig builds the ssh.ClientConfig for opt.
func ClientConfig(opt Options) (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod
	if opt.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if opt.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(opt.PrivateKey), []byte(opt.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(opt.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if opt.Password != "" {
		pw := opt.Password
		auths = append(auths,
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				ans := make([]string, len(qs))
				for i := range ans {
					ans[i] = pw
				}
				return ans, nil
			}),
		)
	}
	return &ssh.ClientConfig{
		User:            opt.User,
		Auth:            auths,
		HostKeyCallback:   opt.HostKeyCallback,
		HostKeyAlgorithms: opt.HostKeyAlgorithms,
		Timeout:           opt.DialTimeout,
		ClientVersion:     "SSH-2.0-OpenSSH_9.6",
	}, nil
}

// DialSSH opens TCP + SSH handshake + auth, honouring ctx. It returns the
// client and the server's IP.
func DialSSH(ctx context.Context, opt Options, cfg *ssh.ClientConfig) (*ssh.Client, string, error) {
	dctx, cancel := context.WithTimeout(ctx, opt.DialTimeout)
	defer cancel()
	var conn net.Conn
	var err error
	if opt.DialServer != nil {
		conn, err = opt.DialServer(dctx, opt.Addr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(dctx, "tcp", opt.Addr)
	}
	if err != nil {
		return nil, "", err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}
	ip := ""
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = ta.IP.String()
	}
	// Abort the handshake if ctx ends.
	stop := context.AfterFunc(dctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	_ = conn.SetDeadline(time.Now().Add(opt.DialTimeout + 5*time.Second))
	sc, chans, reqs, err := ssh.NewClientConn(conn, opt.Addr, cfg)
	stop()
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), ip, nil
}

func isAuthError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "unable to authenticate") || strings.Contains(s, "no supported methods remain")
}

// Dial opens a direct-tcpip channel to addr (host:port; host may be a domain
// name, which the server resolves). If the tunnel is reconnecting it waits
// for the connection until ctx ends.
func (t *Tunnel) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	for {
		t.mu.Lock()
		c, ready, stopped := t.client, t.ready, t.stopped
		t.mu.Unlock()
		if stopped {
			return nil, errors.New("tunnel stopped")
		}
		if c == nil {
			select {
			case <-ready:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("tunnel not connected: %w", ctx.Err())
			}
		}
		conn, err := c.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return &countConn{Conn: conn, up: &t.up, down: &t.down}, nil
	}
}

// countConn counts bytes; it keeps CloseWrite for half-close.
type countConn struct {
	net.Conn
	up, down *atomic.Int64
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.down.Add(int64(n))
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.up.Add(int64(n))
	return n, err
}

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// TestLatency measures TCP connect + SSH handshake/auth time and closes.
func TestLatency(ctx context.Context, opt Options) (time.Duration, error) {
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 10 * time.Second
	}
	cfg, err := ClientConfig(opt)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	c, _, err := DialSSH(ctx, opt, cfg)
	if err != nil {
		return 0, err
	}
	d := time.Since(start)
	c.Close()
	return d, nil
}
