package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testServer is a tiny SSH server that only allows password auth and
// direct-tcpip channels (like the production servers: no shell, no pty).
type testServer struct {
	t      *testing.T
	addr   string
	signer ssh.Signer
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
	// sessionsRequested counts "session" channel attempts (must stay 0).
	sessionsRequested int
}

func newTestServer(t *testing.T, addr string, signer ssh.Signer) *testServer {
	t.Helper()
	if signer == nil {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, _ = ssh.NewSignerFromKey(priv)
	}
	s := &testServer{t: t, signer: signer}
	s.start(addr)
	return s
}

func (s *testServer) start(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.t.Fatal(err)
	}
	s.ln, s.addr = ln, ln.Addr().String()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "tester" && string(pw) == "secret" {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(s.signer)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			go s.handle(c, cfg)
		}
	}()
}

func (s *testServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			s.mu.Lock()
			s.sessionsRequested++
			s.mu.Unlock()
			nc.Reject(ssh.Prohibited, "no")
			continue
		}
		var p struct {
			Host  string
			Port  uint32
			OHost string
			OPort uint32
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
			nc.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		target, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			target.Close()
			continue
		}
		go ssh.DiscardRequests(creqs)
		go func() {
			go func() { io.Copy(ch, target); ch.CloseWrite() }()
			io.Copy(target, ch)
			target.(*net.TCPConn).CloseWrite()
		}()
	}
}

// stop closes the listener and kills all client connections.
func (s *testServer) stop() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
}
