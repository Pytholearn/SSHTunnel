package udpgw

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// DialFunc opens a TCP stream (an SSH direct-tcpip channel).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Relay carries UDP flows through udpgw, (re)opening the channel lazily.
// DNS flows fall back to DNS-over-TCP through the tunnel when udpgw is not
// available (port 0 or the channel cannot be opened).
type Relay struct {
	Dial           DialFunc
	Port           int  // udpgw port on the server's 127.0.0.1; 0 = no udpgw
	TransparentDNS bool // set the DNS flag on port-53 packets
	Logf           func(string, ...any)
	MaxConns       int // conids per channel (default 256, badvpn's default per client)
	Keepalive      time.Duration

	mu       sync.Mutex
	cli      *client
	failedAt time.Time
	closed   bool
}

func (r *Relay) logf(f string, a ...any) {
	if r.Logf != nil {
		r.Logf(f, a...)
	}
}

// Close shuts the current channel and all flows.
func (r *Relay) Close() {
	r.mu.Lock()
	r.closed = true
	c := r.cli
	r.cli = nil
	r.mu.Unlock()
	if c != nil {
		c.close(errors.New("relay closed"))
	}
}

// Warmup opens the udpgw channel now (if enabled) instead of on first use.
func (r *Relay) Warmup() { _, _ = r.get() }

// Active reports whether a udpgw channel is currently open.
func (r *Relay) Active() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cli != nil && !r.cli.isClosed()
}

func (r *Relay) get() (*client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("relay closed")
	}
	if r.Port <= 0 {
		return nil, errors.New("udpgw disabled for this config")
	}
	if r.cli != nil && !r.cli.isClosed() {
		return r.cli, nil
	}
	if time.Since(r.failedAt) < 3*time.Second {
		return nil, errors.New("udpgw unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := r.Dial(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Port)))
	if err != nil {
		r.failedAt = time.Now()
		r.logf("udpgw: open channel to 127.0.0.1:%d: %v", r.Port, err)
		return nil, err
	}
	max := r.MaxConns
	if max <= 0 {
		max = 256
	}
	ka := r.Keepalive
	if ka == 0 {
		ka = 10 * time.Second
	}
	r.cli = newClient(conn, max, ka, r.logf)
	r.logf("udpgw: channel open (127.0.0.1:%d)", r.Port)
	return r.cli, nil
}

// Flow is one UDP association (src -> dst). Replies are delivered to the
// callback with the remote address they came from.
type Flow struct {
	r     *Relay
	dst   netip.AddrPort
	reply func(from netip.AddrPort, payload []byte)
	dns   bool

	mu     sync.Mutex
	cli    *client
	id     uint16
	hasID  bool
	closed bool
}

// NewFlow creates a flow towards dst.
func (r *Relay) NewFlow(dst netip.AddrPort, reply func(from netip.AddrPort, payload []byte)) *Flow {
	return &Flow{r: r, dst: netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()), reply: reply, dns: dst.Port() == 53}
}

// Send sends one datagram.
func (f *Flow) Send(payload []byte) error {
	if len(payload) > MaxPayload {
		return errors.New("udpgw: datagram too large")
	}
	cli, err := f.r.get()
	if err != nil {
		if f.dns {
			go f.dnsOverTCP(append([]byte(nil), payload...))
			return nil
		}
		return err
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	flags := byte(0)
	if f.cli != cli || !f.hasID || !cli.owns(f.id, f) {
		id := cli.register(f)
		f.cli, f.id, f.hasID = cli, id, true
		flags |= FlagRebind // first packet of a (re)bound conid
	}
	id := f.id
	f.mu.Unlock()
	if f.dns && f.r.TransparentDNS {
		flags |= FlagDNS
	}
	return cli.send(flags, id, f.dst, payload)
}

// Close releases the conid.
func (f *Flow) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if f.cli != nil && f.hasID {
		f.cli.unregister(f.id, f)
	}
}

func (f *Flow) deliver(from netip.AddrPort, p []byte) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if !closed {
		f.reply(from, p)
	}
}

// dnsOverTCP sends one DNS query via TCP through the tunnel.
func (f *Flow) dnsOverTCP(q []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := f.r.Dial(ctx, "tcp", f.dst.String())
	if err != nil {
		f.r.logf("dns over tcp %s: %v", f.dst, err)
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(msg, q...)); err != nil {
		return
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return
	}
	f.deliver(f.dst, resp)
}

// ---- one udpgw channel ----

type slot struct {
	flow *Flow
	used time.Time
}

type client struct {
	conn net.Conn
	logf func(string, ...any)
	max  int

	wmu sync.Mutex
	bw  *bufio.Writer

	mu     sync.Mutex
	slots  map[uint16]*slot
	next   uint16
	done   chan struct{}
	err    error
	closed bool
}

func newClient(conn net.Conn, max int, keepalive time.Duration, logf func(string, ...any)) *client {
	c := &client{conn: conn, logf: logf, max: max, bw: bufio.NewWriterSize(conn, 64<<10),
		slots: map[uint16]*slot{}, done: make(chan struct{})}
	go c.readLoop()
	go c.keepaliveLoop(keepalive)
	return c
}

func (c *client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *client) close(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed, c.err = true, err
	close(c.done)
	c.mu.Unlock()
	c.conn.Close()
}

// register assigns a conid to f, evicting the least recently used flow when full.
func (c *client) register(f *Flow) uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.slots) >= c.max {
		var lruID uint16
		var lru *slot
		for id, s := range c.slots {
			if lru == nil || s.used.Before(lru.used) {
				lru, lruID = s, id
			}
		}
		delete(c.slots, lruID)
	}
	for {
		id := c.next
		c.next = uint16((int(c.next) + 1) % c.max)
		if _, busy := c.slots[id]; !busy {
			c.slots[id] = &slot{flow: f, used: time.Now()}
			return id
		}
	}
}

func (c *client) owns(id uint16, f *Flow) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.slots[id]
	if ok && s.flow == f {
		s.used = time.Now()
		return true
	}
	return false
}

func (c *client) unregister(id uint16, f *Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.slots[id]; ok && s.flow == f {
		delete(c.slots, id)
	}
}

func (c *client) send(flags byte, id uint16, dst netip.AddrPort, payload []byte) error {
	pkt := AppendPacket(make([]byte, 0, len(payload)+32), flags, id, dst, payload)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.isClosed() {
		return fmt.Errorf("udpgw channel closed: %v", c.err)
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.bw.Write(pkt); err != nil {
		c.close(err)
		return err
	}
	if err := c.bw.Flush(); err != nil {
		c.close(err)
		return err
	}
	return nil
}

func (c *client) readLoop() {
	br := bufio.NewReaderSize(c.conn, 64<<10)
	var buf []byte
	for {
		p, b, err := ReadPacket(br, buf)
		buf = b
		if err != nil {
			if !c.isClosed() {
				c.logf("udpgw: channel closed: %v", err)
			}
			c.close(err)
			return
		}
		if p.Flags&FlagKeepalive != 0 {
			continue
		}
		c.mu.Lock()
		s := c.slots[p.ConID]
		if s != nil {
			s.used = time.Now()
		}
		c.mu.Unlock()
		if s != nil {
			s.flow.deliver(p.Addr, append([]byte(nil), p.Payload...))
		}
	}
}

func (c *client) keepaliveLoop(d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	ka := KeepalivePacket()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.wmu.Lock()
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := c.bw.Write(ka)
			if err == nil {
				err = c.bw.Flush()
			}
			c.wmu.Unlock()
			if err != nil {
				c.close(err)
				return
			}
		}
	}
}
