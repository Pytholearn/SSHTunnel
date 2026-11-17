// Package udpgw implements the client side of badvpn-udpgw, carried over one
// SSH direct-tcpip channel to 127.0.0.1:<udpgw port> on the server.
//
// Wire format (verified against badvpn protocol/udpgw_proto.h, packetproto.h,
// udpgw/udpgw.c and udpgw_client/UdpGwClient.c):
//
//	packet  := len:uint16 LE | body[len]
//	body    := flags:uint8 | conid:uint16 LE | addr | payload
//	addr    := ipv4[4] port[2]            (flags & IPV6 == 0)
//	         | ipv6[16] port[2]           (flags & IPV6 != 0)
//	           (IP and port in network byte order)
//
// A keepalive is a body with only the 3-byte header and flags=KEEPALIVE.
// Server replies use the same format, with the remote address of the datagram.
package udpgw

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

const (
	FlagKeepalive = 0x01
	FlagRebind    = 0x02
	FlagDNS       = 0x04
	FlagIPv6      = 0x08

	headerLen  = 3
	MaxPayload = 65535 - headerLen - 18
)

// AppendPacket appends one length-prefixed udpgw packet to b.
func AppendPacket(b []byte, flags byte, conid uint16, addr netip.AddrPort, payload []byte) []byte {
	start := len(b)
	b = append(b, 0, 0)
	ip := addr.Addr().Unmap()
	if flags&FlagKeepalive == 0 && ip.Is6() {
		flags |= FlagIPv6
	}
	b = append(b, flags)
	b = binary.LittleEndian.AppendUint16(b, conid)
	if flags&FlagKeepalive == 0 {
		if ip.Is6() {
			a := ip.As16()
			b = append(b, a[:]...)
		} else {
			a := ip.As4()
			b = append(b, a[:]...)
		}
		b = binary.BigEndian.AppendUint16(b, addr.Port())
		b = append(b, payload...)
	}
	binary.LittleEndian.PutUint16(b[start:], uint16(len(b)-start-2))
	return b
}

// KeepalivePacket returns the keepalive packet (03 00 01 00 00).
func KeepalivePacket() []byte { return AppendPacket(nil, FlagKeepalive, 0, netip.AddrPort{}, nil) }

// Packet is a decoded udpgw body.
type Packet struct {
	Flags   byte
	ConID   uint16
	Addr    netip.AddrPort
	Payload []byte
}

// ParseBody decodes one body (without the length prefix).
func ParseBody(body []byte) (Packet, error) {
	var p Packet
	if len(body) < headerLen {
		return p, errors.New("udpgw: short header")
	}
	p.Flags = body[0]
	p.ConID = binary.LittleEndian.Uint16(body[1:3])
	body = body[headerLen:]
	if p.Flags&FlagKeepalive != 0 {
		return p, nil
	}
	if p.Flags&FlagIPv6 != 0 {
		if len(body) < 18 {
			return p, errors.New("udpgw: short ipv6 address")
		}
		p.Addr = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[:16])), binary.BigEndian.Uint16(body[16:18]))
		body = body[18:]
	} else {
		if len(body) < 6 {
			return p, errors.New("udpgw: short ipv4 address")
		}
		p.Addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[:4])), binary.BigEndian.Uint16(body[4:6]))
		body = body[6:]
	}
	p.Payload = body
	return p, nil
}

// ReadPacket reads one length-prefixed packet from r into buf (reused).
func ReadPacket(r io.Reader, buf []byte) (Packet, []byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return Packet{}, buf, err
	}
	n := int(binary.LittleEndian.Uint16(l[:]))
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return Packet{}, buf, err
	}
	p, err := ParseBody(buf)
	return p, buf, err
}
