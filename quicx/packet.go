package quicx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// Forwarded UDP packets
//
// A packet connection is a channel of its session: the transport carries the
// message of one forwarded packet as one datagram, tagged with the number of the
// channel it belongs to, and it hands a message over only once it is whole. What
// is left here is the message format — which command it is and where it goes —
// and the net.PacketConn the router sees.
//
// Each message carries its own destination instead of announcing it once per
// channel. The address costs a handful of bytes, and it buys the property that
// matters more: a message is routed by what is in it, so the first message of a
// channel is not special, a reordered one still routes, and nothing has to be
// remembered to read the next one.

// udpMessage is one forwarded UDP packet.
type udpMessage struct {
	destination M.Socksaddr
	data        []byte
}

// udpMessageHeaderLen is the fixed part of a packet message:
// [version(1)][command(1)][address(variable)][data].
const udpMessageHeaderLen = 2

func (m *udpMessage) pack() []byte {
	message := make([]byte, udpMessageHeaderLen+AddressSerializer.AddrPortLen(m.destination)+len(m.data))
	message[0] = Version
	message[1] = CommandPacket
	addressLen := writeAddrPort(message[udpMessageHeaderLen:], m.destination)
	copy(message[udpMessageHeaderLen+addressLen:], m.data)
	return message
}

// decodeUDPMessage parses one packet message. The payload points into data, which
// the caller owns.
func decodeUDPMessage(data []byte) (udpMessage, error) {
	if len(data) < udpMessageHeaderLen {
		return udpMessage{}, io.ErrUnexpectedEOF
	}
	if data[0] != Version {
		return udpMessage{}, E.New("unknown version ", data[0])
	}
	if data[1] != CommandPacket {
		return udpMessage{}, E.New("unknown command ", data[1])
	}
	destination, addressLen, err := decodeAddrPort(data[udpMessageHeaderLen:])
	if err != nil {
		return udpMessage{}, E.Cause(err, "decode destination")
	}
	return udpMessage{
		destination: destination,
		data:        data[udpMessageHeaderLen+addressLen:],
	}, nil
}

var (
	_ N.NetPacketConn    = (*udpPacketConn)(nil)
	_ N.PacketReadWaiter = (*udpPacketConn)(nil)
)

// udpPacketConn is one packet connection of a session: a channel of the session
// with its own receive buffer, its own deadline and its own lifetime.
type udpPacketConn struct {
	ctx             context.Context
	cancel          context.CancelCauseFunc
	sessionID       uint32
	association     udpx.Association
	data            chan udpMessage
	closeOnce       sync.Once
	isServer        bool
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
	// addrCache holds the *net.UDPAddr of the last destination handed out by
	// ReadFrom. Converting a Socksaddr allocates the address and its IP slice, and
	// a session that keeps sending to the same destination would pay for it once
	// per received packet. The cached object is only reused for an identical
	// destination, so a caller never sees it change under it.
	addrCache struct {
		destination M.Socksaddr
		addr        *net.UDPAddr
	}
}

func newUDPPacketConn(ctx context.Context, association udpx.Association, sessionID uint32, isServer bool, onDestroy func()) *udpPacketConn {
	ctx, cancel := context.WithCancelCause(ctx)
	return &udpPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		sessionID:    sessionID,
		association:  association,
		data:         make(chan udpMessage, 1024),
		isServer:     isServer,
		onDestroy:    onDestroy,
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case message := <-c.data:
		_, err = buffer.Write(message.data)
		return message.destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case message := <-c.data:
		n = copy(p, message.data)
		if message.destination.IsDomain() {
			addr = message.destination
		} else {
			addr = c.destinationAddr(message.destination)
		}
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// destinationAddr returns the *net.UDPAddr of destination, reusing the previous
// one when the destination did not change.
func (c *udpPacketConn) destinationAddr(destination M.Socksaddr) *net.UDPAddr {
	if c.addrCache.addr != nil && c.addrCache.destination == destination {
		return c.addrCache.addr
	}
	addr := destination.UDPAddr()
	c.addrCache.destination = destination
	c.addrCache.addr = addr
	return addr
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	message := udpMessage{destination: destination, data: buffer.Bytes()}
	err := c.writeMessage(message)
	buffer.Release()
	return err
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destination := M.SocksaddrFromNet(addr)
	message := udpMessage{destination: destination, data: p}
	err = c.writeMessage(message)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeMessage sends one forwarded packet on the channel of this connection, as
// one datagram of the session.
func (c *udpPacketConn) writeMessage(message udpMessage) error {
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if !message.destination.IsValid() {
		return E.New("invalid destination address")
	}
	err := c.association.SendDatagram(c.sessionID, message.pack())
	if err != nil {
		return E.Cause(err, "send message")
	}
	return nil
}

// inputPacket hands one received message to the reader of this connection. A full
// receive buffer drops it, which is what the receive buffer of a UDP socket does
// as well: a datagram that arrived too late to be kept is dropped, not queued.
func (c *udpPacketConn) inputPacket(message udpMessage) {
	select {
	case c.data <- message:
	default:
	}
}

func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		c.onDestroy()
	})
	return nil
}

// closeWithError ends this connection only: the session and every other packet
// connection on it keep running. The peer is told that the channel is over, so
// it releases what it holds for it instead of waiting for a timeout.
func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
	if c.isServer {
		return
	}
	message := []byte{Version, CommandDissociate}
	message = binary.BigEndian.AppendUint32(message, c.sessionID)
	_ = c.association.SendDatagram(c.sessionID, message)
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.association.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

// Address family bytes of AddressSerializer, see the serializer options in
// address.go.
const (
	addressFamilyFqdn  = 0x00
	addressFamilyIPv4  = 0x01
	addressFamilyIPv6  = 0x02
	addressFamilyEmpty = 0xff
)

// decodeAddrPort parses a serialized destination and reports how many bytes it
// consumed. The encoding is the one AddressSerializer writes: an address family
// byte, the address, and a port when the address is valid.
func decodeAddrPort(data []byte) (M.Socksaddr, int, error) {
	if len(data) < 1 {
		return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
	}
	switch data[0] {
	case addressFamilyIPv4:
		if len(data) < 1+4+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		var address [4]byte
		copy(address[:], data[1:5])
		return M.Socksaddr{Addr: netip.AddrFrom4(address), Port: binary.BigEndian.Uint16(data[5:7])}, 7, nil
	case addressFamilyIPv6:
		if len(data) < 1+16+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		var address [16]byte
		copy(address[:], data[1:17])
		return M.Socksaddr{Addr: netip.AddrFrom16(address), Port: binary.BigEndian.Uint16(data[17:19])}.Unwrap(), 19, nil
	case addressFamilyFqdn:
		if len(data) < 2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		fqdnLen := int(data[1])
		if len(data) < 2+fqdnLen+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		fqdn := string(data[2 : 2+fqdnLen])
		port := binary.BigEndian.Uint16(data[2+fqdnLen : 4+fqdnLen])
		return M.ParseSocksaddrHostPort(fqdn, port), 4 + fqdnLen, nil
	case addressFamilyEmpty:
		return M.Socksaddr{}, 1, nil
	default:
		return M.Socksaddr{}, 0, E.New("unknown address family ", data[0])
	}
}
