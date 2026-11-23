package quicx

import (
	"context"
	"io"
	"net"
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

const channelBacklog = 1024

var (
	_ N.NetPacketConn    = (*channelConn)(nil)
	_ N.PacketReadWaiter = (*channelConn)(nil)
)

type channelConn struct {
	context     context.Context
	cancel      context.CancelCauseFunc
	session     *session
	association udpx.Association
	channel     uint32

	messages     chan udpMessage
	closeOnce    sync.Once
	readDeadline pipe.Deadline
	readOptions  N.ReadWaitOptions
}

func newChannelConn(ctx context.Context, current *session, id uint32) *channelConn {
	ctx, cancel := context.WithCancelCause(ctx)
	return &channelConn{
		context:      ctx,
		cancel:       cancel,
		session:      current,
		association:  current.association,
		channel:      id,
		messages:     make(chan udpMessage, channelBacklog),
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *channelConn) readMessage() (udpMessage, error) {
	select {
	case message := <-c.messages:
		return message, nil
	case <-c.context.Done():
		return udpMessage{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return udpMessage{}, os.ErrDeadlineExceeded
	}
}

func (c *channelConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	message, err := c.readMessage()
	if err != nil {
		return M.Socksaddr{}, err
	}
	_, err = buffer.Write(message.data)
	return message.destination, err
}

func (c *channelConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	message, err := c.readMessage()
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, message.data)
	if message.destination.IsDomain() {
		return n, message.destination, nil
	}
	return n, message.destination.UDPAddr(), nil
}

func (c *channelConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readOptions = options
	return options.NeedHeadroom()
}

func (c *channelConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	message, err := c.readMessage()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	if c.readOptions.NeedHeadroom() {
		buffer = c.readOptions.NewPacketBuffer()
		_, err = buffer.Write(message.data)
		if err != nil {
			buffer.Release()
			return nil, M.Socksaddr{}, err
		}
		c.readOptions.PostReturn(buffer)
	} else {
		buffer = buf.NewSize(len(message.data))
		_, err = buffer.Write(message.data)
		if err != nil {
			buffer.Release()
			return nil, M.Socksaddr{}, err
		}
	}
	return buffer, message.destination, nil
}

func (c *channelConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := c.write(destination, buffer.Bytes())
	buffer.Release()
	return err
}

func (c *channelConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = c.write(M.SocksaddrFromNet(addr), p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *channelConn) write(destination M.Socksaddr, payload []byte) error {
	select {
	case <-c.context.Done():
		return net.ErrClosed
	default:
	}
	if !destination.IsValid() {
		return E.New("invalid destination address")
	}
	message := udpMessage{destination: destination, data: payload}
	err := c.association.SendDatagram(c.channel, message.pack())
	if err != nil {
		return E.Cause(err, "send message")
	}
	return nil
}

func (c *channelConn) input(message udpMessage) {
	select {
	case c.messages <- message:
	default:
	}
}

func (c *channelConn) Close() error {
	c.closeOnce.Do(func() {
		c.session.access.Lock()
		if c.session.channels[c.channel] == c {
			delete(c.session.channels, c.channel)
		}
		c.session.access.Unlock()
		c.closeWithError(os.ErrClosed)
		_ = c.association.SendDatagram(c.channel, []byte{CommandDissociate})
	})
	return nil
}

func (c *channelConn) closeWithError(err error) {
	c.cancel(err)
}

func (c *channelConn) LocalAddr() net.Addr {
	return c.association.LocalAddr()
}

func (c *channelConn) SetDeadline(deadline time.Time) error {
	return os.ErrInvalid
}

func (c *channelConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline.Set(deadline)
	return nil
}

func (c *channelConn) SetWriteDeadline(deadline time.Time) error {
	return os.ErrInvalid
}
