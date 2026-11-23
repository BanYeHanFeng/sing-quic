package quicx

import (
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	M "github.com/sagernet/sing/common/metadata"
)

type streamConn struct {
	stream      *udpx.Stream
	destination M.Socksaddr
	onClose     func()
	closeOnce   sync.Once
}

func (c *streamConn) Read(p []byte) (n int, err error) {
	return c.stream.Read(p)
}

func (c *streamConn) Write(p []byte) (n int, err error) {
	return c.stream.Write(p)
}

func (c *streamConn) CloseWrite() error {
	return c.stream.CloseWrite()
}

func (c *streamConn) Close() error {
	err := c.stream.Close()
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *streamConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *streamConn) RemoteAddr() net.Addr {
	return c.stream.RemoteAddr()
}

func (c *streamConn) SetDeadline(deadline time.Time) error {
	return c.stream.SetDeadline(deadline)
}

func (c *streamConn) SetReadDeadline(deadline time.Time) error {
	return c.stream.SetReadDeadline(deadline)
}

func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	return c.stream.SetWriteDeadline(deadline)
}

var (
	_ net.Conn = (*streamConn)(nil)
	_ interface {
		CloseWrite() error
	} = (*streamConn)(nil)
)
