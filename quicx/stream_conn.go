package quicx

import (
	"net"
	"time"

	"github.com/sagernet/sing-quic/udpx"
	M "github.com/sagernet/sing/common/metadata"
)

// A proxied connection
//
// One connection is one stream of a session plus the destination it was made to.
// Both ends run on this type: the stream is bidirectional and carries its own
// flow control, and the destination is what the routing rules and the logs of
// either end report, which is the only thing the stream itself does not know.
type streamConn struct {
	stream      *udpx.Stream
	destination M.Socksaddr
}

func (c *streamConn) Read(p []byte) (n int, err error) {
	return c.stream.Read(p)
}

func (c *streamConn) Write(p []byte) (n int, err error) {
	return c.stream.Write(p)
}

// CloseWrite ends the write half and leaves the read half open, which is what a
// proxied connection that went quiet in one direction needs: the other end reads
// the end of the stream and can still answer.
func (c *streamConn) CloseWrite() error {
	return c.stream.CloseWrite()
}

// Close ends the connection. A stream the peer is still writing to is reset by
// the transport, so closing one connection neither waits for the peer nor
// touches the session the other connections run on.
func (c *streamConn) Close() error {
	return c.stream.Close()
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
