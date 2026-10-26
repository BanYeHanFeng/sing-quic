package quicx

import (
	"net"
	"syscall"

	"github.com/sagernet/sing/common/bufio"
)

// socketPacketConn is a packet connection whose socket is still reachable through it.
//
// The transport asks a packet connection for its descriptor before it can send and
// receive in batches: one call cuts a run of equal datagrams, one call reads a run
// that arrived together. A wrapper that only translates addresses does not answer
// that question — and the wrappers are exactly what a client has, because the dialer
// hands back a connected socket while the transport addresses its peer itself. Without
// the descriptor every datagram costs a call in both directions, which for a client
// is the direction it receives data in.
type socketPacketConn struct {
	net.PacketConn
	socket syscall.Conn
}

// bindPacketConn turns the connected socket a dialer returned into the shape the
// transport expects, keeping the descriptor available for the batched path and
// falling back to the plain one on a socket that has none (a proxied chain, for one).
func bindPacketConn(conn net.Conn) net.PacketConn {
	unbound := bufio.NewUnbindPacketConn(conn)
	socket, isSocket := conn.(syscall.Conn)
	if !isSocket {
		return unbound
	}
	return &socketPacketConn{PacketConn: unbound, socket: socket}
}

func (c *socketPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.socket.SyscallConn()
}
