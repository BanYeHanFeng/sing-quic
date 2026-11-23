package quicx

import (
	"net"
	"syscall"

	"github.com/sagernet/sing/common/bufio"
)

type socketPacketConn struct {
	net.PacketConn
	socket syscall.Conn
}

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
