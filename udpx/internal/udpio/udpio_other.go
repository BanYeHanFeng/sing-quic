//go:build !linux

package udpio

import "net"

func newBatched(net.PacketConn) Conn { return nil }
