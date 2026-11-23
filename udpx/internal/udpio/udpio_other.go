//go:build !linux

package udpio

import "net"

func newBatched(net.PacketConn, Options) Conn { return nil }
