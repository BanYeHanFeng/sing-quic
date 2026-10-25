//go:build !linux

package udpio

import "net"

// newBatched has nothing to offer off Linux: neither UDP_SEGMENT nor UDP_GRO is
// there, and the poller workaround that batches sends elsewhere is not worth its
// own build tag until something measures it. Every packet goes on its own.
func newBatched(net.PacketConn, Options) Conn { return nil }
