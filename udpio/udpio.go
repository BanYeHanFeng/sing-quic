// Package udpio moves UDP datagrams in batches.
//
// A session that sends one datagram per system call spends more time crossing
// into the kernel than doing anything else: every packet costs a call, and every
// received packet another. Linux can be asked to do better in both directions
// without changing a byte on the wire:
//
//   - UDP_SEGMENT (GSO) takes one buffer and cuts it into datagrams of a fixed
//     size, so a run of equal packets leaves in one call.
//   - UDP_GRO hands several datagrams up in one buffer, so a run that arrived
//     back to back is read once.
//
// Neither is guaranteed. An old kernel, a socket that did not come from the
// network stack, or a device driver that cannot segment all make the fast path
// unavailable, and the same code then moves one datagram per call. That is why
// the caller hands over a list of packets either way: whether the list becomes
// one system call or twenty is this package's business.
//
// What a batch is not: a batch is never a datagram. Each packet in it is one
// datagram on the wire, so a protocol that must not have two of its packets
// merged by anything (FEC parity, for one) can still put them in one batch.
package udpio

import "net"

// Packet is one datagram, or a run of datagrams that arrived together.
type Packet struct {
	// Data is the datagram, or the concatenated datagrams of a GRO run.
	Data []byte

	// Addr is the source of a received packet or the destination of a sent one.
	Addr net.Addr

	// Segments is how many datagrams Data holds. Zero and one both mean a
	// single datagram, which is what a socket without GRO always reports.
	Segments int

	// SegmentSize is the length of every segment but the last one, which may be
	// shorter. It is only meaningful when Segments is greater than one.
	SegmentSize int
}

// ForEach calls fn with every datagram the packet holds, in arrival order.
func (p Packet) ForEach(fn func(datagram []byte)) {
	remaining := p.Data
	if p.Segments <= 1 || p.SegmentSize <= 0 {
		fn(remaining)
		return
	}
	for range p.Segments {
		if len(remaining) == 0 {
			return
		}
		length := min(p.SegmentSize, len(remaining))
		fn(remaining[:length])
		remaining = remaining[length:]
	}
}

// Conn moves datagrams for one packet socket.
//
// A Conn is safe for concurrent use: several associations may share the socket
// of a listener, and each of them sends whenever it has something to say.
type Conn interface {
	// ReadPackets fills the given buffers from the socket. The returned slice
	// points into buffers and is only valid until the next call: a received
	// packet that is going to outlive it must be copied.
	//
	// The first buffer is used; the rest are there for an implementation that
	// reads more than one datagram per call. A caller that asks for merged
	// datagrams (GRO) has to make the first buffer large enough for the merge,
	// because a datagram that does not fit is truncated by the kernel.
	ReadPackets(buffers [][]byte) ([]Packet, error)

	// WritePackets sends every packet as its own datagram, in order.
	WritePackets(packets []Packet) error

	LocalAddr() net.Addr

	// Offload reports which batched paths are in use.
	Offload() (gso, gro bool)
}

// Options configures what a Conn may ask the socket for.
type Options struct {
	// GRO asks the kernel to merge consecutive datagrams into one read. It
	// changes what ReadPackets returns, so it is off by default: a caller that
	// does not split the result by Segments would read several datagrams as one.
	GRO bool

	// DisableGSO keeps the send path one datagram per call. It exists for tests
	// and for a caller that has already seen segmentation fail on this socket.
	DisableGSO bool
}

// New wraps a packet socket. It reports what the socket can do through Offload
// and never fails: a socket that cannot do any of it is still a socket.
func New(conn net.PacketConn, options Options) Conn {
	if conn == nil {
		return nil
	}
	batched := newBatched(conn, options)
	if batched != nil {
		return batched
	}
	return &plainConn{PacketConn: conn}
}

// plainConn moves one datagram per call. It is both the fallback for a socket
// whose file descriptor is out of reach and the reference implementation of
// what the batched paths must be equivalent to.
type plainConn struct {
	net.PacketConn
	one [1]Packet
}

func (c *plainConn) ReadPackets(buffers [][]byte) ([]Packet, error) {
	if len(buffers) == 0 {
		return nil, nil
	}
	n, addr, err := c.ReadFrom(buffers[0])
	if err != nil {
		return nil, err
	}
	c.one[0] = Packet{Data: buffers[0][:n], Addr: addr, Segments: 1}
	return c.one[:], nil
}

func (c *plainConn) WritePackets(packets []Packet) error {
	for _, packet := range packets {
		_, err := c.WriteTo(packet.Data, packet.Addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *plainConn) Offload() (bool, bool) { return false, false }
