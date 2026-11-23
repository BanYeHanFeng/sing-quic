package udpio

import "net"

type Packet struct {
	Data []byte

	Addr net.Addr

	Segments int

	SegmentSize int
}

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

type Conn interface {
	ReadPackets(buffers [][]byte) ([]Packet, error)

	WritePackets(packets []Packet) error

	LocalAddr() net.Addr

	Offload() (gso, gro bool)
}

type Options struct {
	GRO bool
}

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
