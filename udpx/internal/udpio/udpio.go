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

// Conn 批量收发 UDP 包：ReadPacket 一次读入一个缓冲，GRO 合并出来的多个数据报用 Packet.ForEach 拆开。
type Conn interface {
	ReadPacket(buffer []byte) (Packet, error)

	// WritePackets 顺序写出整批包，返回出错前已经写出的包数。
	WritePackets(packets []Packet) (written int, err error)

	Offload() (gso, gro bool)
}

func New(conn net.PacketConn) Conn {
	if conn == nil {
		return nil
	}
	batched := newBatched(conn)
	if batched != nil {
		return batched
	}
	return &plainConn{PacketConn: conn}
}

type plainConn struct {
	net.PacketConn
}

func (c *plainConn) ReadPacket(buffer []byte) (Packet, error) {
	n, addr, err := c.ReadFrom(buffer)
	if err != nil {
		return Packet{}, err
	}
	return Packet{Data: buffer[:n], Addr: addr, Segments: 1}, nil
}

func (c *plainConn) WritePackets(packets []Packet) (int, error) {
	for index, packet := range packets {
		_, err := c.WriteTo(packet.Data, packet.Addr)
		if err != nil {
			return index, err
		}
	}
	return len(packets), nil
}

func (c *plainConn) Offload() (bool, bool) { return false, false }
