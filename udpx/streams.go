package udpx

import (
	"context"
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"
)

// streamTable 的字段由 conn.streamsMu 保护。
type streamTable struct {
	table map[uint32]*Stream

	// 拨号方：可以打开的流数与额度
	nextID     uint32
	openCredit uint32
	credit     chan struct{}

	// 接听方：允许对端打开的流数，以及跳过的序号
	peerLimit uint32
	peerNext  uint32
	implicit  map[uint32]struct{}

	accept chan *Stream
}

func newStreamTable() streamTable {
	return streamTable{
		table:      make(map[uint32]*Stream),
		openCredit: initialStreams,
		credit:     make(chan struct{}),
		peerLimit:  initialStreams,
		implicit:   make(map[uint32]struct{}),
		accept:     make(chan *Stream, initialStreams),
	}
}

func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	if !c.initiator {
		return nil, E.New("only the dialing side can open a stream")
	}
	for {
		c.streamsMu.Lock()
		if c.streams.nextID < c.streams.openCredit {
			id := c.streams.nextID
			c.streams.nextID++
			stream := newStream(c, id)
			c.streams.table[id] = stream
			c.streamsMu.Unlock()
			c.openStreams.Add(1)
			c.queueData(newStreamFrame(stream, 0, false, nil))
			return stream, nil
		}
		credit := c.streams.credit
		c.streamsMu.Unlock()
		select {
		case <-credit:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-c.ctx.Done():
			return nil, context.Cause(c.ctx)
		}
	}
}

func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-c.streams.accept:
		c.acceptedStream(stream)
		return stream, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

func (c *Conn) acceptedStream(stream *Stream) {
	c.streamsMu.Lock()
	stream.accepted = true
	_, live := c.streams.table[stream.id]
	if live {
		c.streamsMu.Unlock()
		return
	}
	c.streams.peerLimit++
	limit := c.streams.peerLimit
	c.streamsMu.Unlock()
	c.queueControl(appendMaxStreamsFrame(nil, limit))
}

func (c *Conn) stream(id uint32) *Stream {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	return c.streams.table[id]
}

func (c *Conn) activeStreams() int {
	return int(c.openStreams.Load())
}

func (c *Conn) removeStream(id uint32) bool {
	c.streamsMu.Lock()
	stream, loaded := c.streams.table[id]
	if loaded {
		delete(c.streams.table, id)
	}
	grant := loaded && stream.accepted && !c.initiator
	if grant {
		c.streams.peerLimit++
	}
	limit := c.streams.peerLimit
	c.streamsMu.Unlock()
	if loaded {
		c.openStreams.Add(-1)
	}
	if grant {
		c.queueControl(appendMaxStreamsFrame(nil, limit))
	}
	return loaded
}

// acceptOpenedStream 按需建立对端打开的流：落后的序号记成已跳过，迟到的开流仍然接受。
func (c *Conn) acceptOpenedStream(id uint32) (*Stream, error) {
	c.streamsMu.Lock()
	switch {
	case id < c.streams.peerNext:
		if _, skipped := c.streams.implicit[id]; !skipped {
			c.streamsMu.Unlock()
			return nil, nil
		}
		delete(c.streams.implicit, id)
	case id >= c.streams.peerLimit:
		limit := c.streams.peerLimit
		c.streamsMu.Unlock()
		return nil, E.New("the peer opened stream ", id, " with a limit of ", limit)
	default:
		for skipped := c.streams.peerNext; skipped < id; skipped++ {
			c.streams.implicit[skipped] = struct{}{}
		}
		c.streams.peerNext = id + 1
	}
	stream := newStream(c, id)
	c.streams.table[id] = stream
	c.streamsMu.Unlock()
	c.openStreams.Add(1)
	select {
	case c.streams.accept <- stream:
	default:
		c.removeStream(id)
		return nil, E.New("accept queue is full")
	}
	return stream, nil
}

func (c *Conn) releaseImplicitStream(id uint32) {
	c.streamsMu.Lock()
	if _, skipped := c.streams.implicit[id]; !skipped {
		c.streamsMu.Unlock()
		return
	}
	delete(c.streams.implicit, id)
	c.streams.peerLimit++
	limit := c.streams.peerLimit
	c.streamsMu.Unlock()
	c.queueControl(appendMaxStreamsFrame(nil, limit))
}

func (c *Conn) handleMaxStreams(limit uint32) {
	c.streamsMu.Lock()
	if limit <= c.streams.openCredit {
		c.streamsMu.Unlock()
		return
	}
	c.streams.openCredit = limit
	close(c.streams.credit)
	c.streams.credit = make(chan struct{})
	c.streamsMu.Unlock()
}

func (c *Conn) notifyStreams() {
	c.streamsMu.Lock()
	streams := make([]*Stream, 0, len(c.streams.table))
	for _, stream := range c.streams.table {
		streams = append(streams, stream)
	}
	c.streamsMu.Unlock()
	for _, stream := range streams {
		stream.signalSend()
	}
}

func (c *Conn) handleStreamFrame(frameType byte, body []byte) error {
	if len(body) < 12 {
		return errShortFrame
	}
	data := parseStreamFrame(frameType, body)
	stream := c.stream(data.streamID)
	if stream == nil {
		if c.initiator {
			// 流只由拨号方打开：表里没有说明它已经关闭，丢弃数据并归还连接级额度。
			c.dataDropped(len(data.data))
			return nil
		}
		var err error
		stream, err = c.acceptOpenedStream(data.streamID)
		if err != nil {
			return err
		}
		if stream == nil {
			c.dataDropped(len(data.data))
			return nil
		}
	}
	received, err := stream.push(data.offset, data.data, data.fin)
	if err != nil {
		return err
	}
	return c.dataReceived(received)
}

func (c *Conn) handleResetStream(body []byte) error {
	if len(body) < 13 {
		return errShortFrame
	}
	reset := parseResetStream(body)
	stream := c.stream(reset.streamID)
	if stream == nil {
		c.releaseImplicitStream(reset.streamID)
		return nil
	}
	stream.resetFromPeer(reset.finalOffset)
	c.removeStream(reset.streamID)
	return nil
}

func (c *Conn) handleMaxStreamData(body []byte) error {
	if len(body) < 12 {
		return errShortFrame
	}
	streamID := binary.BigEndian.Uint32(body)
	limit := binary.BigEndian.Uint64(body[4:])
	stream := c.stream(streamID)
	if stream == nil {
		return nil
	}
	stream.giveSendCredit(limit)
	return nil
}
