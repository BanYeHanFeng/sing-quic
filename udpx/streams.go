package udpx

import (
	"context"
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"
)

type streamTable struct {
	table map[uint32]*Stream

	implicit map[uint32]struct{}

	nextID uint32

	openCredit uint32

	credit chan struct{}

	peerLimit uint32

	peerNext uint32

	accept chan *Stream

	initiatorBit uint32
}

func newStreamTable(initiator bool) streamTable {
	var initiatorBit uint32
	if !initiator {
		initiatorBit = streamInitiatorBit
	}
	return streamTable{
		table:        make(map[uint32]*Stream),
		implicit:     make(map[uint32]struct{}),
		openCredit:   initialStreams,
		credit:       make(chan struct{}),
		peerLimit:    initialStreams,
		accept:       make(chan *Stream, initialStreams),
		initiatorBit: initiatorBit,
	}
}

func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	for {
		c.streamsMu.Lock()
		if c.streams.nextID < c.streams.openCredit {
			id := c.streams.nextID<<1 | c.streams.initiatorBit
			c.streams.nextID++
			stream := newStream(c, id, initialStreamWindow)
			c.streams.table[id] = stream
			c.streamsMu.Unlock()
			c.queueStreamFrame(newStreamFrame(stream, 0, false, nil))
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
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	return len(c.streams.table)
}

func (c *Conn) removeStream(id uint32) bool {
	c.streamsMu.Lock()
	stream, loaded := c.streams.table[id]
	if loaded {
		delete(c.streams.table, id)
	}
	grant := loaded && stream.accepted && id&streamInitiatorBit != c.streams.initiatorBit
	if grant {
		c.streams.peerLimit++
	}
	limit := c.streams.peerLimit
	c.streamsMu.Unlock()
	if grant {
		c.queueControl(appendMaxStreamsFrame(nil, limit))
	}
	return loaded
}

func (c *Conn) acceptOpenedStream(id uint32) (*Stream, error) {
	index := id >> 1
	c.streamsMu.Lock()
	switch {
	case index < c.streams.peerNext:
		if _, implicit := c.streams.implicit[id]; !implicit {
			c.streamsMu.Unlock()
			return nil, nil
		}
		delete(c.streams.implicit, id)
	case index >= c.streams.peerLimit:
		limit := c.streams.peerLimit
		c.streamsMu.Unlock()
		return nil, E.New("the peer opened stream ", index, " with a limit of ", limit)
	default:
		for skipped := c.streams.peerNext; skipped < index; skipped++ {
			c.streams.implicit[skipped<<1|(id&streamInitiatorBit)] = struct{}{}
		}
		c.streams.peerNext = index + 1
	}
	stream := newStream(c, id, initialStreamWindow)
	c.streams.table[id] = stream
	c.streamsMu.Unlock()
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
	if _, implicit := c.streams.implicit[id]; !implicit {
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
		if data.streamID&streamInitiatorBit == c.streams.initiatorBit {
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
