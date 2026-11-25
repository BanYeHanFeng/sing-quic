package udpx

import (
	"context"
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"
)

// outboundStreamGate 是拨号方的开流额度，字段由 conn.streamsMu 保护。
type outboundStreamGate struct {
	next       uint32        // 下一个要打开的流 ID
	credit     uint32        // 对端允许本端打开的数量
	creditWait chan struct{} // 额度增加时关闭重建
}

// inboundStreamGate 是接听方的接受额度，字段由 conn.streamsMu 保护。
type inboundStreamGate struct {
	limit   uint32              // 本端允许对端打开的数量
	next    uint32              // 对端已出现的最大流 ID + 1
	skipped map[uint32]struct{} // 对端跳过、尚未出现的 ID
}

func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	if !c.initiator {
		return nil, E.New("only the dialing side can open a stream")
	}
	for {
		c.streamsMu.Lock()
		if c.outbound.next < c.outbound.credit {
			id := c.outbound.next
			c.outbound.next++
			stream := newStream(c, id)
			c.streams[id] = stream
			c.streamsMu.Unlock()
			c.openStreams.Add(1)
			c.queueData(newStreamFrame(stream, 0, false, nil))
			return stream, nil
		}
		creditWait := c.outbound.creditWait
		c.streamsMu.Unlock()
		select {
		case <-creditWait:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-c.ctx.Done():
			return nil, context.Cause(c.ctx)
		}
	}
}

func (c *Conn) stream(id uint32) *Stream {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	return c.streams[id]
}

func (c *Conn) activeStreams() int {
	return int(c.openStreams.Load())
}

// removeStream 把流移出表；对端开的一条流被移除时额度加一并发 MAX_STREAMS。
func (c *Conn) removeStream(id uint32) bool {
	c.streamsMu.Lock()
	_, loaded := c.streams[id]
	if loaded {
		delete(c.streams, id)
	}
	grant := loaded && !c.initiator
	if grant {
		c.inbound.limit++
	}
	limit := c.inbound.limit
	c.streamsMu.Unlock()
	if loaded {
		c.openStreams.Add(-1)
	}
	if grant {
		c.queueControl(appendMaxStreamsFrame(nil, limit))
	}
	return loaded
}

// acceptOpenedStream 建立对端打开的流：落后的序号记成已跳过，迟到的开流仍然接受。
// 流一建立就算被接受，交接给 handler。
func (c *Conn) acceptOpenedStream(id uint32) (*Stream, error) {
	c.streamsMu.Lock()
	switch {
	case id < c.inbound.next:
		if _, skipped := c.inbound.skipped[id]; !skipped {
			c.streamsMu.Unlock()
			return nil, nil
		}
		delete(c.inbound.skipped, id)
	case id >= c.inbound.limit:
		limit := c.inbound.limit
		c.streamsMu.Unlock()
		return nil, E.New("the peer opened stream ", id, " with a limit of ", limit)
	default:
		for skipped := c.inbound.next; skipped < id; skipped++ {
			c.inbound.skipped[skipped] = struct{}{}
		}
		c.inbound.next = id + 1
	}
	stream := newStream(c, id)
	c.streams[id] = stream
	c.streamsMu.Unlock()
	c.openStreams.Add(1)
	go c.handler.OnStream(c, stream)
	return stream, nil
}

func (c *Conn) releaseSkippedStream(id uint32) {
	c.streamsMu.Lock()
	if _, skipped := c.inbound.skipped[id]; !skipped {
		c.streamsMu.Unlock()
		return
	}
	delete(c.inbound.skipped, id)
	c.inbound.limit++
	limit := c.inbound.limit
	c.streamsMu.Unlock()
	c.queueControl(appendMaxStreamsFrame(nil, limit))
}

func (c *Conn) handleMaxStreams(limit uint32) {
	c.streamsMu.Lock()
	if limit <= c.outbound.credit {
		c.streamsMu.Unlock()
		return
	}
	c.outbound.credit = limit
	close(c.outbound.creditWait)
	c.outbound.creditWait = make(chan struct{})
	c.streamsMu.Unlock()
}

func (c *Conn) notifyStreams() {
	c.streamsMu.Lock()
	streams := make([]*Stream, 0, len(c.streams))
	for _, stream := range c.streams {
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
		c.releaseSkippedStream(reset.streamID)
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
