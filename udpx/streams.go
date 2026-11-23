package udpx

import (
	"context"
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"
)

type streamTable struct {
	table map[uint32]*Stream

	nextID uint32

	openCredit uint32

	credit chan struct{}

	peerLimit uint32

	peerNext uint32

	accept chan *Stream

	initiatorBit uint32
}

func newStreamTable(isClient bool) streamTable {
	var initiatorBit uint32
	if !isClient {
		initiatorBit = streamInitiatorBit
	}
	return streamTable{
		table:        make(map[uint32]*Stream),
		openCredit:   initialStreams,
		credit:       make(chan struct{}),
		peerLimit:    initialStreams,
		accept:       make(chan *Stream, initialStreams),
		initiatorBit: initiatorBit,
	}
}

func (a *association) OpenStream(ctx context.Context) (*Stream, error) {
	for {
		a.streamsMu.Lock()
		if a.streams.nextID < a.streams.openCredit {
			id := a.streams.nextID<<1 | a.streams.initiatorBit
			a.streams.nextID++
			stream := newStream(a, id, initialStreamWindow)
			a.streams.table[id] = stream
			a.streamsMu.Unlock()
			return stream, nil
		}
		credit := a.streams.credit
		a.streamsMu.Unlock()
		select {
		case <-credit:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-a.ctx.Done():
			return nil, context.Cause(a.ctx)
		}
	}
}

func (a *association) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-a.streams.accept:
		a.acceptedStream(stream)
		return stream, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-a.ctx.Done():
		return nil, context.Cause(a.ctx)
	}
}

func (a *association) acceptedStream(stream *Stream) {
	a.streamsMu.Lock()
	stream.accepted = true
	_, live := a.streams.table[stream.id]
	if live {
		a.streamsMu.Unlock()
		return
	}
	a.streams.peerLimit++
	limit := a.streams.peerLimit
	a.streamsMu.Unlock()
	a.queueControl(appendMaxStreamsFrame(nil, limit), true)
}

func (a *association) stream(id uint32) *Stream {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	return a.streams.table[id]
}

func (a *association) removeStream(id uint32) bool {
	a.streamsMu.Lock()
	stream, loaded := a.streams.table[id]
	if loaded {
		delete(a.streams.table, id)
	}
	grant := loaded && stream.accepted && id&streamInitiatorBit != a.streams.initiatorBit
	if grant {
		a.streams.peerLimit++
	}
	limit := a.streams.peerLimit
	a.streamsMu.Unlock()
	if grant {
		a.queueControl(appendMaxStreamsFrame(nil, limit), true)
	}
	return loaded
}

func (a *association) acceptOpenedStream(id uint32) (*Stream, error) {
	index := id >> 1
	a.streamsMu.Lock()
	switch {
	case index < a.streams.peerNext:
		a.streamsMu.Unlock()
		return nil, nil
	case index >= a.streams.peerLimit:
		limit := a.streams.peerLimit
		a.streamsMu.Unlock()
		return nil, E.New("the peer opened stream ", index, " with a limit of ", limit)
	case index > a.streams.peerNext:
		next := a.streams.peerNext
		a.streamsMu.Unlock()
		return nil, E.New("the peer opened stream ", index, " after ", next-1)
	}
	a.streams.peerNext = index + 1
	stream := newStream(a, id, initialStreamWindow)
	a.streams.table[id] = stream
	a.streamsMu.Unlock()
	select {
	case a.streams.accept <- stream:
	default:
		a.removeStream(id)
		return nil, E.New("accept queue is full")
	}
	return stream, nil
}

func (a *association) handleMaxStreams(limit uint32) {
	a.streamsMu.Lock()
	if limit <= a.streams.openCredit {
		a.streamsMu.Unlock()
		return
	}
	a.streams.openCredit = limit
	close(a.streams.credit)
	a.streams.credit = make(chan struct{})
	a.streamsMu.Unlock()
}

func (a *association) notifyStreams() {
	a.streamsMu.Lock()
	streams := make([]*Stream, 0, len(a.streams.table))
	for _, stream := range a.streams.table {
		streams = append(streams, stream)
	}
	a.streamsMu.Unlock()
	for _, stream := range streams {
		stream.signalSend()
	}
}

func (a *association) handleStreamFrame(frameType byte, body []byte) error {
	if len(body) < 12 {
		return errShortFrame
	}
	data := parseStreamFrame(frameType, body)
	stream := a.stream(data.streamID)
	if stream == nil {
		if data.streamID&streamInitiatorBit == a.streams.initiatorBit {
			a.dataDropped(len(data.data))
			return nil
		}
		var err error
		stream, err = a.acceptOpenedStream(data.streamID)
		if err != nil {
			return err
		}
		if stream == nil {
			a.dataDropped(len(data.data))
			return nil
		}
	}
	received, err := stream.push(data.offset, data.data, data.fin)
	if err != nil {
		return err
	}
	return a.dataReceived(received)
}

func (a *association) handleResetStream(body []byte) error {
	if len(body) < 13 {
		return errShortFrame
	}
	reset := parseResetStream(body)
	stream := a.stream(reset.streamID)
	if stream == nil {
		return nil
	}
	stream.resetFromPeer(reset.finalOffset, reset.code)
	a.removeStream(reset.streamID)
	return nil
}

func (a *association) handleMaxStreamData(body []byte) error {
	if len(body) < 12 {
		return errShortFrame
	}
	streamID := binary.BigEndian.Uint32(body)
	limit := binary.BigEndian.Uint64(body[4:])
	stream := a.stream(streamID)
	if stream == nil {
		return nil
	}
	stream.giveSendCredit(limit)
	return nil
}
