package udpx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/pipe"

	E "github.com/sagernet/sing/common/exceptions"
)

// Streams
//
// A stream is a byte sequence in each direction, with its own window in each
// direction and nothing between the two halves except the stream id. Data arrives
// as offsets, so a hole is not an error: it is kept in the reassembly buffer and
// the bytes behind it wait, which is what keeps one retransmission from stalling
// everything that was sent after it.
//
// A stream closes in each direction separately. Closing the write half queues a FIN
// behind the data that is already there, and it is that FIN — not the close of the
// stream — that tells the peer the data is complete.
const (
	// streamInitiatorBit is the bit of a stream id that says which end opened the
	// stream.
	streamInitiatorBit = 0x01

	// maxStreamDataLen is how much stream data one frame may carry, so that a
	// frame always fits in a packet with the rest of what a packet holds.
	maxStreamDataLen = maxPacketSize - headerLen - tagLen - streamFixedLen
)

// Stream is one stream of an association: a net.Conn whose two halves close
// separately.
type Stream struct {
	association *association
	id          uint32

	// The send half: data the application wrote, the offset it goes to, and the
	// credit the peer granted for it.
	sendMu        sync.Mutex
	sendBuffer    []byte
	sendOffset    uint64
	sendCredit    credit
	closeWrite    bool
	finSent       bool
	writeDeadline pipe.Deadline

	// The recv half: data received out of order, how much was read, and the credit
	// this end granted.
	recvMu       sync.Mutex
	segments     []recvSegment
	readOffset   uint64
	recvHighest  uint64
	recvLimit    uint64
	finOffset    uint64
	finReceived  bool
	closed       bool
	readDeadline pipe.Deadline

	// notify is a single-slot channel: whoever waits on the stream waits for it,
	// and a second notification that arrives before the first was seen changes
	// nothing.
	notify chan struct{}
}

// recvSegment is a piece of a stream that arrived but was not read yet.
type recvSegment struct {
	data   []byte
	offset uint64
}

func newStream(association *association, id uint32, sendLimit uint64) *Stream {
	return &Stream{
		association:   association,
		id:            id,
		sendCredit:    credit{limit: sendLimit},
		recvLimit:     initialStreamWindow,
		writeDeadline: pipe.MakeDeadline(),
		readDeadline:  pipe.MakeDeadline(),
		notify:        make(chan struct{}, 1),
	}
}

// ID returns the identifier of the stream on the wire.
func (s *Stream) ID() uint32 {
	return s.id
}

func (s *Stream) LocalAddr() net.Addr {
	return s.association.LocalAddr()
}

func (s *Stream) RemoteAddr() net.Addr {
	return s.association.RemoteAddr()
}

func (s *Stream) SetDeadline(deadline time.Time) error {
	_ = s.SetReadDeadline(deadline)
	return s.SetWriteDeadline(deadline)
}

func (s *Stream) SetReadDeadline(deadline time.Time) error {
	s.readDeadline.Set(deadline)
	return nil
}

func (s *Stream) SetWriteDeadline(deadline time.Time) error {
	s.writeDeadline.Set(deadline)
	return nil
}

// Write sends data on the stream. It writes what the windows allow, waits for them
// to move forward when they do not, and returns a short write only at a deadline
// or when the association ended.
func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		allowed, err := s.queueData(p[written:])
		if err != nil {
			return written, err
		}
		written += allowed
		err = s.sendQueued()
		if err != nil {
			return written, err
		}
		if allowed == 0 {
			err = s.waitForCredit()
			if err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// queueData takes as much of p into the send buffer as the windows allow.
func (s *Stream) queueData(p []byte) (int, error) {
	select {
	case <-s.association.ctx.Done():
		return 0, context.Cause(s.association.ctx)
	default:
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closeWrite {
		return 0, net.ErrClosed
	}
	// Both windows have to allow the bytes: the stream's own, and the share of the
	// association window this stream is being given.
	allowed := min(s.sendCredit.available(), s.association.connectionCreditAvailable())
	allowed = min(allowed, uint64(len(p)))
	if allowed == 0 {
		return 0, nil
	}
	s.sendCredit.take(allowed)
	s.association.takeConnectionCredit(allowed)
	s.sendBuffer = append(s.sendBuffer, p[:allowed]...)
	s.sendOffset += allowed
	return int(allowed), nil
}

// waitForCredit waits until a window moves forward, the write deadline expires, or
// the association ends.
func (s *Stream) waitForCredit() error {
	select {
	case <-s.notify:
		return nil
	case <-s.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	case <-s.association.ctx.Done():
		return context.Cause(s.association.ctx)
	}
}

// sendQueued turns what the send buffer holds into stream frames and queues the FIN
// once everything before it left.
func (s *Stream) sendQueued() error {
	for {
		s.sendMu.Lock()
		var frame []byte
		if len(s.sendBuffer) > 0 {
			length := min(len(s.sendBuffer), maxStreamDataLen)
			frame = appendStream(nil, s.id, s.sendOffset-uint64(len(s.sendBuffer)), false, s.sendBuffer[:length])
			s.sendBuffer = s.sendBuffer[length:]
		} else if s.closeWrite && !s.finSent {
			// The FIN carries the offset the data ends at, so it does not have to
			// wait for anything else, only for the data before it to be framed.
			frame = appendStream(nil, s.id, s.sendOffset, true, nil)
			s.finSent = true
		}
		s.sendMu.Unlock()
		if frame == nil {
			return s.association.flush()
		}
		s.association.queueFrame(frame)
	}
}

// CloseWrite closes the write half: the peer reads what was written before it and
// then the end of the stream.
func (s *Stream) CloseWrite() error {
	s.sendMu.Lock()
	if s.closeWrite || s.finSent {
		s.sendMu.Unlock()
		return nil
	}
	s.closeWrite = true
	s.sendMu.Unlock()
	return s.sendQueued()
}

// Close closes both halves of the stream. The stream stays known until the peer's
// half of the connection is done with it, so that data still on its way is dropped
// rather than mistaken for a stream that was never opened.
func (s *Stream) Close() error {
	_ = s.CloseWrite()
	s.recvMu.Lock()
	s.closed = true
	s.segments = nil
	finished := s.finReceived
	s.recvMu.Unlock()
	s.signal()
	if finished {
		s.association.removeStream(s.id)
	}
	return nil
}

// Read reads data from the stream. It returns io.EOF once the peer closed its write
// half and everything it sent was read.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.recvMu.Lock()
		// Only data that starts where the last read ended is handed out: a hole
		// means the bytes behind it wait, however much of them already arrived.
		if len(s.segments) > 0 && s.segments[0].offset == s.readOffset {
			segment := s.segments[0]
			read := copy(p, segment.data)
			s.readOffset += uint64(read)
			// The segment moves with the read, so that a segment always covers the
			// offset the stream was read to and the next read can take it.
			s.segments[0].data = segment.data[read:]
			s.segments[0].offset = s.readOffset
			if len(s.segments[0].data) == 0 {
				s.segments = s.segments[1:]
			}
			limit, moved := s.windowMoved()
			s.recvMu.Unlock()
			if moved {
				_ = s.association.send(appendMaxStreamData(nil, s.id, limit))
			}
			s.association.dataRead(read)
			return read, nil
		}
		if s.finReceived && s.readOffset >= s.finOffset {
			s.recvMu.Unlock()
			return 0, io.EOF
		}
		if s.closed {
			s.recvMu.Unlock()
			return 0, net.ErrClosed
		}
		s.recvMu.Unlock()
		select {
		case <-s.notify:
		case <-s.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		case <-s.association.ctx.Done():
			return 0, context.Cause(s.association.ctx)
		}
	}
}

// push records data received from the peer, in whatever order it arrived, and
// returns how far the highest offset moved: the association window is counted in
// the offsets the peer reached rather than in bytes that landed, so a hole costs
// its bytes until it is filled, which is the conservative side to be on.
func (s *Stream) push(offset uint64, data []byte, fin bool) (int, error) {
	s.recvMu.Lock()
	end := offset + uint64(len(data))
	if end > s.recvLimit {
		s.recvMu.Unlock()
		return 0, E.New("stream ", s.id, " received up to ", end, " beyond its window ", s.recvLimit)
	}
	received := 0
	if end > s.recvHighest {
		received = int(end - s.recvHighest)
		s.recvHighest = end
	}
	switch {
	case s.closed:
		// The application is done with this stream; what is still on its way is
		// dropped, and the FIN is what lets the stream be forgotten.
	case len(data) > 0 && end > s.readOffset:
		if offset < s.readOffset {
			// Bytes the application already read are not stored again: a
			// retransmission that arrives after the fact is not an error.
			data = data[s.readOffset-offset:]
			offset = s.readOffset
		}
		s.insertSegment(recvSegment{offset: offset, data: append([]byte(nil), data...)})
	}
	if fin {
		// The end of the stream is an offset like any other: a FIN that arrives
		// before the data in front of it means the stream ended, not that
		// everything before it has been read.
		s.finReceived = true
		s.finOffset = end
	}
	sendFinished := s.finSent
	s.recvMu.Unlock()
	s.signal()
	if fin && sendFinished {
		s.association.removeStream(s.id)
	}
	return received, nil
}

// insertSegment places a segment in the reassembly buffer, which is kept sorted
// by offset and free of overlaps so that reading is a matter of taking whatever
// starts where the last read ended. The caller holds recvMu.
func (s *Stream) insertSegment(segment recvSegment) {
	end := segment.offset + uint64(len(segment.data))
	index := 0
	for index < len(s.segments) && s.segments[index].offset < segment.offset {
		index++
	}
	// Fold in every segment the new one reaches into or touches.
	for index < len(s.segments) && s.segments[index].offset <= end {
		overlapped := s.segments[index]
		overlappedEnd := overlapped.offset + uint64(len(overlapped.data))
		if overlappedEnd > end {
			segment.data = append(segment.data, overlapped.data[end-overlapped.offset:]...)
			end = overlappedEnd
		}
		s.segments = append(s.segments[:index], s.segments[index+1:]...)
	}
	// The segment in front of it may reach into the new one, which is what a
	// retransmission that overlaps what is already stored looks like.
	if index > 0 {
		previous := &s.segments[index-1]
		previousEnd := previous.offset + uint64(len(previous.data))
		if previousEnd >= segment.offset {
			if end > previousEnd {
				previous.data = append(previous.data, segment.data[previousEnd-segment.offset:]...)
			}
			return
		}
	}
	s.segments = append(s.segments, recvSegment{})
	copy(s.segments[index+1:], s.segments[index:])
	s.segments[index] = segment
}

// windowMoved reports whether the window this end granted has to be moved forward,
// and to where. The caller holds recvMu.
func (s *Stream) windowMoved() (uint64, bool) {
	if s.recvLimit-s.readOffset > initialStreamWindow/2 {
		return 0, false
	}
	s.recvLimit = s.readOffset + initialStreamWindow
	return s.recvLimit, true
}

// signal wakes whoever waits on the stream.
func (s *Stream) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// OpenStream opens a stream towards the peer.
func (a *association) OpenStream(ctx context.Context) (*Stream, error) {
	a.streamsMu.Lock()
	if len(a.streams) >= maxStreams {
		a.streamsMu.Unlock()
		return nil, E.New("too many open streams")
	}
	id := a.nextStreamID<<1 | a.initiatorBit()
	a.nextStreamID++
	stream := newStream(a, id, initialStreamWindow)
	a.streams[id] = stream
	a.streamsMu.Unlock()
	return stream, nil
}

// AcceptStream returns the next stream the peer opened.
func (a *association) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-a.acceptStream:
		return stream, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-a.ctx.Done():
		return nil, context.Cause(a.ctx)
	}
}

func (a *association) stream(id uint32) (*Stream, bool) {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	stream, loaded := a.streams[id]
	return stream, loaded
}

func (a *association) removeStream(id uint32) {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	delete(a.streams, id)
}

// initiatorBit is the bit of a stream id that says this end opened the stream.
func (a *association) initiatorBit() uint32 {
	if a.isClient {
		return 0
	}
	return streamInitiatorBit
}

// handleStreamFrame delivers a stream frame to its stream, opening the stream when
// the peer is the one that started it.
func (a *association) handleStreamFrame(data streamData) error {
	stream, loaded := a.stream(data.streamID)
	if !loaded {
		if data.streamID&streamInitiatorBit == a.initiatorBit() {
			return E.New("stream frame for stream ", data.streamID, " that was never opened")
		}
		var err error
		stream, err = a.acceptOpenedStream(data.streamID)
		if err != nil {
			return err
		}
	}
	received, err := stream.push(data.offset, data.data, data.fin)
	if err != nil {
		return err
	}
	return a.dataReceived(received)
}

// acceptOpenedStream records a stream the peer opened and hands it to the
// application.
func (a *association) acceptOpenedStream(id uint32) (*Stream, error) {
	a.streamsMu.Lock()
	if len(a.streams) >= maxStreams {
		a.streamsMu.Unlock()
		return nil, E.New("the peer opened more than ", maxStreams, " streams")
	}
	stream := newStream(a, id, initialStreamWindow)
	a.streams[id] = stream
	a.streamsMu.Unlock()
	select {
	case a.acceptStream <- stream:
		return stream, nil
	default:
		a.removeStream(id)
		return nil, E.New("accept queue is full")
	}
}

// handleMaxData moves the association window forward.
func (a *association) handleMaxData(limit uint64) {
	a.fcMu.Lock()
	moved := a.sendCredit.give(limit)
	a.fcMu.Unlock()
	if moved {
		a.notifyStreams()
	}
}

// handleMaxStreamData moves one stream's window forward.
func (a *association) handleMaxStreamData(streamID uint32, limit uint64) {
	stream, loaded := a.stream(streamID)
	if !loaded {
		return
	}
	stream.sendMu.Lock()
	moved := stream.sendCredit.give(limit)
	stream.sendMu.Unlock()
	if moved {
		stream.signal()
	}
}

// connectionCreditAvailable reports how much of the association window is left.
func (a *association) connectionCreditAvailable() uint64 {
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	return a.sendCredit.available()
}

func (a *association) takeConnectionCredit(n uint64) {
	a.fcMu.Lock()
	a.sendCredit.take(n)
	a.fcMu.Unlock()
}

// dataRead records bytes handed to an application and moves the association window
// forward once half of it was read.
func (a *association) dataRead(n int) {
	a.fcMu.Lock()
	a.recvRead += uint64(n)
	if a.recvLimit-a.recvRead > initialConnectionWindow/2 {
		a.fcMu.Unlock()
		return
	}
	a.recvLimit = a.recvRead + initialConnectionWindow
	limit := a.recvLimit
	a.fcMu.Unlock()
	_ = a.send(appendMaxData(nil, limit))
}

// dataReceived counts bytes that arrived for the first time, which is what the
// association window limits.
func (a *association) dataReceived(n int) error {
	if n == 0 {
		return nil
	}
	a.fcMu.Lock()
	defer a.fcMu.Unlock()
	a.recvReceived += uint64(n)
	if a.recvReceived > a.recvLimit {
		return E.New("association received ", a.recvReceived, " bytes beyond its window ", a.recvLimit)
	}
	return nil
}

// notifyStreams wakes every stream that waits for association credit.
func (a *association) notifyStreams() {
	a.streamsMu.Lock()
	streams := make([]*Stream, 0, len(a.streams))
	for _, stream := range a.streams {
		streams = append(streams, stream)
	}
	a.streamsMu.Unlock()
	for _, stream := range streams {
		stream.signal()
	}
}

// closeStreams ends every stream with the cause of the association, so that a
// reader or writer blocked on one sees why it stopped.
func (a *association) closeStreams(cause error) {
	a.streamsMu.Lock()
	streams := make([]*Stream, 0, len(a.streams))
	for _, stream := range a.streams {
		streams = append(streams, stream)
	}
	a.streams = make(map[uint32]*Stream)
	a.streamsMu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
}

// appendMaxData appends a frame that moves the association window forward.
func appendMaxData(dst []byte, limit uint64) []byte {
	dst = append(dst, byte(frameTypeMaxData))
	return binary.BigEndian.AppendUint64(dst, limit)
}

// appendMaxStreamData appends a frame that moves one stream's window forward.
func appendMaxStreamData(dst []byte, streamID uint32, limit uint64) []byte {
	dst = append(dst, byte(frameTypeMaxStreamData))
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	return binary.BigEndian.AppendUint64(dst, limit)
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ net.Conn           = (*Stream)(nil)
)
