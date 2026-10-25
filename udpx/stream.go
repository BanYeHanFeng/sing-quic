package udpx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
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
)

// streamDataLen is how much stream data one frame may carry, so that a frame always
// fits in a packet with the rest of what a packet holds. What a packet holds depends
// on whether this end protects its packets: the parity has to fit as well.
func (a *association) streamDataLen() int {
	return a.maxPayload - streamFixedLen
}

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
	readDeadline pipe.Deadline

	// endMu guards how the stream ended when it did not end by both halves
	// closing, which is either a reset from the peer or a close by the
	// application. Once done is closed the answer never changes, so whoever waits
	// on the stream waits on the channel and reads the reason afterwards.
	endMu  sync.Mutex
	endErr error
	done   chan struct{}

	// A notification channel per direction, each a single slot: a second
	// notification that arrives before the first was seen changes nothing. They
	// are apart because a reader and a writer wait on the same stream at the same
	// time, and one channel would let the reader take the notification the writer
	// was waiting for — a lost wakeup that leaves the writer waiting for credit
	// that already arrived.
	sendNotify chan struct{}
	recvNotify chan struct{}
}

// StreamResetError is how a stream ended when the peer reset it. A stream is not
// an association: the streams beside it and the association itself keep working,
// and the error is only what the connection this stream carried sees.
type StreamResetError struct {
	// Code is what the reset carried. Zero is a stream the peer was done with,
	// which is the normal end of one direction of a proxied connection rather
	// than a failure, so it is reported as a closed connection.
	Code uint8
}

func (e StreamResetError) Error() string {
	return "udpx: stream reset with code " + strconv.Itoa(int(e.Code))
}

func (e StreamResetError) Is(target error) bool {
	return e.Code == 0 && target == net.ErrClosed
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
		done:          make(chan struct{}),
		sendNotify:    make(chan struct{}, 1),
		recvNotify:    make(chan struct{}, 1),
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
	case <-s.done:
		return 0, s.endCause()
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
	case <-s.done:
		return s.endCause()
	case <-s.sendNotify:
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
		if s.isEnded() {
			return s.endCause()
		}
		s.sendMu.Lock()
		var frame []byte
		if len(s.sendBuffer) > 0 {
			length := min(len(s.sendBuffer), s.association.streamDataLen())
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

// Close closes both halves of the stream: what was written is completed with a FIN,
// and the peer is told that this end will read no more.
//
// The peer has to hear about it, unless its half was already complete: a stream that
// ended on both sides needs no announcement, while one the application abandoned
// would otherwise keep the peer writing into a stream nobody reads, and the entry
// would stay here until the association closed.
func (s *Stream) Close() error {
	_ = s.CloseWrite()
	s.recvMu.Lock()
	finished := s.finReceived && s.readOffset >= s.finOffset
	s.recvMu.Unlock()
	s.end(net.ErrClosed)
	s.discardUnread()
	if finished {
		s.association.removeStream(s.id)
	} else {
		s.association.resetStream(s.id)
	}
	return nil
}

// Read reads data from the stream. It returns io.EOF once the peer closed its write
// half and everything it sent was read, and the reset error when the peer ended the
// stream without completing it. Data that arrived before either is handed out
// first: a stream that ended still has what already arrived.
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
		s.recvMu.Unlock()
		select {
		case <-s.done:
			return 0, s.endCause()
		case <-s.recvNotify:
		case <-s.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		case <-s.association.ctx.Done():
			return 0, context.Cause(s.association.ctx)
		}
	}
}

// end records why the stream ended, which is what a reset from the peer and a
// close by the application have in common: what was written and not yet framed is
// dropped, and whoever waits on the stream wakes up with the reason.
func (s *Stream) end(cause error) {
	s.endMu.Lock()
	if s.endErr != nil {
		s.endMu.Unlock()
		return
	}
	s.endErr = cause
	close(s.done)
	s.endMu.Unlock()
	s.sendMu.Lock()
	s.sendBuffer = nil
	s.sendMu.Unlock()
	s.signalSend()
	s.signalRecv()
}

// discardUnread drops what arrived and was not read. Closing a stream is what
// calls it: the application is done, and the bytes the segments hold have to go
// back to the association window instead of staying spent until the association
// closes.
func (s *Stream) discardUnread() {
	s.recvMu.Lock()
	dropped := 0
	for _, segment := range s.segments {
		dropped += len(segment.data)
	}
	s.segments = nil
	s.recvMu.Unlock()
	if dropped > 0 {
		s.association.dataRead(dropped)
	}
}

// resetFromPeer ends the stream because the peer said it is done with it. What
// already arrived stays readable, because it is data the peer wrote and sent
// before it gave up on the stream.
func (s *Stream) resetFromPeer(code resetCode) {
	s.end(code.err())
}

// isEnded reports whether the stream ended, without waiting for it.
func (s *Stream) isEnded() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// endCause is why the stream ended, or nil while it did not.
func (s *Stream) endCause() error {
	s.endMu.Lock()
	defer s.endMu.Unlock()
	return s.endErr
}

// push records data received from the peer, in whatever order it arrived, and
// returns how far the highest offset moved: the association window is counted in
// the offsets the peer reached rather than in bytes that landed, so a hole costs
// its bytes until it is filled, which is the conservative side to be on.
func (s *Stream) push(offset uint64, data []byte, fin bool) (int, error) {
	// A stream the application is done with has no reader left, so what is still
	// on its way for it is dropped rather than stored.
	if s.isEnded() {
		return 0, nil
	}
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
	if len(data) > 0 && end > s.readOffset {
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
	s.recvMu.Unlock()
	s.signalRecv()
	if fin && s.finQueued() {
		// Both halves are done: nothing is left that either end could wait for.
		s.association.removeStream(s.id)
	}
	return received, nil
}

// finQueued reports whether the FIN was already framed, which is what says the
// write half of the stream is complete.
func (s *Stream) finQueued() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.finSent
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

// signalSend wakes the writer: credit moved forward, or the stream ended.
func (s *Stream) signalSend() {
	select {
	case s.sendNotify <- struct{}{}:
	default:
	}
}

// signalRecv wakes the reader: data arrived, or the stream ended.
func (s *Stream) signalRecv() {
	select {
	case s.recvNotify <- struct{}{}:
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

// endedStreams remembers the streams that ended recently.
//
// A stream ends here before the peer hears about it, so what it already sent for
// it keeps arriving for a while. Without a memory of the end, a frame for an
// ended stream looks exactly like the first frame of a stream being opened, and
// the application would be handed bytes it already read. The memory is a fixed
// ring, because a peer that opens streams forever must not grow the association;
// what arrives after the whole ring turned over is dropped too, and by then the
// path kept it longer than any reordering.
const endedStreamsCount = 64

type endedStreams struct {
	ids    [endedStreamsCount]uint32
	filled int
	next   int
}

func (e *endedStreams) add(id uint32) {
	e.ids[e.next] = id
	e.next = (e.next + 1) % endedStreamsCount
	if e.filled < endedStreamsCount {
		e.filled++
	}
}

func (e *endedStreams) has(id uint32) bool {
	for _, ended := range e.ids[:e.filled] {
		if ended == id {
			return true
		}
	}
	return false
}

// removeStream forgets a stream that ended, which frees both the entry and the
// slot it held against maxStreams.
func (a *association) removeStream(id uint32) {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	delete(a.streams, id)
	a.endedStreams.add(id)
}

// streamEnded reports whether a stream ended recently, which is what a frame that
// arrives for a stream this end no longer knows is checked against.
func (a *association) streamEnded(id uint32) bool {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	return a.endedStreams.has(id)
}

// resetStream ends a stream the application abandoned: the peer is told to stop
// writing into it, and the stream is forgotten here at once rather than when the
// peer's half closes, which may never happen.
func (a *association) resetStream(id uint32) {
	a.removeStream(id)
	_ = a.send(appendResetStream(nil, id, resetCodeNormal))
}

// handleResetStream ends a stream the peer is done with. The stream is one stream,
// not the association: what is on its way out stops, and the application sees the
// code instead of the rest of the data.
func (a *association) handleResetStream(reset streamReset) {
	stream, loaded := a.stream(reset.streamID)
	if !loaded {
		return
	}
	stream.resetFromPeer(reset.code)
	a.removeStream(reset.streamID)
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
		// A stream that just ended is not a stream the peer is opening now: what
		// is still in flight for it arrives after the end and is dropped, the
		// same way a stream that ended on both sides drops it.
		if a.streamEnded(data.streamID) {
			return nil
		}
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
		stream.signalSend()
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
		stream.signalSend()
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
