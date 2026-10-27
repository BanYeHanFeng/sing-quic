package udpx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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

// sendChunkSize is how much one chunk of a send buffer holds. A chunk is the unit
// that is taken from the pool and given back, so it is sized to stay worth keeping
// whole: a write of a few kilobytes leaves most of one behind, and the next write
// fills that part instead of taking another.
const sendChunkSize = 64 << 10

// sendChunk is one chunk of a stream's send buffer: the bytes the application wrote
// and the frames cut from them.
//
// It counts the holders that still read from it, because the memory is handed out
// again as soon as there are none: the send buffer drops a chunk when it has framed
// all of it, and every frame cut from it drops it again when the peer acknowledged
// that frame. A write lives until the last frame carrying it is acknowledged, and
// that lifetime used to be left to the garbage collector — which meant a fresh
// allocation of the whole write, a gigabyte of garbage for every gigabyte sent.
type sendChunk struct {
	buf []byte
	// start is where the next frame begins and end is where the bytes that were
	// written end, so what is left to frame is buf[start:end].
	start int
	end   int
	// holds is how many holders the chunk has: the send buffer while it still has
	// bytes to frame, plus one for every frame cut from it that the peer has not
	// acknowledged yet.
	holds atomic.Int32
}

// sendChunkPool recycles the chunks of every stream. A chunk is in the pool only
// while nothing reads from it, so what it hands out needs no clearing: whoever
// takes it writes over the part it uses before that part is read.
var sendChunkPool = sync.Pool{
	New: func() any {
		sendChunksAllocated.Add(1)
		return &sendChunk{buf: make([]byte, sendChunkSize)}
	},
}

// sendChunksAllocated counts the chunks the pool had to make, which is what says
// whether the memory a transfer went into was reused: what the peer acknowledged is
// back in the pool, so the same transfer made again allocates nothing. It is a
// number for the tests, and one add per chunk is nothing next to copying it.
var sendChunksAllocated atomic.Int64

// retain records one more holder of the chunk.
func (c *sendChunk) retain() {
	c.holds.Add(1)
}

// release gives up one holder of the chunk, and gives the chunk back to the pool
// once the last one is gone.
func (c *sendChunk) release() {
	if c.holds.Add(-1) != 0 {
		return
	}
	c.start = 0
	c.end = 0
	sendChunkPool.Put(c)
}

// Stream is one stream of an association: a net.Conn whose two halves close
// separately.
type Stream struct {
	association *association
	id          uint32

	// The send half: data the application wrote, the offset it goes to, and the
	// credit the peer granted for it.
	sendMu        sync.Mutex
	sendChunks    []*sendChunk
	sendOffset    uint64
	sendFramed    uint64
	sendCredit    credit
	closeWrite    bool
	finSent       bool
	writeDeadline pipe.Deadline

	// The recv half: data received out of order, how much was read, and the credit
	// this end granted. recvWindow is the budget this end allows the stream to cost,
	// and recvLimit is the ceiling the peer was last told about, which is what the
	// credit it may still spend is counted against.
	recvMu       sync.Mutex
	segments     []recvSegment
	readOffset   uint64
	recvHighest  uint64
	recvLimit    uint64
	recvWindow   uint64
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

	// queued says the stream is still in the accept queue, which is what keeps its
	// place against the peer's stream limit until the application takes it: a stream
	// that ends while it waits is still queued, and handing the place back then would
	// let the peer open one more than the queue can hold. The association's
	// streamsMu guards it.
	queued bool

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

// recvSegment is a piece of a stream that arrived but was not read yet. Segments are
// kept apart rather than folded into one buffer: folding means copying everything
// already received every time data arrives in order, which on a bulk transfer is the
// whole window copied again and again.
type recvSegment struct {
	data   []byte
	offset uint64
	// buffer is what data is a window into. A segment is read from its front, so what
	// is left of it has to know which slice to hand back once it is empty.
	buffer []byte
}

// recvSegmentPool recycles the buffers segments are copied into. A receiver of bulk
// data takes one buffer per packet, and a receiver that allocates them instead spends
// more time collecting garbage than copying: a gigabyte of transfer would be a
// gigabyte of garbage, freed as fast as it is made.
var recvSegmentPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, maxPacketSize)
		return &buffer
	},
}

// storeSegment copies a run of received bytes into a buffer of its own, because the
// buffer the packet was read into is the next packet's buffer as well.
func (s *Stream) storeSegment(offset uint64, data []byte) {
	var buffer []byte
	if len(data) <= maxPacketSize {
		pooled := recvSegmentPool.Get().(*[]byte)
		buffer = (*pooled)[:len(data)]
	} else {
		buffer = make([]byte, len(data))
	}
	copy(buffer, data)
	s.insertSegment(recvSegment{data: buffer, offset: offset, buffer: buffer})
}

// releaseSegment hands a buffer back once nothing reads from it any more.
func releaseSegment(segment recvSegment) {
	if cap(segment.buffer) != maxPacketSize {
		return
	}
	buffer := segment.buffer[:maxPacketSize]
	recvSegmentPool.Put(&buffer)
}

func newStream(association *association, id uint32, sendLimit uint64) *Stream {
	return &Stream{
		association:   association,
		id:            id,
		sendCredit:    credit{limit: sendLimit},
		recvLimit:     initialStreamWindow,
		recvWindow:    streamWindow,
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
	// One copy per write, into the send buffer: the bytes have to be taken over
	// here because the caller may reuse its slice as soon as this returns, and they
	// have to live until the last frame cut from them is acknowledged. The chunks
	// they are copied into are recycled, which is what keeps a transfer from
	// allocating a copy of everything it sends.
	s.bufferSendData(p[:allowed])
	s.sendOffset += allowed
	return int(allowed), nil
}

// bufferSendData copies p into the send buffer, filling whatever room the last
// chunk has left before taking another one from the pool. The caller holds sendMu.
func (s *Stream) bufferSendData(p []byte) {
	for len(p) > 0 {
		if count := len(s.sendChunks); count == 0 || s.sendChunks[count-1].end == len(s.sendChunks[count-1].buf) {
			chunk := sendChunkPool.Get().(*sendChunk)
			chunk.retain()
			s.sendChunks = append(s.sendChunks, chunk)
		}
		last := s.sendChunks[len(s.sendChunks)-1]
		written := copy(last.buf[last.end:], p)
		last.end += written
		p = p[written:]
	}
}

// releaseSendChunks drops what was written and not framed, and with it the hold the
// send buffer has on the chunks that hold those bytes. The frames already cut from
// them hold it themselves, so the memory still lives until the peer acknowledged
// what was sent.
func (s *Stream) releaseSendChunks() {
	for index, chunk := range s.sendChunks {
		s.sendChunks[index] = nil
		chunk.release()
	}
	s.sendChunks = nil
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
		var frame streamFrame
		if len(s.sendChunks) > 0 {
			head := s.sendChunks[0]
			pending := head.buf[head.start:head.end]
			length := min(len(pending), s.association.streamDataLen())
			// The frame holds the chunk it was cut from, which is what keeps the
			// bytes alive from here until the peer acknowledged them.
			head.retain()
			frame = streamFrame{
				carried:  true,
				data:     pending[:length],
				chunk:    head,
				offset:   s.sendFramed,
				streamID: s.id,
			}
			s.sendFramed += uint64(length)
			head.start += length
			if head.start == head.end {
				s.sendChunks = s.sendChunks[1:]
				// The send buffer is done with the chunk; the frames cut from it
				// still hold it themselves.
				head.release()
			}
		} else if s.closeWrite && !s.finSent {
			// The FIN carries the offset the data ends at, so it does not have to
			// wait for anything else, only for the data before it to be framed.
			frame = streamFrame{
				carried:  true,
				offset:   s.sendOffset,
				streamID: s.id,
				fin:      true,
			}
			s.finSent = true
		}
		s.sendMu.Unlock()
		if !frame.carried {
			return s.association.flush()
		}
		s.association.queueStreamFrame(frame)
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
			// A read takes everything that follows the last one, which is several
			// segments when the data arrived in packets smaller than the caller's
			// buffer. Each segment moves with the read, so that a segment always
			// covers the offset the stream was read to.
			read := 0
			for read < len(p) && len(s.segments) > 0 && s.segments[0].offset == s.readOffset+uint64(read) {
				segment := s.segments[0]
				copied := copy(p[read:], segment.data)
				read += copied
				segment.data = segment.data[copied:]
				segment.offset += uint64(copied)
				if len(segment.data) == 0 {
					releaseSegment(segment)
					s.segments = s.segments[1:]
					continue
				}
				s.segments[0] = segment
			}
			s.readOffset += uint64(read)
			s.recvMu.Unlock()
			s.association.dataRead(read)
			s.endIfDone()
			s.moveWindow()
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
	s.releaseSendChunks()
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
		releaseSegment(segment)
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
		s.storeSegment(offset, data)
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
	s.moveWindow()
	if fin {
		s.endIfDone()
	}
	return received, nil
}

// endIfDone drops the stream from the table once there is nothing left for either
// end to do with it: the peer closed its half, this end closed its own, and
// everything the peer sent was handed to the application.
//
// The last part is what makes this the end and not the FIN. A FIN is an offset like
// any other, so it can arrive before the data in front of it — and then the stream
// still has to receive that data long after it closed its own half. Dropping it on
// the FIN alone loses what is still on the way, which is a read that never ends.
func (s *Stream) endIfDone() {
	s.recvMu.Lock()
	delivered := s.finReceived && s.readOffset >= s.finOffset
	s.recvMu.Unlock()
	if delivered && s.finQueued() {
		s.association.removeStream(s.id)
	}
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
	// Data that arrives in order goes at the end, which is the case that matters:
	// the list would otherwise be scanned from its front for every packet.
	if count := len(s.segments); count > 0 {
		last := s.segments[count-1]
		if last.offset+uint64(len(last.data)) <= segment.offset {
			s.segments = append(s.segments, segment)
			return
		}
	}
	end := segment.offset + uint64(len(segment.data))
	index := 0
	for index < len(s.segments) && s.segments[index].offset < segment.offset {
		index++
	}
	// What a retransmission repeats is dropped rather than folded in: the bytes are
	// the same ones, and one copy of them is enough.
	if index > 0 {
		previous := s.segments[index-1]
		previousEnd := previous.offset + uint64(len(previous.data))
		if previousEnd > segment.offset {
			skip := previousEnd - segment.offset
			if skip >= uint64(len(segment.data)) {
				releaseSegment(segment)
				return
			}
			segment.data = segment.data[skip:]
			segment.offset = previousEnd
		}
	}
	for index < len(s.segments) {
		following := s.segments[index]
		if following.offset >= end {
			break
		}
		followingEnd := following.offset + uint64(len(following.data))
		if followingEnd <= end {
			// Wholly covered by the new segment, so the bytes are the same ones.
			releaseSegment(following)
			s.segments = append(s.segments[:index], s.segments[index+1:]...)
			continue
		}
		// Half covered: keep the new one up to where the stored one starts.
		segment.data = segment.data[:following.offset-segment.offset]
		end = following.offset
		break
	}
	if len(segment.data) == 0 {
		releaseSegment(segment)
		return
	}
	s.segments = append(s.segments, recvSegment{})
	copy(s.segments[index+1:], s.segments[index:])
	s.segments[index] = segment
}

// windowMoved reports whether the credit this end granted has to be moved forward, and
// to where. The caller holds recvMu.
//
// The credit moves as far as the peer got, not as far as the application read: what the
// application can read is what arrived in order, and on a path that loses packets a hole
// stops it while the data behind the hole is already here. Credit that followed the read
// would wait for a retransmission to move at all, and the peer would spend every round
// trip waiting for credit this end is holding for a hole. What bounds the memory
// instead is the read: the ceiling never goes further than two windows past it, one for
// what the peer may have in flight and one for what arrived behind a hole and is waiting
// to be read.
func (s *Stream) windowMoved() (uint64, bool) {
	if s.recvLimit-s.recvHighest > s.recvWindow/2 {
		return 0, false
	}
	limit := min(s.recvHighest+s.recvWindow, s.readOffset+2*s.recvWindow)
	if limit <= s.recvLimit {
		// The read is what holds the ceiling where it is, so there is nothing new to
		// tell the peer: an announcement that carries the ceiling it already has is a
		// frame per packet while an application is not reading.
		return 0, false
	}
	s.recvLimit = limit
	return limit, true
}

// moveWindow tells the peer about the credit this stream has now. Both halves call it:
// an arrival is what moves the ceiling on a path that is being read as fast as it
// arrives, and a read is the only thing that can move it when the buffer bound is what
// holds it — the peer that is waiting at that bound has nothing left to send, so
// waiting for an arrival would be waiting for the peer to unblock itself.
func (s *Stream) moveWindow() {
	s.recvMu.Lock()
	limit, moved := s.windowMoved()
	s.recvMu.Unlock()
	if moved {
		_ = s.association.send(appendMaxStreamData(nil, s.id, limit))
	}
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

// OpenStream opens a stream towards the peer. It waits while the peer allows no more
// streams: the peer is the one that remembers them, so the number it announced is
// what this end stays inside, and a caller with more connections than that waits for
// the ones in front of it to end rather than being told to go away.
func (a *association) OpenStream(ctx context.Context) (*Stream, error) {
	for {
		a.streamsMu.Lock()
		if a.nextStreamID < a.openCredit {
			id := a.nextStreamID<<1 | a.initiatorBit()
			a.nextStreamID++
			stream := newStream(a, id, initialStreamWindow)
			a.streams[id] = stream
			a.streamsMu.Unlock()
			return stream, nil
		}
		credit := a.streamCredit
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

// AcceptStream returns the next stream the peer opened.
func (a *association) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-a.acceptStream:
		a.acceptedStream(stream)
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

// endedStreams remembers the streams the peer opened that ended recently.
//
// A stream ends here before the peer hears about it, so what it already sent for
// it keeps arriving for a while. Without a memory of the end, a frame for an
// ended stream looks exactly like the first frame of a stream being opened, and
// the application would be handed bytes it already read. The memory is a fixed
// ring, because a peer that opens streams forever must not grow the association.
// A frame for an id the ring forgot opens a stream that is empty or already
// served, which is noise rather than a stall — and it is the price of the only
// thing that can tell a late frame from a new stream: the peer opens its streams
// in order but its frames arrive out of order, so an id below the highest one it
// opened may still be one this end has never seen.
//
// The streams this end opened need no ring: their ids are counted, so the count
// says whether one existed.
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

// removeStream forgets a stream that ended, which frees the entry and, for a stream
// the peer opened, the slot it held against the stream budget.
func (a *association) removeStream(id uint32) {
	a.streamsMu.Lock()
	stream, loaded := a.streams[id]
	delete(a.streams, id)
	peerStream := id&streamInitiatorBit != a.initiatorBit()
	if peerStream {
		a.endedStreams.add(id)
	}
	freed := loaded && !stream.queued && peerStream
	if freed {
		// The peer may open one more now that this one is gone for good.
		a.peerStreamLimit++
	}
	limit := a.peerStreamLimit
	a.streamsMu.Unlock()
	if freed {
		_ = a.send(appendMaxStreams(nil, limit))
	}
}

// acceptedStream takes one stream out of the accept queue. A stream that ended while
// it waited was removed from the table without its slot being freed, because the
// queue was still holding it; the place is free now.
func (a *association) acceptedStream(stream *Stream) {
	a.streamsMu.Lock()
	stream.queued = false
	_, live := a.streams[stream.id]
	freed := !live
	if freed {
		a.peerStreamLimit++
	}
	limit := a.peerStreamLimit
	a.streamsMu.Unlock()
	if freed {
		_ = a.send(appendMaxStreams(nil, limit))
	}
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
		if data.streamID&streamInitiatorBit == a.initiatorBit() {
			// A stream this end opened, which it no longer has: the ids of them are
			// counted, so the count is what says whether this one existed. A frame
			// for one that did is what the peer sent before it heard about the end,
			// however many streams ended here since.
			if data.streamID>>1 < a.nextStreamID {
				return nil
			}
			return E.New("stream frame for stream ", data.streamID, " that was never opened")
		}
		// A stream that just ended is not a stream the peer is opening now: what
		// is still in flight for it arrives after the end and is dropped, the
		// same way a stream that ended on both sides drops it.
		if a.streamEnded(data.streamID) {
			return nil
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
// application. A stream beyond the number this end allowed is a peer that does not
// stay inside what it was told, and that is the whole association's problem.
func (a *association) acceptOpenedStream(id uint32) (*Stream, error) {
	a.streamsMu.Lock()
	if id>>1 >= a.peerStreamLimit {
		limit := a.peerStreamLimit
		a.streamsMu.Unlock()
		return nil, E.New("the peer opened stream ", id>>1, " with a limit of ", limit)
	}
	stream := newStream(a, id, initialStreamWindow)
	stream.queued = true
	a.streams[id] = stream
	// The first stream the peer opens is what tells it the budget: until then both
	// ends are inside the number they know without a frame.
	announce := a.peerStreamLimit == initialStreams
	if announce {
		a.peerStreamLimit = streamBudget
	}
	limit := a.peerStreamLimit
	a.streamsMu.Unlock()
	if announce {
		_ = a.send(appendMaxStreams(nil, limit))
	}
	// The queue always has room: a stream of the peer holds its place from here until
	// it is both ended and accepted, and the limit this end announced is what bounds
	// how many of those there are.
	a.acceptStream <- stream
	return stream, nil
}

// handleMaxStreams takes the number of streams the peer allows this end, and wakes
// every opener that was waiting for one.
func (a *association) handleMaxStreams(limit uint32) {
	a.streamsMu.Lock()
	if limit <= a.openCredit {
		a.streamsMu.Unlock()
		return
	}
	a.openCredit = limit
	close(a.streamCredit)
	a.streamCredit = make(chan struct{})
	a.streamsMu.Unlock()
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

// dataRead records bytes handed to an application and tells the peer about the
// association credit the read released, for the same reason a stream does: a peer
// waiting at the buffer bound is unblocked by the read and by nothing else.
func (a *association) dataRead(n int) {
	a.fcMu.Lock()
	a.recvRead += uint64(n)
	limit, moved := a.windowMoved()
	a.fcMu.Unlock()
	if moved {
		_ = a.send(appendMaxData(nil, limit))
	}
}

// windowMoved reports whether the association credit has to be moved forward, and to
// where. The caller holds fcMu.
func (a *association) windowMoved() (uint64, bool) {
	if a.recvLimit-a.recvReceived > a.recvWindow/2 {
		return 0, false
	}
	limit := min(a.recvReceived+a.recvWindow, a.recvRead+2*a.recvWindow)
	if limit <= a.recvLimit {
		return 0, false
	}
	a.recvLimit = limit
	return limit, true
}

// dataReceived counts bytes that arrived for the first time, which is what the
// association window limits, and moves that window forward once the peer spent half of
// it. It moves for the same reason a stream's does, and it is the same budget for every
// stream together.
func (a *association) dataReceived(n int) error {
	if n == 0 {
		return nil
	}
	a.fcMu.Lock()
	a.recvReceived += uint64(n)
	if a.recvReceived > a.recvLimit {
		limit := a.recvLimit
		a.fcMu.Unlock()
		return E.New("association received ", a.recvReceived, " bytes beyond its window ", limit)
	}
	limit, moved := a.windowMoved()
	a.fcMu.Unlock()
	if moved {
		_ = a.send(appendMaxData(nil, limit))
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

// appendMaxStreams appends a frame that moves the number of streams the peer may
// have open forward.
func appendMaxStreams(dst []byte, limit uint32) []byte {
	dst = append(dst, byte(frameTypeMaxStreams))
	return binary.BigEndian.AppendUint32(dst, limit)
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ net.Conn           = (*Stream)(nil)
)
