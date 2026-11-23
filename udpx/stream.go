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

const (
	streamInitiatorBit = 0x01
)

func (a *association) streamDataLen() int {
	return a.maxPayload - streamFixedLen
}

const sendChunkSize = 64 << 10

type sendChunk struct {
	buf   []byte
	start int
	end   int
	holds atomic.Int32
}

var sendChunkPool = sync.Pool{
	New: func() any {
		sendChunksAllocated.Add(1)
		return &sendChunk{buf: make([]byte, sendChunkSize)}
	},
}

var sendChunksAllocated atomic.Int64

func (c *sendChunk) retain() {
	c.holds.Add(1)
}

func (c *sendChunk) release() {
	if c.holds.Add(-1) != 0 {
		return
	}
	c.start = 0
	c.end = 0
	sendChunkPool.Put(c)
}

type Stream struct {
	association *association
	id          uint32

	sendMu        sync.Mutex
	sendChunks    []*sendChunk
	sendOffset    uint64
	sendFramed    uint64
	sendCredit    credit
	closeWrite    bool
	finSent       bool
	writeDeadline pipe.Deadline
	sendPending   int
	resetOwed     bool

	recvMu       sync.Mutex
	segments     []recvSegment
	readOffset   uint64
	recvHighest  uint64
	recvLimit    uint64
	recvWindow   uint64
	finOffset    uint64
	finReceived  bool
	readDeadline pipe.Deadline

	endMu  sync.Mutex
	endErr error
	done   chan struct{}

	queued bool

	sendNotify chan struct{}
	recvNotify chan struct{}
}

type StreamResetError struct {
	Code uint8
}

func (e StreamResetError) Error() string {
	return "udpx: stream reset with code " + strconv.Itoa(int(e.Code))
}

func (e StreamResetError) Is(target error) bool {
	return e.Code == 0 && target == net.ErrClosed
}

type recvSegment struct {
	data   []byte
	offset uint64
	buffer []byte
}

var recvSegmentPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, maxPacketSize)
		return &buffer
	},
}

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
	allowed := min(s.sendCredit.available(), s.association.connectionCreditAvailable())
	allowed = min(allowed, uint64(len(p)))
	if allowed == 0 {
		return 0, nil
	}
	s.sendCredit.take(allowed)
	s.association.takeConnectionCredit(allowed)
	s.bufferSendData(p[:allowed])
	s.sendOffset += allowed
	return int(allowed), nil
}

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

func (s *Stream) releaseSendChunks() uint64 {
	dropped := uint64(0)
	for index, chunk := range s.sendChunks {
		dropped += uint64(chunk.end - chunk.start)
		s.sendChunks[index] = nil
		chunk.release()
	}
	s.sendChunks = nil
	return dropped
}

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
			head.retain()
			frame = streamFrame{
				carried: true,
				stream:  s,
				data:    pending[:length],
				chunk:   head,
				offset:  s.sendFramed,
			}
			s.sendFramed += uint64(length)
			head.start += length
			if head.start == head.end {
				s.sendChunks = s.sendChunks[1:]
				head.release()
			}
		} else if s.closeWrite && !s.finSent {
			frame = streamFrame{
				carried: true,
				stream:  s,
				offset:  s.sendOffset,
				fin:     true,
			}
			s.finSent = true
		}
		if frame.carried {
			s.sendPending++
		}
		s.sendMu.Unlock()
		if !frame.carried {
			s.association.wake()
			return nil
		}
		s.association.queueStreamFrame(frame)
	}
}

func (s *Stream) splitPendingFrame() {
	s.sendMu.Lock()
	s.sendPending++
	s.sendMu.Unlock()
}

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
		s.association.resetStream(s)
	}
	return nil
}

func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.recvMu.Lock()
		if len(s.segments) > 0 && s.segments[0].offset == s.readOffset {
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
	dropped := s.releaseSendChunks()
	s.sendMu.Unlock()
	if dropped > 0 {
		s.association.releaseSendCredit(dropped)
	}
	s.signalSend()
	s.signalRecv()
}

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

func (s *Stream) resetFromPeer(code resetCode) {
	s.end(code.err())
}

func (s *Stream) isEnded() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Stream) endCause() error {
	s.endMu.Lock()
	defer s.endMu.Unlock()
	return s.endErr
}

func (s *Stream) push(offset uint64, data []byte, fin bool) (int, error) {
	ended := s.isEnded()
	s.recvMu.Lock()
	end := offset + uint64(len(data))
	if !ended && end > s.recvLimit {
		s.recvMu.Unlock()
		return 0, E.New("stream ", s.id, " received up to ", end, " beyond its window ", s.recvLimit)
	}
	received := 0
	if end > s.recvHighest {
		received = int(end - s.recvHighest)
		s.recvHighest = end
	}
	if ended {
		s.recvMu.Unlock()
		if received > 0 {
			s.association.dataDropped(received)
		}
		return 0, nil
	}
	if len(data) > 0 && end > s.readOffset {
		if offset < s.readOffset {
			data = data[s.readOffset-offset:]
			offset = s.readOffset
		}
		s.storeSegment(offset, data)
	}
	if fin {
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

func (s *Stream) endIfDone() {
	s.recvMu.Lock()
	delivered := s.finReceived && s.readOffset >= s.finOffset
	s.recvMu.Unlock()
	if delivered && s.finQueued() {
		s.association.removeStream(s.id)
	}
}

func (s *Stream) finQueued() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.finSent
}

func (s *Stream) insertSegment(segment recvSegment) {
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
			releaseSegment(following)
			s.segments = append(s.segments[:index], s.segments[index+1:]...)
			continue
		}
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

func (s *Stream) windowMoved() (uint64, bool) {
	if s.recvLimit-s.recvHighest > s.recvWindow/2 {
		return 0, false
	}
	limit := min(s.recvHighest+s.recvWindow, s.readOffset+2*s.recvWindow)
	if limit <= s.recvLimit {
		return 0, false
	}
	s.recvLimit = limit
	return limit, true
}

func (s *Stream) moveWindow() {
	s.recvMu.Lock()
	limit, moved := s.windowMoved()
	s.recvMu.Unlock()
	if moved {
		_ = s.association.send(appendMaxStreamData(nil, s.id, limit))
	}
}

func (s *Stream) extendWindow() (uint64, bool) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	limit := min(s.recvHighest+s.recvWindow, s.readOffset+2*s.recvWindow)
	if limit <= s.recvLimit {
		return 0, false
	}
	s.recvLimit = limit
	return limit, true
}

func (s *Stream) signalSend() {
	select {
	case s.sendNotify <- struct{}{}:
	default:
	}
}

func (s *Stream) signalRecv() {
	select {
	case s.recvNotify <- struct{}{}:
	default:
	}
}

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

func (a *association) ackStreamFrames(acked []*sentPacket) {
	for _, packet := range acked {
		for index := range packet.frames {
			stream := packet.frames[index].streamFrame.stream
			if stream != nil {
				stream.frameAcked()
			}
		}
	}
}

func (s *Stream) frameAcked() {
	s.sendMu.Lock()
	s.sendPending--
	due := s.sendPending == 0 && s.resetOwed
	if due {
		s.resetOwed = false
	}
	s.sendMu.Unlock()
	if due {
		s.association.sendReset(s.id)
	}
}

func (s *Stream) oweReset() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sendPending == 0 {
		return false
	}
	s.resetOwed = true
	return true
}

func (a *association) removeStream(id uint32) bool {
	a.streamsMu.Lock()
	stream, loaded := a.streams[id]
	delete(a.streams, id)
	peerStream := id&streamInitiatorBit != a.initiatorBit()
	if peerStream {
		a.endedStreams.add(id)
	}
	freed := loaded && !stream.queued && peerStream
	if freed {
		a.peerStreamLimit++
	}
	limit := a.peerStreamLimit
	a.streamsMu.Unlock()
	if freed {
		_ = a.send(appendMaxStreams(nil, limit))
	}
	return loaded
}

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

func (a *association) streamEnded(id uint32) bool {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	return a.endedStreams.has(id)
}

func (a *association) resetStream(stream *Stream) {
	if stream.oweReset() {
		return
	}
	a.sendReset(stream.id)
}

func (a *association) sendReset(id uint32) {
	if !a.removeStream(id) {
		return
	}
	_ = a.send(appendResetStream(nil, id, resetCodeNormal))
}

func (a *association) handleResetStream(reset streamReset) {
	stream, loaded := a.stream(reset.streamID)
	if !loaded {
		return
	}
	stream.resetFromPeer(reset.code)
	a.removeStream(reset.streamID)
}

func (a *association) initiatorBit() uint32 {
	if a.isClient {
		return 0
	}
	return streamInitiatorBit
}

func (a *association) handleStreamFrame(data streamData) error {
	stream, loaded := a.stream(data.streamID)
	if !loaded {
		if data.streamID&streamInitiatorBit == a.initiatorBit() {
			a.streamsMu.Lock()
			opened := data.streamID>>1 < a.nextStreamID
			a.streamsMu.Unlock()
			if opened {
				a.dataDropped(len(data.data))
				return nil
			}
			return E.New("stream frame for stream ", data.streamID, " that was never opened")
		}
		if a.streamEnded(data.streamID) {
			a.dataDropped(len(data.data))
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
	announce := a.peerStreamLimit == initialStreams
	if announce {
		a.peerStreamLimit = streamBudget
	}
	limit := a.peerStreamLimit
	a.streamsMu.Unlock()
	if announce {
		_ = a.send(appendMaxStreams(nil, limit))
	}
	a.acceptStream <- stream
	return stream, nil
}

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

func (a *association) handleMaxData(limit uint64) {
	a.fcMu.Lock()
	moved := a.sendCredit.give(limit)
	a.fcMu.Unlock()
	if moved {
		a.notifyStreams()
	}
}

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

func (a *association) releaseSendCredit(n uint64) {
	a.fcMu.Lock()
	if n >= a.sendCredit.used {
		a.sendCredit.used = 0
	} else {
		a.sendCredit.used -= n
	}
	a.fcMu.Unlock()
	a.notifyStreams()
}

func (a *association) dataRead(n int) {
	a.fcMu.Lock()
	a.recvRead += uint64(n)
	limit, moved := a.windowMoved()
	a.fcMu.Unlock()
	if moved {
		_ = a.send(appendMaxData(nil, limit))
	}
}

func (a *association) windowMoved() (uint64, bool) {
	if a.recvReceived < a.recvLimit && a.recvLimit-a.recvReceived > a.recvWindow/2 {
		return 0, false
	}
	limit := min(a.recvReceived+a.recvWindow, a.recvRead+2*a.recvWindow)
	if limit <= a.recvLimit {
		return 0, false
	}
	a.recvLimit = limit
	return limit, true
}

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

func (a *association) dataDropped(n int) {
	if n == 0 {
		return
	}
	a.fcMu.Lock()
	a.recvReceived += uint64(n)
	a.recvRead += uint64(n)
	limit, moved := a.windowMoved()
	a.fcMu.Unlock()
	if moved {
		_ = a.send(appendMaxData(nil, limit))
	}
}

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

func appendMaxData(dst []byte, limit uint64) []byte {
	dst = append(dst, byte(frameTypeMaxData))
	return binary.BigEndian.AppendUint64(dst, limit)
}

func appendMaxStreamData(dst []byte, streamID uint32, limit uint64) []byte {
	dst = append(dst, byte(frameTypeMaxStreamData))
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	return binary.BigEndian.AppendUint64(dst, limit)
}

func appendMaxStreams(dst []byte, limit uint32) []byte {
	dst = append(dst, byte(frameTypeMaxStreams))
	return binary.BigEndian.AppendUint32(dst, limit)
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ net.Conn           = (*Stream)(nil)
)
