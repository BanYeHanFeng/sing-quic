package udpx

import (
	"context"
	"errors"
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

const streamInitiatorBit = 0x01

type StreamResetError struct {
	Code uint8
}

func (e StreamResetError) Error() string {
	return "udpx: stream reset with code " + strconv.Itoa(int(e.Code))
}

func (e StreamResetError) Is(target error) bool {
	return target == net.ErrClosed
}

type Stream struct {
	association *association
	id          uint32

	reset atomic.Bool

	sendMu        sync.Mutex
	sendOffset    uint64
	sendLimit     uint64
	sendUsed      uint64
	closeWrite    bool
	writeDeadline pipe.Deadline

	recvMu        sync.Mutex
	segments      []recvSegment
	readOffset    uint64
	recvHighest   uint64
	recvLimit     uint64
	recvWindow    uint64
	finReceived   bool
	finOffset     uint64
	resetReceived bool
	resetOffset   uint64
	readDeadline  pipe.Deadline

	endMu   sync.Mutex
	endErr  error
	endOnce sync.Once
	done    chan struct{}

	accepted bool

	sendNotify chan struct{}
	recvNotify chan struct{}
}

func newStream(association *association, id uint32, sendLimit uint64) *Stream {
	return &Stream{
		association:   association,
		id:            id,
		sendLimit:     sendLimit,
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
		allowed, err := s.writeSome(p[written:])
		if err != nil {
			return written, err
		}
		written += allowed
		if allowed == 0 {
			err = s.waitSend()
			if err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (s *Stream) writeSome(p []byte) (int, error) {
	a := s.association
	select {
	case <-a.ctx.Done():
		return 0, context.Cause(a.ctx)
	case <-s.done:
		return 0, s.endCause()
	default:
	}
	maxPayload := int(a.maxPayload.Load())
	s.sendMu.Lock()
	if s.reset.Load() || s.closeWrite {
		s.sendMu.Unlock()
		return 0, net.ErrClosed
	}
	length := min(len(p), maxPayload-streamHeaderLen)
	if available := s.sendLimit - s.sendUsed; available < uint64(length) {
		length = int(available)
	}
	a.fcMu.Lock()
	if available := a.fc.available(); available < uint64(length) {
		length = int(available)
	}
	if length > 0 {
		s.sendUsed += uint64(length)
		a.fc.sendUsed += uint64(length)
	}
	a.fcMu.Unlock()
	if length == 0 {
		s.sendMu.Unlock()
		return 0, nil
	}
	offset := s.sendOffset
	s.sendOffset += uint64(length)
	s.sendMu.Unlock()
	a.queueStreamFrame(newStreamFrame(s, offset, false, p[:length]))
	return length, nil
}

func (s *Stream) waitSend() error {
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

func (s *Stream) CloseWrite() error {
	s.sendMu.Lock()
	if s.closeWrite || s.reset.Load() {
		s.sendMu.Unlock()
		return nil
	}
	s.closeWrite = true
	offset := s.sendOffset
	s.sendMu.Unlock()
	s.association.queueStreamFrame(newStreamFrame(s, offset, true, nil))
	s.endIfDone()
	return nil
}

func (s *Stream) Close() error {
	if s.reset.Swap(true) {
		return nil
	}
	s.sendMu.Lock()
	closeWrite := s.closeWrite
	sendOffset := s.sendOffset
	s.closeWrite = true
	s.sendMu.Unlock()
	a := s.association
	if !closeWrite {
		a.queueStreamFrame(newStreamFrame(s, sendOffset, true, nil))
	}
	s.recvMu.Lock()
	readSideEnded := (s.finReceived && s.readOffset >= s.finOffset) || s.resetReceived
	s.recvMu.Unlock()
	if !readSideEnded {
		a.queueControl(appendResetStreamFrame(nil, s.id, sendOffset, resetCodeNormal), true)
	}
	s.end(net.ErrClosed)
	a.removeStream(s.id)
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
		if s.resetReceived && s.readOffset >= s.resetOffset {
			s.recvMu.Unlock()
			return 0, s.endCause()
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
	s.endOnce.Do(func() {
		s.endMu.Lock()
		s.endErr = cause
		s.endMu.Unlock()
		var reset StreamResetError
		if !errors.As(cause, &reset) {
			s.discardUnread()
		}
		close(s.done)
	})
	s.signalSend()
	s.signalRecv()
}

func (s *Stream) endCause() error {
	s.endMu.Lock()
	defer s.endMu.Unlock()
	return s.endErr
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

func (s *Stream) push(offset uint64, data []byte, fin bool) (int, error) {
	s.recvMu.Lock()
	end := offset + uint64(len(data))
	if end > s.recvLimit {
		limit := s.recvLimit
		s.recvMu.Unlock()
		return 0, E.New("stream ", s.id, " received up to ", end, " beyond its window ", limit)
	}
	received := 0
	if end > s.recvHighest {
		received = int(end - s.recvHighest)
		s.recvHighest = end
	}
	if len(data) > 0 && end > s.readOffset {
		if offset < s.readOffset {
			data = data[s.readOffset-offset:]
			offset = s.readOffset
		}
		storeSegment(s, offset, data)
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

func (s *Stream) resetFromPeer(finalOffset uint64, code resetCode) {
	s.recvMu.Lock()
	dropped := s.truncate(finalOffset)
	s.resetReceived = true
	s.resetOffset = finalOffset
	s.recvMu.Unlock()
	if dropped > 0 {
		s.association.dataRead(dropped)
	}
	s.end(code.err())
}

func (s *Stream) endIfDone() {
	s.recvMu.Lock()
	recvDone := (s.finReceived && s.readOffset >= s.finOffset) || s.resetReceived
	s.recvMu.Unlock()
	s.sendMu.Lock()
	sendDone := s.closeWrite || s.reset.Load()
	s.sendMu.Unlock()
	if recvDone && sendDone {
		s.association.removeStream(s.id)
	}
}

func (s *Stream) moveWindow() {
	s.recvMu.Lock()
	limit, moved := nextWindow(s.recvHighest, s.readOffset, s.recvWindow, s.recvLimit)
	if moved {
		s.recvLimit = limit
	}
	s.recvMu.Unlock()
	if moved {
		s.association.queueControl(appendMaxStreamDataFrame(nil, s.id, limit), true)
	}
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

func (s *Stream) giveSendCredit(limit uint64) {
	s.sendMu.Lock()
	if limit <= s.sendLimit {
		s.sendMu.Unlock()
		return
	}
	s.sendLimit = limit
	s.sendMu.Unlock()
	s.signalSend()
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ net.Conn           = (*Stream)(nil)
)
