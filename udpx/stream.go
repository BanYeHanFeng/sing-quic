package udpx

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/pipe"

	E "github.com/sagernet/sing/common/exceptions"
)

var ErrStreamReset error = streamResetError{}

type streamResetError struct{}

func (streamResetError) Error() string {
	return "udpx: stream reset by the peer"
}

func (streamResetError) Is(target error) bool {
	return target == net.ErrClosed
}

// Stream 的发送侧字段 reset、sendOffset、sendUsed、sendLimit、closeWrite 由 conn.sendMu 保护，
// 接收侧字段由 recvMu 保护。
type Stream struct {
	conn *Conn
	id   uint32

	reset         bool // 本端已 Close
	sendOffset    uint64
	sendLimit     uint64
	sendUsed      uint64
	closeWrite    bool
	writeDeadline pipe.Deadline

	recvMu        sync.Mutex
	segments      []recvSegment
	recv          receiveWindow
	finReceived   bool
	finOffset     uint64
	resetReceived bool
	resetOffset   uint64
	readDeadline  pipe.Deadline

	endOnce sync.Once
	endErr  error // 在 close(done) 之前写入，只在其后读取
	done    chan struct{}

	sendNotify chan struct{}
	recvNotify chan struct{}
}

func newStream(conn *Conn, id uint32) *Stream {
	return &Stream{
		conn:          conn,
		id:            id,
		sendLimit:     initialStreamWindow,
		recv:          newStreamReceiveWindow(),
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
	return s.conn.LocalAddr()
}

func (s *Stream) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
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
	c := s.conn
	select {
	case <-c.ctx.Done():
		return 0, context.Cause(c.ctx)
	case <-s.done:
		return 0, s.endCause()
	default:
	}
	c.sendMu.Lock()
	if s.reset || s.closeWrite {
		c.sendMu.Unlock()
		return 0, net.ErrClosed
	}
	length := min(len(p), c.send.payloadSize()-streamHeaderLen)
	if available := s.sendLimit - s.sendUsed; available < uint64(length) {
		length = int(available)
	}
	if available := c.send.sendLimit - c.send.sendUsed; available < uint64(length) {
		length = int(available)
	}
	if length == 0 {
		c.sendMu.Unlock()
		return 0, nil
	}
	s.sendUsed += uint64(length)
	c.send.sendUsed += uint64(length)
	offset := s.sendOffset
	s.sendOffset += uint64(length)
	c.send.queueData(newStreamFrame(s, offset, false, p[:length]))
	c.sendMu.Unlock()
	c.wake()
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
	case <-s.conn.ctx.Done():
		return context.Cause(s.conn.ctx)
	}
}

func (s *Stream) CloseWrite() error {
	c := s.conn
	c.sendMu.Lock()
	if s.closeWrite || s.reset {
		c.sendMu.Unlock()
		return nil
	}
	s.closeWrite = true
	c.send.queueData(newStreamFrame(s, s.sendOffset, true, nil))
	c.sendMu.Unlock()
	c.wake()
	s.endIfDone()
	return nil
}

func (s *Stream) Close() error {
	c := s.conn
	c.sendMu.Lock()
	if s.reset {
		c.sendMu.Unlock()
		return nil
	}
	s.reset = true
	if !s.closeWrite {
		s.closeWrite = true
		c.send.queueData(newStreamFrame(s, s.sendOffset, true, nil))
	}
	offset := s.sendOffset
	c.sendMu.Unlock()
	c.wake()
	s.recvMu.Lock()
	readSideEnded := (s.finReceived && s.recv.read >= s.finOffset) || s.resetReceived
	s.recvMu.Unlock()
	if !readSideEnded {
		c.queueControl(appendResetStreamFrame(nil, s.id, offset))
	}
	s.end(net.ErrClosed)
	c.removeStream(s.id)
	return nil
}

func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.recvMu.Lock()
		if len(s.segments) > 0 && s.segments[0].offset == s.recv.read {
			read := 0
			for read < len(p) && len(s.segments) > 0 && s.segments[0].offset == s.recv.read+uint64(read) {
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
			s.recv.onRead(read)
			s.recvMu.Unlock()
			s.conn.dataRead(read)
			s.endIfDone()
			s.moveWindow()
			return read, nil
		}
		if s.finReceived && s.recv.read >= s.finOffset {
			s.recvMu.Unlock()
			return 0, io.EOF
		}
		if s.resetReceived && s.recv.read >= s.resetOffset {
			s.recvMu.Unlock()
			return 0, ErrStreamReset
		}
		s.recvMu.Unlock()
		select {
		case <-s.done:
			return 0, s.endCause()
		case <-s.recvNotify:
		case <-s.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		case <-s.conn.ctx.Done():
			return 0, context.Cause(s.conn.ctx)
		}
	}
}

func (s *Stream) end(cause error) {
	s.endOnce.Do(func() {
		s.endErr = cause
		if !errors.Is(cause, ErrStreamReset) {
			s.discardUnread()
		}
		close(s.done)
	})
	s.signalSend()
	s.signalRecv()
}

func (s *Stream) endCause() error {
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
		s.conn.dataRead(dropped)
	}
}

func (s *Stream) push(offset uint64, data []byte, fin bool) (int, error) {
	s.recvMu.Lock()
	end := offset + uint64(len(data))
	if end > s.recv.limit {
		limit := s.recv.limit
		s.recvMu.Unlock()
		return 0, E.New("stream ", s.id, " received up to ", end, " beyond its window ", limit)
	}
	received := s.recv.observe(end)
	if len(data) > 0 && end > s.recv.read {
		if offset < s.recv.read {
			data = data[s.recv.read-offset:]
			offset = s.recv.read
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

func (s *Stream) resetFromPeer(finalOffset uint64) {
	s.recvMu.Lock()
	dropped := s.truncate(finalOffset)
	s.resetReceived = true
	s.resetOffset = finalOffset
	s.recvMu.Unlock()
	if dropped > 0 {
		s.conn.dataRead(dropped)
	}
	s.end(ErrStreamReset)
}

func (s *Stream) endIfDone() {
	s.recvMu.Lock()
	recvDone := (s.finReceived && s.recv.read >= s.finOffset) || s.resetReceived
	s.recvMu.Unlock()
	s.conn.sendMu.Lock()
	sendDone := s.closeWrite || s.reset
	s.conn.sendMu.Unlock()
	if recvDone && sendDone {
		s.conn.removeStream(s.id)
	}
}

func (s *Stream) moveWindow() {
	s.recvMu.Lock()
	limit, moved := s.recv.next()
	s.recvMu.Unlock()
	if moved {
		s.conn.queueControl(appendMaxStreamDataFrame(nil, s.id, limit))
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
	c := s.conn
	c.sendMu.Lock()
	if limit <= s.sendLimit {
		c.sendMu.Unlock()
		return
	}
	s.sendLimit = limit
	c.sendMu.Unlock()
	s.signalSend()
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ net.Conn           = (*Stream)(nil)
)
