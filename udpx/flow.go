package udpx

import (
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	initialStreamWindow = 512 * 1024

	initialConnectionWindow = 2 * 1024 * 1024

	streamWindow = 8 * 1024 * 1024

	connectionWindow = 16 * 1024 * 1024

	initialStreams = 256
)

type flowControl struct {
	sendLimit uint64
	sendUsed  uint64

	recvRead     uint64
	recvReceived uint64
	recvLimit    uint64
	recvWindow   uint64
}

func newFlowControl() flowControl {
	return flowControl{
		sendLimit:  initialConnectionWindow,
		recvLimit:  initialConnectionWindow,
		recvWindow: connectionWindow,
	}
}

func (f *flowControl) available() uint64 {
	if f.sendUsed >= f.sendLimit {
		return 0
	}
	return f.sendLimit - f.sendUsed
}

func (f *flowControl) nextReceiveLimit() (uint64, bool) {
	limit, moved := nextWindow(f.recvReceived, f.recvRead, f.recvWindow, f.recvLimit)
	if !moved {
		return 0, false
	}
	f.recvLimit = limit
	return limit, true
}

func nextWindow(highest, read, window, current uint64) (uint64, bool) {
	if highest < current && current-highest > window/2 {
		return 0, false
	}
	limit := min(highest+window, read+2*window)
	if limit <= current {
		return 0, false
	}
	return limit, true
}

// advanceWindow 在连接级接收窗口移动时入队 MAX_DATA 并报告；调用方持有 sendMu。
func (s *sender) advanceWindow() bool {
	limit, moved := s.fc.nextReceiveLimit()
	if moved {
		s.queueControl(appendMaxDataFrame(nil, limit))
	}
	return moved
}

func (c *Conn) handleMaxData(body []byte) error {
	if len(body) < 8 {
		return errShortFrame
	}
	limit := binary.BigEndian.Uint64(body)
	c.sendMu.Lock()
	moved := c.send.fc.sendLimit < limit
	if moved {
		c.send.fc.sendLimit = limit
	}
	c.sendMu.Unlock()
	if moved {
		c.notifyStreams()
	}
	return nil
}

// dataReceived 收到流数据：记入连接级接收额度，窗口移动时入队 MAX_DATA。
func (c *Conn) dataReceived(n int) error {
	if n == 0 {
		return nil
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	fc := &c.send.fc
	fc.recvReceived += uint64(n)
	if fc.recvReceived > fc.recvLimit {
		return E.New("connection received ", fc.recvReceived, " bytes beyond its window ", fc.recvLimit)
	}
	if c.send.advanceWindow() {
		c.wake()
	}
	return nil
}

// dataRead 读侧归还连接级接收额度。
func (c *Conn) dataRead(n int) {
	if n == 0 {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.send.fc.recvRead += uint64(n)
	if c.send.advanceWindow() {
		c.wake()
	}
}

// dataDropped 丢弃已关闭的流上的数据，额度立即归还。
func (c *Conn) dataDropped(n int) {
	if n == 0 {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.send.fc.recvReceived += uint64(n)
	c.send.fc.recvRead += uint64(n)
	if c.send.advanceWindow() {
		c.wake()
	}
}
