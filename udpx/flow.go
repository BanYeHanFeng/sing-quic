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

func (c *Conn) handleMaxData(body []byte) error {
	if len(body) < 8 {
		return errShortFrame
	}
	limit := binary.BigEndian.Uint64(body)
	c.fcMu.Lock()
	moved := c.fc.sendLimit < limit
	if moved {
		c.fc.sendLimit = limit
	}
	c.fcMu.Unlock()
	if moved {
		c.notifyStreams()
	}
	return nil
}

func (c *Conn) dataReceived(n int) error {
	if n == 0 {
		return nil
	}
	c.fcMu.Lock()
	c.fc.recvReceived += uint64(n)
	if c.fc.recvReceived > c.fc.recvLimit {
		received := c.fc.recvReceived
		limit := c.fc.recvLimit
		c.fcMu.Unlock()
		return E.New("connection received ", received, " bytes beyond its window ", limit)
	}
	limit, moved := c.fc.nextReceiveLimit()
	c.fcMu.Unlock()
	if moved {
		c.queueControl(appendMaxDataFrame(nil, limit))
	}
	return nil
}

func (c *Conn) dataRead(n int) {
	if n == 0 {
		return
	}
	c.fcMu.Lock()
	c.fc.recvRead += uint64(n)
	limit, moved := c.fc.nextReceiveLimit()
	c.fcMu.Unlock()
	if moved {
		c.queueControl(appendMaxDataFrame(nil, limit))
	}
}

func (c *Conn) dataDropped(n int) {
	if n == 0 {
		return
	}
	c.fcMu.Lock()
	c.fc.recvReceived += uint64(n)
	c.fc.recvRead += uint64(n)
	limit, moved := c.fc.nextReceiveLimit()
	c.fcMu.Unlock()
	if moved {
		c.queueControl(appendMaxDataFrame(nil, limit))
	}
}
