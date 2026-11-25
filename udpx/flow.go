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

// receiveWindow 是连接级与流级共用的接收额度。
// 流级用 observe 把 received 推到见过的最大偏移，连接级用 add 累加。
type receiveWindow struct {
	read     uint64 // 上层已取走的字节
	received uint64 // 已收到的字节
	limit    uint64 // 已通告的上限
	window   uint64 // 每次推进的窗口大小
}

func newStreamReceiveWindow() receiveWindow {
	return receiveWindow{limit: initialStreamWindow, window: streamWindow}
}

func newConnectionReceiveWindow() receiveWindow {
	return receiveWindow{limit: initialConnectionWindow, window: connectionWindow}
}

// add 记入 n 个已收字节；超出已通告的窗口说明对端犯规。
func (w *receiveWindow) add(n int) bool {
	w.received += uint64(n)
	return w.received <= w.limit
}

// observe 把 received 推到 end，返回新增的字节数。
func (w *receiveWindow) observe(end uint64) int {
	if end <= w.received {
		return 0
	}
	received := int(end - w.received)
	w.received = end
	return received
}

// onRead 读侧归还额度。
func (w *receiveWindow) onRead(n int) {
	w.read += uint64(n)
}

// next 在窗口被用掉一半以上时推进，返回新上限。
func (w *receiveWindow) next() (uint64, bool) {
	if w.received < w.limit && w.limit-w.received > w.window/2 {
		return 0, false
	}
	limit := min(w.received+w.window, w.read+2*w.window)
	if limit <= w.limit {
		return 0, false
	}
	w.limit = limit
	return limit, true
}

// advanceWindow 在连接级接收窗口移动时入队 MAX_DATA；调用方持有 sendMu。
func (s *sender) advanceWindow() {
	if limit, moved := s.recv.next(); moved {
		s.queueData(outFrame{payload: appendMaxDataFrame(nil, limit)})
	}
}

func (c *Conn) handleMaxData(body []byte) error {
	if len(body) < 8 {
		return errShortFrame
	}
	limit := binary.BigEndian.Uint64(body)
	c.sendMu.Lock()
	moved := c.send.sendLimit < limit
	if moved {
		c.send.sendLimit = limit
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
	if !c.send.recv.add(n) {
		return E.New("connection received ", c.send.recv.received, " bytes beyond its window ", c.send.recv.limit)
	}
	c.send.advanceWindow()
	return nil
}

// dataRead 读侧归还连接级接收额度。
func (c *Conn) dataRead(n int) {
	if n == 0 {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.send.recv.onRead(n)
	c.send.advanceWindow()
}

// dataDropped 丢弃已关闭的流上的数据，额度立即归还。
func (c *Conn) dataDropped(n int) {
	if n == 0 {
		return
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.send.recv.add(n)
	c.send.recv.onRead(n)
	c.send.advanceWindow()
}
