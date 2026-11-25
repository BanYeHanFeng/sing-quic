package udpx

import (
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/congestion"
)

const (
	maxProbeBackoff = 5

	maxProbeSilence = 20 * time.Second
)

const frameBufferSize = maxPacketSize

var frameBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, frameBufferSize)
		return &buffer
	},
}

// frameKind 说明一帧在发送调度中的待遇。
type frameKind uint8

const (
	frameData  frameKind = iota // 受拥塞窗口与 pacing 约束
	frameProbe                  // PTO 重传：绕过拥塞窗口
	frameMTU                    // MTU 探测：独占一个包
)

type outFrame struct {
	kind frameKind

	payload []byte

	buffer *[]byte

	stream *Stream
}

func (f *outFrame) release() {
	if f.buffer == nil {
		return
	}
	buffer := (*f.buffer)[:frameBufferSize]
	frameBufferPool.Put(&buffer)
	f.buffer = nil
}

func releaseFrames(frames []outFrame) {
	for index := range frames {
		frames[index].release()
	}
}

func (f outFrame) size() int {
	return len(f.payload)
}

func newStreamFrame(stream *Stream, offset uint64, fin bool, data []byte) outFrame {
	buffer := frameBufferPool.Get().(*[]byte)
	payload := appendStreamHeader((*buffer)[:0], stream.id, offset, fin, len(data))
	payload = append(payload, data...)
	return outFrame{
		payload: payload,
		buffer:  buffer,
		stream:  stream,
	}
}

// sender 的全部字段由 conn.sendMu 保护。
type sender struct {
	conn *Conn

	control []outFrame // ACK、CLOSE：不需要对端确认，不受拥塞窗口限制
	data    []outFrame // 其余帧：一律需要对端确认

	inFlight inFlight
	batch    batch

	// 连接级接收额度，以及名字取自对端的发送额度
	recv      receiveWindow
	sendLimit uint64
	sendUsed  uint64

	rtt rttEstimator
	cc  congestion.Controller

	sendPacket uint32
	probes     int
	probeSince time.Time
	lastSentAt time.Time

	ack   ackScheduler
	ackAt time.Time

	idleAt      time.Time
	keepAliveAt time.Time

	mtu             mtuState
	probeSize       int
	mtuQueued       bool
	datagramMessage uint16
	closing         bool
	cause           error
}

func (s *sender) init(conn *Conn, mtu int) {
	s.conn = conn
	s.mtu.init(mtu, conn.options.MTU, conn.RemoteAddr())
	s.batch = newBatch()
	s.recv = newConnectionReceiveWindow()
	s.sendLimit = initialConnectionWindow
	s.cc = newCongestionController()
	s.cc.SetMinRTTProvider(&s.rtt)
	s.idleAt = time.Now().Add(conn.options.IdleTimeout)
}

func (s *sender) payloadSize() int {
	return s.mtu.size - headerLen - tagLen
}

// queueData 入队一个需要对端确认的帧；连接已 closing 时丢弃。
func (s *sender) queueData(frame outFrame) {
	if s.closing {
		frame.release()
		return
	}
	s.data = append(s.data, frame)
}

// fail 记录致命原因，通知对端（可选），丢弃排队与在途的帧。幂等，不等待。
func (s *sender) fail(cause error, notifyPeer bool) bool {
	if s.closing {
		return false
	}
	if cause == nil {
		cause = net.ErrClosed
	}
	s.closing = true
	s.cause = cause
	releaseFrames(s.data)
	s.data = nil
	releaseFrames(s.control)
	s.control = nil
	for _, packet := range s.inFlight.clear() {
		releaseFrames(packet.frames)
	}
	if notifyPeer {
		s.control = append(s.control, outFrame{payload: appendCloseFrame(nil, closeCodeOf(cause))})
	}
	return true
}

// idle 队列已排空，发送循环可以退出。
func (s *sender) idle() bool {
	return s.closing && len(s.control) == 0 && len(s.data) == 0
}

// pending 队首有可以发的帧，此时只差 pacing。
func (s *sender) pending() bool {
	if len(s.control) > 0 {
		return true
	}
	if len(s.data) == 0 {
		return false
	}
	if s.data[0].kind != frameData {
		return true
	}
	return s.cc.CanSend(s.inFlight.bytes)
}

// sendable 现在能不能发：取帧与唤醒计算共用这一处判定。
func (s *sender) sendable(now time.Time) bool {
	if !s.pending() {
		return false
	}
	if len(s.control) > 0 || s.data[0].kind != frameData {
		return true
	}
	return s.cc.PacingWait(now) <= 0
}

func (s *sender) runTimers(now time.Time) error {
	if s.closing {
		if !s.ackAt.IsZero() && !now.Before(s.ackAt) {
			s.enqueueAck(now)
		}
		return nil
	}
	c := s.conn
	activeStreams := c.activeStreams()
	if !now.Before(s.idleAt) {
		if activeStreams == 0 {
			return ErrIdleTimeout
		}
		s.idleAt = now.Add(c.options.IdleTimeout)
	}
	if !s.ackAt.IsZero() && !now.Before(s.ackAt) {
		s.enqueueAck(now)
	}
	if s.mtu.active && !now.Before(s.mtu.deadline) {
		candidate, packetNumber := s.mtu.candidate, s.mtu.packet
		s.mtu.dropCandidate()
		s.dropProbe(packetNumber)
		c.logDebug("mtu probe of ", candidate, " unanswered, mtu stays ", s.mtu.size)
	}
	keepAlive := c.options.KeepAlivePeriod
	if keepAlive <= 0 && activeStreams > 0 {
		keepAlive = c.options.IdleTimeout / 2
	}
	if keepAlive > 0 {
		if s.keepAliveAt.IsZero() {
			s.keepAliveAt = now.Add(keepAlive)
		} else if !now.Before(s.keepAliveAt) {
			if s.inFlight.len() == 0 && len(s.data) == 0 {
				s.queueData(outFrame{payload: appendPingFrame(nil)})
			}
			s.keepAliveAt = now.Add(keepAlive)
		}
	} else {
		s.keepAliveAt = time.Time{}
	}
	if s.inFlight.len() > 0 && !now.Before(s.ptoDeadline()) {
		if cause := s.probeLocked(now); cause != nil {
			return cause
		}
	}
	return nil
}

func (s *sender) dropProbe(packetNumber uint32) {
	for _, packet := range s.inFlight.packets {
		if packet.packetNumber != packetNumber {
			continue
		}
		s.inFlight.remove(packet)
		releaseFrames(packet.frames)
		return
	}
}

func (s *sender) probeLocked(now time.Time) error {
	oldest := s.inFlight.oldest()
	if oldest == nil {
		return nil
	}
	s.probes++
	if s.probes == 1 {
		s.probeSince = now
	}
	if now.Sub(s.probeSince) >= maxProbeSilence {
		s.conn.logDebug("probe ", oldest.packetNumber, " unanswered for ", maxProbeSilence, ", closing")
		return ErrProbeTimeout
	}
	s.inFlight.remove(oldest)
	var retransmit []outFrame
	for index := range oldest.frames {
		frame := oldest.frames[index]
		if retransmittable(frame.payload[0] & frameTypeMask) {
			frame.kind = frameProbe
			retransmit = append(retransmit, frame)
			continue
		}
		frame.release()
	}
	if len(retransmit) == 0 {
		retransmit = append(retransmit, outFrame{kind: frameProbe, payload: appendPingFrame(nil)})
	}
	s.data = append(retransmit, s.data...)
	return nil
}

func (s *sender) ptoDeadline() time.Time {
	if s.inFlight.len() == 0 {
		return time.Time{}
	}
	base := s.lastSentAt
	if base.IsZero() {
		base = s.inFlight.oldest().sentAt
	}
	backoff := min(s.probes, maxProbeBackoff)
	return base.Add(s.rtt.pto() << backoff)
}

func (s *sender) enqueueAck(now time.Time) {
	s.ackAt = time.Time{}
	payload := s.ack.pack(now)
	if len(payload) == 0 {
		return
	}
	s.control = append(s.control, outFrame{payload: payload})
}

func (s *sender) rxPacket(packetNumber uint32, ackEliciting bool, now time.Time) {
	s.idleAt = now.Add(s.conn.options.IdleTimeout)
	if !ackEliciting {
		return
	}
	immediate := s.ack.received(packetNumber, now)
	if immediate {
		s.enqueueAck(now)
		return
	}
	if s.ackAt.IsZero() {
		s.ackAt = now.Add(s.ackDelay())
	}
}

func (s *sender) ackDelay() time.Duration {
	if !s.rtt.sampled {
		return maxAckDelay
	}
	return min(maxAckDelay, max(minAckDelay, s.rtt.smoothed/8))
}

// nextDeadline 下一次需要醒来的时刻：定时器，加上“现在就能发”时的 pacing 等待。
func (s *sender) nextDeadline(now time.Time) time.Time {
	deadline := s.idleAt
	consider := func(at time.Time) {
		if at.IsZero() {
			return
		}
		if deadline.IsZero() || at.Before(deadline) {
			deadline = at
		}
	}
	consider(s.ackAt)
	consider(s.keepAliveAt)
	if s.mtu.active {
		consider(s.mtu.deadline)
	}
	if s.inFlight.len() > 0 {
		consider(s.ptoDeadline())
	}
	if s.pending() {
		if wait := s.cc.PacingWait(now); wait > 0 {
			consider(now.Add(wait))
		} else {
			consider(now)
		}
	}
	return deadline
}

func (s *sender) stepDown() bool {
	next, loaded := s.mtu.nextBelow(s.mtu.size)
	if !loaded {
		return false
	}
	s.mtu.size = next
	return true
}
