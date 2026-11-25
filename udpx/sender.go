package udpx

import (
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

type outFrame struct {
	payload []byte

	buffer *[]byte

	stream *Stream

	ackEliciting bool

	probe bool

	mtu bool
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
		payload:      payload,
		buffer:       buffer,
		stream:       stream,
		ackEliciting: true,
	}
}

type sender struct {
	conn *Conn

	queue    []outFrame
	ackQueue []outFrame

	inFlight inFlight
	batch    batch

	rtt      rttEstimator
	rttStats rttStats
	cc       congestion.Controller

	sendPacket uint32
	probes     int
	probeSince time.Time
	lastSentAt time.Time

	ack   ackScheduler
	ackAt time.Time

	idleAt      time.Time
	keepAliveAt time.Time
	statsAt     time.Time
	statsLast   statsSnapshot

	mtu          mtuState
	probeSize    int
	probePending bool
	closing      bool
}

func (s *sender) init(conn *Conn) {
	s.conn = conn
	s.batch = newBatch()
	s.cc = newCongestionController()
	s.cc.SetRTTStatsProvider(&s.rttStats)
	s.mtu.init(conn.options.MTU, conn.RemoteAddr())
	s.idleAt = time.Now().Add(conn.options.IdleTimeout)
	s.statsAt = time.Now().Add(time.Second)
}

func (s *sender) closeLocked(cause error, notifyPeer bool) {
	s.closing = true
	releaseFrames(s.queue)
	s.queue = nil
	releaseFrames(s.ackQueue)
	s.ackQueue = nil
	for _, packet := range s.inFlight.clear() {
		releaseFrames(packet.frames)
	}
	if notifyPeer {
		s.ackQueue = append(s.ackQueue, outFrame{payload: appendCloseFrame(nil, closeCodeOf(cause))})
	}
}

func (s *sender) idle() bool {
	return s.closing && len(s.ackQueue) == 0 && len(s.queue) == 0
}

func (s *sender) pushControl(payload []byte, ackEliciting bool) {
	s.queue = append(s.queue, outFrame{payload: payload, ackEliciting: ackEliciting})
}

func (s *sender) windowAllows() bool {
	return s.cc.CanSend(s.inFlight.bytes)
}

func (s *sender) hasPending() bool {
	return len(s.ackQueue) > 0 || len(s.queue) > 0
}

func (s *sender) shouldPack(now time.Time) bool {
	if len(s.ackQueue) > 0 {
		return true
	}
	if len(s.queue) == 0 {
		return false
	}
	if s.queue[0].probe || s.queue[0].mtu {
		return true
	}
	if !s.windowAllows() {
		return false
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
		c.logInfo("mtu probe of ", candidate, " unanswered, mtu stays ", c.mtuSize())
	}
	keepAlive := c.options.KeepAlivePeriod
	if keepAlive <= 0 && activeStreams > 0 {
		keepAlive = c.options.IdleTimeout / 2
	}
	if keepAlive > 0 {
		if s.keepAliveAt.IsZero() {
			s.keepAliveAt = now.Add(keepAlive)
		} else if !now.Before(s.keepAliveAt) {
			if s.inFlight.len() == 0 && len(s.queue) == 0 {
				s.pushControl(appendPingFrame(nil), true)
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
		s.conn.logInfo("probe ", oldest.packetNumber, " unanswered for ", maxProbeSilence, ", closing")
		return ErrProbeTimeout
	}
	s.conn.stats.probes.Add(1)
	s.inFlight.remove(oldest)
	var retransmit []outFrame
	for index := range oldest.frames {
		frame := oldest.frames[index]
		if frame.ackEliciting && retransmittable(frame.payload[0]&frameTypeMask) {
			frame.probe = true
			retransmit = append(retransmit, frame)
			continue
		}
		frame.release()
	}
	if len(retransmit) == 0 {
		retransmit = append(retransmit, outFrame{payload: appendPingFrame(nil), ackEliciting: true, probe: true})
	}
	s.queue = append(retransmit, s.queue...)
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
	s.ackQueue = append(s.ackQueue, outFrame{payload: payload})
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
	consider(s.statsAt)
	if s.mtu.active {
		consider(s.mtu.deadline)
	}
	if s.inFlight.len() > 0 {
		consider(s.ptoDeadline())
	}
	switch {
	case len(s.ackQueue) > 0:
		consider(now)
	case len(s.queue) > 0 && (s.queue[0].probe || s.queue[0].mtu || s.windowAllows()):
		if wait := s.cc.PacingWait(now); wait > 0 {
			consider(now.Add(wait))
		} else {
			consider(now)
		}
	}
	return deadline
}

func (s *sender) stepDown() bool {
	current := s.conn.mtuSize()
	next, loaded := s.mtu.nextBelow(current)
	if !loaded {
		return false
	}
	s.conn.maxPayload.Store(int32(next - headerLen - tagLen))
	return true
}
