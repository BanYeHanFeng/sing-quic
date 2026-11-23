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

type txState struct {
	association *association

	queue    []outFrame
	ackQueue []outFrame

	inFlight inFlight
	batch    txBatch

	rtt      rttEstimator
	rttStats rttStats
	cc       congestion.Controller

	sendPacket uint32
	probes     int
	probeSince time.Time

	ack   ackScheduler
	ackAt time.Time

	idleAt      time.Time
	keepAliveAt time.Time
	statsAt     time.Time
	statsLast   statsSnapshot

	mtu       mtuState
	probeSize int
	closing   bool
}

func (t *txState) init(association *association) {
	t.association = association
	t.batch = newTXBatch()
	t.cc = newCongestionController()
	t.cc.SetRTTStatsProvider(&t.rttStats)
	t.mtu.init(association.options.MTU, association.RemoteAddr())
	t.idleAt = time.Now().Add(association.options.IdleTimeout)
	if association.options.KeepAlivePeriod > 0 {
		t.keepAliveAt = time.Now().Add(association.options.KeepAlivePeriod)
	}
	t.statsAt = time.Now().Add(time.Second)
}

func (t *txState) closeLocked(cause error, notifyPeer bool) {
	t.closing = true
	releaseFrames(t.queue)
	t.queue = nil
	releaseFrames(t.ackQueue)
	t.ackQueue = nil
	for _, packet := range t.inFlight.clear() {
		releaseFrames(packet.frames)
	}
	if notifyPeer {
		t.ackQueue = append(t.ackQueue, outFrame{payload: appendCloseFrame(nil, closeCodeOf(cause))})
	}
}

func (t *txState) idle() bool {
	return t.closing && len(t.ackQueue) == 0 && len(t.queue) == 0
}

func (t *txState) pushControl(payload []byte, ackEliciting bool) {
	t.queue = append(t.queue, outFrame{payload: payload, ackEliciting: ackEliciting})
}

func (t *txState) windowAllows() bool {
	return t.cc.CanSend(t.inFlight.bytes)
}

func (t *txState) hasPending() bool {
	return len(t.ackQueue) > 0 || len(t.queue) > 0
}

func (t *txState) shouldPack(now time.Time) bool {
	if len(t.ackQueue) > 0 {
		return true
	}
	if len(t.queue) == 0 {
		return false
	}
	if t.queue[0].probe {
		return true
	}
	if !t.windowAllows() {
		return false
	}
	return t.cc.PacingWait(now) <= 0
}

func (t *txState) runTimers(now time.Time) error {
	if !now.Before(t.idleAt) {
		return ErrIdleTimeout
	}
	if !t.ackAt.IsZero() && !now.Before(t.ackAt) {
		t.enqueueAck(now)
	}
	if t.mtu.active && !now.Before(t.mtu.deadline) {
		candidate, packetNumber := t.mtu.candidate, t.mtu.packet
		t.mtu.dropCandidate()
		t.dropProbe(packetNumber)
		t.association.logInfo("mtu probe of ", candidate, " unanswered, mtu stays ", t.association.mtuSize())
	}
	if !t.keepAliveAt.IsZero() && !now.Before(t.keepAliveAt) {
		if t.inFlight.len() == 0 && len(t.queue) == 0 {
			t.pushControl(appendPingFrame(nil), true)
		}
		t.keepAliveAt = now.Add(t.association.options.KeepAlivePeriod)
	}
	if t.inFlight.len() > 0 && !now.Before(t.ptoDeadline()) {
		if cause := t.probeLocked(now); cause != nil {
			return cause
		}
	}
	return nil
}

func (t *txState) dropProbe(packetNumber uint32) {
	for _, packet := range t.inFlight.packets {
		if packet.packetNumber != packetNumber {
			continue
		}
		t.inFlight.remove(packet)
		releaseFrames(packet.frames)
		return
	}
}

func (t *txState) probeLocked(now time.Time) error {
	oldest := t.inFlight.oldest()
	if oldest == nil {
		return nil
	}
	t.probes++
	if t.probes == 1 {
		t.probeSince = now
	}
	if now.Sub(t.probeSince) >= maxProbeSilence {
		t.association.logInfo("probe ", oldest.packetNumber, " unanswered for ", maxProbeSilence, ", closing")
		return ErrProbeTimeout
	}
	t.association.stats.probes.Add(1)
	t.queue = append([]outFrame{{payload: appendPingFrame(nil), ackEliciting: true, probe: true}}, t.queue...)
	return nil
}

func (t *txState) ptoDeadline() time.Time {
	oldest := t.inFlight.oldest()
	if oldest == nil {
		return time.Time{}
	}
	backoff := min(t.probes, maxProbeBackoff)
	return oldest.sentAt.Add(t.rtt.pto() << backoff)
}

func (t *txState) enqueueAck(now time.Time) {
	t.ackAt = time.Time{}
	payload := t.ack.pack(now)
	if len(payload) == 0 {
		return
	}
	t.ackQueue = append(t.ackQueue, outFrame{payload: payload})
}

func (t *txState) rxPacket(packetNumber uint32, ackEliciting bool, now time.Time) {
	t.idleAt = now.Add(t.association.options.IdleTimeout)
	if !ackEliciting {
		return
	}
	immediate := t.ack.received(packetNumber, now)
	if immediate {
		t.enqueueAck(now)
		return
	}
	if t.ackAt.IsZero() {
		t.ackAt = now.Add(t.ackDelay())
	}
}

func (t *txState) ackDelay() time.Duration {
	if !t.rtt.sampled {
		return maxAckDelay
	}
	return min(maxAckDelay, max(minAckDelay, t.rtt.smoothed/8))
}

func (t *txState) nextDeadline(now time.Time) time.Time {
	deadline := t.idleAt
	consider := func(at time.Time) {
		if at.IsZero() {
			return
		}
		if deadline.IsZero() || at.Before(deadline) {
			deadline = at
		}
	}
	consider(t.ackAt)
	consider(t.keepAliveAt)
	consider(t.statsAt)
	if t.mtu.active {
		consider(t.mtu.deadline)
	}
	if t.inFlight.len() > 0 {
		consider(t.ptoDeadline())
	}
	switch {
	case len(t.ackQueue) > 0:
		consider(now)
	case len(t.queue) > 0 && (t.queue[0].probe || t.windowAllows()):
		if wait := t.cc.PacingWait(now); wait > 0 {
			consider(now.Add(wait))
		} else {
			consider(now)
		}
	}
	return deadline
}

func (t *txState) stepDown() bool {
	current := t.association.mtuSize()
	next, loaded := t.mtu.nextBelow(current)
	if !loaded {
		return false
	}
	t.association.maxPayload.Store(int32(next - headerLen - tagLen))
	return true
}
