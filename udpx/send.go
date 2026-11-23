package udpx

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-quic/congestion"
	"github.com/sagernet/sing-quic/udpio"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type outFrame struct {
	payload []byte

	streamFrame streamFrame

	lastSent uint32

	ackEliciting bool
}

type streamFrame struct {
	carried bool

	stream *Stream

	chunk *sendChunk

	data   []byte
	offset uint64
	fin    bool
}

func (f outFrame) size() int {
	if f.streamFrame.carried {
		return streamFixedLen + len(f.streamFrame.data)
	}
	return len(f.payload)
}

func (f outFrame) appendTo(dst []byte) []byte {
	if f.streamFrame.carried {
		return appendStream(dst, f.streamFrame.stream.id, f.streamFrame.offset, f.streamFrame.fin, f.streamFrame.data)
	}
	return append(dst, f.payload...)
}

func releaseFrames(frames []outFrame) {
	for index := range frames {
		chunk := frames[index].streamFrame.chunk
		if chunk == nil {
			continue
		}
		frames[index].streamFrame.chunk = nil
		chunk.release()
	}
}

type frameQueue struct {
	frames []outFrame
}

func (q *frameQueue) push(frame outFrame) {
	q.frames = append(q.frames, frame)
}

func (q *frameQueue) pushFront(frames []outFrame) {
	if len(frames) == 0 {
		return
	}
	q.frames = append(frames, q.frames...)
}

func (q *frameQueue) len() int {
	return len(q.frames)
}

func (q *frameQueue) headAckEliciting() bool {
	return len(q.frames) > 0 && q.frames[0].ackEliciting
}

func (q *frameQueue) takeAckOnly(budget int) []outFrame {
	count := 0
	size := 0
	for count < len(q.frames) && !q.frames[count].ackEliciting {
		length := q.frames[count].size()
		if size+length > budget {
			break
		}
		size += length
		count++
	}
	if count == 0 {
		return nil
	}
	return q.takePrefix(count)
}

func (q *frameQueue) take(budget int) []outFrame {
	if len(q.frames) > 0 && q.frames[0].size() > budget {
		q.splitHead(budget)
	}
	count := 0
	size := 0
	for count < len(q.frames) {
		length := q.frames[count].size()
		if size+length > budget {
			break
		}
		size += length
		count++
	}
	if count == 0 {
		return nil
	}
	return q.takePrefix(count)
}

func (q *frameQueue) splitHead(budget int) {
	frame := q.frames[0]
	if !frame.streamFrame.carried {
		return
	}
	length := budget - streamFixedLen
	if length <= 0 || length >= len(frame.streamFrame.data) {
		return
	}
	head, tail := frame, frame
	head.streamFrame.data = frame.streamFrame.data[:length]
	head.streamFrame.fin = false
	tail.streamFrame.data = frame.streamFrame.data[length:]
	tail.streamFrame.offset = frame.streamFrame.offset + uint64(length)
	if frame.streamFrame.chunk != nil {
		frame.streamFrame.chunk.retain()
	}
	frame.streamFrame.stream.splitPendingFrame()
	q.frames = append(q.frames, outFrame{})
	copy(q.frames[2:], q.frames[1:])
	q.frames[0] = head
	q.frames[1] = tail
}

func (q *frameQueue) takePrefix(count int) []outFrame {
	taken := q.frames[:count:count]
	q.frames = q.frames[count:]
	if len(q.frames) == 0 {
		q.frames = nil
	}
	return taken
}

func (f outFrame) frameType() frameType {
	if f.streamFrame.carried {
		return frameTypeStream
	}
	return frameType(f.payload[0] & frameTypeBits)
}

type sentPacket struct {
	sentAt       time.Time
	frames       []outFrame
	size         int
	packetNumber uint32
	ackEliciting bool
	sendState    congestion.SendState
	mtuProbe     bool
	removed      bool
	lost         bool
}

type sentPackets struct {
	packets []*sentPacket
	bytes   int
	removed int
}

func (s *sentPackets) append(packet *sentPacket) {
	s.packets = append(s.packets, packet)
	s.bytes += packet.size
}

func (s *sentPackets) len() int {
	return len(s.packets) - s.removed
}

func (s *sentPackets) acked(ranges []pnRange) ([]*sentPacket, int) {
	if len(s.packets) == 0 || len(ranges) == 0 {
		return nil, 0
	}
	var acked []*sentPacket
	spurious := 0
	for _, current := range ranges {
		index := sort.Search(len(s.packets), func(index int) bool {
			return s.packets[index].packetNumber >= current.start
		})
		for ; index < len(s.packets) && s.packets[index].packetNumber <= current.end; index++ {
			packet := s.packets[index]
			if packet.removed {
				if packet.lost {
					spurious++
					packet.lost = false
				}
				continue
			}
			if s.markRemoved(packet) {
				acked = append(acked, packet)
			}
		}
	}
	s.compact()
	return acked, spurious
}

func (s *sentPackets) lost(now time.Time, largestAcked uint32, lossDelay time.Duration, ackTruncated bool) []*sentPacket {
	var lost []*sentPacket
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		if !isLost(packet, now, largestAcked, lossDelay, ackTruncated) {
			break
		}
		if s.markLost(packet) {
			lost = append(lost, packet)
		}
	}
	s.compact()
	return lost
}

func (s *sentPackets) markLost(packet *sentPacket) bool {
	if packet.removed {
		return false
	}
	packet.lost = true
	return s.markRemoved(packet)
}

func (s *sentPackets) remove(packet *sentPacket) bool {
	removed := s.markRemoved(packet)
	s.compact()
	return removed
}

func (s *sentPackets) oldest() *sentPacket {
	var oldest *sentPacket
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		if oldest == nil || packet.sentAt.Before(oldest.sentAt) {
			oldest = packet
		}
	}
	return oldest
}

func (s *sentPackets) markRemoved(packet *sentPacket) bool {
	if packet.removed {
		return false
	}
	packet.removed = true
	s.removed++
	s.bytes -= packet.size
	return true
}

func (s *sentPackets) compact() {
	if s.removed == 0 {
		return
	}
	if s.removed < len(s.packets)/4 && s.removed < 32 && len(s.packets) > 0 {
		return
	}
	kept := s.packets[:0]
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		kept = append(kept, packet)
	}
	for index := len(kept); index < len(s.packets); index++ {
		s.packets[index] = nil
	}
	s.packets = kept
	s.removed = 0
}

func isLost(packet *sentPacket, now time.Time, largestAcked uint32, lossDelay time.Duration, ackTruncated bool) bool {
	if largestAcked < packet.packetNumber {
		return false
	}
	if !ackTruncated && largestAcked-packet.packetNumber >= packetThreshold {
		return true
	}
	return now.Sub(packet.sentAt) >= lossDelay
}

const maxSendBatch = 16

const batchRoom = maxSendBatch * maxPacketSize

const writeDrainTimeout = 100 * time.Millisecond

type batch struct {
	buffer  []byte
	pending []pendingPacket
	sealed  int
	planned int
	packets []udpio.Packet
}

func newBatch() *batch {
	return &batch{buffer: make([]byte, 0, batchRoom)}
}

func (b *batch) reset() {
	for index := range b.pending {
		b.pending[index] = pendingPacket{}
	}
	b.pending = b.pending[:0]
	b.packets = b.packets[:0]
	b.sealed = 0
	b.planned = 0
	b.buffer = b.buffer[:0]
}

type pendingPacket struct {
	sent          *sentPacket
	packet        []byte
	payloadStart  int
	priorInFlight int
}

func (a *association) flush() error {
	a.pumpMu.Lock()
	defer a.pumpMu.Unlock()
	return a.pump()
}

func (a *association) pump() error {
	for {
		select {
		case <-a.ctx.Done():
			return context.Cause(a.ctx)
		default:
		}
		a.sendMu.Lock()
		if len(a.batch.pending) >= maxSendBatch {
			a.sendMu.Unlock()
			if err := a.writeBatch(); err != nil {
				return err
			}
			continue
		}
		if len(a.batch.pending) == 0 && a.queue.len() > 0 && a.queue.headAckEliciting() &&
			a.probeCredits == 0 && !a.closing.Load() && a.windowAllows() {
			wait := a.pacingWait()
			if wait > 0 {
				a.sendMu.Unlock()
				sleepAtLeast(wait)
				continue
			}
		}
		frames := a.nextFramesLocked()
		if frames == nil {
			pending := len(a.batch.pending) > 0
			empty := a.queue.len() == 0
			a.sendMu.Unlock()
			if pending {
				if err := a.writeBatch(); err != nil {
					return err
				}
			}
			if empty {
				a.congestionAppLimited()
			}
			return nil
		}
		err := a.planLocked(frames)
		a.sendMu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (a *association) nextFramesLocked() []outFrame {
	if a.queue.len() == 0 {
		return nil
	}
	if a.closing.Load() || a.probeCredits > 0 {
		if !a.closing.Load() {
			a.probeCredits--
		}
		return a.queue.take(a.maxPayload)
	}
	if a.windowAllows() {
		return a.queue.take(a.maxPayload)
	}
	return a.queue.takeAckOnly(a.maxPayload)
}

func (a *association) sendLoop() {
	defer close(a.sendDone)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.sendWake:
		}
		a.pumpMu.Lock()
		err := a.pump()
		a.pumpMu.Unlock()
		if err != nil {
			return
		}
	}
}

func (a *association) wake() {
	select {
	case a.sendWake <- struct{}{}:
	default:
	}
}

const sleepCoarse = 2 * time.Millisecond

func sleepAtLeast(d time.Duration) {
	if d > sleepCoarse {
		time.Sleep(d - sleepCoarse)
		d = sleepCoarse
	}
	nanosleep(d)
}

func (a *association) planLocked(frames []outFrame) error {
	payloadLen := 0
	for _, frame := range frames {
		payloadLen += frame.size()
	}
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeData,
		PacketNumber: a.sendPacket,
	}
	packet, payloadStart, err := a.reserveLocked(h, payloadLen)
	if err != nil {
		return err
	}
	payload := packet[payloadStart:payloadStart]
	for _, frame := range frames {
		payload = frame.appendTo(payload)
	}
	sent := &sentPacket{
		packetNumber: h.PacketNumber,
		frames:       frames,
		size:         len(packet),
	}
	for index := range frames {
		frames[index].lastSent = h.PacketNumber
		sent.ackEliciting = sent.ackEliciting || frames[index].ackEliciting
	}
	a.batch.pending = append(a.batch.pending, pendingPacket{sent: sent, packet: packet, payloadStart: payloadStart})
	a.batch.planned += len(packet)
	a.sendPacket++
	return nil
}

func (a *association) reserveLocked(h header, payloadLen int) (packet []byte, payloadStart int, err error) {
	length := headerLen + payloadLen + tagLen
	start := len(a.batch.buffer)
	if start+length > batchRoom {
		return nil, 0, E.New("packet of ", length, " bytes in a batch of ", start, " bytes")
	}
	written := h.appendTo(a.batch.buffer[start:start])
	a.batch.buffer = a.batch.buffer[:start+length]
	return a.batch.buffer[start : start+length], len(written), nil
}

func (a *association) sealPendingLocked() {
	if a.batch.sealed == len(a.batch.pending) {
		return
	}
	unsealed := a.batch.pending[a.batch.sealed:]
	for index := range unsealed {
		a.sendCipher.sealInPlace(unsealed[index].packet, unsealed[index].payloadStart, unsealed[index].sent.packetNumber)
	}
	a.batch.sealed = len(a.batch.pending)
}

func (a *association) writeBatch() error {
	a.sendMu.Lock()
	current := a.batch
	if len(current.pending) == 0 {
		a.sendMu.Unlock()
		return nil
	}
	a.sealPendingLocked()
	now := time.Now()
	remote := a.RemoteAddr()
	current.packets = current.packets[:0]
	bytes := 0
	for index := range current.pending {
		current.pending[index].sent.sentAt = now
		bytes += current.pending[index].sent.size
		current.packets = append(current.packets, udpio.Packet{Data: current.pending[index].packet, Addr: remote})
	}
	a.stats.sentPackets.Add(int64(len(current.packets)))
	a.stats.sentBytes.Add(int64(bytes))
	a.flightMu.Lock()
	wasEmpty := a.inFlight.len() == 0
	added := false
	for index := range current.pending {
		packet := &current.pending[index]
		if !packet.sent.ackEliciting {
			continue
		}
		if packet.sent.mtuProbe {
			continue
		}
		packet.priorInFlight = a.inFlight.bytes
		a.inFlight.append(packet.sent)
		added = true
	}
	a.flightMu.Unlock()
	for index := range current.pending {
		packet := &current.pending[index]
		if packet.sent.ackEliciting && !packet.sent.mtuProbe {
			packet.sent.sendState = a.congestionSent(packet.sent.packetNumber, packet.sent.size, packet.priorInFlight)
		}
	}
	a.resetIdle()
	if wasEmpty && added {
		a.armPTO()
	}
	written := current.pending
	current.pending = current.pending[:0]
	current.sealed = 0
	a.sendMu.Unlock()
	err := a.batchIO.WritePackets(current.packets)
	if err != nil {
		if isMessageTooLong(err) {
			if a.writingProbe.Load() {
				current.reset()
				a.mtuProbeFailed()
				return nil
			}
			if a.writeTooLong(written) {
				current.reset()
				return nil
			}
		}
		a.writeFailed(written, err)
		return err
	}
	current.reset()
	return nil
}

func (a *association) writeTooLong(failed []pendingPacket) bool {
	a.sendMu.Lock()
	refused := a.mtu
	stepped := a.mtuStepDownLocked()
	current := a.mtu
	a.sendMu.Unlock()
	if !stepped {
		return false
	}
	a.logInfo("mtu ", refused, " refused by the socket, mtu now ", current)
	a.flightMu.Lock()
	removed := make([]*sentPacket, 0, len(failed))
	for index := range failed {
		packet := failed[index].sent
		if !packet.ackEliciting {
			continue
		}
		if a.inFlight.remove(packet) {
			removed = append(removed, packet)
		}
	}
	a.flightMu.Unlock()
	if len(removed) > 0 {
		a.sendFramesRetransmitted(retransmittableFrames(removed))
	}
	a.flightMu.Lock()
	empty := a.inFlight.len() == 0
	a.flightMu.Unlock()
	if empty {
		a.disarmPTO()
	} else {
		a.armPTO()
	}
	return true
}

func (a *association) writeFailed(failed []pendingPacket, err error) {
	sizes := make([]int, 0, len(failed))
	for index := range failed {
		sizes = append(sizes, failed[index].sent.size)
	}
	a.logDebug("write failed: ", err, " packets=", len(failed), " sizes=", strings.Join(F.MapToString(sizes), ","), " probe=", a.writingProbe.Load())
	a.flightMu.Lock()
	for index := range failed {
		if failed[index].sent.ackEliciting {
			a.inFlight.remove(failed[index].sent)
		}
	}
	a.flightMu.Unlock()
	go a.shutdown(E.Cause(err, "write packets"), false)
}
