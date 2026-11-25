package udpx

import (
	"errors"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/udpio"

	"github.com/sagernet/sing-quic/udpx/internal/congestion"

	E "github.com/sagernet/sing/common/exceptions"
)

type sendOutcome struct {
	packets  []udpio.Packet
	snapshot *statsSnapshot
	cause    error
}

func (c *Conn) sendStep(now time.Time) sendOutcome {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	s := &c.send
	var outcome sendOutcome
	if cause := s.runTimers(now); cause != nil {
		outcome.cause = cause
		return outcome
	}
	s.batch.reset()
	maxPayload := int(c.maxPayload.Load())
	s.planProbe()
	if s.shouldPack(now) {
		s.pack(now, maxPayload)
	}
	outcome.snapshot = s.snapshotIfDue(now)
	s.batch.packets = s.batch.packets[:0]
	remote := *c.peerAddr.Load()
	for _, sent := range s.batch.sent {
		s.batch.packets = append(s.batch.packets, udpio.Packet{Data: sent.data, Addr: remote})
	}
	outcome.packets = s.batch.packets
	return outcome
}

func (c *Conn) sendLoop() {
	defer close(c.sendDone)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		outcome := c.sendStep(time.Now())
		if len(outcome.packets) > 0 {
			err := c.io.WritePackets(outcome.packets)
			if err != nil {
				if c.sendWriteFailed(err) {
					continue
				}
				c.shutdown(E.Cause(err, "write packets"), false)
				return
			}
		}
		if outcome.snapshot != nil {
			c.logStats(outcome.snapshot)
		}
		if outcome.cause != nil {
			c.shutdown(outcome.cause, true)
			return
		}
		if c.sendIdle() {
			return
		}
		timer.Reset(c.sendWait())
		select {
		case <-c.sendWake:
		case <-timer.C:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Conn) sendWait() time.Duration {
	c.sendMu.Lock()
	deadline := c.send.nextDeadline(time.Now())
	c.sendMu.Unlock()
	wait := time.Until(deadline)
	if wait < 0 {
		return 0
	}
	return wait
}

func (c *Conn) sendWriteFailed(err error) bool {
	if !isMessageTooLong(err) {
		return false
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	s := &c.send
	failed := append([]*sentPacket(nil), s.batch.sent...)
	var probed bool
	for _, sent := range failed {
		probed = probed || sent.mtu
	}
	if probed {
		candidate := s.mtu.candidate
		s.mtu.dropCandidate()
		c.logInfo("mtu ", candidate, " too large for the path")
		c.releaseFailed(failed)
		return true
	}
	if !s.stepDown() {
		c.logInfo("mtu ", c.mtuSize(), " refused by the socket and no candidate is left")
		return false
	}
	c.logInfo("mtu refused by the socket, mtu now ", c.mtuSize())
	c.releaseFailed(failed)
	return true
}

func (c *Conn) releaseFailed(failed []*sentPacket) {
	s := &c.send
	var retransmit []outFrame
	for _, sent := range failed {
		s.inFlight.remove(sent)
		for index := range sent.frames {
			frame := sent.frames[index]
			if frame.mtu {
				frame.release()
				continue
			}
			retransmit = append(retransmit, frame)
		}
	}
	if len(retransmit) > 0 {
		s.queue = append(retransmit, s.queue...)
	}
}

func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

func (c *Conn) queueControl(payload []byte, ackEliciting bool) {
	c.sendMu.Lock()
	if c.send.closing {
		c.sendMu.Unlock()
		return
	}
	c.send.pushControl(payload, ackEliciting)
	c.sendMu.Unlock()
	c.wake()
}

func (c *Conn) queueStreamFrame(frame outFrame) {
	c.sendMu.Lock()
	if c.send.closing {
		c.sendMu.Unlock()
		frame.release()
		return
	}
	c.send.queue = append(c.send.queue, frame)
	c.sendMu.Unlock()
	c.wake()
}

func (c *Conn) sendIdle() bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.send.idle()
}
func (s *sender) pack(now time.Time, maxPayload int) {
	for len(s.batch.sent) < maxSendBatch {
		if !s.hasPending() {
			return
		}
		allowData := s.windowAllows()
		if !allowData && len(s.ackQueue) == 0 && !s.queue[0].probe && !s.queue[0].mtu {
			return
		}
		frames := s.takeFrames(maxPayload, allowData)
		if frames == nil {
			return
		}
		if !s.packPacket(now, frames) {
			return
		}
	}
}

func (s *sender) takeFrames(maxPayload int, allowData bool) []outFrame {
	if len(s.ackQueue) > 0 {
		return takePrefix(&s.ackQueue, maxPayload, true)
	}
	if len(s.queue) == 0 {
		return nil
	}
	head := s.queue[0]
	if head.mtu {
		frames := s.queue[:1:1]
		s.queue = s.queue[1:]
		if len(s.queue) == 0 {
			s.queue = nil
		}
		return frames
	}
	if !allowData && head.ackEliciting && !head.probe {
		return nil
	}
	if head.size() > maxPayload && head.stream != nil {
		s.splitHead(maxPayload)
	}
	return takePrefix(&s.queue, maxPayload, allowData)
}

func takePrefix(queue *[]outFrame, maxPayload int, allowData bool) []outFrame {
	frames := *queue
	count := 0
	size := 0
	for count < len(frames) {
		frame := frames[count]
		if frame.mtu {
			break
		}
		if !allowData && frame.ackEliciting && !frame.probe {
			break
		}
		if size+frame.size() > maxPayload {
			break
		}
		size += frame.size()
		count++
	}
	if count == 0 {
		return nil
	}
	taken := frames[:count:count]
	*queue = frames[count:]
	if len(*queue) == 0 {
		*queue = nil
	}
	return taken
}

func (s *sender) splitHead(maxPayload int) {
	head := s.queue[0]
	if len(head.payload) <= streamHeaderLen {
		return
	}
	data := head.payload[streamHeaderLen:]
	firstLen := maxPayload - streamHeaderLen
	if firstLen <= 0 || firstLen >= len(data) {
		return
	}
	var offset uint64
	for index := range 8 {
		offset = offset<<8 | uint64(head.payload[7+index])
	}
	fin := head.payload[0]&frameFlagFin != 0
	first := newStreamFrame(head.stream, offset, false, data[:firstLen])
	second := newStreamFrame(head.stream, offset+uint64(firstLen), fin, data[firstLen:])
	head.release()
	s.queue[0] = first
	s.queue = append(s.queue, outFrame{})
	copy(s.queue[2:], s.queue[1:])
	s.queue[1] = second
}

func (s *sender) planProbe() {
	if s.closing || s.probePending || s.conn.options.MTU > 0 || s.mtu.active {
		return
	}
	candidate, loaded := s.mtu.next(s.conn.mtuSize())
	if !loaded {
		return
	}
	payloadLen := candidate - headerLen - tagLen
	bodyLen := payloadLen - len(appendPingFrame(nil)) - frameHeaderLen
	if bodyLen < 0 {
		return
	}
	probe := appendPaddingFrame(appendPingFrame(nil), bodyLen)
	if len(probe) != payloadLen {
		return
	}
	s.probeSize = candidate
	s.probePending = true
	s.queue = append([]outFrame{{payload: probe, ackEliciting: true, mtu: true}}, s.queue...)
}

func (s *sender) packPacket(now time.Time, frames []outFrame) bool {
	payloadLen := 0
	for _, frame := range frames {
		payloadLen += len(frame.payload)
	}
	length := headerLen + payloadLen + tagLen
	start := len(s.batch.buffer)
	if start+length > batchRoom {
		return false
	}
	packetNumber := s.sendPacket
	h := header{ConnectionID: s.conn.peerID, Type: packetTypeData, PacketNumber: packetNumber}
	packet := s.batch.buffer[start : start+length]
	h.appendTo(packet[:0])
	offset := headerLen
	for _, frame := range frames {
		copy(packet[offset:], frame.payload)
		offset += len(frame.payload)
	}
	s.conn.sendCipher.seal(packet, headerLen, packetNumber)
	s.batch.buffer = s.batch.buffer[:start+length]
	sent := &sentPacket{
		sentAt:       now,
		frames:       frames,
		data:         packet,
		size:         length,
		packetNumber: packetNumber,
	}
	for index := range frames {
		sent.ackEliciting = sent.ackEliciting || frames[index].ackEliciting
		sent.mtu = sent.mtu || frames[index].mtu
	}
	if sent.mtu {
		s.probePending = false
		s.mtu.start(s.probeSize, packetNumber, now)
		s.probeSize = 0
	}
	s.sendPacket++
	if sent.ackEliciting {
		s.lastSentAt = now
		priorInFlight := s.inFlight.bytes
		s.inFlight.append(sent)
		sent.sendState = s.cc.OnPacketSent(now, priorInFlight, congestion.PacketNumber(packetNumber), congestion.ByteCount(length))
	}
	s.batch.sent = append(s.batch.sent, sent)
	s.conn.stats.sentPackets.Add(1)
	s.conn.stats.sentBytes.Add(int64(length))
	return true
}
