package udpx

import (
	"encoding/binary"
	"errors"
	"slices"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/congestion"
	"github.com/sagernet/sing-quic/udpx/internal/udpio"
)

type stepOutcome struct {
	packets []udpio.Packet
	wait    time.Duration
	cause   error
	done    bool
}

// step 一次加锁内完成：定时器、探测规划、打包、算下一次唤醒。
func (c *Conn) step(now time.Time) stepOutcome {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	s := &c.send
	var outcome stepOutcome
	outcome.cause = s.runTimers(now)
	if outcome.cause == nil {
		s.batch.reset()
		s.planProbe()
		s.take(now)
		outcome.packets = s.packets()
	}
	outcome.done = s.idle()
	if wait := time.Until(s.nextDeadline(now)); wait > 0 {
		outcome.wait = wait
	}
	return outcome
}

func (c *Conn) sendLoop() {
	defer c.finishFromLoop()
	defer close(c.sendDone)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		outcome := c.step(time.Now())
		if len(outcome.packets) > 0 {
			if err := c.write(outcome.packets); err != nil {
				c.fail(err, false)
			}
		}
		if outcome.cause != nil {
			c.fail(outcome.cause, true)
		}
		if outcome.done {
			return
		}
		timer.Reset(outcome.wait)
		select {
		case <-c.sendWake:
		case <-timer.C:
		case <-c.ctx.Done():
			return
		}
	}
}

// write 发出本批包。EMSGSIZE 说明路径装不下：丢弃探测候选或下调 MTU，帧放回队列重发。
func (c *Conn) write(packets []udpio.Packet) error {
	err := c.io.WritePackets(packets)
	if !isMessageTooLong(err) {
		return err
	}
	c.sendMu.Lock()
	s := &c.send
	failed := append([]*sentPacket(nil), s.batch.sent...)
	if slices.ContainsFunc(failed, func(packet *sentPacket) bool { return packet.mtu }) {
		candidate := s.mtu.candidate
		s.mtu.dropCandidate()
		s.releaseFailed(failed)
		c.sendMu.Unlock()
		c.logDebug("mtu ", candidate, " too large for the path")
		c.tracer.record("udpx:mtu_probe", traceMTUProbe{Candidate: candidate})
		return nil
	}
	refused := s.mtu.size
	if !s.stepDown() {
		c.sendMu.Unlock()
		c.logDebug("mtu ", refused, " refused by the socket and no candidate is left")
		return err
	}
	s.releaseFailed(failed)
	next := s.mtu.size
	c.sendMu.Unlock()
	c.logDebug("mtu ", refused, " refused by the socket, mtu now ", next)
	c.tracer.record("udpx:mtu_probe", traceMTUProbe{Candidate: refused})
	c.tracer.record("recovery:mtu_updated", traceMTU{MTU: next})
	return nil
}

func isMessageTooLong(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE)
}

// releaseFailed 把写失败的包里的帧放回队列，由累计确认重发。
func (s *sender) releaseFailed(failed []*sentPacket) {
	var retransmit []outFrame
	for _, sent := range failed {
		s.inFlight.remove(sent)
		for index := range sent.frames {
			frame := sent.frames[index]
			if frame.kind == frameMTU {
				frame.release()
				continue
			}
			frame.kind = frameData
			retransmit = append(retransmit, frame)
		}
	}
	if len(retransmit) > 0 {
		s.data = append(retransmit, s.data...)
	}
}

// queueFrame 入队一个需要对端确认的帧。
func (c *Conn) queueFrame(frame outFrame) {
	c.sendMu.Lock()
	c.send.queueData(frame)
	c.sendMu.Unlock()
	c.wake()
}

// queueControl 入队一个需要对端确认的控制帧（流控、RESET_STREAM）。
func (c *Conn) queueControl(payload []byte) {
	c.queueFrame(outFrame{payload: payload})
}

// take 把尽可能多的帧打成包：是否开批由 sendable 决定，批内只再受拥塞窗口限制。
func (s *sender) take(now time.Time) {
	if !s.sendable(now) {
		return
	}
	for len(s.batch.sent) < maxSendBatch {
		frames, ackEliciting := s.takeFrames()
		if frames == nil {
			return
		}
		if !s.packPacket(now, frames, ackEliciting) {
			return
		}
	}
}

// takeFrames 按固定顺序取下一包的帧：控制帧单独成包、MTU 探测独占一包、其余受窗口限制。
func (s *sender) takeFrames() ([]outFrame, bool) {
	if len(s.control) > 0 {
		return takePrefix(&s.control, s.payloadSize(), nil), false
	}
	if len(s.data) == 0 {
		return nil, false
	}
	if s.data[0].kind == frameMTU {
		frames := s.data[:1:1]
		s.data = s.data[1:]
		if len(s.data) == 0 {
			s.data = nil
		}
		return frames, true
	}
	windowOpen := s.cc.CanSend(s.inFlight.bytes)
	if !windowOpen && s.data[0].kind != frameProbe {
		return nil, false
	}
	if s.data[0].size() > s.payloadSize() && s.data[0].stream != nil {
		s.splitHead(s.payloadSize())
	}
	return takePrefix(&s.data, s.payloadSize(), func(frame outFrame) bool {
		return windowOpen || frame.kind != frameData
	}), true
}

// takePrefix 从队首取帧组成一个包；遇到 MTU 探测、不允许取的帧或装不下时停下。
func takePrefix(queue *[]outFrame, maxPayload int, allow func(outFrame) bool) []outFrame {
	frames := *queue
	count := 0
	size := 0
	for count < len(frames) {
		frame := frames[count]
		if frame.kind == frameMTU {
			break
		}
		if allow != nil && !allow(frame) {
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

// splitHead 把队首放不下的流帧就地切成两帧。
func (s *sender) splitHead(maxPayload int) {
	head := s.data[0]
	if len(head.payload) <= streamHeaderLen {
		return
	}
	data := head.payload[streamHeaderLen:]
	firstLen := maxPayload - streamHeaderLen
	if firstLen <= 0 || firstLen >= len(data) {
		return
	}
	offset := binary.BigEndian.Uint64(head.payload[7:])
	fin := head.payload[0]&frameFlagFin != 0
	first := newStreamFrame(head.stream, offset, false, data[:firstLen])
	second := newStreamFrame(head.stream, offset+uint64(firstLen), fin, data[firstLen:])
	head.release()
	s.data[0] = first
	s.data = append(s.data, outFrame{})
	copy(s.data[2:], s.data[1:])
	s.data[1] = second
}

// planProbe 规划一次 MTU 探测：探测帧追加到队尾，独占一个包。
func (s *sender) planProbe() {
	if s.closing || s.mtuQueued || s.mtu.active {
		return
	}
	candidate, loaded := s.mtu.next(s.mtu.size)
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
	s.mtuQueued = true
	s.data = append(s.data, outFrame{kind: frameMTU, payload: probe})
}

func (s *sender) packPacket(now time.Time, frames []outFrame, ackEliciting bool) bool {
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
	mtu := false
	for _, frame := range frames {
		copy(packet[offset:], frame.payload)
		offset += len(frame.payload)
		mtu = mtu || frame.kind == frameMTU
	}
	s.conn.sendCipher.seal(packet, headerLen, packetNumber)
	s.batch.buffer = s.batch.buffer[:start+length]
	sent := &sentPacket{
		sentAt:       now,
		frames:       frames,
		data:         packet,
		size:         length,
		packetNumber: packetNumber,
		ackEliciting: ackEliciting,
		mtu:          mtu,
	}
	if mtu {
		s.mtuQueued = false
		s.mtu.start(s.probeSize, packetNumber, now)
		s.probeSize = 0
	}
	s.sendPacket++
	if ackEliciting {
		s.lastSentAt = now
		priorInFlight := s.inFlight.bytes
		s.inFlight.append(sent)
		sent.sendState = s.cc.OnPacketSent(now, priorInFlight, congestion.PacketNumber(packetNumber), congestion.ByteCount(length))
	}
	s.batch.sent = append(s.batch.sent, sent)
	if s.conn.tracer != nil {
		traced := make([]traceFrame, len(frames))
		for index := range frames {
			traced[index] = traceFrameOf(frames[index].payload)
		}
		s.conn.tracer.record("transport:packet_sent", tracePacket{
			Header: tracePacketHeader{PacketType: "1RTT", PacketNumber: packetNumber},
			Raw:    tracePacketRaw{Length: length},
			Frames: traced,
		})
	}
	return true
}

// packets 把本批已发出的包交给发送循环。
func (s *sender) packets() []udpio.Packet {
	s.batch.packets = s.batch.packets[:0]
	remote := *s.conn.peerAddr.Load()
	for _, sent := range s.batch.sent {
		s.batch.packets = append(s.batch.packets, udpio.Packet{Data: sent.data, Addr: remote})
	}
	return s.batch.packets
}
