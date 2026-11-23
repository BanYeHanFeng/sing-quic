package udpx

import (
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/congestion"
)

func (t *txState) pack(now time.Time, maxPayload int) {
	for len(t.batch.sent) < maxSendBatch {
		if !t.hasPending() {
			return
		}
		allowData := t.windowAllows()
		if !allowData && len(t.ackQueue) == 0 {
			if !t.queue[0].probe {
				return
			}
		}
		frames := t.takeFrames(maxPayload, allowData)
		if frames == nil {
			return
		}
		if !t.packPacket(now, frames) {
			return
		}
	}
}

func (t *txState) takeFrames(maxPayload int, allowData bool) []outFrame {
	if len(t.ackQueue) > 0 {
		return takePrefix(&t.ackQueue, maxPayload, true)
	}
	if len(t.queue) == 0 {
		return nil
	}
	head := t.queue[0]
	if !allowData && head.ackEliciting && !head.probe {
		return nil
	}
	if head.probe {
		frames := t.queue[:1:1]
		t.queue = t.queue[1:]
		if len(t.queue) == 0 {
			t.queue = nil
		}
		return frames
	}
	if head.size() > maxPayload && head.stream != nil {
		t.splitHead(maxPayload)
	}
	return takePrefix(&t.queue, maxPayload, allowData)
}

func takePrefix(queue *[]outFrame, maxPayload int, allowData bool) []outFrame {
	frames := *queue
	count := 0
	size := 0
	for count < len(frames) {
		frame := frames[count]
		if frame.probe {
			break
		}
		if !allowData && frame.ackEliciting {
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

func (t *txState) splitHead(maxPayload int) {
	head := t.queue[0]
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
	t.queue[0] = first
	t.queue = append(t.queue, outFrame{})
	copy(t.queue[2:], t.queue[1:])
	t.queue[1] = second
}

func (t *txState) planProbe() {
	if t.closing || t.association.options.MTU > 0 || t.mtu.active {
		return
	}
	candidate, loaded := t.mtu.next(t.association.mtuSize())
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
	t.probeSize = candidate
	t.queue = append([]outFrame{{payload: probe, ackEliciting: true, probe: true}}, t.queue...)
}

func (t *txState) packPacket(now time.Time, frames []outFrame) bool {
	payloadLen := 0
	for _, frame := range frames {
		payloadLen += len(frame.payload)
	}
	length := headerLen + payloadLen + tagLen
	start := len(t.batch.buffer)
	if start+length > batchRoom {
		return false
	}
	packetNumber := t.sendPacket
	h := header{ConnectionID: t.association.peerConnID, Type: packetTypeData, PacketNumber: packetNumber}
	packet := t.batch.buffer[start : start+length]
	h.appendTo(packet[:0])
	offset := headerLen
	for _, frame := range frames {
		copy(packet[offset:], frame.payload)
		offset += len(frame.payload)
	}
	t.association.sendCipher.seal(packet, headerLen, packetNumber)
	t.batch.buffer = t.batch.buffer[:start+length]
	sent := &sentPacket{
		sentAt:       now,
		frames:       frames,
		data:         packet,
		size:         length,
		packetNumber: packetNumber,
	}
	for index := range frames {
		sent.ackEliciting = sent.ackEliciting || frames[index].ackEliciting
		sent.probe = sent.probe || frames[index].probe
	}
	if sent.probe {
		t.mtu.start(t.probeSize, packetNumber, now)
		t.probeSize = 0
	}
	t.sendPacket++
	if sent.ackEliciting {
		priorInFlight := t.inFlight.bytes
		t.inFlight.append(sent)
		sent.sendState = t.cc.OnPacketSent(now, priorInFlight, congestion.PacketNumber(packetNumber), congestion.ByteCount(length))
	}
	t.batch.sent = append(t.batch.sent, sent)
	t.association.stats.sentPackets.Add(1)
	t.association.stats.sentBytes.Add(int64(length))
	return true
}
