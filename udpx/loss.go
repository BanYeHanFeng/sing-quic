package udpx

import (
	"time"

	"github.com/sagernet/sing-quic/udpx/internal/congestion"
	"github.com/sagernet/sing-quic/udpx/internal/udpio"
)

const (
	packetThreshold = 3

	timeThreshold = 9.0 / 8.0

	maxSendBatch = 16

	batchRoom = maxSendBatch * maxPacketSize
)

type sentPacket struct {
	sentAt       time.Time
	frames       []outFrame
	data         []byte
	size         int
	packetNumber uint32
	ackEliciting bool
	mtu          bool
	sendState    congestion.SendState
}

type inFlight struct {
	packets []*sentPacket
	bytes   congestion.ByteCount
}

func (f *inFlight) append(packet *sentPacket) {
	f.packets = append(f.packets, packet)
	f.bytes += congestion.ByteCount(packet.size)
}

func (f *inFlight) len() int {
	return len(f.packets)
}

func (f *inFlight) oldest() *sentPacket {
	if len(f.packets) == 0 {
		return nil
	}
	return f.packets[0]
}

func (f *inFlight) ack(ranges []pnRange) []*sentPacket {
	acked := make([]*sentPacket, 0, len(f.packets))
	kept := 0
	for _, packet := range f.packets {
		if coversPacketNumber(ranges, packet.packetNumber) {
			acked = append(acked, packet)
			continue
		}
		f.packets[kept] = packet
		kept++
	}
	for index := kept; index < len(f.packets); index++ {
		f.packets[index] = nil
	}
	f.packets = f.packets[:kept]
	f.recount()
	return acked
}

func (f *inFlight) lost(now time.Time, largestAcked uint32, lossDelay time.Duration, ackTruncated bool) []*sentPacket {
	count := 0
	for _, packet := range f.packets {
		if !isLostPacket(packet, now, largestAcked, lossDelay, ackTruncated) {
			break
		}
		count++
	}
	if count == 0 {
		return nil
	}
	lost := make([]*sentPacket, count)
	copy(lost, f.packets[:count])
	remaining := copy(f.packets, f.packets[count:])
	for index := remaining; index < len(f.packets); index++ {
		f.packets[index] = nil
	}
	f.packets = f.packets[:remaining]
	f.recount()
	return lost
}

func (f *inFlight) remove(packet *sentPacket) bool {
	for index, candidate := range f.packets {
		if candidate != packet {
			continue
		}
		f.packets = append(f.packets[:index], f.packets[index+1:]...)
		f.recount()
		return true
	}
	return false
}

func (f *inFlight) clear() []*sentPacket {
	packets := f.packets
	f.packets = nil
	f.bytes = 0
	return packets
}

func (f *inFlight) recount() {
	var bytes congestion.ByteCount
	for _, packet := range f.packets {
		bytes += congestion.ByteCount(packet.size)
	}
	f.bytes = bytes
}

func coversPacketNumber(ranges []pnRange, packetNumber uint32) bool {
	for _, current := range ranges {
		if packetNumber < current.start {
			continue
		}
		return packetNumber <= current.end
	}
	return false
}

func isLostPacket(packet *sentPacket, now time.Time, largestAcked uint32, lossDelay time.Duration, ackTruncated bool) bool {
	if largestAcked < packet.packetNumber {
		return false
	}
	if !ackTruncated && largestAcked-packet.packetNumber >= packetThreshold {
		return true
	}
	return now.Sub(packet.sentAt) >= lossDelay
}

type batch struct {
	buffer  []byte
	packets []udpio.Packet
	sent    []*sentPacket
}

func newBatch() batch {
	return batch{buffer: make([]byte, 0, batchRoom)}
}

func (b *batch) reset() {
	for index := range b.sent {
		b.sent[index] = nil
	}
	b.sent = b.sent[:0]
	b.packets = b.packets[:0]
	b.buffer = b.buffer[:0]
}

func (s *sender) mtuConfirmed(ack ack) {
	if !s.mtu.active || !coversPacketNumber(ack.ranges[:ack.count], s.mtu.packet) {
		return
	}
	candidate := s.mtu.candidate
	s.mtu.confirm()
	if candidate <= s.conn.mtuSize() {
		return
	}
	s.conn.maxPayload.Store(int32(candidate - headerLen - tagLen))
	s.conn.logDebug("mtu confirmed ", candidate)
}

func (s *sender) handleAck(ack ack, now time.Time) {
	if ack.count == 0 {
		return
	}
	s.mtuConfirmed(ack)
	priorInFlight := s.inFlight.bytes
	acked := s.inFlight.ack(ack.ranges[:ack.count])
	for _, packet := range acked {
		releaseFrames(packet.frames)
		if packet.packetNumber != ack.largest || !packet.ackEliciting {
			continue
		}
		s.rtt.sample(now.Sub(packet.sentAt) - ack.delay)
	}
	s.probes = 0
	s.probeSince = time.Time{}
	lostDelay := lossDelay(s.rtt)
	lost := s.inFlight.lost(now, ack.largest, lostDelay, ack.count >= maxAckRanges)
	var retransmit []outFrame
	for _, packet := range lost {
		for index := range packet.frames {
			frame := packet.frames[index]
			if retransmittable(frame.payload[0] & frameTypeMask) {
				retransmit = append(retransmit, frame)
				continue
			}
			frame.release()
		}
	}
	if len(retransmit) > 0 {
		s.queue = append(retransmit, s.queue...)
	}
	if len(acked) > 0 || len(lost) > 0 {
		ackedInfo := make([]congestion.AckedPacketInfo, 0, len(acked))
		for _, packet := range acked {
			if !packet.ackEliciting {
				continue
			}
			ackedInfo = append(ackedInfo, congestion.AckedPacketInfo{
				SendState:    packet.sendState,
				TimeSent:     packet.sentAt,
				BytesAcked:   congestion.ByteCount(packet.size),
				PacketNumber: congestion.PacketNumber(packet.packetNumber),
			})
		}
		lostInfo := make([]congestion.LostPacketInfo, 0, len(lost))
		for _, packet := range lost {
			if !packet.ackEliciting {
				continue
			}
			lostInfo = append(lostInfo, congestion.LostPacketInfo{
				SendState:    packet.sendState,
				TimeSent:     packet.sentAt,
				BytesLost:    congestion.ByteCount(packet.size),
				PacketNumber: congestion.PacketNumber(packet.packetNumber),
			})
		}
		s.cc.OnCongestionEvent(priorInFlight, now, ackedInfo, lostInfo)
	}
}
