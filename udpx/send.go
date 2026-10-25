package udpx

import (
	"context"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Sending
//
// The send path has two queues: frames waiting to be sent, and packets waiting
// to be acknowledged. Keeping them apart is what turns a lost packet into work:
// its frames go back to the head of the first queue and the packet leaves the
// second.
//
// A frame is encoded when it is queued and never again. A frame that is sent
// again is the same bytes in a new packet, so nothing about it can change
// between attempts, and nothing about the packet it travels in is remembered by
// the frame beyond its number.
type outFrame struct {
	// payload is the encoded frame, ready to be copied into a packet.
	payload []byte

	// lastSent is the packet number the frame was last sent in.
	lastSent uint32

	// ackEliciting says whether the frame asks the peer for an acknowledgement.
	// A packet of nothing but acknowledgements is never acknowledged in turn,
	// which is what keeps two ends from acknowledging each other forever.
	ackEliciting bool
}

// frameQueue is the frames waiting to be sent, in the order they were produced.
// Whoever queues a frame hands its bytes over: the queue is what keeps them
// alive until they are in a packet.
type frameQueue struct {
	frames []outFrame
}

func (q *frameQueue) push(frame outFrame) {
	q.frames = append(q.frames, frame)
}

// pushFront puts frames back at the head of the queue, keeping their order: the
// frame that was sent longest ago is the one that has been waited for longest.
func (q *frameQueue) pushFront(frames []outFrame) {
	if len(frames) == 0 {
		return
	}
	q.frames = append(frames, q.frames...)
}

func (q *frameQueue) len() int {
	return len(q.frames)
}

// take removes and returns the frames that fit in budget bytes. A frame that
// does not fit waits for the next packet rather than being split: a frame is the
// unit that is retransmitted, so a frame that changed shape between attempts
// would need its own bookkeeping.
func (q *frameQueue) take(budget int) []outFrame {
	count := 0
	size := 0
	for count < len(q.frames) {
		length := len(q.frames[count].payload)
		if size+length > budget {
			break
		}
		size += length
		count++
	}
	if count == 0 {
		return nil
	}
	taken := q.frames[:count:count]
	q.frames = q.frames[count:]
	return taken
}

// sentPacket is one packet in flight.
type sentPacket struct {
	sentAt       time.Time
	frames       []outFrame
	size         int
	packetNumber uint32
	ackEliciting bool
}

// sentPackets is the set of packets in flight, ordered by packet number. Both
// ways a packet can leave it — an acknowledgement, or a loss — are reported as
// ranges of packet numbers, so removal is a pass over the ordered slice instead
// of a lookup per packet number.
type sentPackets struct {
	packets []*sentPacket
	bytes   int
}

func (s *sentPackets) append(packet *sentPacket) {
	s.packets = append(s.packets, packet)
	s.bytes += packet.size
}

func (s *sentPackets) len() int {
	return len(s.packets)
}

// acked removes the packets an acknowledgement covers and returns them.
func (s *sentPackets) acked(ranges []pnRange) []*sentPacket {
	if len(s.packets) == 0 || len(ranges) == 0 {
		return nil
	}
	var acked []*sentPacket
	kept := s.packets[:0]
	for _, packet := range s.packets {
		if containsPacketNumber(ranges, packet.packetNumber) {
			acked = append(acked, packet)
			s.bytes -= packet.size
			continue
		}
		kept = append(kept, packet)
	}
	s.packets = kept
	return acked
}

// remove drops one packet from flight, which is what a failed write leaves
// behind: the packet never left, so nothing will acknowledge it.
func (s *sentPackets) remove(packet *sentPacket) {
	for index, candidate := range s.packets {
		if candidate == packet {
			s.packets = append(s.packets[:index], s.packets[index+1:]...)
			s.bytes -= packet.size
			return
		}
	}
}

func containsPacketNumber(ranges []pnRange, packetNumber uint32) bool {
	for _, current := range ranges {
		if packetNumber > current.end {
			continue
		}
		if packetNumber >= current.start {
			return true
		}
	}
	return false
}

// flush packs the frames waiting to be sent into packets and sends them.
func (a *association) flush() error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	for a.queue.len() > 0 {
		frames := a.queue.take(maxPacketSize - headerLen - tagLen)
		if len(frames) == 0 {
			return E.New("frame of ", len(a.queue.frames[0].payload), " bytes does not fit in a packet")
		}
		err := a.sendFramesLocked(frames)
		if err != nil {
			return err
		}
	}
	return nil
}

// sendFramesLocked writes the frames as one packet. The caller holds sendMu,
// which is what keeps packet numbers leaving in the order they were assigned.
func (a *association) sendFramesLocked(frames []outFrame) error {
	select {
	case <-a.ctx.Done():
		return context.Cause(a.ctx)
	default:
	}
	h := header{
		ConnectionID: a.peerConnID,
		Type:         packetTypeData,
		Epoch:        a.sendRing.epoch(),
		PacketNumber: a.sendPacket,
	}
	payload := a.buildBuffer[:0]
	for _, frame := range frames {
		payload = append(payload, frame.payload...)
	}
	packet, err := a.sendRing.seal(a.sendBuffer[:0], h, nil, payload)
	if err != nil {
		return err
	}
	a.buildBuffer = payload[:0]
	a.sendBuffer = packet
	a.sendPacket++
	sent := &sentPacket{
		packetNumber: h.PacketNumber,
		sentAt:       time.Now(),
		size:         len(packet),
		frames:       frames,
	}
	for index := range frames {
		frames[index].lastSent = h.PacketNumber
		sent.ackEliciting = sent.ackEliciting || frames[index].ackEliciting
	}
	a.flightMu.Lock()
	a.inFlight.append(sent)
	a.flightMu.Unlock()
	_, err = a.conn.WriteTo(packet, a.RemoteAddr())
	if err != nil {
		a.flightMu.Lock()
		a.inFlight.remove(sent)
		a.flightMu.Unlock()
		return E.Cause(err, "write packet")
	}
	a.resetIdle()
	return nil
}
