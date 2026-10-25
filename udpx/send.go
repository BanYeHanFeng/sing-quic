package udpx

import (
	"context"
	"sort"
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

// takeAckOnly removes the acknowledgements at the head of the queue, up to what
// fits in one packet. They are the one kind of frame that is not congestion
// controlled: everything the other end sends waits for them, so a closed window
// that holds them back is a window that never opens again.
func (q *frameQueue) takeAckOnly(budget int) []outFrame {
	count := 0
	size := 0
	for count < len(q.frames) && !q.frames[count].ackEliciting {
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

// frameType returns the type of the frame the entry carries.
func (f outFrame) frameType() frameType {
	return frameType(f.payload[0] & frameTypeBits)
}

// sentPacket is one packet in flight.
type sentPacket struct {
	sentAt       time.Time
	frames       []outFrame
	size         int
	packetNumber uint32
	ackEliciting bool
	// removed says the packet left the flight table. The entry stays in the
	// ordered slice until the next compaction, because an acknowledgement covers
	// a range of packet numbers and rewriting the whole table once per range is
	// what turns a transfer into a quadratic amount of work.
	removed bool
}

// sentPackets is the set of packets in flight, ordered by packet number.
//
// An acknowledgement names ranges of packet numbers, so the packets it covers are
// found by searching the ordered slice instead of by a scan over everything in
// flight, and the ones that left are compacted out of it once a quarter of the
// table is gone. A loss is handled the same way, and both are reported as a
// prefix: a packet far behind what was acknowledged, or one that has been in
// flight long enough, is lost before anything that came after it.
type sentPackets struct {
	packets []*sentPacket
	bytes   int
	removed int
}

func (s *sentPackets) append(packet *sentPacket) {
	s.packets = append(s.packets, packet)
	s.bytes += packet.size
}

// len is how many packets are in flight, not how many entries the table holds.
func (s *sentPackets) len() int {
	return len(s.packets) - s.removed
}

// acked marks the packets an acknowledgement covers and returns them.
func (s *sentPackets) acked(ranges []pnRange) []*sentPacket {
	if len(s.packets) == 0 || len(ranges) == 0 {
		return nil
	}
	var acked []*sentPacket
	for _, current := range ranges {
		index := sort.Search(len(s.packets), func(index int) bool {
			return s.packets[index].packetNumber >= current.start
		})
		for ; index < len(s.packets) && s.packets[index].packetNumber <= current.end; index++ {
			packet := s.packets[index]
			if packet.removed {
				continue
			}
			if s.markRemoved(packet) {
				acked = append(acked, packet)
			}
		}
	}
	s.compact()
	return acked
}

// lost marks the packets that are lost by now and returns them, oldest first.
func (s *sentPackets) lost(now time.Time, largestAcked uint32, lossDelay time.Duration) []*sentPacket {
	var lost []*sentPacket
	for _, packet := range s.packets {
		if packet.removed {
			continue
		}
		if !isLost(packet, now, largestAcked, lossDelay) {
			// The table is ordered by packet number and, with it, by send time, so
			// nothing behind a packet that is not lost is lost either.
			break
		}
		if s.markRemoved(packet) {
			lost = append(lost, packet)
		}
	}
	s.compact()
	return lost
}

// remove drops one packet from flight, which is what a failed write leaves
// behind: the packet never left, so nothing will acknowledge it.
func (s *sentPackets) remove(packet *sentPacket) {
	s.markRemoved(packet)
	s.compact()
}

// oldest returns the packet that has been in flight longest.
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

// compact drops the entries that left the flight table once enough of them are
// gone for the pass to be worth it.
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

// isLost reports whether a packet is lost. A packet is lost when it is far enough
// behind what the peer acknowledged that a reordering cannot explain it, or when it
// has been in flight for longer than a round trip and something behind it was
// acknowledged, so its acknowledgement is therefore not on the way.
//
// A packet the peer has acknowledged nothing behind is not lost by the second rule
// however long it has been in flight: its answer may be exactly what is on the way,
// and a retransmission of it would be a duplicate. A packet like that is what the
// probe asks about instead, which is the one place where being late is the signal.
func isLost(packet *sentPacket, now time.Time, largestAcked uint32, lossDelay time.Duration) bool {
	if largestAcked < packet.packetNumber {
		return false
	}
	if largestAcked-packet.packetNumber >= packetThreshold {
		return true
	}
	return now.Sub(packet.sentAt) >= lossDelay
}

// flush packs the frames waiting to be sent into packets and sends them, as far
// as the congestion window and the pacing rate allow. What does not fit stays
// queued: an acknowledgement opens the window again and calls this.
func (a *association) flush() error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	for a.queue.len() > 0 {
		allowed, waitUntil := a.congestionBudget()
		if !allowed {
			acknowledgement := a.queue.takeAckOnly(maxPacketSize - headerLen - tagLen)
			if len(acknowledgement) > 0 {
				// The window is closed, but this packet is what the peer needs
				// before it can send anything, and an acknowledgement is not
				// congestion controlled. Two ends that each held one back would
				// wait for the other to open a window neither of them can open.
				err := a.sendFramesLocked(acknowledgement)
				if err != nil {
					return err
				}
				continue
			}
			if waitUntil.IsZero() {
				// The window is full: it opens when an acknowledgement arrives, and
				// nothing before that can change it.
				return nil
			}
			a.paceTimer.Reset(time.Until(waitUntil))
			return nil
		}
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
	if !sent.ackEliciting {
		// Nothing in this packet asks for an acknowledgement, so nothing will
		// ever acknowledge it: putting it in flight would leave an entry that can
		// only be given up on, and would keep the probe timer aimed at a packet
		// nobody is waiting for.
		_, err = a.conn.WriteTo(packet, a.RemoteAddr())
		if err != nil {
			return E.Cause(err, "write packet")
		}
		a.resetIdle()
		return nil
	}
	a.flightMu.Lock()
	wasEmpty := a.inFlight.len() == 0
	priorInFlight := a.inFlight.bytes
	a.inFlight.append(sent)
	a.flightMu.Unlock()
	_, err = a.conn.WriteTo(packet, a.RemoteAddr())
	if err != nil {
		a.flightMu.Lock()
		a.inFlight.remove(sent)
		a.flightMu.Unlock()
		return E.Cause(err, "write packet")
	}
	a.congestionSent(h.PacketNumber, len(packet), priorInFlight, true)
	a.resetIdle()
	// The probe timer belongs to the oldest packet in flight, so it is armed when
	// there was nothing in flight before this one. A packet that follows a
	// pending one is already covered by the wait that packet armed.
	if wasEmpty && sent.ackEliciting {
		a.armPTO()
	}
	return nil
}
