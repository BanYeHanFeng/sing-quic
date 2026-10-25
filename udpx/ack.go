package udpx

import (
	"encoding/binary"
	"math"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Acknowledgements
//
// The packet number is in the clear, so acknowledging packets is a matter of
// naming ranges of them: no per-packet state, no offset arithmetic, and a hole
// in the middle of a range is what tells the sender which packet to send again.
//
// Acknowledgements are not sent for every packet. A peer that answers each
// packet with a packet of its own doubles the traffic to say nothing, so an
// acknowledgement waits for the second ack-eliciting packet or for a short
// delay, whichever comes first, and goes out immediately when a packet arrives
// out of order: a hole is worth reporting as soon as it is known.
const (
	// maxAckRanges is how many disjoint ranges an acknowledgement carries. A
	// peer that has lost more than this many packets in a row is in the middle
	// of an outage, and the older ranges it would report are the ones whose
	// retransmissions are already on the way.
	maxAckRanges = 8

	// receivedRangeLimit bounds the ranges an association remembers. Ranges
	// rather than a bitmap or a list of numbers: a peer that skips a thousand
	// packet numbers costs one range, not a thousand entries.
	receivedRangeLimit = 32

	// ackThreshold is how many ack-eliciting packets may arrive before an
	// acknowledgement goes out without waiting for the delay.
	ackThreshold = 2

	// maxAckDelay is how long an acknowledgement may wait for a second packet.
	maxAckDelay = 25 * time.Millisecond

	// ackDelayLimit is the largest delay an acknowledgement can report, as the
	// field is a uint16 of microseconds.
	ackDelayLimit = math.MaxUint16 * time.Microsecond

	// timerGranularity is the floor of a retransmission timeout, so that a round
	// trip measured in microseconds does not turn into a timer no scheduler can
	// keep.
	timerGranularity = time.Millisecond
)

// pnRange is an inclusive range of packet numbers.
type pnRange struct {
	start uint32
	end   uint32
}

// pnRanges is the set of packet numbers received so far, kept as ranges sorted
// by packet number, newest first.
type pnRanges struct {
	ranges []pnRange
}

// add records pn and reports whether it was new.
func (r *pnRanges) add(pn uint32) bool {
	if r.contains(pn) {
		return false
	}
	index := 0
	for index < len(r.ranges) && r.ranges[index].start > pn {
		index++
	}
	r.ranges = append(r.ranges, pnRange{})
	copy(r.ranges[index+1:], r.ranges[index:])
	r.ranges[index] = pnRange{start: pn, end: pn}
	r.merge()
	return true
}

// merge joins ranges that touch and forgets the oldest ones.
func (r *pnRanges) merge() {
	kept := r.ranges[:1]
	for _, current := range r.ranges[1:] {
		previous := &kept[len(kept)-1]
		if previous.start-current.end <= 1 {
			previous.start = current.start
			continue
		}
		kept = append(kept, current)
	}
	r.ranges = kept
	if len(r.ranges) > receivedRangeLimit {
		r.ranges = r.ranges[:receivedRangeLimit]
	}
}

func (r *pnRanges) contains(pn uint32) bool {
	for _, current := range r.ranges {
		if pn < current.start {
			// The range is entirely above pn, and the ones after it are lower
			// still.
			continue
		}
		return pn <= current.end
	}
	return false
}

// largest returns the highest packet number received so far.
func (r *pnRanges) largest() (uint32, bool) {
	if len(r.ranges) == 0 {
		return 0, false
	}
	return r.ranges[0].end, true
}

// ack builds the acknowledgement of everything received so far.
func (r *pnRanges) ack() ack {
	var result ack
	if len(r.ranges) == 0 {
		return result
	}
	result.largest = r.ranges[0].end
	result.count = len(r.ranges)
	if result.count > maxAckRanges {
		result.count = maxAckRanges
	}
	copy(result.ranges[:], r.ranges[:result.count])
	return result
}

// ack is an acknowledgement: the packet numbers it covers, as ranges, plus how
// long the acknowledging end sat on it.
//
// The delay is part of it because a round trip sample taken from the moment a
// packet was sent to the moment its acknowledgement arrived includes the time
// the peer waited before sending it, and a sender that does not subtract it
// overestimates every round trip it measures.
type ack struct {
	ranges  [maxAckRanges]pnRange
	delay   time.Duration
	largest uint32
	count   int
}

// ackBodyLen is the size of the body of an acknowledgement frame.
func ackBodyLen(body []byte) (int, error) {
	if len(body) < 1+2+4+4 {
		return 0, errShortFrame
	}
	count := int(body[6])
	if count == 0 || count > maxAckRanges {
		return 0, E.New("acknowledgement of ", count, " ranges")
	}
	length := 1 + 2 + 4 + 4 + (count-1)*(4+4)
	if len(body) < length {
		return 0, errShortFrame
	}
	return length, nil
}

// parseAck parses the body of an acknowledgement frame.
func parseAck(body []byte) (ack, error) {
	if _, err := ackBodyLen(body); err != nil {
		return ack{}, err
	}
	var result ack
	count := int(body[6])
	if count == 0 || count > maxAckRanges {
		return ack{}, E.New("acknowledgement of ", count, " ranges")
	}
	result.largest = binary.BigEndian.Uint32(body)
	result.delay = time.Duration(binary.BigEndian.Uint16(body[4:])) * time.Microsecond
	result.count = count
	offset := 7
	end := result.largest
	firstRange := binary.BigEndian.Uint32(body[offset:])
	offset += 4
	if firstRange > end {
		return ack{}, E.New("first range of ", firstRange, " below packet number ", end)
	}
	result.ranges[0] = pnRange{start: end - firstRange, end: end}
	for index := 1; index < count; index++ {
		gap := binary.BigEndian.Uint32(body[offset:])
		length := binary.BigEndian.Uint32(body[offset+4:])
		offset += 8
		// The next range ends below the start of the previous one, with the
		// packets in between left unacknowledged.
		if gap >= result.ranges[index-1].start {
			return ack{}, E.New("gap of ", gap, " below packet number ", result.ranges[index-1].start)
		}
		end = result.ranges[index-1].start - gap - 1
		if length > end {
			return ack{}, E.New("range of ", length, " below packet number ", end)
		}
		result.ranges[index] = pnRange{start: end - length, end: end}
	}
	return result, nil
}

// appendTo appends the acknowledgement as a frame to dst.
func (a ack) appendTo(dst []byte) []byte {
	dst = append(dst, byte(frameTypeAck))
	dst = binary.BigEndian.AppendUint32(dst, a.largest)
	delay := a.delay
	if delay > ackDelayLimit {
		delay = ackDelayLimit
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(delay/time.Microsecond))
	dst = append(dst, byte(a.count))
	dst = binary.BigEndian.AppendUint32(dst, a.ranges[0].end-a.ranges[0].start)
	for index := 1; index < a.count; index++ {
		previous := a.ranges[index-1]
		current := a.ranges[index]
		dst = binary.BigEndian.AppendUint32(dst, previous.start-current.end-1)
		dst = binary.BigEndian.AppendUint32(dst, current.end-current.start)
	}
	return dst
}

// ackScheduler decides when what was received has to be acknowledged.
type ackScheduler struct {
	ranges    pnRanges
	largestAt time.Time
	elicited  int
	pending   bool
}

// received records an ack-eliciting packet and reports whether it has to be
// acknowledged at once rather than after the delay.
func (s *ackScheduler) received(pn uint32, now time.Time) bool {
	previousLargest, hadLargest := s.ranges.largest()
	if !s.ranges.add(pn) {
		// A duplicate reports nothing new, so it does not reset the delay
		// either: the peer sent a packet it did not hear about being received.
		return false
	}
	s.pending = true
	s.elicited++
	if !hadLargest || pn > previousLargest {
		s.largestAt = now
		return s.elicited >= ackThreshold
	}
	// A packet below the largest one is a hole, and a hole is what the sender
	// needs to know about before its own timer expires.
	return true
}

// pack builds the acknowledgement of everything received so far, or nil when
// there is nothing to acknowledge.
func (s *ackScheduler) pack(now time.Time) []byte {
	if !s.pending {
		return nil
	}
	built := s.ranges.ack()
	built.delay = now.Sub(s.largestAt)
	s.pending = false
	s.elicited = 0
	return built.appendTo(nil)
}

// sentHistory remembers when each packet number was sent, so that an
// acknowledgement can be turned into a round trip sample. It is a ring: an entry
// that old is either lost or already accounted for, and keeping every one of
// them would make the send path allocate.
type sentHistory struct {
	entries []sentPacket
}

type sentPacket struct {
	sentAt       time.Time
	packetNumber uint32
}

func newSentHistory(size int) sentHistory {
	return sentHistory{entries: make([]sentPacket, size)}
}

func (h *sentHistory) record(pn uint32, now time.Time) {
	if len(h.entries) == 0 {
		return
	}
	h.entries[pn%uint32(len(h.entries))] = sentPacket{packetNumber: pn, sentAt: now}
}

// sentAt returns when pn was sent, if it is still remembered.
func (h *sentHistory) sentAt(pn uint32) (time.Time, bool) {
	if len(h.entries) == 0 {
		return time.Time{}, false
	}
	entry := h.entries[pn%uint32(len(h.entries))]
	if entry.packetNumber != pn || entry.sentAt.IsZero() {
		return time.Time{}, false
	}
	return entry.sentAt, true
}

// rttEstimator is the round trip estimate a retransmission timeout is built
// from: a smoothed value and its variation, so a timeout can be generous on a
// jittery path and tight on a steady one.
type rttEstimator struct {
	smoothed time.Duration
	rttvar   time.Duration
	latest   time.Duration
	min      time.Duration
	sampled  bool
}

func (e *rttEstimator) sample(latest time.Duration) {
	if latest < 0 {
		latest = 0
	}
	e.latest = latest
	if !e.sampled {
		e.sampled = true
		e.smoothed = latest
		e.rttvar = latest / 2
		e.min = latest
		return
	}
	if latest < e.min {
		e.min = latest
	}
	difference := e.smoothed - latest
	if difference < 0 {
		difference = -difference
	}
	e.rttvar = (3*e.rttvar + difference) / 4
	e.smoothed = (7*e.smoothed + latest) / 8
}

// rto is how long to wait for an acknowledgement before considering a packet
// lost.
func (e *rttEstimator) rto() time.Duration {
	variation := 4 * e.rttvar
	if variation < timerGranularity {
		variation = timerGranularity
	}
	return e.smoothed + variation
}

// pto is how long to wait before probing the path, which is longer than the
// retransmission timeout by the delay an acknowledgement is allowed to sit on.
func (e *rttEstimator) pto() time.Duration {
	return e.rto() + maxAckDelay
}
