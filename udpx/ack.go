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
	//
	// Two is what a transport with one packet per system call can afford; here a
	// fast path leaves in batches of many packets, and answering every second one
	// of them turns most of what leaves the host into answers. Sixteen packets
	// say the same thing in one packet: the ranges an acknowledgement names
	// cover what arrived, and a run of sixteen of them costs one range. It is
	// also the batch size, so a full batch costs one answer instead of two, and
	// the same transfer leaves the host with a third fewer calls to the socket.
	//
	// The threshold cannot be made arbitrarily large: a window that holds fewer
	// packets than this sends that many and then waits, and the wait is the delay
	// below. That is why the delay follows the round trip (see ackDelay) rather
	// than being a constant: a path fast enough to have a window this small must
	// not be answered on the timescale of a slow one.
	ackThreshold = 16

	// minAckDelay is the shortest time an acknowledgement may wait for another
	// packet. A delay below the time a batch takes to arrive answers batches that
	// are still being assembled, which is the cost the threshold exists to avoid:
	// on loopback a floor of a millisecond left one transfer in five in a steady
	// state at half the throughput, and a floor of four milliseconds left none of
	// thirty-four there.
	minAckDelay = 4 * time.Millisecond

	// maxAckDelay is how long an acknowledgement may wait for another packet on a
	// path long enough for the round trip to be the larger term.
	maxAckDelay = 25 * time.Millisecond

	// ackDelayLimit is the largest delay an acknowledgement can report, as the
	// field is a uint16 of microseconds.
	ackDelayLimit = math.MaxUint16 * time.Microsecond

	// timerGranularity is the floor of a retransmission timeout, so that a round
	// trip measured in microseconds does not turn into a timer no scheduler can
	// keep.
	timerGranularity = time.Millisecond

	// initialRTT is the round trip a path is assumed to have before one was
	// measured. Declaring a packet lost before its acknowledgement could have
	// arrived is not loss recovery: on a path of a few hundred milliseconds it
	// retransmits the whole first window, and on one that is merely slow it
	// keeps doing so.
	initialRTT = 333 * time.Millisecond
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
//
// The recovered ranges are the other half of a forward error correction group:
// packets that never arrived but were rebuilt from parity. They are not
// acknowledgements of arrival and they are not losses either — the data is here,
// and the path still dropped it. The sender takes them out of flight without
// sending anything again and tells the congestion controller they were lost,
// which is the one place the difference between "the path lost this" and "the
// data is missing" is worth keeping.
type ack struct {
	ranges  [maxAckRanges]pnRange
	delay   time.Duration
	largest uint32
	count   int

	recovered      [maxAckRanges]pnRange
	recoveredLargest uint32
	recoveredCount int
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
	if len(body) < length+1+4 {
		return 0, errShortFrame
	}
	recoveredCount := int(body[length+4])
	if recoveredCount > maxAckRanges {
		return 0, E.New("acknowledgement of ", recoveredCount, " recovered ranges")
	}
	length += 1 + 4
	if recoveredCount > 0 {
		length += 4 + (recoveredCount-1)*(4+4)
	}
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
	result.recoveredLargest = binary.BigEndian.Uint32(body[offset:])
	result.recoveredCount = int(body[offset+4])
	offset += 5
	if result.recoveredCount == 0 {
		return result, nil
	}
	firstRecovered := binary.BigEndian.Uint32(body[offset:])
	offset += 4
	if firstRecovered > result.recoveredLargest {
		return ack{}, E.New("first recovered range of ", firstRecovered, " below packet number ", result.recoveredLargest)
	}
	result.recovered[0] = pnRange{start: result.recoveredLargest - firstRecovered, end: result.recoveredLargest}
	for index := 1; index < result.recoveredCount; index++ {
		gap := binary.BigEndian.Uint32(body[offset:])
		length := binary.BigEndian.Uint32(body[offset+4:])
		offset += 8
		if gap >= result.recovered[index-1].start {
			return ack{}, E.New("gap of ", gap, " below packet number ", result.recovered[index-1].start)
		}
		end = result.recovered[index-1].start - gap - 1
		if length > end {
			return ack{}, E.New("recovered range of ", length, " below packet number ", end)
		}
		result.recovered[index] = pnRange{start: end - length, end: end}
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
	dst = binary.BigEndian.AppendUint32(dst, a.recoveredLargest)
	dst = append(dst, byte(a.recoveredCount))
	if a.recoveredCount == 0 {
		return dst
	}
	dst = binary.BigEndian.AppendUint32(dst, a.recovered[0].end-a.recovered[0].start)
	for index := 1; index < a.recoveredCount; index++ {
		previous := a.recovered[index-1]
		current := a.recovered[index]
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
	// recovered is what forward error correction rebuilt and the peer has not
	// been told about: packets that never arrived, reported once so the sender can
	// stop counting them and charge the path for them. recoveredSeen is the same
	// set kept for longer, because a group can be rebuilt twice and the second copy
	// is not a second delivery.
	recovered     pnRanges
	recoveredSeen pnRanges
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

// wasReceived reports whether a packet number has already been taken off the
// wire. It is what keeps a recovered packet from being delivered twice: a member
// that arrived before its group was assembled is outside the cache the group was
// filled from, so the group believes it is missing and recovers it again.
//
// The ranges are the ones an acknowledgement names, so they cover the recent past
// and not the whole association. That is the same window a group lives in, which
// is why the answer is the right one here.
func (a *association) wasReceived(packetNumber uint32) bool {
	a.ackMu.Lock()
	defer a.ackMu.Unlock()
	return a.ack.ranges.contains(packetNumber) || a.ack.recoveredSeen.contains(packetNumber)
}

// markRecovered records a packet that parity rebuilt rather than the path
// delivered, so that the next acknowledgement tells the sender it was lost. It is
// not an acknowledgement of arrival: the packet is left out of the ranges for the
// same reason.
func (a *association) markRecovered(packetNumber uint32) {
	a.ackMu.Lock()
	a.ack.recovered.add(packetNumber)
	a.ack.recoveredSeen.add(packetNumber)
	a.ack.pending = true
	a.ackMu.Unlock()
	a.timers.Load().ack.Reset(a.ackDelay())
}

// pack builds the acknowledgement of everything received so far, or nil when
// there is nothing to acknowledge.
func (s *ackScheduler) pack(now time.Time) []byte {
	// An acknowledgement has to name at least one range it received: a recovered
	// packet is not one of them, so it waits for the next packet that was.
	if !s.pending || len(s.ranges.ranges) == 0 {
		s.pending = false
		return nil
	}
	built := s.ranges.ack()
	built.delay = now.Sub(s.largestAt)
	if len(s.recovered.ranges) > 0 {
		built.recoveredLargest = s.recovered.ranges[0].end
		built.recoveredCount = min(len(s.recovered.ranges), maxAckRanges)
		copy(built.recovered[:], s.recovered.ranges[:built.recoveredCount])
		s.recovered.ranges = s.recovered.ranges[:0]
	}
	s.pending = false
	s.elicited = 0
	return built.appendTo(nil)
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
	if !e.sampled {
		return initialRTT
	}
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
