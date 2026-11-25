package udpx

import (
	"encoding/binary"
	"math"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	receivedRangeLimit = 32

	maxAckRanges = receivedRangeLimit

	ackThreshold = 4

	minAckDelay = 4 * time.Millisecond

	maxAckDelay = 25 * time.Millisecond

	ackDelayLimit = math.MaxUint16 * time.Microsecond

	timerGranularity = time.Millisecond

	initialRTT = 333 * time.Millisecond
)

type pnRange struct {
	start uint32
	end   uint32
}

type pnRanges struct {
	ranges []pnRange
}

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
			continue
		}
		return pn <= current.end
	}
	return false
}

func (r *pnRanges) largest() (uint32, bool) {
	if len(r.ranges) == 0 {
		return 0, false
	}
	return r.ranges[0].end, true
}

type ack struct {
	ranges  [maxAckRanges]pnRange
	delay   time.Duration
	largest uint32
	count   int
}

func parseAckFrame(body []byte) (ack, error) {
	if len(body) < 4+2+1 {
		return ack{}, errShortFrame
	}
	count := int(body[6])
	if count == 0 || count > maxAckRanges {
		return ack{}, E.New("acknowledgement of ", count, " ranges")
	}
	if len(body) < 4+2+1+count*8 {
		return ack{}, errShortFrame
	}
	var result ack
	result.largest = binary.BigEndian.Uint32(body)
	result.delay = time.Duration(binary.BigEndian.Uint16(body[4:])) * time.Microsecond
	result.count = count
	for index := range count {
		start := binary.BigEndian.Uint32(body[7+index*8:])
		end := binary.BigEndian.Uint32(body[7+index*8+4:])
		if start > end {
			return ack{}, E.New("acknowledged range of ", start, " above ", end)
		}
		result.ranges[index] = pnRange{start: start, end: end}
	}
	return result, nil
}

func (a ack) appendTo(dst []byte) []byte {
	bodyLen := 4 + 2 + 1 + a.count*8
	dst = append(dst, frameTypeAck, byte(bodyLen>>8), byte(bodyLen))
	dst = binary.BigEndian.AppendUint32(dst, a.largest)
	delay := min(a.delay, ackDelayLimit)
	dst = binary.BigEndian.AppendUint16(dst, uint16(delay/time.Microsecond))
	dst = append(dst, byte(a.count))
	for index := range a.count {
		dst = binary.BigEndian.AppendUint32(dst, a.ranges[index].start)
		dst = binary.BigEndian.AppendUint32(dst, a.ranges[index].end)
	}
	return dst
}

type ackScheduler struct {
	ranges    pnRanges
	largestAt time.Time
	elicited  int
	pending   bool
}

func (s *ackScheduler) received(pn uint32, now time.Time) bool {
	previousLargest, hadLargest := s.ranges.largest()
	if !s.ranges.add(pn) {
		return false
	}
	s.pending = true
	s.elicited++
	if !hadLargest || pn > previousLargest {
		s.largestAt = now
		return s.elicited >= ackThreshold
	}
	return true
}

func (s *ackScheduler) pack(now time.Time) []byte {
	if !s.pending || len(s.ranges.ranges) == 0 {
		s.pending = false
		return nil
	}
	var packed ack
	packed.largest = s.ranges.ranges[0].end
	packed.count = min(len(s.ranges.ranges), maxAckRanges)
	copy(packed.ranges[:], s.ranges.ranges[:packed.count])
	packed.delay = now.Sub(s.largestAt)
	s.pending = false
	s.elicited = 0
	return packed.appendTo(nil)
}

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

func (e *rttEstimator) pto() time.Duration {
	return e.rto() + maxAckDelay
}

func lossDelay(rtt rttEstimator) time.Duration {
	base := rtt.smoothed
	if rtt.latest > base {
		base = rtt.latest
	}
	if base <= 0 {
		base = initialRTT
	}
	delay := time.Duration(float64(base)*timeThreshold) + maxAckDelay
	if delay < timerGranularity {
		delay = timerGranularity
	}
	return delay
}

func (e *rttEstimator) MinRTT() time.Duration {
	return e.min
}
