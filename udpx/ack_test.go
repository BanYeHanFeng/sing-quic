package udpx

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func fillRanges(ranges *pnRanges, from, to uint32) {
	for pn := from; pn <= to; pn++ {
		ranges.add(pn)
	}
}

func TestPnRangesInOrder(t *testing.T) {
	var ranges pnRanges
	fillRanges(&ranges, 0, 9)
	if len(ranges.ranges) != 1 {
		t.Fatalf("%d ranges for a sequence of packets", len(ranges.ranges))
	}
	if ranges.ranges[0] != (pnRange{start: 0, end: 9}) {
		t.Fatalf("range %+v", ranges.ranges[0])
	}
	if largest, loaded := ranges.largest(); !loaded || largest != 9 {
		t.Fatalf("largest %d", largest)
	}
}

func TestPnRangesDuplicate(t *testing.T) {
	var ranges pnRanges
	fillRanges(&ranges, 0, 9)
	if ranges.add(5) {
		t.Fatal("a duplicate packet was new")
	}
	if !ranges.contains(5) {
		t.Fatal("a received packet is not contained")
	}
	if ranges.contains(10) {
		t.Fatal("a packet that was not received is contained")
	}
	if len(ranges.ranges) != 1 {
		t.Fatalf("%d ranges after a duplicate", len(ranges.ranges))
	}
}

// TestPnRangesReordered requires a hole to be remembered and closed later
// without losing what surrounds it.
func TestPnRangesReordered(t *testing.T) {
	var ranges pnRanges
	fillRanges(&ranges, 0, 9)
	// 10 to 19 are lost; 20 arrives.
	if !ranges.add(20) {
		t.Fatal("a packet above the hole was not new")
	}
	if len(ranges.ranges) != 2 {
		t.Fatalf("%d ranges around a hole", len(ranges.ranges))
	}
	if ranges.ranges[0] != (pnRange{start: 20, end: 20}) || ranges.ranges[1] != (pnRange{start: 0, end: 9}) {
		t.Fatalf("ranges %+v", ranges.ranges)
	}
	// A packet inside the hole.
	if !ranges.add(15) {
		t.Fatal("a packet in the hole was not new")
	}
	if len(ranges.ranges) != 3 {
		t.Fatalf("%d ranges with a hole inside a hole", len(ranges.ranges))
	}
	// Filling the hole joins the three ranges into one.
	fillRanges(&ranges, 10, 19)
	if len(ranges.ranges) != 1 {
		t.Fatalf("%d ranges after the hole was filled", len(ranges.ranges))
	}
	if ranges.ranges[0] != (pnRange{start: 0, end: 20}) {
		t.Fatalf("range %+v", ranges.ranges[0])
	}
}

// TestPnRangesHugeJump requires a jump of a billion packet numbers to cost one
// range and one comparison rather than a billion entries.
func TestPnRangesHugeJump(t *testing.T) {
	var ranges pnRanges
	fillRanges(&ranges, 0, 2)
	if !ranges.add(1 << 30) {
		t.Fatal("a distant packet was not new")
	}
	if len(ranges.ranges) != 2 {
		t.Fatalf("%d ranges for a distant packet", len(ranges.ranges))
	}
	if !ranges.contains(1<<30) || ranges.contains(500) {
		t.Fatal("the distant packet was not placed")
	}
	if !ranges.add((1 << 30) - 1) {
		t.Fatal("the packet below a distant one was not new")
	}
	if len(ranges.ranges) != 2 {
		t.Fatalf("%d ranges below a distant packet", len(ranges.ranges))
	}
	if ranges.ranges[0] != (pnRange{start: (1 << 30) - 1, end: 1 << 30}) {
		t.Fatalf("range %+v", ranges.ranges[0])
	}
}

func TestPnRangesLimit(t *testing.T) {
	var ranges pnRanges
	for index := uint32(0); index < receivedRangeLimit+10; index++ {
		ranges.add(index * 100)
	}
	if len(ranges.ranges) > receivedRangeLimit {
		t.Fatalf("%d ranges", len(ranges.ranges))
	}
	// The newest ranges are the ones kept.
	if largest, _ := ranges.largest(); largest != (receivedRangeLimit+9)*100 {
		t.Fatalf("largest %d", largest)
	}
}

func TestAckRoundTrip(t *testing.T) {
	var ranges pnRanges
	fillRanges(&ranges, 0, 4)
	fillRanges(&ranges, 9, 12)
	ranges.add(20)
	built := ranges.ack()
	built.delay = 7 * time.Millisecond
	encoded := built.appendTo(nil)

	parsed, err := nextFrameAck(t, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.largest != built.largest || parsed.count != built.count || parsed.delay != built.delay {
		t.Fatalf("parsed %+v", parsed)
	}
	for index := range built.count {
		if parsed.ranges[index] != built.ranges[index] {
			t.Fatalf("range %d is %+v, want %+v", index, parsed.ranges[index], built.ranges[index])
		}
	}
}

func nextFrameAck(t *testing.T, encoded []byte) (ack, error) {
	t.Helper()
	f, rest, err := nextFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if f.frameType != frameTypeAck {
		t.Fatalf("frame of type %d", f.frameType)
	}
	if len(rest) != 0 {
		t.Fatalf("%d bytes after the acknowledgement", len(rest))
	}
	return parseAck(f.body)
}

func TestAckParseRejects(t *testing.T) {
	var ranges pnRanges
	fillRanges(&ranges, 0, 4)
	valid := ranges.ack().appendTo(nil)
	body := valid[1:]

	patched := func(patch func(body []byte) []byte) []byte {
		return patch(bytes.Clone(body))
	}
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"truncated", body[:len(body)-1]},
		{"no ranges", patched(func(body []byte) []byte { body[6] = 0; return body })},
		{"too many ranges", patched(func(body []byte) []byte { body[6] = maxAckRanges + 1; return body })},
		{"first range above largest", patched(func(body []byte) []byte { body[7] = 0xff; return body })},
	} {
		if _, err := parseAck(test.body); err == nil {
			t.Fatalf("%s: parsed", test.name)
		}
	}

	// A gap that reaches above the range it follows, and a range that reaches
	// below packet number zero.
	var twoRanges pnRanges
	fillRanges(&twoRanges, 0, 1)
	twoRanges.add(10)
	twoRangesBody := twoRanges.ack().appendTo(nil)[1:]
	gapOffset := 7 + 4
	for _, test := range []struct {
		name  string
		patch func(body []byte)
	}{
		{"gap above the previous range", func(body []byte) { binary.BigEndian.PutUint32(body[gapOffset:], 100) }},
		{"range below zero", func(body []byte) { binary.BigEndian.PutUint32(body[gapOffset+4:], 100) }},
	} {
		body := bytes.Clone(twoRangesBody)
		test.patch(body)
		if _, err := parseAck(body); err == nil {
			t.Fatalf("%s: parsed", test.name)
		}
	}
}

// TestAckScheduler requires the delay policy: the first packet waits, the second
// sends at once, and a hole is reported at once.
func TestAckScheduler(t *testing.T) {
	var scheduler ackScheduler
	now := time.Now()
	if scheduler.received(0, now) {
		t.Fatal("the first packet asked for an acknowledgement at once")
	}
	if scheduler.pack(now) == nil {
		t.Fatal("nothing was acknowledged")
	}
	if scheduler.pack(now) != nil {
		t.Fatal("the same acknowledgement was sent twice")
	}
	// The packet count is counted since the last acknowledgement, so the next
	// packet waits for its companion.
	if scheduler.received(1, now) {
		t.Fatal("the first packet after an acknowledgement asked for an immediate acknowledgement")
	}
	if !scheduler.received(2, now) {
		t.Fatal("the second packet after an acknowledgement did not ask for an immediate acknowledgement")
	}
	if scheduler.pack(now) == nil {
		t.Fatal("nothing was acknowledged")
	}

	// A hole is worth an acknowledgement before the delay expires.
	if scheduler.received(5, now) {
		t.Fatal("a new largest packet asked for an immediate acknowledgement")
	}
	if !scheduler.received(3, now) {
		t.Fatal("a packet below a hole did not ask for an immediate acknowledgement")
	}

	// A duplicate reports nothing new, so it neither acknowledges nor resets the
	// delay.
	scheduler.pack(now)
	if scheduler.received(3, now) {
		t.Fatal("a duplicate asked for an acknowledgement")
	}
	if scheduler.pack(now) != nil {
		t.Fatal("a duplicate was acknowledged")
	}
}

// TestAckDelayBudget requires the delay an acknowledgement reports to stay
// inside the field that carries it, and the delay the scheduler waits to stay
// inside the budget that a sender's timer is built from.
func TestAckDelayBudget(t *testing.T) {
	var scheduler ackScheduler
	start := time.Now()
	scheduler.received(0, start)
	body := scheduler.pack(start.Add(time.Hour))
	parsed, err := nextFrameAck(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.delay != ackDelayLimit {
		t.Fatalf("reported delay %v", parsed.delay)
	}

	if maxAckDelay > 100*time.Millisecond {
		t.Fatalf("a delayed acknowledgement may wait %v", maxAckDelay)
	}
	var second ackScheduler
	second.received(0, start)
	second.received(1, start)
	if second.pack(start.Add(maxAckDelay)) == nil {
		t.Fatal("a packet pair was not acknowledged within the delay budget")
	}
}

func TestSentHistory(t *testing.T) {
	history := newSentHistory(4)
	now := time.Now()
	history.record(9, now)
	if _, loaded := history.sentAt(9); !loaded {
		t.Fatal("a recorded packet is not remembered")
	}
	if _, loaded := history.sentAt(10); loaded {
		t.Fatal("a packet that was never sent is remembered")
	}
	// The entry for a packet number is overwritten by the packet a full ring
	// later, and the lookup tells them apart instead of returning the wrong time.
	history.record(13, now.Add(time.Second))
	if sentAt, loaded := history.sentAt(9); loaded {
		t.Fatalf("an overwritten packet is still remembered: %v", sentAt)
	}
	if sentAt, loaded := history.sentAt(13); !loaded || !sentAt.Equal(now.Add(time.Second)) {
		t.Fatal("the newer packet is not remembered")
	}
}

func TestRTTEstimator(t *testing.T) {
	var estimator rttEstimator
	estimator.sample(100 * time.Millisecond)
	if estimator.smoothed != 100*time.Millisecond || estimator.min != 100*time.Millisecond {
		t.Fatalf("first sample: %+v", estimator)
	}
	estimator.sample(50 * time.Millisecond)
	// smoothed = 7/8 of 100 + 1/8 of 50
	if estimator.smoothed < 93*time.Millisecond || estimator.smoothed > 94*time.Millisecond {
		t.Fatalf("smoothed %v", estimator.smoothed)
	}
	if estimator.min != 50*time.Millisecond {
		t.Fatalf("minimum %v", estimator.min)
	}
	if estimator.rto() <= estimator.smoothed {
		t.Fatalf("rto %v against smoothed %v", estimator.rto(), estimator.smoothed)
	}
	if estimator.pto() != estimator.rto()+maxAckDelay {
		t.Fatalf("pto %v", estimator.pto())
	}

	// A steady path shrinks the variation but never below the timer granularity.
	var steady rttEstimator
	for range 4 {
		steady.sample(10 * time.Millisecond)
	}
	if steady.rto() < steady.smoothed+timerGranularity {
		t.Fatalf("rto %v against smoothed %v", steady.rto(), steady.smoothed)
	}
	if steady.rto() > 100*time.Millisecond {
		t.Fatalf("rto %v on a steady path", steady.rto())
	}
}
