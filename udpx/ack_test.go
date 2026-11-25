package udpx

import (
	"testing"
	"time"
)

func TestPnRangesMerge(t *testing.T) {
	var ranges pnRanges
	for _, pn := range []uint32{4, 1, 2, 8, 3} {
		ranges.add(pn)
	}
	if len(ranges.ranges) != 2 {
		t.Fatalf("%d ranges", len(ranges.ranges))
	}
	if ranges.ranges[0] != (pnRange{start: 8, end: 8}) {
		t.Fatalf("first range %+v", ranges.ranges[0])
	}
	if ranges.ranges[1] != (pnRange{start: 1, end: 4}) {
		t.Fatalf("second range %+v", ranges.ranges[1])
	}
	if ranges.add(3) {
		t.Fatal("a duplicate was added")
	}
	if !ranges.contains(2) || ranges.contains(5) {
		t.Fatal("containment is wrong")
	}
}

func TestPnRangesLimit(t *testing.T) {
	var ranges pnRanges
	for index := range receivedRangeLimit + 8 {
		ranges.add(uint32(index * 2))
	}
	if len(ranges.ranges) > receivedRangeLimit {
		t.Fatalf("%d ranges are remembered", len(ranges.ranges))
	}
}

func TestAckScheduler(t *testing.T) {
	now := time.Now()
	var scheduler ackScheduler
	for index := range ackThreshold - 1 {
		if scheduler.received(uint32(index), now) {
			t.Fatal("an acknowledgement was owed too early")
		}
	}
	if !scheduler.received(ackThreshold-1, now) {
		t.Fatal("the threshold did not elicit an acknowledgement")
	}
	packed := scheduler.pack(now)
	if packed == nil {
		t.Fatal("nothing was packed")
	}
	if scheduler.pack(now) != nil {
		t.Fatal("the same acknowledgement was packed twice")
	}
	parsed, err := parseAckFrame(packed[frameHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.largest != ackThreshold-1 || parsed.count != 1 || parsed.ranges[0].start != 0 {
		t.Fatalf("packed %+v", parsed)
	}
}

func TestAckSchedulerImmediateOnReorder(t *testing.T) {
	now := time.Now()
	var scheduler ackScheduler
	scheduler.received(2, now)
	if !scheduler.received(0, now) {
		t.Fatal("a reordered packet did not elicit an acknowledgement")
	}
}

func TestAckDelayFollowsRTT(t *testing.T) {
	s := &sender{}
	if delay := s.ackDelay(); delay != maxAckDelay {
		t.Fatalf("%v before a sample", delay)
	}
	s.rtt.sample(400 * time.Millisecond)
	if delay := s.ackDelay(); delay != 50*time.Millisecond && delay != maxAckDelay {
		t.Fatalf("%v at 400ms", delay)
	}
	s.rtt.sample(8 * time.Millisecond)
	if delay := s.ackDelay(); delay < minAckDelay || delay > maxAckDelay {
		t.Fatalf("%v at 8ms", delay)
	}
}

func TestRTTEstimator(t *testing.T) {
	var estimator rttEstimator
	if estimator.rto() != initialRTT {
		t.Fatalf("initial rto %v", estimator.rto())
	}
	estimator.sample(100 * time.Millisecond)
	if estimator.smoothed != 100*time.Millisecond {
		t.Fatalf("smoothed %v", estimator.smoothed)
	}
	if estimated := estimator.rto(); estimated < 100*time.Millisecond {
		t.Fatalf("rto %v", estimated)
	}
	estimator.sample(200 * time.Millisecond)
	if estimator.latest != 200*time.Millisecond || estimator.min != 100*time.Millisecond {
		t.Fatalf("latest %v min %v", estimator.latest, estimator.min)
	}
	if estimator.smoothed <= 100*time.Millisecond || estimator.smoothed >= 200*time.Millisecond {
		t.Fatalf("smoothed %v", estimator.smoothed)
	}
	if estimator.pto() <= estimator.rto() {
		t.Fatal("pto did not include the acknowledgement delay")
	}
}

func TestLossDelayNeverZero(t *testing.T) {
	if delay := lossDelay(rttEstimator{}); delay < timerGranularity {
		t.Fatalf("loss delay %v", delay)
	}
	var estimator rttEstimator
	estimator.sample(time.Millisecond)
	if delay := lossDelay(estimator); delay < maxAckDelay {
		t.Fatalf("loss delay %v", delay)
	}
}
