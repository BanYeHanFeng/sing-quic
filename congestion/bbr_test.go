package congestion

import (
	"testing"
	"time"
)

// fixedRTT is a round trip estimate for a path that was measured once and does not
// change, which is what makes a window test a test of the controller rather than of
// a path simulator.
type fixedRTT time.Duration

func (f fixedRTT) MinRTT() time.Duration      { return time.Duration(f) }
func (f fixedRTT) SmoothedRTT() time.Duration { return time.Duration(f) }
func (f fixedRTT) LatestRTT() time.Duration   { return time.Duration(f) }

const (
	testDatagramSize = 1200
	testRoundTrip    = 50 * time.Millisecond
	testWindow       = 32 * testDatagramSize
)

// bbrSimulation drives a controller the way a transport does: packets leave, then
// one acknowledgement settles a window's worth of them, and what comes out is what
// the transport would be allowed to send next.
type bbrSimulation struct {
	controller Controller
	now        time.Time
	packet     PacketNumber
	acked      []AckedPacketInfo
	inFlight   ByteCount
}

func newBBRSimulation() *bbrSimulation {
	controller := NewBbrController(testDatagramSize, ProfileConservative)
	controller.SetRTTStatsProvider(fixedRTT(testRoundTrip))
	return &bbrSimulation{
		controller: controller,
		now:        time.Unix(0, 0),
	}
}

// send puts count packets in flight, which is what the transport reports as they
// leave.
func (s *bbrSimulation) send(count int) {
	s.acked = s.acked[:0]
	for index := 0; index < count; index++ {
		sentAt := s.now
		s.packet++
		s.controller.OnPacketSent(sentAt, s.inFlight, s.packet, testDatagramSize, true)
		s.inFlight += testDatagramSize
		s.acked = append(s.acked, AckedPacketInfo{
			TimeSent:     sentAt,
			BytesAcked:   testDatagramSize,
			PacketNumber: s.packet,
		})
	}
}

// acknowledge settles everything in flight as acknowledged, one round trip later.
func (s *bbrSimulation) acknowledge() {
	priorInFlight := s.inFlight
	s.now = s.now.Add(testRoundTrip)
	s.controller.OnCongestionEvent(priorInFlight, s.now, s.acked, nil)
	s.inFlight -= ByteCount(len(s.acked)) * testDatagramSize
	s.acked = s.acked[:0]
}

// lose settles everything in flight with half of it lost, which is the shape of an
// answer that arrives despite the loss of what came before it.
func (s *bbrSimulation) lose() {
	priorInFlight := s.inFlight
	s.now = s.now.Add(testRoundTrip)
	lost := make([]LostPacketInfo, 0, len(s.acked)/2)
	for index := 0; index < len(s.acked); index += 2 {
		acked := s.acked[index]
		lost = append(lost, LostPacketInfo{
			TimeSent:     acked.TimeSent,
			BytesLost:    acked.BytesAcked,
			PacketNumber: acked.PacketNumber,
		})
	}
	s.controller.OnCongestionEvent(priorInFlight, s.now, s.acked, lost)
	s.inFlight = 0
	s.acked = s.acked[:0]
}

// TestBbrWindowGrows requires the window to leave the initial one when nothing is
// lost. A controller that is never told what arrived is one whose window stays where
// it started, which is what this transport did until the events were wired up.
func TestBbrWindowGrows(t *testing.T) {
	simulation := newBBRSimulation()
	if window := simulation.controller.GetCongestionWindow(); window != testWindow {
		t.Fatalf("window of %d before anything was sent", window)
	}
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.acknowledge()
	}
	window := simulation.controller.GetCongestionWindow()
	if window <= testWindow {
		t.Fatalf("window of %d after twenty round trips of clean acknowledgements", window)
	}
	if window > MaxCongestionWindowPackets*testDatagramSize {
		t.Fatalf("window of %d is larger than the ceiling", window)
	}
}

// TestBbrWindowFallsOnLoss requires the window to come back down when a round trip
// loses half of it, and the pacing rate to follow: a path that is dropping what is
// sent is not one to answer by sending more.
func TestBbrWindowFallsOnLoss(t *testing.T) {
	simulation := newBBRSimulation()
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.acknowledge()
	}
	grown := simulation.controller.GetCongestionWindow()
	simulation.send(32)
	simulation.lose()
	recovered := simulation.controller.GetCongestionWindow()
	if recovered >= grown {
		t.Fatalf("window of %d after losing half of a round trip, up from %d", recovered, grown)
	}
	if rate := simulation.controller.(*bbrSender).PacingRate(); rate < Bandwidth(minBps) {
		t.Fatalf("pacing rate of %v after losses", rate)
	}
	// What was lost grows back: the ceiling is the path, not the loss.
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.acknowledge()
	}
	if window := simulation.controller.GetCongestionWindow(); window <= recovered {
		t.Fatalf("window of %d after the path recovered from %d", window, recovered)
	}
}
