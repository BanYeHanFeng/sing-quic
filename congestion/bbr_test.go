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
	sent       []AckedPacketInfo
	inFlight   ByteCount
}

func newBBRSimulation() *bbrSimulation {
	controller := NewBbrController(testDatagramSize, initialCongestionWindowPackets)
	controller.SetRTTStatsProvider(fixedRTT(testRoundTrip))
	return &bbrSimulation{
		controller: controller,
		now:        time.Unix(0, 0),
	}
}

// send puts count packets in flight, which is what the transport reports as they
// leave: what the controller hands back is kept beside each packet, as the flight
// table of the transport keeps it.
func (s *bbrSimulation) send(count int) {
	s.sent = s.sent[:0]
	for index := 0; index < count; index++ {
		sentAt := s.now
		s.packet++
		state := s.controller.OnPacketSent(sentAt, s.inFlight, s.packet, testDatagramSize)
		s.inFlight += testDatagramSize
		s.sent = append(s.sent, AckedPacketInfo{
			SendState:    state,
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
	s.controller.OnCongestionEvent(priorInFlight, s.now, s.sent, nil)
	s.inFlight -= ByteCount(len(s.sent)) * testDatagramSize
	s.sent = s.sent[:0]
}

// lose settles everything in flight with one packet in share lost, which is the
// shape of a path that drops a packet now and then and delivers the rest: what
// arrived is acknowledged, what did not is lost, and the delivery rate is the
// difference between the two.
func (s *bbrSimulation) lose(share int) {
	priorInFlight := s.inFlight
	s.now = s.now.Add(testRoundTrip)
	acked := make([]AckedPacketInfo, 0, len(s.sent))
	lost := make([]LostPacketInfo, 0, len(s.sent)/share)
	for index, packet := range s.sent {
		if index%share == 0 {
			lost = append(lost, LostPacketInfo{
				SendState:    packet.SendState,
				TimeSent:     packet.TimeSent,
				BytesLost:    packet.BytesAcked,
				PacketNumber: packet.PacketNumber,
			})
			continue
		}
		acked = append(acked, packet)
	}
	s.controller.OnCongestionEvent(priorInFlight, s.now, acked, lost)
	s.inFlight = 0
	s.sent = s.sent[:0]
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
	if window > maxCongestionWindowPackets*testDatagramSize {
		t.Fatalf("window of %d is larger than the ceiling", window)
	}
}

// TestBbrWindowSurvivesRandomLoss requires a path that drops one packet in ten to
// leave the window near where the model put it. The window is the delivery rate
// multiplied by the round trip, and a path dropping a tenth still delivers nine
// tenths: a window that falls for the loss itself reads the path as a queue, and
// on a path that always drops something it never leaves the floor.
func TestBbrWindowSurvivesRandomLoss(t *testing.T) {
	simulation := newBBRSimulation()
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.acknowledge()
	}
	grown := simulation.controller.GetCongestionWindow()
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.lose(10)
	}
	after := simulation.controller.GetCongestionWindow()
	if after < grown*3/4 {
		t.Fatalf("window of %d after twenty round trips losing a tenth of each, down from %d", after, grown)
	}
}

// TestBbrWindowFallsOnCongestion requires the window to come back down when the
// path itself narrows: the loss rate is not what shrinks it, but the delivery rate
// behind the loss is, and a round trip that answers half of what was sent is half
// the path.
func TestBbrWindowFallsOnCongestion(t *testing.T) {
	simulation := newBBRSimulation()
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.acknowledge()
	}
	grown := simulation.controller.GetCongestionWindow()
	for round := 0; round < 20; round++ {
		simulation.send(32)
		simulation.lose(2)
	}
	after := simulation.controller.GetCongestionWindow()
	if after >= grown {
		t.Fatalf("window of %d after twenty round trips losing half of each, up from %d", after, grown)
	}
	if after < simulation.controller.(*bbrSender).minCongestionWindow {
		t.Fatalf("window of %d under the floor", after)
	}
}

// TestBbrInitialWindowIsTheCallers requires the first window to be what the caller
// asked for and nothing else. The window a transfer starts with is what a path with
// room is measured against: every doubling from there costs a round trip, which is
// why the transport, and not this package, decides it.
func TestBbrInitialWindowIsTheCallers(t *testing.T) {
	for _, test := range []struct {
		packets int64
		window  ByteCount
	}{
		{packets: 0, window: initialCongestionWindowPackets * testDatagramSize},
		{packets: 128, window: 128 * testDatagramSize},
		{packets: 2, window: minCongestionWindowPackets * testDatagramSize},
	} {
		sender := newBbrSender(testDatagramSize, test.packets)
		window := sender.GetCongestionWindow()
		if window != test.window {
			t.Errorf("window of %d for %d packets asked for, want %d", window, test.packets, test.window)
		}
		if floor := sender.minCongestionWindow; window < floor {
			t.Errorf("window of %d under the floor of %d", window, floor)
		}
	}
}
