package congestion

import (
	"testing"
	"time"
)

type fixedRTT time.Duration

func (f fixedRTT) MinRTT() time.Duration { return time.Duration(f) }

const (
	testDatagramSize = 1200
	testRoundTrip    = 50 * time.Millisecond
	testWindow       = 32 * testDatagramSize
)

type bbrSimulation struct {
	controller Controller
	now        time.Time
	packet     PacketNumber
	sent       []AckedPacketInfo
	inFlight   ByteCount
}

func newBBRSimulation() *bbrSimulation {
	controller := NewBbrController(testDatagramSize, initialCongestionWindowPackets)
	controller.SetMinRTTProvider(fixedRTT(testRoundTrip))
	return &bbrSimulation{
		controller: controller,
		now:        time.Unix(0, 0),
	}
}

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

func (s *bbrSimulation) acknowledge() {
	priorInFlight := s.inFlight
	s.now = s.now.Add(testRoundTrip)
	s.controller.OnCongestionEvent(priorInFlight, s.now, s.sent, nil)
	s.inFlight -= ByteCount(len(s.sent)) * testDatagramSize
	s.sent = s.sent[:0]
}

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

func TestBbrProbeRttEndsWithoutADrain(t *testing.T) {
	simulation := newBBRSimulation()
	simulation.send(100)
	settle := func(count int) {
		acked := simulation.sent[:count]
		simulation.now = simulation.now.Add(testRoundTrip)
		simulation.controller.OnCongestionEvent(simulation.inFlight, simulation.now, acked, nil)
		simulation.inFlight -= ByteCount(count) * testDatagramSize
		simulation.sent = simulation.sent[count:]
	}
	settle(1)
	if minRtt := simulation.controller.(*bbrSender).minRtt; minRtt == 0 {
		t.Fatal("the round trip was never measured")
	}
	simulation.now = simulation.now.Add(minRttExpiry + time.Second)
	settle(1)
	if mode := simulation.controller.(*bbrSender).mode; mode != bbrModeProbeRtt {
		t.Fatalf("mode %s after the minimum round trip expired", mode)
	}
	for round := 0; round < 30; round++ {
		settle(1)
	}
	if mode := simulation.controller.(*bbrSender).mode; mode == bbrModeProbeRtt {
		t.Fatalf("still in probe_rtt after thirty rounds without a drain")
	}
}

func TestBbrProbeRttSkippedWhileLosing(t *testing.T) {
	simulation := newBBRSimulation()
	simulation.send(100)
	settle := func(count int, lost int) {
		acked := simulation.sent[:count]
		lostPackets := make([]LostPacketInfo, 0, lost)
		for index := 0; index < lost; index++ {
			packet := simulation.sent[count+index]
			lostPackets = append(lostPackets, LostPacketInfo{
				SendState:    packet.SendState,
				TimeSent:     packet.TimeSent,
				BytesLost:    testDatagramSize,
				PacketNumber: packet.PacketNumber,
			})
		}
		simulation.now = simulation.now.Add(testRoundTrip)
		simulation.controller.OnCongestionEvent(simulation.inFlight, simulation.now, acked, lostPackets)
		simulation.inFlight -= ByteCount(count+lost) * testDatagramSize
		simulation.sent = simulation.sent[count+lost:]
	}
	settle(1, 0)
	simulation.now = simulation.now.Add(minRttExpiry + time.Second)
	settle(1, 1)
	if mode := simulation.controller.(*bbrSender).mode; mode == bbrModeProbeRtt {
		t.Fatal("probe_rtt entered on a round that lost packets")
	}
}

func TestBbrEstimateBoundedByPacing(t *testing.T) {
	sender := newBbrSender(testDatagramSize, initialCongestionWindowPackets)
	sender.SetMinRTTProvider(fixedRTT(testRoundTrip))
	now := time.Unix(0, 0)
	var inFlight ByteCount
	var sent []AckedPacketInfo
	for index := 0; index < 16; index++ {
		packet := PacketNumber(index + 1)
		state := sender.OnPacketSent(now, inFlight, packet, testDatagramSize)
		inFlight += testDatagramSize
		sent = append(sent, AckedPacketInfo{
			SendState:    state,
			TimeSent:     now,
			BytesAcked:   testDatagramSize,
			PacketNumber: packet,
		})
	}
	paced := sender.pacingRate()
	sender.OnCongestionEvent(inFlight, now.Add(time.Millisecond), sent, nil)
	if estimate := sender.bandwidthEstimate(); estimate > paced {
		t.Fatalf("estimate of %d bits per second above the paced rate of %d", estimate, paced)
	}
}
