package congestion

import (
	"testing"
	"time"
)

type idleSimulation struct {
	controller *bbrSender
	now        time.Time
	packet     PacketNumber
	sent       []AckedPacketInfo
	inFlight   ByteCount
}

func newIdleSimulation() *idleSimulation {
	controller := newBbrSender(testDatagramSize, initialCongestionWindowPackets)
	controller.SetMinRTTProvider(fixedRTT(testRoundTrip))
	return &idleSimulation{controller: controller, now: time.Unix(0, 0)}
}

func (s *idleSimulation) send(count int, size ByteCount) {
	s.sent = s.sent[:0]
	for index := 0; index < count; index++ {
		sentAt := s.now
		s.packet++
		state := s.controller.OnPacketSent(sentAt, s.inFlight, s.packet, size)
		s.inFlight += size
		s.sent = append(s.sent, AckedPacketInfo{
			SendState:    state,
			TimeSent:     sentAt,
			BytesAcked:   size,
			PacketNumber: s.packet,
		})
	}
}

func (s *idleSimulation) acknowledge() {
	priorInFlight := s.inFlight
	s.now = s.now.Add(testRoundTrip)
	s.controller.OnCongestionEvent(priorInFlight, s.now, s.sent, nil)
	s.inFlight = 0
	s.sent = s.sent[:0]
}

func TestBbrBandwidthSurvivesIdle(t *testing.T) {
	simulation := newIdleSimulation()
	for round := 0; round < 40; round++ {
		simulation.send(int(simulation.controller.GetCongestionWindow()/testDatagramSize), testDatagramSize)
		simulation.acknowledge()
	}
	burstBandwidth := simulation.controller.bandwidthEstimate()
	burstWindow := simulation.controller.GetCongestionWindow()
	for round := 0; round < 20; round++ {
		simulation.controller.OnAppLimited()
		simulation.send(1, 100)
		simulation.acknowledge()
	}
	idleBandwidth := simulation.controller.bandwidthEstimate()
	idleWindow := simulation.controller.GetCongestionWindow()
	if idleBandwidth < burstBandwidth*3/4 {
		t.Fatalf("bandwidth estimate of %d after twenty idle round trips, down from %d", idleBandwidth, burstBandwidth)
	}
	if idleWindow < burstWindow*3/4 {
		t.Fatalf("window of %d after twenty idle round trips, down from %d", idleWindow, burstWindow)
	}
}

func TestBbrTransferAfterIdleIsMeasured(t *testing.T) {
	simulation := newIdleSimulation()
	for round := 0; round < 40; round++ {
		simulation.send(int(simulation.controller.GetCongestionWindow()/testDatagramSize), testDatagramSize)
		simulation.acknowledge()
	}
	burstBandwidth := simulation.controller.bandwidthEstimate()
	for round := 0; round < 20; round++ {
		simulation.controller.OnAppLimited()
		simulation.send(1, 100)
		simulation.acknowledge()
	}
	for round := 0; round < 40; round++ {
		simulation.send(int(simulation.controller.GetCongestionWindow()/testDatagramSize), testDatagramSize)
		simulation.acknowledge()
	}
	if measured := simulation.controller.bandwidthEstimate(); measured < burstBandwidth {
		t.Fatalf("bandwidth estimate of %d after the transfer resumed, down from %d", measured, burstBandwidth)
	}
}

func TestBbrStartupEndsWhenTheApplicationStops(t *testing.T) {
	simulation := newIdleSimulation()
	simulation.send(32, testDatagramSize)
	simulation.acknowledge()
	if mode := simulation.controller.mode; mode != bbrModeStartup {
		t.Fatalf("mode %s after the first round", mode)
	}
	for round := 0; round < 20; round++ {
		simulation.controller.OnAppLimited()
		simulation.send(1, testDatagramSize)
		simulation.acknowledge()
	}
	if mode := simulation.controller.mode; mode == bbrModeStartup {
		t.Fatal("still in startup after twenty rounds the application did not fill")
	}
}
