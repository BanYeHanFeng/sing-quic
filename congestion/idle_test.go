package congestion

import (
	"testing"
	"time"
)

// idleSimulation is a controller driven through a transfer and then through the
// quiet that follows it, where the only packets left are the keep-alives an
// association sends when it has nothing to say.
type idleSimulation struct {
	controller *bbrSender
	now        time.Time
	packet     PacketNumber
	sent       []AckedPacketInfo
	inFlight   ByteCount
}

func newIdleSimulation() *idleSimulation {
	controller := newBbrSender(testDatagramSize, initialCongestionWindowPackets)
	controller.SetRTTStatsProvider(fixedRTT(testRoundTrip))
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

// TestBbrBandwidthSurvivesIdle requires the estimate a transfer measured to outlast
// the quiet after it. A keep-alive is a packet like any other to the sampler, and a
// filter that took it would replace a path that carries megabits with a hundred
// bytes a second: the window derived from it is the floor, and the transfer after
// the quiet starts from there. What tells the sampler that the quiet was the
// application's is the transport, which is the only one that knows its queue ran
// empty.
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

// TestBbrTransferAfterIdleIsMeasured requires the phase an idle association leaves
// behind to end with the first packet acknowledged: a keep-alive ignored is one
// thing, a transfer ignored is an estimate that never learns the path again.
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

// TestBbrStartupEndsWhenTheApplicationStops requires a startup that is never fed a
// transfer to end anyway. A round the application did not fill measures the
// application, not the path, which is why it is not counted against startup: what it
// does say, once enough of them have passed, is that the transfer startup is waiting
// for is not coming. The gain it keeps until then is two and a half times the
// estimate on every burst.
func TestBbrStartupEndsWhenTheApplicationStops(t *testing.T) {
	simulation := newIdleSimulation()
	// One filled round, so the path has said something and startup has a rate to
	// grow from.
	simulation.send(32, testDatagramSize)
	simulation.acknowledge()
	if mode := simulation.controller.mode; mode != bbrModeStartup {
		t.Fatalf("mode %s after the first round", mode)
	}
	// The application answers a request and stops, twenty times over.
	for round := 0; round < 20; round++ {
		simulation.controller.OnAppLimited()
		simulation.send(1, testDatagramSize)
		simulation.acknowledge()
	}
	if mode := simulation.controller.mode; mode == bbrModeStartup {
		t.Fatal("still in startup after twenty rounds the application did not fill")
	}
}
