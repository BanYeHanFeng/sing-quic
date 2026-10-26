package congestion_test

// This package was copied out of congestion_meta2 with the quic-go types replaced by
// its own, so the two are supposed to be the same algorithm fed by different
// interfaces. Until now nothing said so: the copies were kept in step by hand, and a
// rewrite of one of them would have been a silent behaviour change for whoever
// migrates a transport from one to the other.
//
// The tests below drive both with one script and compare what comes out. Three things
// about how that has to be done:
//
//   - The script is open loop: how much is sent, which packet is given up on and when
//     an answer arrives are all decided before the controllers are asked anything. A
//     closed loop (send what the controller allows) would feed each side's answer back
//     into the next question, and a difference would be absorbed instead of shown.
//   - The script alternates bursts with quiet exchanges. A controller that is always
//     given more to send than it may has no reason to leave DRAIN, because in flight
//     never falls back to the bandwidth-delay product; and one that is always given
//     exactly a bandwidth-delay product per answer sits in PROBE_BW's 1.25 gain
//     phase forever, because in flight never reaches 1.25 of it. Both are properties
//     of the script, not of the controller, and both would hide the modes they lead
//     to.
//   - The random starting phase of the PROBE_BW gain cycle cannot be aligned between
//     two instances (math/rand is not seedable since Go 1.24), so anything that goes
//     through the phase is compared on the set of rates the cycle produces rather
//     than on the sequence. The window, the recovery state and CanSend do not go
//     through the phase at all and are compared value by value.

import (
	"maps"
	"slices"
	"testing"
	"time"

	qcongestion "github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"

	"github.com/sagernet/sing-quic/congestion"
	meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

const (
	// crossDatagramSize is the packet size both controllers are told about; the
	// script never changes it, because SetMaxDatagramSize is a separate question.
	crossDatagramSize = 1200

	// crossRoundTrip is how long an answer takes, and therefore the minimum RTT both
	// sides estimate.
	crossRoundTrip = 50 * time.Millisecond

	// crossSpacing is how far apart the packets of one exchange are sent. Evenly
	// spaced packets are what makes the bandwidth sample the rate of the script
	// rather than the rate of a burst: a hundred packets sent back to back sample the
	// spacing between two packets, which is not a path's bandwidth at all.
	crossSpacing = crossRoundTrip / 32
)

// crossPacket is one packet of the script: what the driver remembers so that it can
// report it as acknowledged or lost later.
type crossPacket struct {
	number int64
	sentAt time.Time
	size   int64
}

// crossSender is the shape both controllers are put behind, in the script's own
// units: numbers of bytes, numbers of packets and instants. Each side converts them
// to its own, which is what makes them comparable.
type crossSender interface {
	OnPacketSent(at time.Time, inFlight, number, size int64, retransmittable bool)
	OnCongestionEvent(priorInFlight int64, at time.Time, acked, lost []crossPacket)
	Window() int64
	CanSend(inFlight int64) bool
	InSlowStart() bool
	InRecovery() bool
	PacingRate() int64
	HasPacingBudget(at time.Time) bool
	TimeUntilSend(inFlight int64) int64
}

// crossRTT is the path both sides are told about: measured once, never changing, so
// that what the controllers do is the controller's own doing. The methods past the
// first three are what quic-go's provider needs and our own does not; nothing on
// either side asks for them, so they answer zero.
type crossRTT time.Duration

func (r crossRTT) MinRTT() time.Duration        { return time.Duration(r) }
func (r crossRTT) SmoothedRTT() time.Duration   { return time.Duration(r) }
func (r crossRTT) LatestRTT() time.Duration     { return time.Duration(r) }
func (r crossRTT) MeanDeviation() time.Duration { return 0 }
func (r crossRTT) MaxAckDelay() time.Duration   { return 0 }

func (r crossRTT) PTO(includeMaxAckDelay bool) time.Duration   { return 0 }
func (r crossRTT) UpdateRTT(sendDelta, ackDelay time.Duration) {}
func (r crossRTT) SetMaxAckDelay(maxAckDelay time.Duration)    {}
func (r crossRTT) SetInitialRTT(initialRTT time.Duration)      {}

// udpxController is what our own controller can be asked beyond congestion.Controller:
// the debug surfaces BBR still carries.
type udpxController interface {
	congestion.Controller
	InSlowStart() bool
	InRecovery() bool
	PacingRate() congestion.Bandwidth
}

type udpxSender struct {
	controller udpxController
}

// meta2Controller is the same surface on the copy the quic-go transports use.
type meta2Controller interface {
	qcongestion.CongestionControlEx
	PacingRate() meta2.Bandwidth
}

type meta2Sender struct {
	controller meta2Controller
}

func newUdpxSender(t *testing.T, profile string) crossSender {
	t.Helper()
	parsed, err := congestion.ParseProfile(profile)
	if err != nil {
		t.Fatalf("parsing profile %q: %v", profile, err)
	}
	controller := congestion.NewBbrSenderWithProfile(crossDatagramSize, parsed)
	controller.SetRTTStatsProvider(crossRTT(crossRoundTrip))
	return &udpxSender{controller: controller}
}

func newMeta2Sender(t *testing.T, profile string) crossSender {
	t.Helper()
	parsed, err := meta2.ParseProfile(profile)
	if err != nil {
		t.Fatalf("parsing profile %q: %v", profile, err)
	}
	controller := meta2.NewBbrSenderWithProfile(crossDatagramSize, parsed)
	controller.SetRTTStatsProvider(crossRTT(crossRoundTrip))
	return &meta2Sender{controller: controller}
}

func (s *udpxSender) OnPacketSent(at time.Time, inFlight, number, size int64, retransmittable bool) {
	s.controller.OnPacketSent(at, congestion.ByteCount(inFlight), congestion.PacketNumber(number), congestion.ByteCount(size), retransmittable)
}

func (s *udpxSender) OnCongestionEvent(priorInFlight int64, at time.Time, acked, lost []crossPacket) {
	ackedPackets := make([]congestion.AckedPacketInfo, len(acked))
	for index, packet := range acked {
		ackedPackets[index] = congestion.AckedPacketInfo{
			TimeSent:     packet.sentAt,
			BytesAcked:   congestion.ByteCount(packet.size),
			PacketNumber: congestion.PacketNumber(packet.number),
		}
	}
	lostPackets := make([]congestion.LostPacketInfo, len(lost))
	for index, packet := range lost {
		lostPackets[index] = congestion.LostPacketInfo{
			TimeSent:     packet.sentAt,
			BytesLost:    congestion.ByteCount(packet.size),
			PacketNumber: congestion.PacketNumber(packet.number),
		}
	}
	s.controller.OnCongestionEvent(congestion.ByteCount(priorInFlight), at, ackedPackets, lostPackets)
}

func (s *udpxSender) Window() int64                     { return int64(s.controller.GetCongestionWindow()) }
func (s *udpxSender) InSlowStart() bool                 { return s.controller.InSlowStart() }
func (s *udpxSender) InRecovery() bool                  { return s.controller.InRecovery() }
func (s *udpxSender) PacingRate() int64                 { return int64(s.controller.PacingRate()) }
func (s *udpxSender) HasPacingBudget(at time.Time) bool { return s.controller.HasPacingBudget(at) }

func (s *udpxSender) CanSend(inFlight int64) bool {
	return s.controller.CanSend(congestion.ByteCount(inFlight))
}

func (s *udpxSender) TimeUntilSend(inFlight int64) int64 {
	return int64(monotime.FromTime(s.controller.TimeUntilSend(congestion.ByteCount(inFlight))))
}

func (s *meta2Sender) OnPacketSent(at time.Time, inFlight, number, size int64, retransmittable bool) {
	s.controller.OnPacketSent(monotime.FromTime(at), qcongestion.ByteCount(inFlight), qcongestion.PacketNumber(number), qcongestion.ByteCount(size), retransmittable)
}

func (s *meta2Sender) OnCongestionEvent(priorInFlight int64, at time.Time, acked, lost []crossPacket) {
	ackedPackets := make([]qcongestion.AckedPacketInfo, len(acked))
	for index, packet := range acked {
		// ReceivedTime is left at zero: neither copy reads it, it is only there
		// because quic-go's struct has it.
		ackedPackets[index] = qcongestion.AckedPacketInfo{
			PacketNumber: qcongestion.PacketNumber(packet.number),
			BytesAcked:   qcongestion.ByteCount(packet.size),
			SentTime:     monotime.FromTime(packet.sentAt),
		}
	}
	// quic-go's LostPacketInfo has no send time; the sampler on that side keeps its
	// own copy from the moment the packet was sent.
	lostPackets := make([]qcongestion.LostPacketInfo, len(lost))
	for index, packet := range lost {
		lostPackets[index] = qcongestion.LostPacketInfo{
			PacketNumber: qcongestion.PacketNumber(packet.number),
			BytesLost:    qcongestion.ByteCount(packet.size),
		}
	}
	s.controller.OnCongestionEventEx(qcongestion.ByteCount(priorInFlight), monotime.FromTime(at), ackedPackets, lostPackets)
}

func (s *meta2Sender) Window() int64     { return int64(s.controller.GetCongestionWindow()) }
func (s *meta2Sender) InSlowStart() bool { return s.controller.InSlowStart() }
func (s *meta2Sender) InRecovery() bool  { return s.controller.InRecovery() }
func (s *meta2Sender) PacingRate() int64 { return int64(s.controller.PacingRate()) }
func (s *meta2Sender) HasPacingBudget(at time.Time) bool {
	return s.controller.HasPacingBudget(monotime.FromTime(at))
}

func (s *meta2Sender) CanSend(inFlight int64) bool {
	return s.controller.CanSend(qcongestion.ByteCount(inFlight))
}

func (s *meta2Sender) TimeUntilSend(inFlight int64) int64 {
	return int64(s.controller.TimeUntilSend(qcongestion.ByteCount(inFlight)))
}

// crossDriver is the script: it decides what is sent, when, what is acknowledged and
// what is given up on, and never asks a controller what to do.
type crossDriver struct {
	now      time.Time
	number   int64
	inFlight []crossPacket
	bytes    int64
}

func newCrossDriver() *crossDriver {
	return &crossDriver{now: time.Unix(0, 0)}
}

// send puts count packets in flight, spaced out the way a paced sender would space
// them. What the controllers answer is not looked at: the next step is decided
// already.
func (d *crossDriver) send(senders []crossSender, count int) {
	for index := 0; index < count; index++ {
		sentAt := d.now.Add(time.Duration(index) * crossSpacing)
		d.number++
		for _, sender := range senders {
			sender.OnPacketSent(sentAt, d.bytes, d.number, crossDatagramSize, true)
		}
		d.inFlight = append(d.inFlight, crossPacket{number: d.number, sentAt: sentAt, size: crossDatagramSize})
		d.bytes += crossDatagramSize
	}
	d.now = d.now.Add(time.Duration(count-1) * crossSpacing)
}

// settle answers everything in flight one round trip after the last of it was sent,
// giving up on every loseEvery'th packet when loseEvery is not zero.
func (d *crossDriver) settle(senders []crossSender, loseEvery int) {
	if len(d.inFlight) == 0 {
		return
	}
	at := d.inFlight[len(d.inFlight)-1].sentAt.Add(crossRoundTrip)
	acked := make([]crossPacket, 0, len(d.inFlight))
	var lost []crossPacket
	for index, packet := range d.inFlight {
		if loseEvery > 0 && index%loseEvery == loseEvery-1 {
			lost = append(lost, packet)
			continue
		}
		acked = append(acked, packet)
	}
	priorInFlight := d.bytes
	for _, sender := range senders {
		sender.OnCongestionEvent(priorInFlight, at, acked, lost)
	}
	d.inFlight = d.inFlight[:0]
	d.bytes = 0
	d.now = at
}

// idle moves the script forward without sending anything, which is what lets the
// minimum RTT estimate go stale.
func (d *crossDriver) idle(duration time.Duration) {
	d.now = d.now.Add(duration)
}

// compareSenders requires the two controllers to be in the same state. The failure
// message carries the step number: this compares integers that are the result of
// hundreds of events, and without the step there is nothing to look at.
func compareSenders(t *testing.T, step int, now time.Time, inFlight int64, udpx, reference crossSender) {
	t.Helper()
	if ours, theirs := udpx.Window(), reference.Window(); ours != theirs {
		t.Fatalf("step %d: window %d, congestion_meta2 %d", step, ours, theirs)
	}
	if ours, theirs := udpx.InSlowStart(), reference.InSlowStart(); ours != theirs {
		t.Fatalf("step %d: in slow start %v, congestion_meta2 %v", step, ours, theirs)
	}
	if ours, theirs := udpx.InRecovery(), reference.InRecovery(); ours != theirs {
		t.Fatalf("step %d: in recovery %v, congestion_meta2 %v", step, ours, theirs)
	}
	window := udpx.Window()
	for _, probe := range []int64{0, inFlight, window - 1, window, window + 1} {
		if ours, theirs := udpx.CanSend(probe), reference.CanSend(probe); ours != theirs {
			t.Fatalf("step %d: can send %v with %d in flight, congestion_meta2 %v", step, ours, probe, theirs)
		}
	}
	// The pacing rate and everything the pacer answers are compared only while the
	// gain is the profile's high gain. In PROBE_BW the gain cycle starts at a random
	// phase, so two instances pace differently on purpose; the window above does not
	// go through the phase at all.
	if !udpx.InSlowStart() {
		return
	}
	if ours, theirs := udpx.PacingRate(), reference.PacingRate(); ours != theirs {
		t.Fatalf("step %d: pacing rate %d, congestion_meta2 %d", step, ours, theirs)
	}
	if ours, theirs := udpx.HasPacingBudget(now), reference.HasPacingBudget(now); ours != theirs {
		t.Fatalf("step %d: has pacing budget %v, congestion_meta2 %v", step, ours, theirs)
	}
	if ours, theirs := udpx.TimeUntilSend(inFlight), reference.TimeUntilSend(inFlight); ours != theirs {
		t.Fatalf("step %d: next send at %d, congestion_meta2 %d", step, ours, theirs)
	}
}

// crossPair holds one script's two controllers and the step counter the comparisons
// are numbered with.
type crossPair struct {
	t         *testing.T
	udpx      crossSender
	reference crossSender
	senders   []crossSender
	driver    *crossDriver
	step      int
}

func newCrossPair(t *testing.T, profile string) *crossPair {
	udpx := newUdpxSender(t, profile)
	reference := newMeta2Sender(t, profile)
	return &crossPair{
		t:         t,
		udpx:      udpx,
		reference: reference,
		senders:   []crossSender{udpx, reference},
		driver:    newCrossDriver(),
	}
}

func (p *crossPair) compare() {
	p.step++
	compareSenders(p.t, p.step, p.driver.now, p.driver.bytes, p.udpx, p.reference)
}

// exchange sends count packets and settles them all, which is one round trip of
// sending and one answer.
func (p *crossPair) exchange(count int) {
	p.driver.send(p.senders, count)
	p.compare()
	p.driver.settle(p.senders, 0)
	p.compare()
}

// exchangeLossy is the same with a packet given up on every loseEvery'th one: an
// answer that arrives anyway is the shape recovery and the window behind it are about.
func (p *crossPair) exchangeLossy(count, loseEvery int) {
	p.driver.send(p.senders, count)
	p.compare()
	p.driver.settle(p.senders, loseEvery)
	p.compare()
}

// TestBbrSenderMatchesMeta2 runs one script through both controllers under each
// profile and requires every state they expose to agree after every step: startup with
// its growing window, the drain that follows it, PROBE_BW with losses to recover from,
// answers that are delayed by a round trip, and a minimum RTT that goes stale until the
// window is probed down to its floor.
func TestBbrSenderMatchesMeta2(t *testing.T) {
	for _, profile := range []string{"conservative", "standard", "aggressive"} {
		t.Run(profile, func(t *testing.T) {
			pair := newCrossPair(t, profile)
			// STARTUP: exchanges worth of an initial window each, all acknowledged,
			// which is the phase the window grows in. Six of them is past the four
			// round trips the profile with the most patience waits for.
			for exchange := 0; exchange < 6; exchange++ {
				pair.exchange(96)
			}
			if pair.udpx.InSlowStart() {
				t.Fatal("the script never left startup")
			}
			// DRAIN and then the gain cycle, with bursts that put enough in flight to
			// probe and quiet exchanges that let in flight fall back: one without the
			// other keeps the controller in DRAIN or in the 1.25 gain phase.
			for exchange := 0; exchange < 24; exchange++ {
				count := 96
				if exchange%4 >= 2 {
					count = 4
				}
				if exchange%7 == 6 {
					pair.exchangeLossy(count, 3)
					continue
				}
				pair.exchange(count)
			}
			// Two exchanges settled by one answer, which is what a delayed
			// acknowledgement looks like: more in flight at the event, and a later one.
			for exchange := 0; exchange < 8; exchange++ {
				pair.driver.send(pair.senders, 48)
				pair.compare()
				pair.driver.send(pair.senders, 48)
				pair.compare()
				pair.driver.settle(pair.senders, 0)
				pair.compare()
			}
			// Longer than the minimum RTT estimate is allowed to live: it is
			// re-sampled, and the following exchanges have to drain the window to its
			// floor and bring it back.
			pair.driver.idle(11 * time.Second)
			for exchange := 0; exchange < 10; exchange++ {
				pair.exchange(8)
			}
		})
	}
}

// TestBbrSenderMatchesMeta2GainCycle holds both controllers at one burst-and-quiet
// pattern until the gain cycle turns steadily, and compares the set of pacing rates it
// produces. In steady state the set does not depend on where the cycle started: it is
// the gain table times the estimated bandwidth, so a table edited on one side shows up
// as a set that differs.
func TestBbrSenderMatchesMeta2GainCycle(t *testing.T) {
	pair := newCrossPair(t, "standard")
	ourRates := make(map[int64]struct{})
	theirRates := make(map[int64]struct{})
	for exchange := 0; exchange < 60; exchange++ {
		count := 96
		if exchange%4 >= 2 {
			count = 4
		}
		pair.exchange(count)
		// The first exchanges are still leaving startup and drain, where the gain is
		// not the cycle's: let the pattern settle before recording.
		if exchange < 12 {
			continue
		}
		ourRates[pair.udpx.PacingRate()] = struct{}{}
		theirRates[pair.reference.PacingRate()] = struct{}{}
	}
	if len(ourRates) < 3 {
		t.Fatalf("pacing rate set %v holds %d rates, the gain cycle produces at least three", slices.Sorted(maps.Keys(ourRates)), len(ourRates))
	}
	if !maps.Equal(ourRates, theirRates) {
		t.Fatalf("pacing rate set %v, congestion_meta2 %v", slices.Sorted(maps.Keys(ourRates)), slices.Sorted(maps.Keys(theirRates)))
	}
}

// TestPacerMatchesMeta2 takes the pacer on its own, which needs no script: given the
// same sends at the same instants and the same bandwidth, the budget and the deadline
// it hands out have to be the same number of nanoseconds. Nothing here goes through a
// random phase, so it is compared value by value.
func TestPacerMatchesMeta2(t *testing.T) {
	bandwidth := int64(500000)
	udpx := congestion.NewPacer(crossDatagramSize, func() congestion.ByteCount {
		return congestion.ByteCount(bandwidth)
	})
	reference := meta2.NewPacer(crossDatagramSize, func() qcongestion.ByteCount {
		return qcongestion.ByteCount(bandwidth)
	})
	now := time.Unix(0, 0)
	step := 0
	compare := func() {
		step++
		if ours, theirs := int64(udpx.Budget(now)), int64(reference.Budget(monotime.FromTime(now))); ours != theirs {
			t.Fatalf("step %d: budget %d, congestion_meta2 %d", step, ours, theirs)
		}
		if ours, theirs := int64(monotime.FromTime(udpx.TimeUntilSend())), int64(reference.TimeUntilSend()); ours != theirs {
			t.Fatalf("step %d: next send at %d, congestion_meta2 %d", step, ours, theirs)
		}
	}
	// A fresh pacer hands out a burst before it has seen anything.
	compare()
	// Then a hundred packets at half the rate the budget refills at, so most of them
	// are paid for by waiting rather than by the burst.
	for index := 0; index < 100; index++ {
		udpx.SentPacket(now, crossDatagramSize)
		reference.SentPacket(monotime.FromTime(now), crossDatagramSize)
		compare()
		now = now.Add(1500 * time.Microsecond)
		compare()
	}
	// A slower path: the burst floor is ten datagrams, so the budget has to follow the
	// bandwidth and not only its refill.
	bandwidth = 100000
	compare()
	// An idle hour: the budget is capped by the burst, whichever way it got there.
	now = now.Add(time.Hour)
	compare()
	// A larger datagram: the burst and the wait both scale with it.
	udpx.SetMaxDatagramSize(1500)
	reference.SetMaxDatagramSize(1500)
	compare()
	udpx.SentPacket(now, 1500)
	reference.SentPacket(monotime.FromTime(now), 1500)
	compare()
}
