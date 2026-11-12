package congestion

// src from https://github.com/google/quiche/blob/e7872fc9e12bb1d46a118949c3d4da36de58aa44/quiche/quic/core/congestion_control/bbr_sender.cc

import (
	"fmt"
	"math/rand"
	"time"
)

// BbrSender implements BBR congestion control algorithm.  BBR aims to estimate
// the current available Bottleneck Bandwidth and RTT (hence the name), and
// regulates the pacing rate and the size of the congestion window based on
// those signals.
//
// BBR relies on pacing in order to function properly.  Do not use BBR when
// pacing is disabled.
//

const (
	minBps = 65536 // 64 KB/s

	invalidPacketNumber            = -1
	initialCongestionWindowPackets = 32
	minCongestionWindowPackets     = 4
	// maxCongestionWindowPackets is the ceiling of the congestion window.
	maxCongestionWindowPackets = 20000

	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.

	// The gain used for the STARTUP, equal to 2/ln(2).
	defaultHighGain = 2.885
	// The newly derived CWND gain for STARTUP, 2.
	derivedHighCWNDGain = 2.0
)

// The cycle of gains used during the PROBE_BW stage.
var pacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	// The length of the gain cycle.
	gainCycleLength = len(pacingGain)
	// The size of the bandwidth filter window, in round-trips.
	bandwidthWindowSize = gainCycleLength + 2

	// The time after which the current min_rtt value expires.
	minRttExpiry = 10 * time.Second
	// The minimum time the connection can spend in PROBE_RTT mode.
	probeRttTime = 200 * time.Millisecond
	// probeRttMaxStay is how long PROBE_RTT may last without a round trip to end
	// it. A probe measures the round trip of a path, and a path whose peer answers
	// nothing does not have one: staying there holds the window at the minimum and
	// the estimate decays with it, so the probe ends on its own clock and the
	// window goes back to probing for bandwidth.
	probeRttMaxStay = time.Second
	// probeRTTWindowSlack is how much room a PROBE_RTT window is allowed over the
	// minimum: the window is checked before a packet leaves, so one more packet is
	// already in flight by the time it looks full.
	probeRTTWindowSlack ByteCount = 1000
	// cycleOffsetRange is how far from zero the probe cycle of a new association
	// may start, so that associations created together do not probe together.
	cycleOffsetRange = 100
	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	//
	// Two rounds, not three, because one round is a number the estimate can produce
	// on a path that is still climbing: the estimate is the maximum over the samples
	// of a round, and a round that answers a whole window more with a fifth more is
	// a round where the window grew and the sample did not follow it exactly. What
	// two rounds in a row mean is the path answering the same thing twice, which is
	// what the round is spent to hear. Measured on a 175 ms path with a capacity of
	// 400 Mbit/s: 64 MiB goes from 19.2 to 22.1 MiB/s and the bytes that do not
	// arrive go from 21.2 to 17.9 MB, and 256 MiB is unchanged (36.6 against 36.8).
	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(2)
)

type bbrMode int

const (
	// Startup phase of the connection.
	bbrModeStartup = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	bbrModeDrain
	// Cruising mode.
	bbrModeProbeBw
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	bbrModeProbeRtt
)

type bbrSender struct {
	rttStats RTTStatsProvider
	pacer    *pacer

	mode bbrMode

	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *bandwidthSampler

	// The number of the round trips that have occurred during the connection.
	roundTripCount roundTripCount

	// The packet number of the most recently sent packet.
	lastSentPacket PacketNumber
	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd PacketNumber

	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *windowedFilter[Bandwidth]

	// Minimum RTT estimate.  Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp time.Time

	// The maximum allowed number of bytes in flight.
	congestionWindow ByteCount

	// The initial value of the |congestion_window_|.
	initialCongestionWindow ByteCount

	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow ByteCount

	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow ByteCount

	// The pacing gain applied during the STARTUP phase.
	highGain float64

	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64

	// The pacing gain applied during the DRAIN phase.
	drainGain float64

	// The pacing rate the model last calculated, which is zero until it has a
	// bandwidth estimate to multiply a gain with.
	measuredPacingRate Bandwidth

	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64

	// The gain used for the congestion window during PROBE_BW.  Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConstant float64
	// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
	numStartupRtts int64

	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart time.Time

	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth

	// Set to true upon exiting quiescence.
	exitingQuiescence bool

	// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt time.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool
	// enteredProbeRttAt is when this round of PROBE_RTT began. Leaving it needs a
	// round trip to have passed, and a round trip is only counted when an
	// acknowledgement arrives: an association whose peer has nothing to send never
	// gets one, and a PROBE_RTT that waits for it holds the window at four packets
	// for as long as the stall lasts. The bandwidth estimate then decays with the
	// delivery it measures, which is the rate the window is derived from, so the
	// stall feeds itself. What ends it is this timestamp: a probe that lasted long
	// enough to have measured the round trip it was there for has measured it.
	enteredProbeRttAt time.Time

	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool

	// lastEventHadLoss says the last acknowledgement declared packets lost. A
	// round that lost packets is a round in which the path is dropping what it is
	// handed, which is not a path with a queue left to drain: PROBE_RTT exists to
	// empty the queue and measure the round trip without it, and a queue that is
	// already overflowing is empty by definition. See maybeEnterOrExitProbeRtt.
	lastEventHadLoss bool

	// Recorded on packet sent. equivalent |unacked_packets_->bytes_in_flight()|
	bytesInFlight ByteCount
}

// newBbrSender builds a sender whose window starts at initialWindowPackets
// packets. Zero or less asks for the default.
//
// The first window is the caller's answer, not the algorithm's: how much may leave
// before the path has said anything about itself is the path's bandwidth-delay
// product and the room the peer is holding, and a transport that knows either of
// them knows more about it than a constant here does. Raising it shortens the
// ramp at the start of a transfer by a round trip per doubling; the cost is that
// the first window arrives as one burst, so it is bounded by what the peer was
// told to expect.
func newBbrSender(initialMaxDatagramSize ByteCount, initialWindowPackets int64) *bbrSender {
	if initialWindowPackets <= 0 {
		initialWindowPackets = initialCongestionWindowPackets
	}
	if initialWindowPackets < minCongestionWindowPackets {
		initialWindowPackets = minCongestionWindowPackets
	}
	initialCongestionWindow := ByteCount(initialWindowPackets) * initialMaxDatagramSize
	initialMaxCongestionWindow := maxCongestionWindowPackets * initialMaxDatagramSize
	b := &bbrSender{
		mode:                         bbrModeStartup,
		sampler:                      newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		lastSentPacket:               invalidPacketNumber,
		currentRoundTripEnd:          invalidPacketNumber,
		maxBandwidth:                 newWindowedFilter(roundTripCount(bandwidthWindowSize), maxFilter[Bandwidth]),
		congestionWindow:             initialCongestionWindow,
		initialCongestionWindow:      initialCongestionWindow,
		maxCongestionWindow:          initialMaxCongestionWindow,
		minCongestionWindow:          minCongestionWindowForMaxDatagramSize(initialMaxDatagramSize),
		highGain:                     defaultHighGain,
		highCwndGain:                 derivedHighCWNDGain,
		drainGain:                    1.0 / defaultHighGain,
		pacingGain:                   1.0,
		congestionWindowGain:         1.0,
		congestionWindowGainConstant: 2.0,
		numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
	}
	b.pacer = newPacer(initialMaxDatagramSize, b.bandwidthForPacer)

	b.enterStartupMode(time.Now())

	return b
}

func minCongestionWindowForMaxDatagramSize(maxDatagramSize ByteCount) ByteCount {
	return minCongestionWindowPackets * maxDatagramSize
}

func (b *bbrSender) SetRTTStatsProvider(provider RTTStatsProvider) {
	b.rttStats = provider
}

// PacingWait is how long the send path has to wait before the next batch may leave.
func (b *bbrSender) PacingWait(now time.Time) time.Duration {
	return b.pacer.wait(now)
}

// Describe is what a debug log says about the controller: the phase, the window,
// the rate, the estimate and how much of the path the model believes it may fill.
// The last number is the controller's view in bytes, and it is named for that
// rather than for the flight table: a line that says inflight twice says the packet
// count and the byte count in one breath, and a reader parsing it gets whichever
// came last.
func (b *bbrSender) Describe() string {
	return fmt.Sprintf("mode=%s cwnd=%d pacing=%d bw=%d minrtt=%s unacked=%d",
		b.mode, b.GetCongestionWindow(), b.pacingRate(), b.bandwidthEstimate(),
		b.getMinRtt(), b.bytesInFlight)
}

func (m bbrMode) String() string {
	switch m {
	case bbrModeStartup:
		return "startup"
	case bbrModeDrain:
		return "drain"
	case bbrModeProbeBw:
		return "probe_bw"
	case bbrModeProbeRtt:
		return "probe_rtt"
	default:
		return "unknown"
	}
}

// OnPacketSent records a packet that left and what was in flight before it, and
// hands back what has to be kept beside that packet until its answer arrives.
func (b *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount) SendState {
	b.pacer.sentPacket(sentTime, bytes)

	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	return b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight)
}

// CanSend reports whether the window has room for another packet.
func (b *bbrSender) CanSend(bytesInFlight ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// OnAppLimited tells the sampler that the application has nothing to send, which
// is what keeps a quiet association from measuring itself: the packets after it are
// keep-alives, and a keep-alive's rate is the rate of the application, not of the
// path. The sample they produce is ignored until one of them is acknowledged, at
// which point the phase ends and the next real transfer is measured again.
func (b *bbrSender) OnAppLimited() {
	b.sampler.onAppLimited()
}

// GetCongestionWindow is the window the transport may fill. It is the model's
// window and nothing else: a loss does not shrink it, because a loss is not what
// the window is built from. What a loss does is lower the estimate of the path
// the window is derived from, and that estimate is already the answer.
func (b *bbrSender) GetCongestionWindow() ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	return b.congestionWindow
}

// OnCongestionEvent is the one event a transport reports per acknowledgement. Everything BBR does
// with an answer happens here: the window, the pacing rate and the round trip
// counter only move when an acknowledgement and the losses it implies arrive
// together, which is why the event is one call and not one call per packet.
//
// What is lost is not what the window is derived from. The window is the model's
// estimate of the path multiplied by a gain, and a path that drops a packet does
// not become a narrower path because of it: a loss lowers the estimate only when
// the loss was the model's own doing, which is what the delivery rate says and a
// loss count does not. This is the difference between a controller that survives a
// path dropping one packet in ten and one that crawls on it.
func (b *bbrSender) OnCongestionEvent(priorInFlight ByteCount, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo) {
	totalBytesAckedBefore := b.sampler.totalBytesAcked

	var isRoundStart, minRttExpired bool

	b.lastEventHadLoss = len(lostPackets) != 0

	// Update bytesInFlight
	b.bytesInFlight = priorInFlight
	for _, p := range ackedPackets {
		b.bytesInFlight -= p.BytesAcked
	}
	for _, p := range lostPackets {
		b.bytesInFlight -= p.BytesLost
	}

	if len(ackedPackets) != 0 {
		lastAckedPacket := ackedPackets[len(ackedPackets)-1].PacketNumber
		isRoundStart = b.updateRoundTripCounter(lastAckedPacket)
	}

	sample := b.sampler.OnCongestionEvent(eventTime,
		ackedPackets, lostPackets, b.maxBandwidth.getBest(), infBandwidth, b.roundTripCount)
	b.lastSampleIsAppLimited = sample.lastPacketState.appLimited
	// A sample is a slope between two acknowledgements, and the transport sends in
	// batches: sixteen packets leave in one write and the next batch waits for the
	// pacer, so the slope between the two acknowledgements of one batch is the slope
	// of a burst rather than of the path. The send rate the sampler bounds the answer
	// with has the same shape, which is why a burst can raise the estimate the window
	// is derived from past what the pacer was willing to send.
	//
	// The rate this end paced at is the one number that says what the path was asked
	// to carry, and a sample above it is a sample of the burst: what the path
	// answered is more than what was asked of it, which is compression somewhere
	// between the two ends and not capacity. Measured over nineteen hours of a
	// proxied phone: an estimate of twelve megabits on a path that carried two and
	// six tenths, a third of everything sent declared lost, and the loss answered by
	// sending it again.
	//
	// What the bound costs is the ramp: an estimate may grow by the pacing gain per
	// round instead of by whatever a burst measured, which is the growth the probe
	// cycle of PROBE_BW is built around anyway.
	if paced := b.pacingRate(); sample.sampleMaxBandwidth > paced {
		sample.sampleMaxBandwidth = paced
	}
	// Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b) all
	// packets in |acked_packets| did not generate valid samples. (e.g. ack of
	// ack-only packets). In both cases, sampler_.total_bytes_acked() will not
	// change.
	if totalBytesAckedBefore != b.sampler.totalBytesAcked {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.getBest() {
			b.maxBandwidth.update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(lostPackets) != 0)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached()
	}

	b.maybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// Calculate number of packets acked.
	bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.calculatePacingRate()
	b.calculateCongestionWindow(bytesAcked)
}

func (b *bbrSender) pacingRate() Bandwidth {
	if b.measuredPacingRate == 0 {
		return Bandwidth(b.highGain * float64(
			bandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt())))
	}

	return b.measuredPacingRate
}

// What's the current estimated bandwidth in bytes per second.
func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.getBest()
}

func (b *bbrSender) bandwidthForPacer() ByteCount {
	bps := ByteCount(float64(b.pacingRate()) / float64(BytesPerSecond))
	if bps < minBps {
		// The pacer divides by this rate, so it is never zero.
		return minBps
	}
	return bps
}

// Returns the current estimate of the RTT of the connection.  Outside of the
// edge cases, this is minimum RTT.
func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	// min_rtt could be available if the handshake packet gets neutered then
	// gets acknowledged. This could only happen for QUIC crypto where we do not
	// drop keys.
	minRtt := b.rttStats.MinRTT()
	if minRtt == 0 {
		return 100 * time.Millisecond
	} else {
		return minRtt
	}
}

// Computes the target congestion window using the specified gain.
func (b *bbrSender) getTargetCongestionWindow(gain float64) ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := ByteCount(gain * float64(bdp))

	// BDP estimate will be zero if no bandwidth samples are available yet.
	if congestionWindow == 0 {
		congestionWindow = ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return max(congestionWindow, b.minCongestionWindow)
}

// The target congestion window during PROBE_RTT.
func (b *bbrSender) probeRttCongestionWindow() ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now time.Time, sampleMinRtt time.Duration) bool {
	// Do not expire min_rtt if none was ever available.
	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}

	return minRttExpired
}

// Enters the STARTUP mode.
func (b *bbrSender) enterStartupMode(now time.Time) {
	b.mode = bbrModeStartup
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

// Enters the PROBE_BW mode.
func (b *bbrSender) enterProbeBandwidthMode(now time.Time) {
	b.mode = bbrModeProbeBw
	b.congestionWindowGain = b.congestionWindowGainConstant

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = int(rand.Int31n(cycleOffsetRange)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]
}

// Updates the round-trip counter if a round-trip has passed.  Returns true if
// the counter has been advanced.
func (b *bbrSender) updateRoundTripCounter(lastAckedPacket PacketNumber) bool {
	if b.currentRoundTripEnd == invalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}
	return false
}

// Updates the current gain used in PROBE_BW mode.
func (b *bbrSender) updateGainCyclePhase(now time.Time, priorInFlight ByteCount, hasLosses bool) {
	// In most cases, the cycle is advanced after an RTT passes.
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))
	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP.  Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it.  If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1.0 && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

// Tracks for how many round-trips the bandwidth has not increased
// significantly, which is the one signal startup ends on: the path has stopped
// saying that it carries more.
func (b *bbrSender) checkIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts {
		b.isAtFullBandwidth = true
	}
}

// Transitions from STARTUP to DRAIN and from DRAIN to PROBE_BW if
// appropriate.
func (b *bbrSender) maybeExitStartupOrDrain(now time.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode == bbrModeDrain && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		b.enterProbeBandwidthMode(now)
	}
}

// Decides whether to enter or exit PROBE_RTT.
//
// Entering it is for a path whose queue this end filled itself: the estimate the
// window is derived from is measured through that queue, so the round trip it
// believes is the one with the queue in it. A round that lost packets has no queue
// to drain — the path is dropping what it is handed — and a probe there buys a
// measurement of a queue that is not the reason the round trip grew. What it costs
// is the window: four packets for as long as the probe lasts, on a path that is
// already losing a third of what it carries. Measured over nineteen hours of a
// proxied phone: two hundred and thirty-nine probes, the longest of them twelve
// seconds, every one of them on a path that was dropping packets.
//
// Leaving it needs a round trip to have passed, and the window to have drained to
// what the probe allows. Neither is guaranteed on a path that is dropping: an
// acknowledgement that never comes is not a round trip, and packets that were lost
// leave the flight table only when the probe timer gives up on them, so the drain
// waits for a timer instead of for an answer. That is what probeRttMaxStay is for,
// and it is checked here rather than only in the branch that has a deadline: a
// deadline that is never set is a probe that never ends.
func (b *bbrSender) maybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && b.lastEventHadLoss {
		b.minRttTimestamp = now
		minRttExpired = false
	}
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.pacingGain = 1.0
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		b.exitProbeRttAt = time.Time{}
		b.enteredProbeRttAt = now
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.onAppLimited()
		// quiche marks the sampler app-limited here (its
		// CongestionStateApplicationLimited). It is deliberately not reported:
		// it is not a BBR phase change, and emitting it would interleave the
		// application_limited state with probe_rtt, hiding the probe_rtt
		// intervals the trace is meant to show.

		if b.exitProbeRttAt.IsZero() {
			// If the window has reached the appropriate size, schedule exiting
			// PROBE_RTT.  The CWND during PROBE_RTT is kMinimumCongestionWindow, but
			// we allow an extra packet since QUIC checks CWND before sending a
			// packet.
			if b.bytesInFlight < b.probeRttCongestionWindow()+probeRTTWindowSlack {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			} else if now.Sub(b.enteredProbeRttAt) >= probeRttMaxStay {
				// The window did not drain, and it will not: what is in flight on a
				// path that is dropping is waiting for a timer, not for an answer.
				// The probe ends on its own clock rather than on a drain that never
				// finishes.
				b.exitProbeRttAt = now
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			// A probe that has been in this mode for longer than the round trip it
			// came to measure is done with it whether or not an acknowledgement
			// came back: the alternative is a window held at four packets until
			// the peer sends something, which is what a peer waiting for credit
			// never does.
			probeRttDone := b.probeRttRoundPassed || now.Sub(b.enteredProbeRttAt) >= probeRttMaxStay
			if now.Sub(b.exitProbeRttAt) >= 0 && probeRttDone {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.enterStartupMode(now)
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}

	b.exitingQuiescence = false
}

// Determines the appropriate pacing rate for the connection: the gain the mode
// asks for times the bandwidth estimate, and nothing else.
//
// The window is not a floor on it. It used to be one, on the argument that a rate
// collapsing with the estimate would keep the delivery it is measured from
// collapsed; what it cost is that the estimate stopped deciding the rate at all.
// Measured over ten hours of a proxied phone: the window set the rate in 92 percent
// of the seconds on the sending end and 99 percent of them on the receiving one, at
// twice the estimate at the median and three times it at the ninetieth percentile,
// because a window is a round trip of the path plus a half and a round trip of the
// window is that much more than the path carries. The queue answered exactly that:
// in the same ten hours the share of what left that was declared lost rose with this
// ratio alone, a quarter at twice the estimate and two thirds at four times, and a
// packet sent again is a packet the path carries for nothing.
//
// What the window is for is the other half: it bounds what may be in flight, and
// pacing below it is the state every controller is in when the path is narrower than
// the window the last estimate produced. Leaving that state is the estimate's job,
// which the probe cycle does by pacing a quarter above it for one round and reading
// what arrives.
func (b *bbrSender) calculatePacingRate() {
	if b.bandwidthEstimate() == 0 {
		return
	}
	b.measuredPacingRate = Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
}

// Determines the appropriate congestion window for the connection.
func (b *bbrSender) calculateCongestionWindow(bytesAcked ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to CWND.
		targetWindow += b.sampler.maxAckHeight()
	}

	// Instead of immediately setting the target CWND as the new one, BBR grows
	// the CWND towards |target_window| by only increasing it |bytes_acked| at a
	// time.
	if b.isAtFullBandwidth {
		b.congestionWindow = min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.totalBytesAcked < b.initialCongestionWindow {
		// If the connection is not yet out of startup phase, do not decrease the
		// window.
		b.congestionWindow += bytesAcked
	}

	// Enforce the limits on the congestion window.
	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) ByteCount {
	return ByteCount(rtt) * ByteCount(bandwidth) / ByteCount(BytesPerSecond) / ByteCount(time.Second)
}
