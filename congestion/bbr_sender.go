package congestion

// src from https://github.com/google/quiche/blob/e7872fc9e12bb1d46a118949c3d4da36de58aa44/quiche/quic/core/congestion_control/bbr_sender.cc

import (
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
	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(3)
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

// Indicates how the congestion control limits the amount of bytes in flight.
type bbrRecoveryState int

const (
	// Do not limit.
	bbrRecoveryStateNotInRecovery = iota
	// Allow an extra outstanding byte for each byte acknowledged.
	bbrRecoveryStateConservation
	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	bbrRecoveryStateGrowth
)

type bbrSender struct {
	rttStats RTTStatsProvider
	pacer    *Pacer

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
	maxBandwidth *WindowedFilter[Bandwidth]

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

	// The current pacing rate of the connection.
	pacingRate Bandwidth

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

	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool
	// Indicates whether any non app-limited samples have been recorded.
	hasNoAppLimitedSample bool

	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode.  A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow ByteCount
	// If true, consider all samples in recovery app-limited.
	isAppLimitedRecovery bool // not used

	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool // not used
	// When true, disables packet conservation in STARTUP.
	rateBasedStartup bool // not used

	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool

	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool

	// If true, slow down pacing rate in STARTUP when overshooting is detected.
	detectOvershooting bool
	// Bytes lost while detect_overshooting_ is true.
	bytesLostWhileDetectingOvershooting ByteCount
	// Slow down pacing rate if
	// bytes_lost_while_detecting_overshooting_ *
	// bytes_lost_multiplier_while_detecting_overshooting_ > IW.
	bytesLostMultiplierWhileDetectingOvershooting uint8
	// When overshooting is detected, do not drop pacing_rate_ below this value /
	// min_rtt.
	cwndToCalculateMinPacingRate ByteCount

	// Max congestion window when adjusting network parameters.
	maxCongestionWindowWithNetworkParametersAdjusted ByteCount // not used

	// Params.
	maxDatagramSize ByteCount
	// Recorded on packet sent. equivalent |unacked_packets_->bytes_in_flight()|
	bytesInFlight ByteCount
}

// NewBbrSender builds a sender whose window starts at initialWindowPackets
// packets. Zero or less asks for the default.
//
// The first window is the caller's answer, not the algorithm's: how much may leave
// before the path has said anything about itself is the path's bandwidth-delay
// product and the room the peer is holding, and a transport that knows either of
// them knows more about it than a constant here does. Raising it shortens the
// ramp at the start of a transfer by a round trip per doubling; the cost is that
// the first window arrives as one burst, so it is bounded by what the peer was
// told to expect.
func NewBbrSender(initialMaxDatagramSize ByteCount, initialWindowPackets int64) *bbrSender {
	if initialWindowPackets <= 0 {
		initialWindowPackets = initialCongestionWindowPackets
	}
	if initialWindowPackets < minCongestionWindowPackets {
		initialWindowPackets = minCongestionWindowPackets
	}
	return newBbrSender(
		initialMaxDatagramSize,
		ByteCount(initialWindowPackets)*initialMaxDatagramSize,
		MaxCongestionWindowPackets*initialMaxDatagramSize,
	)
}

func newBbrSender(
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow ByteCount,
) *bbrSender {
	b := &bbrSender{
		mode:                         bbrModeStartup,
		sampler:                      newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		lastSentPacket:               invalidPacketNumber,
		currentRoundTripEnd:          invalidPacketNumber,
		maxBandwidth:                 NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth]),
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
		recoveryState:                bbrRecoveryStateNotInRecovery,
		endRecoveryAt:                invalidPacketNumber,
		recoveryWindow:               initialMaxCongestionWindow,
		bytesLostMultiplierWhileDetectingOvershooting:    2,
		cwndToCalculateMinPacingRate:                     initialCongestionWindow,
		maxCongestionWindowWithNetworkParametersAdjusted: initialMaxCongestionWindow,
		maxDatagramSize: initialMaxDatagramSize,
	}
	b.pacer = NewPacer(initialMaxDatagramSize, b.bandwidthForPacer)

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
	if !b.isAtFullBandwidth {
		// Startup is where the window probes the path, and what the pacer would
		// follow there is an estimate a round trip behind that window.
		return 0
	}
	return b.pacer.Wait(now)
}

// OnPacketSent records a packet that left and what was in flight before it.
func (b *bbrSender) OnPacketSent(
	sentTime time.Time,
	bytesInFlight ByteCount,
	packetNumber PacketNumber,
	bytes ByteCount,
	isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)

	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 && b.sampler.IsAppLimited() {
		b.exitingQuiescence = true
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

// CanSend reports whether the window has room for another packet.
func (b *bbrSender) CanSend(bytesInFlight ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// InSlowStart reports whether the controller is still looking for more bandwidth.
func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

// InRecovery reports whether the controller is still recovering from loss.
func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

// GetCongestionWindow is the window the transport may fill.
func (b *bbrSender) GetCongestionWindow() ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	if b.InRecovery() {
		return Min(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

// OnCongestionEvent is the one event a transport reports per acknowledgement. Everything BBR does
// with an answer happens here: the window, the pacing rate and the round trip
// counter only move when an acknowledgement and the losses it implies arrive
// together, which is why the event is one call and not one call per packet.
func (b *bbrSender) OnCongestionEvent(priorInFlight ByteCount, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo) {
	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()

	var isRoundStart, minRttExpired bool
	var excessAcked, bytesLost ByteCount

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
		b.updateRecoveryState(lastAckedPacket, len(lostPackets) != 0, isRoundStart)
	}

	sample := b.sampler.OnCongestionEvent(eventTime,
		ackedPackets, lostPackets, b.maxBandwidth.GetBest(), infBandwidth, b.roundTripCount)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
		b.hasNoAppLimitedSample = b.hasNoAppLimitedSample || !b.lastSampleIsAppLimited
	}
	// Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b) all
	// packets in |acked_packets| did not generate valid samples. (e.g. ack of
	// ack-only packets). In both cases, sampler_.total_bytes_acked() will not
	// change.
	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}
	bytesLost = b.sampler.TotalBytesLost() - totalBytesLostBefore

	excessAcked = sample.extraAcked

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

	// Calculate number of packets acked and lost.
	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.calculatePacingRate(bytesLost)
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)
}

func (b *bbrSender) PacingRate() Bandwidth {
	if b.pacingRate == 0 {
		return Bandwidth(b.highGain * float64(
			BandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt())))
	}

	return b.pacingRate
}

// Sets the CWND gain used in STARTUP.  Must be greater than 1.
func (b *bbrSender) setHighCwndGain(highCwndGain float64) {
	b.highCwndGain = highCwndGain
	if b.mode == bbrModeStartup {
		b.congestionWindowGain = highCwndGain
	}
}

// What's the current estimated bandwidth in bytes per second.
func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.GetBest()
}

func (b *bbrSender) bandwidthForPacer() ByteCount {
	bps := ByteCount(float64(b.PacingRate()) / float64(BytesPerSecond))
	if bps < minBps {
		// We need to make sure that the bandwidth value for pacer is never zero,
		// otherwise it will go into an edge case where HasPacingBudget = false
		// but TimeUntilSend is before, causing the quic-go send loop to go crazy and get stuck.
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

	return Max(congestionWindow, b.minCongestionWindow)
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
	b.cycleCurrentOffset = int(rand.Int31n(PacketsPerConnectionID)) % (gainCycleLength - 1)
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
		// Stay in low gain mode until the target BDP is hit.
		// Low gain mode will be exited immediately when the target BDP is achieved.
		if b.drainToTarget && b.pacingGain < 1 &&
			pacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight > b.getTargetCongestionWindow(1) {
			return
		}
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

// Tracks for how many round-trips the bandwidth has not increased
// significantly, which is the one signal startup ends on: the path has stopped
// saying that it carries more. Losing packets is not one of them, because a path
// that drops some of what it carries still carries the rest, and an estimate that
// stops where the first loss arrived is one the sender never gets back.
func (b *bbrSender) checkIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			// Expire old excess delivery measurements now that bandwidth increased.
			b.sampler.ResetMaxAckHeightTracker(0, b.roundTripCount)
		}
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
func (b *bbrSender) maybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.pacingGain = 1.0
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		b.exitProbeRttAt = time.Time{}
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.OnAppLimited()
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
			if b.bytesInFlight < b.probeRttCongestionWindow()+MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.Sub(b.exitProbeRttAt) >= 0 && b.probeRttRoundPassed {
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

// Determines whether BBR needs to enter, exit or advance state of the
// recovery.
func (b *bbrSender) updateRecoveryState(lastAckedPacket PacketNumber, hasLosses, isRoundStart bool) {
	// Disable recovery in startup, if loss-based exit is enabled.
	if !b.isAtFullBandwidth {
		return
	}

	// Exit recovery when there are no losses for a round.
	if hasLosses {
		b.endRecoveryAt = b.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation
			// This will cause the |recovery_window_| to be set to the correct
			// value in CalculateRecoveryWindow().
			b.recoveryWindow = 0
			// Since the conservation phase is meant to be lasting for a whole
			// round, extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:
		// Exit recovery if appropriate.
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

// Determines the appropriate pacing rate for the connection.
func (b *bbrSender) calculatePacingRate(bytesLost ByteCount) {
	if b.bandwidthEstimate() == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	// Pace at the rate of initial_window / RTT as soon as RTT measurements are
	// available.
	if b.pacingRate == 0 && b.rttStats.MinRTT() != 0 {
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		return
	}

	if b.detectOvershooting {
		b.bytesLostWhileDetectingOvershooting += bytesLost
		// Check for overshooting with network parameters adjusted when pacing rate
		// > target_rate and loss has been detected.
		if b.pacingRate > targetRate && b.bytesLostWhileDetectingOvershooting > 0 {
			if b.hasNoAppLimitedSample ||
				b.bytesLostWhileDetectingOvershooting*ByteCount(b.bytesLostMultiplierWhileDetectingOvershooting) > b.initialCongestionWindow {
				// We are fairly sure overshoot happens if 1) there is at least one
				// non app-limited bw sample or 2) half of IW gets lost. Slow pacing
				// rate.
				b.pacingRate = Max(targetRate, BandwidthFromDelta(b.cwndToCalculateMinPacingRate, b.getMinRtt()))
				b.bytesLostWhileDetectingOvershooting = 0
				b.detectOvershooting = false
			}
		}
	}

	// Do not decrease the pacing rate during startup.
	b.pacingRate = Max(b.pacingRate, targetRate)
}

// Determines the appropriate congestion window for the connection.
func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to CWND.
		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {
		// Add the most recent excess acked.  Because CWND never decreases in
		// STARTUP, this will automatically create a very localized max filter.
		targetWindow += excessAcked
	}

	// Instead of immediately setting the target CWND as the new one, BBR grows
	// the CWND towards |target_window| by only increasing it |bytes_acked| at a
	// time.
	if b.isAtFullBandwidth {
		b.congestionWindow = Min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		// If the connection is not yet out of startup phase, do not decrease the
		// window.
		b.congestionWindow += bytesAcked
	}

	// Enforce the limits on the congestion window.
	b.congestionWindow = Max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = Min(b.congestionWindow, b.maxCongestionWindow)
}

// Determines the appropriate window that constrains the in-flight during recovery.
func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	// Set up the initial recovery window.
	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight + bytesAcked
		b.recoveryWindow = Max(b.minCongestionWindow, b.recoveryWindow)
		return
	}

	// Remove losses from the recovery window, while accounting for a potential
	// integer underflow.
	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow = b.recoveryWindow - bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	// In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
	// release additional |bytes_acked| to achieve a slow-start-like behavior.
	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	// Always allow sending at least |bytes_acked| in response.
	b.recoveryWindow = Max(b.recoveryWindow, b.bytesInFlight+bytesAcked)
	b.recoveryWindow = Max(b.minCongestionWindow, b.recoveryWindow)
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) ByteCount {
	return ByteCount(rtt) * ByteCount(bandwidth) / ByteCount(BytesPerSecond) / ByteCount(time.Second)
}
