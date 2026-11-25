package congestion

import (
	"math/rand"
	"time"
)

const (
	minBps = 65536

	invalidPacketNumber            = -1
	initialCongestionWindowPackets = 32
	minCongestionWindowPackets     = 4
	maxCongestionWindowPackets     = 20000

	defaultHighGain     = 2.885
	derivedHighCWNDGain = 2.0
)

var pacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	gainCycleLength     = len(pacingGain)
	bandwidthWindowSize = gainCycleLength + 2

	minRttExpiry                                          = 10 * time.Second
	probeRttTime                                          = 200 * time.Millisecond
	probeRttMaxStay                                       = time.Second
	probeRTTWindowSlack                         ByteCount = 1000
	cycleOffsetRange                                      = 100
	startupGrowthTarget                                   = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup           = int64(2)
)

type bbrMode int

const (
	bbrModeStartup = iota
	bbrModeDrain
	bbrModeProbeBw
	bbrModeProbeRtt
)

type bbrSender struct {
	minRTT MinRTTProvider
	pacer  *pacer

	mode bbrMode

	sampler *bandwidthSampler

	roundTripCount roundTripCount

	lastSentPacket      PacketNumber
	currentRoundTripEnd PacketNumber

	maxBandwidth *windowedFilter[Bandwidth]

	minRtt          time.Duration
	minRttTimestamp time.Time

	congestionWindow ByteCount

	initialCongestionWindow ByteCount

	maxCongestionWindow ByteCount

	minCongestionWindow ByteCount

	highGain float64

	highCwndGain float64

	drainGain float64

	measuredPacingRate Bandwidth

	pacingGain           float64
	congestionWindowGain float64

	congestionWindowGainConstant float64
	numStartupRtts               int64

	cycleCurrentOffset int
	lastCycleStart     time.Time

	isAtFullBandwidth          bool
	roundsWithoutBandwidthGain int64
	bandwidthAtLastRound       Bandwidth

	exitingQuiescence bool

	exitProbeRttAt      time.Time
	probeRttRoundPassed bool
	enteredProbeRttAt   time.Time

	lastSampleIsAppLimited bool

	lastEventHadLoss bool

	bytesInFlight ByteCount
}

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

func (b *bbrSender) SetMinRTTProvider(provider MinRTTProvider) {
	b.minRTT = provider
}

func (b *bbrSender) PacingWait(now time.Time) time.Duration {
	return b.pacer.wait(now)
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

func (b *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount) SendState {
	b.pacer.sentPacket(sentTime, bytes)

	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	return b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight)
}

func (b *bbrSender) CanSend(bytesInFlight ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) OnAppLimited() {
	b.sampler.onAppLimited()
}

func (b *bbrSender) GetCongestionWindow() ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	return b.congestionWindow
}

func (b *bbrSender) OnCongestionEvent(priorInFlight ByteCount, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo) {
	totalBytesAckedBefore := b.sampler.totalBytesAcked

	var isRoundStart, minRttExpired bool

	b.lastEventHadLoss = len(lostPackets) != 0

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
	if paced := b.pacingRate(); sample.sampleMaxBandwidth > paced {
		sample.sampleMaxBandwidth = paced
	}
	if totalBytesAckedBefore != b.sampler.totalBytesAcked {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.getBest() {
			b.maxBandwidth.update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}

	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(lostPackets) != 0)
	}

	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached()
	}

	b.maybeExitStartupOrDrain(eventTime)

	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore

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

func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.getBest()
}

func (b *bbrSender) bandwidthForPacer() ByteCount {
	bps := ByteCount(float64(b.pacingRate()) / float64(BytesPerSecond))
	if bps < minBps {
		return minBps
	}
	return bps
}

func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	minRtt := b.minRTT.MinRTT()
	if minRtt == 0 {
		return 100 * time.Millisecond
	} else {
		return minRtt
	}
}

func (b *bbrSender) getTargetCongestionWindow(gain float64) ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := ByteCount(gain * float64(bdp))

	if congestionWindow == 0 {
		congestionWindow = ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return max(congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) probeRttCongestionWindow() ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now time.Time, sampleMinRtt time.Duration) bool {
	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}

	return minRttExpired
}

func (b *bbrSender) enterStartupMode(now time.Time) {
	b.mode = bbrModeStartup
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *bbrSender) enterProbeBandwidthMode(now time.Time) {
	b.mode = bbrModeProbeBw
	b.congestionWindowGain = b.congestionWindowGainConstant

	b.cycleCurrentOffset = int(rand.Int31n(cycleOffsetRange)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]
}

func (b *bbrSender) updateRoundTripCounter(lastAckedPacket PacketNumber) bool {
	if b.currentRoundTripEnd == invalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}
	return false
}

func (b *bbrSender) updateGainCyclePhase(now time.Time, priorInFlight ByteCount, hasLosses bool) {
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	if b.pacingGain < 1.0 && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) checkIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		if b.bandwidthEstimate() == 0 {
			return
		}
		b.roundsWithoutBandwidthGain++
		if b.roundsWithoutBandwidthGain >= b.numStartupRtts*4 {
			b.isAtFullBandwidth = true
		}
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

func (b *bbrSender) maybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && b.lastEventHadLoss {
		b.minRttTimestamp = now
		minRttExpired = false
	}
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.pacingGain = 1.0
		b.exitProbeRttAt = time.Time{}
		b.enteredProbeRttAt = now
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.onAppLimited()

		if b.exitProbeRttAt.IsZero() {
			if b.bytesInFlight < b.probeRttCongestionWindow()+probeRTTWindowSlack {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			} else if now.Sub(b.enteredProbeRttAt) >= probeRttMaxStay {
				b.exitProbeRttAt = now
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
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

func (b *bbrSender) calculatePacingRate() {
	if b.bandwidthEstimate() == 0 {
		return
	}
	b.measuredPacingRate = Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		targetWindow += b.sampler.maxAckHeight()
	}

	if b.isAtFullBandwidth {
		b.congestionWindow = min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.totalBytesAcked < b.initialCongestionWindow {
		b.congestionWindow += bytesAcked
	}

	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) ByteCount {
	return ByteCount(rtt) * ByteCount(bandwidth) / ByteCount(BytesPerSecond) / ByteCount(time.Second)
}
