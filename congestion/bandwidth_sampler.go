package congestion

import (
	"math"
	"time"
)

const (
	infRTT = time.Duration(math.MaxInt64)
)

type roundTripCount uint64

type extraAckedEvent struct {
	extraAcked ByteCount

	bytesAcked ByteCount
	timeDelta  time.Duration
	round      roundTripCount
}

func maxExtraAckedEventFunc(a, b extraAckedEvent) int {
	if a.extraAcked > b.extraAcked {
		return 1
	} else if a.extraAcked < b.extraAcked {
		return -1
	}
	return 0
}

type bandwidthSample struct {
	bandwidth Bandwidth
	rtt       time.Duration
}

func newBandwidthSample() *bandwidthSample {
	return &bandwidthSample{}
}

type maxAckHeightTracker struct {
	maxAckHeightFilter               *windowedFilter[extraAckedEvent]
	aggregationEpochStartTime        time.Time
	aggregationEpochBytes            ByteCount
	lastSentPacketNumberBeforeEpoch  PacketNumber
	numAckAggregationEpochs          uint64
	ackAggregationBandwidthThreshold float64
}

func newMaxAckHeightTracker(windowLength roundTripCount) *maxAckHeightTracker {
	return &maxAckHeightTracker{
		maxAckHeightFilter:               newWindowedFilter(windowLength, maxExtraAckedEventFunc),
		lastSentPacketNumberBeforeEpoch:  invalidPacketNumber,
		ackAggregationBandwidthThreshold: 1.0,
	}
}

func (m *maxAckHeightTracker) get() ByteCount {
	return m.maxAckHeightFilter.getBest().extraAcked
}

func (m *maxAckHeightTracker) update(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
	lastSentPacketNumber PacketNumber,
	lastAckedPacketNumber PacketNumber,
	ackTime time.Time,
	bytesAcked ByteCount,
) ByteCount {
	forceNewEpoch := false

	if isNewMaxBandwidth {
		best := m.maxAckHeightFilter.getBest()
		secondBest := m.maxAckHeightFilter.getSecondBest()
		thirdBest := m.maxAckHeightFilter.getThirdBest()
		m.maxAckHeightFilter.clear()

		expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, best.timeDelta)
		if expectedBytesAcked < best.bytesAcked {
			best.extraAcked = best.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.update(best, best.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, secondBest.timeDelta)
		if expectedBytesAcked < secondBest.bytesAcked {
			secondBest.extraAcked = secondBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.update(secondBest, secondBest.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, thirdBest.timeDelta)
		if expectedBytesAcked < thirdBest.bytesAcked {
			thirdBest.extraAcked = thirdBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.update(thirdBest, thirdBest.round)
		}
	}

	if m.aggregationEpochStartTime.IsZero() || forceNewEpoch {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	aggregationDelta := ackTime.Sub(m.aggregationEpochStartTime)
	expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, aggregationDelta)
	if m.aggregationEpochBytes <= ByteCount(m.ackAggregationBandwidthThreshold*float64(expectedBytesAcked)) {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	m.aggregationEpochBytes += bytesAcked

	extraBytesAcked := m.aggregationEpochBytes - expectedBytesAcked
	newEvent := extraAckedEvent{
		extraAcked: extraBytesAcked,
		bytesAcked: m.aggregationEpochBytes,
		timeDelta:  aggregationDelta,
	}
	m.maxAckHeightFilter.update(newEvent, roundTripCount)
	return extraBytesAcked
}

type congestionEventSample struct {
	sampleMaxBandwidth Bandwidth
	sampleIsAppLimited bool
	sampleRtt          time.Duration
	lastPacketState    SendState
}

func newCongestionEventSample() *congestionEventSample {
	return &congestionEventSample{
		sampleRtt: infRTT,
	}
}

type bandwidthSampler struct {
	totalBytesSent ByteCount

	totalBytesAcked ByteCount

	totalBytesLost ByteCount

	totalBytesSentAtLastAckedPacket ByteCount

	lastAckedPacketSentTime time.Time

	lastAckedPacketAckTime time.Time

	lastSentPacket PacketNumber

	lastAckedPacket PacketNumber

	isAppLimited bool

	endOfAppLimitedPhase PacketNumber

	maxAckHeightTracker              *maxAckHeightTracker
	totalBytesAckedAfterLastAckEvent ByteCount
}

func newBandwidthSampler(maxAckHeightTrackerWindowLength roundTripCount) *bandwidthSampler {
	b := &bandwidthSampler{
		maxAckHeightTracker:  newMaxAckHeightTracker(maxAckHeightTrackerWindowLength),
		lastSentPacket:       invalidPacketNumber,
		lastAckedPacket:      invalidPacketNumber,
		endOfAppLimitedPhase: invalidPacketNumber,
	}

	return b
}

func (b *bandwidthSampler) maxAckHeight() ByteCount {
	return b.maxAckHeightTracker.get()
}

func (b *bandwidthSampler) OnPacketSent(sentTime time.Time, packetNumber PacketNumber, bytes ByteCount, bytesInFlight ByteCount) SendState {
	b.lastSentPacket = packetNumber
	b.totalBytesSent += bytes

	if bytesInFlight == 0 {
		b.lastAckedPacketAckTime = sentTime
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent

		b.lastAckedPacketSentTime = sentTime
	}

	state := SendState{
		priorAckTime: b.lastAckedPacketAckTime,
		delivered:    b.totalBytesAcked,
		sentTotal:    b.totalBytesSent,
		appLimited:   b.isAppLimited,
	}
	if !b.lastAckedPacketSentTime.IsZero() {
		if sentTime.After(b.lastAckedPacketSentTime) {
			state.sendRate = bandwidthFromDelta(
				b.totalBytesSent-b.totalBytesSentAtLastAckedPacket,
				sentTime.Sub(b.lastAckedPacketSentTime),
			)
		} else {
			state.sendRate = infBandwidth
		}
	}
	return state
}

func (b *bandwidthSampler) OnCongestionEvent(
	ackTime time.Time,
	ackedPackets []AckedPacketInfo,
	lostPackets []LostPacketInfo,
	maxBandwidth Bandwidth,
	estBandwidthUpperBound Bandwidth,
	roundTripCount roundTripCount,
) congestionEventSample {
	eventSample := newCongestionEventSample()

	for _, p := range lostPackets {
		b.totalBytesLost += p.BytesLost
	}

	if len(ackedPackets) == 0 {
		eventSample.lastPacketState = lostPackets[len(lostPackets)-1].SendState
		return *eventSample
	}

	for _, p := range ackedPackets {
		sample := b.onPacketAcknowledged(ackTime, p)
		if sample.rtt != 0 {
			eventSample.sampleRtt = min(eventSample.sampleRtt, sample.rtt)
		}
		if sample.bandwidth > eventSample.sampleMaxBandwidth {
			eventSample.sampleMaxBandwidth = sample.bandwidth
			eventSample.sampleIsAppLimited = p.appLimited
		}
	}

	eventSample.lastPacketState = ackedPackets[len(ackedPackets)-1].SendState
	if len(lostPackets) > 0 && lostPackets[len(lostPackets)-1].PacketNumber > ackedPackets[len(ackedPackets)-1].PacketNumber {
		eventSample.lastPacketState = lostPackets[len(lostPackets)-1].SendState
	}

	isNewMaxBandwidth := eventSample.sampleMaxBandwidth > maxBandwidth
	maxBandwidth = max(maxBandwidth, eventSample.sampleMaxBandwidth)

	b.onAckEventEnd(min(estBandwidthUpperBound, maxBandwidth), isNewMaxBandwidth, roundTripCount)

	return *eventSample
}

func (b *bandwidthSampler) onAppLimited() {
	b.isAppLimited = true
	b.endOfAppLimitedPhase = b.lastSentPacket
}

func (b *bandwidthSampler) onPacketAcknowledged(ackTime time.Time, packet AckedPacketInfo) bandwidthSample {
	sample := newBandwidthSample()
	b.lastAckedPacket = packet.PacketNumber

	b.totalBytesAcked += packet.BytesAcked
	b.totalBytesSentAtLastAckedPacket = packet.sentTotal
	b.lastAckedPacketSentTime = packet.TimeSent
	b.lastAckedPacketAckTime = ackTime

	if b.isAppLimited {
		if b.endOfAppLimitedPhase == invalidPacketNumber ||
			packet.PacketNumber > b.endOfAppLimitedPhase {
			b.isAppLimited = false
		}
	}

	if packet.sendRate == 0 {
		return *sample
	}

	if ackTime.Sub(packet.priorAckTime) <= 0 {
		return *sample
	}

	ackRate := bandwidthFromDelta(b.totalBytesAcked-packet.delivered, ackTime.Sub(packet.priorAckTime))

	sample.bandwidth = min(packet.sendRate, ackRate)
	sample.rtt = ackTime.Sub(packet.TimeSent)

	return *sample
}

func (b *bandwidthSampler) onAckEventEnd(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
) {
	newlyAckedBytes := b.totalBytesAcked - b.totalBytesAckedAfterLastAckEvent
	if newlyAckedBytes == 0 {
		return
	}
	b.totalBytesAckedAfterLastAckEvent = b.totalBytesAcked
	b.maxAckHeightTracker.update(
		bandwidthEstimate,
		isNewMaxBandwidth,
		roundTripCount,
		b.lastSentPacket,
		b.lastAckedPacket,
		b.lastAckedPacketAckTime,
		newlyAckedBytes)
}

func bytesFromBandwidthAndTimeDelta(bandwidth Bandwidth, delta time.Duration) ByteCount {
	return (ByteCount(bandwidth) * ByteCount(delta)) /
		(ByteCount(time.Second) * 8)
}
