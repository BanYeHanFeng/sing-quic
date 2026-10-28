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
	// The excess bytes acknowlwedged in the time delta for this event.
	extraAcked ByteCount

	// The bytes acknowledged and time delta from the event.
	bytesAcked ByteCount
	timeDelta  time.Duration
	// The round trip of the event.
	round roundTripCount
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
	// The bandwidth at that particular sample. Zero if no valid bandwidth sample
	// is available.
	bandwidth Bandwidth
	// The RTT measurement at this particular sample.  Zero if no RTT sample is
	// available.  Does not correct for delayed ack time.
	rtt time.Duration
}

func newBandwidthSample() *bandwidthSample {
	return &bandwidthSample{}
}

// MaxAckHeightTracker is part of the BandwidthSampler. It is called after every
// ack event to keep track the degree of ack aggregation(a.k.a "ack height").
type maxAckHeightTracker struct {
	// Tracks the maximum number of bytes acked faster than the estimated
	// bandwidth.
	maxAckHeightFilter *windowedFilter[extraAckedEvent]
	// The time this aggregation started and the number of bytes acked during it.
	aggregationEpochStartTime time.Time
	aggregationEpochBytes     ByteCount
	// The last sent packet number before the current aggregation epoch started.
	lastSentPacketNumberBeforeEpoch PacketNumber
	// The number of ack aggregation epochs ever started, including the ongoing
	// one. Stats only.
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
		// Save and clear existing entries.
		best := m.maxAckHeightFilter.getBest()
		secondBest := m.maxAckHeightFilter.getSecondBest()
		thirdBest := m.maxAckHeightFilter.getThirdBest()
		m.maxAckHeightFilter.clear()

		// Reinsert the heights into the filter after recalculating.
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

	// Compute how many bytes are expected to be delivered, assuming max bandwidth
	// is correct.
	aggregationDelta := ackTime.Sub(m.aggregationEpochStartTime)
	expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, aggregationDelta)
	// Reset the current aggregation epoch as soon as the ack arrival rate is less
	// than or equal to the max bandwidth.
	if m.aggregationEpochBytes <= ByteCount(m.ackAggregationBandwidthThreshold*float64(expectedBytesAcked)) {
		// Reset to start measuring a new aggregation epoch.
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	m.aggregationEpochBytes += bytesAcked

	// Compute how many extra bytes were delivered vs max bandwidth.
	extraBytesAcked := m.aggregationEpochBytes - expectedBytesAcked
	newEvent := extraAckedEvent{
		extraAcked: extraBytesAcked,
		bytesAcked: m.aggregationEpochBytes,
		timeDelta:  aggregationDelta,
	}
	m.maxAckHeightFilter.update(newEvent, roundTripCount)
	return extraBytesAcked
}

// BandwidthSampler keeps track of sent and acknowledged packets and outputs a
// bandwidth sample for every packet acknowledged. The samples are taken for
// individual packets, and are not filtered; the consumer has to filter the
// bandwidth samples itself. In certain cases, the sampler will locally severely
// underestimate the bandwidth, hence a maximum filter with a size of at least
// one RTT is recommended.
//
// This class bases its samples on the slope of two curves: the number of bytes
// sent over time, and the number of bytes acknowledged as received over time.
// It produces a sample of both slopes for every packet that gets acknowledged,
// based on a slope between two points on each of the corresponding curves. Note
// that due to the packet loss, the number of bytes on each curve might get
// further and further away from each other, meaning that it is not feasible to
// compare byte values coming from different curves with each other.
//
// The obvious points for measuring slope sample are the ones corresponding to
// the packet that was just acknowledged. Let us denote them as S_1 (point at
// which the current packet was sent) and A_1 (point at which the current packet
// was acknowledged). However, taking a slope requires two points on each line,
// so estimating bandwidth requires picking a packet in the past with respect to
// which the slope is measured.
//
// For that purpose, BandwidthSampler always keeps track of the most recently
// acknowledged packet, and records it together with every outgoing packet.
// When a packet gets acknowledged (A_1), it has not only information about when
// it itself was sent (S_1), but also the information about the latest
// acknowledged packet right before it was sent (S_0 and A_0).
//
// Based on that data, send and ack rate are estimated as:
//
//	send_rate = (bytes(S_1) - bytes(S_0)) / (time(S_1) - time(S_0))
//	ack_rate = (bytes(A_1) - bytes(A_0)) / (time(A_1) - time(A_0))
//
// Here, the ack rate is intuitively the rate we want to treat as bandwidth.
// However, in certain cases (e.g. ack compression) the ack rate at a point may
// end up higher than the rate at which the data was originally sent, which is
// not indicative of the real bandwidth. Hence, we use the send rate as an upper
// bound, and the sample value is
//
//	rate_sample = min(send_rate, ack_rate)
//
// An important edge case handled by the sampler is tracking the app-limited
// samples. There are multiple meaning of "app-limited" used interchangeably,
// hence it is important to understand and to be able to distinguish between
// them.
//
// Meaning 1: connection state. The connection is said to be app-limited when
// there is no outstanding data to send. This means that certain bandwidth
// samples in the future would not be an accurate indication of the link
// capacity, and it is important to inform consumer about that. Whenever
// connection becomes app-limited, the sampler is notified via onAppLimited()
// method.
//
// Meaning 2: a phase in the bandwidth sampler. As soon as the bandwidth
// sampler becomes notified about the connection being app-limited, it enters
// app-limited phase. In that phase, all *sent* packets are marked as
// app-limited. Note that the connection itself does not have to be
// app-limited during the app-limited phase, and in fact it will not be
// (otherwise how would it send packets?). The boolean flag below indicates
// whether the sampler is in that phase.
//
// Meaning 3: a flag on the sent packet and on the sample. If a sent packet is
// sent during the app-limited phase, the resulting sample related to the
// packet will be marked as app-limited.
//
// With the terminology issue out of the way, let us consider the question of
// what kind of situation it addresses.
//
// Consider a scenario where we first send packets 1 to 20 at a regular
// bandwidth, and then immediately run out of data. After a few seconds, we send
// packets 21 to 60, and only receive ack for 21 between sending packets 40 and
// 41. In this case, when we sample bandwidth for packets 21 to 40, the S_0/A_0
// we use to compute the slope is going to be packet 20, a few seconds apart
// from the current packet, hence the resulting estimate would be extremely low
// and not indicative of anything. Only at packet 41 the S_0/A_0 will become 21,
// meaning that the bandwidth sample would exclude the quiescence.
//
// Based on the analysis of that scenario, we implement the following rule: once
// onAppLimited() is called, all sent packets will produce app-limited samples
// up until an ack for a packet that was sent after onAppLimited() was called.
// Note that while the scenario above is not the only scenario when the
// connection is app-limited, the approach works in other cases too.

type congestionEventSample struct {
	// The maximum bandwidth sample from all acked packets.
	// QuicBandwidth::Zero() if no samples are available.
	sampleMaxBandwidth Bandwidth
	// Whether |sample_max_bandwidth| is from a app-limited sample.
	sampleIsAppLimited bool
	// The minimum rtt sample from all acked packets.
	// QuicTime::Delta::Infinite() if no samples are available.
	sampleRtt time.Duration
	// The state of the largest packet in acked_packets, unless it is empty. If
	// acked_packets is empty, it's the state of the largest packet in lost_packets.
	lastPacketState SendState
}

func newCongestionEventSample() *congestionEventSample {
	return &congestionEventSample{
		sampleRtt: infRTT,
	}
}

type bandwidthSampler struct {
	// The total number of congestion controlled bytes sent during the connection.
	totalBytesSent ByteCount

	// The total number of congestion controlled bytes which were acknowledged.
	totalBytesAcked ByteCount

	// The total number of congestion controlled bytes which were lost.
	totalBytesLost ByteCount

	// The value of |total_bytes_sent_| at the time the last acknowledged packet
	// was sent. Valid only when |last_acked_packet_sent_time_| is valid.
	totalBytesSentAtLastAckedPacket ByteCount

	// The time at which the last acknowledged packet was sent. Set to
	// QuicTime::Zero() if no valid timestamp is available.
	lastAckedPacketSentTime time.Time

	// The time at which the most recent packet was acknowledged.
	lastAckedPacketAckTime time.Time

	// The most recently sent packet.
	lastSentPacket PacketNumber

	// The most recently acked packet.
	lastAckedPacket PacketNumber

	// Indicates whether the bandwidth sampler is currently in an app-limited
	// phase.
	isAppLimited bool

	// The packet that will be acknowledged after this one will cause the sampler
	// to exit the app-limited phase.
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

	// If there are no packets in flight, the time at which the new transmission
	// opens can be treated as the A_0 point for the purpose of bandwidth
	// sampling. This underestimates bandwidth to some extent, and produces some
	// artificially low samples for most packets in flight, but it provides with
	// samples at important points where we would not have them otherwise, most
	// importantly at the beginning of the connection.
	if bytesInFlight == 0 {
		b.lastAckedPacketAckTime = sentTime
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent

		// In this situation ack compression is not a concern, set send rate to
		// effectively infinite.
		b.lastAckedPacketSentTime = sentTime
	}

	state := SendState{
		priorAckTime: b.lastAckedPacketAckTime,
		delivered:    b.totalBytesAcked,
		sentTotal:    b.totalBytesSent,
		appLimited:   b.isAppLimited,
	}
	// The send rate is the slope of the sending up to this packet, taken from the
	// last packet that was acknowledged before it left. Before the first
	// acknowledgement there is nothing to measure against, and a packet with no send
	// rate behind it yields no sample at all.
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
		// Only populate send state for a loss-only event.
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

	// If two packets are inflight and an alarm is armed to lose a packet and it
	// wakes up late, then the first of two in flight packets could have been
	// acknowledged before the wakeup, which re-evaluates loss detection, and
	// could declare the later of the two lost.
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
		// Exit app-limited phase in two cases:
		// (1) end_of_app_limited_phase_ is not initialized, i.e., so far all
		// packets are sent while there are buffered packets or pending data.
		// (2) The current acked packet is after the sent packet marked as the end
		// of the app limit phase.
		if b.endOfAppLimitedPhase == invalidPacketNumber ||
			packet.PacketNumber > b.endOfAppLimitedPhase {
			b.isAppLimited = false
		}
	}

	// There might have been no packets acknowledged at the moment when the
	// current packet was sent. In that case, there is no bandwidth sample to
	// make.
	if packet.sendRate == 0 {
		return *sample
	}

	// The ack line starts at the last acknowledgement before this one: the sample
	// is what arrived between the two, over the time between the two.
	//
	// During the slope calculation, ensure that ack time of the current packet is
	// always larger than the time of the previous packet, otherwise division by
	// zero or integer underflow can occur.
	if ackTime.Sub(packet.priorAckTime) <= 0 {
		return *sample
	}

	ackRate := bandwidthFromDelta(b.totalBytesAcked-packet.delivered, ackTime.Sub(packet.priorAckTime))

	sample.bandwidth = min(packet.sendRate, ackRate)
	// Note: this sample does not account for delayed acknowledgement time.  This
	// means that the RTT measurements here can be artificially high, especially
	// on low bandwidth connections.
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

// BytesFromBandwidthAndTimeDelta calculates the bytes
// from a bandwidth(bits per second) and a time delta
func bytesFromBandwidthAndTimeDelta(bandwidth Bandwidth, delta time.Duration) ByteCount {
	return (ByteCount(bandwidth) * ByteCount(delta)) /
		(ByteCount(time.Second) * 8)
}
