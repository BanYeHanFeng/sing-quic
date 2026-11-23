package udpx

import (
	"time"
)

const (
	packetThreshold = 3

	timeThreshold = 9.0 / 8.0

	initialPTO = 500 * time.Millisecond

	maxProbeBackoff = 5

	maxProbeSilence = 20 * time.Second

	quietPathBudget = 2 * time.Second
)

func lossDelay(rtt rttEstimator) time.Duration {
	base := rtt.smoothed
	if rtt.latest > base {
		base = rtt.latest
	}
	if base <= 0 {
		base = initialRTT
	}
	delay := time.Duration(float64(base)*timeThreshold) + maxAckDelay
	if delay < timerGranularity {
		delay = timerGranularity
	}
	return delay
}

func retransmittableFrames(packets []*sentPacket) []outFrame {
	var frames []outFrame
	for _, packet := range packets {
		for _, frame := range packet.frames {
			if frame.frameType().retransmittable() {
				frames = append(frames, frame)
			}
		}
	}
	return frames
}

func (a *association) sendFramesRetransmitted(frames []outFrame) {
	if len(frames) == 0 {
		return
	}
	a.stats.retransmits.Add(int64(len(frames)))
	a.sendMu.Lock()
	a.queue.pushFront(frames)
	a.sendMu.Unlock()
	a.wake()
}

func (a *association) armPTO() {
	a.flightMu.Lock()
	delay := a.rtt.pto()
	backoff := a.probes
	a.flightMu.Unlock()
	if backoff > maxProbeBackoff {
		backoff = maxProbeBackoff
	}
	a.timers.Load().pto.Reset(delay << backoff)
}

func (a *association) disarmPTO() {
	a.timers.Load().pto.Stop()
}

func (a *association) Reachable() bool {
	a.flightMu.Lock()
	probing := a.probes > 0
	since := a.probeSince
	a.flightMu.Unlock()
	if !probing {
		return true
	}
	return time.Since(since) < quietPathBudget
}

func (a *association) probe() {
	a.flightMu.Lock()
	oldest := a.inFlight.oldest()
	if oldest == nil {
		a.flightMu.Unlock()
		return
	}
	a.probes++
	now := time.Now()
	if a.probes == 1 {
		a.probeSince = now
	}
	silent := now.Sub(a.probeSince) >= maxProbeSilence
	a.stats.probes.Add(1)
	a.flightMu.Unlock()
	if silent {
		a.logInfo("probe ", oldest.packetNumber, " unanswered for ", maxProbeSilence, ", closing")
		a.shutdown(ErrProbeTimeout, false)
		return
	}
	a.logDebug("probe ", oldest.packetNumber, " after ", a.probes, " unanswered")

	a.sendMu.Lock()
	a.queue.pushFront([]outFrame{{payload: appendPing(nil), ackEliciting: true}})
	a.probeCredits++
	a.sendMu.Unlock()
	a.wake()
	a.armPTO()
}

func (a *association) handleAck(body []byte, now time.Time) {
	acknowledgement, err := parseAck(body)
	if err != nil {
		return
	}
	a.mtuProbeConfirmed(acknowledgement)
	a.flightMu.Lock()
	priorInFlight := a.inFlight.bytes
	acked, spurious := a.inFlight.acked(acknowledgement.ranges[:acknowledgement.count])
	for _, packet := range acked {
		releaseFrames(packet.frames)
		if packet.packetNumber != acknowledgement.largest {
			continue
		}
		a.rtt.sample(now.Sub(packet.sentAt) - acknowledgement.delay)
	}
	a.probes = 0
	a.probeSince = time.Time{}
	lost := a.inFlight.lost(now, acknowledgement.largest, lossDelay(a.rtt), acknowledgement.count >= maxAckRanges)
	a.stats.lostPackets.Add(int64(len(lost)))
	if len(lost) > 0 {
		a.logDebug("ack ", acknowledgement.largest, " acked=", len(acked), " lost=", len(lost),
			" inflight=", priorInFlight, "B")
	}
	recovered := retransmittableFrames(lost)
	empty := a.inFlight.len() == 0
	a.flightMu.Unlock()

	a.stats.spuriousLoss.Add(int64(spurious))
	a.rttStats.update(a.rttEstimate())
	a.congestionAcked(acked, lost, priorInFlight, now)
	if empty {
		a.disarmPTO()
	} else {
		a.armPTO()
	}
	a.ackStreamFrames(acked)
	a.sendFramesRetransmitted(recovered)
	a.wake()
}
