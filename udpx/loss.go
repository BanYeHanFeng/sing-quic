package udpx

import (
	"time"
)

// Loss detection
//
// A packet is either acknowledged, or it is lost, or it is still in flight. There
// is no fourth state and nothing to repair: the frames of a lost packet go back
// to the send queue and leave again in a new packet, which is the same path they
// took the first time.
//
// Two thresholds decide when a packet is lost, and they cover each other:
//
//   - a packet far enough behind what the peer acknowledged is lost, because a
//     path does not reorder that much. This is the fast path, and it is why an
//     acknowledgement names ranges: the holes in it are the packets to recover.
//   - a packet that has been in flight longer than the round trip is lost, which
//     catches the last packets of a burst, where nothing behind them can be
//     acknowledged.
//
// What neither threshold catches is a path that went silent, or an acknowledgement
// that was itself lost. For that there is a probe: when the timer for the oldest
// packet in flight expires, that packet is declared lost and sent again, and the
// wait before the next probe doubles, because a path that did not answer once may
// be gone rather than slow. An association that keeps probing is not idle, which
// is why the idle timeout does not fire while it does.
const (
	// packetThreshold is how many packets a peer must have acknowledged past a
	// packet before it is declared lost.
	packetThreshold = 3

	// timeThreshold is the fraction of the round trip a packet may spend in
	// flight before it is declared lost. A round trip and an eighth is the
	// smallest margin that does not declare packets lost on a path that merely
	// jittered.
	timeThreshold = 9.0 / 8.0

	// initialPTO is how long the first probe waits, before anything about the
	// path has been measured.
	initialPTO = 500 * time.Millisecond

	// maxProbeBackoff is how often the wait between probes may double.
	maxProbeBackoff = 4
)

// lossDelay is how long a packet must have been in flight before it is lost. The
// larger of the smoothed and the latest round trip is used, so a path that just
// got slower is not declared to be losing packets.
func lossDelay(rtt rttEstimator) time.Duration {
	base := rtt.smoothed
	if rtt.latest > base {
		base = rtt.latest
	}
	if base <= 0 {
		return timerGranularity
	}
	delay := time.Duration(float64(base) * timeThreshold)
	if delay < timerGranularity {
		delay = timerGranularity
	}
	return delay
}

// retransmittableFrames returns the frames of the lost packets that have to be
// sent again, oldest packet first: the frame that was in flight longest is the
// one whose data the peer has waited for longest.
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

// sendFramesRetransmitted puts frames back at the head of the send queue, so a
// recovered packet does not wait behind data produced after it, and sends what can
// go out now.
func (a *association) sendFramesRetransmitted(frames []outFrame) error {
	if len(frames) == 0 {
		return nil
	}
	a.sendMu.Lock()
	a.queue.pushFront(frames)
	a.sendMu.Unlock()
	return a.flush()
}

// armPTO starts the probe timer. The wait doubles with every probe that went
// unanswered, but only up to a point: a path that is merely slow must still be
// probed often enough to notice it came back.
func (a *association) armPTO() {
	a.flightMu.Lock()
	delay := a.rtt.pto()
	backoff := a.probes
	a.flightMu.Unlock()
	if backoff > maxProbeBackoff {
		backoff = maxProbeBackoff
	}
	a.ptoTimer.Reset(delay << backoff)
}

// disarmPTO stops the probe timer. A probe exists to find out whether a packet
// arrived, and with nothing in flight there is no packet left to ask about.
func (a *association) disarmPTO() {
	a.ptoTimer.Stop()
}

// probe declares the oldest packet in flight lost and sends it again.
func (a *association) probe() {
	a.flightMu.Lock()
	oldest := a.inFlight.oldest()
	if oldest == nil {
		a.flightMu.Unlock()
		return
	}
	frames := retransmittableFrames([]*sentPacket{oldest})
	a.inFlight.remove(oldest)
	a.probes++
	a.flightMu.Unlock()

	// The frames go out as a new packet, which arms the timer again through the
	// send path; a probe of nothing but a ping is what asks a silent peer for an
	// answer when there is nothing to send again.
	err := a.sendFramesRetransmitted(frames)
	if err != nil {
		return
	}
	if len(frames) == 0 {
		_ = a.send(appendPing(nil))
		return
	}
	a.armPTO()
}

// handleAck takes the acknowledged packets out of flight, samples the round trip,
// tells the congestion controller what arrived and what was lost, and sends
// whatever the window now allows.
func (a *association) handleAck(body []byte, now time.Time) {
	acknowledgement, err := parseAck(body)
	if err != nil {
		return
	}
	a.flightMu.Lock()
	priorInFlight := a.inFlight.bytes
	acked := a.inFlight.acked(acknowledgement.ranges[:acknowledgement.count])
	for _, packet := range acked {
		if packet.packetNumber != acknowledgement.largest {
			continue
		}
		a.rtt.sample(now.Sub(packet.sentAt) - acknowledgement.delay)
	}
	if len(acked) > 0 {
		// An answer arrived, so the path is there and the probes start over.
		a.probes = 0
	}
	lost := a.inFlight.lost(now, acknowledgement.largest, lossDelay(a.rtt))
	recovered := retransmittableFrames(lost)
	empty := a.inFlight.len() == 0
	a.flightMu.Unlock()

	a.rttStats.update(a.rttEstimate())
	a.congestionAcked(acked, lost, priorInFlight, now)
	if empty {
		a.disarmPTO()
	} else {
		a.armPTO()
	}
	if len(recovered) > 0 {
		_ = a.sendFramesRetransmitted(recovered)
	}
	// The window just opened, so whatever waited for it can go out.
	if a.queueLength() > 0 {
		_ = a.flush()
	}
}
