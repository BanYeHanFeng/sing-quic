package udpx

import (
	"sync"
	"time"

	"github.com/sagernet/sing-quic/congestion"
)

// Congestion control
//
// The controller decides how much may be in flight and when the next packet may
// leave. What it needs from the transport is only what the transport knows:
// packets leaving, packets acknowledged, packets given up on, and how long the
// path takes. That is why it lives in its own package: the same controller runs
// over this protocol and over one whose packet numbers are not in the clear.
//
// A redundant packet is a packet: it takes room in the window like any other, and
// the pacing that comes out of the window is what the send path follows. Without
// that, a stream with nothing to lose would be free to fill every buffer between
// the two ends, and the losses that follow would be the sender's own doing.
//
// The controller is called with ccMu held, and it is the innermost lock: it is
// taken after the send lock and after the flight lock, never around them.

// rttSnapshot is the round trip estimate in the shape the controller asks for.
//
// It is a copy with a lock of its own rather than a view of the estimator: the
// controller asks for it while the association holds its flight lock, and reading
// the estimator directly would take that lock twice.
type rttSnapshot struct {
	mu       sync.Mutex
	smoothed time.Duration
	latest   time.Duration
	min      time.Duration
}

func (s *rttSnapshot) update(estimator rttEstimator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smoothed = estimator.smoothed
	s.latest = estimator.latest
	s.min = estimator.min
}

func (s *rttSnapshot) MinRTT() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.min
}

func (s *rttSnapshot) SmoothedRTT() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.smoothed
}

func (s *rttSnapshot) LatestRTT() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

// newCongestionController builds the controller of an association.
func newCongestionController(options Options) congestion.Controller {
	return congestion.NewBbrController(congestion.ByteCount(maxPacketSize), options.Congestion)
}

// congestionBudget reports whether a packet may leave now, and when it may if it
// may not.
func (a *association) congestionBudget() (bool, time.Time) {
	a.flightMu.Lock()
	inFlight := congestion.ByteCount(a.inFlight.bytes)
	a.flightMu.Unlock()
	now := time.Now()
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	if !a.cc.CanSend(inFlight) {
		return false, time.Time{}
	}
	if a.cc.HasPacingBudget(now) {
		return true, time.Time{}
	}
	return false, a.cc.TimeUntilSend(inFlight)
}

// congestionSent records a packet that left.
func (a *association) congestionSent(packetNumber uint32, size int, priorInFlight int, retransmittable bool) {
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	a.cc.OnPacketSent(time.Now(), congestion.ByteCount(priorInFlight), congestion.PacketNumber(packetNumber), congestion.ByteCount(size), retransmittable)
}

// congestionAcked reports what one acknowledgement settled: the packets it
// acknowledged, and the packets that were declared lost by the same answer.
//
// Both go to the controller in one event, because that is the shape of the
// decision it makes: a window that grows by what arrived and falls by what was
// lost, where the two only mean something next to each other.
func (a *association) congestionAcked(acked, lost []*sentPacket, priorInFlight int, now time.Time) {
	if len(acked) == 0 && len(lost) == 0 {
		return
	}
	acknowledged := make([]congestion.AckedPacketInfo, 0, len(acked))
	for _, packet := range acked {
		acknowledged = append(acknowledged, congestion.AckedPacketInfo{
			TimeSent:     packet.sentAt,
			BytesAcked:   congestion.ByteCount(packet.size),
			PacketNumber: congestion.PacketNumber(packet.packetNumber),
		})
	}
	lostPackets := make([]congestion.LostPacketInfo, 0, len(lost))
	for _, packet := range lost {
		lostPackets = append(lostPackets, congestion.LostPacketInfo{
			TimeSent:     packet.sentAt,
			BytesLost:    congestion.ByteCount(packet.size),
			PacketNumber: congestion.PacketNumber(packet.packetNumber),
		})
	}
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	a.cc.OnCongestionEvent(congestion.ByteCount(priorInFlight), now, acknowledged, lostPackets)
}

// rttEstimate returns a copy of the round trip estimate.
func (a *association) rttEstimate() rttEstimator {
	a.flightMu.Lock()
	defer a.flightMu.Unlock()
	return a.rtt
}

// queueLength is how many frames wait to be sent.
func (a *association) queueLength() int {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.queue.len()
}
