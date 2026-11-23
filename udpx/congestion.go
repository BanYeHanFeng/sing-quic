package udpx

import (
	"sync"
	"time"

	"github.com/sagernet/sing-quic/congestion"
)

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

const initialCongestionWindowPackets = 128

func newCongestionController() congestion.Controller {
	return congestion.NewBbrController(
		congestion.ByteCount(maxPacketSize),
		int64(initialCongestionWindowPackets),
	)
}

func (a *association) congestionCharged() congestion.ByteCount {
	a.flightMu.Lock()
	inFlight := a.inFlight.bytes
	a.flightMu.Unlock()
	return congestion.ByteCount(inFlight + a.batch.planned)
}

func (a *association) windowAllows() bool {
	charged := a.congestionCharged()
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	return a.cc.CanSend(charged)
}

func (a *association) congestionAppLimited() {
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	a.cc.OnAppLimited()
}

func (a *association) pacingWait() time.Duration {
	now := time.Now()
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	return a.cc.PacingWait(now)
}

func (a *association) congestionSent(packetNumber uint32, size int, priorInFlight int) congestion.SendState {
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	return a.cc.OnPacketSent(time.Now(), congestion.ByteCount(priorInFlight), congestion.PacketNumber(packetNumber), congestion.ByteCount(size))
}

func (a *association) congestionAcked(acked, lost []*sentPacket, priorInFlight int, now time.Time) {
	if len(acked) == 0 && len(lost) == 0 {
		return
	}
	acknowledged := make([]congestion.AckedPacketInfo, 0, len(acked))
	for _, packet := range acked {
		acknowledged = append(acknowledged, congestion.AckedPacketInfo{
			SendState:    packet.sendState,
			TimeSent:     packet.sentAt,
			BytesAcked:   congestion.ByteCount(packet.size),
			PacketNumber: congestion.PacketNumber(packet.packetNumber),
		})
	}
	lostPackets := make([]congestion.LostPacketInfo, 0, len(lost))
	for _, packet := range lost {
		lostPackets = append(lostPackets, congestion.LostPacketInfo{
			SendState:    packet.sendState,
			TimeSent:     packet.sentAt,
			BytesLost:    congestion.ByteCount(packet.size),
			PacketNumber: congestion.PacketNumber(packet.packetNumber),
		})
	}
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	a.cc.OnCongestionEvent(congestion.ByteCount(priorInFlight), now, acknowledged, lostPackets)
}

func (a *association) rttEstimate() rttEstimator {
	a.flightMu.Lock()
	defer a.flightMu.Unlock()
	return a.rtt
}

func (a *association) queueLength() int {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return a.queue.len()
}
