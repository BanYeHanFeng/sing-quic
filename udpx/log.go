package udpx

import (
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/congestion"
)

type associationStats struct {
	sentPackets      atomic.Int64
	sentBytes        atomic.Int64
	recvPackets      atomic.Int64
	recvBytes        atomic.Int64
	lostPackets      atomic.Int64
	retransmits      atomic.Int64
	probes           atomic.Int64
	spuriousLoss     atomic.Int64
	droppedDatagrams atomic.Int64
}

type statsSnapshot struct {
	sentPackets    int64
	sentBytes      int64
	recvPackets    int64
	recvBytes      int64
	lostPackets    int64
	retransmits    int64
	probes         int64
	spuriousLoss   int64
	dropped        int64
	cwnd           int64
	inFlight       int
	inFlightSize   int
	queued         int
	state          string
	sendCreditLeft uint64
	recvCreditLeft uint64
}

func (a *association) snapshot() statsSnapshot {
	snapshot := statsSnapshot{
		sentPackets:  a.stats.sentPackets.Load(),
		sentBytes:    a.stats.sentBytes.Load(),
		recvPackets:  a.stats.recvPackets.Load(),
		recvBytes:    a.stats.recvBytes.Load(),
		lostPackets:  a.stats.lostPackets.Load(),
		retransmits:  a.stats.retransmits.Load(),
		probes:       a.stats.probes.Load(),
		spuriousLoss: a.stats.spuriousLoss.Load(),
		dropped:      a.stats.droppedDatagrams.Load(),
		queued:       a.queueLength(),
	}
	a.flightMu.Lock()
	snapshot.inFlight = a.inFlight.len()
	snapshot.inFlightSize = a.inFlight.bytes
	a.flightMu.Unlock()
	a.fcMu.Lock()
	snapshot.sendCreditLeft = a.sendCredit.available()
	if a.recvLimit > a.recvReceived {
		snapshot.recvCreditLeft = a.recvLimit - a.recvReceived
	}
	a.fcMu.Unlock()
	a.ccMu.Lock()
	snapshot.cwnd = int64(a.cc.GetCongestionWindow())
	if diagnostics, isDiagnostics := a.cc.(congestion.Diagnostics); isDiagnostics {
		snapshot.state = diagnostics.Describe()
	}
	a.ccMu.Unlock()
	return snapshot
}

func (a *association) statsLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := a.snapshot()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
		}
		current := a.snapshot()
		if current == last {
			continue
		}
		a.logger.Debug(a.logPrefix(),
			"1s tx=", current.sentPackets-last.sentPackets, "pkt/", current.sentBytes-last.sentBytes, "B",
			" rx=", current.recvPackets-last.recvPackets, "pkt/", current.recvBytes-last.recvBytes, "B",
			" lost=", current.lostPackets-last.lostPackets,
			" retx=", current.retransmits-last.retransmits,
			" spurious=", current.spuriousLoss-last.spuriousLoss,
			" drop=", current.dropped-last.dropped,
			" probes=", current.probes-last.probes,
			" inflight=", current.inFlight, "pkt/", current.inFlightSize, "B",
			" queued=", current.queued,
			" sendcredit=", current.sendCreditLeft,
			" recvcredit=", current.recvCreditLeft,
			" ", current.state)
		last = current
	}
}

func (a *association) logPrefix() string {
	return "udpx[" + a.logTag + "]: "
}

func (a *association) logDebug(args ...any) {
	if a.logger != nil {
		a.logger.Debug(append([]any{a.logPrefix()}, args...)...)
	}
}

func (a *association) logInfo(args ...any) {
	if a.logger != nil {
		a.logger.Info(append([]any{a.logPrefix()}, args...)...)
	}
}

func logTagFor(localConnID connectionID) string {
	return hex.EncodeToString(localConnID[:2])
}
