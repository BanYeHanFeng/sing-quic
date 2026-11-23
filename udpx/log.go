package udpx

import (
	"encoding/hex"
	"sync/atomic"
	"time"
)

type associationStats struct {
	sentPackets      atomic.Int64
	sentBytes        atomic.Int64
	recvPackets      atomic.Int64
	recvBytes        atomic.Int64
	lostPackets      atomic.Int64
	retransmits      atomic.Int64
	probes           atomic.Int64
	droppedDatagrams atomic.Int64
}

type statsSnapshot struct {
	txPackets    int64
	txBytes      int64
	rxPackets    int64
	rxBytes      int64
	lostPackets  int64
	retransmits  int64
	probes       int64
	dropped      int64
	inFlight     int
	inFlightSize int
	queued       int
	cwnd         int64
}

func (a *association) logStats(snapshot *statsSnapshot) {
	a.logger.Debug(a.logPrefix(),
		"1s tx=", snapshot.txPackets, "pkt/", snapshot.txBytes, "B",
		" rx=", snapshot.rxPackets, "pkt/", snapshot.rxBytes, "B",
		" lost=", snapshot.lostPackets,
		" retx=", snapshot.retransmits,
		" drop=", snapshot.dropped,
		" probes=", snapshot.probes,
		" inflight=", snapshot.inFlight, "pkt/", snapshot.inFlightSize, "B",
		" queued=", snapshot.queued,
		" cwnd=", snapshot.cwnd)
}

func (a *association) logPrefix() string {
	return "udpx[" + a.logTag + "]: "
}

func (a *association) logInfo(args ...any) {
	a.logger.Info(append([]any{a.logPrefix()}, args...)...)
}

func logTagFor(localConnID connectionID) string {
	return hex.EncodeToString(localConnID[:2])
}

func (t *txState) snapshotIfDue(now time.Time) *statsSnapshot {
	if now.Before(t.statsAt) {
		return nil
	}
	t.statsAt = now.Add(time.Second)
	current := statsSnapshot{
		txPackets:    t.association.stats.sentPackets.Load(),
		txBytes:      t.association.stats.sentBytes.Load(),
		rxPackets:    t.association.stats.recvPackets.Load(),
		rxBytes:      t.association.stats.recvBytes.Load(),
		lostPackets:  t.association.stats.lostPackets.Load(),
		retransmits:  t.association.stats.retransmits.Load(),
		probes:       t.association.stats.probes.Load(),
		dropped:      t.association.stats.droppedDatagrams.Load(),
		inFlight:     t.inFlight.len(),
		inFlightSize: int(t.inFlight.bytes),
		queued:       len(t.queue),
		cwnd:         int64(t.cc.GetCongestionWindow()),
	}
	last := t.statsLast
	t.statsLast = current
	if current == last {
		return nil
	}
	delta := statsSnapshot{
		txPackets:    current.txPackets - last.txPackets,
		txBytes:      current.txBytes - last.txBytes,
		rxPackets:    current.rxPackets - last.rxPackets,
		rxBytes:      current.rxBytes - last.rxBytes,
		lostPackets:  current.lostPackets - last.lostPackets,
		retransmits:  current.retransmits - last.retransmits,
		probes:       current.probes - last.probes,
		dropped:      current.dropped - last.dropped,
		inFlight:     current.inFlight,
		inFlightSize: current.inFlightSize,
		queued:       current.queued,
		cwnd:         current.cwnd,
	}
	return &delta
}

func (t *txState) snapshot() *statsSnapshot {
	current := statsSnapshot{
		txPackets:    t.association.stats.sentPackets.Load(),
		txBytes:      t.association.stats.sentBytes.Load(),
		rxPackets:    t.association.stats.recvPackets.Load(),
		rxBytes:      t.association.stats.recvBytes.Load(),
		lostPackets:  t.association.stats.lostPackets.Load(),
		retransmits:  t.association.stats.retransmits.Load(),
		probes:       t.association.stats.probes.Load(),
		dropped:      t.association.stats.droppedDatagrams.Load(),
		inFlight:     t.inFlight.len(),
		inFlightSize: int(t.inFlight.bytes),
		queued:       len(t.queue),
		cwnd:         int64(t.cc.GetCongestionWindow()),
	}
	return &current
}
