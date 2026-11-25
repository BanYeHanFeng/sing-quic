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

func (c *Conn) logStats(snapshot *statsSnapshot) {
	c.logger.Debug(c.logPrefix(),
		"1s send=", snapshot.txPackets, "pkt/", snapshot.txBytes, "B",
		" rx=", snapshot.rxPackets, "pkt/", snapshot.rxBytes, "B",
		" lost=", snapshot.lostPackets,
		" retx=", snapshot.retransmits,
		" drop=", snapshot.dropped,
		" probes=", snapshot.probes,
		" inflight=", snapshot.inFlight, "pkt/", snapshot.inFlightSize, "B",
		" queued=", snapshot.queued,
		" cwnd=", snapshot.cwnd)
}

func (c *Conn) logPrefix() string {
	return "udpx[" + c.logTag + "]: "
}

func (c *Conn) logInfo(args ...any) {
	c.logger.Info(append([]any{c.logPrefix()}, args...)...)
}

func logTagFor(localID connectionID) string {
	return hex.EncodeToString(localID[:2])
}

func (t *sender) snapshotIfDue(now time.Time) *statsSnapshot {
	if now.Before(t.statsAt) {
		return nil
	}
	t.statsAt = now.Add(time.Second)
	current := statsSnapshot{
		txPackets:    t.conn.stats.sentPackets.Load(),
		txBytes:      t.conn.stats.sentBytes.Load(),
		rxPackets:    t.conn.stats.recvPackets.Load(),
		rxBytes:      t.conn.stats.recvBytes.Load(),
		lostPackets:  t.conn.stats.lostPackets.Load(),
		retransmits:  t.conn.stats.retransmits.Load(),
		probes:       t.conn.stats.probes.Load(),
		dropped:      t.conn.stats.droppedDatagrams.Load(),
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

func (t *sender) snapshot() *statsSnapshot {
	current := statsSnapshot{
		txPackets:    t.conn.stats.sentPackets.Load(),
		txBytes:      t.conn.stats.sentBytes.Load(),
		rxPackets:    t.conn.stats.recvPackets.Load(),
		rxBytes:      t.conn.stats.recvBytes.Load(),
		lostPackets:  t.conn.stats.lostPackets.Load(),
		retransmits:  t.conn.stats.retransmits.Load(),
		probes:       t.conn.stats.probes.Load(),
		dropped:      t.conn.stats.droppedDatagrams.Load(),
		inFlight:     t.inFlight.len(),
		inFlightSize: int(t.inFlight.bytes),
		queued:       len(t.queue),
		cwnd:         int64(t.cc.GetCongestionWindow()),
	}
	return &current
}
