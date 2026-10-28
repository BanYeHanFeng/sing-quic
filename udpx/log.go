package udpx

// Logging
//
// What the transport says about itself, and nothing more: a line per event worth
// following and one line per second of numbers. The events are at trace level
// because a packet is one, and the numbers are at debug because they are what a
// report of "it is slow" is diagnosed with: the window, the rate, the round trip,
// what was lost and what the redundancy repaired.
//
// There is no level switch here. A logger filters, and one that was handed to the
// transport because its own level asked for debug is a transport that should say
// what it knows. A nil logger means nobody asked, and costs nothing.

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/congestion"
)

// associationStats counts what the association did, so that a line of them can be
// printed without walking the tables. Every field is written by the goroutine that
// does the work and read by the stats line, so they are atomics rather than a
// mutex: a counter is not worth a lock on the send path.
type associationStats struct {
	sentPackets  atomic.Int64
	sentBytes    atomic.Int64
	recvPackets  atomic.Int64
	recvBytes    atomic.Int64
	lostPackets  atomic.Int64
	retransmits  atomic.Int64
	recovered    atomic.Int64
	probes       atomic.Int64
	spuriousLoss atomic.Int64
}

// statsSnapshot is one reading of the counters and the state they belong to.
type statsSnapshot struct {
	sentPackets  int64
	sentBytes    int64
	recvPackets  int64
	recvBytes    int64
	lostPackets  int64
	retransmits  int64
	recovered    int64
	probes       int64
	spuriousLoss int64
	cwnd         int64
	inFlight     int
	queued       int
	state        string
}

func (a *association) snapshot() statsSnapshot {
	snapshot := statsSnapshot{
		sentPackets:  a.stats.sentPackets.Load(),
		sentBytes:    a.stats.sentBytes.Load(),
		recvPackets:  a.stats.recvPackets.Load(),
		recvBytes:    a.stats.recvBytes.Load(),
		lostPackets:  a.stats.lostPackets.Load(),
		retransmits:  a.stats.retransmits.Load(),
		recovered:    a.stats.recovered.Load(),
		probes:       a.stats.probes.Load(),
		spuriousLoss: a.stats.spuriousLoss.Load(),
		queued:       a.queueLength(),
	}
	a.flightMu.Lock()
	snapshot.inFlight = a.inFlight.len()
	a.flightMu.Unlock()
	a.ccMu.Lock()
	snapshot.cwnd = int64(a.cc.GetCongestionWindow())
	if diagnostics, isDiagnostics := a.cc.(congestion.Diagnostics); isDiagnostics {
		snapshot.state = diagnostics.Describe()
	}
	a.ccMu.Unlock()
	return snapshot
}

// statsLoop prints what changed over the last second. It runs only when a logger
// was given, which is what keeps a transport nobody is watching from spending a
// timer on it.
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
		a.logger.Debug("udpx: 1s",
			" tx=", current.sentPackets-last.sentPackets, "pkt/", current.sentBytes-last.sentBytes, "B",
			" rx=", current.recvPackets-last.recvPackets, "pkt/", current.recvBytes-last.recvBytes, "B",
			" lost=", current.lostPackets-last.lostPackets,
			" retx=", current.retransmits-last.retransmits,
			" spurious=", current.spuriousLoss-last.spuriousLoss,
			" fec=", current.recovered-last.recovered,
			" probes=", current.probes-last.probes,
			" inflight=", current.inFlight,
			" queued=", current.queued,
			" ", current.state)
		last = current
	}
}

// logTrace prints a line at trace level when a logger was given.
func (a *association) logTrace(args ...any) {
	if a.logger != nil {
		a.logger.Trace(append([]any{"udpx: "}, args...)...)
	}
}

// logDebug prints a line at debug level when a logger was given.
func (a *association) logDebug(args ...any) {
	if a.logger != nil {
		a.logger.Debug(append([]any{"udpx: "}, args...)...)
	}
}

// logInfo prints a line at info level when a logger was given.
func (a *association) logInfo(args ...any) {
	if a.logger != nil {
		a.logger.Info(append([]any{"udpx: "}, args...)...)
	}
}

// describeState is the controller's own description, or empty when it has none.
func (a *association) describeState() string {
	a.ccMu.Lock()
	defer a.ccMu.Unlock()
	if diagnostics, isDiagnostics := a.cc.(congestion.Diagnostics); isDiagnostics {
		return diagnostics.Describe()
	}
	return ""
}

// duration is a round trip in a shape a log line reads well.
func duration(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
}
