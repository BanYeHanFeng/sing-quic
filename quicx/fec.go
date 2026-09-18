package quicx

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// FECOptions enables packet level forward error correction (FEC) for QUICX.
//
// With FEC enabled, the sender protects the packets it sends with repair rows, and the
// receiver reconstructs the packets that were lost on the path from them. The
// reconstructed packets are acknowledged like packets that arrived over the wire, so
// the congestion controller doesn't see the loss and doesn't reduce the send rate, but
// - unlike Hysteria's "brutal" congestion control - no bandwidth is wasted either: the
// amount of redundancy follows the loss rate measured by the peer, and no parity
// packets are sent at all on a path that doesn't lose packets. A loss rate that arrives
// in bursts drives the redundancy through the peak of the burst rather than through a
// smoothed estimate, so the rows a burst needs are spent while its packets are still
// inside the window.
//
// The sliding window scheme implements this: one repair row protects the window of the
// most recent packets that carry application data, and successive rows protect
// overlapping windows, so a lost packet is covered by every row emitted while it stays
// in the window. A burst of losses is reconstructed row by row instead of leaving a
// whole group unprotected.
//
// Because a row can only reconstruct a packet that is still inside the window, the window
// bounds how long a lost packet stays repairable. A loss report can trigger a repair burst
// of up to 127 extra rows from the credit accumulated while the path looked cleaner; rows
// that would exceed the configured byte cap are skipped.
//
// FEC is negotiated between the two QUICX endpoints: the client announces the scheme it
// supports in its authentication request, and the server confirms the scheme both ends
// run on a unidirectional stream. No additional QUIC transport parameter is used, so
// the HTTP/3 / Chrome fingerprint of the connection is unchanged.
type FECOptions struct {
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC may spend, no matter how lossy the path
	// is. Defaults to 30: with the 1.5x-loss safety factor, the reactive rate then
	// stays uncapped through about 20% measured random loss.
	MaxOverheadPercent int
	// MaxGroupSize is the number of packets one sliding window protects. Larger
	// windows tolerate longer bursts, at the price of memory. A burst can only be
	// reconstructed while its packets are inside the window, so the window size bounds
	// the time a lost packet stays repairable; a loss report can add a repair burst of up
	// to 127 extra rows from the accumulated credit. Defaults to the largest window the
	// wire format has, 128.
	MaxGroupSize int
	// MaxParityRows is the number of repair rows an idle sender emits for the tail of
	// its window, so that the packets sent last aren't left with less protection than
	// the ones before them. Defaults to 2.
	MaxParityRows int
	// BaselineRedundancyPercent keeps a small fixed redundancy on the wire even while
	// the path looks lossless, so the first burst doesn't have to wait for the peer's
	// feedback (about 0.5*RTT plus the feedback interval). It is bounded by
	// MaxOverheadPercent. The library zero value stays 0 (a purely reactive path);
	// sing-box sets a 5% default for links that occasionally burst to about 8% loss.
	BaselineRedundancyPercent int
	// RecoveredPacketFeedback reports packets this endpoint reconstructed with FEC back
	// to the sender, so that the sender's congestion controller sees the loss without
	// retransmitting the packet (RFC 9265, known-lossy-path exception). It has to be
	// enabled on the receiving side, and the sending side has to understand the frame.
	// The library zero value stays false; sing-box enables it by default.
	RecoveredPacketFeedback bool
	// ExtendedFeedback is the FEC_FEEDBACK_V2 capability bit (0x08). This build always
	// advertises and enables it; the field is kept for API compatibility and test
	// inspection, and there is no fallback to the cumulative v1 feedback frame.
	ExtendedFeedback bool
	// AdaptiveWindow adjusts the working window size to RTT and packet rate without a
	// wire format change. MaxGroupSize remains the maximum; sing-box enables it by
	// default and an explicit false pins the fixed window.
	AdaptiveWindow bool
	// MultiWindow splits one connection into MultiWindowCount independent sub-windows
	// assigned by packet number modulo the count. It is exchanged as capability 0x04;
	// sing-box enables it by default and both ends have to confirm the bit.
	// MultiWindowCount defaults to 2 and is bounded by quic.MaxFECMultiWindowCount.
	MultiWindow      bool
	MultiWindowCount int
	// RepairBurstRowsPerLoss is an internal phase 2 experiment knob: the number of
	// repair rows scheduled per lost packet after a feedback report. Zero keeps the
	// quic-go default (2.0).
	RepairBurstRowsPerLoss float64
}

// fecCapabilityWindow is the FEC capability flag of the sliding window scheme, the only
// scheme this version implements. It is the same flag the window scheme used when the
// fork still implemented the block scheme, so a peer that announces the window scheme
// keeps interoperating. The block scheme flag (0x01) is neither offered nor accepted
// anymore: a block-only peer runs the connection without FEC instead of being sent
// frames it can't decode.
const (
	fecCapabilityWindow = 0x02
	// fecCapabilityMultiWindow is reserved for the phase 2 multi-window scheme. It is
	// advertised only when the local endpoint is explicitly configured for it; the
	// sliding window scheme above remains the fallback.
	fecCapabilityMultiWindow = 0x04
	// fecCapabilityMissingRanges extends FEC_FEEDBACK with the precise missing packet
	// ranges of FEC_FEEDBACK_V2. A peer that only knows fecCapabilityWindow keeps the
	// cumulative-counter feedback, and the connection still runs the window scheme.
	fecCapabilityMissingRanges = 0x08
)

// fecCapabilityImplemented is the set of capability bits this version understands.
// The server only confirms bits from this set, and the client rejects any bit outside
// it so that a misbehaving server can not silently change the protocol it runs.
const fecCapabilityImplemented = fecCapabilityWindow | fecCapabilityMultiWindow | fecCapabilityMissingRanges

func (o *FECOptions) config() quic.FECConfig {
	if o == nil {
		return quic.FECConfig{}
	}
	return quic.FECConfig{
		MaxOverheadPercent:        o.MaxOverheadPercent,
		MaxGroupSize:              o.MaxGroupSize,
		MaxParityRows:             o.MaxParityRows,
		BaselineRedundancyPercent: o.BaselineRedundancyPercent,
		RecoveredPacketFeedback:   o.RecoveredPacketFeedback,
		// Phase 2 is the only protocol this build speaks: FEC_FEEDBACK_V2 and
		// FEC_WINDOW_REPAIR_MULTI are not negotiated down for old peers.
		ExtendedFeedback:       true,
		AdaptiveWindow:         o.AdaptiveWindow,
		MultiWindow:            o.MultiWindow,
		MultiWindowCount:       o.multiWindowCount(),
		RepairBurstRowsPerLoss: o.RepairBurstRowsPerLoss,
	}
}

// multiWindowCount returns the configured sub-window count, defaulting to 2 and
// clamped to the protocol bound when multi-window is enabled.
func (o *FECOptions) multiWindowCount() int {
	if o == nil {
		return 1
	}
	count := o.MultiWindowCount
	if count <= 0 {
		count = 2
	}
	if count > quic.MaxFECMultiWindowCount {
		count = quic.MaxFECMultiWindowCount
	}
	if count < 2 {
		count = 2
	}
	return count
}

// FEC capability flag, sent by the client at the end of its authentication request.
// Authentication request messages without a capability byte come from clients that
// don't support FEC at all.
func fecCapability(options *FECOptions) []byte {
	if options == nil {
		return nil
	}
	capability := byte(fecCapabilityWindow | fecCapabilityMissingRanges)
	if options.MultiWindow {
		capability |= fecCapabilityMultiWindow
	}
	return []byte{capability}
}

func parseFECCapability(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0] & fecCapabilityImplemented
}

// enableFEC turns on packet level FEC on the client side, once the server confirmed the
// scheme. A second confirmation for a connection that already has FEC enabled is
// ignored: the negotiation happens once per connection, and re-enabling would only
// reset the connection's FEC statistics.
func (c *Client) enableFEC(conn *clientQUICConnection, scheme byte) error {
	if c.fec == nil {
		return nil
	}
	if scheme&(fecCapabilityWindow|fecCapabilityMissingRanges) != fecCapabilityWindow|fecCapabilityMissingRanges || scheme&^fecCapabilityImplemented != 0 {
		// This build only speaks the phase 2 capability set. A peer that does not
		// confirm FEC_FEEDBACK_V2 is not supported; FEC stays off instead of falling
		// back to the cumulative v1 feedback frame.
		c.logger.Debug("QUICX FEC not enabled (client, ", fecPeer(conn.quicConn), ", peer did not confirm the phase 2 capability set)")
		return nil
	}
	if conn.quicConn.FECStats().Enabled {
		return nil
	}
	select {
	case <-conn.quicConn.HandshakeComplete():
	case <-c.ctx.Done():
		return context.Cause(c.ctx)
	}
	config := c.fec.config()
	// Pure phase 2: V2 feedback is mandatory, so it is always used. Multi-window is a
	// new-feature negotiation: it runs only when both sides confirmed 0x04.
	config.ExtendedFeedback = true
	config.MultiWindow = scheme&fecCapabilityMultiWindow != 0
	if config.MultiWindow {
		config.MultiWindowCount = c.fec.multiWindowCount()
	}
	err := conn.quicConn.EnableFEC(config)
	if err != nil {
		return err
	}
	// FEC is negotiated per QUIC connection, so this line is written once for every
	// connection the client establishes, not once per client. The peer address is
	// included so that the lines can be attributed to a connection: a client that
	// redials - also from the same UDP source port - produces one line per dial.
	c.logger.Debug("QUICX FEC enabled (client, ", fecPeer(conn.quicConn), ", sliding window scheme", fecLimits(c.fec), ")")
	go c.loopFECStats(conn)
	return nil
}

// fecLimits describes the explicitly configured FEC limits for the negotiation log
// line. Limits that are left at zero use the quic-go defaults, and are omitted.
func fecLimits(options *FECOptions) string {
	if options == nil {
		return ""
	}
	var limits string
	if options.MaxOverheadPercent > 0 {
		limits += fmt.Sprintf(", max overhead %d%%", options.MaxOverheadPercent)
	}
	if options.BaselineRedundancyPercent > 0 {
		limits += fmt.Sprintf(", baseline %d%%", options.BaselineRedundancyPercent)
	}
	limits += ", extended feedback"
	if options.RecoveredPacketFeedback {
		limits += ", recovered feedback"
	}
	if options.AdaptiveWindow {
		limits += ", adaptive window"
	}
	if options.MultiWindow {
		limits += fmt.Sprintf(", multi-window %d", options.multiWindowCount())
	}
	if options.RepairBurstRowsPerLoss > 0 {
		limits += fmt.Sprintf(", repair burst %.1f rows/loss", options.RepairBurstRowsPerLoss)
	}
	if options.MaxGroupSize > 0 {
		limits += fmt.Sprintf(", window %d", options.MaxGroupSize)
	}
	if options.MaxParityRows > 1 {
		limits += fmt.Sprintf(", tail rows %d", options.MaxParityRows)
	}
	return limits
}

// readFECCapability reads the FEC capability byte that FEC capable clients append to
// their authentication request. Clients that don't support FEC don't send it, and
// they close the stream right after the request, so this read can't block.
func (s *serverSession[U]) readFECCapability(buffer *buf.Buffer, stream *quic.ReceiveStream, offset int) byte {
	if s.fec == nil {
		return 0
	}
	if buffer.Len() > offset {
		return parseFECCapability(buffer.From(offset))
	}
	var capability [1]byte
	if _, err := io.ReadFull(stream, capability[:]); err != nil {
		return 0
	}
	return parseFECCapability(capability[:])
}

// startFEC turns on packet level FEC on the server side and tells the client which
// scheme it picked. The sliding window scheme is the only one this version implements,
// so FEC is enabled as soon as the client announced it; a client that doesn't (or that
// only knows the removed block scheme) runs the connection without FEC.
func (s *serverSession[U]) startFEC(clientCapability byte) {
	options := s.fec
	if options == nil {
		return
	}
	// A phase 2 peer must offer both the window scheme and the precise-feedback
	// extension. There is no fallback to the cumulative v1 feedback frame for a peer
	// that only announces 0x02.
	if clientCapability&(fecCapabilityWindow|fecCapabilityMissingRanges) != fecCapabilityWindow|fecCapabilityMissingRanges {
		s.logger.Debug("QUICX FEC not enabled (server, ", fecPeer(s.quicConn), ", peer does not support the phase 2 capability set)")
		return
	}
	// Multi-window is negotiated among phase 2 peers: both sides have to advertise
	// 0x04. The base window and missing-range feedback are mandatory and always
	// confirmed.
	selected := clientCapability & (fecCapabilityWindow | fecCapabilityMissingRanges)
	if options.MultiWindow && clientCapability&fecCapabilityMultiWindow != 0 {
		selected |= fecCapabilityMultiWindow
	}
	go func() {
		select {
		case <-s.quicConn.HandshakeComplete():
		case <-s.ctx.Done():
			return
		}
		config := options.config()
		config.ExtendedFeedback = true
		config.MultiWindow = selected&fecCapabilityMultiWindow != 0
		if config.MultiWindow {
			config.MultiWindowCount = options.multiWindowCount()
		}
		if err := s.quicConn.EnableFEC(config); err != nil {
			s.logger.Debug(E.Cause(err, "enable FEC"))
			return
		}
		// The client only enables FEC after it received this confirmation, so it has
		// to be written before FEC is reported as enabled. Otherwise a failed
		// notification would be logged as a success while the client keeps running
		// without FEC - and the server sends parity packets the client ignores.
		if err := s.notifyFECAccept(selected); err != nil {
			s.logger.Error(E.Cause(err, "notify FEC accept"))
			return
		}
		// FEC is negotiated per QUIC connection, so this line is written once for
		// every connection a client establishes, not once per client. The peer
		// address is included so that the lines can be attributed to a connection: a
		// client that redials - also from the same UDP source port - produces one
		// line per dial.
		s.logger.Debug("QUICX FEC enabled (server, ", fecPeer(s.quicConn), ", sliding window scheme", fecLimits(options), ")")
		go s.loopFECStats()
	}()
}

// notifyFECAccept tells the client that FEC was enabled on the server side, and which
// scheme it runs, by sending CommandFECAccept on a unidirectional stream. The scheme
// byte is the capability flag of the sliding window scheme; clients that read it
// accept the connection only when it is a scheme they offered.
func (s *serverSession[U]) notifyFECAccept(capability byte) error {
	stream, err := s.quicConn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open stream")
	}
	_, err = stream.Write([]byte{Version, CommandFECAccept, capability})
	closeErr := stream.Close()
	if err != nil {
		return E.Cause(err, "write request")
	}
	if closeErr != nil {
		return E.Cause(closeErr, "close stream")
	}
	return nil
}

// fecPeer identifies the peer of the QUIC connection a FEC negotiation log line
// belongs to. The source address is stable across redials, so a line per dial from
// the same address:port is visible as such instead of looking like FEC being enabled
// repeatedly on one connection.
func fecPeer(conn *quic.Conn) string {
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return "unknown"
	}
	return M.SocksaddrFromNet(remoteAddr).Unwrap().String()
}

const (
	// fecStatsInterval is how often a FEC statistics line is written for a connection
	// while FEC is enabled. Windows without any FEC activity are not logged.
	fecStatsInterval = 10 * time.Second
	// fecStatsInfoInterval is the minimum interval between two info level statistics
	// lines. Windows in which packets had to be repaired are logged at info level, so
	// that FEC is visible without enabling debug logging - but at most once a minute
	// per connection, to keep the noise down on lossy servers.
	fecStatsInfoInterval = time.Minute
)

// loopFECStats periodically logs what FEC is doing: the loss rate measured on the
// path, the resulting redundancy, and how many packets were repaired.
func (c *Client) loopFECStats(conn *clientQUICConnection) {
	ticker := time.NewTicker(fecStatsInterval)
	defer ticker.Stop()
	var last quic.FECStats
	var lastInfo time.Time
	for {
		select {
		case <-conn.connDone:
			return
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			stats := conn.quicConn.FECStats()
			if !stats.Enabled {
				return
			}
			line, notable := formatFECStats(last, stats)
			last = stats
			if line == "" {
				continue
			}
			if notable && now.Sub(lastInfo) >= fecStatsInfoInterval {
				c.logger.Info(line)
				lastInfo = now
			} else {
				c.logger.Debug(line)
			}
		}
	}
}

// loopFECStats periodically logs what FEC is doing (server side).
func (s *serverSession[U]) loopFECStats() {
	ticker := time.NewTicker(fecStatsInterval)
	defer ticker.Stop()
	var last quic.FECStats
	var lastInfo time.Time
	for {
		select {
		case <-s.connDone:
			return
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			stats := s.quicConn.FECStats()
			if !stats.Enabled {
				return
			}
			line, notable := formatFECStats(last, stats)
			last = stats
			if line == "" {
				continue
			}
			if notable && now.Sub(lastInfo) >= fecStatsInfoInterval {
				s.logger.Info(line)
				lastInfo = now
			} else {
				s.logger.Debug(line)
			}
		}
	}
}

// formatFECStats formats one statistics window. It returns an empty line if nothing
// happened in the window, and whether the window is notable: packets were repaired,
// packets were given up on, duplicate rows arrived, or protected packets are still
// missing while no repair row arrived (the "sender went idle" signature). RTT
// inflation is reported as context for deciding whether the loss is congestion.
//
// The line reports the two directions separately, because they are measured by
// different endpoints: the loss rate is the one the *peer* observed on the path we
// send on, while repaired and unrecoverable are what our own decoder saw on the path
// we receive on. Mixing them made the line look self contradictory - "path loss 0.0%"
// next to a pile of unrecoverable packets.
func formatFECStats(previous, current quic.FECStats) (line string, notable bool) {
	delta := func(prev, cur uint64) uint64 {
		if cur < prev {
			return 0
		}
		return cur - prev
	}
	protectedSent := delta(previous.ProtectedPacketsSent, current.ProtectedPacketsSent)
	protectedBytes := delta(previous.ProtectedBytesSent, current.ProtectedBytesSent)
	paritySent := delta(previous.ParityPacketsSent, current.ParityPacketsSent)
	parityBytes := delta(previous.ParityBytesSent, current.ParityBytesSent)
	parityReceived := delta(previous.ParityPacketsReceived, current.ParityPacketsReceived)
	protectedReceived := delta(previous.ProtectedPacketsReceived, current.ProtectedPacketsReceived)
	repaired := delta(previous.RecoveredPackets, current.RecoveredPackets)
	failed := delta(previous.FailedPackets, current.FailedPackets)
	skipped := delta(previous.SkippedRows, current.SkippedRows)
	skippedBudget := delta(previous.SkippedRowsBudget, current.SkippedRowsBudget)
	skippedUnbuildable := delta(previous.SkippedRowsUnbuildable, current.SkippedRowsUnbuildable)
	dropped := delta(previous.DroppedFrames, current.DroppedFrames)
	duplicates := delta(previous.DuplicateRows, current.DuplicateRows)
	recoveredReported := delta(previous.RecoveredPacketsReported, current.RecoveredPacketsReported)
	recoveredReceived := delta(previous.RecoveredPacketsReceived, current.RecoveredPacketsReceived)
	repairBursts := delta(previous.RepairBursts, current.RepairBursts)
	repairBurstRows := delta(previous.RepairBurstRowsSent, current.RepairBurstRowsSent)
	repairBurstSkipped := delta(previous.RepairBurstRowsSkipped, current.RepairBurstRowsSkipped)
	repairBurstRowsScheduled := delta(previous.RepairBurstRowsScheduled, current.RepairBurstRowsScheduled)
	repairBurstSkippedBudget := delta(previous.RepairBurstRowsSkippedBudget, current.RepairBurstRowsSkippedBudget)
	repairBurstSkippedNoWindow := delta(previous.RepairBurstRowsSkippedNoWindow, current.RepairBurstRowsSkippedNoWindow)
	missingRanges := delta(previous.MissingRangesReceived, current.MissingRangesReceived)
	missingInWindow := delta(previous.MissingPacketsInWindow, current.MissingPacketsInWindow)
	missingRepairable := delta(previous.MissingPacketsRepairable, current.MissingPacketsRepairable)
	missingChanged := current.MissingPackets != previous.MissingPackets
	if protectedSent == 0 && paritySent == 0 && parityBytes == 0 && parityReceived == 0 &&
		repaired == 0 && failed == 0 && skipped == 0 && dropped == 0 && !missingChanged &&
		duplicates == 0 && recoveredReported == 0 && recoveredReceived == 0 &&
		repairBursts == 0 && repairBurstRows == 0 && repairBurstSkipped == 0 &&
		repairBurstRowsScheduled == 0 && repairBurstSkippedBudget == 0 && repairBurstSkippedNoWindow == 0 &&
		missingRanges == 0 && missingInWindow == 0 && missingRepairable == 0 {
		return "", false
	}
	state := "idle"
	if current.WindowSize > 0 {
		state = fmt.Sprintf("window %d pkts", current.WindowSize)
		if current.AdaptiveWindow && current.WindowMaxSize > 0 {
			// The working window, not the configured protocol maximum, is what the
			// line reports while the window follows the path. Printing both makes it
			// possible to see when the adaptive controller has room left to grow.
			state = fmt.Sprintf("window %d/%d pkts (rtt-adaptive)", current.WindowSize, current.WindowMaxSize)
		}
		if current.WindowCount > 1 {
			// Each sub-window keeps the configured window, so the effective window is
			// the product. Printing both keeps the phase 2 multi-window field visible.
			state += fmt.Sprintf(", %d sub-windows (effective %d pkts)", current.WindowCount, current.EffectiveWindowSize)
		}
	}
	// The measured value is the one the cap applies to. It has to be printed even when
	// FEC is idle at the moment of the tick: parity can have been sent earlier in the
	// window while the loss rate was still above the threshold, and printing only the
	// configured value was what hid partial rows costing several times the cap.
	overhead := ""
	if current.RedundancyRate > 0 {
		// The window scheme has no group to compute a ratio from: it targets a
		// redundancy rate, and the measured overhead is what the cap bounds.
		overhead = fmt.Sprintf(", rate %.1f%%", current.RedundancyRate*100)
	}
	if protectedBytes > 0 {
		overhead += fmt.Sprintf(" / %.1f%% measured", float64(parityBytes)/float64(protectedBytes)*100)
	}
	// Split the skipped rows into the two causes the sender now counts separately: a
	// growing budget part means the overhead cap - not the loss estimate - is what
	// limits FEC, while "too large" rows are the datagram/window limit.
	skippedPart := fmt.Sprintf("skipped %d rows", skipped)
	if skippedBudget > 0 || skippedUnbuildable > 0 {
		skippedPart += fmt.Sprintf(" (%d budget, %d too large)", skippedBudget, skippedUnbuildable)
	}
	// Repair bursts are the loss-triggered rows that are sent out of the accumulated
	// byte credit. They are reported separately from the steady-state parity because
	// they are the direct answer to "the loss is already reported; are there enough
	// rows to repair it before the window expires".
	burstPart := ""
	if repairBursts > 0 || repairBurstRows > 0 || repairBurstSkipped > 0 || repairBurstRowsScheduled > 0 {
		if repairBurstRowsScheduled > repairBurstRows {
			burstPart = fmt.Sprintf(", burst %d/%d rows", repairBurstRows, repairBurstRowsScheduled)
		} else {
			burstPart = fmt.Sprintf(", burst %d rows", repairBurstRows)
		}
		if repairBurstSkipped > 0 {
			burstPart += fmt.Sprintf(" (%d skipped", repairBurstSkipped)
			if repairBurstSkippedBudget > 0 || repairBurstSkippedNoWindow > 0 {
				burstPart += fmt.Sprintf(": %d budget, %d no-window", repairBurstSkippedBudget, repairBurstSkippedNoWindow)
			}
			burstPart += ")"
		}
	}
	// P4 observation fields: the packet rate, the highest peer loss peak and the
	// feedback latency are printed when they are set, without changing the meaning of
	// the decision fields above.
	observationPart := ""
	if current.ProtectedPacketRate > 0 {
		observationPart += fmt.Sprintf(", %.0f pps protected", current.ProtectedPacketRate)
	}
	if current.PeerLossPeak > 0 {
		observationPart += fmt.Sprintf(", peer loss peak %.1f%%", current.PeerLossPeak*100)
	}
	if current.FeedbackLatency > 0 {
		observationPart += fmt.Sprintf(", feedback latency %s", current.FeedbackLatency.Round(100*time.Microsecond))
	}
	// RTT inflation is the queueing delay the connection sees. While FEC is recovering
	// packets, a value that grows with the redundancy is evidence of congestion rather
	// than an intrinsically lossy path, and the operator should reduce redundancy.
	rttPart := ""
	if current.SmoothedRTT > 0 {
		rttPart = fmt.Sprintf(", rtt %s", current.SmoothedRTT.Round(100*time.Microsecond))
		if current.RTTInflation > 0 {
			rttPart += fmt.Sprintf(" (+%s vs min)", current.RTTInflation.Round(100*time.Microsecond))
		}
	}
	// recoveredReceived is the peer telling us that packets we sent were reconstructed:
	// they were acknowledged, so nothing is retransmitted, but the loss is fed to our
	// congestion controller.
	recoveredPart := ""
	if recoveredReceived > 0 {
		recoveredPart = fmt.Sprintf(", recovered losses %d", recoveredReceived)
	}
	rxPart := fmt.Sprintf("rx repaired %d, unrecoverable %d, parity %d pkts, protected %d pkts",
		repaired, failed, parityReceived, protectedReceived)
	// MissingPackets is a gauge: protected packets the peer announced that this side has
	// neither received nor reconstructed. Non-zero while parity stopped arriving is the
	// "sender went idle while the receiver still has gaps" signature.
	if current.MissingPackets > 0 {
		rxPart += fmt.Sprintf(", still missing %d pkts", current.MissingPackets)
	}
	if duplicates > 0 {
		rxPart += fmt.Sprintf(", duplicate %d rows", duplicates)
	}
	if recoveredReported > 0 {
		rxPart += fmt.Sprintf(", recovered reported %d", recoveredReported)
	}
	if missingRanges > 0 {
		rxPart += fmt.Sprintf(", missing-ranges %d (%d in window, %d repairable)", missingRanges, missingInWindow, missingRepairable)
	}
	// Missing packets with no repair row arriving in the window are notable even
	// without a repair or failure counter: that is the case the field logs missed.
	notable = repaired > 0 || failed > 0 || duplicates > 0 ||
		(current.MissingPackets > 0 && parityReceived == 0) ||
		recoveredReported > 0 || recoveredReceived > 0 ||
		repairBurstRows > 0 || repairBurstSkipped > 0 || repairBurstRowsScheduled > 0 ||
		repairBurstSkippedBudget > 0 || repairBurstSkippedNoWindow > 0 || missingRanges > 0
	return fmt.Sprintf(
		"QUICX FEC: tx loss %.1f%% (peer reported), %s%s, protected %d pkts (%s), parity %d pkts (%s), %s, dropped %d frames%s%s%s%s; %s",
		current.LossRate*100, state, overhead,
		protectedSent, humanBytes(protectedBytes), paritySent, humanBytes(parityBytes),
		skippedPart, dropped, recoveredPart, rttPart, burstPart, observationPart, rxPart,
	), notable
}

func humanBytes(bytes uint64) string {
	switch {
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
