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
// Because a row can only reconstruct a packet that is still inside the window, and rows
// are paid for out of the packets that follow the loss, the window size bounds the burst
// that can be reconstructed at all: about window*cap/(1+cap) packets.
//
// FEC is negotiated between the two QUICX endpoints: the client announces the scheme it
// supports in its authentication request, and the server confirms the scheme both ends
// run on a unidirectional stream. No additional QUIC transport parameter is used, so
// the HTTP/3 / Chrome fingerprint of the connection is unchanged.
type FECOptions struct {
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC may spend, no matter how lossy the path
	// is. Defaults to 10.
	MaxOverheadPercent int
	// MaxGroupSize is the number of packets one sliding window protects. Larger
	// windows tolerate longer bursts, at the price of memory. A burst can only be
	// reconstructed while its packets are inside the window, so the window size bounds
	// the burst the receiver can repair at all: about window*cap/(1+cap) packets.
	// Defaults to the largest window the wire format has, 128.
	MaxGroupSize int
	// MaxParityRows is the number of repair rows an idle sender emits for the tail of
	// its window, so that the packets sent last aren't left with less protection than
	// the ones before them. Defaults to 2.
	MaxParityRows int
}

// fecCapabilityWindow is the FEC capability flag of the sliding window scheme, the only
// scheme this version implements. It is the same flag the window scheme used when the
// fork still implemented the block scheme, so a peer that announces the window scheme
// keeps interoperating. The block scheme flag (0x01) is neither offered nor accepted
// anymore: a block-only peer runs the connection without FEC instead of being sent
// frames it can't decode.
const fecCapabilityWindow = 0x02

func (o *FECOptions) config() quic.FECConfig {
	if o == nil {
		return quic.FECConfig{}
	}
	return quic.FECConfig{
		MaxOverheadPercent: o.MaxOverheadPercent,
		MaxGroupSize:       o.MaxGroupSize,
		MaxParityRows:      o.MaxParityRows,
	}
}

// FEC capability flag, sent by the client at the end of its authentication request.
// Authentication request messages without a capability byte come from clients that
// don't support FEC at all.
func fecCapability(options *FECOptions) []byte {
	if options == nil {
		return nil
	}
	return []byte{fecCapabilityWindow}
}

func parseFECCapability(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0] & fecCapabilityWindow
}

// enableFEC turns on packet level FEC on the client side, once the server confirmed the
// scheme. A second confirmation for a connection that already has FEC enabled is
// ignored: the negotiation happens once per connection, and re-enabling would only
// reset the connection's FEC statistics.
func (c *Client) enableFEC(conn *clientQUICConnection, scheme byte) error {
	if c.fec == nil {
		return nil
	}
	if scheme != fecCapabilityWindow {
		// The server picked a scheme this client didn't offer. Without FEC the
		// connection still works; with a scheme it didn't implement it wouldn't.
		c.logger.Debug("QUICX FEC not enabled (client, ", fecPeer(conn.quicConn), ", peer selected an unsupported scheme)")
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
	err := conn.quicConn.EnableFEC(c.fec.config())
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
	if clientCapability&fecCapabilityWindow == 0 {
		s.logger.Debug("QUICX FEC not enabled (server, ", fecPeer(s.quicConn), ", no scheme in common with the client)")
		return
	}
	go func() {
		select {
		case <-s.quicConn.HandshakeComplete():
		case <-s.ctx.Done():
			return
		}
		if err := s.quicConn.EnableFEC(options.config()); err != nil {
			s.logger.Debug(E.Cause(err, "enable FEC"))
			return
		}
		// The client only enables FEC after it received this confirmation, so it has
		// to be written before FEC is reported as enabled. Otherwise a failed
		// notification would be logged as a success while the client keeps running
		// without FEC - and the server sends parity packets the client ignores.
		if err := s.notifyFECAccept(); err != nil {
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
func (s *serverSession[U]) notifyFECAccept() error {
	stream, err := s.quicConn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open stream")
	}
	_, err = stream.Write([]byte{Version, CommandFECAccept, fecCapabilityWindow})
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
// happened in the window, and whether packets were repaired (a notable window).
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
	dropped := delta(previous.DroppedFrames, current.DroppedFrames)
	if protectedSent == 0 && paritySent == 0 && parityBytes == 0 && parityReceived == 0 &&
		repaired == 0 && failed == 0 && skipped == 0 && dropped == 0 {
		return "", false
	}
	state := "idle"
	if current.WindowSize > 0 {
		state = fmt.Sprintf("window %d pkts", current.WindowSize)
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
	return fmt.Sprintf(
		"QUICX FEC: tx loss %.1f%% (peer reported), %s%s, protected %d pkts (%s), parity %d pkts (%s), skipped %d rows, dropped %d frames; "+
			"rx repaired %d, unrecoverable %d, parity %d pkts, protected %d pkts",
		current.LossRate*100, state, overhead,
		protectedSent, humanBytes(protectedBytes), paritySent, humanBytes(parityBytes), skipped, dropped,
		repaired, failed, parityReceived, protectedReceived,
	), repaired > 0 || failed > 0
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
