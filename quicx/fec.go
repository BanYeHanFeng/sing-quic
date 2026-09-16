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
// With FEC enabled, the sender protects the packets it sends with parity packets, and
// the receiver reconstructs the packets that were lost on the path from them. The
// reconstructed packets are acknowledged like packets that arrived over the wire, so
// the congestion controller doesn't see the loss and doesn't reduce the send rate, but
// - unlike Hysteria's "brutal" congestion control - no bandwidth is wasted either: the
// amount of redundancy follows the loss rate measured by the peer, and no parity
// packets are sent at all on a path that doesn't lose packets.
//
// Two schemes implement this. The block scheme protects a closed group of packets with
// a fixed number of parity rows; the sliding window scheme protects the last packets
// with continuously generated repair rows, which recovers bursts and low rate flows
// that the block scheme has to leave to retransmissions.
//
// FEC is negotiated between the two QUICX endpoints: the client announces the schemes
// it supports in its authentication request, and the server confirms the scheme both
// ends run on a unidirectional stream. No additional QUIC transport parameter is used,
// so the HTTP/3 / Chrome fingerprint of the connection is unchanged.
type FECOptions struct {
	// Scheme selects the packet level FEC scheme, or "auto" to offer every scheme this
	// build supports. The client announces what it supports, the server picks the best
	// scheme both endpoints implement and tells the client which one it picked, so the
	// two ends always run the same code. Defaults to "auto".
	Scheme string
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC may spend, no matter how lossy the path
	// is. Defaults to 10.
	MaxOverheadPercent int
	// MaxGroupSize is the maximum number of packets protected by one FEC group (block
	// scheme), or the number of packets one sliding window protects (window scheme).
	// Larger values reduce the relative overhead, but increase the time until a lost
	// packet can be repaired. Defaults to 32 (block) / 64 (window).
	MaxGroupSize int
	// MaxParityRows is the maximum number of parity rows per group (block scheme), or
	// the number of repair rows an idle window sender emits for the tail of its window
	// (window scheme). Defaults to 2.
	MaxParityRows int
}

// FEC scheme identifiers. They are used both as capability flags in the authentication
// request and as the value the server echoes to select the scheme, so a peer that
// understands a flag understands the scheme it names.
const (
	fecCapabilityEnabled = 0x01 // the group based block scheme
	fecCapabilityWindow  = 0x02 // the sliding window scheme
	fecCapabilityAll     = fecCapabilityEnabled | fecCapabilityWindow
)

// capability is the capability mask this endpoint advertises: every scheme the
// configuration allows it to run.
func (o *FECOptions) capability() byte {
	switch o.Scheme {
	case "block":
		return fecCapabilityEnabled
	case "window":
		return fecCapabilityWindow
	default:
		return fecCapabilityAll
	}
}

func (o *FECOptions) config(scheme byte) quic.FECConfig {
	if o == nil {
		return quic.FECConfig{}
	}
	config := quic.FECConfig{
		MaxOverheadPercent: o.MaxOverheadPercent,
		MaxGroupSize:       o.MaxGroupSize,
		MaxParityRows:      o.MaxParityRows,
	}
	if scheme == fecCapabilityWindow {
		config.Scheme = quic.FECSchemeWindow
	}
	return config
}

func fecSchemeName(scheme byte) string {
	switch scheme {
	case fecCapabilityWindow:
		return "sliding window scheme"
	case fecCapabilityEnabled:
		return "block scheme"
	default:
		return "no scheme"
	}
}

// FEC capability flags, sent by the client at the end of its authentication request.
// Authentication request messages without a capability byte come from clients that
// don't support FEC at all.
func fecCapability(options *FECOptions) []byte {
	if options == nil {
		return nil
	}
	return []byte{options.capability()}
}

func parseFECCapability(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0] & fecCapabilityAll
}

// enableFEC turns on packet level FEC on the client side, once both sides agreed on a
// scheme. A second confirmation for a connection that already has FEC enabled is
// ignored: the negotiation happens once per connection, and re-enabling would only
// reset the connection's FEC statistics.
func (c *Client) enableFEC(conn *clientQUICConnection, scheme byte) error {
	if c.fec == nil {
		return nil
	}
	if scheme != fecCapabilityEnabled && scheme != fecCapabilityWindow {
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
	err := conn.quicConn.EnableFEC(c.fec.config(scheme))
	if err != nil {
		return err
	}
	// FEC is negotiated per QUIC connection, so this line is written once for every
	// connection the client establishes, not once per client. The peer address is
	// included so that the lines can be attributed to a connection: a client that
	// redials - also from the same UDP source port - produces one line per dial.
	c.logger.Debug("QUICX FEC enabled (client, ", fecPeer(conn.quicConn), ", ", fecSchemeName(scheme), fecLimits(c.fec, scheme), ")")
	go c.loopFECStats(conn)
	return nil
}

// fecLimits describes the explicitly configured FEC limits for the negotiation log
// line. Limits that are left at zero use the quic-go defaults, and are omitted.
func fecLimits(options *FECOptions, scheme byte) string {
	if options == nil {
		return ""
	}
	var limits string
	if options.MaxOverheadPercent > 0 {
		limits += fmt.Sprintf(", max overhead %d%%", options.MaxOverheadPercent)
	}
	if scheme == fecCapabilityWindow {
		if options.MaxGroupSize > 0 {
			limits += fmt.Sprintf(", window %d", options.MaxGroupSize)
		}
		return limits
	}
	if options.MaxGroupSize > 0 {
		limits += fmt.Sprintf(", max group %d", options.MaxGroupSize)
	}
	if options.MaxParityRows > 1 {
		limits += fmt.Sprintf(", parity rows %d", options.MaxParityRows)
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

// fecScheme selects the scheme both endpoints run: the best scheme the client
// announced that this server also supports, or 0 when they have none in common.
func fecScheme(clientCapability, serverCapability byte) byte {
	common := clientCapability & serverCapability
	switch {
	case common&fecCapabilityWindow != 0:
		return fecCapabilityWindow
	case common&fecCapabilityEnabled != 0:
		return fecCapabilityEnabled
	default:
		return 0
	}
}

// startFEC turns on packet level FEC on the server side and tells the client which
// scheme it picked. The scheme is the best one both endpoints announced, so the two
// ends always run the same code; when they have no scheme in common, FEC stays off on
// both sides.
func (s *serverSession[U]) startFEC(clientCapability byte) {
	options := s.fec
	if options == nil {
		return
	}
	scheme := fecScheme(clientCapability, options.capability())
	if scheme == 0 {
		s.logger.Debug("QUICX FEC not enabled (server, ", fecPeer(s.quicConn), ", no scheme in common with the client)")
		return
	}
	go func() {
		select {
		case <-s.quicConn.HandshakeComplete():
		case <-s.ctx.Done():
			return
		}
		if err := s.quicConn.EnableFEC(options.config(scheme)); err != nil {
			s.logger.Debug(E.Cause(err, "enable FEC"))
			return
		}
		// The client only enables FEC after it received this confirmation, so it has
		// to be written before FEC is reported as enabled. Otherwise a failed
		// notification would be logged as a success while the client keeps running
		// without FEC - and the server sends parity packets the client ignores.
		if err := s.notifyFECAccept(scheme); err != nil {
			s.logger.Error(E.Cause(err, "notify FEC accept"))
			return
		}
		// FEC is negotiated per QUIC connection, so this line is written once for
		// every connection a client establishes, not once per client. The peer
		// address is included so that the lines can be attributed to a connection: a
		// client that redials - also from the same UDP source port - produces one
		// line per dial.
		s.logger.Debug("QUICX FEC enabled (server, ", fecPeer(s.quicConn), ", ", fecSchemeName(scheme), fecLimits(options, scheme), ")")
		go s.loopFECStats()
	}()
}

// notifyFECAccept tells the client that FEC was enabled on the server side, and which
// scheme it runs, by sending CommandFECAccept on a unidirectional stream. Clients of
// the first FEC version read the command and ignore the scheme byte, which selects the
// only scheme they implement.
func (s *serverSession[U]) notifyFECAccept(scheme byte) error {
	stream, err := s.quicConn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open stream")
	}
	_, err = stream.Write([]byte{Version, CommandFECAccept, scheme})
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
	skipped := delta(previous.SkippedGroups, current.SkippedGroups)
	dropped := delta(previous.DroppedFrames, current.DroppedFrames)
	if protectedSent == 0 && paritySent == 0 && parityBytes == 0 && parityReceived == 0 &&
		repaired == 0 && failed == 0 && skipped == 0 && dropped == 0 {
		return "", false
	}
	state := "idle"
	if current.Scheme == quic.FECSchemeWindow {
		if current.GroupSize > 0 {
			state = fmt.Sprintf("window %d pkts", current.GroupSize)
		}
	} else if current.GroupSize > 0 {
		state = fmt.Sprintf("group %d rows %d", current.GroupSize, current.ParityRows)
	}
	// The measured value is the one the cap applies to. It has to be printed even when
	// FEC is idle at the moment of the tick: parity can have been sent earlier in the
	// window while the group was still open, and printing only the configured value was
	// what hid partial groups costing several times the cap.
	overhead := ""
	if current.ConfiguredOverhead > 0 {
		if current.Scheme == quic.FECSchemeWindow {
			// The window scheme has no group to compute a ratio from: it targets a
			// redundancy rate, and the measured overhead is what the cap bounds.
			overhead = fmt.Sprintf(", rate %.1f%%", current.ConfiguredOverhead*100)
		} else {
			overhead = fmt.Sprintf(", overhead %.1f%% configured", current.ConfiguredOverhead*100)
		}
	}
	if protectedBytes > 0 {
		overhead += fmt.Sprintf(" / %.1f%% measured", float64(parityBytes)/float64(protectedBytes)*100)
	}
	skippedUnit := "groups"
	if current.Scheme == quic.FECSchemeWindow {
		skippedUnit = "rows"
	}
	return fmt.Sprintf(
		"QUICX FEC: tx loss %.1f%% (peer reported), %s%s, protected %d pkts (%s), parity %d pkts (%s), skipped %d %s, dropped %d frames; "+
			"rx repaired %d, unrecoverable %d, parity %d pkts, protected %d pkts",
		current.LossRate*100, state, overhead,
		protectedSent, humanBytes(protectedBytes), paritySent, humanBytes(parityBytes), skipped, skippedUnit, dropped,
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
