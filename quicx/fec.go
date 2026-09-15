package quicx

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

// FECOptions enables packet level forward error correction (FEC) for QUICX.
//
// With FEC enabled, the sender groups outgoing QUIC packets and sends one parity
// packet per group. The receiver reconstructs packets that were lost on the path
// from the parity packet, and acknowledges them like packets that arrived over the
// wire. The congestion controller therefore doesn't see the loss and doesn't reduce
// the send rate, but - unlike Hysteria's "brutal" congestion control - no bandwidth
// is wasted either: the amount of redundancy follows the loss rate measured by the
// peer, and no parity packets are sent at all on a path that doesn't lose packets.
//
// FEC is negotiated between the two QUICX endpoints: the client announces support in
// its authentication request, and the server confirms it on a unidirectional stream.
// No additional QUIC transport parameter is used, so the HTTP/3 / Chrome fingerprint
// of the connection is unchanged.
type FECOptions struct {
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC may spend, no matter how lossy the path
	// is. Defaults to 10.
	MaxOverheadPercent int
	// MaxGroupSize is the maximum number of packets protected by one FEC group.
	// Larger groups reduce the relative overhead, but increase the time until a lost
	// packet can be repaired. Defaults to 16.
	MaxGroupSize int
	// MaxParityRows is the maximum number of parity rows per group. 1 (the default)
	// repairs a single loss per group (XOR parity), 2 repairs two losses per group
	// (Reed-Solomon parity over GF(2^8)).
	MaxParityRows int
}

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

// FEC capability flags, sent by the client at the end of its authentication request.
// Authentication request messages without a capability byte come from clients that
// don't support FEC at all.
const fecCapabilityEnabled = 0x01

func fecCapability(options *FECOptions) []byte {
	if options == nil {
		return nil
	}
	return []byte{fecCapabilityEnabled}
}

func parseFECCapability(data []byte) bool {
	return len(data) > 0 && data[0]&fecCapabilityEnabled != 0
}

// enableFEC turns on packet level FEC on the client side, once both sides agreed.
func (c *Client) enableFEC(conn *clientQUICConnection) error {
	if c.fec == nil {
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
	c.logger.Debug("QUICX FEC enabled (client", fecLimits(c.fec), ")")
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
func (s *serverSession[U]) readFECCapability(buffer *buf.Buffer, stream *quic.ReceiveStream, offset int) bool {
	if s.fec == nil {
		return false
	}
	if buffer.Len() > offset {
		return parseFECCapability(buffer.From(offset))
	}
	var capability [1]byte
	if _, err := io.ReadFull(stream, capability[:]); err != nil {
		return false
	}
	return parseFECCapability(capability[:])
}

// startFEC turns on packet level FEC on the server side and tells the client that
// its FEC capability was accepted.
func (s *serverSession[U]) startFEC() {
	options := s.fec
	if options == nil {
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
		s.logger.Debug("QUICX FEC enabled (server", fecLimits(options), ")")
		go s.loopFECStats()
		stream, err := s.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = stream.Write([]byte{Version, CommandFECAccept})
	}()
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
func formatFECStats(previous, current quic.FECStats) (line string, notable bool) {
	delta := func(prev, cur uint64) uint64 {
		if cur < prev {
			return 0
		}
		return cur - prev
	}
	protectedSent := delta(previous.ProtectedPacketsSent, current.ProtectedPacketsSent)
	paritySent := delta(previous.ParityPacketsSent, current.ParityPacketsSent)
	parityBytes := delta(previous.ParityBytesSent, current.ParityBytesSent)
	parityReceived := delta(previous.ParityPacketsReceived, current.ParityPacketsReceived)
	repaired := delta(previous.RecoveredPackets, current.RecoveredPackets)
	failed := delta(previous.FailedPackets, current.FailedPackets)
	if protectedSent == 0 && paritySent == 0 && parityBytes == 0 && parityReceived == 0 && repaired == 0 && failed == 0 {
		return "", false
	}
	redundancy := "idle"
	if current.GroupSize > 0 {
		redundancy = fmt.Sprintf("group %d (overhead %.1f%%)", current.GroupSize, current.SendOverhead*100)
	}
	return fmt.Sprintf(
		"QUICX FEC: path loss %.1f%%, %s, repaired %d, unrecoverable %d, parity %d sent / %d received, protected %d packets (%s parity data)",
		current.LossRate*100, redundancy, repaired, failed, paritySent, parityReceived, protectedSent, humanBytes(parityBytes),
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
