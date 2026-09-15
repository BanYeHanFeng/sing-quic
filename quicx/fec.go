package quicx

import (
	"context"
	"io"

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
	c.logger.Debug("QUICX FEC enabled (client, max overhead ", c.fec.MaxOverheadPercent, "%, max group ", c.fec.MaxGroupSize, ")")
	return nil
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
		s.logger.Debug("QUICX FEC enabled (server, max overhead ", options.MaxOverheadPercent, "%, max group ", options.MaxGroupSize, ")")
		stream, err := s.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = stream.Write([]byte{Version, CommandFECAccept})
	}()
}
