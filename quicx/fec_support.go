package quicx

import (
	"context"
	"io"
	"time"

	"github.com/sagernet/quic-go"
)

func writeFECCapabilities(ctx context.Context, conn *quic.Conn, capabilities uint8) error {
	stream, err := openUniStream0RTT(ctx, conn)
	if err != nil {
		return err
	}
	_, err = stream.Write([]byte{Version, CommandCapability, capabilities})
	if err != nil {
		stream.CancelWrite(0)
		return err
	}
	return stream.Close()
}

func (s *serverSession[U]) announceFECCapabilities() {
	capabilities := s.fec.config.capabilities()
	if capabilities == 0 {
		return
	}
	_ = writeFECCapabilities(s.ctx, s.quicConn, capabilities)
}

func (c *Client) loopUniStreams(conn *clientQUICConnection) {
	for {
		stream, err := conn.quicConn.AcceptUniStream(c.ctx)
		if err != nil {
			return
		}
		go c.handleUniStream(conn, stream)
	}
}

func (c *Client) handleUniStream(conn *clientQUICConnection, stream *quic.ReceiveStream) {
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	var header [2]byte
	n, _ := stream.Peek(header[:])
	if n < 2 || header[0] != Version {
		return
	}
	switch header[1] {
	case CommandCapability:
		defer stream.CancelRead(0)
		var message [3]byte
		if _, err := io.ReadFull(stream, message[:]); err != nil {
			return
		}
		conn.fec.setPeerCapabilities(message[2])
		capabilities := c.fec.capabilities()
		if capabilities == 0 {
			return
		}
		_ = writeFECCapabilities(conn.ctx, conn.quicConn, capabilities)
	case CommandFECReport:
		defer stream.CancelRead(0)
		var message [6]byte
		if _, err := io.ReadFull(stream, message[:]); err != nil {
			return
		}
		sessionID, lossPerMille, err := decodeFECReport(message[:])
		if err != nil {
			return
		}
		conn.setFECParity(sessionID, lossPerMille)
	}
}
