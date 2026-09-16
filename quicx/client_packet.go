package quicx

import (
	"io"

	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
)

// loopUniStreams handles the unidirectional streams the server opens. QUICX only
// uses them to confirm the FEC capability of the client.
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
	defer stream.CancelRead(0)
	// The scheme the server confirmed follows the command. A server that doesn't send
	// it only implements the removed block scheme, which this client didn't offer.
	var header [3]byte
	_, err := io.ReadFull(stream, header[:])
	if err != nil {
		return
	}
	if header[0] != Version || header[1] != CommandFECAccept {
		// Ignore anything else (e.g. HTTP/3 control streams of a standard server).
		return
	}
	if header[2] != fecCapabilityWindow {
		c.logger.Debug("QUICX FEC not enabled (client, ", fecPeer(conn.quicConn), ", peer confirmed an unsupported scheme)")
		return
	}
	if err = c.enableFEC(conn, header[2]); err != nil {
		conn.closeWithError(E.Cause(err, "enable FEC"))
	}
}

func (c *Client) loopMessages(conn *clientQUICConnection) {
	for {
		message, err := conn.quicConn.ReceiveDatagram(c.ctx)
		if err != nil {
			conn.closeWithError(E.Cause(err, "receive message"))
			return
		}
		go func() {
			hErr := c.handleMessage(conn, message)
			if hErr != nil {
				conn.closeWithError(E.Cause(hErr, "handle message"))
			}
		}()
	}
}

func (c *Client) handleMessage(conn *clientQUICConnection, data []byte) error {
	if len(data) < 2 {
		return E.New("invalid message")
	}
	if data[0] != Version {
		return E.New("unknown version ", data[0])
	}
	switch data[1] {
	case CommandPacket:
		message := allocMessage()
		err := decodeUDPMessage(message, data[2:])
		if err != nil {
			message.releaseMessage()
			return E.Cause(err, "decode UDP message")
		}
		conn.handleUDPMessage(message)
		return nil
	case CommandHeartbeat:
		return nil
	default:
		return E.New("unknown command ", data[1])
	}
}

func (c *clientQUICConnection) handleUDPMessage(message *udpMessage) {
	c.udpAccess.RLock()
	udpConn, loaded := c.udpConnMap[message.sessionID]
	c.udpAccess.RUnlock()
	if !loaded {
		message.releaseMessage()
		return
	}
	select {
	case <-udpConn.ctx.Done():
		message.releaseMessage()
		return
	default:
	}
	udpConn.inputPacket(message)
}
