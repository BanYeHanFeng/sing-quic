package quicx

import (
	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
)

// loopMessages dispatches the datagrams received on the session.
//
// The message is handled inline instead of on a fresh goroutine: the handler
// only decodes the message and hands it to the session's packet connection,
// which never blocks (a full receive buffer drops the packet), so the goroutine
// bought no concurrency. It did cost a closure allocation, a goroutine start and
// a stack growth per datagram, which showed up as several percent of the client
// CPU at forwarding rates. The service side has always handled messages inline.
func (c *Client) loopMessages(conn *clientQUICConnection) {
	for {
		message, owner, err := conn.quicConn.ReceiveDatagramOwned(c.ctx)
		if err != nil {
			conn.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := c.handleMessage(conn, message, owner)
		if hErr != nil {
			conn.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (c *Client) handleMessage(conn *clientQUICConnection, data []byte, owner quic.DatagramBufferOwner) error {
	if len(data) < 2 {
		releaseDatagramOwner(owner)
		return E.New("invalid message")
	}
	if data[0] != Version {
		releaseDatagramOwner(owner)
		return E.New("unknown version ", data[0])
	}
	switch data[1] {
	case CommandPacket:
		message := allocMessage()
		err := decodeUDPMessage(message, data[2:], owner)
		if err != nil {
			message.releaseMessage()
			return E.Cause(err, "decode UDP message")
		}
		return conn.handleUDPMessage(message)
	case CommandHeartbeat:
		releaseDatagramOwner(owner)
		return nil
	default:
		releaseDatagramOwner(owner)
		return E.New("unknown command ", data[1])
	}
}

func (c *clientQUICConnection) handleUDPMessage(message *udpMessage) error {
	c.udpAccess.RLock()
	udpConn, loaded := c.udpConnMap[message.sessionID]
	c.udpAccess.RUnlock()
	if !loaded {
		message.releaseMessage()
		return nil
	}
	select {
	case <-udpConn.ctx.Done():
		message.releaseMessage()
		return nil
	default:
	}
	return udpConn.inputPacket(message)
}
