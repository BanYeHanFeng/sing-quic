package quicx

import (
	"github.com/sagernet/sing-quic/udpx"
	E "github.com/sagernet/sing/common/exceptions"
)

// loopMessages dispatches the datagrams received on the session.
//
// The message is handled inline instead of on a fresh goroutine: the handler only
// decodes the message and hands it to the session's packet connection, which never
// blocks (a full receive buffer drops the packet), so the goroutine bought no
// concurrency. It did cost a closure allocation, a goroutine start and a stack
// growth per datagram, which showed up as several percent of the client CPU at
// forwarding rates.
func (c *Client) loopMessages(session *clientSession) {
	for {
		datagram, err := session.association.ReceiveDatagram(session.association.Context())
		if err != nil {
			return
		}
		hErr := c.handleMessage(session, datagram)
		if hErr != nil {
			session.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (c *Client) handleMessage(session *clientSession, datagram udpx.Datagram) error {
	if len(datagram.Data) < udpMessageHeaderLen {
		return E.New("invalid message")
	}
	if datagram.Data[0] != Version {
		return E.New("unknown version ", datagram.Data[0])
	}
	switch datagram.Data[1] {
	case CommandPacket:
		message, err := decodeUDPMessage(datagram.Data)
		if err != nil {
			return err
		}
		session.udpAccess.RLock()
		udpConn, loaded := session.udpConnMap[datagram.Channel]
		session.udpAccess.RUnlock()
		if !loaded {
			// The connection this message belongs to ended here; what the peer
			// sent before it heard about that is dropped.
			return nil
		}
		udpConn.inputPacket(message)
		return nil
	case CommandDissociate:
		session.udpAccess.Lock()
		udpConn, loaded := session.udpConnMap[datagram.Channel]
		delete(session.udpConnMap, datagram.Channel)
		session.udpAccess.Unlock()
		if loaded {
			udpConn.closeWithError(E.New("remote closed"))
		}
		return nil
	default:
		return E.New("unknown command ", datagram.Data[1])
	}
}
