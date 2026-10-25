package quicx

import (
	"github.com/sagernet/sing-quic/udpx"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// loopMessages dispatches the datagrams of the session to its packet
// connections.
func (s *serverSession[U]) loopMessages() {
	for {
		datagram, err := s.association.ReceiveDatagram(s.association.Context())
		if err != nil {
			return
		}
		hErr := s.handleMessage(datagram)
		if hErr != nil {
			// A message no channel can read is a session that is not speaking
			// this protocol, which is the one thing on this path worth ending it
			// for: the streams report their own failures.
			s.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (s *serverSession[U]) handleMessage(datagram udpx.Datagram) error {
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
		return s.handleUDPMessage(datagram.Channel, message)
	case CommandDissociate:
		s.closePacketConn(datagram.Channel, E.New("remote closed"))
		return nil
	default:
		return E.New("unknown command ", datagram.Data[1])
	}
}

// handleUDPMessage hands one forwarded packet to its packet connection, and
// creates that connection from the first message of a channel that arrives.
func (s *serverSession[U]) handleUDPMessage(sessionID uint32, message udpMessage) error {
	if !message.destination.IsValid() {
		// A message without a destination cannot be routed. It is dropped rather
		// than reported: a channel is created from the first message that
		// arrives, and dialing an outbound for a destination of ":0" would
		// report a session that can never be used.
		return nil
	}
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		udpConn = newUDPPacketConn(s.requestCtx, s.association, sessionID, true, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		})
		s.udpAccess.Lock()
		s.udpConnMap[sessionID] = udpConn
		s.udpAccess.Unlock()
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnectionEx(newCtx, newConn, M.SocksaddrFromNet(s.association.RemoteAddr()).Unwrap(), message.destination, nil)
	}
	udpConn.inputPacket(message)
	return nil
}
