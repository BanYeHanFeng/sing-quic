package quicx

import (
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *serverSession[U]) loopMessages() {
	select {
	case <-s.connDone:
		return
	case <-s.authDone:
	}
	for {
		message, owner, err := s.quicConn.ReceiveDatagramOwned(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := s.handleMessage(message, owner)
		if hErr != nil {
			s.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (s *serverSession[U]) handleMessage(data []byte, owner quic.DatagramBufferOwner) error {
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
		return s.handleUDPMessage(message)
	case CommandFECPacket:
		packet, err := decodeFECPacket(data[2:], owner)
		if err != nil {
			return E.Cause(err, "decode fec packet")
		}
		return s.handleFECPacket(packet)
	case CommandHeartbeat:
		releaseDatagramOwner(owner)
		return nil
	default:
		releaseDatagramOwner(owner)
		return E.New("unknown command ", data[1])
	}
}

func (s *serverSession[U]) handleUDPMessage(message *udpMessage) error {
	if !message.destination.IsValid() {
		// A message without a destination cannot be routed, and the session is
		// created from the first message of its sessionID: creating one here
		// would route (and report) a session to ":0" and dial an outbound
		// packet connection it can never use. Fragments of one message all
		// carry the same destination, so the message is dropped whole.
		message.releaseMessage()
		return nil
	}
	sessionID := message.sessionID
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, sessionID, true, s.fec, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		})
		s.udpAccess.Lock()
		s.udpConnMap[sessionID] = udpConn
		s.udpAccess.Unlock()
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnectionEx(newCtx, newConn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), message.destination, nil)
	}
	return udpConn.inputPacket(message)
}

func (s *serverSession[U]) handleFECPacket(packet fecPacket) error {
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[packet.sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		return nil
	}
	return udpConn.inputFECPacket(packet)
}

func (s *serverSession[U]) setFECParity(sessionID uint16, lossPerMille uint16) {
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded {
		return
	}
	udpConn.setFECParity(lossPerMille)
}
