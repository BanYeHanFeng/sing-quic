package udpx

import (
	"encoding/binary"
	"net"
	"time"
)

func (a *association) rxDone(packetNumber uint32, ackEliciting bool, now time.Time) {
	a.txMu.Lock()
	a.tx.rxPacket(packetNumber, ackEliciting, now)
	a.txMu.Unlock()
	a.wake()
}

func (a *association) handlePacket(packet []byte, source net.Addr) error {
	packetHeader, err := parseHeader(packet)
	if err != nil {
		return err
	}
	a.stats.recvPackets.Add(1)
	a.stats.recvBytes.Add(int64(len(packet)))
	if packetHeader.ConnectionID != a.localConnID {
		return errAuthentication
	}
	_, payload, err := a.recvCipher.open(packet)
	if err != nil {
		return err
	}
	a.peerAddr.Store(&source)
	err = a.handlePayload(packetHeader.PacketNumber, payload, time.Now())
	if err != nil {
		a.shutdown(err, true)
	}
	return err
}

func (a *association) handlePayload(packetNumber uint32, payload []byte, now time.Time) error {
	ackEliciting := false
	for len(payload) > 0 {
		if len(payload) < frameHeaderLen {
			return errShortFrame
		}
		frameType := payload[0]
		length := int(binary.BigEndian.Uint16(payload[1:3]))
		if len(payload) < frameHeaderLen+length {
			return errShortFrame
		}
		body := payload[frameHeaderLen : frameHeaderLen+length]
		payload = payload[frameHeaderLen+length:]
		var err error
		switch frameType & frameTypeMask {
		case frameTypePadding:
		case frameTypePing:
			ackEliciting = true
		case frameTypeClose:
			code := closeCodeNormal
			if len(body) > 0 {
				code = closeCode(body[0])
			}
			a.rxDone(packetNumber, ackEliciting, now)
			a.shutdown(code.err(), false)
			return nil
		case frameTypeAck:
			err = a.handleAck(body, now)
		case frameTypeStream:
			ackEliciting = true
			err = a.handleStreamFrame(frameType, body)
		case frameTypeMaxData:
			ackEliciting = true
			err = a.handleMaxData(body)
		case frameTypeMaxStreamData:
			ackEliciting = true
			err = a.handleMaxStreamData(body)
		case frameTypeResetStream:
			ackEliciting = true
			err = a.handleResetStream(body)
		case frameTypeDatagram:
			ackEliciting = true
			err = a.handleDatagram(body)
		case frameTypeMaxStreams:
			ackEliciting = true
			if len(body) < 4 {
				err = errShortFrame
				break
			}
			a.handleMaxStreams(binary.BigEndian.Uint32(body))
		default:
			return errUnknownFrame
		}
		if err != nil {
			return err
		}
	}
	a.rxDone(packetNumber, ackEliciting, now)
	return nil
}

func (a *association) handleAck(body []byte, now time.Time) error {
	acknowledgement, err := parseAckFrame(body)
	if err != nil {
		return err
	}
	a.txMu.Lock()
	a.tx.handleAck(acknowledgement, now)
	a.txMu.Unlock()
	a.wake()
	return nil
}
