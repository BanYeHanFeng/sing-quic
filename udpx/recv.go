package udpx

import (
	"encoding/binary"
	"net"
	"time"
)

func (c *Conn) rxDone(packetNumber uint32, ackEliciting bool, now time.Time) {
	c.sendMu.Lock()
	c.send.rxPacket(packetNumber, ackEliciting, now)
	c.sendMu.Unlock()
	c.wake()
}

func (c *Conn) handlePacket(packet []byte, source net.Addr) error {
	packetHeader, err := parseHeader(packet)
	if err != nil {
		return err
	}
	if packetHeader.ConnectionID != c.localID {
		return errAuthentication
	}
	_, payload, err := c.recvCipher.open(packet)
	if err != nil {
		return err
	}
	c.peerAddr.Store(&source)
	err = c.handlePayload(packetHeader.PacketNumber, payload, time.Now())
	if err != nil {
		c.shutdown(err, true)
	}
	return err
}

// ackElicitingFrame 说明哪种帧需要对端确认：唯一一张表，不再散写在 switch 里。
func ackElicitingFrame(frameType uint8) bool {
	switch frameType {
	case frameTypePadding, frameTypeAck, frameTypeClose:
		return false
	default:
		return true
	}
}

func (c *Conn) handlePayload(packetNumber uint32, payload []byte, now time.Time) error {
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
		ackEliciting = ackEliciting || ackElicitingFrame(frameType&frameTypeMask)
		var err error
		switch frameType & frameTypeMask {
		case frameTypePadding, frameTypePing:
		case frameTypeClose:
			code := closeCodeNormal
			if len(body) > 0 {
				code = closeCode(body[0])
			}
			c.rxDone(packetNumber, ackEliciting, now)
			c.shutdown(code.err(), false)
			return nil
		case frameTypeAck:
			err = c.handleAck(body, now)
		case frameTypeStream:
			err = c.handleStreamFrame(frameType, body)
		case frameTypeMaxData:
			err = c.handleMaxData(body)
		case frameTypeMaxStreamData:
			err = c.handleMaxStreamData(body)
		case frameTypeResetStream:
			err = c.handleResetStream(body)
		case frameTypeDatagram:
			err = c.handleDatagram(body)
		case frameTypeMaxStreams:
			err = c.handleMaxStreams(body)
		default:
			return errUnknownFrame
		}
		if err != nil {
			return err
		}
	}
	c.rxDone(packetNumber, ackEliciting, now)
	return nil
}

func (c *Conn) handleAck(body []byte, now time.Time) error {
	acknowledgement, err := parseAckFrame(body)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	c.send.handleAck(acknowledgement, now)
	c.sendMu.Unlock()
	c.wake()
	return nil
}
