package quicx

import (
	"encoding/binary"
	"io"

	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
)

func decodeFECPacket(data []byte, owner quic.DatagramBufferOwner) (fecPacket, error) {
	var packet fecPacket
	if len(data) < fecBlockHeaderLen {
		releaseDatagramOwner(owner)
		return packet, io.ErrUnexpectedEOF
	}
	packet.sessionID = binary.BigEndian.Uint16(data[0:2])
	packet.blockID = binary.BigEndian.Uint16(data[2:4])
	packet.shardIndex = data[4]
	packet.k = data[5]
	packet.m = data[6]
	dataLength := int(binary.BigEndian.Uint16(data[7:9]))
	payload := data[fecBlockHeaderLen:]
	if len(payload) != dataLength {
		releaseDatagramOwner(owner)
		return packet, io.ErrUnexpectedEOF
	}
	packet.payload = copyFECPayload(payload)
	releaseDatagramOwner(owner)
	return packet, nil
}

func (c *udpPacketConn) writeFECBlockMessage(message *udpMessage) error {
	body := make([]byte, message.bodySize())
	message.writeBody(body)
	var sendErr error
	err := c.fecBlock.write(body, func(blockID uint16, frame fecFrame) error {
		frameErr := c.writeFECFrame(blockID, frame)
		if sendErr == nil {
			sendErr = frameErr
		}
		return frameErr
	})
	if err != nil && sendErr == nil {
		sendErr = err
	}
	return sendErr
}

func (c *udpPacketConn) writeFECFrame(blockID uint16, frame fecFrame) error {
	buffer := getWireBuffer(2 + fecBlockHeaderLen + len(frame.payload))
	data := buffer.data
	data[0] = Version
	data[1] = CommandFECPacket
	binary.BigEndian.PutUint16(data[2:4], c.sessionID)
	binary.BigEndian.PutUint16(data[4:6], blockID)
	data[6] = frame.shardIndex
	data[7] = frame.k
	data[8] = frame.m
	binary.BigEndian.PutUint16(data[9:11], uint16(len(frame.payload)))
	copy(data[2+fecBlockHeaderLen:], frame.payload)
	return c.quicConn.SendDatagramOwned(data, buffer)
}

func (c *udpPacketConn) inputFECPacket(packet fecPacket) error {
	select {
	case <-c.ctx.Done():
		return nil
	default:
	}
	if c.fecBlock == nil {
		return nil
	}
	c.fecAccess.Lock()
	if c.fecDecoder == nil {
		c.fecDecoder = newFECBlockDecoder(c.fecBlock.config, c.reportFECLoss)
	}
	decoder := c.fecDecoder
	c.fecAccess.Unlock()
	return decoder.input(packet.blockID, packet.shardIndex, packet.k, packet.m, packet.payload, c.deliverFECBody)
}

func (c *udpPacketConn) deliverFECBody(body []byte) error {
	message := allocMessage()
	err := decodeUDPMessage(message, body, nil)
	if err != nil {
		message.releaseMessage()
		return E.Cause(err, "decode fec message")
	}
	buffer := getWireBuffer(len(message.data))
	copy(buffer.data, message.data)
	message.data = buffer.data
	message.buffer = nil
	message.owner = buffer
	select {
	case c.data <- message:
	default:
		message.releaseMessage()
	}
	return nil
}

func (c *udpPacketConn) reportFECLoss(lossPerMille uint16) {
	go func() {
		stream, err := openUniStream0RTT(c.ctx, c.quicConn)
		if err != nil {
			return
		}
		frame := []byte{Version, CommandFECReport, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(frame[2:4], c.sessionID)
		binary.BigEndian.PutUint16(frame[4:6], lossPerMille)
		_, err = stream.Write(frame)
		if err != nil {
			stream.CancelWrite(0)
			return
		}
		_ = stream.Close()
	}()
}

func (c *udpPacketConn) setFECParity(lossPerMille uint16) {
	if c.fecBlock == nil {
		return
	}
	c.fecBlock.setParity(fecParityForLoss(c.fecBlock.config.blockSize, lossPerMille, c.fecBlock.config.maxParity))
}

func decodeFECReport(data []byte) (sessionID uint16, lossPerMille uint16, err error) {
	if len(data) < 6 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	sessionID = binary.BigEndian.Uint16(data[2:4])
	lossPerMille = binary.BigEndian.Uint16(data[4:6])
	if lossPerMille > 1000 {
		return 0, 0, E.New("invalid fec loss report ", lossPerMille)
	}
	return sessionID, lossPerMille, nil
}
