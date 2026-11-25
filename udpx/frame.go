package udpx

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"

	"golang.org/x/crypto/chacha20poly1305"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	connectionIDLen = 8

	packetNumberLen = 4

	headerLen = connectionIDLen + 1 + packetNumberLen

	tagLen = chacha20poly1305.Overhead

	nonceLen = chacha20poly1305.NonceSize

	keyLen = chacha20poly1305.KeySize
)

const (
	packetTypeHandshake = 0

	packetTypeData = 1

	packetTypeMask = 0x0f

	packetReservedMask = 0xf0
)

var (
	errShortPacket    = errors.New("packet is shorter than its clear header")
	errReservedFlags  = errors.New("packet has reserved header flags set")
	errUnknownType    = errors.New("packet has unknown type")
	errAuthentication = errors.New("packet failed authentication")
	errShortFrame     = errors.New("frame is truncated")
	errUnknownFrame   = errors.New("frame has unknown type")
)

type connectionID [connectionIDLen]byte

type header struct {
	ConnectionID connectionID
	Type         uint8
	PacketNumber uint32
}

func (h header) appendTo(dst []byte) []byte {
	dst = append(dst, h.ConnectionID[:]...)
	dst = append(dst, h.Type)
	return binary.BigEndian.AppendUint32(dst, h.PacketNumber)
}

func parseHeader(packet []byte) (header, error) {
	if len(packet) < headerLen {
		return header{}, errShortPacket
	}
	flags := packet[connectionIDLen]
	if flags&packetReservedMask != 0 {
		return header{}, errReservedFlags
	}
	h := header{
		Type:         flags & packetTypeMask,
		PacketNumber: binary.BigEndian.Uint32(packet[connectionIDLen+1:]),
	}
	copy(h.ConnectionID[:], packet[:connectionIDLen])
	switch h.Type {
	case packetTypeHandshake, packetTypeData:
	default:
		return header{}, errUnknownType
	}
	return h, nil
}

type packetCipher struct {
	aead  cipher.AEAD
	nonce [nonceLen]byte
}

func newPacketCipher(key []byte) (packetCipher, error) {
	if len(key) != keyLen {
		return packetCipher{}, E.New("packet key of ", len(key), " bytes")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return packetCipher{}, err
	}
	return packetCipher{aead: aead}, nil
}

func (c *packetCipher) seal(packet []byte, payloadStart int, packetNumber uint32) {
	nonce := appendNonce(c.nonce[:0], packetNumber)
	clearHeader := packet[:payloadStart]
	c.aead.Seal(clearHeader, nonce, packet[payloadStart:len(packet)-tagLen], clearHeader)
}

func (c *packetCipher) open(packet []byte) (header, []byte, error) {
	h, err := parseHeader(packet)
	if err != nil {
		return header{}, nil, err
	}
	if len(packet) < headerLen+tagLen {
		return header{}, nil, errShortPacket
	}
	sealed := packet[headerLen:]
	nonce := appendNonce(c.nonce[:0], h.PacketNumber)
	payload, err := c.aead.Open(sealed[:0], nonce, sealed, packet[:headerLen])
	if err != nil {
		return header{}, nil, errAuthentication
	}
	return h, payload, nil
}

func appendNonce(dst []byte, packetNumber uint32) []byte {
	dst = append(dst, 0, 0, 0, 0, 0, 0, 0, 0)
	return binary.BigEndian.AppendUint32(dst, packetNumber)
}

const (
	frameTypePadding = 0

	frameTypePing = 1

	frameTypeClose = 2

	frameTypeAck = 3

	frameTypeStream = 4

	frameTypeMaxData = 5

	frameTypeMaxStreamData = 6

	frameTypeResetStream = 7

	frameTypeDatagram = 8

	frameTypeMaxStreams = 9
)

const (
	frameHeaderLen = 3

	frameTypeMask = 0x7f

	frameFlagFin = 0x80
)

const (
	streamHeaderLen = frameHeaderLen + 4 + 8

	datagramHeaderLen = frameHeaderLen + 2 + 1 + 1
)

func retransmittable(frameType uint8) bool {
	switch frameType {
	case frameTypeStream, frameTypeMaxData, frameTypeMaxStreamData, frameTypeResetStream, frameTypeMaxStreams:
		return true
	default:
		return false
	}
}

func appendPingFrame(dst []byte) []byte {
	return append(dst, frameTypePing, 0, 0)
}

func appendCloseFrame(dst []byte, code closeCode) []byte {
	return append(dst, frameTypeClose, 0, 1, byte(code))
}

func appendPaddingFrame(dst []byte, bodyLen int) []byte {
	dst = append(dst, frameTypePadding, byte(bodyLen>>8), byte(bodyLen))
	return append(dst, make([]byte, bodyLen)...)
}

func appendMaxDataFrame(dst []byte, limit uint64) []byte {
	dst = append(dst, frameTypeMaxData, 0, 8)
	return binary.BigEndian.AppendUint64(dst, limit)
}

func appendMaxStreamDataFrame(dst []byte, streamID uint32, limit uint64) []byte {
	dst = append(dst, frameTypeMaxStreamData, 0, 12)
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	return binary.BigEndian.AppendUint64(dst, limit)
}

func appendMaxStreamsFrame(dst []byte, limit uint32) []byte {
	dst = append(dst, frameTypeMaxStreams, 0, 4)
	return binary.BigEndian.AppendUint32(dst, limit)
}

func appendResetStreamFrame(dst []byte, streamID uint32, finalOffset uint64) []byte {
	dst = append(dst, frameTypeResetStream, 0, 13)
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	dst = binary.BigEndian.AppendUint64(dst, finalOffset)
	return append(dst, 0)
}

func appendStreamHeader(dst []byte, streamID uint32, offset uint64, fin bool, dataLen int) []byte {
	frameType := byte(frameTypeStream)
	if fin {
		frameType |= frameFlagFin
	}
	dst = append(dst, frameType, byte((4+8+dataLen)>>8), byte(4+8+dataLen))
	dst = binary.BigEndian.AppendUint32(dst, streamID)
	return binary.BigEndian.AppendUint64(dst, offset)
}

func appendDatagramHeader(dst []byte, message uint16, index uint8, total uint8, dataLen int) []byte {
	dst = append(dst, frameTypeDatagram, byte((2+1+1+dataLen)>>8), byte(2+1+1+dataLen))
	dst = binary.BigEndian.AppendUint16(dst, message)
	dst = append(dst, index, total)
	return dst
}

type closeCode uint8

const (
	closeCodeNormal closeCode = iota

	closeCodeIdleTimeout

	closeCodeError
)

func (c closeCode) err() error {
	switch c {
	case closeCodeNormal:
		return net.ErrClosed
	case closeCodeIdleTimeout:
		return ErrIdleTimeout
	default:
		return E.New("udpx: closed by peer with code ", int(c))
	}
}

func closeCodeOf(err error) closeCode {
	switch {
	case err == nil, errors.Is(err, net.ErrClosed):
		return closeCodeNormal
	case errors.Is(err, ErrIdleTimeout):
		return closeCodeIdleTimeout
	default:
		return closeCodeError
	}
}

type streamData struct {
	data     []byte
	offset   uint64
	streamID uint32
	fin      bool
}

func parseStreamFrame(frameType byte, body []byte) streamData {
	return streamData{
		streamID: binary.BigEndian.Uint32(body),
		offset:   binary.BigEndian.Uint64(body[4:]),
		fin:      frameType&frameFlagFin != 0,
		data:     body[12:],
	}
}

type streamReset struct {
	streamID    uint32
	finalOffset uint64
}

func parseResetStream(body []byte) streamReset {
	return streamReset{
		streamID:    binary.BigEndian.Uint32(body),
		finalOffset: binary.BigEndian.Uint64(body[4:]),
	}
}

type datagramData struct {
	data    []byte
	message uint16
	index   uint8
	total   uint8
}

func parseDatagram(body []byte) datagramData {
	return datagramData{
		message: binary.BigEndian.Uint16(body),
		index:   body[2],
		total:   body[3],
		data:    body[4:],
	}
}
