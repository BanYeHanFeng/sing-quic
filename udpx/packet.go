package udpx

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

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
	packetTypeMask = 0x0f
	reservedMask   = 0xf0
)

var (
	errShortPacket    = errors.New("packet is shorter than its clear header")
	errReservedFlags  = errors.New("packet has reserved header flags set")
	errUnknownType    = errors.New("packet has unknown type")
	errAuthentication = errors.New("packet failed authentication")
	errShortFrame     = errors.New("frame is truncated")
)

type connectionID [connectionIDLen]byte

type packetType uint8

const (
	packetTypeHandshake packetType = iota

	packetTypeData
)

type header struct {
	ConnectionID connectionID
	Type         packetType
	PacketNumber uint32
}

func (h header) appendTo(dst []byte) []byte {
	dst = append(dst, h.ConnectionID[:]...)
	dst = append(dst, byte(h.Type))
	return binary.BigEndian.AppendUint32(dst, h.PacketNumber)
}

func parseHeader(packet []byte) (header, error) {
	if len(packet) < headerLen {
		return header{}, errShortPacket
	}
	flags := packet[connectionIDLen]
	if flags&reservedMask != 0 {
		return header{}, errReservedFlags
	}
	h := header{
		Type:         packetType(flags & packetTypeMask),
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

func (c *packetCipher) sealInPlace(packet []byte, payloadStart int, packetNumber uint32) {
	nonce := appendNonce(c.nonce[:0], packetNumber)
	clearHeader := packet[:payloadStart]
	payload := packet[payloadStart : len(packet)-tagLen]
	c.aead.Seal(clearHeader, nonce, payload, clearHeader)
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

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, E.New("packet key of ", len(key), " bytes")
	}
	return chacha20poly1305.New(key)
}
