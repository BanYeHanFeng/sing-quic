// Package udpx is the transport underneath quicx: encryption, handshake,
// acknowledgements, retransmission, flow control, congestion control and
// forward error correction, and nothing that knows about proxying.
//
// The reason it exists instead of QUIC is the packet number. It is in the
// clear, so the receiver knows which packets of a FEC group are missing and
// can recover them without asking the sender, and recovering a packet is not
// a different kind of event from receiving one: both end up as bytes that go
// through the same parsing and authentication.
//
// # Wire format
//
// A packet is a clear header followed by an authenticated payload:
//
//	connection id 8B | flags 1B | packet number 4B | payload
//
// flags carries the packet type in the low four bits and the key epoch in the
// next two. The two top bits are reserved and must be zero: that leaves room
// for a change of the layout which today's peers can still tell apart from a
// packet they understand.
//
// The packet number is a full uint32 rather than a truncated one. It is what
// orders packets and what names a FEC group, and a truncated number would only
// save bytes no one is short of.
//
// Nothing in the header is believed before it is authenticated: the connection
// id decides which keys to try, and the payload is only looked at once it opens
// with those keys.
//
// The payload is sealed with an AEAD whose additional data is the clear header
// itself, so a header byte flipped on the wire fails authentication instead of
// silently renumbering the packet. A FEC packet puts its group description
// between the common header and the payload, and that description is
// authenticated too.
package udpx

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// connectionIDLen is the size of the association identifier. It is what a
	// listener routes on, so it is a fixed-size value rather than a length
	// prefixed one: routing a packet must not depend on parsing variable
	// length data of unauthenticated origin.
	connectionIDLen = 8

	// packetNumberLen is the size of the packet number.
	packetNumberLen = 4

	// headerLen is the size of the clear header every packet starts with.
	headerLen = connectionIDLen + 1 + packetNumberLen

	// tagLen is the size of the AEAD tag that closes every sealed payload.
	tagLen = chacha20poly1305.Overhead

	// nonceLen is the size of the AEAD nonce: the key epoch followed by the
	// packet number, which is unique per key.
	nonceLen = chacha20poly1305.NonceSize

	// keyLen is the size of a packet key.
	keyLen = chacha20poly1305.KeySize
)

// Layout of the flags byte.
const (
	packetTypeMask = 0x0f
	epochShift     = 4
	epochMask      = 0x03
	reservedMask   = 0xc0

	// epochCount is the number of key generations the epoch field can name. It
	// is also the point at which epochs wrap around.
	epochCount = epochMask + 1
)

// Errors a packet can be rejected with. Callers drop the packet in every case:
// a packet that does not parse or does not authenticate is indistinguishable
// from one an off-path attacker sent, and there is nothing to answer.
var (
	errShortPacket    = errors.New("packet is shorter than its clear header")
	errReservedFlags  = errors.New("packet has reserved header flags set")
	errUnknownType    = errors.New("packet has unknown type")
	errUnknownEpoch   = errors.New("packet epoch has no key")
	errAuthentication = errors.New("packet failed authentication")
)

// connectionID identifies an association on the side that receives it. Each
// peer generates the one it is addressed by, so a connection id says nothing
// about the other end and means nothing on its own.
type connectionID [connectionIDLen]byte

type packetType uint8

const (
	// packetTypeHandshake carries ClientHello and ServerHello. It is the only
	// packet whose payload is not encrypted, because the payload is where the
	// keys come from. It authenticates itself with a MAC over the handshake
	// transcript instead.
	packetTypeHandshake packetType = iota

	// packetTypeData carries frames.
	packetTypeData

	// packetTypeFEC carries one parity shard of a FEC group. The shard is
	// encrypted like any other payload, while the group description in front
	// of it is in the clear: a parity shard is useless unless it can be applied
	// the moment it arrives, next to members that are still missing.
	packetTypeFEC

	// packetTypeReset ends an association from an endpoint that keeps no state
	// for it, so a peer that lost its own state learns about it instead of
	// retransmitting into a black hole until its idle timeout expires.
	packetTypeReset
)

// header is the clear header of every packet.
type header struct {
	ConnectionID connectionID
	Type         packetType
	// Epoch is the key generation the payload was sealed with. Both peers move
	// through epochs in the same deterministic order, so this field is what lets
	// the receiver wait with its own rotation until packets sealed with the
	// previous epoch have arrived.
	Epoch        uint8
	PacketNumber uint32
}

// appendTo appends the header to dst.
func (h header) appendTo(dst []byte) []byte {
	dst = append(dst, h.ConnectionID[:]...)
	dst = append(dst, byte(h.Type)|h.Epoch<<epochShift)
	return binary.BigEndian.AppendUint32(dst, h.PacketNumber)
}

// parseHeader parses the clear header of packet. It reads the whole header and
// rejects anything it cannot interpret, so a caller that gets a header back can
// route on it without validating it again.
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
		Epoch:        flags >> epochShift & epochMask,
		PacketNumber: binary.BigEndian.Uint32(packet[connectionIDLen+1:]),
	}
	copy(h.ConnectionID[:], packet[:connectionIDLen])
	switch h.Type {
	case packetTypeHandshake, packetTypeData, packetTypeFEC, packetTypeReset:
	default:
		return header{}, errUnknownType
	}
	return h, nil
}

// FEC group description.
//
// A group is k consecutive packet numbers starting at GroupID, of which the
// first k packets are the members and the next m are parity shards. Members
// are not enumerated: naming the first packet number and counting is enough,
// and it is what lets the receiver know a member is missing before any parity
// shard arrived.
//
// The lengths of the members are part of the description because the members
// are padded to the length of the longest packet in the group rather than to
// the MTU: a group of small datagrams must not be inflated to full size just
// to be able to recover them. A recovered member is the whole packet bytes
// including that padding, so the receiver needs the original length of each to
// know where the packet ends.
const (
	// fecFixedLen is the size of the group description without the lengths.
	fecFixedLen = 4 + 1 + 1 + 1

	// fecLengthLen is the size of one member length.
	fecLengthLen = 2

	// fecHeaderLen is the size of the clear header of a FEC packet that
	// describes memberCount members.
	fecHeaderLen = headerLen + fecFixedLen
)

// fecHeader is the clear group description of a FEC packet.
type fecHeader struct {
	// GroupID is the packet number of the first member of the group.
	GroupID uint32
	// Index is which parity shard of the group the packet carries.
	Index uint8
	// MemberCount is k, the number of members the group can recover from.
	MemberCount uint8
	// ParityCount is m, the number of parity shards of the group.
	ParityCount uint8
	// lengths holds the length of every member, most significant byte first,
	// pointing into the packet the description was parsed from.
	lengths []byte
}

// memberLength returns the original length of the member at index.
func (h *fecHeader) memberLength(index int) int {
	offset := index * fecLengthLen
	return int(h.lengths[offset])<<8 | int(h.lengths[offset+1])
}

// setMemberLength records the original length of the member at index.
func (h *fecHeader) setMemberLength(index int, length int) {
	offset := index * fecLengthLen
	h.lengths[offset] = byte(length >> 8)
	h.lengths[offset+1] = byte(length)
}

// appendTo appends the group description to dst.
func (h *fecHeader) appendTo(dst []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, h.GroupID)
	dst = append(dst, h.Index, h.MemberCount, h.ParityCount)
	return append(dst, h.lengths...)
}

// parseFECHeader parses the group description of a FEC packet whose common
// header h was parsed from the same packet. The returned header's lengths
// point into packet.
func parseFECHeader(packet []byte, h header) (fecHeader, error) {
	if len(packet) < fecHeaderLen+fecLengthLen {
		return fecHeader{}, errShortPacket
	}
	description := packet[headerLen:]
	f := fecHeader{
		GroupID:     binary.BigEndian.Uint32(description),
		Index:       description[4],
		MemberCount: description[5],
		ParityCount: description[6],
	}
	if f.MemberCount == 0 || f.ParityCount == 0 {
		return fecHeader{}, E.New("FEC group of ", f.MemberCount, " members and ", f.ParityCount, " parity shards")
	}
	if f.Index >= f.ParityCount {
		return fecHeader{}, E.New("FEC parity shard ", f.Index, " of ", f.ParityCount)
	}
	lengthsEnd := fecHeaderLen + int(f.MemberCount)*fecLengthLen
	if len(packet) < lengthsEnd+tagLen {
		return fecHeader{}, errShortPacket
	}
	f.lengths = packet[fecHeaderLen:lengthsEnd]
	return f, nil
}

// packetKeys is one generation of packet keys.
type packetKeys struct {
	aead cipher.AEAD
	// epoch is the number the key is addressed by on the wire.
	epoch uint8
}

// keyRing is the two key generations a peer keeps: the one it writes with and
// the one that was just replaced.
//
// Two are needed because packets do not arrive in order. A rotation is
// triggered by packet number thresholds, so packets sealed with the previous
// epoch are still in flight when the peer rotates, and dropping them would turn
// every rotation into a retransmission burst. Keeping more than two is not
// worth it: a peer that falls two epochs behind has a round trip long enough
// that the packets are lost anyway.
//
// A ring belongs to one direction of an association and is driven by one
// goroutine, the one that sends or receives that direction, so it holds no
// lock. The two directions derive their keys from the same handshake but
// advance independently.
type keyRing struct {
	current     packetKeys
	previous    packetKeys
	previousSet bool
}

func newKeyRing(epoch uint8, aead cipher.AEAD) keyRing {
	return keyRing{current: packetKeys{aead: aead, epoch: epoch & epochMask}}
}

// epoch returns the generation the ring seals with.
func (ring *keyRing) epoch() uint8 {
	return ring.current.epoch
}

// rotate starts a new generation. The generation that was current stays
// readable until the next rotation.
func (ring *keyRing) rotate(aead cipher.AEAD) {
	ring.previous = ring.current
	ring.previousSet = true
	ring.current = packetKeys{aead: aead, epoch: (ring.current.epoch + 1) & epochMask}
}

// keysFor returns the keys of epoch.
func (ring *keyRing) keysFor(epoch uint8) (packetKeys, error) {
	if epoch == ring.current.epoch {
		return ring.current, nil
	}
	if ring.previousSet && epoch == ring.previous.epoch {
		return ring.previous, nil
	}
	return packetKeys{}, errUnknownEpoch
}

// seal appends the packet with header h and the given payload to dst, and
// returns the extended slice. A FEC packet passes its group description as
// fec, which is written and authenticated along with the header.
func (ring *keyRing) seal(dst []byte, h header, fec *fecHeader, payload []byte) ([]byte, error) {
	if h.Epoch != ring.current.epoch {
		return nil, E.New("seal with epoch ", h.Epoch, " while the current epoch is ", ring.current.epoch)
	}
	headerStart := len(dst)
	dst = h.appendTo(dst)
	if fec != nil {
		if h.Type != packetTypeFEC {
			return nil, E.New("group description on a packet of type ", int(h.Type))
		}
		dst = fec.appendTo(dst)
	}
	// The additional data is the clear header, which is exactly what was just
	// appended. Authenticating it is what makes the packet number and the FEC
	// group description as trustworthy as the payload.
	clearHeader := dst[headerStart:]
	return ring.current.aead.Seal(dst, nonce(ring.current.epoch, h.PacketNumber), payload, clearHeader), nil
}

// open parses and authenticates packet, whose keys must belong to the
// association it is addressed to. The returned payload and the lengths of a
// returned group description point into packet and must be used before it is
// reused.
func (ring *keyRing) open(packet []byte) (header, *fecHeader, []byte, error) {
	h, err := parseHeader(packet)
	if err != nil {
		return header{}, nil, nil, err
	}
	var fec *fecHeader
	clearHeaderLen := headerLen
	if h.Type == packetTypeFEC {
		parsed, parseErr := parseFECHeader(packet, h)
		if parseErr != nil {
			return header{}, nil, nil, parseErr
		}
		fec = &parsed
		clearHeaderLen += fecFixedLen + int(parsed.MemberCount)*fecLengthLen
	}
	if len(packet) < clearHeaderLen+tagLen {
		return header{}, nil, nil, errShortPacket
	}
	keys, err := ring.keysFor(h.Epoch)
	if err != nil {
		return header{}, nil, nil, err
	}
	// The payload is opened in place: the caller's packet buffer is where the
	// plaintext belongs, and it is no longer needed once it opened.
	sealed := packet[clearHeaderLen:]
	payload, err := keys.aead.Open(sealed[:0], nonce(keys.epoch, h.PacketNumber), sealed, packet[:clearHeaderLen])
	if err != nil {
		return header{}, nil, nil, errAuthentication
	}
	return h, fec, payload, nil
}

// nonce builds the AEAD nonce of a packet. The epoch is part of it although the
// key already differs per epoch, which costs nothing and makes a nonce repeat
// after a wrap around impossible: the key changed when the epoch did.
func nonce(epoch uint8, packetNumber uint32) []byte {
	n := make([]byte, nonceLen)
	n[0] = epoch
	binary.BigEndian.PutUint32(n[nonceLen-packetNumberLen:], packetNumber)
	return n
}

// newAEAD builds the AEAD a packet key is used with. ChaCha20-Poly1305 is the
// one cipher the whole protocol uses: unlike AES-GCM it needs no hardware
// support to be fast enough, and one choice is one thing to understand.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, E.New("packet key of ", len(key), " bytes")
	}
	return chacha20poly1305.New(key)
}
