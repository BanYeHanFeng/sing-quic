package udpx

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func testKey(fill byte) []byte {
	key := make([]byte, keyLen)
	for index := range key {
		key[index] = fill + byte(index)
	}
	return key
}

func testRing(t *testing.T, epoch uint8, fill byte) *keyRing {
	t.Helper()
	ring := newKeyRing(epoch, mustAEAD(t, testKey(fill)))
	return &ring
}

func testHeader(epoch uint8) header {
	var id connectionID
	for index := range id {
		id[index] = byte(index + 1)
	}
	return header{
		ConnectionID: id,
		Type:         packetTypeData,
		Epoch:        epoch,
		PacketNumber: 0x01020304,
	}
}

func mustAEAD(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func mustSeal(t *testing.T, ring *keyRing, h header, payload []byte) []byte {
	t.Helper()
	h.Epoch = ring.epoch()
	packet, err := ring.seal(nil, h, nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func mustSealFEC(t *testing.T, ring *keyRing, fec *fecHeader, payload []byte) []byte {
	t.Helper()
	h := testHeader(ring.epoch())
	h.Type = packetTypeFEC
	packet, err := ring.seal(nil, h, fec, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestHeaderRoundTrip(t *testing.T) {
	parsed, err := parseHeader(testHeader(0).appendTo(nil))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != testHeader(0) {
		t.Fatalf("parsed %+v, want %+v", parsed, testHeader(0))
	}
	for _, epoch := range []uint8{0, 1, 2, epochMask} {
		for _, packetTypeValue := range []packetType{packetTypeHandshake, packetTypeData, packetTypeFEC, packetTypeReset} {
			h := testHeader(epoch)
			h.Type = packetTypeValue
			parsed, err = parseHeader(h.appendTo(nil))
			if err != nil {
				t.Fatalf("type %d epoch %d: %v", packetTypeValue, epoch, err)
			}
			if parsed != h {
				t.Fatalf("type %d epoch %d: parsed %+v, want %+v", packetTypeValue, epoch, parsed, h)
			}
		}
	}
}

func TestParseHeaderRejects(t *testing.T) {
	valid := testHeader(0).appendTo(nil)

	if _, err := parseHeader(valid[:headerLen-1]); err != errShortPacket {
		t.Fatalf("short packet: %v", err)
	}

	reserved := bytes.Clone(valid)
	reserved[connectionIDLen] |= 0x80
	if _, err := parseHeader(reserved); err != errReservedFlags {
		t.Fatalf("reserved flags: %v", err)
	}

	unknown := bytes.Clone(valid)
	unknown[connectionIDLen] = byte(packetTypeReset) + 1
	if _, err := parseHeader(unknown); err != errUnknownType {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	for _, size := range []int{0, 1, tagLen, 100, 1200, 65535} {
		payload := bytes.Repeat([]byte{0xaa}, size)
		packet := mustSeal(t, ring, testHeader(0), payload)
		if len(packet) != headerLen+size+tagLen {
			t.Fatalf("size %d: packet of %d bytes", size, len(packet))
		}
		h, fec, opened, err := ring.open(packet)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if h != testHeader(0) {
			t.Fatalf("size %d: header %+v", size, h)
		}
		if fec != nil {
			t.Fatalf("size %d: unexpected group description", size)
		}
		if !bytes.Equal(opened, payload) {
			t.Fatalf("size %d: payload changed", size)
		}
	}
}

func TestSealRejectsStaleEpoch(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	if _, err := ring.seal(nil, testHeader(1), nil, nil); err == nil {
		t.Fatal("sealed with an epoch the ring is not on")
	}
}

func TestSealAppends(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	prefix := []byte{0x01, 0x02, 0x03}
	packet, err := ring.seal(bytes.Clone(prefix), testHeader(0), nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet[:len(prefix)], prefix) {
		t.Fatalf("prefix overwritten: %x", packet[:len(prefix)])
	}
	if _, _, _, err = ring.open(packet[len(prefix):]); err != nil {
		t.Fatal(err)
	}
}

// TestOpenTampered flips every single bit of a packet and requires that none of
// the results open. The clear header is authenticated as additional data, so a
// flipped header bit fails exactly like a flipped payload bit.
func TestOpenTampered(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	payload := bytes.Repeat([]byte{0x5a}, 64)
	packet := mustSeal(t, ring, testHeader(0), payload)
	for offset := range packet {
		for bit := 0; bit < 8; bit++ {
			tampered := bytes.Clone(packet)
			tampered[offset] ^= 1 << bit
			if _, _, _, err := ring.open(tampered); err == nil {
				t.Fatalf("packet with bit %d of byte %d flipped opened", bit, offset)
			}
		}
	}
	if _, _, opened, err := ring.open(packet); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(opened, payload) {
		t.Fatal("payload changed")
	}
}

func TestOpenTruncated(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	packet := mustSeal(t, ring, testHeader(0), bytes.Repeat([]byte{0x5a}, 64))
	for length := 0; length < len(packet); length++ {
		if _, _, _, err := ring.open(packet[:length]); err == nil {
			t.Fatalf("packet truncated to %d of %d bytes opened", length, len(packet))
		}
	}
}

func TestEpochBoundary(t *testing.T) {
	ring := testRing(t, epochMask-1, 0x11)
	packetBefore := mustSeal(t, ring, testHeader(0), []byte("before"))

	ring.rotate(mustAEAD(t, testKey(0x22)))
	if ring.epoch() != epochMask {
		t.Fatalf("epoch wrapped early: %d", ring.epoch())
	}
	if _, _, opened, err := ring.open(packetBefore); err != nil {
		t.Fatalf("packet of the previous epoch: %v", err)
	} else if !bytes.Equal(opened, []byte("before")) {
		t.Fatal("payload of the previous epoch changed")
	}

	packetCurrent := mustSeal(t, ring, testHeader(0), []byte("current"))

	// The epoch wraps around: the generation after the last one is the first
	// one. The ring must name it as the current generation rather than keep
	// reading with it as the previous one.
	ring.rotate(mustAEAD(t, testKey(0x33)))
	if ring.epoch() != 0 {
		t.Fatalf("epoch after wrap around is %d", ring.epoch())
	}
	if _, _, _, err := ring.open(packetBefore); err == nil {
		t.Fatal("packet two generations old opened")
	}
	if _, _, _, err := ring.open(packetCurrent); err != nil {
		t.Fatalf("packet of the previous epoch: %v", err)
	}
	if _, _, _, err := ring.open(mustSeal(t, ring, testHeader(0), []byte("wrapped"))); err != nil {
		t.Fatalf("packet of the wrapped epoch: %v", err)
	}
}

func TestOpenUnknownEpoch(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	packet := mustSeal(t, ring, testHeader(0), []byte("payload"))
	if _, _, _, err := testRing(t, 2, 0x11).open(packet); err != errUnknownEpoch {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenWrongKey(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	packet := mustSeal(t, ring, testHeader(0), []byte("payload"))
	if _, _, _, err := testRing(t, 0, 0x44).open(packet); err != errAuthentication {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFECHeaderRoundTrip(t *testing.T) {
	lengths := []int{17, 1200, 65535}
	fec := fecHeader{
		GroupID:     0x11223344,
		Index:       1,
		MemberCount: uint8(len(lengths)),
		ParityCount: 2,
		lengths:     make([]byte, len(lengths)*fecLengthLen),
	}
	for index, length := range lengths {
		fec.setMemberLength(index, length)
	}
	ring := testRing(t, 0, 0x11)

	h, parsed, _, err := ring.open(mustSeal(t, ring, testHeader(0), []byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != nil {
		t.Fatalf("group description parsed from a packet of type %d", h.Type)
	}

	h, parsed, payload, err := ring.open(mustSealFEC(t, ring, &fec, []byte("parity")))
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != packetTypeFEC || h.PacketNumber != 0x01020304 || h.ConnectionID != testHeader(0).ConnectionID {
		t.Fatalf("header %+v", h)
	}
	if parsed == nil {
		t.Fatal("no group description")
	}
	if parsed.GroupID != fec.GroupID || parsed.Index != fec.Index || parsed.MemberCount != fec.MemberCount || parsed.ParityCount != fec.ParityCount {
		t.Fatalf("group description %+v", *parsed)
	}
	for index, length := range lengths {
		if parsed.memberLength(index) != length {
			t.Fatalf("member %d has length %d", index, parsed.memberLength(index))
		}
	}
	if !bytes.Equal(payload, []byte("parity")) {
		t.Fatal("payload changed")
	}
}

// TestFECHeaderTampered requires the group description to be authenticated:
// a flipped member length must not parse into a group the receiver would
// decode against.
func TestFECHeaderTampered(t *testing.T) {
	fec := fecHeader{
		GroupID:     7,
		MemberCount: 2,
		ParityCount: 2,
		lengths:     make([]byte, 2*fecLengthLen),
	}
	fec.setMemberLength(0, 100)
	fec.setMemberLength(1, 200)
	ring := testRing(t, 0, 0x11)
	packet := mustSealFEC(t, ring, &fec, []byte("parity"))
	for offset := headerLen; offset < headerLen+fecFixedLen+2*fecLengthLen; offset++ {
		tampered := bytes.Clone(packet)
		tampered[offset] ^= 0x01
		if _, _, _, err := ring.open(tampered); err == nil {
			t.Fatalf("group description byte %d flipped opened", offset-headerLen)
		}
	}
}

func TestFECHeaderRejects(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	fec := fecHeader{GroupID: 1, MemberCount: 2, ParityCount: 2, lengths: make([]byte, 2*fecLengthLen)}
	fec.setMemberLength(0, 10)
	fec.setMemberLength(1, 20)
	packet := mustSealFEC(t, ring, &fec, []byte("parity"))

	for _, patch := range []struct {
		name  string
		apply func(packet []byte)
	}{
		{"no members", func(packet []byte) { packet[headerLen+5] = 0 }},
		{"no parity", func(packet []byte) { packet[headerLen+6] = 0 }},
		{"shard out of range", func(packet []byte) { packet[headerLen+4] = 2 }},
	} {
		tampered := bytes.Clone(packet)
		patch.apply(tampered)
		if _, _, _, err := ring.open(tampered); err == nil {
			t.Fatalf("%s: opened", patch.name)
		}
	}

	if _, _, _, err := ring.open(packet[:headerLen+fecFixedLen+fecLengthLen-1]); err == nil {
		t.Fatal("truncated group description opened")
	}
}

func TestSealRejectsGroupDescriptionOnData(t *testing.T) {
	ring := testRing(t, 0, 0x11)
	fec := fecHeader{GroupID: 1, MemberCount: 1, ParityCount: 1, lengths: make([]byte, fecLengthLen)}
	if _, err := ring.seal(nil, testHeader(0), &fec, nil); err == nil {
		t.Fatal("sealed a data packet with a group description")
	}
}
