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

func testCipher(t *testing.T, fill byte) *packetCipher {
	t.Helper()
	return &packetCipher{aead: mustAEAD(t, testKey(fill))}
}

func testHeader() header {
	var id connectionID
	for index := range id {
		id[index] = byte(index + 1)
	}
	return header{
		ConnectionID: id,
		Type:         packetTypeData,
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

func mustSeal(t *testing.T, cipher *packetCipher, h header, payload []byte) []byte {
	t.Helper()
	packet := make([]byte, 0, headerLen+len(payload)+tagLen)
	packet = h.appendTo(packet)
	payloadStart := len(packet)
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, tagLen)...)
	cipher.sealInPlace(packet, payloadStart, h.PacketNumber)
	return packet
}

func TestHeaderRoundTrip(t *testing.T) {
	parsed, err := parseHeader(testHeader().appendTo(nil))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != testHeader() {
		t.Fatalf("parsed %+v, want %+v", parsed, testHeader())
	}
	for _, packetTypeValue := range []packetType{packetTypeHandshake, packetTypeData} {
		h := testHeader()
		h.Type = packetTypeValue
		parsed, err = parseHeader(h.appendTo(nil))
		if err != nil {
			t.Fatalf("type %d: %v", packetTypeValue, err)
		}
		if parsed != h {
			t.Fatalf("type %d: parsed %+v, want %+v", packetTypeValue, parsed, h)
		}
	}
}

func TestParseHeaderRejects(t *testing.T) {
	valid := testHeader().appendTo(nil)

	if _, err := parseHeader(valid[:headerLen-1]); err != errShortPacket {
		t.Fatalf("short packet: %v", err)
	}

	reserved := bytes.Clone(valid)
	reserved[connectionIDLen] |= 0x80
	if _, err := parseHeader(reserved); err != errReservedFlags {
		t.Fatalf("reserved flags: %v", err)
	}

	unknown := bytes.Clone(valid)
	unknown[connectionIDLen] = byte(packetTypeData) + 1
	if _, err := parseHeader(unknown); err != errUnknownType {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	cipher := testCipher(t, 0x11)
	for _, size := range []int{0, 1, tagLen, 100, 1200, 65535} {
		payload := bytes.Repeat([]byte{0xaa}, size)
		packet := mustSeal(t, cipher, testHeader(), payload)
		if len(packet) != headerLen+size+tagLen {
			t.Fatalf("size %d: packet of %d bytes", size, len(packet))
		}
		h, opened, err := cipher.open(packet)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if h != testHeader() {
			t.Fatalf("size %d: header %+v", size, h)
		}
		if !bytes.Equal(opened, payload) {
			t.Fatalf("size %d: payload changed", size)
		}
	}
}

func TestSealInPlaceOpens(t *testing.T) {
	cipher := testCipher(t, 0x11)
	for _, size := range []int{0, 1, 1000, maxPacketSize - headerLen - tagLen} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		packet := mustSeal(t, cipher, testHeader(), payload)
		h, opened, err := cipher.open(packet)
		if err != nil {
			t.Fatalf("size %d: the packet does not open: %v", size, err)
		}
		if h != testHeader() {
			t.Fatalf("size %d: header %+v", size, h)
		}
		if !bytes.Equal(opened, payload) {
			t.Fatalf("size %d: the payload changed", size)
		}
	}
}

func TestOpenTampered(t *testing.T) {
	cipher := testCipher(t, 0x11)
	payload := bytes.Repeat([]byte{0x5a}, 64)
	packet := mustSeal(t, cipher, testHeader(), payload)
	for offset := range packet {
		for bit := 0; bit < 8; bit++ {
			tampered := bytes.Clone(packet)
			tampered[offset] ^= 1 << bit
			if _, _, err := cipher.open(tampered); err == nil {
				t.Fatalf("packet with bit %d of byte %d flipped opened", bit, offset)
			}
		}
	}
	if _, opened, err := cipher.open(packet); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(opened, payload) {
		t.Fatal("payload changed")
	}
}

func TestOpenTruncated(t *testing.T) {
	cipher := testCipher(t, 0x11)
	packet := mustSeal(t, cipher, testHeader(), bytes.Repeat([]byte{0x5a}, 64))
	for length := 0; length < len(packet); length++ {
		if _, _, err := cipher.open(packet[:length]); err == nil {
			t.Fatalf("packet truncated to %d of %d bytes opened", length, len(packet))
		}
	}
}

func TestOpenWrongKey(t *testing.T) {
	packet := mustSeal(t, testCipher(t, 0x11), testHeader(), []byte("payload"))
	if _, _, err := testCipher(t, 0x44).open(packet); err != errAuthentication {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenNonceNeverAllocates(t *testing.T) {
	cipher := testCipher(t, 0x11)
	packet := mustSeal(t, cipher, testHeader(), bytes.Repeat([]byte{0x5a}, 1200))
	sealed := make([]byte, len(packet))
	allocs := testing.AllocsPerRun(100, func() {
		copy(sealed, packet)
		if _, _, err := cipher.open(sealed); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("%v allocations per packet", allocs)
	}
}
