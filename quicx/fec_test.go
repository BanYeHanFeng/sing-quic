package quicx

import (
	"net/netip"
	"testing"

	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
)

func testUDPMessage(size int) *udpMessage {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + 1)
	}
	return &udpMessage{
		sessionID:     7,
		packetID:      11,
		fragmentTotal: 1,
		destination:   M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 53),
		data:          data,
	}
}

func testFragments(t *testing.T, size, mtu int) (*udpMessage, []*udpMessage, *udpMessage) {
	t.Helper()
	message := testUDPMessage(size)
	fragments, err := fragUDPMessage(message, mtu)
	if err != nil {
		t.Fatal(err)
	}
	parity, err := buildParityFragment(fragments)
	if err != nil {
		t.Fatal(err)
	}
	return message, fragments, parity
}

func receiveFragment(t *testing.T, fragment *udpMessage) *udpMessage {
	t.Helper()
	packed := fragment.pack()
	decoded := allocMessage()
	err := decodeUDPMessage(decoded, packed.data[2:], quic.DatagramBufferOwner(packed))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertMessage(t *testing.T, expected, delivered *udpMessage) {
	t.Helper()
	if len(delivered.data) != len(expected.data) {
		t.Fatalf("message length: got %d, want %d", len(delivered.data), len(expected.data))
	}
	for i := range expected.data {
		if delivered.data[i] != expected.data[i] {
			t.Fatalf("message differs at byte %d", i)
		}
	}
	if delivered.destination != expected.destination {
		t.Fatalf("destination: got %v, want %v", delivered.destination, expected.destination)
	}
	if delivered.sessionID != expected.sessionID || delivered.packetID != expected.packetID {
		t.Fatalf("session %d/%d, want %d/%d", delivered.sessionID, delivered.packetID, expected.sessionID, expected.packetID)
	}
}

func TestFECFragmentFlagRoundTrip(t *testing.T) {
	message, fragments, parity := testFragments(t, 4000, 1197)
	if parity == nil {
		t.Fatal("no parity fragment")
	}
	if !fragments[0].fec || fragments[0].fragmentTotal != uint8(len(fragments)) {
		t.Fatalf("fragments not marked: %+v", fragments[0])
	}
	if !parity.fec || parity.fragmentID != uint8(len(fragments)) {
		t.Fatalf("parity header: %+v", parity)
	}
	totalLen := int(parity.data[0])<<8 | int(parity.data[1])
	if totalLen != len(message.data) {
		t.Fatalf("parity carries length %d, want %d", totalLen, len(message.data))
	}
	decoded := receiveFragment(t, parity)
	if !decoded.fec {
		t.Fatal("fec flag lost")
	}
	if decoded.fragmentTotal != uint8(len(fragments)) || decoded.fragmentID != uint8(len(fragments)) {
		t.Fatalf("decoded parity header: %+v", decoded)
	}
}

func TestFECSingleFragmentHasNoParity(t *testing.T) {
	message, fragments, parity := testFragments(t, 100, 1197)
	if parity != nil {
		t.Fatal("parity for a single fragment message")
	}
	if len(fragments) != 1 {
		t.Fatalf("fragments: %d", len(fragments))
	}
	if fragments[0].fec {
		t.Fatal("single fragment marked as fec")
	}
	if fragments[0].fragmentTotal != 1 || len(message.data) != 100 {
		t.Fatal("single fragment modified")
	}
}

func TestFECReassemblyRecoversLostFragment(t *testing.T) {
	for _, size := range []int{2500, 4000, 12000} {
		message, fragments, parity := testFragments(t, size, 1180)
		all := append(append([]*udpMessage{}, fragments...), parity)
		for _, lost := range []int{0, 1, len(fragments) - 1, len(all) - 1} {
			defragger := newUDPDefragger()
			var delivered *udpMessage
			for index, fragment := range all {
				if index == lost {
					continue
				}
				result, err := defragger.feed(receiveFragment(t, fragment))
				if err != nil {
					t.Fatalf("size %d lost %d: %v", size, lost, err)
				}
				if result != nil {
					delivered = result
				}
			}
			if delivered == nil {
				t.Fatalf("size %d lost %d: message not delivered", size, lost)
			}
			assertMessage(t, message, delivered)
			delivered.releaseMessage()
		}
	}
}

func TestFECReassemblyDeliversWithoutRecovery(t *testing.T) {
	for _, lostParity := range []bool{true, false} {
		message, fragments, parity := testFragments(t, 4000, 1180)
		defragger := newUDPDefragger()
		var delivered *udpMessage
		for _, fragment := range fragments {
			result, err := defragger.feed(receiveFragment(t, fragment))
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				delivered = result
			}
		}
		if lostParity {
			if delivered == nil {
				t.Fatal("message not delivered when the parity fragment is missing")
			}
		} else {
			result, err := defragger.feed(receiveFragment(t, parity))
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				t.Fatal("message delivered twice")
			}
		}
		if delivered == nil {
			t.Fatal("message not delivered")
		}
		assertMessage(t, message, delivered)
		delivered.releaseMessage()
	}
}

func TestFECReassemblyDropsTwoLostFragments(t *testing.T) {
	_, fragments, parity := testFragments(t, 4000, 1180)
	all := append(append([]*udpMessage{}, fragments...), parity)
	defragger := newUDPDefragger()
	for index, fragment := range all {
		if index == 0 || index == 1 {
			continue
		}
		result, err := defragger.feed(receiveFragment(t, fragment))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Fatal("message delivered without enough fragments")
		}
	}
}

func TestFECDuplicateFragmentIgnored(t *testing.T) {
	message, fragments, parity := testFragments(t, 4000, 1180)
	defragger := newUDPDefragger()
	var delivered *udpMessage
	for index, fragment := range fragments {
		result, err := defragger.feed(receiveFragment(t, fragment))
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			delivered = result
		}
		if index == 0 {
			result, err = defragger.feed(receiveFragment(t, fragment))
			if err != nil {
				t.Fatal(err)
			}
			if result != nil {
				t.Fatal("duplicate fragment completed the message")
			}
		}
	}
	result, err := defragger.feed(receiveFragment(t, parity))
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatal("parity completed a message which was already delivered")
	}
	assertMessage(t, message, delivered)
	delivered.releaseMessage()
}
