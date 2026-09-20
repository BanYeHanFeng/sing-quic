package quicx

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func testUDPMessage(data []byte) *udpMessage {
	message := allocMessage()
	*message = udpMessage{
		sessionID:     1,
		packetID:      1,
		fragmentTotal: 1,
		destination:   M.ParseSocksaddrHostPort("example.com", 443),
		data:          buf.As(data),
	}
	return message
}

func TestDatagramMTURejectsInvalidPeerLimit(t *testing.T) {
	headerSize := (&udpMessage{destination: M.ParseSocksaddrHostPort("example.com", 443)}).headerSize()
	tests := []struct {
		name     string
		reported int64
		wantErr  bool
		expected int
	}{
		{name: "zero", reported: 0, wantErr: true},
		{name: "negative", reported: -1, wantErr: true},
		{name: "one", reported: 1, wantErr: true},
		{name: "below header", reported: int64(headerSize), wantErr: true},
		{name: "header only", reported: int64(headerSize + udpMTUSafetyMargin), wantErr: true},
		{name: "minimum usable", reported: int64(headerSize + udpMTUSafetyMargin + 1), expected: headerSize + 1},
		{name: "standard", reported: 1200, expected: 1200 - udpMTUSafetyMargin},
		{name: "huge", reported: 1 << 62, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			udpMTU, err := datagramMTU(test.reported, headerSize)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for a reported payload size of %d, got MTU %d", test.reported, udpMTU)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if udpMTU != test.expected {
				t.Fatalf("expected MTU %d, got %d", test.expected, udpMTU)
			}
		})
	}
}

// TestFragUDPMessageRejectsInvalidPacketSize covers the packet size a peer can
// force through a forged max_datagram_frame_size: a non-positive fragment size
// used to panic with "slice bounds out of range" or to loop forever while
// allocating fragments.
func TestFragUDPMessageRejectsInvalidPacketSize(t *testing.T) {
	message := testUDPMessage(bytes.Repeat([]byte{1}, 100))
	defer message.releaseMessage()
	headerSize := message.headerSize()
	for _, maxPacketSize := range []int{-3, 0, 1, headerSize - 1, headerSize} {
		fragments, err := fragUDPMessage(message, maxPacketSize)
		if err == nil {
			t.Fatalf("expected an error for a packet size of %d, got %d fragments", maxPacketSize, len(fragments))
		}
	}
}

// TestFragUDPMessageFragmentCountLimit covers a message which cannot be split
// into the 255 fragments the uint8 fragmentTotal field can express.
func TestFragUDPMessageFragmentCountLimit(t *testing.T) {
	message := testUDPMessage(bytes.Repeat([]byte{1}, 65535))
	defer message.releaseMessage()
	for _, maxPacketSize := range []int{message.headerSize() + 1, message.headerSize() + 8} {
		fragments, err := fragUDPMessage(message, maxPacketSize)
		if err == nil {
			t.Fatalf("expected an error for a packet size of %d, got %d fragments", maxPacketSize, len(fragments))
		}
	}
}
