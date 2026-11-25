package quicx

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestAddrPortRoundTrip(t *testing.T) {
	for _, destination := range []M.Socksaddr{
		M.ParseSocksaddr("1.2.3.4:53"),
		M.ParseSocksaddr("[2001:db8::1]:443"),
		M.ParseSocksaddr("example.com:80"),
		{},
	} {
		encoded := appendAddrPort(nil, destination)
		parsed, length, err := parseAddrPort(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if length != len(encoded) {
			t.Fatalf("%v read as %d of %d bytes", destination, length, len(encoded))
		}
		if parsed.String() != destination.String() {
			t.Fatalf("%v came back as %v", destination, parsed)
		}
	}
}

func TestAddrPortFamilyBytes(t *testing.T) {
	if encoded := appendAddrPort(nil, M.ParseSocksaddr("example.com:80")); encoded[0] != addressFamilyFqdn {
		t.Fatalf("a domain starts with 0x%02x", encoded[0])
	}
	if encoded := appendAddrPort(nil, M.ParseSocksaddr("1.2.3.4:53")); encoded[0] != addressFamilyIPv4 {
		t.Fatalf("an IPv4 address starts with 0x%02x", encoded[0])
	}
	if encoded := appendAddrPort(nil, M.ParseSocksaddr("[2001:db8::1]:443")); encoded[0] != addressFamilyIPv6 {
		t.Fatalf("an IPv6 address starts with 0x%02x", encoded[0])
	}
	if encoded := appendAddrPort(nil, M.Socksaddr{}); encoded[0] != addressFamilyEmpty {
		t.Fatalf("an empty address starts with 0x%02x", encoded[0])
	}
}

func FuzzAddrPort(f *testing.F) {
	f.Add(appendAddrPort(nil, M.ParseSocksaddr("example.com:80")))
	f.Add(appendAddrPort(nil, M.ParseSocksaddr("1.2.3.4:53")))
	f.Add(appendAddrPort(nil, M.ParseSocksaddr("[2001:db8::1]:443")))
	f.Fuzz(func(t *testing.T, data []byte) {
		destination, length, err := parseAddrPort(data)
		if err != nil {
			return
		}
		if length < 1 || length > len(data) {
			t.Fatalf("read %d of %d bytes", length, len(data))
		}
		_ = destination.String()
	})
}

func TestMessageRoundTrip(t *testing.T) {
	destination := M.ParseSocksaddr("example.com:53")
	message := udpMessage{destination: destination, data: []byte("payload")}
	packed := message.pack(7)
	if channel := binary.BigEndian.Uint32(packed); channel != 7 {
		t.Fatalf("channel %d", channel)
	}
	command, parsedDestination, payload, err := parseMessage(packed[4:])
	if err != nil {
		t.Fatal(err)
	}
	if command != CommandPacket {
		t.Fatalf("command %d", command)
	}
	if parsedDestination.String() != destination.String() {
		t.Fatalf("destination %v", parsedDestination)
	}
	if !bytes.Equal(payload, []byte("payload")) {
		t.Fatalf("payload %q", payload)
	}
}

func TestDissociateMessage(t *testing.T) {
	command, _, payload, err := parseMessage([]byte{CommandDissociate})
	if err != nil {
		t.Fatal(err)
	}
	if command != CommandDissociate || len(payload) != 0 {
		t.Fatalf("command %d with %d bytes", command, len(payload))
	}
}

func TestParseMessageRejects(t *testing.T) {
	for _, message := range [][]byte{
		nil,
		{42},
		{CommandPacket},
		{CommandPacket, 0x7f},
	} {
		if _, _, _, err := parseMessage(message); err == nil {
			t.Fatalf("parsed a message of %d bytes", len(message))
		}
	}
}

func TestStreamRequestRoundTrip(t *testing.T) {
	destination := M.ParseSocksaddr("[2001:db8::1]:443")
	request := writeStreamRequest(nil, destination)
	parsed, err := readStreamRequest(bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != destination.String() {
		t.Fatalf("request destination %v", parsed)
	}
}

func TestDissociateClosesTheChannel(t *testing.T) {
	client, handler := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destination := M.ParseSocksaddr("1.1.1.1:53")
	if _, err = packetConn.WriteTo([]byte("query"), destination); err != nil {
		t.Fatal(err)
	}
	serverConn := handler.packetConnection(t, ctx)
	if err = serverConn.conn.Close(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	_ = packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err = packetConn.ReadFrom(buffer)
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("the channel survived the dissociate")
	}
	_ = packetConn.Close()
}

func TestNewClientRequiresOptions(t *testing.T) {
	if _, err := NewClient(ClientOptions{}); err == nil {
		t.Fatal("a client without a dialer was created")
	}
	if _, err := NewService[int](ServiceOptions{}); err == nil {
		t.Fatal("a service without a handler was created")
	}
}

func TestClosedClientRefusesConnections(t *testing.T) {
	client, _ := testSetup(t, "password")
	if err := client.CloseWithError(nil); err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 5*time.Second)
	if _, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:80")); err == nil {
		t.Fatal("a closed client dialed")
	}
}
