package udpx

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramRoundTrip(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	payload := testPayload(1000)
	if err := client.SendDatagram(7, payload); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if datagram.Channel != 7 {
		t.Fatalf("channel %d", datagram.Channel)
	}
	if !bytes.Equal(datagram.Data, payload) {
		t.Fatal("the datagram changed on the way")
	}
}

func TestDatagramEmpty(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	if err := client.SendDatagram(1, nil); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(datagram.Data) != 0 {
		t.Fatalf("%d bytes", len(datagram.Data))
	}
}

func TestDatagramFragments(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	payload := testPayload(16 * 1024)
	if err := client.SendDatagram(3, payload); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(datagram.Data, payload) {
		t.Fatal("the datagram changed on the way")
	}
}

func TestDatagramTooLarge(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	if err := client.SendDatagram(1, make([]byte, maxDatagramSize+1)); err == nil {
		t.Fatal("an oversized datagram was accepted")
	}
}

func TestDatagramDefraggerRejects(t *testing.T) {
	defragger := newDatagramDefragger()
	now := time.Now()
	if _, _, err := defragger.feed(datagramData{index: 0, total: 0}, now); err == nil {
		t.Fatal("c zero-fragment datagram was accepted")
	}
	if _, _, err := defragger.feed(datagramData{index: 2, total: 2}, now); err == nil {
		t.Fatal("c fragment past the total was accepted")
	}
}

func TestDatagramDefraggerOrdersFragments(t *testing.T) {
	defragger := newDatagramDefragger()
	now := time.Now()
	if _, complete, err := defragger.feed(datagramData{channel: 1, message: 1, index: 1, total: 2, data: []byte("world")}, now); err != nil || complete {
		t.Fatal("an incomplete datagram was completed")
	}
	message, complete, err := defragger.feed(datagramData{channel: 1, message: 1, index: 0, total: 2, data: []byte("hello ")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !complete || string(message) != "hello world" {
		t.Fatalf("reassembled %q", message)
	}
}

func TestDatagramDefraggerExpires(t *testing.T) {
	defragger := newDatagramDefragger()
	now := time.Now()
	_, _, _ = defragger.feed(datagramData{channel: 1, message: 1, index: 0, total: 2, data: []byte("c")}, now)
	if defragger.bytes == 0 {
		t.Fatal("nothing was remembered")
	}
	_, _, _ = defragger.feed(datagramData{channel: 2, message: 1, index: 0, total: 2, data: []byte("b")}, now.Add(datagramReassemblyAge+time.Second))
	if defragger.bytes > 1 {
		t.Fatalf("%d bytes are remembered", defragger.bytes)
	}
}

func FuzzDatagramReassembly(f *testing.F) {
	f.Add(uint32(1), uint16(1), []byte{0, 0, 1, 1}, []byte("data"))
	f.Fuzz(func(t *testing.T, channel uint32, message uint16, header []byte, data []byte) {
		if len(header) < 4 {
			return
		}
		payload := make([]byte, 0, 8+len(data))
		payload = append(payload, byte(channel>>24), byte(channel>>16), byte(channel>>8), byte(channel))
		payload = append(payload, byte(message>>8), byte(message))
		payload = append(payload, header[0]&0x0f, header[1]&0x0f)
		payload = append(payload, data...)
		defragger := newDatagramDefragger()
		_, _, _ = defragger.feed(parseDatagram(payload), time.Now())
	})
}

func TestDatagramChannelIsolation(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	if err := client.SendDatagram(1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram(2, []byte("two")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		datagram, err := server.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		switch datagram.Channel {
		case 1:
			if string(datagram.Data) != "one" {
				t.Fatalf("channel 1 got %q", datagram.Data)
			}
		case 2:
			if string(datagram.Data) != "two" {
				t.Fatalf("channel 2 got %q", datagram.Data)
			}
		default:
			t.Fatalf("unknown channel %d", datagram.Channel)
		}
	}
}
