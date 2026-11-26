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
	if err := client.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(datagram, payload) {
		t.Fatal("the datagram changed on the way")
	}
}

func TestDatagramEmpty(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	if err := client.SendDatagram(nil); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(datagram) != 0 {
		t.Fatalf("%d bytes", len(datagram))
	}
}

func TestDatagramFragments(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	payload := testPayload(16 * 1024)
	if err := client.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(datagram, payload) {
		t.Fatal("the datagram changed on the way")
	}
}

func TestDatagramTooLarge(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	if err := client.SendDatagram(make([]byte, maxDatagramSize+1)); err == nil {
		t.Fatal("an oversized datagram was accepted")
	}
}

func TestDatagramDefraggerRejects(t *testing.T) {
	defragger := newDatagramDefragger(nil)
	now := time.Now()
	if _, _, err := defragger.feed(datagramData{index: 0, total: 0}, now); err == nil {
		t.Fatal("a zero-fragment datagram was accepted")
	}
	if _, _, err := defragger.feed(datagramData{index: 2, total: 2}, now); err == nil {
		t.Fatal("a fragment past the total was accepted")
	}
}

func TestDatagramDefraggerOrdersFragments(t *testing.T) {
	defragger := newDatagramDefragger(nil)
	now := time.Now()
	if _, complete, err := defragger.feed(datagramData{message: 1, index: 1, total: 2, data: []byte("world")}, now); err != nil || complete {
		t.Fatal("an incomplete datagram was completed")
	}
	message, complete, err := defragger.feed(datagramData{message: 1, index: 0, total: 2, data: []byte("hello ")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !complete || string(message) != "hello world" {
		t.Fatalf("reassembled %q", message)
	}
}

func TestDatagramDefraggerExpires(t *testing.T) {
	defragger := newDatagramDefragger(nil)
	now := time.Now()
	_, _, _ = defragger.feed(datagramData{message: 1, index: 0, total: 2, data: []byte("a")}, now)
	if defragger.bytes == 0 {
		t.Fatal("nothing was remembered")
	}
	_, _, _ = defragger.feed(datagramData{message: 2, index: 0, total: 2, data: []byte("b")}, now.Add(datagramReassemblyAge+time.Second))
	if defragger.bytes > 1 {
		t.Fatalf("%d bytes are remembered", defragger.bytes)
	}
}

func FuzzDatagramReassembly(f *testing.F) {
	f.Add(uint16(1), []byte{0, 0, 1, 1}, []byte("data"))
	f.Fuzz(func(t *testing.T, message uint16, header []byte, data []byte) {
		if len(header) < 4 {
			return
		}
		payload := make([]byte, 0, 4+len(data))
		payload = append(payload, byte(message>>8), byte(message))
		payload = append(payload, header[0]&0x0f, header[1]&0x0f)
		payload = append(payload, data...)
		defragger := newDatagramDefragger(nil)
		_, _, _ = defragger.feed(parseDatagram(payload), time.Now())
	})
}

func TestDatagramKeepsOrder(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	for _, payload := range [][]byte{[]byte("one"), []byte("two")} {
		if err := client.SendDatagram(payload); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []string{"one", "two"} {
		datagram, err := server.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(datagram) != expected {
			t.Fatalf("read %q, want %q", datagram, expected)
		}
	}
}
