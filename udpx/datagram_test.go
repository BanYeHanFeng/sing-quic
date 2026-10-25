package udpx

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// receiveDatagram waits for one message and fails the test if it does not arrive.
func receiveDatagram(t *testing.T, association Association, ctx context.Context) Datagram {
	t.Helper()
	datagram, err := association.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return datagram
}

// TestDatagramRoundTrip requires a message to arrive whole on the channel it was
// sent on, and the channels of one association to stay apart.
func TestDatagramRoundTrip(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	if err := client.SendDatagram(1, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram(9, []byte("second")); err != nil {
		t.Fatal(err)
	}
	first := receiveDatagram(t, server, ctx)
	if first.Channel != 1 || string(first.Data) != "first" {
		t.Fatalf("first message is %d %q", first.Channel, first.Data)
	}
	second := receiveDatagram(t, server, ctx)
	if second.Channel != 9 || string(second.Data) != "second" {
		t.Fatalf("second message is %d %q", second.Channel, second.Data)
	}
	// The reply runs the other way on the same channel.
	if err := server.SendDatagram(1, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	reply := receiveDatagram(t, client, ctx)
	if reply.Channel != 1 || string(reply.Data) != "reply" {
		t.Fatalf("reply is %d %q", reply.Channel, reply.Data)
	}
}

// TestDatagramEmpty requires a message of no bytes to be a message, not nothing.
func TestDatagramEmpty(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	if err := client.SendDatagram(4, nil); err != nil {
		t.Fatal(err)
	}
	datagram := receiveDatagram(t, server, ctx)
	if datagram.Channel != 4 || len(datagram.Data) != 0 {
		t.Fatalf("empty message is %d %q", datagram.Channel, datagram.Data)
	}
}

// TestDatagramFragments requires a message larger than a packet to be split, sent,
// and handed over once, whole, and in order.
func TestDatagramFragments(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	payload := testPayload(8 * datagramFragmentLen)
	if err := client.SendDatagram(2, payload); err != nil {
		t.Fatal(err)
	}
	datagram := receiveDatagram(t, server, ctx)
	if datagram.Channel != 2 {
		t.Fatalf("message is on channel %d", datagram.Channel)
	}
	if !bytes.Equal(datagram.Data, payload) {
		t.Fatalf("the message changed on the way: %d bytes of %d", len(datagram.Data), len(payload))
	}
}

// TestDatagramFragmentOrder requires a reassembly to wait for the pieces it does
// not have, to ignore the ones it already has, and to keep two messages of one
// channel apart when their fragments are interleaved.
func TestDatagramFragmentOrder(t *testing.T) {
	defragger := newDatagramDefragger()
	now := time.Now()
	fragment := func(message uint16, index, total uint8, data string) datagramData {
		return datagramData{channel: 7, message: message, index: index, total: total, data: []byte(data)}
	}
	// The tail arrives first, which is what a path that reordered the first
	// fragment looks like.
	datagram, complete, err := defragger.feed(fragment(1, 2, 3, "cc"), now)
	if err != nil || complete {
		t.Fatalf("a tail fragment produced %q, %v", datagram, err)
	}
	datagram, complete, err = defragger.feed(fragment(1, 0, 3, "aa"), now)
	if err != nil || complete {
		t.Fatalf("a first fragment produced %q, %v", datagram, err)
	}
	// A second message of the same channel is reassembled beside the first one.
	datagram, complete, err = defragger.feed(fragment(2, 0, 2, "xx"), now)
	if err != nil || complete {
		t.Fatalf("a fragment of another message produced %q, %v", datagram, err)
	}
	datagram, complete, err = defragger.feed(fragment(1, 1, 3, "bb"), now)
	if err != nil || !complete || string(datagram) != "aabbcc" {
		t.Fatalf("the first message is %q, %v", datagram, err)
	}
	datagram, complete, err = defragger.feed(fragment(2, 0, 2, "xx"), now)
	if err != nil || complete {
		t.Fatalf("a duplicated fragment produced %q, %v", datagram, err)
	}
	datagram, complete, err = defragger.feed(fragment(2, 1, 2, "yy"), now)
	if err != nil || !complete || string(datagram) != "xxyy" {
		t.Fatalf("the second message is %q, %v", datagram, err)
	}
	if len(defragger.entries) != 0 || defragger.bytes != 0 {
		t.Fatalf("%d reassemblies and %d bytes are left", len(defragger.entries), defragger.bytes)
	}
}

// TestDatagramFragmentInvalid requires a fragment that cannot belong to any
// datagram to be rejected, which is the only case a message is worth an error.
func TestDatagramFragmentInvalid(t *testing.T) {
	defragger := newDatagramDefragger()
	for _, data := range []datagramData{
		{channel: 1, message: 1, index: 0, total: 0, data: []byte("aa")},
		{channel: 1, message: 1, index: 3, total: 3, data: []byte("aa")},
	} {
		if _, complete, err := defragger.feed(data, time.Now()); err == nil || complete {
			t.Fatalf("fragment %d of %d was accepted", data.index, data.total)
		}
	}
}

// TestDatagramFragmentBounded requires the state of the reassemblies to stay
// bounded when a peer starts messages it never completes.
func TestDatagramFragmentBounded(t *testing.T) {
	defragger := newDatagramDefragger()
	for message := 0; message < 4*maxDatagramReassemblyCount; message++ {
		data := datagramData{channel: 1, message: uint16(message), index: 0, total: 2, data: []byte("aa")}
		if _, complete, err := defragger.feed(data, time.Now()); err != nil || complete {
			t.Fatalf("an incomplete message produced %v, %v", complete, err)
		}
	}
	if len(defragger.entries) > maxDatagramReassemblyCount {
		t.Fatalf("%d reassemblies are tracked", len(defragger.entries))
	}
	// A reassembly that is too old to complete is dropped as well.
	later := time.Now().Add(datagramReassemblyAge + time.Second)
	if _, complete, err := defragger.feed(datagramData{channel: 2, message: 1, index: 0, total: 2}, later); err != nil || complete {
		t.Fatalf("a fragment of an incomplete message produced %v, %v", complete, err)
	}
	if len(defragger.entries) != 1 {
		t.Fatalf("%d reassemblies are tracked after the old ones expired", len(defragger.entries))
	}
}

// TestDatagramTooLarge requires a message no fragment layout can carry to be
// refused before it is sent.
func TestDatagramTooLarge(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	err := client.SendDatagram(1, make([]byte, maxDatagramSize+1))
	if err == nil {
		t.Fatal("a datagram larger than the wire format allows was sent")
	}
}

// TestDatagramFrame requires a datagram frame to carry its channel, message and
// position, and to be rejected when it is cut short or flagged.
func TestDatagramFrame(t *testing.T) {
	encoded := appendDatagram(nil, datagramData{
		channel: 1 << 20,
		message: 1 << 12,
		index:   2,
		total:   5,
		data:    []byte("hello"),
	})
	f, rest, err := nextFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 || f.frameType != frameTypeDatagram {
		t.Fatalf("frame of type %d with %d bytes after it", f.frameType, len(rest))
	}
	data := f.datagram()
	if data.channel != 1<<20 || data.message != 1<<12 || data.index != 2 || data.total != 5 {
		t.Fatalf("frame carries %d %d %d %d", data.channel, data.message, data.index, data.total)
	}
	if string(data.data) != "hello" {
		t.Fatalf("frame carries %q", data.data)
	}
	for _, truncated := range []int{0, 1, datagramFixedLen - 1, len(encoded) - 1} {
		if _, _, err = nextFrame(encoded[:truncated]); err == nil {
			t.Fatalf("datagram frame truncated to %d bytes parsed", truncated)
		}
	}
	flagged := append([]byte(nil), encoded...)
	flagged[0] |= frameFlagFIN
	if _, _, err = nextFrame(flagged); err == nil {
		t.Fatal("a datagram with the end-of-stream flag parsed")
	}
	// A datagram is never sent again, which is what makes it a datagram.
	if frameTypeDatagram.retransmittable() {
		t.Fatal("a datagram is retransmitted")
	}
}
