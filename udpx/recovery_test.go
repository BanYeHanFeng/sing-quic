package udpx

import (
	"context"
	"errors"
	"testing"
	"time"
)

func openStreamFrame(t *testing.T, a *association, index uint32, payload string) error {
	t.Helper()
	frame := appendStreamHeader(nil, index<<1, 0, false, len(payload))
	frame = append(frame, payload...)
	return a.handleStreamFrame(frameTypeStream, frame[frameHeaderLen:])
}

func TestPeerOpensStreamsOutOfOrder(t *testing.T) {
	_, server, _ := testSetup(t, Options{MTU: mtuIPv4}, Options{MTU: mtuIPv4})
	a := server.(*association)
	ctx := testContext(t, 5*time.Second)
	if err := openStreamFrame(t, a, 0, "zero"); err != nil {
		t.Fatal(err)
	}
	if err := openStreamFrame(t, a, 2, "two"); err != nil {
		t.Fatalf("stream 2 arrived before stream 1: %v", err)
	}
	a.streamsMu.Lock()
	next := a.streams.peerNext
	a.streamsMu.Unlock()
	if next != 3 {
		t.Fatalf("the peer next stream is %d", next)
	}
	for _, expected := range []string{"zero", "two"} {
		stream, err := a.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if read := readAll(t, stream, len(expected)); string(read) != expected {
			t.Fatalf("stream read %q", read)
		}
	}
	if err := openStreamFrame(t, a, 1, "one"); err != nil {
		t.Fatalf("stream 1 arrived after stream 2: %v", err)
	}
	stream, err := a.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("stream 1 was dropped: %v", err)
	}
	if read := readAll(t, stream, 3); string(read) != "one" {
		t.Fatalf("stream 1 read %q", read)
	}
	if err = openStreamFrame(t, a, 1, "one"); err != nil {
		t.Fatalf("stream 1 arrived again: %v", err)
	}
	select {
	case <-a.Context().Done():
		t.Fatalf("the association ended with %v", context.Cause(a.Context()))
	default:
	}
}

func TestProbeRetransmitsWithoutAFlood(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{credential: credential}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{})
	ctx := testContext(t, 30*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, accepted, len(mustWrite(t, stream, testPayload(32*1024))))

	link.setLoss(1)
	payload := testPayload(8 * 1024)
	mustWrite(t, stream, payload)
	before := testSnapshot(client.(*association))
	time.Sleep(2 * time.Second)
	after := testSnapshot(client.(*association))
	probes := after.probes - before.probes
	if probes > 20 {
		t.Fatalf("%d probes were sent in two seconds", probes)
	}
	if after.inFlight > 64 {
		t.Fatalf("%d packets are in flight", after.inFlight)
	}

	link.setLoss(0)
	readAll(t, accepted, len(payload))
}

func mustWrite(t *testing.T, stream *Stream, payload []byte) []byte {
	t.Helper()
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestIdleTimeoutSparesActiveStreams(t *testing.T) {
	client, server, _ := testSetup(t, Options{IdleTimeout: 200 * time.Millisecond}, Options{IdleTimeout: 200 * time.Millisecond})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Context().Done():
		t.Fatalf("the client ended with %v", context.Cause(client.Context()))
	case <-time.After(time.Second):
	}
	_ = accepted.Close()
	_ = stream.Close()
	waitDone(t, client.Context(), 3*time.Second)
	if cause := context.Cause(client.Context()); !errors.Is(cause, ErrIdleTimeout) {
		t.Fatalf("the client ended with %v", cause)
	}
}
