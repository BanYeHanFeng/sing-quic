package udpx

import (
	"context"
	"errors"
	"testing"
	"time"
)

func openStreamFrame(t *testing.T, c *Conn, index uint32, payload string) error {
	t.Helper()
	frame := appendStreamHeader(nil, index, 0, false, len(payload))
	frame = append(frame, payload...)
	return c.handleStreamFrame(frameTypeStream, frame[frameHeaderLen:])
}

// acceptStreams 收下 n 条流，按 ID 索引：OnStream 每条流一个新 goroutine，到达顺序不保证。
func acceptStreams(t *testing.T, ctx context.Context, peer *testPeer, count int) map[uint32]*Stream {
	t.Helper()
	streams := make(map[uint32]*Stream, count)
	for len(streams) < count {
		stream, err := peer.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams[stream.ID()] = stream
	}
	return streams
}

func TestPeerOpensStreamsOutOfOrder(t *testing.T) {
	_, server, _ := testSetup(t, Options{MTU: mtuIPv4}, Options{MTU: mtuIPv4})
	c := server.Conn
	ctx := testContext(t, 5*time.Second)
	if err := openStreamFrame(t, c, 0, "zero"); err != nil {
		t.Fatal(err)
	}
	if err := openStreamFrame(t, c, 2, "two"); err != nil {
		t.Fatalf("stream 2 arrived before stream 1: %v", err)
	}
	streams := acceptStreams(t, ctx, server, 2)
	for id, expected := range map[uint32]string{0: "zero", 2: "two"} {
		stream, loaded := streams[id]
		if !loaded {
			t.Fatalf("stream %d was not accepted", id)
		}
		if read := readAll(t, stream, len(expected)); string(read) != expected {
			t.Fatalf("stream %d read %q", id, read)
		}
	}
	if err := openStreamFrame(t, c, 1, "one"); err != nil {
		t.Fatalf("stream 1 arrived after stream 2: %v", err)
	}
	if read := readAll(t, acceptStreams(t, ctx, server, 1)[1], 3); string(read) != "one" {
		t.Fatalf("stream 1 read %q", read)
	}
	if err := openStreamFrame(t, c, 1, "one"); err != nil {
		t.Fatalf("stream 1 arrived again: %v", err)
	}
	select {
	case <-c.Context().Done():
		t.Fatalf("the connection ended with %v", context.Cause(c.Context()))
	default:
	}
}

func TestProbeRetransmitsWithoutAFlood(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, peers := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{})
	ctx := testContext(t, 30*time.Second)
	client := testDial(t, ctx, udpConn(t), link.clientAddr(), credential, Options{MTU: mtuIPv4})
	defer client.CloseWithError(nil)
	server := testAccept(t, ctx, peers)
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
	before := link.sentFromClient.Load()
	time.Sleep(2 * time.Second)
	if sent := link.sentFromClient.Load() - before; sent > 64 {
		t.Fatalf("%d packets were sent in two seconds of silence", sent)
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
