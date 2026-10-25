package udpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func readAll(t *testing.T, stream *Stream, expected int) []byte {
	t.Helper()
	read := make([]byte, 0, expected)
	buffer := make([]byte, 32*1024)
	for len(read) < expected {
		n, err := stream.Read(buffer)
		if err != nil {
			t.Fatalf("read %d of %d bytes: %v", len(read), expected, err)
		}
		read = append(read, buffer[:n]...)
	}
	return read
}

func testPayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index*7 + index/251)
	}
	return payload
}

// TestStreamRoundTrip requires a stream to carry data in both directions and each
// half to end on its own.
func TestStreamRoundTrip(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(100 * 1024)
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		if closeErr := stream.CloseWrite(); closeErr != nil {
			t.Errorf("close write: %v", closeErr)
		}
	}()

	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, len(payload)); !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
	if n, err := accepted.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("read after the end of the stream: %d, %v", n, err)
	}

	// The other direction is still open.
	reply := testPayload(4 * 1024)
	_, err = accepted.Write(reply)
	if err != nil {
		t.Fatal(err)
	}
	err = accepted.CloseWrite()
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, stream, len(reply)); !bytes.Equal(read, reply) {
		t.Fatal("the reply changed on the way")
	}
	if n, err := stream.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("read after the end of the reply: %d, %v", n, err)
	}
}

// TestStreamHalfClose requires a half-closed stream to keep working in the other
// direction, which is what a proxied connection that went quiet in one direction
// needs.
func TestStreamHalfClose(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := testPayload(1024)
	_, err = stream.Write(request)
	if err != nil {
		t.Fatal(err)
	}
	err = stream.CloseWrite()
	if err != nil {
		t.Fatal(err)
	}

	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, len(request)); !bytes.Equal(read, request) {
		t.Fatal("the request changed on the way")
	}
	reply := testPayload(2048)
	_, err = accepted.Write(reply)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, stream, len(reply)); !bytes.Equal(read, reply) {
		t.Fatal("the reply changed on the way")
	}
	if _, err = stream.Write([]byte("more")); err == nil {
		t.Fatal("wrote to a half-closed stream")
	}
}

// TestStreamWindow requires a transfer larger than the stream window to complete,
// which it can only do if the receiver moves the window forward as it reads.
func TestStreamWindow(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(3 * initialStreamWindow)
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		_ = stream.CloseWrite()
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, len(payload)); !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
}

// TestStreamStarvation requires one stream that nobody reads to stop at its own
// window without taking the association window with it: another stream has to keep
// working.
func TestStreamStarvation(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stalled, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blockedWrite := make(chan error, 1)
	go func() {
		// Twice the stream window, which the peer never reads.
		_, writeErr := stalled.Write(testPayload(2 * initialStreamWindow))
		blockedWrite <- writeErr
	}()
	if _, err = server.AcceptStream(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-blockedWrite:
		t.Fatalf("the write to a stream nobody reads returned: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// The other stream is unaffected.
	other, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(64 * 1024)
	go func() {
		if _, writeErr := other.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		_ = other.CloseWrite()
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, len(payload)); !bytes.Equal(read, payload) {
		t.Fatal("the other stream did not get through")
	}
}

// TestStreamReassembly requires data that arrives out of order to be handed to the
// application in order, once the hole was filled.
func TestStreamReassembly(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	stream, err := client.OpenStream(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// The count a segment reports is how far the highest offset moved, so the
	// segment that arrived first pays for the hole in front of it.
	for _, segment := range []struct {
		data   string
		offset uint64
		raised int
	}{
		{"ijkl", 8, 12},
		{"abcd", 0, 0},
		{"efgh", 4, 0},
	} {
		received, pushErr := stream.push(segment.offset, []byte(segment.data), false)
		if pushErr != nil {
			t.Fatal(pushErr)
		}
		if received != segment.raised {
			t.Fatalf("segment at %d raised the highest offset by %d", segment.offset, received)
		}
	}
	read := make([]byte, 16)
	n, err := stream.Read(read)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read[:n], []byte("abcdefghijkl")) {
		t.Fatalf("read %q", read[:n])
	}

	// A duplicate that arrives after the fact reports nothing new and does not
	// disturb what is buffered.
	received, err := stream.push(4, []byte("efgh"), false)
	if err != nil {
		t.Fatal(err)
	}
	if received != 0 {
		t.Fatalf("a duplicate reported %d new bytes", received)
	}
	if _, err = stream.push(12, []byte("mnop"), true); err != nil {
		t.Fatal(err)
	}
	read = make([]byte, 16)
	n, err = stream.Read(read)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read[:n], []byte("mnop")) {
		t.Fatalf("read %q", read[:n])
	}
	if _, err = stream.Read(read); err != io.EOF {
		t.Fatalf("read after the end: %v", err)
	}
}

// TestStreamBeyondWindow rejects data that the receiver did not grant credit for.
func TestStreamBeyondWindow(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	stream, err := client.OpenStream(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.push(initialStreamWindow, make([]byte, 1), false); err == nil {
		t.Fatal("data beyond the stream window was accepted")
	}
}

// TestStreamDeadline requires a read that nothing arrives for to end at its
// deadline rather than waiting for the association to end.
func TestStreamDeadline(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	stream, err := client.OpenStream(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	err = stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("a read without data returned")
	}
}

// TestStreamEndsWithAssociation requires a blocked reader to learn why the
// association ended rather than waiting for a read that will never come.
func TestStreamEndsWithAssociation(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	stream, err := client.OpenStream(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := stream.Read(make([]byte, 1))
		readResult <- readErr
	}()
	_ = client.CloseWithError(context.Canceled)
	select {
	case err = <-readResult:
		if err == nil {
			t.Fatal("the read returned without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("the read did not end with the association")
	}
}

func TestCredit(t *testing.T) {
	window := credit{limit: 100}
	if window.available() != 100 {
		t.Fatalf("%d bytes available", window.available())
	}
	if took := window.take(30); took != 30 {
		t.Fatalf("took %d bytes", took)
	}
	if took := window.take(100); took != 70 {
		t.Fatalf("took %d bytes from a window of 70", took)
	}
	if window.available() != 0 {
		t.Fatalf("%d bytes available", window.available())
	}
	// A window only moves forward, and moving it forward is what wakes a writer.
	if window.give(50) {
		t.Fatal("the window moved backwards")
	}
	if !window.give(200) {
		t.Fatal("the window did not move forward")
	}
	if window.available() != 100 {
		t.Fatalf("%d bytes available after the window moved", window.available())
	}
}

// TestStreamLargeTransfer requires a transfer larger than the association window
// to complete, which it can only do if the association window is moved forward as
// data is read and not just the window of the stream.
func TestStreamLargeTransfer(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 120*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(2 * initialConnectionWindow)
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		_ = stream.CloseWrite()
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := make([]byte, 0, len(payload))
	buffer := make([]byte, 64*1024)
	for len(read) < len(payload) {
		n, readErr := accepted.Read(buffer)
		if readErr != nil {
			t.Fatalf("read %d of %d bytes: %v", len(read), len(payload), readErr)
		}
		read = append(read, buffer[:n]...)
	}
	if !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
}

// streamCount is how many streams the association still knows about, which is what
// says whether a stream that ended was released or left behind.
func streamCount(t *testing.T, conn Association) int {
	t.Helper()
	a := conn.(*association)
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	return len(a.streams)
}

func waitStreamCount(t *testing.T, conn Association, expected int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		count := streamCount(t, conn)
		if count == expected {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d streams are still open, expected %d", count, expected)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestStreamResetByClose requires closing a stream the peer still writes to to tell
// the peer, to release the stream here at once, and to leave the association
// working.
func TestStreamResetByClose(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Write([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, 7); string(read) != "request" {
		t.Fatalf("the request arrived as %q", read)
	}
	// The peer never closed its half, so the stream is abandoned rather than
	// finished, and the peer is what hears about it.
	err = stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	if count := streamCount(t, client); count != 0 {
		t.Fatalf("%d streams are still open after a close", count)
	}
	buffer := make([]byte, 1)
	_, err = accepted.Read(buffer)
	if !errors.Is(err, net.ErrClosed) && err != io.EOF {
		t.Fatalf("read on a closed stream returned %v", err)
	}
	waitStreamCount(t, server, 0)
	if _, err = accepted.Write([]byte("reply")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write on a stream the peer closed returned %v", err)
	}

	// The association is one stream wider than before, not closed.
	other, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = other.Write([]byte("next"))
		_ = other.CloseWrite()
	}()
	next, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, next, 4); string(read) != "next" {
		t.Fatalf("the next stream carried %q", read)
	}
}

// TestStreamResetEndsWrite requires a stream the peer ended to stop a write that
// waits for credit, instead of leaving it waiting for a window that will never
// move.
func TestStreamResetEndsWrite(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Twice the stream window, so the write has to wait for the peer to read.
	blocked := make(chan error, 1)
	go func() {
		_, writeErr := stream.Write(testPayload(2 * initialStreamWindow))
		blocked <- writeErr
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-blocked:
		t.Fatalf("the write returned before the peer ended the stream: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	err = accepted.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-blocked:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the write returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the write waited for a stream the peer ended")
	}
}

// TestStreamEndedIgnoresLateFrames requires data that arrives for a stream this end
// already ended to be dropped, not taken for a stream the peer opens now.
func TestStreamEndedIgnoresLateFrames(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, 5); string(read) != "hello" {
		t.Fatalf("the stream carried %q", read)
	}
	id := accepted.ID()
	if err = accepted.Close(); err != nil {
		t.Fatal(err)
	}
	waitStreamCount(t, server, 0)
	// What the client sent before it heard about the end arrives now.
	err = server.(*association).handleStreamFrame(streamData{streamID: id, data: []byte("late")})
	if err != nil {
		t.Fatalf("a frame for an ended stream was rejected: %v", err)
	}
	if count := streamCount(t, server); count != 0 {
		t.Fatalf("a frame for an ended stream opened %d streams", count)
	}
	select {
	case late := <-server.(*association).acceptStream:
		t.Fatalf("a frame for an ended stream was accepted as stream %d", late.ID())
	default:
	}
	// The client hears about the end too, and its write half goes with it.
	waitStreamCount(t, client, 0)
	if _, err = stream.Write([]byte("still open")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write on a stream the peer ended returned %v", err)
	}
}

// TestStreamResetCode requires the code of a reset to reach the application as an
// error it can tell apart from a stream that ended on purpose.
func TestStreamResetCode(t *testing.T) {
	normal := resetCodeNormal.err()
	if !errors.Is(normal, net.ErrClosed) {
		t.Fatalf("a normal reset is reported as %v", normal)
	}
	failed := resetCode(3).err()
	if errors.Is(failed, net.ErrClosed) {
		t.Fatal("a failed stream is reported as a closed connection")
	}
	var resetErr StreamResetError
	if !errors.As(failed, &resetErr) || resetErr.Code != 3 {
		t.Fatalf("a failed stream is reported as %v", failed)
	}
}
