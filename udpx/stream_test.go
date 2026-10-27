package udpx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
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
		// More than the peer may hold: two budgets of arrival is the ceiling this
		// end grants before the application reads anything.
		_, writeErr := stalled.Write(testPayload(2*streamWindow + 4096))
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
	// More than the peer may hold, so the write has to wait for the peer to read.
	blocked := make(chan error, 1)
	go func() {
		_, writeErr := stream.Write(testPayload(2*streamWindow + 4096))
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

// TestStreamFinBeforeData requires a FIN that arrives before the data in front of it
// to end the stream without dropping what is still on the way. The FIN is an offset
// like any other, so a path that reordered it did not deliver a stream that ends
// empty — and a stream this end has finished writing is still a stream this end is
// reading.
func TestStreamFinBeforeData(t *testing.T) {
	conn := newFakeConn()
	listenerConn := udpConn(t)
	password := NewPassword("password")
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	client, err := Dial(testContext(t, 5*time.Second), conn, listenerConn.LocalAddr(), password, Options{})
	if err != nil {
		// The fake socket answers nothing, so the stream is driven directly below.
		_ = client
	}
	receiver := newTestAssociation(t, newFakeConn())
	ctx := testContext(t, 10*time.Second)
	// A read that never ends is the failure this is here to catch, so it is given a
	// deadline to end with.
	deadline := time.Now().Add(10 * time.Second)
	id := uint32(0)
	// The peer opens a stream and sends one frame of it.
	err = receiver.handleStreamFrame(streamData{streamID: id, data: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := receiver.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, 5); string(read) != "hello" {
		t.Fatalf("the stream carried %q", read)
	}
	// This end answers and closes its half, so both halves are now closed from its
	// own point of view — but the peer's FIN has not arrived yet.
	if _, err = accepted.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	if err = accepted.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The peer's FIN arrives first, before the data in front of it.
	err = receiver.handleStreamFrame(streamData{streamID: id, offset: 10, fin: true})
	if err != nil {
		t.Fatal(err)
	}
	// The data it covers arrives after it, and has to be delivered all the same.
	err = receiver.handleStreamFrame(streamData{streamID: id, offset: 5, data: []byte("again")})
	if err != nil {
		t.Fatal(err)
	}
	accepted.SetReadDeadline(deadline)
	if read := readAll(t, accepted, 5); string(read) != "again" {
		t.Fatalf("the stream carried %q after its FIN arrived first", read)
	}
	// What arrives for a stream that ended on both sides and was read whole is
	// dropped: there is nothing left for it to change.
	err = receiver.handleStreamFrame(streamData{streamID: id, offset: 5, data: []byte("again")})
	if err != nil {
		t.Fatalf("a frame for an ended stream was rejected: %v", err)
	}
	if count := streamCount(t, receiver); count != 0 {
		t.Fatalf("%d streams are open after the stream ended", count)
	}
}

// waitSendIdle waits until the send path has nothing left to do: nothing in flight,
// and nothing waiting to be framed. Only then is everything that was written
// acknowledged, and only then is the memory it went into back in the pool.
func waitSendIdle(t *testing.T, conn *association) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.flightMu.Lock()
		packets := conn.inFlight.len()
		conn.flightMu.Unlock()
		queued := conn.queueLength()
		if packets == 0 && queued == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d packets in flight and %d frames queued after an acknowledgement", packets, queued)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSendChunkRelease requires the count a chunk carries to be what its two kinds
// of holder say: the send buffer while it still has bytes to frame, and one per
// frame cut from it. The memory goes back to the pool when the last one is gone,
// and not before.
func TestSendChunkRelease(t *testing.T) {
	chunk := &sendChunk{buf: make([]byte, sendChunkSize)}
	chunk.retain()
	chunk.retain()
	chunk.end = 100
	chunk.start = 40
	chunk.release()
	if holds, start, end := chunk.holds.Load(), chunk.start, chunk.end; holds != 1 || start != 40 || end != 100 {
		t.Fatalf("a chunk once given up is at %d:%d and held %d times", start, end, holds)
	}
	chunk.release()
	if holds, start, end := chunk.holds.Load(), chunk.start, chunk.end; holds != 0 || start != 0 || end != 0 {
		t.Fatalf("a chunk nobody holds is at %d:%d and held %d times", start, end, holds)
	}
}

// TestSendChunksHeldByTheSendBuffer requires the send buffer to hold every chunk it
// has bytes in: a chunk is handed out again once nobody holds it, so a chunk the
// send buffer forgot to hold is a chunk whose bytes are overwritten while they are
// still waiting to be framed. What the frames of a write hold is on top of that, and
// it is what TestSendChunksHeldUntilAcknowledged is about.
func TestSendChunksHeldByTheSendBuffer(t *testing.T) {
	stream := newStream(&association{maxPayload: 1024}, 4, initialStreamWindow)
	stream.bufferSendData(testPayload(2*sendChunkSize + 1000))
	if count := len(stream.sendChunks); count != 3 {
		t.Fatalf("%d chunks for two chunks and a bit of payload", count)
	}
	for index, chunk := range stream.sendChunks {
		if holds := chunk.holds.Load(); holds != 1 {
			t.Fatalf("chunk %d of the send buffer is held %d times", index, holds)
		}
	}
	// A write smaller than what the last chunk has left fills that room rather than
	// taking another chunk.
	stream.bufferSendData(testPayload(24))
	if count := len(stream.sendChunks); count != 3 {
		t.Fatalf("%d chunks after a write that fitted in the last one", count)
	}
	last := stream.sendChunks[2]
	if last.end != 1024 {
		t.Fatalf("the last chunk ends at %d after two writes that fit in it", last.end)
	}
	stream.releaseSendChunks()
	if len(stream.sendChunks) != 0 {
		t.Fatalf("%d chunks left after the send buffer let them go", len(stream.sendChunks))
	}
	if holds := last.holds.Load(); holds != 0 {
		t.Fatalf("a chunk the send buffer let go is still held %d times", holds)
	}
	if last.start != 0 || last.end != 0 {
		t.Fatalf("a chunk nobody holds is at %d:%d", last.start, last.end)
	}
}

// checkSendChunkHolds reports what the count of a send buffer chunk disagrees with:
// the frames that still point into it. The send path is read first and the flight
// table second, both under sendMu and in that order, because that is the order the
// send path itself takes them in — and because a frame that is in a packet of the
// batch being handed over is in the flight table and nowhere else.
func checkSendChunkHolds(conn *association) string {
	references := make(map[*sendChunk]int)
	count := func(frames []outFrame) {
		for index := range frames {
			if chunk := frames[index].stream.chunk; chunk != nil {
				references[chunk]++
			}
		}
	}
	conn.sendMu.Lock()
	count(conn.queue.frames)
	for index := range conn.batch.pending {
		count(conn.batch.pending[index].sent.frames)
	}
	conn.flightMu.Lock()
	for _, packet := range conn.inFlight.packets {
		if packet.removed {
			continue
		}
		count(packet.frames)
	}
	conn.flightMu.Unlock()
	defer conn.sendMu.Unlock()
	for chunk, carried := range references {
		if holds := int(chunk.holds.Load()); holds < carried {
			return fmt.Sprintf("a chunk of the send buffer is held %d times for %d frames that point into it", holds, carried)
		}
	}
	return ""
}

// TestSendChunksHoldWhatPointsIntoThem requires the count a chunk carries to stay
// above the frames that point into it, whatever the send path does with them: a
// packet the peer acknowledged gives its frames up, a lost one does not, and a
// retransmission points into the same chunk again. The transfer runs over a path
// that loses a fifth of its packets, so chunks are released and taken again while
// other frames of theirs are still on their way — which is where a count that is one
// short stops being memory that is kept longer than needed and becomes bytes that
// changed on the way.
func TestSendChunksHoldWhatPointsIntoThem(t *testing.T) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{loss: 0.2})
	ctx := testContext(t, 60*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	conn, isAssociation := client.(*association)
	if !isAssociation {
		t.Fatal("client is not an association")
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(256 * 1024)
	sender, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	checked := make(chan struct{})
	go func() {
		defer close(checked)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if problem := checkSendChunkHolds(conn); problem != "" {
				t.Errorf("%s", problem)
				return
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	go func() {
		if _, writeErr := sender.Write(payload); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		if closeErr := sender.CloseWrite(); closeErr != nil {
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
	close(stop)
	<-checked
}

// TestSendChunksHeldUntilAcknowledged requires the memory of a write to stay with
// the frames that carry it: the write that follows takes memory of its own, because
// the first one is still on its way to the peer. A chunk that came back too early
// is a chunk whose bytes are overwritten before they are sent — the frames still
// waiting in the queue point into it — and what the peer reads at the end is then
// the write that came after.
func TestSendChunksHeldUntilAcknowledged(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	sender, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := testPayload(1 << 20)
	second := testPayload(1 << 20)
	for index := range second {
		second[index] ^= 0xff
	}
	// The two writes fill the stream window between them, so the second one waits
	// for the peer to read the first: they are the shortest writes that cannot be
	// held at the same time.
	go func() {
		if _, writeErr := sender.Write(first); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		if _, writeErr := sender.Write(second); writeErr != nil {
			t.Errorf("write: %v", writeErr)
			return
		}
		if closeErr := sender.CloseWrite(); closeErr != nil {
			t.Errorf("close write: %v", closeErr)
		}
	}()
	receiver, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := readAll(t, receiver, len(first)+len(second))
	if !bytes.Equal(read[:len(first)], first) {
		t.Fatal("the first write did not arrive as it was written")
	}
	if !bytes.Equal(read[len(first):], second) {
		t.Fatal("the second write did not arrive as it was written")
	}
}

// TestSendChunkReused requires the memory a transfer went into to be reused by the
// next one: what the peer acknowledged is back in the pool, so a transfer made
// again allocates no chunk at all. Without that, every byte sent is a byte of
// garbage, and collecting it is what the send path spends its time on.
func TestSendChunkReused(t *testing.T) {
	// A collection empties the pool, which would measure the collection rather
	// than the reuse.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	client, server, _ := testSetup(t, Options{}, Options{})
	conn, isAssociation := client.(*association)
	if !isAssociation {
		t.Fatal("client is not an association")
	}
	ctx := testContext(t, 30*time.Second)
	sender, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(256 << 10)
	var receiver *Stream
	transfer := func() int64 {
		t.Helper()
		allocated := sendChunksAllocated.Load()
		if _, err = sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		// The stream exists on the peer as soon as data for it arrives.
		if receiver == nil {
			receiver, err = server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
		}
		if read := readAll(t, receiver, len(payload)); !bytes.Equal(read, payload) {
			t.Fatal("the bytes the peer read are not the ones written")
		}
		waitSendIdle(t, conn)
		return sendChunksAllocated.Load() - allocated
	}
	transfer()
	if allocated := transfer(); allocated != 0 {
		t.Fatalf("a transfer the peer read whole allocated %d chunks of the send buffer", allocated)
	}
}
