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

func TestStreamStarvation(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	stalled, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blockedWrite := make(chan error, 1)
	go func() {
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

func TestStreamReassembly(t *testing.T) {
	client, _, _ := testSetup(t, Options{}, Options{})
	stream, err := client.OpenStream(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
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
	err = stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	waitStreamCount(t, client, 0)
	buffer := make([]byte, 1)
	_, err = accepted.Read(buffer)
	if !errors.Is(err, net.ErrClosed) && err != io.EOF {
		t.Fatalf("read on a closed stream returned %v", err)
	}
	waitStreamCount(t, server, 0)
	if _, err = accepted.Write([]byte("reply")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write on a stream the peer closed returned %v", err)
	}

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

type droppingConn struct {
	net.PacketConn
	longer int
	drops  int
}

func (c *droppingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, from, err
		}
		if c.drops > 0 && n > c.longer {
			c.drops--
			continue
		}
		return n, from, nil
	}
}

func TestStreamCloseKeepsTheLastPacket(t *testing.T) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(&droppingConn{
		PacketConn: listenerConn,
		longer:     maxPacketSize - 16,
		drops:      1,
	}, testVerifier{password}, Options{})
	defer listener.Close()
	ctx := testContext(t, 30*time.Second)
	client, err := Dial(ctx, udpConn(t), listenerConn.LocalAddr(), password, Options{MTU: mtuIPv4})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(nil)

	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(client.(*association).streamDataLen())
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read, err := readToEnd(accepted, len(payload))
	if err != nil {
		t.Fatalf("the stream ended after %d of %d bytes: %v", len(read), len(payload), err)
	}
	if !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
}

func TestStreamResetEndsWrite(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
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
	waitStreamCount(t, client, 0)
	if _, err = stream.Write([]byte("still open")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write on a stream the peer ended returned %v", err)
	}
}

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

func TestStreamFinBeforeData(t *testing.T) {
	conn := newFakeConn()
	listenerConn := udpConn(t)
	password := NewPassword("password")
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{MTU: mtuIPv4})
	defer listener.Close()
	client, err := Dial(testContext(t, 5*time.Second), conn, listenerConn.LocalAddr(), password, Options{MTU: mtuIPv4})
	if err != nil {
		_ = client
	}
	receiver := newTestAssociation(t, newFakeConn())
	ctx := testContext(t, 10*time.Second)
	deadline := time.Now().Add(10 * time.Second)
	id := uint32(0)
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
	if _, err = accepted.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	if err = accepted.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	err = receiver.handleStreamFrame(streamData{streamID: id, offset: 10, fin: true})
	if err != nil {
		t.Fatal(err)
	}
	err = receiver.handleStreamFrame(streamData{streamID: id, offset: 5, data: []byte("again")})
	if err != nil {
		t.Fatal(err)
	}
	accepted.SetReadDeadline(deadline)
	if read := readAll(t, accepted, 5); string(read) != "again" {
		t.Fatalf("the stream carried %q after its FIN arrived first", read)
	}
	err = receiver.handleStreamFrame(streamData{streamID: id, offset: 5, data: []byte("again")})
	if err != nil {
		t.Fatalf("a frame for an ended stream was rejected: %v", err)
	}
	if count := streamCount(t, receiver); count != 0 {
		t.Fatalf("%d streams are open after the stream ended", count)
	}
}

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

func checkSendChunkHolds(conn *association) string {
	references := make(map[*sendChunk]int)
	count := func(frames []outFrame) {
		for index := range frames {
			if chunk := frames[index].streamFrame.chunk; chunk != nil {
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

func TestSendChunksHoldWhatPointsIntoThem(t *testing.T) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{MTU: mtuIPv4})
	defer listener.Close()
	link := newSimulatedLink(t, listenerConn.LocalAddr(), linkOptions{loss: 0.2, lossReturn: 0.2})
	ctx := testContext(t, 60*time.Second)
	client, err := Dial(ctx, udpConn(t), link.clientAddr(), password, Options{MTU: mtuIPv4})
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

func TestSendChunkReused(t *testing.T) {
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

func TestOpenStreamWaitsForThePeersCredit(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	streams := make([]*Stream, 0, initialStreams)
	for range initialStreams {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
	}
	opened := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(ctx)
		opened <- err
	}()
	select {
	case err := <-opened:
		t.Fatalf("a stream was opened past the credit the peer granted: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := streams[0].Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-opened:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the opener is still waiting for credit the peer granted")
	}
	if count := streamCount(t, client); count != initialStreams+1 {
		t.Fatalf("%d streams are open, expected %d", count, initialStreams+1)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ID() != streams[0].ID() {
		t.Fatalf("the peer accepted stream %d, expected %d", accepted.ID(), streams[0].ID())
	}
}

func TestStreamsPastTheInitialNumber(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	const count = initialStreams + 64
	for index := range count {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("stream %d: %v", index, err)
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatalf("stream %d: %v", index, err)
		}
	}
	for index := range count {
		accepted, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("accept %d: %v", index, err)
		}
		if read, readErr := readExactly(accepted, 1); readErr != nil || read[0] != 0 {
			t.Fatalf("accept %d: the first byte is %v, %v", index, read, readErr)
		}
		if err = accepted.Close(); err != nil {
			t.Fatalf("accept %d: %v", index, err)
		}
	}
	waitStreamCount(t, server, 0)
	waitStreamCount(t, client, 0)
}

func TestStreamSlotIsHeldUntilAccepted(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	peerLimit := func() uint32 {
		a := server.(*association)
		a.streamsMu.Lock()
		defer a.streamsMu.Unlock()
		return a.peerStreamLimit
	}
	open := func() *Stream {
		t.Helper()
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		return stream
	}
	open()
	if _, err := server.AcceptStream(ctx); err != nil {
		t.Fatal(err)
	}
	if limit := peerLimit(); limit != streamBudget {
		t.Fatalf("the peer allows %d streams, expected the budget %d", limit, streamBudget)
	}
	second := open()
	waitStreamCount(t, server, 2)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	waitStreamCount(t, server, 1)
	if limit := peerLimit(); limit != streamBudget {
		t.Fatalf("the peer allows %d streams after a stream it never took ended, expected %d", limit, streamBudget)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ID() != second.ID() {
		t.Fatalf("the peer accepted stream %d, expected %d", accepted.ID(), second.ID())
	}
	if limit := peerLimit(); limit != streamBudget+1 {
		t.Fatalf("the peer allows %d streams after the stream was taken, expected %d", limit, streamBudget+1)
	}
}

func TestStreamLateFramePastTheRing(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	late := uint32(0)
	for index := range 2 * endedStreamsCount {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			late = stream.ID()
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if _, err = server.AcceptStream(ctx); err != nil {
			t.Fatal(err)
		}
		if err = stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	err := client.(*association).handleStreamFrame(streamData{streamID: late, data: []byte("late")})
	if err != nil {
		t.Fatalf("a frame for an ended stream was rejected: %v", err)
	}
}
