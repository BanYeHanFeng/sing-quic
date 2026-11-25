package udpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

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
	if _, err = accepted.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the stream ended with %v", err)
	}
	if err = accepted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamHalfClose(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("more")); err == nil {
		t.Fatal("a closed write side accepted data")
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := readAll(t, accepted, len("request"))
	if string(request) != "request" {
		t.Fatalf("read %q", request)
	}
	if _, err = accepted.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the peer's write side did not end: %v", err)
	}
	if _, err = accepted.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err = accepted.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response := readAll(t, stream, len("response"))
	if string(response) != "response" {
		t.Fatalf("read %q", response)
	}
	if _, err = stream.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the stream ended with %v", err)
	}
}

func TestStreamStarvation(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 20*time.Second)
	first, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(64 * 1024)
	if _, err = first.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = second.Write(payload); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		accepted, acceptErr := server.AcceptStream(ctx)
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		go func() {
			_, _ = io.Copy(io.Discard, accepted)
		}()
	}
	_ = second.CloseWrite()
	_ = first.CloseWrite()
}

func TestStreamReassembly(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write(testPayload(16 * 1024)); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	var read int
	for {
		n, readErr := accepted.Read(buffer)
		read += n
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
	}
	if read != 16*1024 {
		t.Fatalf("read %d bytes", read)
	}
}

func TestStreamDeadline(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, 5); string(read) != "first" {
		t.Fatalf("read %q", read)
	}
	if err = accepted.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = accepted.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the read ended with %v", err)
	}
	if err = accepted.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, 4); string(read) != "late" {
		t.Fatalf("read %q", read)
	}
	_ = stream.Close()
	_ = accepted.Close()
}

func TestStreamEndsWithAssociation(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("open")); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = server.CloseWithError(nil); err != nil {
		t.Fatal(err)
	}
	if _, err = accepted.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream of an ended connection still reads")
	}
	select {
	case <-stream.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not notice that the peer closed")
	}
	if _, err = stream.Write([]byte("more")); err == nil {
		t.Fatal("a stream of an ended connection still writes")
	}
}

func (s *Stream) Context() context.Context {
	return s.conn.Context()
}

func TestStreamResetByClose(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(8 * 1024)
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if read := readAll(t, accepted, len(payload)); !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err = accepted.Read(make([]byte, 1)); err != io.EOF && !errors.Is(err, ErrStreamReset) {
		t.Fatalf("the peer's read ended with %v", err)
	}
	if _, err = accepted.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the peer's write ended with %v", err)
	}
}

func TestStreamCloseDeliversWhatWasWritten(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload(64 * 1024)
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	read := make([]byte, 0, len(payload))
	for {
		n, readErr := accepted.Read(buffer)
		read = append(read, buffer[:n]...)
		if readErr == nil {
			continue
		}
		if readErr != io.EOF && !errors.Is(readErr, ErrStreamReset) {
			t.Fatalf("the peer's read ended with %v", readErr)
		}
		break
	}
	if !bytes.Equal(read, payload) {
		t.Fatalf("the peer read %d of %d bytes", len(read), len(payload))
	}
}

func TestStreamChurn(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	go func() {
		for {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, stream)
				_ = stream.CloseWrite()
				_ = stream.Close()
			}()
		}
	}()
	for round := range 40 {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write([]byte{byte(round)}); err != nil {
			t.Fatal(err)
		}
		if err = stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(io.Discard, stream); err != nil {
			t.Fatal(err)
		}
		if err = stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamsPastTheInitialNumber(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 30*time.Second)
	go func() {
		for {
			stream, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				_, _ = stream.Write([]byte("x"))
				_ = stream.CloseWrite()
				_, _ = io.Copy(io.Discard, stream)
				_ = stream.Close()
			}()
		}
	}()
	for round := range initialStreams + 40 {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("opening stream %d: %v", round, err)
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if err = stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if read := readAll(t, stream, 1); len(read) != 1 {
			t.Fatal("no answer")
		}
		if err = stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamSlotIsHeldUntilAccepted(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 20*time.Second)
	for range initialStreams {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if err = stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = accepted.Close()
	late, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("the peer never gave a slot back: %v", err)
	}
	_ = late.Close()
}

func TestStreamLocalAddrIsTheDestination(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stream.ID() != 0 {
		t.Fatalf("the first stream has id %d", stream.ID())
	}
	if _, isUDP := stream.LocalAddr().(*net.UDPAddr); !isUDP {
		t.Fatalf("local address %v", stream.LocalAddr())
	}
	if _, err = stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ID() != stream.ID() {
		t.Fatalf("the accepted stream has id %d, the opened one %d", accepted.ID(), stream.ID())
	}
	_ = stream.Close()
	_ = accepted.Close()
}

func TestOnlyTheDialingSideOpensStreams(t *testing.T) {
	_, server, _ := testSetup(t, Options{}, Options{})
	if _, err := server.OpenStream(testContext(t, time.Second)); err == nil {
		t.Fatal("the accepting side opened a stream")
	}
}

func TestStreamBeyondThePeerLimitIsAnError(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write([]byte("open")); err != nil {
		t.Fatal(err)
	}
	if _, err = server.AcceptStream(ctx); err != nil {
		t.Fatal(err)
	}
	if err = openStreamFrame(t, server.Conn, initialStreams, "beyond"); err == nil {
		t.Fatal("a stream beyond the limit was accepted")
	}
	select {
	case <-server.Context().Done():
		t.Fatalf("the connection ended with %v", context.Cause(server.Context()))
	default:
	}
}

func TestStreamLargeTransfer(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 60*time.Second)
	payload := testPayload(2 * 1024 * 1024)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		if _, writeErr := stream.Write(payload); writeErr != nil {
			done <- writeErr
			return
		}
		done <- stream.CloseWrite()
	}()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	read := readAll(t, accepted, len(payload))
	t.Log("read", len(read), "in", time.Since(start))
	if !bytes.Equal(read, payload) {
		t.Fatal("payload changed")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
