package udpx

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestIsNormalClose(t *testing.T) {
	for _, err := range []error{
		nil,
		net.ErrClosed,
		io.EOF,
		context.Canceled,
		ErrIdleTimeout,
		ErrProbeTimeout,
		ErrStreamReset,
	} {
		if !IsNormalClose(err) {
			t.Fatalf("%v is not a normal close", err)
		}
	}
	for _, err := range []error{
		errAuthentication,
		errShortFrame,
		net.UnknownNetworkError("tcp"),
	} {
		if IsNormalClose(err) {
			t.Fatalf("%v is a normal close", err)
		}
	}
}

func waitGoroutines(t *testing.T, baseline int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var current int
	for time.Now().Before(deadline) {
		current = runtime.NumGoroutine()
		if current <= baseline {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	buffer := make([]byte, 1<<20)
	n := runtime.Stack(buffer, true)
	t.Fatalf("%d goroutines are left after the connection ended, baseline %d\n%s", current, baseline, buffer[:n])
}

func TestCloseLeavesNoGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()
	client, server, listener := testSetup(t, Options{}, Options{})
	ctx := testContext(t, 10*time.Second)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Write(testPayload(64 * 1024)); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, accepted); err != nil {
		t.Fatal(err)
	}
	_ = accepted.Close()
	_ = stream.Close()
	_ = client.CloseWithError(nil)
	_ = server.CloseWithError(nil)
	_ = listener.Close()
	waitGoroutines(t, baseline, 5*time.Second)
}

func TestPeerCloseEndsTheAssociation(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	if err := client.CloseWithError(nil); err != nil {
		t.Fatal(err)
	}
	waitDone(t, server.Context(), 3*time.Second)
	if cause := context.Cause(server.Context()); !errors.Is(cause, net.ErrClosed) {
		t.Fatalf("the server ended with %v", cause)
	}
}

// 空闲超时由发送循环自己发现：它必须先把 CLOSE 发出去，再收尾。
func TestIdleTimeoutIsSentToThePeer(t *testing.T) {
	baseline := runtime.NumGoroutine()
	client, server, listener := testSetup(t, Options{IdleTimeout: 150 * time.Millisecond}, Options{IdleTimeout: 10 * time.Second})
	waitDone(t, client.Context(), 3*time.Second)
	if cause := context.Cause(client.Context()); !errors.Is(cause, ErrIdleTimeout) {
		t.Fatalf("the client ended with %v", cause)
	}
	waitDone(t, server.Context(), 2*time.Second)
	if cause := context.Cause(server.Context()); !errors.Is(cause, ErrIdleTimeout) {
		t.Fatalf("the server ended with %v", cause)
	}
	_ = listener.Close()
	waitGoroutines(t, baseline, 5*time.Second)
}

// forgePacket 用本端发送密钥伪造一个带指定帧的包，冒充对端发过去。
func forgePacket(c *Conn, frame []byte) []byte {
	packet := header{ConnectionID: c.peerID, Type: packetTypeData}.appendTo(make([]byte, 0, headerLen+len(frame)+tagLen))
	packet = append(packet, frame...)
	packet = append(packet, make([]byte, tagLen)...)
	c.sendCipher.seal(packet, headerLen, 0)
	return packet
}

// 接收循环遇到致命错误时收尾，并且尽力告诉对端。
func TestReceiveErrorEndsTheConnection(t *testing.T) {
	baseline := runtime.NumGoroutine()
	client, server, listener := testSetup(t, Options{}, Options{})
	packet := forgePacket(client.Conn, []byte{0x7e, 0, 0})
	if _, err := client.socket.WriteTo(packet, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, server.Context(), 3*time.Second)
	if cause := context.Cause(server.Context()); !errors.Is(cause, errUnknownFrame) {
		t.Fatalf("the server ended with %v", cause)
	}
	waitDone(t, client.Context(), 2*time.Second)
	if cause := context.Cause(client.Context()); IsNormalClose(cause) {
		t.Fatalf("the client ended with %v", cause)
	}
	_ = listener.Close()
	waitGoroutines(t, baseline, 5*time.Second)
}
