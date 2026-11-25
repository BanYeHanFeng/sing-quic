package udpx

import (
	"context"
	"net"
	"testing"
	"time"
)

func udpConn(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return conn
}

func testContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

func waitDone(t *testing.T, ctx context.Context, timeout time.Duration) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(timeout):
		t.Fatal("conn did not end")
	}
}

type testVerifier struct {
	credential Credential
}

func (v testVerifier) Lookup(keyID [keyIDLen]byte) (Credential, bool) {
	if keyID != v.credential.KeyID() {
		return Credential{}, false
	}
	return v.credential, true
}

func testSetup(t *testing.T, clientOptions, serverOptions Options) (*Conn, *Conn, *Listener) {
	t.Helper()
	if clientOptions.MTU == 0 {
		clientOptions.MTU = mtuIPv4
	}
	if serverOptions.MTU == 0 {
		serverOptions.MTU = mtuIPv4
	}
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener := Listen(listenerConn, testVerifier{credential: credential}, serverOptions)
	t.Cleanup(func() {
		_ = listener.Close()
	})
	client, err := Dial(testContext(t, 5*time.Second), udpConn(t), listenerConn.LocalAddr(), credential, clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.CloseWithError(nil)
	})
	server, err := listener.Accept(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return client, server, listener
}

func testSnapshot(c *Conn) statsSnapshot {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return *c.send.snapshot()
}

func testPayload(size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index*7 + index/251)
	}
	return payload
}

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
