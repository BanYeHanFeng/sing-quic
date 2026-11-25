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
		t.Fatal("the connection did not end")
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

// testPeer 把 Handler 的事件接成通道，让测试用阻塞的写法读事件。
type testPeer struct {
	*Conn
	streams   chan *Stream
	datagrams chan []byte
	closed    chan error
}

func newTestPeer(conn *Conn) *testPeer {
	return &testPeer{
		Conn:      conn,
		streams:   make(chan *Stream, initialStreams),
		datagrams: make(chan []byte, 4096),
		closed:    make(chan error, 1),
	}
}

func (p *testPeer) handler() Handler {
	return p
}

func (p *testPeer) OnDatagram(conn *Conn, data []byte) {
	p.datagrams <- data
}

func (p *testPeer) OnStream(conn *Conn, stream *Stream) {
	p.streams <- stream
}

func (p *testPeer) OnClose(conn *Conn, cause error) {
	select {
	case p.closed <- cause:
	default:
	}
}

func (p *testPeer) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-p.streams:
		return stream, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-p.Context().Done():
		return nil, context.Cause(p.Context())
	}
}

func (p *testPeer) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-p.datagrams:
		return datagram, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-p.Context().Done():
		return nil, context.Cause(p.Context())
	}
}

func testHandler(options *Options) func(conn *Conn) Handler {
	if options.NewHandler != nil {
		return options.NewHandler
	}
	return func(conn *Conn) Handler {
		return newTestPeer(conn)
	}
}

// testListen 让每条握手成功的连接变成一个 testPeer。
func testListen(t *testing.T, socket net.PacketConn, credential Credential, options Options) (*Listener, chan *testPeer) {
	t.Helper()
	peers := make(chan *testPeer, 8)
	options.NewHandler = func(conn *Conn) Handler {
		peer := newTestPeer(conn)
		peers <- peer
		return peer
	}
	listener := Listen(socket, testVerifier{credential: credential}, options)
	t.Cleanup(func() {
		_ = listener.Close()
	})
	return listener, peers
}

func testAccept(t *testing.T, ctx context.Context, peers chan *testPeer) *testPeer {
	t.Helper()
	select {
	case peer := <-peers:
		return peer
	case <-ctx.Done():
		t.Fatal("the listener accepted no connection")
		return nil
	}
}

func testDial(t *testing.T, ctx context.Context, socket net.PacketConn, remote net.Addr, credential Credential, options Options) *testPeer {
	t.Helper()
	var peer *testPeer
	options.NewHandler = func(conn *Conn) Handler {
		peer = newTestPeer(conn)
		return peer
	}
	_, err := Dial(ctx, socket, remote, credential, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = peer.CloseWithError(nil)
	})
	return peer
}

func testSetup(t *testing.T, clientOptions, serverOptions Options) (*testPeer, *testPeer, *Listener) {
	t.Helper()
	if clientOptions.MTU == 0 {
		clientOptions.MTU = mtuIPv4
	}
	if serverOptions.MTU == 0 {
		serverOptions.MTU = mtuIPv4
	}
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, peers := testListen(t, listenerConn, credential, serverOptions)
	client := testDial(t, testContext(t, 5*time.Second), udpConn(t), listenerConn.LocalAddr(), credential, clientOptions)
	server := testAccept(t, testContext(t, 5*time.Second), peers)
	return client, server, listener
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
