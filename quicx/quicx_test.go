package quicx

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/udpio"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// testHandler is the two halves of the router a service hands its connections to.
type testHandler struct {
	connections chan testConnection
	packets     chan testPacketConnection
}

type testConnection struct {
	conn        net.Conn
	source      M.Socksaddr
	destination M.Socksaddr
}

type testPacketConnection struct {
	conn        N.PacketConn
	source      M.Socksaddr
	destination M.Socksaddr
}

func newTestHandler() *testHandler {
	return &testHandler{
		connections: make(chan testConnection, 8),
		packets:     make(chan testPacketConnection, 8),
	}
}

func (h *testHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections <- testConnection{conn: conn, source: source, destination: destination}
}

func (h *testHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.packets <- testPacketConnection{conn: conn, source: source, destination: destination}
}

func (h *testHandler) connection(t *testing.T, ctx context.Context) testConnection {
	t.Helper()
	select {
	case conn := <-h.connections:
		return conn
	case <-ctx.Done():
		t.Fatal("the service did not hand the connection over")
		return testConnection{}
	}
}

func (h *testHandler) packetConnection(t *testing.T, ctx context.Context) testPacketConnection {
	t.Helper()
	select {
	case conn := <-h.packets:
		return conn
	case <-ctx.Done():
		t.Fatal("the service did not hand the packet connection over")
		return testPacketConnection{}
	}
}

// testDialer dials the UDP socket of the test service.
type testDialer struct {
	server M.Socksaddr
}

func (d testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "udp", d.server.String())
}

func (d testDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var listenConfig net.ListenConfig
	return listenConfig.ListenPacket(ctx, "udp", "")
}

// testSetup starts a service and a client that are ready to proxy.
func testSetup(t *testing.T, password string) (*Client, *testHandler) {
	t.Helper()
	ctx := testContext(t, 20*time.Second)
	handler := newTestHandler()
	service, err := NewService[int](ServiceOptions{
		Context: ctx,
		Handler: handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	listenerConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = service.Start(listenerConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = service.Close()
	})
	service.UpdateUsers([]int{0}, []string{password})
	client, err := NewClient(ClientOptions{
		Context:       ctx,
		Dialer:        testDialer{server: M.SocksaddrFromNet(listenerConn.LocalAddr())},
		ServerAddress: M.SocksaddrFromNet(listenerConn.LocalAddr()),
		Password:      password,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.CloseWithError(nil)
	})
	return client, handler
}

func testContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}

// TestClientBatches requires the socket a dialer hands back to keep its
// descriptor. The transport batches whatever the socket allows and moves one
// datagram per call otherwise, and it decides that from the descriptor alone: a
// dialer whose connection is wrapped in something that does not pass the
// descriptor on makes every send and receive its own system call, silently. The
// client is the side that dials through such a wrapper, so the client is what is
// measured here.
func TestClientBatches(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if gso, gro := udpio.New(probe, udpio.Options{GRO: true}).Offload(); !gso || !gro {
		t.Skip("this kernel does not batch: gso ", gso, ", gro ", gro)
	}
	client, _ := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	conn, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client.connAccess.Lock()
	session := client.conn
	client.connAccess.Unlock()
	if session == nil {
		t.Fatal("a dial left no session")
	}
	gso, gro := session.association.Offload()
	if !gso || !gro {
		t.Fatalf("the client socket batches with gso %v and gro %v", gso, gro)
	}
}

// TestConnections requires a proxied connection to carry data in both directions
// and to end its write half on its own, which is what a protocol that closes one
// direction first needs.
func TestConnections(t *testing.T) {
	client, handler := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	destination := M.ParseSocksaddr("example.com:443")
	conn, err := client.DialConn(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.LocalAddr().String() != destination.String() {
		t.Fatalf("the connection was made to %v", conn.LocalAddr())
	}
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	serverConn := handler.connection(t, ctx)
	if serverConn.destination.String() != destination.String() {
		t.Fatalf("the service was asked for %v", serverConn.destination)
	}
	request := make([]byte, 5)
	_, err = readFull(serverConn.conn, request)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "hello" {
		t.Fatalf("the request arrived as %q", request)
	}
	// The answer runs the other way on the same connection.
	_, err = serverConn.conn.Write([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 5)
	_, err = readFull(conn, response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "world" {
		t.Fatalf("the answer arrived as %q", response)
	}
	// Half-closing one direction leaves the other one working.
	err = conn.(interface{ CloseWrite() error }).CloseWrite()
	if err != nil {
		t.Fatal(err)
	}
	if n, readErr := serverConn.conn.Read(make([]byte, 1)); n != 0 || readErr == nil {
		t.Fatalf("the end of the request read as %d, %v", n, readErr)
	}
	_, err = serverConn.conn.Write([]byte("more"))
	if err != nil {
		t.Fatal(err)
	}
	more := make([]byte, 4)
	_, err = readFull(conn, more)
	if err != nil {
		t.Fatal(err)
	}
	if string(more) != "more" {
		t.Fatalf("the rest of the answer arrived as %q", more)
	}
}

// TestMultiplexedConnections requires two connections of one client to stay apart
// and to run at the same time, which is what multiplexing them on one session
// means.
func TestMultiplexedConnections(t *testing.T) {
	client, handler := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	first, err := client.DialConn(ctx, M.ParseSocksaddr("first.example:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := client.DialConn(ctx, M.ParseSocksaddr("second.example:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_, err = first.Write([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = second.Write([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	// The service hands both connections over, in whichever order they arrived,
	// and each carries the data written on it.
	seen := make(map[string]bool)
	for range 2 {
		serverConn := handler.connection(t, ctx)
		payload := make([]byte, 3)
		_, err = readFull(serverConn.conn, payload)
		if err != nil {
			t.Fatal(err)
		}
		switch string(payload) {
		case "one":
			if serverConn.destination.String() != "first.example:80" {
				t.Fatalf("the first connection goes to %v", serverConn.destination)
			}
		case "two":
			if serverConn.destination.String() != "second.example:80" {
				t.Fatalf("the second connection goes to %v", serverConn.destination)
			}
		default:
			t.Fatalf("a connection carried %q", payload)
		}
		seen[string(payload)] = true
	}
	if !seen["one"] || !seen["two"] {
		t.Fatalf("the connections are %v", seen)
	}
}

// TestPacketConnections requires a forwarded UDP packet to arrive with its
// destination, and an answer to come back on the same session.
func TestPacketConnections(t *testing.T) {
	client, handler := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	destination := M.ParseSocksaddr("1.1.1.1:53")
	_, err = packetConn.WriteTo([]byte("query"), destination)
	if err != nil {
		t.Fatal(err)
	}
	serverConn := handler.packetConnection(t, ctx)
	if serverConn.destination.String() != destination.String() {
		t.Fatalf("the packet connection goes to %v", serverConn.destination)
	}
	request := buf.New()
	defer request.Release()
	source, err := serverConn.conn.ReadPacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.Bytes(), []byte("query")) {
		t.Fatalf("the query arrived as %q", request.Bytes())
	}
	if source.String() != destination.String() {
		t.Fatalf("the query came from %v", source)
	}
	answer := buf.NewSize(6)
	answer.Write([]byte("answer"))
	err = serverConn.conn.WritePacket(answer, source)
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 16*1024)
	n, responseSource, err := packetConn.ReadFrom(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[:n], []byte("answer")) {
		t.Fatalf("the answer arrived as %q", response[:n])
	}
	if responseSource.String() != destination.String() {
		t.Fatalf("the answer came from %v", responseSource)
	}
}

// TestLargeTransfer requires a transfer larger than both windows of the stream to
// complete, which it can only do if the windows move forward as the reader reads.
func TestLargeTransfer(t *testing.T) {
	client, handler := testSetup(t, "password")
	ctx := testContext(t, 60*time.Second)
	const size = 4 * 1024 * 1024
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte(index % 251)
	}
	conn, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	serverConn := handler.connection(t, ctx)
	written := make(chan error, 1)
	go func() {
		_, writeErr := serverConn.conn.Write(payload)
		written <- writeErr
	}()
	read := make([]byte, 0, size)
	buffer := make([]byte, 32*1024)
	for len(read) < size {
		n, readErr := conn.Read(buffer)
		if readErr != nil {
			t.Fatalf("read %d of %d bytes: %v", len(read), size, readErr)
		}
		read = append(read, buffer[:n]...)
	}
	if !bytes.Equal(read, payload) {
		t.Fatal("the payload changed on the way")
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
}

// TestWrongPassword requires a client with a password the server does not know to
// be refused, with nothing to authenticate against.
func TestWrongPassword(t *testing.T) {
	client, _ := testSetup(t, "password")
	// A handshake this server will not answer ends when the dial gives up, so
	// the test waits for that rather than for the protocol timeout.
	ctx := testContext(t, 2*time.Second)
	// The client of the setup authenticates; a second one with another password
	// does not.
	wrongClient, err := NewClient(ClientOptions{
		Context:       ctx,
		Dialer:        client.dialer,
		ServerAddress: client.serverAddr,
		Password:      "not-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongClient.CloseWithError(nil)
	_, err = wrongClient.DialConn(ctx, M.ParseSocksaddr("example.com:80"))
	if err == nil {
		t.Fatal("a client with the wrong password was accepted")
	}
}

// readFull reads exactly len(p) bytes, which is what a stream read is not: it
// returns what the stream gave it.
func readFull(conn net.Conn, p []byte) (int, error) {
	read := 0
	for read < len(p) {
		n, err := conn.Read(p[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
