package quicx

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

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

func TestClientSessionsAreShared(t *testing.T) {
	client, _ := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	first, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:81"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	client.access.Lock()
	sessions := 0
	if client.session != nil {
		sessions = 1
	}
	client.access.Unlock()
	if sessions != 1 {
		t.Fatal("the client opened more than one session")
	}
}

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

func TestWrongPassword(t *testing.T) {
	client, _ := testSetup(t, "password")
	ctx := testContext(t, 2*time.Second)
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

func TestResetRedials(t *testing.T) {
	client, handler := testSetup(t, "password")
	ctx := testContext(t, 20*time.Second)
	first, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:80"))
	if err != nil {
		t.Fatal(err)
	}
	_ = handler.connection(t, ctx)
	client.Reset()
	second, err := client.DialConn(ctx, M.ParseSocksaddr("example.com:81"))
	if err != nil {
		t.Fatalf("the client did not redial after reset: %v", err)
	}
	defer second.Close()
	defer first.Close()
	_ = handler.connection(t, ctx)
}
