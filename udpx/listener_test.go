package udpx

import (
	"context"
	"errors"
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
		t.Fatal("association did not end")
	}
}

// testSetup starts a listener and dials it once, returning both ends.
func testSetup(t *testing.T, clientOptions, serverOptions Options) (Association, Association, *Listener) {
	t.Helper()
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, serverOptions)
	t.Cleanup(func() {
		_ = listener.Close()
	})
	client, err := Dial(testContext(t, 5*time.Second), udpConn(t), listenerConn.LocalAddr(), password, clientOptions)
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

func TestHandshakeOverSocket(t *testing.T) {
	client, server, listener := testSetup(t, Options{}, Options{})
	if client.RemoteAddr().String() != listener.conn.LocalAddr().String() {
		t.Fatalf("client peer is %v", client.RemoteAddr())
	}
	if server.LocalAddr().String() != listener.conn.LocalAddr().String() {
		t.Fatalf("server local address is %v", server.LocalAddr())
	}
	if client.LocalAddr().String() != server.RemoteAddr().String() {
		t.Fatalf("server peer is %v, client local address is %v", server.RemoteAddr(), client.LocalAddr())
	}
	select {
	case <-client.Context().Done():
		t.Fatalf("client ended after the handshake: %v", context.Cause(client.Context()))
	default:
	}

	// A close of either end reaches the other, with the class of the ending.
	err := client.CloseWithError(nil)
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, server.Context(), time.Second)
	if cause := context.Cause(server.Context()); !errors.Is(cause, net.ErrClosed) {
		t.Fatalf("server ended with %v", cause)
	}
}

// TestDemux requires every association to see only its own packets: closing one
// leaves the other untouched, which is what a connection id is for.
func TestDemux(t *testing.T) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()
	ctx := testContext(t, 5*time.Second)
	var clients []Association
	for range 2 {
		client, err := Dial(ctx, udpConn(t), listenerConn.LocalAddr(), password, Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseWithError(nil)
		clients = append(clients, client)
	}
	var servers []Association
	for range 2 {
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, server)
	}
	if servers[0].RemoteAddr().String() != clients[0].LocalAddr().String() {
		t.Fatal("the first association was accepted out of order")
	}

	err := clients[0].CloseWithError(nil)
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, servers[0].Context(), time.Second)
	select {
	case <-servers[1].Context().Done():
		t.Fatalf("the other association ended too: %v", context.Cause(servers[1].Context()))
	case <-time.After(100 * time.Millisecond):
	}
}

// TestUnknownConnectionID requires a packet nobody claims to be dropped without
// an answer: a prober must see a port that says nothing.
func TestUnknownConnectionID(t *testing.T) {
	password := NewPassword("password")
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{password}, Options{})
	defer listener.Close()

	attacker := udpConn(t)
	var unknownID connectionID
	for index := range unknownID {
		unknownID[index] = 0x5a
	}
	buffer := make([]byte, maxPacketSize)

	// A data packet with a connection id no association has.
	dataPacket := header{ConnectionID: unknownID, Type: packetTypeData}.appendTo(nil)
	dataPacket = append(dataPacket, make([]byte, tagLen)...)
	// A hello with a key id the verifier does not know.
	hello := header{ConnectionID: unknownID, Type: packetTypeHandshake}.appendTo(nil)
	hello = append(hello, make([]byte, clientHelloBodyLen)...)
	hello[headerLen] = handshakeTagClient
	hello[headerLen+1] = byte(version >> 8)
	hello[headerLen+2] = byte(version)

	for _, packet := range [][]byte{dataPacket, hello} {
		_, err := attacker.WriteTo(packet, listenerConn.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		err = attacker.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = attacker.ReadFrom(buffer)
		if err == nil {
			t.Fatal("the listener answered a packet it knows nothing about")
		}
		if !isTimeout(err) {
			t.Fatalf("unexpected read error: %v", err)
		}
	}

	if _, err := listener.Accept(testContext(t, 100*time.Millisecond)); err == nil {
		t.Fatal("an association was accepted for a packet nobody authenticated")
	}

	// The listener is still there.
	client, err := Dial(testContext(t, 5*time.Second), udpConn(t), listenerConn.LocalAddr(), password, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(nil)
	if _, err = listener.Accept(testContext(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
}

// TestWrongPassword requires a client that cannot authenticate to fail on its
// own: the server has nothing to answer it with.
func TestWrongPassword(t *testing.T) {
	listenerConn := udpConn(t)
	listener := ListenPacket(listenerConn, testVerifier{NewPassword("password")}, Options{})
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := Dial(ctx, udpConn(t), listenerConn.LocalAddr(), NewPassword("wrong password"), Options{}); err == nil {
		t.Fatal("dialled with a password the server does not know")
	}
	if _, err := listener.Accept(testContext(t, 100*time.Millisecond)); err == nil {
		t.Fatal("an association was accepted for a hello that did not authenticate")
	}
}

func TestIdleTimeout(t *testing.T) {
	client, server, _ := testSetup(t, Options{IdleTimeout: 100 * time.Millisecond}, Options{IdleTimeout: 100 * time.Millisecond})
	waitDone(t, server.Context(), time.Second)
	if cause := context.Cause(server.Context()); !errors.Is(cause, ErrIdleTimeout) {
		t.Fatalf("server ended with %v", cause)
	}
	// Either end may be the one that notices first, and both report the same
	// reason whoever noticed.
	waitDone(t, client.Context(), time.Second)
	if cause := context.Cause(client.Context()); !errors.Is(cause, ErrIdleTimeout) {
		t.Fatalf("client ended with %v", cause)
	}
}

func TestKeepAlive(t *testing.T) {
	client, server, _ := testSetup(t, Options{IdleTimeout: 300 * time.Millisecond, KeepAlivePeriod: 50 * time.Millisecond}, Options{IdleTimeout: 300 * time.Millisecond})
	select {
	case <-client.Context().Done():
		t.Fatalf("client ended: %v", context.Cause(client.Context()))
	case <-server.Context().Done():
		t.Fatalf("server ended: %v", context.Cause(server.Context()))
	case <-time.After(600 * time.Millisecond):
	}
}

// TestStatelessReset requires a reset from the peer address to end the
// association, and a reset from anywhere else to be ignored.
func TestStatelessReset(t *testing.T) {
	client, server, listener := testSetup(t, Options{}, Options{})
	clientAssociation, isAssociation := client.(*association)
	if !isAssociation {
		t.Fatal("client is not an association")
	}
	reset := header{ConnectionID: clientAssociation.localConnID, Type: packetTypeReset}.appendTo(nil)
	reset = append(reset, make([]byte, resetLen)...)

	// From another address first: the association must not care.
	_, err := udpConn(t).WriteTo(reset, clientAssociation.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Context().Done():
		t.Fatalf("a reset from a third party ended the association: %v", context.Cause(client.Context()))
	case <-time.After(100 * time.Millisecond):
	}

	_, err = listener.conn.WriteTo(reset, clientAssociation.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, client.Context(), time.Second)
	if cause := context.Cause(client.Context()); !errors.Is(cause, ErrStatelessReset) {
		t.Fatalf("client ended with %v", cause)
	}
	_ = server.CloseWithError(nil)
}

// TestPacketTamperedOnTheWire requires a packet that carries an association's
// connection id but does not authenticate to be dropped without ending it.
func TestPacketTamperedOnTheWire(t *testing.T) {
	client, server, listener := testSetup(t, Options{}, Options{})
	clientAssociation, isAssociation := client.(*association)
	if !isAssociation {
		t.Fatal("client is not an association")
	}
	// A packet sealed with the client's keys, but with one payload byte flipped.
	packet := mustSeal(t, &clientAssociation.sendRing, header{ConnectionID: clientAssociation.peerConnID, Type: packetTypeData}, []byte("payload"))
	packet[len(packet)-1] ^= 0x01
	_, err := udpConn(t).WriteTo(packet, listener.conn.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.Context().Done():
		t.Fatalf("a packet that did not authenticate ended the association: %v", context.Cause(server.Context()))
	case <-time.After(100 * time.Millisecond):
	}
	_ = client.CloseWithError(nil)
}
