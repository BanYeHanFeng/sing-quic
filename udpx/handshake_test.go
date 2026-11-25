package udpx

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"
)

func listenerDone(listener *Listener) <-chan struct{} {
	return listener.ctx.Done()
}

func TestCredential(t *testing.T) {
	credential := NewCredential("password")
	other := NewCredential("password ")
	if credential.KeyID() == other.KeyID() {
		t.Fatal("two passwords share a key id")
	}
	signature := credential.Sign([]byte("transcript"))
	if !credential.Verify([]byte("transcript"), signature) {
		t.Fatal("a signature did not verify")
	}
	if credential.Verify([]byte("transcript "), signature) {
		t.Fatal("a signature verified another transcript")
	}
	if credential.Verify([]byte("transcript"), []byte("forged")) {
		t.Fatal("a forged signature verified")
	}
	if again := NewCredential("password"); again.KeyID() != credential.KeyID() {
		t.Fatal("key id is not deterministic")
	}
}

func exchange(t *testing.T, clientCredential Credential, verifier Verifier) (handshakeResult, error) {
	t.Helper()
	handshake, err := newClientHandshake(clientCredential)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServerHandshake(handshake.hello(), verifier)
	if err != nil {
		return handshakeResult{}, err
	}
	answer := server.hello()
	clientResult, err := handshake.handleResponse(answer)
	if err != nil {
		return handshakeResult{}, err
	}
	serverResult, err := server.keys()
	if err != nil {
		t.Fatal(err)
	}
	return handshakeResult{
		localID: clientResult.localID,
		peerID:  clientResult.peerID,
		keyID:   clientResult.keyID,
		send:    clientResult.send,
		recv:    serverResult.send,
	}, nil
}

func TestHandshake(t *testing.T) {
	credential := NewCredential("password")
	result, err := exchange(t, credential, testVerifier{credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	if result.keyID != credential.KeyID() {
		t.Fatal("the key id changed")
	}
	if result.peerID == (connectionID{}) || result.localID == (connectionID{}) {
		t.Fatal("the handshake produced no connection ids")
	}
}

func TestHandshakeWrongPassword(t *testing.T) {
	_, err := exchange(t, NewCredential("password"), testVerifier{credential: NewCredential("other")})
	if err == nil {
		t.Fatal("the handshake accepted another password")
	}
}

func TestHandshakeTamperedHello(t *testing.T) {
	credential := NewCredential("password")
	handshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	hello := bytes.Clone(handshake.hello())
	hello[headerLen+3+keyIDLen+randomLen] ^= 0xff
	if _, err = newServerHandshake(hello, testVerifier{credential: credential}); err == nil {
		t.Fatal("a tampered hello was accepted")
	}
}

func TestHandshakeTamperedAnswer(t *testing.T) {
	credential := NewCredential("password")
	handshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServerHandshake(handshake.hello(), testVerifier{credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	answer := bytes.Clone(server.hello())
	answer[headerLen+3+randomLen] ^= 0xff
	if _, err = handshake.handleResponse(answer); err == nil {
		t.Fatal("a tampered answer was accepted")
	}
}

func TestHandshakeVersion(t *testing.T) {
	credential := NewCredential("password")
	handshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	hello := bytes.Clone(handshake.hello())
	hello[headerLen+1] = 0xff
	_, err = newServerHandshake(hello, testVerifier{credential: credential})
	if !errors.Is(err, errUnsupportedVersion) {
		t.Fatalf("a hello of another version ended with %v", err)
	}
}

func TestHandshakePacketType(t *testing.T) {
	credential := NewCredential("password")
	handshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	hello := bytes.Clone(handshake.hello())
	hello[connectionIDLen] = packetTypeData
	if _, err = newServerHandshake(hello, testVerifier{credential: credential}); err == nil {
		t.Fatal("a data packet was taken for a hello")
	}
}

func TestKeyIDIsNotThePassword(t *testing.T) {
	credential := NewCredential("password")
	keyID := credential.KeyID()
	if bytes.Contains(keyID[:], []byte("password")[:keyIDLen]) {
		t.Fatal("the key id contains the password")
	}
}

func TestHandshakeOverSocket(t *testing.T) {
	client, server, _ := testSetup(t, Options{}, Options{})
	if client.RemoteAddr().String() != server.LocalAddr().String() {
		t.Fatalf("client peer is %v, server local address is %v", client.RemoteAddr(), server.LocalAddr())
	}
	if client.LocalAddr().String() != server.RemoteAddr().String() {
		t.Fatalf("server peer is %v, client local address is %v", server.RemoteAddr(), client.LocalAddr())
	}
	select {
	case <-client.Context().Done():
		t.Fatalf("client ended after the handshake: %v", context.Cause(client.Context()))
	default:
	}
	err := client.CloseWithError(nil)
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, server.Context(), time.Second)
	if cause := context.Cause(server.Context()); !errors.Is(cause, net.ErrClosed) {
		t.Fatalf("server ended with %v", cause)
	}
}

func TestWrongPasswordOverSocket(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, _ := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	ctx := testContext(t, 2*time.Second)
	_, err := Dial(ctx, udpConn(t), listenerConn.LocalAddr(), NewCredential("other"), Options{MTU: mtuIPv4})
	if err == nil {
		t.Fatal("the handshake accepted another password")
	}
}

func TestUnknownConnectionID(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, _ := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	client := udpConn(t)
	packet := header{ConnectionID: connectionID{1, 2, 3, 4, 5, 6, 7, 8}, Type: packetTypeData, PacketNumber: 1}.appendTo(nil)
	packet = append(packet, make([]byte, tagLen)...)
	_, err := client.WriteTo(packet, listenerConn.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-listenerDone(listener):
		t.Fatal("the listener ended on a stray packet")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIdleTimeout(t *testing.T) {
	client, server, _ := testSetup(t, Options{IdleTimeout: 200 * time.Millisecond}, Options{IdleTimeout: 200 * time.Millisecond})
	waitDone(t, client.Context(), 3*time.Second)
	if cause := context.Cause(client.Context()); !errors.Is(cause, ErrIdleTimeout) {
		t.Fatalf("the client ended with %v", cause)
	}
	waitDone(t, server.Context(), 3*time.Second)
}

func TestKeepAlive(t *testing.T) {
	client, server, _ := testSetup(t, Options{IdleTimeout: 300 * time.Millisecond, KeepAlivePeriod: 50 * time.Millisecond}, Options{IdleTimeout: 300 * time.Millisecond})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-client.Context().Done():
			t.Fatalf("the client ended with %v", context.Cause(client.Context()))
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = client.CloseWithError(nil)
	waitDone(t, server.Context(), time.Second)
}

func TestRepeatedHelloIsOneAssociation(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, peers := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	handshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	client := udpConn(t)
	ctx := testContext(t, 5*time.Second)
	for range 3 {
		_, err = client.WriteTo(handshake.hello(), listenerConn.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var answers int
	buffer := make([]byte, maxPacketSize)
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, _, readErr := client.ReadFrom(buffer)
		if readErr != nil {
			break
		}
		packetHeader, parseErr := parseHeader(buffer[:n])
		if parseErr == nil && packetHeader.Type == packetTypeHandshake {
			answers++
		}
	}
	if answers == 0 {
		t.Fatal("not one answer arrived")
	}
	conn := testAccept(t, ctx, peers)
	select {
	case extra := <-peers:
		t.Fatalf("a repeated hello created another connection: %v", extra)
	case <-time.After(100 * time.Millisecond):
	}
	_ = conn.CloseWithError(nil)
}

func TestDemux(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, peers := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	ctx := testContext(t, 5*time.Second)
	var clients []*testPeer
	for range 2 {
		clients = append(clients, testDial(t, ctx, udpConn(t), listenerConn.LocalAddr(), credential, Options{MTU: mtuIPv4}))
	}
	servers := make([]*testPeer, 0, len(clients))
	for range clients {
		server := testAccept(t, ctx, peers)
		servers = append(servers, server)
	}
	for index, client := range clients {
		stream, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		marker := []byte{byte('c' + index)}
		if _, err = stream.Write(marker); err != nil {
			t.Fatal(err)
		}
		if err = stream.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	for index, server := range servers {
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		read := readAll(t, stream, 1)
		if !bytes.Equal(read, []byte{byte('c' + index)}) {
			t.Fatalf("server %d read %q", index, read)
		}
	}
}

func TestPacketTamperedOnTheWire(t *testing.T) {
	credential := NewCredential("password")
	listenerConn := udpConn(t)
	listener, peers := testListen(t, listenerConn, credential, Options{MTU: mtuIPv4})
	defer listener.Close()
	tamper := udpConn(t)
	client := testDial(t, testContext(t, 5*time.Second), tamper, listenerConn.LocalAddr(), credential, Options{MTU: mtuIPv4})
	server := testAccept(t, testContext(t, 5*time.Second), peers)
	stream, err := client.OpenStream(testContext(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 0, 128)
	packet = header{Type: packetTypeData}.appendTo(packet)
	packet = append(packet, make([]byte, tagLen)...)
	packet[headerLen] ^= 0xff
	_, err = tamper.WriteTo(packet, listenerConn.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.Context().Done():
		t.Fatal("a tampered packet ended the connection")
	case <-time.After(100 * time.Millisecond):
	}
	if _, err = stream.Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
}

var _ = rand.Reader
