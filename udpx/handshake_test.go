package udpx

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

type testCredential struct {
	password []byte
}

func (c testCredential) KeyID() [keyIDLen]byte {
	return keyIDFromPassword(c.password)
}

func (c testCredential) AuthKey(transcript []byte) []byte {
	hash := sha256.New()
	hash.Write(c.password)
	hash.Write(transcript)
	return hash.Sum(nil)
}

type testVerifier []Credential

func (v testVerifier) Lookup(keyID [keyIDLen]byte) (func([]byte) []byte, bool) {
	for _, credential := range v {
		if credential.KeyID() == keyID {
			return credential.AuthKey, true
		}
	}
	return nil, false
}

type impostorCredential struct {
	keyID      [keyIDLen]byte
	credential testCredential
}

func (c impostorCredential) KeyID() [keyIDLen]byte {
	return c.keyID
}

func (c impostorCredential) AuthKey(transcript []byte) []byte {
	return c.credential.AuthKey(transcript)
}

func runHandshake(t *testing.T, credential Credential, verifier Verifier) (client, server handshakeResult) {
	t.Helper()
	clientHandshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	serverHandshake, err := newServerHandshake(clientHandshake.hello(), verifier)
	if err != nil {
		t.Fatal(err)
	}
	server, err = serverHandshake.keys()
	if err != nil {
		t.Fatal(err)
	}
	client, err = clientHandshake.handleResponse(serverHandshake.hello())
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestHandshake(t *testing.T) {
	credential := NewPassword("correct horse battery staple")
	client, server := runHandshake(t, credential, testVerifier{credential})
	if client.localConnID != server.peerConnID {
		t.Fatal("the client does not receive on the connection id the server addresses it by")
	}
	if client.peerConnID != server.localConnID {
		t.Fatal("the server does not receive on the connection id the client addresses it by")
	}
	if client.localConnID == client.peerConnID {
		t.Fatal("both ends picked the same connection id")
	}

	toServer := mustSeal(t, &client.send, header{ConnectionID: client.peerConnID, Type: packetTypeData}, []byte("client to server"))
	if _, payload, err := server.recv.open(toServer); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(payload, []byte("client to server")) {
		t.Fatal("payload changed")
	}
	toClient := mustSeal(t, &server.send, header{ConnectionID: server.peerConnID, Type: packetTypeData}, []byte("server to client"))
	if _, payload, err := client.recv.open(toClient); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(payload, []byte("server to client")) {
		t.Fatal("payload changed")
	}

	if _, _, err := client.recv.open(toServer); err == nil {
		t.Fatal("the client opened the packet it sent")
	}
	if _, _, err := server.recv.open(toClient); err == nil {
		t.Fatal("the server opened the packet it sent")
	}
}

func TestHandshakeWrongPassword(t *testing.T) {
	clientCredential := testCredential{password: []byte("client password")}
	serverCredential := testCredential{password: []byte("server password")}
	clientHandshake, err := newClientHandshake(clientCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newServerHandshake(clientHandshake.hello(), testVerifier{serverCredential}); err != errUnknownKeyID {
		t.Fatalf("unexpected error: %v", err)
	}

	impostor := impostorCredential{keyID: clientCredential.KeyID(), credential: serverCredential}
	if _, err = newServerHandshake(clientHandshake.hello(), testVerifier{impostor}); err != errHandshakeMAC {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandshakeTamperedHello(t *testing.T) {
	credential := testCredential{password: []byte("password")}
	verifier := testVerifier{credential}
	clientHandshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	hello := clientHandshake.hello()
	for offset := range hello {
		tampered := bytes.Clone(hello)
		tampered[offset] ^= 0x01
		if _, err = newServerHandshake(tampered, verifier); err == nil {
			t.Fatalf("hello with byte %d flipped was accepted", offset)
		}
	}
}

func TestHandshakeTamperedAnswer(t *testing.T) {
	credential := testCredential{password: []byte("password")}
	clientHandshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	serverHandshake, err := newServerHandshake(clientHandshake.hello(), testVerifier{credential})
	if err != nil {
		t.Fatal(err)
	}
	answer := serverHandshake.hello()
	for offset := range answer {
		tampered := bytes.Clone(answer)
		tampered[offset] ^= 0x01
		if _, err = clientHandshake.handleResponse(tampered); err == nil {
			t.Fatalf("answer with byte %d flipped was accepted", offset)
		}
	}
}

func TestHandshakeReplay(t *testing.T) {
	credential := testCredential{password: []byte("password")}
	verifier := testVerifier{credential}
	clientHandshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	hello := clientHandshake.hello()

	first, err := newServerHandshake(hello, verifier)
	if err != nil {
		t.Fatal(err)
	}
	firstResult, err := first.keys()
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := newServerHandshake(bytes.Clone(hello), verifier)
	if err != nil {
		t.Fatal(err)
	}
	replayedResult, err := replayed.keys()
	if err != nil {
		t.Fatal(err)
	}
	if replayedResult.localConnID == firstResult.localConnID {
		t.Fatal("the replayed hello was answered with the connection id of the first answer")
	}
	packet := mustSeal(t, &firstResult.send, header{ConnectionID: firstResult.peerConnID, Type: packetTypeData}, []byte("first"))
	if _, _, err = replayedResult.recv.open(packet); err == nil {
		t.Fatal("the two answers to the same hello share keys")
	}
}

func TestHandshakeVersion(t *testing.T) {
	credential := testCredential{password: []byte("password")}
	clientHandshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	hello := bytes.Clone(clientHandshake.hello())
	hello[headerLen+1] = byte(version) + 1
	if _, err = newServerHandshake(hello, testVerifier{credential}); err != errUnsupportedVersion {
		t.Fatalf("unexpected error: %v", err)
	}

	serverHandshake, err := newServerHandshake(clientHandshake.hello(), testVerifier{credential})
	if err != nil {
		t.Fatal(err)
	}
	answer := bytes.Clone(serverHandshake.hello())
	answer[headerLen+1] = byte(version) + 1
	if _, err = clientHandshake.handleResponse(answer); err != errUnsupportedVersion {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandshakePacketType(t *testing.T) {
	credential := testCredential{password: []byte("password")}
	packet := mustSeal(t, testCipher(t, 0x11), testHeader(), make([]byte, clientHelloBodyLen))
	if _, err := newServerHandshake(packet, testVerifier{credential}); err == nil {
		t.Fatal("a data packet was accepted as a hello")
	}
	clientHandshake, err := newClientHandshake(credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clientHandshake.handleResponse(packet); err == nil {
		t.Fatal("a data packet was accepted as an answer")
	}
}

func TestPassword(t *testing.T) {
	password := NewPassword("password")
	if password.KeyID() != keyIDFromPassword([]byte("password")) {
		t.Fatal("the key id is not derived from the password")
	}
	if password.KeyID() == NewPassword("password ").KeyID() {
		t.Fatal("two passwords share a key id")
	}
	transcript := []byte("transcript")
	authKey := password.AuthKey(transcript)
	if len(authKey) != keyLen {
		t.Fatalf("auth key of %d bytes", len(authKey))
	}
	if !bytes.Equal(authKey, NewPassword("password").AuthKey(transcript)) {
		t.Fatal("the auth key of a password is not deterministic")
	}
	if bytes.Equal(authKey, password.AuthKey([]byte("other transcript"))) {
		t.Fatal("the auth key does not depend on the transcript")
	}
	if bytes.Equal(authKey, NewPassword("password ").AuthKey(transcript)) {
		t.Fatal("two passwords share an auth key")
	}
}
