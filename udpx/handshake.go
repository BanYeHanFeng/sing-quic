package udpx

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	version = 7

	randomLen = 16

	keyIDLen = 8

	publicKeyLen = 32

	macLen = sha256.Size

	handshakeTagClient = 1
	handshakeTagServer = 2

	clientHelloBodyLen = 1 + 2 + keyIDLen + randomLen + publicKeyLen + macLen

	serverHelloBodyLen = 1 + 2 + randomLen + publicKeyLen + macLen
)

var (
	errUnsupportedVersion = E.New("unsupported handshake version")
	errUnknownKeyID       = E.New("handshake with unknown key id")
	errHandshakeMAC       = E.New("handshake failed authentication")
	errHandshakePacket    = E.New("malformed handshake packet")
)

type handshakeResult struct {
	localID connectionID
	peerID  connectionID
	keyID   [keyIDLen]byte
	send    packetCipher
	recv    packetCipher
}

type clientHandshake struct {
	connID     connectionID
	keyID      [keyIDLen]byte
	random     [randomLen]byte
	privateKey *ecdh.PrivateKey
	credential Credential
	transcript []byte
	packet     []byte
}

func newClientHandshake(credential Credential) (*clientHandshake, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, E.Cause(err, "generate key")
	}
	h := &clientHandshake{privateKey: privateKey, credential: credential}
	err = fillRandom(h.connID[:])
	if err != nil {
		return nil, err
	}
	err = fillRandom(h.random[:])
	if err != nil {
		return nil, err
	}
	h.keyID = credential.KeyID()
	h.packet = header{ConnectionID: h.connID, Type: packetTypeHandshake}.appendTo(nil)
	h.transcript = make([]byte, 0, headerLen+clientHelloBodyLen)
	h.transcript = append(h.transcript, h.packet...)
	h.transcript = append(h.transcript, handshakeTagClient)
	h.transcript = append(h.transcript, versionBytes()...)
	h.transcript = append(h.transcript, h.keyID[:]...)
	h.transcript = append(h.transcript, h.random[:]...)
	h.transcript = append(h.transcript, privateKey.PublicKey().Bytes()...)
	h.packet = append(h.packet, h.transcript[headerLen:]...)
	h.packet = append(h.packet, credential.Sign(h.transcript)...)
	return h, nil
}

func (h *clientHandshake) hello() []byte {
	return h.packet
}

func (h *clientHandshake) handleResponse(packet []byte) (handshakeResult, error) {
	packetHeader, err := parseHeader(packet)
	if err != nil {
		return handshakeResult{}, err
	}
	if packetHeader.Type != packetTypeHandshake {
		return handshakeResult{}, E.New("handshake answer has type ", int(packetHeader.Type))
	}
	body := packet[headerLen:]
	if len(body) != serverHelloBodyLen || body[0] != handshakeTagServer {
		return handshakeResult{}, errHandshakePacket
	}
	if binary.BigEndian.Uint16(body[1:3]) != version {
		return handshakeResult{}, errUnsupportedVersion
	}
	publicKeyOffset := 1 + 2 + randomLen
	publicKey, err := ecdh.X25519().NewPublicKey(body[publicKeyOffset : publicKeyOffset+publicKeyLen])
	if err != nil {
		return handshakeResult{}, E.Cause(err, "parse public key")
	}
	transcript := make([]byte, 0, len(h.packet)+headerLen+serverHelloBodyLen-macLen)
	transcript = append(transcript, h.packet...)
	transcript = append(transcript, packet[:headerLen]...)
	transcript = append(transcript, body[:len(body)-macLen]...)
	if !h.credential.Verify(transcript, body[len(body)-macLen:]) {
		return handshakeResult{}, errHandshakeMAC
	}
	sharedSecret, err := h.privateKey.ECDH(publicKey)
	if err != nil {
		return handshakeResult{}, E.Cause(err, "derive shared secret")
	}
	clientToServer, serverToClient, err := trafficKeys(sharedSecret, h.random[:], body[3:3+randomLen], transcript)
	if err != nil {
		return handshakeResult{}, err
	}
	send, recv, err := directionalCiphers(clientToServer, serverToClient, true)
	if err != nil {
		return handshakeResult{}, err
	}
	return handshakeResult{
		localID: h.connID,
		peerID:  packetHeader.ConnectionID,
		keyID:   h.keyID,
		send:    send,
		recv:    recv,
	}, nil
}

type serverHandshake struct {
	clientConnID    connectionID
	connID          connectionID
	keyID           [keyIDLen]byte
	clientRandom    []byte
	serverRandom    [randomLen]byte
	clientPublicKey *ecdh.PublicKey
	privateKey      *ecdh.PrivateKey
	transcript      []byte
	packet          []byte
}

func newServerHandshake(clientHello []byte, verifier Verifier) (*serverHandshake, error) {
	packetHeader, err := parseHeader(clientHello)
	if err != nil {
		return nil, err
	}
	if packetHeader.Type != packetTypeHandshake {
		return nil, E.New("handshake request has type ", int(packetHeader.Type))
	}
	body := clientHello[headerLen:]
	if len(body) != clientHelloBodyLen || body[0] != handshakeTagClient {
		return nil, errHandshakePacket
	}
	if binary.BigEndian.Uint16(body[1:3]) != version {
		return nil, errUnsupportedVersion
	}
	var keyID [keyIDLen]byte
	copy(keyID[:], body[3:3+keyIDLen])
	credential, loaded := verifier.Lookup(keyID)
	if !loaded {
		return nil, errUnknownKeyID
	}
	clientTranscript := clientHello[:headerLen+clientHelloBodyLen-macLen]
	if !credential.Verify(clientTranscript, body[len(body)-macLen:]) {
		return nil, errHandshakeMAC
	}
	publicKeyOffset := headerLen + 3 + keyIDLen + randomLen
	clientPublicKey, err := ecdh.X25519().NewPublicKey(clientHello[publicKeyOffset : publicKeyOffset+publicKeyLen])
	if err != nil {
		return nil, E.Cause(err, "parse public key")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, E.Cause(err, "generate key")
	}
	h := &serverHandshake{
		clientConnID:    packetHeader.ConnectionID,
		keyID:           keyID,
		clientRandom:    clientHello[headerLen+3+keyIDLen : headerLen+3+keyIDLen+randomLen],
		clientPublicKey: clientPublicKey,
		privateKey:      privateKey,
	}
	err = fillRandom(h.connID[:])
	if err != nil {
		return nil, err
	}
	err = fillRandom(h.serverRandom[:])
	if err != nil {
		return nil, err
	}
	h.packet = header{ConnectionID: h.connID, Type: packetTypeHandshake}.appendTo(nil)
	h.transcript = make([]byte, 0, len(clientHello)+headerLen+serverHelloBodyLen-macLen)
	h.transcript = append(h.transcript, clientHello...)
	h.transcript = append(h.transcript, h.packet...)
	h.transcript = append(h.transcript, handshakeTagServer)
	h.transcript = append(h.transcript, versionBytes()...)
	h.transcript = append(h.transcript, h.serverRandom[:]...)
	h.transcript = append(h.transcript, privateKey.PublicKey().Bytes()...)
	h.packet = append(h.packet, h.transcript[len(clientHello)+headerLen:]...)
	h.packet = append(h.packet, credential.Sign(h.transcript)...)
	return h, nil
}

func (h *serverHandshake) hello() []byte {
	return h.packet
}

func (h *serverHandshake) keys() (handshakeResult, error) {
	sharedSecret, err := h.privateKey.ECDH(h.clientPublicKey)
	if err != nil {
		return handshakeResult{}, E.Cause(err, "derive shared secret")
	}
	clientToServer, serverToClient, err := trafficKeys(sharedSecret, h.clientRandom, h.serverRandom[:], h.transcript)
	if err != nil {
		return handshakeResult{}, err
	}
	send, recv, err := directionalCiphers(clientToServer, serverToClient, false)
	if err != nil {
		return handshakeResult{}, err
	}
	return handshakeResult{
		localID: h.connID,
		peerID:  h.clientConnID,
		keyID:   h.keyID,
		send:    send,
		recv:    recv,
	}, nil
}

func trafficKeys(sharedSecret, clientRandom, serverRandom, transcript []byte) (clientToServer, serverToClient []byte, err error) {
	salt := make([]byte, 0, randomLen*2)
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)
	master, err := hkdf.Key(sha256.New, sharedSecret, salt, string(transcript), keyLen)
	if err != nil {
		return nil, nil, E.Cause(err, "derive master key")
	}
	clientToServer, err = hkdf.Key(sha256.New, master, nil, "udpx client to server", keyLen)
	if err != nil {
		return nil, nil, E.Cause(err, "derive client to server key")
	}
	serverToClient, err = hkdf.Key(sha256.New, master, nil, "udpx server to client", keyLen)
	if err != nil {
		return nil, nil, E.Cause(err, "derive server to client key")
	}
	return clientToServer, serverToClient, nil
}

func directionalCiphers(clientToServer, serverToClient []byte, initiator bool) (send, recv packetCipher, err error) {
	toServer, err := newPacketCipher(clientToServer)
	if err != nil {
		return packetCipher{}, packetCipher{}, err
	}
	toClient, err := newPacketCipher(serverToClient)
	if err != nil {
		return packetCipher{}, packetCipher{}, err
	}
	if initiator {
		return toServer, toClient, nil
	}
	return toClient, toServer, nil
}

func versionBytes() []byte {
	return []byte{byte(version >> 8), byte(version)}
}

func fillRandom(b []byte) error {
	_, err := rand.Read(b)
	if err != nil {
		return E.Cause(err, "read random")
	}
	return nil
}
