package udpx

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/argon2"

	E "github.com/sagernet/sing/common/exceptions"
)

// Handshake
//
// One round trip and two packets:
//
//	C → S  ClientHello  tag | version | key id | client random | client public key | mac
//	S → C  ServerHello  tag | version | server random | server public key | mac
//	C → S  data
//
// The server assigns itself a connection id in the answer, which is the id the
// client addresses from then on; the client announces its own in the packet
// header of its hello. Neither packet is encrypted, because the session keys
// are what they are establishing, and both carry a MAC over the handshake as it
// stands so far, keyed by the auth key the password turns into.
//
// The server holds no state for a hello it has not authenticated, and a
// ClientHello carries no data, so replaying one gives an attacker nothing: the
// answer is another hello with fresh randomness, and the client that sent it
// has long finished. That is also why there is no anti-replay cache and no
// 0-RTT.
const (
	// version is the protocol version. The handshake is the only place it
	// appears, and a packet carrying another version is dropped without an
	// answer, which is what lets an old and a new implementation share a port:
	// a prober sees a port that answers nothing.
	//
	// It is 5 since an acknowledgement also reports what parity rebuilt: a peer
	// that does not know the field would read the recovered ranges as another
	// frame and end the association on a type it does not have. The same bump
	// covers the padding frame path MTU discovery sends, and the rule is the same
	// one that made 3 the stream count and 4 the Reed-Solomon parity: an addition
	// to the wire is a new version, because the version is what keeps an old peer
	// from reaching something it cannot parse.
	version = 5

	// randomLen is the size of the random value each side contributes. It makes
	// every handshake unique, so a repeated hello never produces the keys of an
	// older session.
	randomLen = 16

	// keyIDLen is the size of the identifier a client announces in place of its
	// password.
	keyIDLen = 8

	// publicKeyLen is the size of an X25519 public key.
	publicKeyLen = 32

	// macLen is the size of the HMAC-SHA256 that authenticates a handshake
	// packet.
	macLen = sha256.Size

	// handshakeTagClient and handshakeTagServer open the authenticated part of
	// their packet. They are what keeps a ClientHello from being read as a
	// ServerHello by whoever reflects it back: the two transcripts cannot be
	// made to match.
	handshakeTagClient = 1
	handshakeTagServer = 2

	// clientHelloBodyLen is tag | version | key id | random | public key | mac.
	clientHelloBodyLen = 1 + 2 + keyIDLen + randomLen + publicKeyLen + macLen

	// serverHelloBodyLen is tag | version | random | public key | mac.
	serverHelloBodyLen = 1 + 2 + randomLen + publicKeyLen + macLen
)

// Argon2id parameters.
//
// The password is meant to be a random string, and the KDF is the fallback for
// when it is not: a captured handshake can be tested against a guess offline,
// and the point of the parameters is to make that test expensive rather than to
// make the handshake slow. Each side pays it once per handshake, which bounds
// how far they can be pushed on a router.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 16 * 1024
	argonThreads uint8  = 2
)

var (
	errUnsupportedVersion = E.New("unsupported handshake version")
	errUnknownKeyID       = E.New("handshake with unknown key id")
	errHandshakeMAC       = E.New("handshake failed authentication")
	errHandshakePacket    = E.New("malformed handshake packet")
)

// Credential is what a client proves: the key id it announces, and the auth key
// it derives from the handshake transcript.
//
// The auth key is what the password turns into, so the password never crosses
// the wire, and neither does a user name: the key id stands for both.
type Credential interface {
	KeyID() [keyIDLen]byte
	AuthKey(transcript []byte) []byte
}

// Verifier answers which auth key belongs to a key id. What a key id may do is
// policy and stays with the user table the verifier is built from.
type Verifier interface {
	Lookup(keyID [keyIDLen]byte) (AuthKey func(transcript []byte) []byte, ok bool)
}

// Password is the pre-shared secret that authenticates both ends: it is a
// Credential on the client and the source of a Verifier's entries on the
// server.
type Password struct {
	password []byte
	keyID    [keyIDLen]byte
}

func NewPassword(password string) Password {
	// The key id is a PRF output of the password, so announcing it is not
	// announcing the password, and it is stable, so a peer reacts to the same
	// key id across connections without either side keeping a name for it.
	return Password{
		password: []byte(password),
		keyID:    keyIDFromPassword([]byte(password)),
	}
}

func (p Password) KeyID() [keyIDLen]byte {
	return p.keyID
}

// AuthKey derives the key that authenticates a handshake. It is called once per
// handshake with the transcript of the ClientHello, and the same value
// authenticates both packets: the transcript of the ServerHello extends the one
// of the ClientHello, and the client can verify the answer with the key it
// proved it can derive.
func (p Password) AuthKey(transcript []byte) []byte {
	salt := sha256.Sum256(transcript)
	return argon2.IDKey(p.password, salt[:], argonTime, argonMemory, argonThreads, keyLen)
}

// keyIDFromPassword returns the identifier a password announces.
func keyIDFromPassword(password []byte) [keyIDLen]byte {
	mac := hmac.New(sha256.New, password)
	mac.Write([]byte("udpx key id"))
	var keyID [keyIDLen]byte
	copy(keyID[:], mac.Sum(nil))
	return keyID
}

// handshakeResult is what a completed handshake hands to the association.
type handshakeResult struct {
	// localConnID is the id the peer addresses this end by.
	localConnID connectionID
	// peerConnID is the id this end addresses the peer by.
	peerConnID connectionID
	// keyID is the key the client authenticated with. It is the client's own
	// on both ends, which is what lets the server tell which account a
	// connection belongs to without the password ever being sent.
	keyID [keyIDLen]byte
	send  keyRing
	recv  keyRing
}

// clientHandshake is the client side of the handshake. It builds the hello once
// and keeps it: a lost hello is answered by sending the same bytes again, which
// the server treats as the new handshake it is, rather than by building a
// second one that would have to be told apart from the first.
type clientHandshake struct {
	// connID is the id this end receives on, and the one its hello is addressed
	// to.
	connID     connectionID
	keyID      [keyIDLen]byte
	random     [randomLen]byte
	privateKey *ecdh.PrivateKey
	// transcript is the ClientHello up to its MAC, starting with the clear
	// header.
	transcript []byte
	authKey    []byte
	packet     []byte
}

func newClientHandshake(credential Credential) (*clientHandshake, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, E.Cause(err, "generate key")
	}
	h := &clientHandshake{privateKey: privateKey}
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
	h.transcript = make([]byte, 0, headerLen+clientHelloBodyLen-macLen)
	h.transcript = append(h.transcript, h.packet...)
	h.transcript = append(h.transcript, handshakeTagClient)
	h.transcript = append(h.transcript, versionBytes()...)
	h.transcript = append(h.transcript, h.keyID[:]...)
	h.transcript = append(h.transcript, h.random[:]...)
	h.transcript = append(h.transcript, privateKey.PublicKey().Bytes()...)
	h.authKey = credential.AuthKey(h.transcript)
	h.packet = append(h.packet, h.transcript[headerLen:]...)
	h.packet = append(h.packet, hmacSum(h.authKey, h.transcript)...)
	return h, nil
}

// hello returns the ClientHello to send, and to send again if no answer came.
func (h *clientHandshake) hello() []byte {
	return h.packet
}

// handleResponse verifies a ServerHello and returns the keys it produces.
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
	// The transcript of the answer is the hello the client sent, then the answer
	// up to its MAC, clear header and all.
	transcript := make([]byte, 0, len(h.packet)+headerLen+serverHelloBodyLen-macLen)
	transcript = append(transcript, h.packet...)
	transcript = append(transcript, packet[:headerLen]...)
	transcript = append(transcript, body[:len(body)-macLen]...)
	if !hmac.Equal(body[len(body)-macLen:], hmacSum(h.authKey, transcript)) {
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
	send, recv, err := directionalRings(clientToServer, serverToClient, true)
	if err != nil {
		return handshakeResult{}, err
	}
	return handshakeResult{
		localConnID: h.connID,
		peerConnID:  packetHeader.ConnectionID,
		keyID:       h.keyID,
		send:        send,
		recv:        recv,
	}, nil
}

// serverHandshake verifies a ClientHello and answers it. It is built only after
// the hello authenticated, so an unauthenticated packet costs the server
// nothing but the work of rejecting it.
type serverHandshake struct {
	clientConnID    connectionID
	connID          connectionID
	keyID           [keyIDLen]byte
	clientRandom    []byte
	serverRandom    [randomLen]byte
	clientPublicKey *ecdh.PublicKey
	privateKey      *ecdh.PrivateKey
	// transcript is the ServerHello transcript: the ClientHello as received,
	// then this end's connection id, then the answer up to its MAC.
	transcript []byte
	packet     []byte
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
	authKeyFunc, loaded := verifier.Lookup(keyID)
	if !loaded {
		return nil, errUnknownKeyID
	}
	// The auth key is derived from the hello as it stands without its MAC. The
	// answer extends that with the hello exactly as it was received, MAC
	// included, so the client can tell its own hello back out of the transcript.
	clientTranscript := clientHello[:headerLen+clientHelloBodyLen-macLen]
	authKey := authKeyFunc(clientTranscript)
	if !hmac.Equal(body[len(body)-macLen:], hmacSum(authKey, clientTranscript)) {
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
	h.packet = append(h.packet, hmacSum(authKey, h.transcript)...)
	return h, nil
}

// hello returns the ServerHello to send.
func (h *serverHandshake) hello() []byte {
	return h.packet
}

// keys returns the keys of the association the hello asked for.
func (h *serverHandshake) keys() (handshakeResult, error) {
	sharedSecret, err := h.privateKey.ECDH(h.clientPublicKey)
	if err != nil {
		return handshakeResult{}, E.Cause(err, "derive shared secret")
	}
	clientToServer, serverToClient, err := trafficKeys(sharedSecret, h.clientRandom, h.serverRandom[:], h.transcript)
	if err != nil {
		return handshakeResult{}, err
	}
	send, recv, err := directionalRings(clientToServer, serverToClient, false)
	if err != nil {
		return handshakeResult{}, err
	}
	return handshakeResult{
		localConnID: h.connID,
		peerConnID:  h.clientConnID,
		keyID:       h.keyID,
		send:        send,
		recv:        recv,
	}, nil
}

// trafficKeys derives the two directional keys of an association.
//
// The shared secret alone would be enough for secrecy, but not for freshness:
// the transcript includes the random value of each side and both hellos, so a
// key cannot be reused by replaying a hello from an older session, and nothing
// that was ever sent in the clear can be read back out of it.
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

// nextKey derives the key of the next epoch. Both ends derive it from the same
// current key, so nothing about the rotation has to be negotiated: the packet
// number threshold that triggers it is a constant of the protocol.
func nextKey(key []byte) ([]byte, error) {
	derived, err := hkdf.Key(sha256.New, key, nil, "udpx key update", keyLen)
	if err != nil {
		return nil, E.Cause(err, "derive next key")
	}
	return derived, nil
}

// directionalRings builds the key rings of an association from the two derived
// keys. The two directions are keyed differently, so a packet cannot be
// reflected back at its sender and open.
func directionalRings(clientToServer, serverToClient []byte, isClient bool) (send, recv keyRing, err error) {
	toServer, err := newAEAD(clientToServer)
	if err != nil {
		return keyRing{}, keyRing{}, err
	}
	toClient, err := newAEAD(serverToClient)
	if err != nil {
		return keyRing{}, keyRing{}, err
	}
	if isClient {
		return newKeyRing(0, toServer), newKeyRing(0, toClient), nil
	}
	return newKeyRing(0, toClient), newKeyRing(0, toServer), nil
}

func versionBytes() []byte {
	return []byte{byte(version >> 8), byte(version)}
}

func hmacSum(authKey, transcript []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(transcript)
	return mac.Sum(nil)
}

func fillRandom(b []byte) error {
	_, err := rand.Read(b)
	if err != nil {
		return E.Cause(err, "read random")
	}
	return nil
}
