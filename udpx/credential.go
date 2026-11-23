package udpx

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

const (
	credentialSalt = "udpx credential v7"

	argonTime    uint32 = 2
	argonMemory  uint32 = 16 * 1024
	argonThreads uint8  = 2
)

type Credential struct {
	prk   [sha256.Size]byte
	keyID [keyIDLen]byte
}

func NewCredential(password string) Credential {
	prk := argon2.IDKey([]byte(password), []byte(credentialSalt), argonTime, argonMemory, argonThreads, sha256.Size)
	var credential Credential
	copy(credential.prk[:], prk)
	mac := hmac.New(sha256.New, credential.prk[:])
	mac.Write([]byte("udpx key id"))
	copy(credential.keyID[:], mac.Sum(nil))
	return credential
}

func (c Credential) KeyID() [keyIDLen]byte {
	return c.keyID
}

func (c Credential) Sign(transcript []byte) []byte {
	mac := hmac.New(sha256.New, c.prk[:])
	mac.Write(transcript)
	return mac.Sum(nil)
}

func (c Credential) Verify(transcript, signature []byte) bool {
	return hmac.Equal(signature, c.Sign(transcript))
}

type Verifier interface {
	Lookup(keyID [keyIDLen]byte) (Credential, bool)
}
