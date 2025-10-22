package security

// TODO: maybe rename this to crypto

import (
	"crypto/ed25519"
)

func Sign(message string, privateKey []byte) []byte {
	return ed25519.Sign(privateKey, []byte(message))
}

func Verify(message string, publicKey []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, []byte(message), signature)
}
