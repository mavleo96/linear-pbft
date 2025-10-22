package security

import (
	"crypto/sha256"
)

func Digest(message string) []byte {
	digest := sha256.Sum256([]byte(message))
	return digest[:]
}
