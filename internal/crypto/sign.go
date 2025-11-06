package crypto

import (
	"encoding/json"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// Sign signs a message with a private key and returns the serialized signature
func Sign[T any](message T, privateKey *bls.SecretKey) []byte {
	msgBytes, _ := json.Marshal(message)
	return privateKey.SignByte(msgBytes).Serialize()
}

// Verify verifies a message with a public key and a signature and returns true if the signature is valid
func Verify[T any](message T, publicKey *bls.PublicKey, signature []byte) bool {
	msgBytes, _ := json.Marshal(message)
	var sig bls.Sign
	sig.Deserialize(signature)
	return sig.VerifyByte(publicKey, msgBytes)
}
