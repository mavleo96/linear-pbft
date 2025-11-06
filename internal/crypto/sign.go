package crypto

import (
	"encoding/json"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// Sign signs a message with a private key and returns the serialized signature
func Sign[T any](message T, privateKey *bls.SecretKey) []byte {
	originalMsgBytes, _ := json.Marshal(message)
	cleaned := regexRemoveKey(string(originalMsgBytes), "nodeID")
	msgBytes := []byte(cleaned)
	return privateKey.SignByte(msgBytes).Serialize()
}

// Verify verifies a message with a public key and a signature and returns true if the signature is valid
func Verify[T any](message T, publicKey *bls.PublicKey, signature []byte) bool {
	originalMsgBytes, _ := json.Marshal(message)
	cleaned := regexRemoveKey(string(originalMsgBytes), "nodeID")
	msgBytes := []byte(cleaned)
	var sig bls.Sign
	sig.Deserialize(signature)
	return sig.VerifyByte(publicKey, msgBytes)
}

// AggregateSignatures aggregates signatures from a map of node IDs to signatures
func AggregateSignatures(signatureMap map[bls.ID][]byte) []byte {
	signatures := make([]bls.Sign, 0)
	ids := make([]bls.ID, 0)
	for id, signature := range signatureMap {
		var sig bls.Sign
		sig.Deserialize(signature)
		signatures = append(signatures, sig)
		ids = append(ids, id)
	}

	aggSig := bls.Sign{}
	aggSig.Recover(signatures, ids)
	return aggSig.Serialize()
}
