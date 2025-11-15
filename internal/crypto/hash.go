package crypto

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/mavleo96/pbft/pb"
)

// Digest hashes a signed transaction request
func Digest(request *pb.SignedTransactionRequest) []byte {
	requestBytes, _ := json.Marshal(request)
	digest := sha256.Sum256(requestBytes)
	return digest[:]
}

// DigestAny hashes any message
func DigestAny(msg any) []byte {
	msgBytes, _ := json.Marshal(msg)
	digest := sha256.Sum256(msgBytes)
	return digest[:]
}
