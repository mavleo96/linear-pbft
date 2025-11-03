package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/mavleo96/bft-mavleo96/pb"
)

// Digest hashes a signed transaction request
func Digest(request *pb.SignedTransactionRequest) []byte {
	requestBytes, _ := json.Marshal(request)
	digest := sha256.Sum256(requestBytes)
	return digest[:]
}

func DigestAny[T any](messages ...T) []byte {
	fullMsgBytes := bytes.NewBuffer([]byte{})
	for _, message := range messages {
		msgBytes, _ := json.Marshal(message)
		fullMsgBytes.Write(msgBytes)
	}
	digest := sha256.Sum256(fullMsgBytes.Bytes())
	return digest[:]
}
