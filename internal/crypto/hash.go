package crypto

import (
	"crypto/sha256"

	"github.com/mavleo96/bft-mavleo96/pb"
)

// Digest hashes a signed transaction request
func Digest(request *pb.SignedTransactionRequest) []byte {
	requestString := signedTransactionRequestString(request)
	digest := sha256.Sum256([]byte(requestString))
	return digest[:]
}
