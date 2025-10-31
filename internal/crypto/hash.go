package crypto

import (
	"crypto/sha256"

	"github.com/mavleo96/bft-mavleo96/pb"
)

func Digest(request *pb.TransactionRequest) []byte {
	requestString := transactionRequestString(request)
	digest := sha256.Sum256([]byte(requestString))
	return digest[:]
}
