package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// // CreateMaliciousSignedPrePrepareMessage creates a malicious signed preprepare message
// func (n *LinearPBFTNode) CreateMaliciousSignedPrePrepareMessage(signedMessage *pb.SignedPrePrepareMessage) *pb.SignedPrePrepareMessage {
// 	message := signedMessage.Message
// 	message.SequenceNum += 1
// 	return &pb.SignedPrePrepareMessage{
// 		Message:   message,
// 		Signature: crypto.Sign(message, n.PrivateKey),
// 		Request:   signedMessage.Request,
// 	}
// }

// CreateMessageWithInvalidSequenceNumber creates a malicious signed preprepare message
func (n *LinearPBFTNode) CreateMessageWithInvalidSequenceNumber(signedMessage *pb.SignedPrePrepareMessage) *pb.SignedPrePrepareMessage {
	message := signedMessage.Message
	message.SequenceNum += 1
	return &pb.SignedPrePrepareMessage{
		Message:   message,
		Signature: crypto.Sign(message, n.Handler.privateKey1),
		Request:   signedMessage.Request,
	}
}

// type MessageWithSignature interface {
// 	Signature
// 	GetSignature() []byte
// }

// // CreateMessageWithInvalidSignature creates a message with an invalid signature
// func (n *LinearPBFTNode) CreateMessageWithInvalidSignature(signedMessage MessageWithSignature) MessageWithSignature {
// 	signedMessage.
// 		signedMessage.Signature = []byte("invalid signature")
// 	return signedMessage
// }

// MaliciousUpdateLogState updates the log state maliciously to prevent log from getting prepared or committed
// despite having valid prepare and commit messages
// Byzantine node behavior: crash attack
func (l *LogRecord) MaliciousUpdateLogState() {
	l.prepared = false
	l.committed = false
}
