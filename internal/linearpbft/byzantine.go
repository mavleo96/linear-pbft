package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// ByzantineConfig represents the configuration of a byzantine node
type ByzantineConfig struct {
	Alive                   bool
	Byzantine               bool
	SignAttack              bool
	CrashAttack             bool
	DarkAttack              bool
	DarkAttackNodes         []string
	TimeAttack              bool
	EquivocationAttack      bool
	EquivocationAttackNodes []string
}

// Reset resets the byzantine config
func (b *ByzantineConfig) Reset() {
	b.Alive = true
	b.Byzantine = false
	b.SignAttack = false
	b.CrashAttack = false
	b.DarkAttack = false
	b.DarkAttackNodes = make([]string, 0)
	b.TimeAttack = false
	b.EquivocationAttack = false
	b.EquivocationAttackNodes = make([]string, 0)
}

// CreateByzantineConfig creates a new byzantine config
func CreateByzantineConfig() *ByzantineConfig {
	return &ByzantineConfig{
		Alive:                   true,
		Byzantine:               false,
		SignAttack:              false,
		CrashAttack:             false,
		DarkAttack:              false,
		DarkAttackNodes:         make([]string, 0),
		TimeAttack:              false,
		EquivocationAttack:      false,
		EquivocationAttackNodes: make([]string, 0),
	}
}

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
		Signature: crypto.Sign(message, n.handler.privateKey1),
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
