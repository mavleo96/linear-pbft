package linearpbft

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// ProtocolHandler is a struct that contains the state of the protocol
type ProtocolHandler struct {
	id          string
	state       *ServerState
	privateKey1 *bls.SecretKey
	// privateKey2    *bls.SecretKey
	masterPublicKey1 *bls.PublicKey
	peers            map[string]*models.Node
	F                int64
	N                int64

	// Channels
	executeCh    chan int64
	requestCh    chan *pb.SignedTransactionRequest
	preprepareCh chan *pb.SignedPrePrepareMessage
	prepareCh    chan *pb.SignedPrepareMessage
	commitCh     chan *pb.SignedCommitMessage
}

func (h *ProtocolHandler) GetRequestChannel() <-chan *pb.SignedTransactionRequest {
	return h.requestCh
}

func (h *ProtocolHandler) GetPreprepareChannel() <-chan *pb.SignedPrePrepareMessage {
	return h.preprepareCh
}

func (h *ProtocolHandler) GetPrepareChannel() <-chan *pb.SignedPrepareMessage {
	return h.prepareCh
}

func (h *ProtocolHandler) GetCommitChannel() <-chan *pb.SignedCommitMessage {
	return h.commitCh
}
