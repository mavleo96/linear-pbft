package linearpbft

import (
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/linear-pbft/internal/models"
	"github.com/mavleo96/linear-pbft/pb"
)

// ProtocolHandler is a struct that contains the state of the protocol
type ProtocolHandler struct {
	id               string
	state            *ServerState
	config           *ServerConfig
	byzantineConfig  *ByzantineConfig
	privateKey1      *bls.SecretKey
	privateKey2      *bls.SecretKey
	masterPublicKey1 *bls.PublicKey
	masterPublicKey2 *bls.PublicKey
	peers            map[string]*models.Node

	// Timer instance
	timer *SafeTimer

	// Channels
	executionTriggerCh   chan int64
	clientRequestCh      chan *pb.SignedTransactionRequest
	preprepareToRouteCh  chan *pb.SignedPrePrepareMessage
	prepareToRouteCh     chan *pb.SignedPrepareMessage
	sbftPrepareToRouteCh chan *pb.SignedPrepareMessage
	commitToRouteCh      chan *pb.SignedCommitMessage

	// Function pointers
	SendGetRequest func(digest []byte) (*pb.SignedTransactionRequest, error)
}

// GetClientRequestChannel returns the channel for receiving client transaction requests
func (h *ProtocolHandler) GetClientRequestChannel() <-chan *pb.SignedTransactionRequest {
	return h.clientRequestCh
}

// GetPreprepareToRouteChannel returns the channel for sending preprepare messages to route
func (h *ProtocolHandler) GetPreprepareToRouteChannel() <-chan *pb.SignedPrePrepareMessage {
	return h.preprepareToRouteCh
}

// GetPrepareToRouteChannel returns the channel for sending prepare messages to route
func (h *ProtocolHandler) GetPrepareToRouteChannel() <-chan *pb.SignedPrepareMessage {
	return h.prepareToRouteCh
}

// GetSBFTPrepareToRouteChannel returns the channel for sending sbft prepare messages to route
func (h *ProtocolHandler) GetSBFTPrepareToRouteChannel() <-chan *pb.SignedPrepareMessage {
	return h.sbftPrepareToRouteCh
}

// GetCommitToRouteChannel returns the channel for sending commit messages to route
func (h *ProtocolHandler) GetCommitToRouteChannel() <-chan *pb.SignedCommitMessage {
	return h.commitToRouteCh
}

// CreateProtocolHandler creates a new protocol handler
func CreateProtocolHandler(id string, state *ServerState, config *ServerConfig, byzantineConfig *ByzantineConfig, privateKey1 *bls.SecretKey, privateKey2 *bls.SecretKey, masterPublicKey1 *bls.PublicKey, masterPublicKey2 *bls.PublicKey, peers map[string]*models.Node, timer *SafeTimer, executionTriggerCh chan int64) *ProtocolHandler {
	return &ProtocolHandler{
		id:                   id,
		state:                state,
		config:               config,
		byzantineConfig:      byzantineConfig,
		privateKey1:          privateKey1,
		privateKey2:          privateKey2,
		masterPublicKey1:     masterPublicKey1,
		masterPublicKey2:     masterPublicKey2,
		peers:                peers,
		timer:                timer,
		executionTriggerCh:   executionTriggerCh,
		clientRequestCh:      make(chan *pb.SignedTransactionRequest, 100),
		preprepareToRouteCh:  make(chan *pb.SignedPrePrepareMessage, 100),
		prepareToRouteCh:     make(chan *pb.SignedPrepareMessage, 100),
		sbftPrepareToRouteCh: make(chan *pb.SignedPrepareMessage, 100),
		commitToRouteCh:      make(chan *pb.SignedCommitMessage, 100),
	}
}
