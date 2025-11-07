package linearpbft

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (n *LinearPBFTNode) ViewChangeRequest(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber
	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	// Verify view number
	if viewNumber <= n.State.GetViewNumber() {
		log.Warnf("Rejected: %s; lower view number (expected: %d)", utils.LoggingString(viewChangeMessage), n.State.GetViewNumber())
		return nil, status.Errorf(codes.FailedPrecondition, "invalid view number")
	}

	// Verify signature
	ok := crypto.Verify(viewChangeMessage, n.GetPublicKey1(viewChangeMessage.NodeID), signedViewChangeMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(viewChangeMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify check point messages signatures
	// TODO: need to verify digest
	for _, signedCheckPointMessage := range viewChangeMessage.CheckPointMessages {
		checkPointMessage := signedCheckPointMessage.Message
		ok := crypto.Verify(checkPointMessage, n.GetPublicKey1(checkPointMessage.NodeID), signedCheckPointMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on check point message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on check point message")
		}
	}

	// Verify prepare set
	for _, prepareProof := range viewChangeMessage.PreparedSet {
		signedPrePrepareMessage := prepareProof.SignedPrePrepareMessage
		prePrepareMessage := signedPrePrepareMessage.Message
		signedPrepareMessage := prepareProof.SignedPrepareMessage
		prepareMessage := signedPrepareMessage.Message

		// Verify preprepare message signature
		proposerID := utils.ViewNumberToPrimaryID(prePrepareMessage.ViewNumber, n.Handler.N)
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey1(proposerID), signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on preprepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on preprepare message")
		}

		// Verify prepare message signature
		ok = crypto.Verify(prepareMessage, n.Handler.masterPublicKey1, signedPrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on prepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on prepare message")
		}

		// Verify prepare message digest, view number and sequence number against corresponding preprepare message
		if prepareMessage.ViewNumber != prePrepareMessage.ViewNumber ||
			prepareMessage.SequenceNum != prePrepareMessage.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, prePrepareMessage.Digest) {
			log.Warnf("Rejected: %s; invalid digest on prepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid digest on prepare message")
		}
	}

	go n.ViewChangeManager.ViewChangeRequestHandler(signedViewChangeMessage)

	return &emptypb.Empty{}, nil
}

func (v *ViewChangeManager) ViewChangeRequestHandler(signedViewChangeMessage *pb.SignedViewChangeMessage) {
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber

	// Log the view change message
	log.Infof("Logged: %s", utils.LoggingString(viewChangeMessage))
	v.AddViewChangeMessage(signedViewChangeMessage)

	// Send view change message to all nodes if f + 1 view change messages are collected
	if v.state.GetViewChangeViewNumber() < viewNumber && len(v.log[viewNumber]) == int(v.f+1) {
		alreadyExpired := v.SafeTimer.Cleanup()
		if !alreadyExpired || utils.ViewNumberToPrimaryID(viewNumber, v.n) != v.id {
			// log.Infof("Sending view change message to all nodes since f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			// go v.SendViewChange(viewNumber)
			// TODO: signal view change request channel
			log.Infof("Signaling view change request channel since f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			v.viewChangeRequestCh <- true
		} else {
			log.Infof("View change timer already expired at v %d vc %d", v.state.GetViewNumber(), v.state.GetViewChangeViewNumber())
		}
	}

	// If 2f + 1 view change messages are collected and next primary then send new view message
	if len(v.log[viewNumber]) == int(2*v.f+1) {
		if utils.ViewNumberToPrimaryID(viewNumber, v.n) == v.id {
			// // Byzantine node behavior: crash attack
			// if v.byzantine && v.crashAttack {
			// 	// log.Infof("Node %s is Byzantine and is performing crash attack", v.id)
			// 	return
			// }
			// TODO: signal new view request channel
			log.Infof("Signaling new view request channel since 2f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			v.newViewRequestCh <- true
		} else {
			// else start view change timer
			log.Infof("Starting view change timer since 2f + 1 view change messages are collected but not next primary: %s", utils.LoggingString(viewChangeMessage))
			v.SafeTimer.StartViewTimerIfNotRunning()
		}
	}

}

func (n *LinearPBFTNode) CreateViewChangeMessage(viewNumber int64) *pb.SignedViewChangeMessage {
	maxSequenceNum := n.State.StateLog.MaxSequenceNum()
	lowerSequenceNum := n.config.lowWaterMark

	// Get prepared message proof set
	preparedSet := make([]*pb.PrepareProof, 0)
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		record, exists := n.State.StateLog.Get(sequenceNum)
		if !exists {
			continue
		}
		if record == nil || !record.IsPrepared() {
			continue
		}
		prepareProof := record.GetPrepareProof()
		preparedSet = append(preparedSet, prepareProof)
	}

	// Get check point messages
	stableCheckpointSequenceNum := n.CheckPointLog.GetStableCheckpointSequenceNum()
	signedCheckPointMessages := n.CheckPointLog.GetMessages(stableCheckpointSequenceNum)

	// Create signed view change message
	viewChangeMessage := &pb.ViewChangeMessage{
		ViewNumber:         viewNumber,
		SequenceNum:        lowerSequenceNum,
		CheckPointMessages: signedCheckPointMessages,
		PreparedSet:        preparedSet,
		NodeID:             n.ID,
	}
	signedViewChangeMessage := &pb.SignedViewChangeMessage{
		Message:   viewChangeMessage,
		Signature: crypto.Sign(viewChangeMessage, n.Handler.privateKey1),
	}
	// // Byzantine node behavior: sign attack
	// if n.Byzantine && n.SignAttack {
	// 	// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
	// 	signedViewChangeMessage.Signature = []byte("invalid signature")
	// }
	return signedViewChangeMessage
}
