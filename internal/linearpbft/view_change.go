package linearpbft

import (
	"context"
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ViewChangeRoutine is a persistent routine that sends view change messages to all nodes
func (n *LinearPBFTNode) ViewChangeRoutine(ctx context.Context) {
	log.Infof("Starting view change routine for %s", n.ID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.SafeTimer.TimeoutCh:
			log.Infof("View change routine: Timer expired at v %d vc %d", n.ViewNumber, n.ViewChangeViewNumber)

			// Get smallest view number of the logged view change messages which is higher than latest sent view change message view number
			n.Mutex.Lock()
			viewNumber := n.ViewChangeViewNumber + 1
			maxViewNumber := utils.Max(utils.Keys(n.ViewChangeMessageLog))
			for v := viewNumber; v <= maxViewNumber; v++ {
				if _, ok := n.ViewChangeMessageLog[v]; ok {
					viewNumber = v
					break
				}
			}
			log.Infof("VCN: %d, NEW VCN: %d, Key of VC log: %d", n.ViewChangeViewNumber, viewNumber, utils.Keys(n.ViewChangeMessageLog))
			n.Mutex.Unlock()
			go n.SendViewChange(viewNumber)
		}
	}
}

// SendViewChange sends a view change message to all nodes
func (n *LinearPBFTNode) SendViewChange(viewNumber int64) error {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Set sent view change flag to true
	log.Infof("Node %s is entering view change phase and updated vc to %d", n.ID, viewNumber)
	n.ViewChangePhase = true
	n.ViewChangeViewNumber = viewNumber

	// Get max sequence number in log record
	maxSequenceNum := utils.Max(utils.Keys(n.LogRecords))
	// TODO: later get this from stable checkpoint
	lowerSequenceNum := int64(0)

	// Get prepared message proof set
	preparedSet := make([]*pb.PrepareProof, 0)
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		record := n.LogRecords[sequenceNum]
		if record == nil || !record.IsPrepared() {
			continue
		}
		prepareProof := record.GetPrepareProof()
		preparedSet = append(preparedSet, prepareProof)

	}

	// Create signed view change message
	viewChangeMessage := &pb.ViewChangeMessage{
		ViewNumber:  viewNumber,
		SequenceNum: lowerSequenceNum,
		PreparedSet: preparedSet,
		NodeID:      n.ID,
	}
	signedViewChangeMessage := &pb.SignedViewChangeMessage{
		Message:   viewChangeMessage,
		Signature: crypto.Sign(viewChangeMessage, n.PrivateKey),
	}
	// Byzantine node behavior: sign attack
	if n.Byzantine && n.SignAttack {
		// log.Infof("Node %s is Byzantine and is performing sign attack", n.ID)
		signedViewChangeMessage.Signature = []byte("invalid signature")
	}

	// Log the view change message
	if _, ok := n.ViewChangeMessageLog[viewNumber]; !ok {
		n.ViewChangeMessageLog[viewNumber] = make(map[string]*pb.SignedViewChangeMessage)
	}
	viewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	if _, ok := viewChangeMessageLog[viewChangeMessage.NodeID]; !ok {
		viewChangeMessageLog[viewChangeMessage.NodeID] = signedViewChangeMessage
	}

	// Multicast view change message to all nodes
	log.Infof("Sending view change message to all nodes: %s", utils.LoggingString(viewChangeMessage))
	for _, peer := range n.Peers {
		go func(peer *models.Node) {
			// Byzantine node behavior: dark attack
			if n.Byzantine && n.DarkAttack && slices.Contains(n.DarkAttackNodes, peer.ID) {
				// log.Infof("Node %s is Byzantine and is performing dark attack on node %s", n.ID, peer.ID)
				return
			}
			_, err := (*peer.Client).ViewChangeRequest(context.Background(), signedViewChangeMessage)
			if err != nil {
				return
			}
		}(peer)
	}
	return nil
}

// ViewChange handles incoming view change messages from nodes
func (n *LinearPBFTNode) ViewChangeRequest(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
	// Ignore if not alive
	if !n.Alive {
		log.Infof("Node %s is not alive", n.ID)
		return nil, status.Errorf(codes.Unavailable, "node not alive")
	}

	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber

	// Verify signature
	ok := crypto.Verify(viewChangeMessage, n.GetPublicKey(viewChangeMessage.NodeID), signedViewChangeMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(viewChangeMessage))
		return nil, status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify view number
	if viewNumber <= n.ViewNumber {
		log.Warnf("Rejected: %s; lower view number (expected: %d)", utils.LoggingString(viewChangeMessage), n.ViewNumber)
		return nil, status.Errorf(codes.FailedPrecondition, "invalid view number")
	}

	// Verify prepare set
	for _, prepareProof := range viewChangeMessage.PreparedSet {
		// Get signed preprepare message and prepare messages
		signedPrePrepareMessage := prepareProof.SignedPrePrepareMessage
		prePrepareMessage := signedPrePrepareMessage.Message
		signedPrepareMessages := prepareProof.SignedPrepareMessages

		// Get view number, sequence number and digest
		viewNumber := prePrepareMessage.ViewNumber
		sequenceNum := prePrepareMessage.SequenceNum
		digest := prePrepareMessage.Digest

		// Verify preprepare message signature
		proposerID := utils.ViewNumberToLeaderID(viewNumber, n.N)
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey(proposerID), signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature on prepare message", utils.LoggingString(viewChangeMessage))
			return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on preprepare message")
		}

		// Verify preprepare message digest
		// TODO: think what else needs to be verified
		// view number and sequence number have to accepted
		// digest may not be possible to verify if request not availables

		// Verify prepare messages signatures
		for _, signedPrepareMessage := range signedPrepareMessages {
			prepareMessage := signedPrepareMessage.Message
			ok := crypto.Verify(prepareMessage, n.GetPublicKey(prepareMessage.NodeID), signedPrepareMessage.Signature)
			if !ok {
				log.Warnf("Rejected: %s; invalid signature on prepare message", utils.LoggingString(viewChangeMessage))
				return nil, status.Errorf(codes.FailedPrecondition, "invalid signature on prepare message")
			}

			// Verify prepare message digest, view number and sequence number
			if prepareMessage.ViewNumber != viewNumber ||
				prepareMessage.SequenceNum != sequenceNum ||
				!cmp.Equal(prepareMessage.Digest, digest) {
				return nil, status.Errorf(codes.FailedPrecondition, "invalid digest on prepare message")
			}
		}
	}

	// Log the view change message
	log.Infof("Logged: %s", utils.LoggingString(viewChangeMessage))
	if _, ok := n.ViewChangeMessageLog[viewNumber]; !ok {
		n.ViewChangeMessageLog[viewNumber] = make(map[string]*pb.SignedViewChangeMessage)
	}
	viewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	if _, ok := viewChangeMessageLog[viewChangeMessage.NodeID]; !ok {
		viewChangeMessageLog[viewChangeMessage.NodeID] = signedViewChangeMessage
	}

	// Send view change message to all nodes if f + 1 view change messages are collected
	if n.ViewChangeViewNumber < viewNumber && len(viewChangeMessageLog) == int(n.F+1) {
		alreadyExpired := n.SafeTimer.Cleanup()
		if !alreadyExpired || utils.ViewNumberToLeaderID(viewNumber, n.N) != n.ID {
			log.Infof("Sending view change message to all nodes since f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			go n.SendViewChange(viewNumber)
		} else {
			log.Infof("View change timer already expired at v %d vc %d", n.ViewNumber, n.ViewChangeViewNumber)
		}
	}

	// If 2f + 1 view change messages are collected and next primary then send new view message
	if len(viewChangeMessageLog) == int(2*n.F+1) {
		if utils.ViewNumberToLeaderID(viewNumber, n.N) == n.ID {
			// Byzantine node behavior: crash attack
			if n.Byzantine && n.CrashAttack {
				// log.Infof("Node %s is Byzantine and is performing crash attack", n.ID)
				return &emptypb.Empty{}, nil
			}
			log.Infof("Sending new view message to primary since 2f + 1 view change messages are collected: %s", utils.LoggingString(viewChangeMessage))
			go n.NewViewRoutine(context.Background(), viewNumber)
		} else {
			n.SafeTimer.StartViewTimerIfNotRunning()
		}
	}

	return &emptypb.Empty{}, nil
}
