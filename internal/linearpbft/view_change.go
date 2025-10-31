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

func (n *LinearPBFTNode) ViewChangeRoutine(ctx context.Context) {
	log.Infof("Starting view change routine for %s", n.ID)
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.SafeTimer.TimeoutCh:
			log.Infof("View change routine: Timer expired")
			go n.SendViewChange()
		}
	}
}

func (n *LinearPBFTNode) SendViewChange() error {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Set sent view change flag to true and view number to current view number + 1
	// TODO: need to send view change for smallest view number of the logged view change messages or current view number + 1
	n.ViewChangePhase = true
	n.ViewNumber = n.ViewNumber + 1

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
		ViewNumber:  n.ViewNumber,
		SequenceNum: lowerSequenceNum,
		PreparedSet: preparedSet,
		NodeID:      n.ID,
	}
	signedViewChangeMessage := &pb.SignedViewChangeMessage{
		Message:   viewChangeMessage,
		Signature: crypto.Sign(viewChangeMessage, n.PrivateKey),
	}

	// Log the view change message
	if _, ok := n.ViewChangeMessageLog[viewChangeMessage.ViewNumber]; !ok {
		n.ViewChangeMessageLog[viewChangeMessage.ViewNumber] = make(map[string]*pb.SignedViewChangeMessage)
	}
	viewChangeMessageLog := n.ViewChangeMessageLog[viewChangeMessage.ViewNumber]
	if _, ok := viewChangeMessageLog[viewChangeMessage.NodeID]; !ok {
		viewChangeMessageLog[viewChangeMessage.NodeID] = signedViewChangeMessage
	}

	// Multicast view change message to all nodes
	log.Infof("Sending view change message to all nodes: %s", utils.LoggingString(viewChangeMessage))
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).ViewChange(context.Background(), signedViewChangeMessage)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	// TODO: Need to start timer here for view change timeout
	return nil
}

func (n *LinearPBFTNode) ViewChange(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	viewChangeMessage := signedViewChangeMessage.Message
	viewNumber := viewChangeMessage.ViewNumber

	// Verify signature

	ok := crypto.Verify(viewChangeMessage, n.Peers[viewChangeMessage.NodeID].PublicKey, signedViewChangeMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(viewChangeMessage))
		// return nil, status.Errorf(codes.InvalidArgument, "invalid signature")
		return nil, nil
	}

	// Verify view number
	if viewNumber <= n.ViewNumber {
		return &emptypb.Empty{}, nil
	}

	// Verify prepare set
	for _, prepareProof := range viewChangeMessage.PreparedSet {
		signedPrePrepareMessage := prepareProof.SignedPrePrepareMessage
		prePrepareMessage := signedPrePrepareMessage.Message
		signedPrepareMessages := prepareProof.SignedPrepareMessages

		viewNumber := prePrepareMessage.ViewNumber
		sequenceNum := prePrepareMessage.SequenceNum
		digest := prePrepareMessage.Digest

		// Verify preprepare message signature
		leaderID := utils.ViewNumberToLeaderID(viewNumber, n.N)
		var leaderPublicKey []byte
		if leaderID == n.ID {
			leaderPublicKey = n.PublicKey
		} else {
			leaderPublicKey = n.Peers[leaderID].PublicKey
		}
		ok := crypto.Verify(prePrepareMessage, leaderPublicKey, signedPrePrepareMessage.Signature)
		if !ok {
			// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(preprepareMessage))
			// continue
			return nil, nil
		}

		// Verify preprepare message digest
		// TODO: think what else needs to be verified
		// view number and sequence number have to accepted
		// digest may not be possible to verify if request not availables

		// Verify prepare messages signatures
		for _, signedPrepareMessage := range signedPrepareMessages {
			prepareMessage := signedPrepareMessage.Message
			// Verify signature
			var publicKey []byte
			if prepareMessage.NodeID == n.ID {
				publicKey = n.PublicKey
			} else {
				publicKey = n.Peers[prepareMessage.NodeID].PublicKey
			}
			ok := crypto.Verify(prepareMessage, publicKey, signedPrepareMessage.Signature)
			if !ok {
				// log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prepareMessage))
				return nil, nil
			}

			// Verify prepare message digest, view number and sequence number
			if prepareMessage.ViewNumber != viewNumber ||
				prepareMessage.SequenceNum != sequenceNum ||
				!cmp.Equal(prepareMessage.Digest, digest) {
				// log.Warnf("Rejected: %s; invalid digest", utils.LoggingString(prepareMessage))
				return nil, nil
			}
		}
	}

	// Log the view change message
	log.Infof("Logged view change message: %s", utils.LoggingString(viewChangeMessage))
	if _, ok := n.ViewChangeMessageLog[viewNumber]; !ok {
		n.ViewChangeMessageLog[viewNumber] = make(map[string]*pb.SignedViewChangeMessage)
	}
	viewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	if _, ok := viewChangeMessageLog[viewChangeMessage.NodeID]; !ok {
		viewChangeMessageLog[viewChangeMessage.NodeID] = signedViewChangeMessage
	}

	// Send view change message to all nodes if f + 1 view change messages are collected
	if !n.ViewChangePhase && len(viewChangeMessageLog) >= int(n.F+1) {
		go n.SendViewChange()
	}

	// If 2f + 1 view change messages are collected, go if next primary then send new view message
	if len(viewChangeMessageLog) >= int(2*n.F+1) && utils.ViewNumberToLeaderID(viewNumber, n.N) == n.ID {
		go n.SendNewView(viewNumber)
	}

	return &emptypb.Empty{}, nil
}

func (n *LinearPBFTNode) NewViewRoutine(ctx context.Context) {
	n.SendNewView(n.ViewNumber)
}

func (n *LinearPBFTNode) NewView(signedNewViewMessage *pb.SignedNewViewMessage, stream pb.LinearPBFTNode_NewViewServer) error {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	newViewMessage := signedNewViewMessage.Message
	signedViewChangeMessages := newViewMessage.SignedViewChangeMessages
	// viewNumber := newViewMessage.ViewNumber

	// Check if view number is less than current view number
	if newViewMessage.ViewNumber < n.ViewNumber {
		return status.Errorf(codes.FailedPrecondition, "view number is less than current view number")
	}

	// Verify signature
	leaderID := utils.ViewNumberToLeaderID(newViewMessage.ViewNumber, n.N)
	var leaderPublicKey []byte
	if leaderID == n.ID {
		leaderPublicKey = n.PublicKey
	} else {
		leaderPublicKey = n.Peers[leaderID].PublicKey
	}
	ok := crypto.Verify(newViewMessage, leaderPublicKey, signedNewViewMessage.Signature)
	if !ok {
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.InvalidArgument, "invalid signature")
	}

	// Verify view change messages signatures
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message

		var publicKey []byte
		if viewChangeMessage.NodeID == n.ID {
			publicKey = n.PublicKey
		} else {
			publicKey = n.Peers[viewChangeMessage.NodeID].PublicKey
		}
		ok := crypto.Verify(viewChangeMessage, publicKey, signedViewChangeMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(viewChangeMessage))
			return status.Errorf(codes.InvalidArgument, "invalid signature")
		}
	}
	// Verify preprepare messages signatures
	for _, signedPrePrepareMessage := range newViewMessage.SignedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		ok := crypto.Verify(prePrepareMessage, leaderPublicKey, signedPrePrepareMessage.Signature)
		if !ok {
			log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(prePrepareMessage))
			return status.Errorf(codes.InvalidArgument, "invalid signature")
		}
	}

	log.Infof("Logged new view message: %s", utils.LoggingString(newViewMessage))

	// Update view number
	n.ViewNumber = newViewMessage.ViewNumber
	n.ViewChangePhase = false

	// // Stream prepare messages to client
	// for _, signedPrePrepareMessage := range newViewMessage.SignedPrePrepareMessages {
	// 	signedPrepareMessage, err := n.PrePrepare(context.Background(), signedPrePrepareMessage)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	if err := stream.Send(signedPrepareMessage); err != nil {
	// 		log.Fatal(err)
	// 	}
	// }

	return nil
}

func (n *LinearPBFTNode) SendNewView(viewNumber int64) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Update view number
	n.ViewNumber = viewNumber
	n.ViewChangePhase = false

	// Get view change messages from view change message log
	viewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	signedViewChangeMessages := make([]*pb.SignedViewChangeMessage, 0)
	for _, viewChangeMessage := range viewChangeMessageLog {
		signedViewChangeMessages = append(signedViewChangeMessages, viewChangeMessage)
	}

	// TODO: later get this from stable checkpoint
	lowerSequenceNum := int64(0)

	// Aggregate preprepare messages from view change messages
	signedPrePrepareMessages := make(map[int64]*pb.SignedPrePrepareMessage)
	for _, signedViewChangeMessage := range viewChangeMessageLog {
		viewChangeMessage := signedViewChangeMessage.Message

		// Loop through prepare proofs and add to signed preprepare messages if not already added
		for _, prepareProof := range viewChangeMessage.PreparedSet {
			prePrepareMessage := prepareProof.SignedPrePrepareMessage.Message
			sequenceNum := prePrepareMessage.SequenceNum

			if _, ok := signedPrePrepareMessages[sequenceNum]; ok {
				continue
			}

			// Create new preprepare message and add to signed preprepare messages
			newPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      prePrepareMessage.Digest,
			}
			signedPrePrepareMessages[sequenceNum] = &pb.SignedPrePrepareMessage{
				Message:   newPrePrepareMessage,
				Signature: crypto.Sign(newPrePrepareMessage, n.PrivateKey),
			}
		}
	}
	// Order signed preprepare messages by sequence number and add no op preprepare message if sequence number is not in the log record
	sortedSignedPrePrepareMessages := make([]*pb.SignedPrePrepareMessage, 0)
	maxSequenceNum := utils.Max(utils.Keys(signedPrePrepareMessages))
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		var newSignedPrePrepareMessage *pb.SignedPrePrepareMessage
		if _, ok := signedPrePrepareMessages[sequenceNum]; !ok {
			newPrePrepareMessage := &pb.PrePrepareMessage{
				ViewNumber:  viewNumber,
				SequenceNum: sequenceNum,
				Digest:      crypto.Digest(NoOpTransactionRequest),
			}
			newSignedPrePrepareMessage = &pb.SignedPrePrepareMessage{
				Message:   newPrePrepareMessage,
				Signature: crypto.Sign(newPrePrepareMessage, n.PrivateKey),
			}
		} else {
			newSignedPrePrepareMessage = signedPrePrepareMessages[sequenceNum]
		}
		sortedSignedPrePrepareMessages = append(sortedSignedPrePrepareMessages, newSignedPrePrepareMessage)
		continue
	}

	// Create new view message and sign it
	newViewMessage := &pb.NewViewMessage{
		ViewNumber:               viewNumber,
		SignedViewChangeMessages: signedViewChangeMessages,
		SignedPrePrepareMessages: sortedSignedPrePrepareMessages,
	}
	signedNewViewMessage := &pb.SignedNewViewMessage{
		Message:   newViewMessage,
		Signature: crypto.Sign(newViewMessage, n.PrivateKey),
	}

	// Multicast new view message to all nodes
	log.Infof("Sending new view message for view number %d: %s", viewNumber, utils.LoggingString(newViewMessage))
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).NewView(context.Background(), signedNewViewMessage)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	// Install a receive for prepare messages
}
