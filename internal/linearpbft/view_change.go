package linearpbft

import (
	"context"
	"io"
	"sync"

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
			log.Infof("View change routine: Timer expired")

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
		go func() {
			_, err := (*peer.Client).ViewChangeRequest(context.Background(), signedViewChangeMessage)
			if err != nil {
				return
			}
		}()
	}
	return nil
}

// ViewChange handles incoming view change messages from nodes
func (n *LinearPBFTNode) ViewChangeRequest(ctx context.Context, signedViewChangeMessage *pb.SignedViewChangeMessage) (*emptypb.Empty, error) {
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
	if !n.ViewChangePhase && len(viewChangeMessageLog) >= int(n.F+1) {
		go n.SendViewChange(viewNumber)
	}

	// If 2f + 1 view change messages are collected and next primary then send new view message
	if len(viewChangeMessageLog) >= int(2*n.F+1) {
		if utils.ViewNumberToLeaderID(viewNumber, n.N) == n.ID {
			go n.SendNewView(viewNumber)
		} else {
			n.SafeTimer.IncrementWaitCountOrStart()
		}
	}

	return &emptypb.Empty{}, nil
}

// NewViewRoutine is a routine that handles sending new view messages to all nodes
func (n *LinearPBFTNode) NewViewRoutine(ctx context.Context) {
	n.SendNewView(n.ViewNumber)
}

func (n *LinearPBFTNode) NewViewRequest(signedNewViewMessage *pb.SignedNewViewMessage, stream pb.LinearPBFTNode_NewViewRequestServer) error {
	n.Mutex.Lock()
	newViewMessage := signedNewViewMessage.Message
	signedViewChangeMessages := newViewMessage.SignedViewChangeMessages
	signedPrePrepareMessages := newViewMessage.SignedPrePrepareMessages
	viewNumber := newViewMessage.ViewNumber

	// Check if view number matches latest sent view change message view number
	if viewNumber != n.ViewChangeViewNumber {
		n.Mutex.Unlock()
		log.Warnf("Rejected: %s; view number does not match latest sent view change message view number", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.FailedPrecondition, "view number does not match latest sent view change message view number")
	}

	// Verify signature
	leaderID := utils.ViewNumberToLeaderID(viewNumber, n.N)
	ok := crypto.Verify(newViewMessage, n.GetPublicKey(leaderID), signedNewViewMessage.Signature)
	if !ok {
		n.Mutex.Unlock()
		log.Warnf("Rejected: %s; invalid signature", utils.LoggingString(newViewMessage))
		return status.Errorf(codes.Unauthenticated, "invalid signature")
	}

	// Verify view change messages signatures
	for _, signedViewChangeMessage := range signedViewChangeMessages {
		viewChangeMessage := signedViewChangeMessage.Message
		ok := crypto.Verify(viewChangeMessage, n.GetPublicKey(viewChangeMessage.NodeID), signedViewChangeMessage.Signature)
		if !ok {
			n.Mutex.Unlock()
			log.Warnf("Rejected: %s; invalid signature on view change message", utils.LoggingString(newViewMessage))
			return status.Errorf(codes.Unauthenticated, "invalid signature on view change message")
		}
	}

	// Verify preprepare messages signatures
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		ok := crypto.Verify(prePrepareMessage, n.GetPublicKey(leaderID), signedPrePrepareMessage.Signature)
		if !ok {
			n.Mutex.Unlock()
			log.Warnf("Rejected: %s; invalid signature on preprepare message", utils.LoggingString(newViewMessage))
			return status.Errorf(codes.Unauthenticated, "invalid signature on preprepare message")
		}
	}

	// Cleanup timer and update view number
	n.SafeTimer.Cleanup()
	n.ViewNumber = viewNumber
	n.ViewChangePhase = false
	log.Infof("Accepted %s", utils.LoggingString(newViewMessage))
	n.Mutex.Unlock()

	// Stream prepare messages to client
	for _, signedPrePrepareMessage := range signedPrePrepareMessages {
		signedPrepareMessage, err := n.PrePrepareRequest(context.Background(), signedPrePrepareMessage)
		if err != nil {
			log.Fatal(err)
		}
		if err := stream.Send(signedPrepareMessage); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Streamed prepares messages for view number %d", viewNumber)
	return nil
}

// SendNewView sends a new view message to all nodes
func (n *LinearPBFTNode) SendNewView(viewNumber int64) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	// Update view number
	n.ViewNumber = viewNumber
	n.ViewChangePhase = false

	// Get view change messages from view change message log
	signedViewChangeMessageLog := n.ViewChangeMessageLog[viewNumber]
	signedViewChangeMessages := make([]*pb.SignedViewChangeMessage, 0)
	for _, signedViewChangeMessage := range signedViewChangeMessageLog {
		signedViewChangeMessages = append(signedViewChangeMessages, signedViewChangeMessage)
	}

	// TODO: later get this from stable checkpoint in the new view message
	lowerSequenceNum := int64(0)

	// Aggregate preprepare messages from view change messages and create preprepare message with current view number
	signedPrePrepareMessages := make(map[int64]*pb.SignedPrePrepareMessage)
	for _, signedViewChangeMessage := range signedViewChangeMessageLog {
		viewChangeMessage := signedViewChangeMessage.Message

		// Loop through prepare proofs and add to signed preprepare messages if not already added
		for _, prepareProof := range viewChangeMessage.PreparedSet {
			prePrepareMessage := prepareProof.SignedPrePrepareMessage.Message
			sequenceNum := prePrepareMessage.SequenceNum

			// If preprepare message is already in the map, then continue
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

	// Order signed preprepare messages by sequence number
	sortedSignedPrePrepareMessages := make([]*pb.SignedPrePrepareMessage, 0)
	maxSequenceNum := utils.Max(utils.Keys(signedPrePrepareMessages))
	for sequenceNum := lowerSequenceNum + 1; sequenceNum <= maxSequenceNum; sequenceNum++ {
		// If preprepare message is not in the map, then create a new no op preprepare message and add to the map
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
	}

	// TODO: leader needs to first preprepare the request in its own log record
	for _, signedPrePrepareMessage := range sortedSignedPrePrepareMessages {
		prePrepareMessage := signedPrePrepareMessage.Message
		sequenceNum := prePrepareMessage.SequenceNum
		record := n.LogRecords[sequenceNum]
		if record == nil {
			record = CreateLogRecord(viewNumber, sequenceNum, crypto.Digest(NoOpTransactionRequest))
			n.LogRecords[sequenceNum] = record
		} else {
			log.Infof("Before reset: %s", record.LogString())
			record.Reset(viewNumber, prePrepareMessage.Digest)
			log.Infof("After reset: %s", record.LogString())

			// Get missing via get request
			if signedRequest := n.TransactionMap.Get(record.Digest); signedRequest == nil {
				response, err := n.SendGetRequest(record.Digest)
				if err != nil || response == nil {
					log.Fatal(err)
				}
				signedRequest = response
				n.TransactionMap.Set(record.Digest, signedRequest)
				log.Infof("Adding request to log record: %s", record.LogString())
			}

			log.Infof("request after add request: %s", record.LogString())
			record.AddPrePrepareMessage(signedPrePrepareMessage)
		}
	}
	// Print current log state
	for sequenceNum, record := range n.LogRecords {
		log.Infof("Log record for sequence number %d: %s", sequenceNum, record.LogString())
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

	// Multicast new view message to all nodes and collect signed prepare messages
	log.Infof("Sending new view message for view number %d: %s", viewNumber, utils.LoggingString(newViewMessage))
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	collectedSignedPrepareMessages := make(map[int64][]*pb.SignedPrepareMessage)
	for _, peer := range n.Peers {
		wg.Add(1)
		go func(peer *models.Node) {
			defer wg.Done()
			stream, err := (*peer.Client).NewViewRequest(context.Background(), signedNewViewMessage)
			if err != nil {
				return
			}

			// Stream prepare messages from peer
			for {
				signedPrepareMessage, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Warn(err)
					return
				}

				sequenceNum := signedPrepareMessage.Message.SequenceNum
				mu.Lock()
				collectedSignedPrepareMessages[sequenceNum] = append(collectedSignedPrepareMessages[sequenceNum], signedPrepareMessage)
				mu.Unlock()
			}
		}(peer)
	}
	wg.Wait()

	// Print collected signed prepare messages
	for sequenceNum, signedPrepareMessages := range collectedSignedPrepareMessages {
		log.Infof("Collected %d signed prepare messages for sequence number %d", len(signedPrepareMessages), sequenceNum)
		for _, signedPrepareMessage := range signedPrepareMessages {
			log.Infof("Signed prepare message: %s", utils.LoggingString(signedPrepareMessage.Message, NoOpTransactionRequest))
		}
	}
}
