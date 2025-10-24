package linearpbft

import (
	"context"
	"errors"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) SendPrePrepare(request *pb.TransactionRequest) ([]*pb.SignedPrepareMessage, error) {
	// Assign sequence number to request
	sequenceNum := n.AssignSequenceNumber(request)

	// Create preprepare message and sign it
	preprepare := &pb.PrePrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      security.Digest(request),
	}
	signedPreprepare := &pb.SignedPrePrepareMessage{
		Message:   preprepare,
		Signature: security.Sign(preprepare, n.PrivateKey),
		Request:   request,
	}

	// Add preprepare message to preprepare log
	n.Mutex.Lock()
	n.PrePreparedLog[sequenceNum] = &LogRecord{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      security.Digest(request),
	}
	log.Infof("Preprepared (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(request))
	n.Mutex.Unlock()

	// Multicast preprepare message to all nodes
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Peers))
	log.Infof("Sending preprepare (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(request))
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Go(func() {
			signedPrepareMsg, err := (*peer.Client).PrePrepare(context.Background(), signedPreprepare)
			if err != nil {
				log.Fatal(err)
			}
			responseCh <- signedPrepareMsg
		})
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	for range len(n.Peers) {
		signedPrepareMsg := <-responseCh
		if signedPrepareMsg == nil {
			continue
		}
		signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMsg)
		if len(signedPrepareMsgs) == int(n.N-n.F) {
			log.Infof("Prepare messages collected for sequence number %d", sequenceNum)
			return signedPrepareMsgs, nil
		}
	}
	log.Infof("Prepare messages not collected for sequence number %d", sequenceNum)
	return nil, nil
}

func (n *LinearPBFTNode) SendPrepare(signedPrepareMessages []*pb.SignedPrepareMessage, sequenceNum int64) ([]*pb.SignedCommitMessage, error) {
	// Create collected signed prepare message
	collectedSignedPrepareMessage := &pb.CollectedSignedPrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Messages:    signedPrepareMessages,
	}

	// Multicast prepare message to all nodes
	responseCh := make(chan *pb.SignedCommitMessage, len(n.Peers))
	// defer close(responseCh)
	log.Infof("Sending prepare message for sequence number %d", sequenceNum)
	wg := sync.WaitGroup{}
	for _, peer := range n.Peers {
		wg.Go(func() {
			signedCommitMsg, err := (*peer.Client).Prepare(context.Background(), collectedSignedPrepareMessage)
			if err != nil {
				log.Fatal(err)
			}
			responseCh <- signedCommitMsg
		})
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Get preprepare record from preprepare log
	n.Mutex.Lock()
	preprepareRecord := n.PrePreparedLog[sequenceNum]
	n.Mutex.Unlock()
	if preprepareRecord == nil {
		log.Fatal("Preprepare record is nil")
	}

	// Verify the prepare messages
	verifiedCount := 0
	for _, signedPrepareMessage := range signedPrepareMessages {
		if signedPrepareMessage == nil {
			log.Fatal("Signed prepare message is nil")
		}
		prepareMessage := signedPrepareMessage.Message

		// Verify Signature
		ok := security.Verify(prepareMessage, n.Peers[prepareMessage.NodeID].PublicKey, signedPrepareMessage.Signature)
		if !ok {
			continue
		}

		// Check if the prepare message matches preprepare message
		if prepareMessage.ViewNumber != preprepareRecord.ViewNumber ||
			prepareMessage.SequenceNum != preprepareRecord.SequenceNum ||
			!cmp.Equal(prepareMessage.Digest, preprepareRecord.Digest) {
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	signedCommitMsgs := make([]*pb.SignedCommitMessage, 0)

	// If 2f matching prepare messages are collected, then log the prepare message
	if verifiedCount >= int(2*n.F) {
		log.Infof("Verified prepare messages for sequence number %d", sequenceNum)
		n.Mutex.Lock()
		n.PreparedLog[sequenceNum] = &LogRecord{
			ViewNumber:  n.ViewNumber,
			SequenceNum: sequenceNum,
			Digest:      preprepareRecord.Digest,
		}
		log.Infof("Prepared (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(n.TransactionMap[utils.To32Bytes(preprepareRecord.Digest)]))
		n.Mutex.Unlock()
		commitMessage := &pb.CommitMessage{
			ViewNumber:  n.ViewNumber,
			SequenceNum: sequenceNum,
			Digest:      preprepareRecord.Digest,
			NodeID:      n.ID,
		}
		signedCommitMsgs = append(signedCommitMsgs, &pb.SignedCommitMessage{
			Message:   commitMessage,
			Signature: security.Sign(commitMessage, n.PrivateKey),
		})
	} else {
		n.Mutex.Lock()
		log.Warnf("Not enough prepare messages to prepare message (v: %d, s: %d)", n.ViewNumber, sequenceNum)
		n.Mutex.Unlock()
	}

	for range len(n.Peers) {
		signedCommitMsg := <-responseCh
		if signedCommitMsg == nil {
			continue
		}
		signedCommitMsgs = append(signedCommitMsgs, signedCommitMsg)
		if len(signedCommitMsgs) == int(n.N-n.F) {
			log.Infof("Collected commit message for sequence number %d", sequenceNum)
			return signedCommitMsgs, nil
		}
	}
	return nil, nil
}

func (n *LinearPBFTNode) SendCommit(signedCommitMessages []*pb.SignedCommitMessage, sequenceNum int64) error {
	// Create collected signed commit message
	collectedSignedCommitMessage := &pb.CollectedSignedCommitMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Messages:    signedCommitMessages,
	}

	// Multicast commit message to all nodes
	log.Infof("Sending commit message for sequence number %d", sequenceNum)
	for _, peer := range n.Peers {
		go func() {
			_, err := (*peer.Client).Commit(context.Background(), collectedSignedCommitMessage)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	// Get prepared record from prepared log
	n.Mutex.Lock()
	preparedRecord := n.PreparedLog[sequenceNum]
	n.Mutex.Unlock()
	if preparedRecord == nil {
		log.Fatal("Prepared record is nil")
	}

	// Verify the commit messages
	verifiedCount := 0
	for _, signedCommitMessage := range signedCommitMessages {
		if signedCommitMessage == nil {
			log.Fatal("Signed commit message is nil")
		}
		commitMessage := signedCommitMessage.Message

		// Verify Signature
		if commitMessage.NodeID == n.ID {
			verifiedCount++
			continue
		}
		ok := security.Verify(commitMessage, n.Peers[commitMessage.NodeID].PublicKey, signedCommitMessage.Signature)
		if !ok {
			continue
		}

		// Check if the commit message matches prepare message
		if commitMessage.ViewNumber != preparedRecord.ViewNumber ||
			commitMessage.SequenceNum != preparedRecord.SequenceNum ||
			!cmp.Equal(commitMessage.Digest, preparedRecord.Digest) {
			continue
		}

		// Increment verified count
		verifiedCount++
	}

	if verifiedCount >= int(2*n.F+1) {
		log.Infof("Verified commit messages for sequence number %d", sequenceNum)
		n.Mutex.Lock()
		n.CommittedLog[sequenceNum] = &LogRecord{
			ViewNumber:  n.ViewNumber,
			SequenceNum: sequenceNum,
			Digest:      preparedRecord.Digest,
		}
		log.Infof("Committed (v: %d, s: %d): %s", n.ViewNumber, sequenceNum, utils.LoggingString(n.TransactionMap[utils.To32Bytes(preparedRecord.Digest)]))
		n.Mutex.Unlock()
		return nil
	}

	log.Warnf("Not enough commit messages to commit message (v: %d, s: %d)", n.ViewNumber, sequenceNum)
	return errors.New("not enough commit messages")
}
