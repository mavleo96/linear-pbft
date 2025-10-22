package linearpbft

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func (n *LinearPBFTNode) SendPrePrepare(request *pb.TransactionRequest) ([]*pb.SignedPrepareMessage, error) {
	// Compute digest of request
	digest := security.Digest(request.String())

	// Assign sequence number to request
	sequenceNum := n.AssignSequenceNumber(request)

	// Create preprepare message and sign it
	preprepare := &pb.PrePrepareMessage{
		ViewNumber:  n.ViewNumber,
		SequenceNum: sequenceNum,
		Digest:      digest,
	}
	signedPreprepare := &pb.SignedPrePrepareMessage{
		Message:   preprepare,
		Signature: security.Sign(preprepare.String(), n.PrivateKey),
		Request:   request,
	}

	// Add preprepare message to preprepare log
	n.PrePrepareLog[sequenceNum] = preprepare
	log.Infof("Logged preprepare message for sequence number %d", sequenceNum)

	// Multicast preprepare message to all nodes
	responseCh := make(chan *pb.SignedPrepareMessage, len(n.Peers))
	log.Infof("Sending preprepare message for sequence number %d", sequenceNum)
	for _, peer := range n.Peers {
		go func() {
			signedPrepareMsg, err := (*peer.Client).PrePrepare(context.Background(), signedPreprepare)
			if err != nil {
				log.Fatal(err)
			}
			responseCh <- signedPrepareMsg
		}()
	}

	signedPrepareMsgs := make([]*pb.SignedPrepareMessage, 0)
	for range len(n.Peers) - n.F + 1 {
		signedPrepareMsg := <-responseCh
		signedPrepareMsgs = append(signedPrepareMsgs, signedPrepareMsg)
		log.Infof("Collected prepare message for sequence number %d", sequenceNum)
	}

	return signedPrepareMsgs, nil
}
