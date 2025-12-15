package linearpbft

import (
	"slices"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/mavleo96/linear-pbft/internal/crypto"
	"github.com/mavleo96/linear-pbft/internal/models"
	"github.com/mavleo96/linear-pbft/internal/utils"
	"github.com/mavleo96/linear-pbft/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SendGetRequest sends a get request to all nodes for a given sequence number
func (n *LinearPBFTNode) SendGetRequest(digest []byte) (*pb.SignedTransactionRequest, error) {
	getRequestMessage := &pb.GetRequestMessage{
		Digest: digest,
		NodeID: n.ID,
	}

	// Multicast get request to all nodes
	responseCh := make(chan *pb.SignedTransactionRequest, len(n.handler.peers))
	wg := sync.WaitGroup{}
	log.Infof("Sending get request: %s", utils.LoggingString(getRequestMessage))
	for _, peer := range n.handler.peers {
		wg.Add(1)
		go func(peer *models.Node) {
			defer wg.Done()

			// Byzantine node behavior: dark attack
			if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, peer.ID) {
				return
			}

			signedRequest, err := n.Transport.GetRequest(n.serverCtx, peer.ID, getRequestMessage)
			if err != nil {
				return
			}
			responseCh <- signedRequest
		}(peer)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Return the first valid response
	for signedRequest := range responseCh {
		request := signedRequest.Request

		if request == nil {
			continue
		}

		// Verify client signature
		if !cmp.Equal(crypto.Digest(signedRequest), DigestNoOp) &&
			!crypto.Verify(request, n.clients[request.Sender].PublicKey, signedRequest.Signature) {
			log.Warnf("Rejected: %s; invalid signature on request", utils.LoggingString(signedRequest))
			continue
		}

		// Verify if digest is same as in log record
		if !cmp.Equal(crypto.Digest(signedRequest), digest) {
			log.Warnf("Rejected: %s; invalid digest on request", utils.LoggingString(signedRequest))
			continue
		}

		return signedRequest, nil
	}
	log.Warnf("Missing request: %s; could not be retrieved from any node", utils.LoggingString(getRequestMessage))
	return nil, status.Errorf(codes.NotFound, "request not found")
}

// SendGetCheckpoint sends a get check point request to all nodes for a given sequence number
func (n *LinearPBFTNode) SendGetCheckpoint(sequenceNum int64) (*pb.Checkpoint, error) {
	getCheckpointMessage := &pb.GetCheckpointMessage{
		SequenceNum: sequenceNum,
		NodeID:      n.ID,
	}

	responseCh := make(chan *pb.Checkpoint, len(n.handler.peers))
	wg := sync.WaitGroup{}
	log.Infof("Sending get check point request: %s", utils.LoggingString(getCheckpointMessage))
	for _, peer := range n.handler.peers {
		wg.Add(1)
		go func(peer *models.Node) {
			defer wg.Done()

			// Byzantine node behavior: dark attack
			if n.byzantineConfig.Byzantine && n.byzantineConfig.DarkAttack && slices.Contains(n.byzantineConfig.DarkAttackNodes, peer.ID) {
				return
			}

			checkpoint, err := n.Transport.GetCheckpoint(n.serverCtx, peer.ID, getCheckpointMessage)
			if err != nil {
				return
			}
			responseCh <- checkpoint
		}(peer)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Return the first valid response
	for checkpoint := range responseCh {
		if checkpoint == nil || checkpoint.Snapshot == nil {
			continue
		}

		// Verify check point digest
		if !cmp.Equal(crypto.DigestAny(checkpoint.Snapshot), checkpoint.Digest) {
			log.Warnf("Rejected: %s; invalid check point digest", utils.LoggingString(getCheckpointMessage))
			continue
		}
		log.Infof("Got checkpoint sequence number %d: %s", sequenceNum, utils.LoggingString(checkpoint))
		return checkpoint, nil
	}
	log.Warnf("Missing check point sequence number %d: %s; could not be retrieved from any node", sequenceNum, utils.LoggingString(getCheckpointMessage))
	return nil, status.Errorf(codes.NotFound, "check point not found")
}
