package clientapp

// TODO: consider alternatives: clientlib, clientcore

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type ClientAppServer struct {
	*models.Client
	PrivateKey        []byte
	CurrentTimestamp  int64
	CurrentViewNumber int64
	F                 int64
	Nodes             map[string]*models.Node
	Counter           map[string]int64
	SignalCh          chan *TestSet                // TODO: should be closed by send routine
	ResponseCh        chan *pb.TransactionResponse // TODO: should be closed by receive routine
	ResultCh          chan int64                   // TODO: should be closed by receive routine
	pb.UnimplementedLinearPBFTClientAppServer
}

func (s *ClientAppServer) ClientReceiveRoutine(ctx context.Context) {
	log.Infof("Starting client receive routine for %s", s.ID)
	// Listen on client address
	lis, err := net.Listen("tcp", s.Client.Address)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()
	grpcServer := grpc.NewServer()
	pb.RegisterLinearPBFTClientAppServer(grpcServer, s)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	// Main receive loop
	replyMap := make(map[string]int64)
	majorityReached := false

	for {
		select {
		case <-ctx.Done():
			return
		case resp := <-s.ResponseCh:
			// Ignore replies for old timestamps or if majority has been reached
			if resp.Timestamp < s.CurrentTimestamp {
				continue
			} else if resp.Timestamp > s.CurrentTimestamp || resp.ViewNumber > s.CurrentViewNumber {
				// Reset reply map and state record if new view number or timestamp is greater
				s.CurrentTimestamp = resp.Timestamp
				s.CurrentViewNumber = resp.ViewNumber
				replyMap = make(map[string]int64)
				majorityReached = false
			} else if majorityReached {
				continue
			}
			// Record reply
			replyMap[resp.NodeID] = resp.Result

			// Check if f+1 matching values have been received
			// and respond on result channel with the value
			maxVal, maxCnt := CounterFunction(replyMap)
			if maxCnt >= s.F+1 {
				majorityReached = true
				s.ResultCh <- maxVal
			}
		}
	}
}

// ClientRoutine is a persistent routine that processes transactions for a client
func (s *ClientAppServer) ClientSendRoutine(ctx context.Context) {
	log.Infof("Starting client send routine for %s", s.ID)
	for {
		select {
		// Wait for set id to process from main routine
		case testSet := <-s.SignalCh:
			leaderNode := "n1" // leader initialized to n1 by default
			// Process transactions for the set
			for _, t := range testSet.Transactions[s.ID] {
				// Create a signed transaction request
				timestamp := time.Now().UnixMilli()
				request := &pb.TransactionRequest{
					Transaction: t,
					Timestamp:   timestamp,
					Sender:      s.ID,
				}
				signedRequest := &pb.SignedTransactionRequest{
					Request:   request,
					Signature: security.Sign(request, s.PrivateKey),
				}
				// TODO: processTransaction functions error design is not good
				if t.Type == "read" {
					result, err := processReadOnlyTransaction(signedRequest, s.ID, &leaderNode, s.Nodes)
					if err != nil {
						log.Warnf("%s: %s -> %s", s.ID, request.String(), err.Error())
					} else {
						log.Infof("%s: %s -> %d", s.ID, request.String(), result)
						continue
					}
				}
				result, err := processTransaction(signedRequest, s.ID, &leaderNode, s.Nodes, s.ResultCh)
				if err != nil {
					log.Fatal(err)
				}
				log.Infof("%s: %s -> %d", s.ID, request.String(), result)
			}
			// Signal main routine that the set is done
			s.SignalCh <- nil

		// Exit signal
		case <-ctx.Done():
			close(s.SignalCh)
			log.Infof("%s received exit signal", s.ID)
			return
		}
	}
}

func (s *ClientAppServer) ReceiveReply(ctx context.Context, resp *pb.SignedTransactionResponse) (*emptypb.Empty, error) {
	message := resp.Message

	// Verify signature and ignore replies with invalid signature
	ok := security.Verify(message, s.Nodes[message.NodeID].PublicKey, resp.Signature)
	if !ok {
		log.Warnf("Invalid signature for reply from node %s", message.NodeID)
		return &emptypb.Empty{}, nil
	}

	// Send reply to client receive routine
	s.ResponseCh <- message

	return &emptypb.Empty{}, nil
}

// Max return the key whose value is maximum
func CounterFunction(m map[string]int64) (int64, int64) {
	count := make(map[int64]int64)
	for _, v := range m {
		count[v]++
	}
	maxVal := int64(0)
	maxCnt := int64(0)
	for k, v := range count {
		if v > maxCnt {
			maxVal = k
			maxCnt = v
		}
	}
	return maxVal, maxCnt
}

func CreateClientAppServer(ctx context.Context, client *models.Client, nodes map[string]*models.Node) (chan *TestSet, error) {
	privateKey, err := security.ReadPrivateKey(filepath.Join("./keys", "client", client.ID+".pem"))
	if err != nil {
		log.Fatal(err)
	}
	clientAppServer := &ClientAppServer{
		Client:            client,
		PrivateKey:        privateKey,
		CurrentTimestamp:  0,
		CurrentViewNumber: 0,
		Nodes:             nodes,
		F:                 int64((len(nodes) - 1) / 3),
		Counter:           make(map[string]int64),
		SignalCh:          make(chan *TestSet),
		ResponseCh:        make(chan *pb.TransactionResponse, 100),
		ResultCh:          make(chan int64),
	}

	go clientAppServer.ClientReceiveRoutine(ctx)
	go clientAppServer.ClientSendRoutine(ctx)

	return clientAppServer.SignalCh, nil
}
