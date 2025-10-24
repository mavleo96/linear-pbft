package linearpbft

import (
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// LinearPBFTNode represents a LinearPBFT node
type LinearPBFTNode struct {
	*models.Node
	PrivateKey []byte
	DB         *database.Database

	Peers   map[string]*models.Node
	F       int
	N       int
	Clients map[string]*models.Client

	Mutex         sync.Mutex
	ViewNumber    int64
	PrePrepareLog map[int64]*pb.PrePrepareMessage
	PrepareLog    map[int64]*pb.PrepareMessage
	CommitLog     map[int64]*pb.CommitMessage

	TransactionMap map[[32]byte]*pb.TransactionRequest

	*pb.UnimplementedLinearPBFTNodeServer
}
