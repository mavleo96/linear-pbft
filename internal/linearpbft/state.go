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
	F       int64
	N       int64
	Clients map[string]*models.Client

	Mutex          sync.Mutex
	ViewNumber     int64
	PrePreparedLog map[int64]*LogRecord
	PreparedLog    map[int64]*LogRecord
	CommittedLog   map[int64]*LogRecord

	TransactionMap map[[32]byte]*pb.TransactionRequest

	*pb.UnimplementedLinearPBFTNodeServer
}

type LogRecord struct {
	ViewNumber  int64
	SequenceNum int64
	Digest      []byte
}
