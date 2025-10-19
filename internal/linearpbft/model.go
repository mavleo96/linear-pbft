package linearpbft

import (
	"github.com/mavleo96/bft-mavleo96/internal/database"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// LinearPBFT represents a LinearPBFT node
type LinearPBFTServer struct {
	*models.Node
	DB *database.Database
	*pb.UnimplementedLinearPBFTServer
}
