package linearpbftdb

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/magiconair/properties"
	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/pingcap/go-ycsb/pkg/util"
	"github.com/pingcap/go-ycsb/pkg/ycsb"
	log "github.com/sirupsen/logrus"
)

// LinearPBFTDB represents a LinearPBFT database
type LinearPBFTDB struct {
	n       int64
	f       int64
	p       *properties.Properties
	nodeMap map[string]*models.Node
	r       *util.RowCodec
	bufPool *util.BufPool
}

// LinearPBFTDBCreator implements ycsb.DBCreator
type LinearPBFTDBCreator struct{}

// Create creates a new LinearPBFTDB instance
func (c *LinearPBFTDBCreator) Create(props *properties.Properties) (ycsb.DB, error) {
	// Read from config file
	cfg, err := config.ParseConfig("./configs/config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Get node map and connections
	nodeMap, err := models.GetNodeMap(cfg.Nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to get node map: %v", err)
	}

	// Create LinearPBFTDB instance
	db := &LinearPBFTDB{
		n:       int64(len(nodeMap)),
		f:       int64((len(nodeMap) - 1) / 3),
		p:       props,
		nodeMap: nodeMap,
		r:       util.NewRowCodec(props),
		bufPool: util.NewBufPool(),
	}

	return db, nil
}

// contextKey represents a context key
type contextKey string

const clientIDKey contextKey = "clientID"
const privateKeyKey contextKey = "privateKey"

// InitThread initializes thread-specific state
func (p *LinearPBFTDB) InitThread(ctx context.Context, threadID int, threadCount int) context.Context {
	// Note: thread related state is passed as part of the context

	// Assign thread ID as client ID
	clientID := string(rune(threadID + 65))
	ctx = context.WithValue(ctx, clientIDKey, clientID)

	// Get private key for this thread
	privateKey, err := crypto.ReadPrivateKey(filepath.Join("./keys", "client", fmt.Sprintf("%s_secret.key", clientID)))
	if err != nil {
		log.Fatal(err)
	}
	ctx = context.WithValue(ctx, privateKeyKey, privateKey)

	return ctx
}

// Close closes all connections
func (p *LinearPBFTDB) Close() error {
	for _, node := range p.nodeMap {
		node.Close()
	}
	return nil
}

// CleanupThread cleans up thread-specific state
func (p *LinearPBFTDB) CleanupThread(_ context.Context) {
}

// Register registers the LinearPBFTDB creator
func Register() {
	ycsb.RegisterDBCreator("linearpbftdb", &LinearPBFTDBCreator{})
}
