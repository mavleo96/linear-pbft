package linearpbftdb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
)

// Read reads a record from PBFT
func (p *LinearPBFTDB) Read(ctx context.Context, table string, key string, fields []string) (map[string][]byte, error) {
	tx := &pb.Transaction{
		Type:   "ycsb_read",
		Sender: ctx.Value(clientIDKey).(string),
		Key:    key,
		Fields: fields,
	}
	request := &pb.TransactionRequest{
		Transaction: tx,
		Timestamp:   time.Now().UnixNano(),
		Sender:      ctx.Value(clientIDKey).(string),
	}
	signedRequest := &pb.SignedTransactionRequest{
		Request:   request,
		Signature: crypto.Sign(request, ctx.Value(privateKeyKey).(*bls.SecretKey)),
	}

	// Send request to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, len(p.nodeMap))
	wg := sync.WaitGroup{}
	for _, node := range p.nodeMap {
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			response, err := (*n.Client).BenchmarkRPC(ctx, signedRequest)
			if err == nil && response != nil {
				responseCh <- response
			}
		}(node)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Check for f+1 matching values
	// Use hashable keys (map keys) instead of maps directly
	responseMap := make(map[[32]byte]int64)
	valueMap := make(map[[32]byte]map[string][]byte)
	for response := range responseCh {
		if response != nil && response.Message != nil {
			if response.Message.Error != "" {
				// return nil, fmt.Errorf("PBFT error: %s", response.Message.Error)
				continue
			}
			key := mapKey(response.Message.ResultData)
			responseMap[key]++
			// Store the actual value for this key (overwrites are fine since they're the same)
			valueMap[key] = response.Message.ResultData
		}
	}
	if len(responseMap) == 0 {
		return nil, fmt.Errorf("no responses received from nodes")
	}
	maxKey, maxCnt := utils.MaxByValue(responseMap)
	if maxCnt >= p.f+1 {
		return valueMap[maxKey], nil
	}
	return nil, fmt.Errorf("no majority reached (got %d matching responses, need %d)", maxCnt, p.f+1)
}

// Scan scans records from PBFT
func (p *LinearPBFTDB) Scan(ctx context.Context, table string, startKey string, count int, fields []string) ([]map[string][]byte, error) {
	// Use ReadOnlyRequest for scans (synchronous, no consensus)
	tx := &pb.Transaction{
		Type:      "ycsb_scan",
		Sender:    ctx.Value(clientIDKey).(string),
		StartKey:  startKey,
		ScanCount: int64(count),
		Fields:    fields,
	}
	request := &pb.TransactionRequest{
		Transaction: tx,
		Timestamp:   time.Now().UnixNano(),
		Sender:      ctx.Value(clientIDKey).(string),
	}
	signedRequest := &pb.SignedTransactionRequest{
		Request:   request,
		Signature: crypto.Sign(request, ctx.Value(privateKeyKey).(*bls.SecretKey)),
	}

	// Send request to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, len(p.nodeMap))
	wg := sync.WaitGroup{}
	for _, node := range p.nodeMap {
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			response, err := (*n.Client).BenchmarkRPC(ctx, signedRequest)
			if err == nil && response != nil {
				responseCh <- response
			}
		}(node)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Check for f+1 matching values
	// Use hashable keys instead of slices directly
	responseMap := make(map[[32]byte]int64)
	valueMap := make(map[[32]byte][]map[string][]byte)
	for response := range responseCh {
		if response != nil && response.Message != nil {
			if response.Message.Error != "" {
				// return nil, fmt.Errorf("PBFT error: %s", response.Message.Error)
				continue
			}
			// Convert []*pb.ScanResult to []map[string][]byte
			scanResults := make([]map[string][]byte, 0, len(response.Message.ScanResults))
			for _, sr := range response.Message.ScanResults {
				if sr != nil {
					scanResults = append(scanResults, sr.Fields)
				}
			}
			key := scanResultsKey(response.Message.ScanResults)
			responseMap[key]++
			// Store the actual value for this key
			valueMap[key] = scanResults
		}
	}
	if len(responseMap) == 0 {
		return nil, fmt.Errorf("no responses received from nodes")
	}
	maxKey, maxCnt := utils.MaxByValue(responseMap)
	if maxCnt >= p.f+1 {
		return valueMap[maxKey], nil
	}
	return nil, fmt.Errorf("no majority reached (got %d matching responses, need %d)", maxCnt, p.f+1)
}

// Insert inserts a record through PBFT consensus
func (p *LinearPBFTDB) Insert(ctx context.Context, table string, key string, values map[string][]byte) error {
	// Encode values using RowCodec
	buf := p.bufPool.Get()
	defer func() {
		p.bufPool.Put(buf)
	}()

	encoded, err := p.r.Encode(buf, values)
	if err != nil {
		return fmt.Errorf("failed to encode values: %v", err)
	}

	// Create transaction
	tx := &pb.Transaction{
		Type:   "ycsb_write",
		Sender: ctx.Value(clientIDKey).(string),
		Table:  table,
		Key:    key,
		Values: map[string][]byte{"data": encoded}, // Store encoded data
	}

	request := &pb.TransactionRequest{
		Transaction: tx,
		Timestamp:   time.Now().UnixNano(),
		Sender:      ctx.Value(clientIDKey).(string),
	}

	signedRequest := &pb.SignedTransactionRequest{
		Request:   request,
		Signature: crypto.Sign(request, ctx.Value(privateKeyKey).(*bls.SecretKey)),
	}

	// Send request to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, len(p.nodeMap))
	wg := sync.WaitGroup{}
	for _, node := range p.nodeMap {
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			response, err := (*n.Client).BenchmarkRPC(ctx, signedRequest)
			if err == nil && response != nil {
				responseCh <- response
			}
		}(node)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Check for f+1 matching values
	responseMap := make(map[any]int64)
	for response := range responseCh {
		if response != nil && response.Message != nil {
			if response.Message.Error != "" {
				// return fmt.Errorf("PBFT error: %s", response.Message.Error)
				continue
			}
			responseMap[response.Message.Result]++
		}
	}
	if len(responseMap) == 0 {
		return fmt.Errorf("no responses received from nodes")
	}
	_, maxCnt := utils.MaxByValue(responseMap)
	if maxCnt >= p.f+1 {
		return nil
	}
	return fmt.Errorf("no majority reached (got %d responses, need %d)", maxCnt, p.f+1)
}

// Update updates a record through PBFT consensus
func (p *LinearPBFTDB) Update(ctx context.Context, table string, key string, values map[string][]byte) error {
	// Encode values
	buf := p.bufPool.Get()
	defer func() {
		p.bufPool.Put(buf)
	}()

	encoded, err := p.r.Encode(buf, values)
	if err != nil {
		return fmt.Errorf("failed to encode values: %v", err)
	}

	tx := &pb.Transaction{
		Type:   "ycsb_update",
		Sender: ctx.Value(clientIDKey).(string),
		Table:  table,
		Key:    key,
		Values: map[string][]byte{"data": encoded},
	}

	request := &pb.TransactionRequest{
		Transaction: tx,
		Timestamp:   time.Now().UnixNano(),
		Sender:      ctx.Value(clientIDKey).(string),
	}

	signedRequest := &pb.SignedTransactionRequest{
		Request:   request,
		Signature: crypto.Sign(request, ctx.Value(privateKeyKey).(*bls.SecretKey)),
	}

	// Send request to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, len(p.nodeMap))
	wg := sync.WaitGroup{}
	for _, node := range p.nodeMap {
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			response, err := (*n.Client).BenchmarkRPC(ctx, signedRequest)
			if err == nil && response != nil {
				responseCh <- response
			}
		}(node)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Check for f+1 matching values
	responseMap := make(map[any]int64)
	for response := range responseCh {
		if response != nil && response.Message != nil {
			if response.Message.Error != "" {
				// return fmt.Errorf("PBFT error: %s", response.Message.Error)
				continue
			}
			responseMap[response.Message.Result]++
		}
	}
	if len(responseMap) == 0 {
		return fmt.Errorf("no responses received from nodes")
	}
	_, maxCnt := utils.MaxByValue(responseMap)
	if maxCnt >= p.f+1 {
		return nil
	}
	return fmt.Errorf("no majority reached (got %d responses, need %d)", maxCnt, p.f+1)
}

// Delete deletes a record through PBFT consensus
func (p *LinearPBFTDB) Delete(ctx context.Context, table string, key string) error {
	tx := &pb.Transaction{
		Type:   "ycsb_delete",
		Sender: ctx.Value(clientIDKey).(string),
		Table:  table,
		Key:    key,
	}

	request := &pb.TransactionRequest{
		Transaction: tx,
		Timestamp:   time.Now().UnixNano(),
		Sender:      ctx.Value(clientIDKey).(string),
	}

	signedRequest := &pb.SignedTransactionRequest{
		Request:   request,
		Signature: crypto.Sign(request, ctx.Value(privateKeyKey).(*bls.SecretKey)),
	}

	// Send request to all nodes
	responseCh := make(chan *pb.SignedTransactionResponse, len(p.nodeMap))
	wg := sync.WaitGroup{}
	for _, node := range p.nodeMap {
		wg.Add(1)
		go func(n *models.Node) {
			defer wg.Done()
			response, err := (*n.Client).BenchmarkRPC(ctx, signedRequest)
			if err == nil && response != nil {
				responseCh <- response
			}
		}(node)
	}
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	// Check for f+1 matching values
	responseMap := make(map[any]int64)
	for response := range responseCh {
		if response != nil && response.Message != nil {
			if response.Message.Error != "" {
				// return fmt.Errorf("PBFT error: %s", response.Message.Error)
				continue
			}
			responseMap[response.Message.Result]++
		}
	}
	if len(responseMap) == 0 {
		return fmt.Errorf("no responses received from nodes")
	}
	_, maxCnt := utils.MaxByValue(responseMap)
	if maxCnt >= p.f+1 {
		return nil
	}
	return fmt.Errorf("no majority reached (got %d responses, need %d)", maxCnt, p.f+1)
}
