package linearpbft

import (
	"sync"

	"github.com/mavleo96/pbft/pb"
)

// Logger is a logger for the linear PBFT node
type Logger struct {
	mutex                         sync.RWMutex
	sentPrePrepareMessages        []*pb.SignedPrePrepareMessage
	receivedPrePrepareMessages    []*pb.SignedPrePrepareMessage
	sentPrepareMessages           []*pb.SignedPrepareMessage
	receivedPrepareMessages       []*pb.SignedPrepareMessage
	collectedPrepareMessages      []*pb.SignedPrepareMessage
	sentAggregatedPrepareMessages []*pb.SignedPrepareMessage
	sentCommitMessages            []*pb.SignedCommitMessage
	receivedCommitMessages        []*pb.SignedCommitMessage
	collectedCommitMessages       []*pb.SignedCommitMessage
	sentAggregatedCommitMessages  []*pb.SignedCommitMessage
	sentViewChangeMessages        []*pb.SignedViewChangeMessage
	receivedViewChangeMessages    []*pb.SignedViewChangeMessage
	sentNewViewMessages           []*pb.SignedNewViewMessage
	receivedNewViewMessages       []*pb.SignedNewViewMessage
	sentCheckpointMessages        []*pb.SignedCheckpointMessage
	receivedCheckpointMessages    []*pb.SignedCheckpointMessage
	receivedTransactionRequests   []*pb.SignedTransactionRequest
	forwardedTransactionRequests  []*pb.SignedTransactionRequest
	sentTransactionResponses      []*pb.SignedTransactionResponse
	sentReadOnlyResponses         []*pb.SignedTransactionResponse
}

// AddSentPrePrepareMessage adds a sent pre prepare message to the logger
func (l *Logger) AddSentPrePrepareMessage(signedPrePrepareMessage *pb.SignedPrePrepareMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentPrePrepareMessages = append(l.sentPrePrepareMessages, signedPrePrepareMessage)
}

// GetSentPrePrepareMessages returns the sent pre prepare messages
func (l *Logger) GetSentPrePrepareMessages() []*pb.SignedPrePrepareMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentPrePrepareMessages
}

// AddReceivedPrePrepareMessage adds a received pre prepare message to the logger
func (l *Logger) AddReceivedPrePrepareMessage(signedPrePrepareMessage *pb.SignedPrePrepareMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedPrePrepareMessages = append(l.receivedPrePrepareMessages, signedPrePrepareMessage)
}

// GetReceivedPrePrepareMessages returns the received pre prepare messages
func (l *Logger) GetReceivedPrePrepareMessages() []*pb.SignedPrePrepareMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedPrePrepareMessages
}

// AddSentPrepareMessage adds a sent prepare message to the logger
func (l *Logger) AddSentPrepareMessage(signedPrepareMessage *pb.SignedPrepareMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentPrepareMessages = append(l.sentPrepareMessages, signedPrepareMessage)
}

// GetSentPrepareMessages returns the sent prepare messages
func (l *Logger) GetSentPrepareMessages() []*pb.SignedPrepareMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentPrepareMessages
}

// AddReceivedPrepareMessage adds a received prepare message to the logger
func (l *Logger) AddReceivedPrepareMessage(signedPrepareMessage *pb.SignedPrepareMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedPrepareMessages = append(l.receivedPrepareMessages, signedPrepareMessage)
}

// GetReceivedPrepareMessages returns the received prepare messages
func (l *Logger) GetReceivedPrepareMessages() []*pb.SignedPrepareMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedPrepareMessages
}

// AddCollectedPrepareMessage adds a collected prepare message to the logger
func (l *Logger) AddCollectedPrepareMessage(signedPrepareMessage *pb.SignedPrepareMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.collectedPrepareMessages = append(l.collectedPrepareMessages, signedPrepareMessage)
}

// GetCollectedPrepareMessages returns the collected prepare messages
func (l *Logger) GetCollectedPrepareMessages() []*pb.SignedPrepareMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.collectedPrepareMessages
}

// AddSentAggregatedPrepareMessage adds a sent aggregated prepare message to the logger
func (l *Logger) AddSentAggregatedPrepareMessage(signedPrepareMessage *pb.SignedPrepareMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentAggregatedPrepareMessages = append(l.sentAggregatedPrepareMessages, signedPrepareMessage)
}

// GetSentAggregatedPrepareMessages returns the sent aggregated prepare messages
func (l *Logger) GetSentAggregatedPrepareMessages() []*pb.SignedPrepareMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentAggregatedPrepareMessages
}

// AddSentCommitMessage adds a sent commit message to the logger
func (l *Logger) AddSentCommitMessage(signedCommitMessage *pb.SignedCommitMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentCommitMessages = append(l.sentCommitMessages, signedCommitMessage)
}

// GetSentCommitMessages returns the sent commit messages
func (l *Logger) GetSentCommitMessages() []*pb.SignedCommitMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentCommitMessages
}

// AddCollectedCommitMessage adds a collected commit message to the logger
func (l *Logger) AddCollectedCommitMessage(signedCommitMessage *pb.SignedCommitMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.collectedCommitMessages = append(l.collectedCommitMessages, signedCommitMessage)
}

// GetCollectedCommitMessages returns the collected commit messages
func (l *Logger) GetCollectedCommitMessages() []*pb.SignedCommitMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.collectedCommitMessages
}

// AddSentAggregatedCommitMessage adds a sent aggregated commit message to the logger
func (l *Logger) AddSentAggregatedCommitMessage(signedCommitMessage *pb.SignedCommitMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentAggregatedCommitMessages = append(l.sentAggregatedCommitMessages, signedCommitMessage)
}

// GetSentAggregatedCommitMessages returns the sent aggregated commit messages
func (l *Logger) GetSentAggregatedCommitMessages() []*pb.SignedCommitMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentAggregatedCommitMessages
}

// AddReceivedCommitMessage adds a received commit message to the logger
func (l *Logger) AddReceivedCommitMessage(signedCommitMessage *pb.SignedCommitMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedCommitMessages = append(l.receivedCommitMessages, signedCommitMessage)
}

// GetReceivedCommitMessages returns the received commit messages
func (l *Logger) GetReceivedCommitMessages() []*pb.SignedCommitMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedCommitMessages
}

// AddSentViewChangeMessage adds a sent view change message to the logger
func (l *Logger) AddSentViewChangeMessage(signedViewChangeMessage *pb.SignedViewChangeMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentViewChangeMessages = append(l.sentViewChangeMessages, signedViewChangeMessage)
}

// GetSentViewChangeMessages returns the sent view change messages
func (l *Logger) GetSentViewChangeMessages() []*pb.SignedViewChangeMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentViewChangeMessages
}

// AddReceivedViewChangeMessage adds a received view change message to the logger
func (l *Logger) AddReceivedViewChangeMessage(signedViewChangeMessage *pb.SignedViewChangeMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedViewChangeMessages = append(l.receivedViewChangeMessages, signedViewChangeMessage)
}

// GetReceivedViewChangeMessages returns the received view change messages
func (l *Logger) GetReceivedViewChangeMessages() []*pb.SignedViewChangeMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedViewChangeMessages
}

// AddSentNewViewMessage adds a sent new view message to the logger
func (l *Logger) AddSentNewViewMessage(signedNewViewMessage *pb.SignedNewViewMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentNewViewMessages = append(l.sentNewViewMessages, signedNewViewMessage)
}

// GetSentNewViewMessages returns the sent new view messages
func (l *Logger) GetSentNewViewMessages() []*pb.SignedNewViewMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentNewViewMessages
}

// AddReceivedNewViewMessage adds a received new view message to the logger
func (l *Logger) AddReceivedNewViewMessage(signedNewViewMessage *pb.SignedNewViewMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedNewViewMessages = append(l.receivedNewViewMessages, signedNewViewMessage)
}

// GetReceivedNewViewMessages returns the received new view messages
func (l *Logger) GetReceivedNewViewMessages() []*pb.SignedNewViewMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedNewViewMessages
}

// AddSentCheckpointMessage adds a sent checkpoint message to the logger
func (l *Logger) AddSentCheckpointMessage(signedCheckpointMessage *pb.SignedCheckpointMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentCheckpointMessages = append(l.sentCheckpointMessages, signedCheckpointMessage)
}

// GetSentCheckpointMessages returns the sent checkpoint messages
func (l *Logger) GetSentCheckpointMessages() []*pb.SignedCheckpointMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentCheckpointMessages
}

// AddReceivedCheckpointMessage adds a received checkpoint message to the logger
func (l *Logger) AddReceivedCheckpointMessage(signedCheckpointMessage *pb.SignedCheckpointMessage) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedCheckpointMessages = append(l.receivedCheckpointMessages, signedCheckpointMessage)
}

// GetReceivedCheckpointMessages returns the received checkpoint messages
func (l *Logger) GetReceivedCheckpointMessages() []*pb.SignedCheckpointMessage {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedCheckpointMessages
}

// AddReceivedTransactionRequest adds a received transaction request to the logger
func (l *Logger) AddReceivedTransactionRequest(signedTransactionRequest *pb.SignedTransactionRequest) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.receivedTransactionRequests = append(l.receivedTransactionRequests, signedTransactionRequest)
}

// GetReceivedTransactionRequests returns the received transaction requests
func (l *Logger) GetReceivedTransactionRequests() []*pb.SignedTransactionRequest {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.receivedTransactionRequests
}

// AddForwardedTransactionRequest adds a forwarded transaction request to the logger
func (l *Logger) AddForwardedTransactionRequest(signedTransactionRequest *pb.SignedTransactionRequest) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.forwardedTransactionRequests = append(l.forwardedTransactionRequests, signedTransactionRequest)
}

// GetForwardedTransactionRequests returns the forwarded transaction requests
func (l *Logger) GetForwardedTransactionRequests() []*pb.SignedTransactionRequest {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.forwardedTransactionRequests
}

// AddSentTransactionResponse adds a sent transaction response to the logger
func (l *Logger) AddSentTransactionResponse(signedTransactionResponse *pb.SignedTransactionResponse) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentTransactionResponses = append(l.sentTransactionResponses, signedTransactionResponse)
}

// GetSentTransactionResponses returns the sent transaction responses
func (l *Logger) GetSentTransactionResponses() []*pb.SignedTransactionResponse {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentTransactionResponses
}

// AddSentReadOnlyResponse adds a sent read only response to the logger
func (l *Logger) AddSentReadOnlyResponse(signedReadOnlyResponse *pb.SignedTransactionResponse) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentReadOnlyResponses = append(l.sentReadOnlyResponses, signedReadOnlyResponse)
}

// GetSentReadOnlyResponses returns the sent read only responses
func (l *Logger) GetSentReadOnlyResponses() []*pb.SignedTransactionResponse {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.sentReadOnlyResponses
}

// Reset resets the logger
func (l *Logger) Reset() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sentPrePrepareMessages = make([]*pb.SignedPrePrepareMessage, 0)
	l.receivedPrePrepareMessages = make([]*pb.SignedPrePrepareMessage, 0)
	l.sentPrepareMessages = make([]*pb.SignedPrepareMessage, 0)
	l.receivedPrepareMessages = make([]*pb.SignedPrepareMessage, 0)
	l.collectedPrepareMessages = make([]*pb.SignedPrepareMessage, 0)
	l.sentAggregatedPrepareMessages = make([]*pb.SignedPrepareMessage, 0)
	l.sentCommitMessages = make([]*pb.SignedCommitMessage, 0)
	l.receivedCommitMessages = make([]*pb.SignedCommitMessage, 0)
	l.collectedCommitMessages = make([]*pb.SignedCommitMessage, 0)
	l.sentAggregatedCommitMessages = make([]*pb.SignedCommitMessage, 0)
	l.sentViewChangeMessages = make([]*pb.SignedViewChangeMessage, 0)
	l.receivedViewChangeMessages = make([]*pb.SignedViewChangeMessage, 0)
	l.sentNewViewMessages = make([]*pb.SignedNewViewMessage, 0)
	l.receivedNewViewMessages = make([]*pb.SignedNewViewMessage, 0)
	l.sentCheckpointMessages = make([]*pb.SignedCheckpointMessage, 0)
	l.receivedCheckpointMessages = make([]*pb.SignedCheckpointMessage, 0)
	l.receivedTransactionRequests = make([]*pb.SignedTransactionRequest, 0)
	l.forwardedTransactionRequests = make([]*pb.SignedTransactionRequest, 0)
	l.sentTransactionResponses = make([]*pb.SignedTransactionResponse, 0)
	l.sentReadOnlyResponses = make([]*pb.SignedTransactionResponse, 0)
}

// CreateLogger creates a new logger
func CreateLogger() *Logger {
	return &Logger{
		mutex:                         sync.RWMutex{},
		sentPrePrepareMessages:        make([]*pb.SignedPrePrepareMessage, 0),
		receivedPrePrepareMessages:    make([]*pb.SignedPrePrepareMessage, 0),
		sentPrepareMessages:           make([]*pb.SignedPrepareMessage, 0),
		receivedPrepareMessages:       make([]*pb.SignedPrepareMessage, 0),
		collectedPrepareMessages:      make([]*pb.SignedPrepareMessage, 0),
		sentAggregatedPrepareMessages: make([]*pb.SignedPrepareMessage, 0),
		sentCommitMessages:            make([]*pb.SignedCommitMessage, 0),
		receivedCommitMessages:        make([]*pb.SignedCommitMessage, 0),
		collectedCommitMessages:       make([]*pb.SignedCommitMessage, 0),
		sentAggregatedCommitMessages:  make([]*pb.SignedCommitMessage, 0),
		sentViewChangeMessages:        make([]*pb.SignedViewChangeMessage, 0),
		receivedViewChangeMessages:    make([]*pb.SignedViewChangeMessage, 0),
		sentNewViewMessages:           make([]*pb.SignedNewViewMessage, 0),
		receivedNewViewMessages:       make([]*pb.SignedNewViewMessage, 0),
		sentCheckpointMessages:        make([]*pb.SignedCheckpointMessage, 0),
		receivedCheckpointMessages:    make([]*pb.SignedCheckpointMessage, 0),
		receivedTransactionRequests:   make([]*pb.SignedTransactionRequest, 0),
		forwardedTransactionRequests:  make([]*pb.SignedTransactionRequest, 0),
		sentTransactionResponses:      make([]*pb.SignedTransactionResponse, 0),
		sentReadOnlyResponses:         make([]*pb.SignedTransactionResponse, 0),
	}
}
