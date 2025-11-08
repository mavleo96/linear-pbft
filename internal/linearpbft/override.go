package linearpbft

import (
	"context"
	"fmt"
	"strings"

	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ReconfigureNode reconfigures a node's status and attacks
func (n *LinearPBFTNode) ReconfigureNode(ctx context.Context, changeStatusMessage *pb.ChangeStatusMessage) (*emptypb.Empty, error) {
	n.Alive = changeStatusMessage.Alive
	n.Byzantine = changeStatusMessage.Byzantine
	logString := fmt.Sprintf("Reconfigured node %s to alive: %t, byzantine: %t", n.ID, n.Alive, n.Byzantine)

	if n.Byzantine {
		n.SignAttack = changeStatusMessage.SignAttack
		if n.SignAttack {
			logString += fmt.Sprintf(", sign attack: %t", n.SignAttack)
		}
		n.CrashAttack = changeStatusMessage.CrashAttack
		if n.CrashAttack {
			logString += fmt.Sprintf(", crash attack: %t", n.CrashAttack)
		}
		n.DarkAttack = changeStatusMessage.DarkAttack
		n.DarkAttackNodes = changeStatusMessage.DarkAttackNodes
		if n.DarkAttack {
			logString += fmt.Sprintf(", dark attack: %s [%s]", n.DarkAttackNodes, strings.Join(n.DarkAttackNodes, ", "))
		}
		n.TimeAttack = changeStatusMessage.TimeAttack
		if n.TimeAttack {
			logString += fmt.Sprintf(", time attack: %t", n.TimeAttack)
		}
		n.EquivocationAttack = changeStatusMessage.EquivocationAttack
		n.EquivocationAttackNodes = changeStatusMessage.EquivocationAttackNodes
		if n.EquivocationAttack {
			logString += fmt.Sprintf(", equivocation attack: %s [%s]", n.EquivocationAttackNodes, strings.Join(n.EquivocationAttackNodes, ", "))
		}
	}
	log.Info(logString)
	return &emptypb.Empty{}, nil
}

// ResetNode resets the server state and database
func (n *LinearPBFTNode) ResetNode(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	// Reset server state
	n.State.StateLog.log = make(map[int64]*LogRecord)
	n.State.SetLastExecutedSequenceNum(0)
	n.State.LastReply.ReplyMap = make(map[string]*pb.TransactionResponse)
	n.State.SetViewNumber(0)
	n.State.SetViewChangePhase(false)
	n.State.SetViewChangeViewNumber(0)
	n.State.TransactionMap = CreateTransactionMap()
	n.ForwardedRequestsLog = make([]*pb.SignedTransactionRequest, 0)
	n.CheckPointManager.log = make(map[int64]map[string]*pb.SignedCheckPointMessage)
	n.CheckPointManager.checkpoints = make(map[int64]*pb.CheckPoint)
	n.config.LowWaterMark = 0
	n.config.HighWaterMark = 100

	// Reset DB
	n.Executor.db.ResetDB(10)

	return &emptypb.Empty{}, nil

}
