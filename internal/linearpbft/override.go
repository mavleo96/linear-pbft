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
	n.byzantineConfig.Alive = changeStatusMessage.Alive
	n.byzantineConfig.Byzantine = changeStatusMessage.Byzantine
	logString := fmt.Sprintf("Reconfigured node %s to alive: %t, byzantine: %t", n.ID, n.byzantineConfig.Alive, n.byzantineConfig.Byzantine)

	if n.byzantineConfig.Byzantine {
		n.byzantineConfig.SignAttack = changeStatusMessage.SignAttack
		if n.byzantineConfig.SignAttack {
			logString += fmt.Sprintf(", sign attack: %t", n.byzantineConfig.SignAttack)
		}
		n.byzantineConfig.CrashAttack = changeStatusMessage.CrashAttack
		if n.byzantineConfig.CrashAttack {
			logString += fmt.Sprintf(", crash attack: %t", n.byzantineConfig.CrashAttack)
		}
		n.byzantineConfig.DarkAttack = changeStatusMessage.DarkAttack
		n.byzantineConfig.DarkAttackNodes = changeStatusMessage.DarkAttackNodes
		if n.byzantineConfig.DarkAttack {
			logString += fmt.Sprintf(", dark attack: %s [%s]", n.byzantineConfig.DarkAttackNodes, strings.Join(n.byzantineConfig.DarkAttackNodes, ", "))
		}
		n.byzantineConfig.TimeAttack = changeStatusMessage.TimeAttack
		if n.byzantineConfig.TimeAttack {
			logString += fmt.Sprintf(", time attack: %t", n.byzantineConfig.TimeAttack)
		}
		n.byzantineConfig.EquivocationAttack = changeStatusMessage.EquivocationAttack
		n.byzantineConfig.EquivocationAttackNodes = changeStatusMessage.EquivocationAttackNodes
		if n.byzantineConfig.EquivocationAttack {
			logString += fmt.Sprintf(", equivocation attack: %s [%s]", n.byzantineConfig.EquivocationAttackNodes, strings.Join(n.byzantineConfig.EquivocationAttackNodes, ", "))
		}
	}
	log.Info(logString)
	return &emptypb.Empty{}, nil
}

// ResetNode resets the server state and database
func (n *LinearPBFTNode) ResetNode(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	// Reset configuration
	n.config.Reset(L)
	n.byzantineConfig.Reset()

	// Reset server state
	n.state.Reset()
	n.viewchanger.Reset()
	n.executor.checkpointer.Reset()
	n.executor.db.ResetDB(10)
	n.logger.Reset()

	return &emptypb.Empty{}, nil
}
