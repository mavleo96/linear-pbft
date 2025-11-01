package linearpbft

import (
	"context"
	"fmt"
	"strings"

	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (n *LinearPBFTNode) ReconfigureNode(ctx context.Context, changeStatusMessage *pb.ChangeStatusMessage) (*emptypb.Empty, error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

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
