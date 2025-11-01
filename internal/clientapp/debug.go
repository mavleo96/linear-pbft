package clientapp

import (
	"context"

	"github.com/mavleo96/bft-mavleo96/internal/models"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func SendPrintLogCommand(nodeMap map[string]*models.Node) error {
	log.Info("Print log command received")
	for _, node := range nodeMap {
		_, err := (*node.Client).PrintLog(context.Background(), &emptypb.Empty{})
		if err != nil {
			return err
		}
	}
	return nil
}

func SendPrintDBCommand(nodeMap map[string]*models.Node) error {
	log.Info("Print db command received")
	for _, node := range nodeMap {
		_, err := (*node.Client).PrintDB(context.Background(), &emptypb.Empty{})
		if err != nil {
			return err
		}
	}
	return nil
}

func SendPrintStatusCommand(nodeMap map[string]*models.Node, sequenceNum int64) error {
	log.Infof("Print status command received for %d", sequenceNum)
	for _, node := range nodeMap {
		_, err := (*node.Client).PrintStatus(context.Background(), &wrapperspb.Int64Value{Value: sequenceNum})
		if err != nil {
			return err
		}
	}
	return nil
}

func SendPrintViewCommand(nodeMap map[string]*models.Node) error {
	log.Info("Print view command received")
	return nil
}
