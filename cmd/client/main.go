package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"strconv"
	"strings"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/linear-pbft/internal/clientapp"
	"github.com/mavleo96/linear-pbft/internal/config"
	"github.com/mavleo96/linear-pbft/internal/models"
	"github.com/mavleo96/linear-pbft/internal/utils"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.InfoLevel)

	// Initialize BLS library
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	filePath := flag.String("file", "testdata/test1.csv", "The path to the test data file")
	flag.Parse()

	// Parse Config
	cfg, err := config.ParseConfig("./configs/config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	// Create map of node structs
	// Note: this object is shared by clients
	nodeMap, err := models.GetNodeMap(cfg.Nodes)
	if err != nil {
		log.Fatal(err)
	}

	// Create map of client structs
	clientMap, err := models.GetClientMap(cfg.Clients)
	if err != nil {
		log.Fatal(err)
	}

	// Read CSV file and parse transactions
	// The entire csv file is loaded into memory and transactions are queued by
	// each set number for each client.
	records, err := clientapp.ReadCSV(*filePath)
	if err != nil {
		log.Fatal(err)
	}
	testSets, err := clientapp.ParseRecords(records, utils.Keys(cfg.Clients), nodeMap)
	if err != nil {
		log.Fatal(err)
	}

	// Create context and channels for client routines
	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()
	clientSignalChs := make(map[string]chan<- *clientapp.TestSet)
	clientResetChs := make(map[string]chan bool)
	for _, c := range clientMap {
		clientSignalChs[c.ID], clientResetChs[c.ID], err = clientapp.CreateClientAppServer(mainCtx, c, nodeMap)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Info("Client routines created")

	// Main interaction loop
	// This loop is used to interact with the user and execute commands
	// to control the execution of the test sets and log the results.
	log.Info("Main interaction loop started")
	scanner := bufio.NewScanner(os.Stdin)
	nextTestSet := -1
interactionLoop:
	for {
		// Read command from stdin
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				log.Panic(err)
			}
		}
		cmd := strings.TrimSpace(scanner.Text())

		// If command contains "print status", then parse the argument
		var arg int
		if strings.HasPrefix(cmd, "print status") {
			var err error
			n := strings.TrimPrefix(cmd, "print status")
			n = strings.TrimSpace(n)
			if n == "all" {
				arg = 0
			} else {
				arg, err = strconv.Atoi(n)
			}
			if err != nil {
				log.Warn(err)
				continue interactionLoop
			}
			cmd = "print status"
			if arg < 0 {
				log.Warn("Invalid argument for print status")
				continue interactionLoop
			}
		}

		// Execute command
		switch cmd {
		case "next":
			// Increment next test set
			nextTestSet++
			if nextTestSet >= len(testSets) {
				break interactionLoop
			}
			testSet := testSets[nextTestSet]

			// Reconfigure nodes
			clientapp.ReconfigureNodes(mainCtx, nodeMap, testSet.Live, testSet.Byzantine, testSet.Attack)

			// Send test set to clients
			log.Infof("Sending test set %d to clients", testSet.SetNumber)
			for clientID := range cfg.Clients {
				if testSet.Transactions[clientID] == nil {
					log.Warnf("Skipping client %s because no transactions", clientID)
					continue
				}
				clientSignalChs[clientID] <- testSet
			}
			continue interactionLoop
		case "skip":
			nextTestSet++
			if nextTestSet >= len(testSets) {
				break interactionLoop
			}
			log.Infof("Skipping test set %d", testSets[nextTestSet].SetNumber)
			continue interactionLoop
		case "print log":
			clientapp.SendPrintLogCommand(mainCtx, nodeMap, int64(nextTestSet+1))
		case "print db":
			clientapp.SendPrintDBCommand(mainCtx, nodeMap, int64(nextTestSet+1))
		case "print status":
			clientapp.SendPrintStatusCommand(mainCtx, nodeMap, int64(nextTestSet+1), int64(arg))
		case "print view":
			clientapp.SendPrintViewCommand(mainCtx, nodeMap, int64(nextTestSet+1))
		case "reset":
			log.Info("Resetting clients...")
			for clientID := range cfg.Clients {
				clientResetChs[clientID] <- true
			}
			for clientID := range cfg.Clients {
				<-clientResetChs[clientID]
			}
			log.Info("Clients reset complete")
			clientapp.SendResetCommand(mainCtx, nodeMap, cfg.InitBalance)
		case "reset clients":
			log.Info("Resetting clients...")
			for clientID := range cfg.Clients {
				clientResetChs[clientID] <- true
			}
			for clientID := range cfg.Clients {
				<-clientResetChs[clientID]
			}
			log.Info("Clients reset complete")
		case "reset nodes":
			clientapp.SendResetCommand(mainCtx, nodeMap, cfg.InitBalance)
		case "exit":
			break interactionLoop
		default:
			continue interactionLoop
		}
	}

	mainCancel()
	log.Info("Client main routine exiting...")

	// Cleanup: close all node and client connections
	log.Info("Closing node connections...")
	for _, node := range nodeMap {
		if err := node.Close(); err != nil {
			log.Warnf("Error closing node connection %s: %v", node.ID, err)
		}
	}

	log.Info("Closing client connections...")
	for _, client := range clientMap {
		if err := client.Close(); err != nil {
			log.Warnf("Error closing client connection %s: %v", client.ID, err)
		}
	}

	log.Info("Client shutdown complete")
}
