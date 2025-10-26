package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mavleo96/bft-mavleo96/internal/clientapp"
	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/models"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
	filePath := flag.String("file", "testdata/test1.csv", "The path to the test data file")
	flag.Parse()

	// Parse Config
	cfg, err := config.ParseConfig("./configs/config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	// log.Info("Config parsed")

	// Create map of node structs
	// Note: this object is shared by clients
	nodeMap, err := models.GetNodeMap(cfg.Nodes)
	if err != nil {
		log.Fatal(err)
	}
	// log.Info("Node map created")

	// Create map of client structs
	clientMap, err := models.GetClientMap(cfg.Clients)
	if err != nil {
		log.Fatal(err)
	}
	// log.Info("Client map created")

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
	// log.Info("Test sets parsed")

	// Create context and channels for client routines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientSignalChs := make(map[string]chan *clientapp.TestSet)
	for _, c := range clientMap {
		clientSignalChs[c.ID], err = clientapp.CreateClientAppServer(ctx, c, nodeMap)
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
			arg, err = strconv.Atoi(n)
			if err != nil {
				log.Warn(err)
				continue interactionLoop
			}
			cmd = "print status"
			if arg <= 0 {
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
			clientapp.ReconfigureNodes(testSet.Live, testSet.Byzantine, testSet.Attack)

			// Send test set to clients
			log.Debugf("Sending set %d to clients at timestamp %d", testSet.SetNumber, time.Now().UnixMilli())
			for clientID := range cfg.Clients {
				clientSignalChs[clientID] <- testSet
			}
			for clientID := range cfg.Clients {
				<-clientSignalChs[clientID]
			}
			log.Debugf("Set %d done at timestamp %d", testSet.SetNumber, time.Now().UnixMilli())
			log.Infof("Set %d done", testSet.SetNumber)
			continue interactionLoop
		case "print log":
			log.Info("Print log command received")
			// TODO: Implement print log
		case "print db":
			log.Info("Print db command received")
			// TODO: Implement print db
		case "print status":
			// TODO: Implement print status
			log.Infof("Print status command received for %d", arg)
		case "print view":
			// TODO: Implement print view
			log.Info("Print view command received")
		case "exit":
			break interactionLoop
		default:
			continue interactionLoop
		}
	}

	cancel()
	log.Info("Client main routine exiting...")
}
