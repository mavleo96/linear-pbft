package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/mavleo96/bft-mavleo96/internal/client"
	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/security"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
	"github.com/mavleo96/bft-mavleo96/pb"
	log "github.com/sirupsen/logrus"
)

func main() {
	filePath := flag.String("file", "testdata/test1.csv", "The path to the test data file")
	flag.Parse()

	// Parse Config
	cfg, err := config.ParseConfig("./configs/config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	for nodeID, node := range cfg.Nodes {
		node.PublicKey, err = security.ReadPublicKey(filepath.Join("./keys", "node", nodeID+".pub.pem"))
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Info("Config parsed")
	// log.Info(cfg.String())

	// Create gRPC clients for each node
	nodeClientMap := make(map[string]pb.LinearPBFTClient)
	for nodeID, node := range cfg.Nodes {
		conn, err := utils.Connect(node)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		nodeClient := pb.NewLinearPBFTClient(conn)
		nodeClientMap[nodeID] = nodeClient
	}
	log.Info("gRPC clients created")

	// Read CSV file
	records, err := client.ReadCSV(*filePath)
	if err != nil {
		log.Fatal(err)
	}

	// Parse test sets
	// The entire csv file is loaded into memory and transactions are queued by
	// each set number for each client.
	testSets, err := client.ParseRecords(records, cfg.Clients, cfg.Nodes)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Test sets parsed")
	// for _, testSet := range testSets {
	// 	log.Info(testSet)
	// }

	// Client routines
	// Each client has its own goroutine and channel. The channel is used by main routine and client routine to communicate.
	// - main routine sends test set to client routine
	// - client routine send nil to main routine when test set is done
	wg := sync.WaitGroup{}
	clientChannels := make(map[string]chan *client.TestSet)
	for _, clientID := range cfg.Clients {
		clientChannels[clientID] = make(chan *client.TestSet)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, clientID := range cfg.Clients {
		wg.Add(1)
		go func(ctx context.Context, id string) {
			defer wg.Done()
			client.ClientRoutine(ctx, id, clientChannels[id], nodeClientMap)
		}(ctx, clientID)
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
			client.ReconfigureNodes(testSet.Live, testSet.Byzantine, testSet.Attack)

			// Send test set to clients
			for _, clientID := range cfg.Clients {
				clientChannels[clientID] <- testSet
			}
			for _, clientID := range cfg.Clients {
				<-clientChannels[clientID]
			}
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
	wg.Wait()
	log.Info("Client main routine exiting...")
}
