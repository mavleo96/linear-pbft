package main

import (
	"context"
	"log"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/magiconair/properties"
	"github.com/mavleo96/linear-pbft/benchmark/client/linearpbftdb"
	"github.com/pingcap/go-ycsb/pkg/client"
	"github.com/pingcap/go-ycsb/pkg/measurement"
	"github.com/pingcap/go-ycsb/pkg/prop"
	_ "github.com/pingcap/go-ycsb/pkg/workload"
	"github.com/pingcap/go-ycsb/pkg/ycsb"
)

func main() {
	// Initialize BLS library
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	// Register LinearPBFT database
	linearpbftdb.Register()

	// Create properties
	props := properties.NewProperties()
	props.Set(prop.RecordCount, "500")
	props.Set(prop.OperationCount, "20000")
	props.Set(prop.ThreadCount, "1")
	props.Set(prop.RequestDistribution, "uniform")
	props.Set(prop.Workload, "core")
	props.Set("readproportion", "0.25")
	props.Set("updateproportion", "0.25")
	props.Set("scanproportion", "0.25")
	props.Set("deleteproportion", "0.25")

	// Initialize measurement
	measurement.InitMeasure(props)

	// Create workload
	workloadName := props.GetString(prop.Workload, "core")
	workloadCreator := ycsb.GetWorkloadCreator(workloadName)
	if workloadCreator == nil {
		log.Fatalf("workload creator %s not found", workloadName)
	}
	workload, err := workloadCreator.Create(props)
	if err != nil {
		log.Fatalf("create workload failed: %v", err)
	}
	defer workload.Close()

	// Create database
	dbCreator := ycsb.GetDBCreator("linearpbftdb")
	if dbCreator == nil {
		log.Fatal("database creator 'linearpbftdb' not found")
	}

	db, err := dbCreator.Create(props)
	if err != nil {
		log.Fatalf("create database failed: %v", err)
	}
	defer db.Close()

	// Wrap database with client wrapper
	wrappedDB := client.DbWrapper{DB: db}

	ctx := context.Background()

	// Load phase
	log.Println("Starting load phase...")
	loadProps := properties.NewProperties()
	// Copy all properties from props
	for k, v := range props.Map() {
		loadProps.Set(k, v)
	}
	loadProps.Set(prop.DoTransactions, "false")
	loadProps.Set(prop.Command, "load")
	loadClient := client.NewClient(loadProps, workload, wrappedDB)
	loadClient.Run(ctx)
	log.Println("Load complete.")

	// Run phase
	log.Println("Running benchmark...")
	runProps := properties.NewProperties()
	// Copy all properties from props
	for k, v := range props.Map() {
		runProps.Set(k, v)
	}
	runProps.Set(prop.DoTransactions, "true")
	runProps.Set(prop.Command, "run")
	runClient := client.NewClient(runProps, workload, wrappedDB)
	runClient.Run(ctx)

	// Output measurements
	log.Println("Benchmark complete.")
	measurement.Output()
}
