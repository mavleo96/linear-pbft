package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/mavleo96/bft-mavleo96/internal/config"
	"github.com/mavleo96/bft-mavleo96/internal/crypto"
	"github.com/mavleo96/bft-mavleo96/internal/utils"
)

// generateShares generates secret and public shares for a given master secret and node IDs
func generateShares(masterSec bls.SecretKey, ids []string, t int) (map[string]*bls.SecretKey, map[string]*bls.PublicKey) {
	// create (t-1)-coefficient polynomial
	msk := masterSec.GetMasterSecretKey(t - 1)

	// generate and save secret/public shares for all nodes
	secretShares := make(map[string]*bls.SecretKey)
	publicShares := make(map[string]*bls.PublicKey)
	for _, id := range ids {
		blsID := crypto.NodeIDToBLSMaskID(id)

		var secShare bls.SecretKey
		secShare.Set(msk, &blsID)
		secretShares[id] = &secShare

		pubShare := secShare.GetPublicKey()
		publicShares[id] = pubShare
	}
	return secretShares, publicShares
}

// generateMasterKeys generates a master secret and public key
func generateMasterKeys() (bls.SecretKey, bls.PublicKey) {
	var masterSec bls.SecretKey
	masterSec.SetByCSPRNG()
	masterPub := masterSec.GetPublicKey()
	return masterSec, *masterPub
}

// saveToFile saves data to a file
func saveToFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func main() {
	configPath := flag.String("config", "./configs/config.yaml", "Path to config file")
	keysDir := flag.String("dir", "./nkeys", "Path to keys directory")
	flag.Parse()

	// Parse config
	cfg, err := config.ParseConfig(*configPath)
	if err != nil {
		fmt.Println("Error parsing config:", err)
		os.Exit(1)
	}

	// Get node IDs
	nodeIDs := utils.Keys(cfg.Nodes)
	n := len(nodeIDs)
	t := 2*(n-1)/3 + 1

	// Initialize BLS
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)

	// Generate and save node master secret and public key
	masterSec1, masterPub1 := generateMasterKeys()
	saveToFile(filepath.Join(*keysDir, "node", "master_public1.key"), masterPub1.Serialize())
	masterSec2, masterPub2 := generateMasterKeys()
	saveToFile(filepath.Join(*keysDir, "node", "master_public2.key"), masterPub2.Serialize())
	fmt.Println("Generated Node TSS Master Secret and Public Key")

	// Generate and save node shares t of n
	secretShares1, publicShares1 := generateShares(masterSec1, nodeIDs, t)

	for i := range n {
		id := nodeIDs[i]
		secShare := secretShares1[id]
		pubShare := publicShares1[id]
		saveToFile(filepath.Join(*keysDir, "node", fmt.Sprintf("%s_secret1.key", id)), secShare.Serialize())
		saveToFile(filepath.Join(*keysDir, "node", fmt.Sprintf("%s_public1.key", id)), pubShare.Serialize())
	}
	fmt.Printf("Generated Node TSS Shares %d-of-%d\n", t, n)

	// Generate and save node shares n of n
	secretShares2, publicShares2 := generateShares(masterSec2, nodeIDs, n)

	for i := range n {
		id := nodeIDs[i]
		secShare := secretShares2[id]
		pubShare := publicShares2[id]
		saveToFile(filepath.Join(*keysDir, "node", fmt.Sprintf("%s_secret2.key", id)), secShare.Serialize())
		saveToFile(filepath.Join(*keysDir, "node", fmt.Sprintf("%s_public2.key", id)), pubShare.Serialize())
	}
	fmt.Printf("Generated Node TSS Shares %d-of-%d\n", n, n)

	// Generate and save client master secret and public key
	for clientID := range cfg.Clients {
		secretKey, publicKey := generateMasterKeys()
		saveToFile(filepath.Join(*keysDir, "client", fmt.Sprintf("%s_secret.key", clientID)), secretKey.Serialize())
		saveToFile(filepath.Join(*keysDir, "client", fmt.Sprintf("%s_public.key", clientID)), publicKey.Serialize())
	}
	fmt.Println("Generated Client Keys")
}
