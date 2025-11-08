#!/bin/bash
# Script to generate BLS TSS keys for nodes and clients
set -euo pipefail

CONFIG_FILE="./configs/config.yaml"
BASE_KEY_DIR="./keys"

rm -rf "$BASE_KEY_DIR"
go run cmd/generate_keys/main.go --config "$CONFIG_FILE" --dir "$BASE_KEY_DIR"