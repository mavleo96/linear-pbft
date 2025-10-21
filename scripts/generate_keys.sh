#!/bin/bash
# Script to generate ed25519 keys for nodes and clients
# Created using ChatGPT 4.5
set -euo pipefail

CONFIG_FILE="./configs/config.yaml"

# Key directories
BASE_KEY_DIR="keys"
NODE_KEY_DIR="$BASE_KEY_DIR/node"
CLIENT_KEY_DIR="$BASE_KEY_DIR/client"

# Clean old keys
rm -rf "$BASE_KEY_DIR"
mkdir -p "$NODE_KEY_DIR" "$CLIENT_KEY_DIR"

# Function to generate ed25519 key
generate_ed25519_key() {
    local name=$1
    local dir=$2
    local priv_path="$dir/${name}.pem"
    local pub_path="$dir/${name}.pub.pem"

    # Only generate if not exists
    if [[ ! -f "$priv_path" ]]; then
        openssl genpkey -algorithm ed25519 -out "$priv_path"
        openssl pkey -in "$priv_path" -pubout -out "$pub_path"
    fi
}

# Generate node keys
for NODE_ID in $(yq e '.nodes[].id' "$CONFIG_FILE"); do
    generate_ed25519_key "${NODE_ID}" "$NODE_KEY_DIR"
    echo "Generated key for node ${NODE_ID}"
done

# Generate client keys
for CLIENT_ID in $(yq e '.clients[].id' "$CONFIG_FILE"); do
    generate_ed25519_key "${CLIENT_ID}" "$CLIENT_KEY_DIR"
    echo "Generated key for client ${CLIENT_ID}"
done
