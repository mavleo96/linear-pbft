#!/bin/bash
# Script to generate SSH keys for nodes and clients
# Created using ChatGPT 4.5
set -euo pipefail

CONFIG_FILE="./configs/config.yaml"

# Key directories
BASE_KEY_DIR="keys"
NODE_KEY_DIR="$BASE_KEY_DIR/nodes"
CLIENT_KEY_DIR="$BASE_KEY_DIR/clients"

# Clean old keys
rm -rf "$BASE_KEY_DIR"
mkdir -p "$NODE_KEY_DIR" "$CLIENT_KEY_DIR"

# Function to generate SSH key
generate_ssh_key() {
    local name=$1
    local dir=$2
    local key_path="$dir/$name"

    # Only generate if not exists
    if [[ ! -f "$key_path" ]]; then
        ssh-keygen -t ed25519 -b 2048 -f "$key_path" -N "" >/dev/null
    fi
}

# Generate node keys
for NODE_ID in $(yq e '.nodes[].id' "$CONFIG_FILE"); do
    generate_ssh_key "id_ed25519_${NODE_ID}" "$NODE_KEY_DIR"
    echo "Generated key for node ${NODE_ID}"
done

# Generate client keys
for CLIENT_ID in $(yq e '.clients[]' "$CONFIG_FILE"); do
    generate_ssh_key "id_ed25519_${CLIENT_ID}" "$CLIENT_KEY_DIR"
    echo "Generated key for client ${CLIENT_ID}"
done
