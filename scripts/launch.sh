#!/bin/bash

CONFIG_FILE="./configs/config.yaml"

rm -rf "./logs" "./data"
mkdir -p "./logs/out" "./logs/err" "./data"
for NODE_ID in $(yq e '.nodes[].id' $CONFIG_FILE); do
    go run cmd/server/main.go --id "$NODE_ID" --config "$CONFIG_FILE" > "./logs/out/$NODE_ID.out" 2>"./logs/err/$NODE_ID.err" &
done
