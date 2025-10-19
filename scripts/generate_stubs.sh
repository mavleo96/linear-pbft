#!/bin/bash

rm -rf pb
mkdir -p pb

protoc -I=proto --go_out=paths=source_relative:pb --go-grpc_out=paths=source_relative:pb proto/bft.proto
echo "Generated stubs"

go mod tidy
echo "Tidied dependencies"