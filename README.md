# BFT-Mavleo96

<!-- Submission 1: 09/11/2025 17:44 EST -->

A Byzantine Fault Tolerant distributed system implementation using Linear PBFT (Practical Byzantine Fault Tolerance) consensus protocol.

## Overview

This project implements a distributed banking system with Byzantine fault tolerance using **Linear PBFT** (Practical Byzantine Fault Tolerance) consensus protocol. The system also supports **SBFT** (Simplified Byzantine Fault Tolerance) as an optimization.

### Linear PBFT
Linear PBFT is a variant of the PBFT protocol that provides Byzantine fault tolerance through a three-phase consensus protocol:
- **Pre-Prepare**: The primary (leader) node proposes a transaction
- **Prepare**: Backup nodes prepare the transaction and exchange prepare messages
- **Commit**: Nodes commit the transaction after receiving sufficient prepare messages

The system maintains a distributed ledger across all nodes and can tolerate up to `f` Byzantine failures with `3f+1` total nodes.

### SBFT (Simplified Byzantine Fault Tolerance)
SBFT is a protocol optimization that reduces the consensus protocol from three phases to two phases. When the leader receives prepare messages from all N nodes, it can skip the commit phase because consensus has already been reached. This optimization:
- Reduces message rounds from 3 to 2 (pre-prepare, prepare)
- Requires all N prepare messages to be received (instead of just 2f+1)
- Skips the commit phase when all nodes have prepared
- Maintains the same safety and liveness guarantees as Linear PBFT
- Includes a timeout mechanism (50ms) to fall back to standard PBFT if SBFT doesn't occur quickly

*Note: In this implementation, master public key 2 is used to verify aggregated threshold signatures, but SBFT itself is a protocol optimization independent of the cryptographic scheme used.*

The system consists of multiple nodes (replicas) that maintain a distributed ledger and can tolerate Byzantine (arbitrary) failures. Clients can submit transactions to transfer funds between accounts, and the system ensures consensus despite malicious nodes.

## Components

### 1. **Server Nodes** (`cmd/server/main.go`)
- Implements the Linear PBFT consensus protocol with SBFT optimization
- Maintains a distributed database (BoltDB) for account balances and key-value storage
- Handles transaction processing through the PBFT consensus phases:
  - **Pre-Prepare**: Leader proposes a transaction
  - **Prepare**: Nodes prepare the transaction
  - **Commit**: Nodes commit the transaction (skipped in SBFT mode)
- Supports SBFT optimization to skip commit phase when all N prepare messages are received
- Supports view changes for leader election
- Handles checkpointing for state management
- Uses BLS threshold signature scheme (TSS) for cryptographic operations
- Communicates via gRPC
- Provides BenchmarkRPC endpoint for performance testing with key-value operations
- Supports both banking transactions (transfer/read) and generic key-value operations (benchmarking)
- Read-only requests bypass consensus for improved performance
- Graceful shutdown with proper cleanup of resources

### 2. **Client Application** (`cmd/client/main.go`)
- Loads transactions from CSV test files
- Manages multiple client instances (A-J)
- Sends transaction requests to nodes
- Collects and verifies responses from nodes
- Provides an interactive command interface for test execution

### 3. **Key Generation** (`cmd/generate_keys/main.go`)
- Generates BLS (Boneh-Lynn-Shacham) threshold signature keys
- Creates keys for nodes and clients
- Sets up two sets of keys for nodes:
  - **Key Set 1**: For standard PBFT signatures (secret1, master_public1)
  - **Key Set 2**: For threshold signature verification (secret2, master_public2)
- Enables both Linear PBFT and SBFT protocol support

### 4. **Benchmark Application** (`cmd/benchmark/ycsb/main.go`)
- YCSB (Yahoo Cloud Serving Benchmark) integration for performance testing
- Supports standard YCSB workloads (core, workloada, workloadb, etc.)
- Benchmarks key-value operations:
  - **Read**: Read a record by key
  - **Write/Insert**: Create a new record
  - **Update**: Update an existing record
  - **Scan**: Read multiple consecutive records
  - **Delete**: Delete a record by key
- Configurable record counts, operation counts, and thread counts
- Uses LinearPBFT database driver for benchmarking the BFT system
- Thread-safe client management with graceful cleanup
- Requires f+1 matching responses for consensus verification

### 5. **Internal Packages**

#### `internal/linearpbft/`
- Core PBFT protocol implementation (Linear PBFT and SBFT)
- Message handling (PrePrepare, Prepare, Commit)
- SBFT optimization: skips commit phase when all N prepare messages are received
- View change protocol
- Checkpoint management
- Byzantine fault handling
- Timer and timeout management for SBFT
- Benchmark RPC endpoint support

#### `internal/clientapp/`
- Client application logic
- Transaction coordination
- Response collection
- Test set management
- Node reconfiguration

#### `internal/config/`
- Configuration file parsing
- YAML configuration support

#### `internal/crypto/`
- BLS signature operations
- Hash functions
- Cryptographic utilities

#### `internal/database/`
- BoltDB integration
- Account balance management
- Transaction logging
- Generic key-value operations for benchmarking (Put, Get, Update, Delete, Scan)

#### `internal/models/`
- Node and client data structures
- Network models

#### `benchmark/client/linearpbftdb/`
- YCSB database driver implementation for LinearPBFT
- Thread-safe client management
- Key-value operation translation to BFT transactions

## Client Details

The client application is responsible for:
1. **Transaction Submission**: Sends transfer and read-only transactions to the BFT nodes
2. **Response Collection**: Receives and verifies responses from nodes (requires f+1 matching responses)
3. **Test Management**: Processes test sets from CSV files with different configurations
4. **Interactive Control**: Provides commands to control test execution
5. **Node Reconfiguration**: Dynamically configures node behavior (alive, byzantine, attack types) per test set
6. **Signature Verification**: Verifies node signatures on all received responses

### Client Commands

The client application supports the following interactive commands:

- `next` - Execute the next test set
- `skip` - Skip the current test set
- `print log` - Print transaction log from nodes
- `print db` - Print database state from nodes
- `print status [n|all]` - Print status of sequence number `n` or all sequences
- `print view` - Print current view information
- `reset` - Reset both clients and nodes
- `reset clients` - Reset only clients
- `reset nodes` - Reset only nodes
- `exit` - Exit the application

### Client Architecture

- **Coordinator**: Manages transaction sending and response collection
- **Collector**: Gathers responses from nodes
- **Processor**: Processes transactions and manages state
- **Server**: gRPC server to receive responses from nodes

## Configuration

Configuration is stored in `configs/config.yaml`. The configuration file defines:

### Nodes
```yaml
nodes:
  n1:
    id: "n1"
    address: "localhost:5001"
  n2:
    id: "n2"
    address: "localhost:5002"
  # ... more nodes
```

### Clients
```yaml
clients:
  A:
    id: "A"
    address: "localhost:6001"
  B:
    id: "B"
    address: "localhost:6002"
  # ... more clients
```

### Database and Initial Settings
```yaml
db_dir: ./data          # Directory for database files
init_balance: 10        # Initial balance for each client account
```

### Configuration Parameters

- **nodes**: Map of node IDs to their network addresses
- **clients**: Map of client IDs to their network addresses
- **db_dir**: Directory where BoltDB files are stored (one per node)
- **init_balance**: Initial account balance for all clients

## Run Commands

### Prerequisites

1. **Install Dependencies**:
   - **Go**: Version 1.21 or later (see `go.mod` for exact version requirements)
   - **yq**: Required for parsing YAML configuration files in launch script
     - Install via: `brew install yq` (macOS) or `sudo apt-get install yq` (Linux)
     - Or download from: https://github.com/mikefarah/yq

2. **Generate Keys**: First, generate cryptographic keys for nodes and clients
   ```bash
   ./scripts/generate_keys.sh
   ```
   This generates BLS keys in the `keys/` directory:
   - Node keys: `keys/node/{node_id}_secret1.key`, `keys/node/{node_id}_secret2.key`
   - Master keys: `keys/node/master_public1.key`, `keys/node/master_public2.key`
   - Client keys: `keys/client/{client_id}_secret.key`

### Running the System

#### 1. Start All Nodes

Launch all BFT nodes using the launch script:
```bash
./scripts/launch.sh
```

This script:
- Cleans up previous logs and data directories
- Starts each node defined in `config.yaml` (requires `yq` to be installed)
- Redirects output to `logs/out/{node_id}.out`
- Redirects errors to `logs/err/{node_id}.err`
- Supports graceful shutdown via SIGTERM/SIGINT signals

**Note**: The launch script requires `yq` to parse the YAML configuration file. Install it before running the script.

Alternatively, start nodes individually:
```bash
go run cmd/server/main.go --id n1 --config ./configs/config.yaml
go run cmd/server/main.go --id n2 --config ./configs/config.yaml
# ... for each node
```

Each node supports graceful shutdown:
- Send SIGTERM or SIGINT (Ctrl+C) to stop the node gracefully
- The node will complete existing RPCs before shutting down
- Database connections and gRPC servers are closed cleanly

#### 2. Run Client Application

Run the client application with a test file:
```bash
go run cmd/client/main.go --file testdata/test_normal.csv
```

The client will:
- Load transactions from the CSV file
- Start client gRPC servers for each client (A-J)
- Provide an interactive command prompt
- Execute test sets based on user commands
- Support graceful shutdown and cleanup of connections

#### 3. Run Benchmark

Run YCSB benchmark to test system performance:
```bash
go run cmd/benchmark/ycsb/main.go
```

The benchmark will:
- Load initial data into the system
- Execute a configurable workload (read/write/update operations)
- Measure performance metrics (throughput, latency)
- Output benchmark results

**Benchmark Configuration:**
You can modify benchmark parameters in `cmd/benchmark/ycsb/main.go`:
- `RecordCount`: Number of records to load (default: 500)
- `OperationCount`: Number of operations to perform (default: 5000)
- `ThreadCount`: Number of concurrent threads (default: 10)
- `Workload`: YCSB workload type (core, workloada, workloadb, etc., default: core)

**Benchmark Execution:**
The benchmark runs in two phases:
1. **Load Phase**: Initializes the database with the specified number of records
2. **Run Phase**: Executes the workload operations and measures performance

Benchmark results include throughput and latency metrics, which are output after completion.

### Test Data Format

Test data files are CSV files located in `testdata/` directory. The CSV format includes:
- Transaction type (transfer or read)
- Client ID
- Source account
- Destination account
- Amount
- Test set number
- Node configuration (live, byzantine, attack types)

### Utility Scripts

#### Kill All Nodes
```bash
./scripts/kill.sh
```
Kills all running node processes.

#### Generate Protocol Buffers
```bash
./scripts/generate_stubs.sh
```
Generates gRPC and protocol buffer code from `.proto` files.

## Project Structure

```
bft-mavleo96/
├── benchmark/
│   └── client/
│       └── linearpbftdb/  # YCSB database driver for LinearPBFT
├── cmd/
│   ├── benchmark/
│   │   └── ycsb/          # YCSB benchmark application
│   ├── client/            # Client application
│   ├── server/            # BFT node server
│   └── generate_keys/     # Key generation utility
├── configs/               # Configuration files
├── data/                  # Database files (one per node)
├── debug/                 # Debug utilities and test scripts
├── internal/
│   ├── clientapp/         # Client application logic
│   ├── config/            # Configuration parsing
│   ├── crypto/            # Cryptographic operations
│   ├── database/          # Database operations
│   ├── linearpbft/        # PBFT protocol implementation
│   ├── models/            # Data models
│   └── utils/             # Utility functions
├── keys/                  # Cryptographic keys
├── logs/                  # Log files
├── pb/                    # Generated protocol buffer code
├── proto/                 # Protocol buffer definitions
├── scripts/               # Utility scripts
└── testdata/              # Test data files
```

## Dependencies

### Go Dependencies (managed via `go.mod`)
- **gRPC**: For inter-node and client-node communication
- **BLS-ETH-Go-Binary**: For BLS threshold signatures (Boneh-Lynn-Shacham)
- **BoltDB**: For persistent key-value storage
- **Logrus**: For structured logging
- **YAML** (gopkg.in/yaml.v3): For configuration file parsing
- **go-ycsb**: For performance benchmarking (Yahoo Cloud Serving Benchmark)
- **properties**: For property file handling in benchmarks
- **go-cmp**: For value comparisons and testing utilities

### System Dependencies
- **yq**: YAML processor required for the launch script
  - Install: `brew install yq` (macOS) or `sudo apt-get install yq` (Linux)
- **Go**: Version 1.21 or later (see `go.mod` for exact requirements)

All Go dependencies are automatically downloaded when you run `go mod download` or build the project.

## Notes

### System Requirements
- The system requires at least **3f+1 nodes** to tolerate **f Byzantine failures**
- Default configuration uses **7 nodes** (can tolerate **2 Byzantine failures**)
- Each node maintains its own database file in the `data/` directory
- Client applications listen on ports **6001-6010** by default
- Node servers listen on ports **5001-5007** by default

### Operation Modes
- **Banking Transactions**: Transfer and read-only operations for account management
- **Key-Value Operations**: Generic key-value operations for benchmarking (read, write, update, scan, delete)

### Features
- **Graceful Shutdown**: All components support graceful shutdown via SIGTERM/SIGINT
- **Connection Management**: Automatic cleanup of gRPC connections and database handles
- **Duplicate Request Handling**: Clients receive cached replies for duplicate requests
- **Request Forwarding**: Backup nodes automatically forward requests to the primary
- **View Change Support**: System can recover from primary failures through view changes
- **Checkpointing**: State checkpoints for efficient state management and recovery

### Benchmarking
- Benchmark operations require **f+1 matching responses** for consensus verification
- Thread-safe client management with per-thread gRPC servers
- Supports both load and run phases for comprehensive performance testing


## AI Usage

This project utilized open-source LLMs (Large Language Models) during development for assistance with the following components:

- **BLS Key Generation**: Implementation of the key generation script (`cmd/generate_keys/main.go`)
- **Utility Functions**: Logger string formatting functions for debugging and logging
- **Client Application**: Reset handler implementation in the `internal/clientapp` package
- **Code Review**: AI-assisted code review using Cursor IDE to identify unsafe operations and potential bugs
- **Benchmarking**: Generic key-value operations in database module
- **Documentation**: This README file was generated using AI
