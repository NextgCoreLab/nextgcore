# NextGCore Rust Integration Tests

This directory contains integration tests for the NextGCore Rust implementation.
The tests verify end-to-end functionality of the 5G Core and EPC network functions.

## Test Categories

### 1. Registration Flow Tests (`registration/`)
- 5G UE registration through AMF
- 4G UE attach through MME

### 2. Session Establishment Tests (`session/`)
- PDU session establishment through SMF/UPF
- EPS bearer activation through MME/SGWC/SGWU

### 3. Inter-NF Communication Tests (`inter_nf/`)
- SBI communication between 5G NFs
- Diameter communication between EPC NFs
- GTP-C/GTP-U communication

### 4. Property Tests (`property/`)
- Message sequence equivalence with C implementation

## Prerequisites

### MongoDB
Integration tests require MongoDB for subscriber data storage.
The test framework uses `testcontainers` to automatically spin up MongoDB containers.

### Docker
Docker must be installed and running for testcontainers to work.

## Running Tests

```bash
# Run all integration tests
cargo test --test integration

# Run specific test category
cargo test --test integration registration
cargo test --test integration session
cargo test --test integration inter_nf

# Run with verbose output
cargo test --test integration -- --nocapture
```

## Test Configuration

Tests use the following default configuration:
- MongoDB: Automatically provisioned via testcontainers
- Network: Uses localhost with dynamic port allocation
- Timeouts: 30 seconds for NF startup, 10 seconds for message exchange

## Writing New Tests

1. Add test functions to the appropriate module
2. Use the `TestContext` for NF lifecycle management
3. Use `TestSubscriber` for subscriber provisioning
4. Follow the existing patterns for message verification
