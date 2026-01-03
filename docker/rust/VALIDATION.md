# NextGCore Rust Docker Deployment Validation

This document describes how to validate Docker Compose deployments for the NextGCore Rust implementation.

## Overview

The validation script (`validate-deployment.sh`) tests both 5G Core (5GC) and EPC (4G) deployments to ensure:

1. All containers are running
2. All network function processes are active
3. NRF is accepting NF registrations (5GC)
4. MongoDB is accessible
5. Key interfaces are operational

## Prerequisites

- Docker and Docker Compose installed
- `curl` for HTTP health checks
- `jq` (optional) for better JSON output parsing
- Images built using `./build.sh -a` or Docker Compose build

## Quick Start

### Build Images First

```bash
cd docker/rust

# Build all images
./build.sh -a

# Or build specific stacks
./build.sh -5  # 5G Core only
./build.sh -4  # EPC only
```

### Deploy and Validate

```bash
# Deploy and validate 5G Core
./validate-deployment.sh -d -5

# Deploy and validate EPC
./validate-deployment.sh -d -4

# Deploy and validate both stacks
./validate-deployment.sh -d -a

# Deploy, validate, and cleanup
./validate-deployment.sh -d -a -c
```

### Validate Existing Deployment

If services are already running:

```bash
# Validate 5G Core
./validate-deployment.sh -5

# Validate EPC
./validate-deployment.sh -4

# Validate both
./validate-deployment.sh -a
```

## Validation Checks

### 5G Core (5GC) Stack

| Component | Checks |
|-----------|--------|
| MongoDB | Container running, accepting connections, database accessible |
| NRF | Container running, SBI endpoint responding, NF registration |
| AUSF | Container running, process active |
| UDM | Container running, process active |
| UDR | Container running, process active |
| PCF | Container running, process active |
| NSSF | Container running, process active |
| BSF | Container running, process active |
| AMF | Container running, process active |
| SMF | Container running, process active |
| UPF | Container running, process active, TUN interface exists |

### EPC Stack

| Component | Checks |
|-----------|--------|
| MongoDB | Container running, accepting connections |
| HSS | Container running, process active |
| PCRF | Container running, process active |
| MME | Container running, process active |
| SGW-C | Container running, process active |
| SGW-U | Container running, process active |

## Command Line Options

```
Usage: ./validate-deployment.sh [OPTIONS]

Options:
  -5, --5gc       Validate 5G Core deployment only
  -4, --epc       Validate EPC deployment only
  -a, --all       Validate both 5GC and EPC (default)
  -d, --deploy    Deploy before validating (builds images if needed)
  -c, --cleanup   Clean up after validation
  -t, --timeout N Timeout in seconds for service readiness (default: 120)
  -v, --verbose   Enable verbose output
  -h, --help      Show this help message
```

## Example Output

```
============================================
NextGCore Rust Docker Deployment Validation
============================================

Configuration:
  Validate 5GC: true
  Validate EPC: false
  Deploy:       true
  Cleanup:      false
  Timeout:      120s
  Verbose:      false

============================================
Deploying 5G Core Stack
============================================
[INFO] Starting 5GC services...
[INFO] Waiting for services to initialize...
[INFO] Waiting for MongoDB to be ready...
[INFO] Waiting for NRF to be ready...
[INFO] Waiting for NFs to register with NRF...

============================================
Validating 5G Core Stack
============================================
[INFO] Validating MongoDB for 5GC...
[PASS] MongoDB: Accepting connections
[PASS] MongoDB: nextgcore database accessible
[INFO] Validating NRF (Network Repository Function)...
[PASS] NRF SBI: HTTP 200
[INFO] Validating NF Registration with NRF...
[PASS] NRF: 9 NF(s) registered
  - AUSF: abc123...
  - UDM: def456...
  ...
[INFO] Validating AUSF (Authentication Server Function)...
[PASS] AUSF: Process running
...

============================================
Validation Summary
============================================
Tests Passed:  15
Tests Failed:  0
Tests Skipped: 0

Pass Rate: 100%

All validations passed!
```

## Troubleshooting

### Services Not Starting

1. Check Docker logs:
   ```bash
   docker compose -f docker-compose-5gc.yml logs -f
   ```

2. Check individual container logs:
   ```bash
   docker logs nextgcore-5gc-nrf
   ```

3. Verify images are built:
   ```bash
   docker images | grep nextgcore
   ```

### NFs Not Registering with NRF

1. Check NRF is accessible:
   ```bash
   curl http://localhost:7777/nnrf-nfm/v1/nf-instances
   ```

2. Check NF logs for registration errors:
   ```bash
   docker logs nextgcore-5gc-amf 2>&1 | grep -i "register\|nrf"
   ```

3. Verify network connectivity:
   ```bash
   docker network inspect nextgcore-5gc
   ```

### MongoDB Connection Issues

1. Check MongoDB is running:
   ```bash
   docker exec nextgcore-5gc-mongodb mongosh --eval "db.adminCommand('ping')"
   ```

2. Check MongoDB logs:
   ```bash
   docker logs nextgcore-5gc-mongodb
   ```

### UPF TUN Interface Issues

1. Check if TUN device exists:
   ```bash
   docker exec nextgcore-5gc-upf ip link show ogstun
   ```

2. Verify UPF has required capabilities:
   ```bash
   docker inspect nextgcore-5gc-upf | grep -A5 "CapAdd"
   ```

## Manual Deployment

### 5G Core

```bash
cd docker/rust

# Start services
docker compose -f docker-compose-5gc.yml up -d

# Check status
docker compose -f docker-compose-5gc.yml ps

# View logs
docker compose -f docker-compose-5gc.yml logs -f

# Stop services
docker compose -f docker-compose-5gc.yml down
```

### EPC

```bash
cd docker/rust

# Start services
docker compose -f docker-compose-epc.yml up -d

# Check status
docker compose -f docker-compose-epc.yml ps

# View logs
docker compose -f docker-compose-epc.yml logs -f

# Stop services
docker compose -f docker-compose-epc.yml down
```

### Combined Deployment

```bash
cd docker/rust

# Start all services (5GC + EPC)
docker compose up -d

# With SCP (Service Communication Proxy)
docker compose --profile scp up -d

# With SEPP (Security Edge Protection Proxy)
docker compose --profile sepp up -d

# Stop all services
docker compose down
```

## CI/CD Integration

The validation script can be integrated into CI/CD pipelines:

```yaml
# GitHub Actions example
jobs:
  validate-docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker images
        run: |
          cd docker/rust
          ./build.sh -a
      
      - name: Validate 5GC deployment
        run: |
          cd docker/rust
          ./validate-deployment.sh -d -5 -c
      
      - name: Validate EPC deployment
        run: |
          cd docker/rust
          ./validate-deployment.sh -d -4 -c
```

## Network Architecture

### 5G Core Network (172.23.0.0/24)

| Service | IP Address | Ports |
|---------|------------|-------|
| MongoDB | 172.23.0.2 | 27017 |
| NRF | 172.23.0.10 | 7777 (SBI) |
| AUSF | 172.23.0.11 | 7777 (SBI) |
| UDM | 172.23.0.12 | 7777 (SBI) |
| PCF | 172.23.0.13 | 7777 (SBI), 9090 (Metrics) |
| NSSF | 172.23.0.14 | 7777 (SBI) |
| BSF | 172.23.0.15 | 7777 (SBI) |
| UDR | 172.23.0.20 | 7777 (SBI) |
| AMF | 172.23.0.5 | 7777 (SBI), 38412/sctp (NGAP) |
| SMF | 172.23.0.4 | 7777 (SBI), 8805/udp (PFCP) |
| UPF | 172.23.0.7 | 2152/udp (GTP-U), 8805/udp (PFCP) |

### EPC Network (172.24.0.0/24)

| Service | IP Address | Ports |
|---------|------------|-------|
| MongoDB | 172.24.0.2 | 27017 |
| HSS | 172.24.0.8 | 3868 (Diameter) |
| PCRF | 172.24.0.9 | 3868 (Diameter) |
| SGW-C | 172.24.0.3 | 2123/udp (GTP-C), 8805/udp (PFCP) |
| MME | 172.24.0.5 | 36412/sctp (S1AP) |
| SGW-U | 172.24.0.6 | 2152/udp (GTP-U) |
