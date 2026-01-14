# NextGCore Rust Docker Deployment

This directory contains Docker configurations for deploying the NextGCore Rust implementation. The Rust version provides memory-safe network functions with exact algorithm parity to the C implementation.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building Images](#building-images)
- [Deployment Options](#deployment-options)
- [Configuration](#configuration)
- [Network Architecture](#network-architecture)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

## Prerequisites

- Docker 24.0+ with BuildKit support
- Docker Compose v2.20+
- 4GB+ RAM (8GB recommended for full deployment)
- `curl` and `jq` for validation scripts

### Verify Prerequisites

```bash
# Check Docker version
docker --version

# Check Docker Compose version
docker compose version

# Verify BuildKit is enabled
docker buildx version
```

## Quick Start

### Deploy 5G Core (5GC)

```bash
cd docker/rust

# Build images
./build.sh -5

# Deploy
docker compose -f docker-compose-5gc.yml up -d

# Verify deployment
./validate-deployment.sh -5

# View logs
docker compose -f docker-compose-5gc.yml logs -f
```

### Deploy EPC (4G LTE)

```bash
cd docker/rust

# Build images
./build.sh -4

# Deploy
docker compose -f docker-compose-epc.yml up -d

# Verify deployment
./validate-deployment.sh -4

# View logs
docker compose -f docker-compose-epc.yml logs -f
```

### Deploy Full Stack (5GC + EPC)

```bash
cd docker/rust

# Build all images
./build.sh -a

# Deploy
docker compose up -d

# Verify deployment
./validate-deployment.sh -a

# View logs
docker compose logs -f
```

## Building Images

### Build Script Options

```bash
./build.sh [OPTIONS] [NF_NAME...]

Options:
  -t, --tag TAG           Image tag (default: latest)
  -r, --registry REG      Registry prefix (e.g., ghcr.io/nextgcore)
  -p, --push              Push images after building
  -a, --all               Build all network functions
  -5, --5gc               Build only 5G Core NFs
  -4, --epc               Build only EPC (4G) NFs
  -T, --template          Use template Dockerfile
  -P, --parallel          Build images in parallel
  -j, --jobs N            Number of parallel jobs (default: 4)
  --no-cache              Build without using cache
  --platforms PLATFORMS   Multi-platform build (e.g., linux/amd64,linux/arm64)
  --build-base            Build base image first
  --auto-version          Auto-generate version from git
  --dry-run               Show what would be built
  -v, --verbose           Enable verbose output
  -h, --help              Show help message
```

### Build Examples

```bash
# Build all images
./build.sh -a

# Build with custom tag
./build.sh -t v1.0.0 -a

# Build and push to registry
./build.sh -r ghcr.io/nextgcore -t v1.0.0 -p -a

# Parallel build (faster)
./build.sh -P -j 8 -a

# Multi-platform build
./build.sh --platforms linux/amd64,linux/arm64 -a

# Build specific NFs
./build.sh nextgcore-amfd nextgcore-smfd nextgcore-upfd
```

### Build Individual Images

```bash
# Using Docker directly
docker build -f Dockerfile.nf-template \
  --build-arg NF_NAME=nextgcore-amfd \
  -t nextgcore-rust/amf:latest \
  ../..
```

## Deployment Options

### Docker Compose Files

| File | Description |
|------|-------------|
| `docker-compose.yml` | Full deployment (5GC + EPC) |
| `docker-compose-5gc.yml` | 5G Core only |
| `docker-compose-epc.yml` | EPC (4G) only |

### Deployment Profiles

```bash
# Basic 5GC deployment
docker compose -f docker-compose-5gc.yml up -d

# 5GC with SCP (Service Communication Proxy)
docker compose -f docker-compose-5gc.yml --profile scp up -d

# 5GC with SEPP (Security Edge Protection Proxy for roaming)
docker compose -f docker-compose-5gc.yml --profile sepp up -d

# Full deployment with all optional services
docker compose --profile scp --profile sepp up -d
```

### Scaling Services

```bash
# Scale UPF instances
docker compose -f docker-compose-5gc.yml up -d --scale upf=3
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key configuration options:

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level | `info` |
| `PLMN_MCC` | Mobile Country Code | `999` |
| `PLMN_MNC` | Mobile Network Code | `70` |
| `TAC` | Tracking Area Code | `1` |
| `MAX_UE` | Maximum UEs | `1024` |
| `SBI_TLS_ENABLED` | Enable TLS for SBI | `false` |

### Configuration Files

Configuration files are mounted from `configs/` directory:

```
configs/
├── 5gc/                    # 5G Core configurations
│   ├── amf.yaml
│   ├── smf.yaml
│   ├── upf.yaml
│   ├── nrf.yaml
│   ├── ausf.yaml
│   ├── udm.yaml
│   ├── udr.yaml
│   ├── pcf.yaml
│   ├── nssf.yaml
│   ├── bsf.yaml
│   └── hnet/              # Home network keys
├── epc/                    # EPC configurations
│   ├── mme.yaml
│   ├── hss.yaml
│   ├── pcrf.yaml
│   ├── sgwc.yaml
│   ├── sgwu.yaml
│   └── freeDiameter/      # Diameter configurations
├── scp.yaml               # SCP configuration
├── sepp1.yaml             # SEPP1 configuration
├── sepp2.yaml             # SEPP2 configuration
└── tls/                   # TLS certificates
```

### Custom Configuration

Mount custom configuration files:

```yaml
services:
  amf:
    volumes:
      - ./my-configs/amf.yaml:/etc/nextgcore/nextgcore-amfd.yaml:ro
```

## Network Architecture

### 5G Core Network (172.23.0.0/24)

```
┌─────────────────────────────────────────────────────────────────┐
│                        5G Core Network                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │
│  │   NRF   │    │  AUSF   │    │   UDM   │    │   UDR   │     │
│  │ .0.10   │    │ .0.11   │    │ .0.12   │    │ .0.20   │     │
│  └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘     │
│       │              │              │              │           │
│       └──────────────┴──────────────┴──────────────┘           │
│                          │ SBI                                  │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │
│  │   PCF   │    │  NSSF   │    │   BSF   │    │   SCP   │     │
│  │ .0.13   │    │ .0.14   │    │ .0.15   │    │ .0.50   │     │
│  └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘     │
│       │              │              │              │           │
│       └──────────────┴──────────────┴──────────────┘           │
│                          │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    AMF (.0.5)                            │   │
│  │              NGAP: 38412/sctp, SBI: 7777                │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    SMF (.0.4)                            │   │
│  │              PFCP: 8805/udp, SBI: 7777                  │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ N4 (PFCP)                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    UPF (.0.7)                            │   │
│  │         GTP-U: 2152/udp, PFCP: 8805/udp                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### EPC Network (172.24.0.0/24)

```
┌─────────────────────────────────────────────────────────────────┐
│                        EPC Network                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    HSS (.0.8)                            │   │
│  │                 Diameter: 3868                           │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ S6a                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    MME (.0.5)                            │   │
│  │              S1AP: 36412/sctp, GTP-C: 2123              │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ S11                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   SGW-C (.0.3)                           │   │
│  │              GTP-C: 2123, PFCP: 8805                    │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ Sxa                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   SGW-U (.0.6)                           │   │
│  │                    GTP-U: 2152                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   PCRF (.0.9)                            │   │
│  │                 Diameter: 3868                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Port Mappings

| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| NRF | HTTP/2 | 7777 | SBI interface |
| AMF | SCTP | 38412 | NGAP (N2 to gNB) |
| AMF | HTTP/2 | 7777 | SBI interface |
| SMF | UDP | 8805 | PFCP (N4 to UPF) |
| SMF | HTTP/2 | 7777 | SBI interface |
| UPF | UDP | 2152 | GTP-U (N3 to gNB) |
| UPF | UDP | 8805 | PFCP (N4 to SMF) |
| MME | SCTP | 36412 | S1AP (to eNB) |
| HSS | TCP | 3868 | Diameter (S6a) |
| MongoDB | TCP | 27017 | Database |
| WebUI | TCP | 9999 | Management UI |

## Validation

### Automated Validation

```bash
# Validate 5GC deployment
./validate-deployment.sh -5

# Validate EPC deployment
./validate-deployment.sh -4

# Validate both with deployment
./validate-deployment.sh -d -a

# Validate and cleanup
./validate-deployment.sh -d -a -c
```

See [VALIDATION.md](VALIDATION.md) for detailed validation procedures.

### Manual Validation

```bash
# Check container status
docker compose ps

# Check NRF health
curl http://localhost:7777/nnrf-nfm/v1/nf-instances

# Check MongoDB
docker exec nextgcore-mongodb mongosh --eval "db.adminCommand('ping')"

# Check UPF TUN interface
docker exec nextgcore-upf ip link show ogstun
```

## Troubleshooting

### Common Issues

#### Containers Not Starting

```bash
# Check logs
docker compose logs [service_name]

# Check resource usage
docker stats

# Verify images exist
docker images | grep nextgcore
```

#### NFs Not Registering with NRF

```bash
# Check NRF is accessible
curl -v http://localhost:7777/nnrf-nfm/v1/nf-instances

# Check NF logs for registration errors
docker logs nextgcore-amf 2>&1 | grep -i "register\|nrf"

# Verify network connectivity
docker network inspect nextgcore-5gc
```

#### MongoDB Connection Issues

```bash
# Check MongoDB status
docker logs nextgcore-mongodb

# Test connection
docker exec nextgcore-mongodb mongosh --eval "db.adminCommand('ping')"

# Check database
docker exec nextgcore-mongodb mongosh nextgcore --eval "db.subscribers.count()"
```

#### UPF TUN Interface Issues

```bash
# Check TUN device
docker exec nextgcore-upf ip link show ogstun

# Check capabilities
docker inspect nextgcore-upf | grep -A5 "CapAdd"

# Check IP forwarding
docker exec nextgcore-upf sysctl net.ipv4.ip_forward
```

### Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f amf

# Last 100 lines
docker compose logs --tail=100 amf

# With timestamps
docker compose logs -t amf
```

### Cleanup

```bash
# Stop services
docker compose down

# Stop and remove volumes
docker compose down -v

# Remove all NextGCore images
docker images | grep nextgcore | awk '{print $3}' | xargs docker rmi

# Full cleanup
docker compose down -v --rmi all
```

## Advanced Usage

### Multi-Platform Builds

```bash
# Create buildx builder
docker buildx create --name nextgcore-builder --use

# Build for multiple platforms
./build.sh --platforms linux/amd64,linux/arm64 -p -a
```

### CI/CD Integration

```yaml
# GitHub Actions example
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build images
        run: |
          cd docker/rust
          ./build.sh -a
      
      - name: Validate deployment
        run: |
          cd docker/rust
          ./validate-deployment.sh -d -a -c
```

### Production Deployment

For production deployments:

1. Enable TLS for SBI interfaces
2. Use external MongoDB with authentication
3. Configure proper network segmentation
4. Set up monitoring with Prometheus/Grafana
5. Configure log aggregation
6. Use secrets management for credentials

```bash
# Production deployment with TLS
SBI_TLS_ENABLED=true docker compose up -d
```

### Kubernetes Deployment

Helm charts for Kubernetes deployment are available in the `helm/` directory (coming soon).

## License

NextGCore is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

## Support

- [GitHub Issues](https://github.com/nextgcore/nextgcore/issues)
- [GitHub Discussions](https://github.com/nextgcore/nextgcore/discussions)
- [Discord](https://discord.gg/GreNkuc)
