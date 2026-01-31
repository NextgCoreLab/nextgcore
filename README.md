# NextGCore - Pure Rust 5G/LTE Core Network

NextGCore is a pure Rust implementation of a 5G/LTE mobile core network, derived from the Open5GS project. It provides a complete, production-ready 5G Standalone (SA) core with zero C library dependencies.

## Key Features

- **Pure Rust** - No C library dependencies, enabling true cross-compilation
- **Cross-Platform** - Build for Linux (x86_64, ARM64), macOS, and more
- **Userspace SCTP** - Pure Rust SCTP implementation over UDP (no kernel SCTP required)
- **Async/Await** - Modern async runtime using Tokio
- **Container-Ready** - Optimized Docker images with minimal footprint
- **Complete 5GC** - All core network functions implemented

## Quickstart

### Option 1: Docker (Recommended)

The fastest way to deploy a complete 5G core:

```bash
# Clone the repository
git clone https://github.com/nextgcore/nextgcore.git
cd nextgcore/docker/rust

# Build optimized images (uses pre-built binaries)
docker compose -f docker-compose-5gc-optimized.yml build

# Start the 5G core
docker compose -f docker-compose-5gc-optimized.yml up -d

# Verify all services are running
docker ps --filter "name=nextgcore-5gc" --format "table {{.Names}}\t{{.Status}}"

# Check AMF logs
docker logs nextgcore-5gc-amf 2>&1 | tail -20
```

Expected output:
```
nextgcore-5gc-amf       Up 2 minutes (healthy)
nextgcore-5gc-smf       Up 2 minutes (healthy)
nextgcore-5gc-upf       Up 2 minutes (healthy)
...
```

### Option 2: Build from Source

```bash
# Prerequisites: Rust 1.85+
cd rust_src
cargo build --release

# Start network functions individually
./target/release/nextgcore-nrfd -c configs/nrf.yaml &
./target/release/nextgcore-amfd -c configs/amf.yaml &
./target/release/nextgcore-smfd -c configs/smf.yaml &
./target/release/nextgcore-upfd -c configs/upf.yaml &
```

### Option 3: Connect with nextgsim Simulator

```bash
# Start the 5G core
cd nextgcore/docker/rust
docker compose -f docker-compose-5gc-optimized.yml up -d

# Start the UE/gNB simulator (from nextgsim repository)
cd ../../nextgsim
docker compose up -d

# Verify UE registration
docker logs nextgsim-ue 2>&1 | grep "REGISTERED"
# Expected: "UE is now REGISTERED"
```

## Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NextGCore 5G Core Network                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────── Control Plane ───────────────────────────┐   │
│  │                                                                      │   │
│  │   ┌─────┐    ┌──────┐    ┌─────┐    ┌─────┐    ┌──────┐           │   │
│  │   │ NRF │◄──►│ AUSF │◄──►│ UDM │◄──►│ UDR │◄──►│  DB  │           │   │
│  │   └──┬──┘    └──────┘    └─────┘    └─────┘    └──────┘           │   │
│  │      │                                                              │   │
│  │      │ SBI (HTTP/2)                                                 │   │
│  │      ▼                                                              │   │
│  │   ┌─────┐    ┌──────┐    ┌─────┐    ┌─────┐                       │   │
│  │   │ AMF │◄──►│ NSSF │◄──►│ PCF │◄──►│ BSF │                       │   │
│  │   └──┬──┘    └──────┘    └─────┘    └─────┘                       │   │
│  │      │                                                              │   │
│  └──────┼──────────────────────────────────────────────────────────────┘   │
│         │ NGAP (N2)                        │ N11                            │
│         ▼                                  ▼                                │
│   ┌──────────┐                      ┌──────────┐                           │
│   │   gNB    │                      │   SMF    │                           │
│   │ (RAN)    │                      └────┬─────┘                           │
│   └────┬─────┘                           │ N4 (PFCP)                       │
│        │                                 ▼                                  │
│        │ GTP-U (N3)              ┌──────────────┐                          │
│        └────────────────────────►│     UPF      │──────► Internet          │
│                                  │ (User Plane) │       (N6)               │
│                                  └──────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Docker Deployment

### Container IP Addresses

| Service | IP Address | Ports |
|---------|------------|-------|
| MongoDB | 172.23.0.2 | 27017 |
| NRF | 172.23.0.10 | 7777 (SBI) |
| AUSF | 172.23.0.11 | SBI |
| UDM | 172.23.0.12 | SBI |
| PCF | 172.23.0.13 | 9093 (metrics) |
| NSSF | 172.23.0.14 | SBI |
| BSF | 172.23.0.15 | SBI |
| UDR | 172.23.0.20 | SBI |
| **AMF** | **172.23.0.5** | **38412/NGAP** |
| SMF | 172.23.0.4 | 8805/PFCP |
| **UPF** | **172.23.0.7** | **2152/GTP-U** |

### Docker Compose Files

| File | Description |
|------|-------------|
| `docker-compose-5gc-optimized.yml` | 5G Core with pre-built binaries (recommended) |
| `docker-compose-5gc.yml` | 5G Core with in-container build |
| `docker-compose-epc.yml` | 4G EPC deployment |
| `docker-compose.yml` | Full 5GC + EPC deployment |

### Environment Variables

```bash
RUST_LOG=info           # Log level (trace, debug, info, warn, error)
RUST_BACKTRACE=1        # Enable backtraces for debugging
```

## Project Structure

```
nextgcore/
├── rust_src/           # Rust source code
│   ├── bins/           # Network function binaries
│   │   ├── nextgcore-amfd/    # Access and Mobility Management Function
│   │   ├── nextgcore-ausfd/   # Authentication Server Function
│   │   ├── nextgcore-bsfd/    # Binding Support Function
│   │   ├── nextgcore-hssd/    # Home Subscriber Server
│   │   ├── nextgcore-mmed/    # Mobility Management Entity
│   │   ├── nextgcore-nrfd/    # Network Repository Function
│   │   ├── nextgcore-nssfd/   # Network Slice Selection Function
│   │   ├── nextgcore-pcfd/    # Policy Control Function
│   │   ├── nextgcore-pcrfd/   # Policy and Charging Rules Function
│   │   ├── nextgcore-scpd/    # Service Communication Proxy
│   │   ├── nextgcore-seppd/   # Security Edge Protection Proxy
│   │   ├── nextgcore-sgwcd/   # Serving Gateway Control Plane
│   │   ├── nextgcore-sgwud/   # Serving Gateway User Plane
│   │   ├── nextgcore-smfd/    # Session Management Function
│   │   ├── nextgcore-udmd/    # Unified Data Management
│   │   ├── nextgcore-udrd/    # Unified Data Repository
│   │   └── nextgcore-upfd/    # User Plane Function
│   ├── libs/           # Shared library crates
│   └── tests/          # Integration tests
├── docker/             # Docker deployment files
│   ├── rust/           # Rust NF Docker configurations
│   │   ├── configs/    # Network function configurations
│   │   └── binaries/   # Pre-built binaries (for fast builds)
│   └── webui/          # WebUI Docker configuration
└── webui/              # Web-based management interface
```

## Network Functions

### 5G Core (5GC)

| NF | Description | 3GPP Spec |
|----|-------------|-----------|
| **NRF** | Network Repository Function - Service discovery | TS 29.510 |
| **AUSF** | Authentication Server Function - UE authentication | TS 29.509 |
| **UDM** | Unified Data Management - Subscriber data | TS 29.503 |
| **UDR** | Unified Data Repository - Data storage | TS 29.504 |
| **PCF** | Policy Control Function - QoS policies | TS 29.507 |
| **NSSF** | Network Slice Selection Function | TS 29.531 |
| **BSF** | Binding Support Function - PCF binding | TS 29.521 |
| **AMF** | Access and Mobility Management Function | TS 29.518 |
| **SMF** | Session Management Function | TS 29.502 |
| **UPF** | User Plane Function - Data forwarding | TS 29.244 |

### Evolved Packet Core (EPC)

| NF | Description |
|----|-------------|
| **HSS** | Home Subscriber Server |
| **PCRF** | Policy and Charging Rules Function |
| **MME** | Mobility Management Entity |
| **SGW-C** | Serving Gateway Control Plane |
| **SGW-U** | Serving Gateway User Plane |

### Optional Components

| NF | Description |
|----|-------------|
| **SCP** | Service Communication Proxy |
| **SEPP** | Security Edge Protection Proxy |

## Configuration

### AMF Configuration

```yaml
# configs/5gc/amf.yaml
amf:
  sbi:
    server:
      address: 0.0.0.0
      port: 7777
  ngap:
    server:
      address: 0.0.0.0
      port: 38412
  guami:
    - plmn_id:
        mcc: 999
        mnc: 70
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: 999
        mnc: 70
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 999
        mnc: 70
      s_nssai:
        - sst: 1
```

### UPF Configuration

```yaml
# configs/5gc/upf.yaml
upf:
  pfcp:
    server:
      address: 172.23.0.7
  gtpu:
    server:
      address: 172.23.0.7
  session:
    - subnet: 10.45.0.0/16
      gateway: 10.45.0.1
```

## Testing

### Unit Tests

```bash
cd rust_src
cargo test
```

### Integration Tests

```bash
# With Docker running
cd docker/rust
./validate-deployment.sh
```

### Protocol Conformance

The implementation follows 3GPP Release 17 specifications:
- NGAP: TS 38.413
- NAS 5G: TS 24.501
- SBI: TS 29.500 series
- PFCP: TS 29.244
- GTP-U: TS 29.281

## Development

### Building

```bash
cd rust_src

# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Build specific NF
cargo build --release -p nextgcore-amfd
```

### Cross-Compilation

```bash
# Add target
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64 Linux
cargo build --release --target aarch64-unknown-linux-gnu
```

### Code Quality

```bash
# Format code
cargo fmt

# Run lints
cargo clippy --all-targets

# Check for security vulnerabilities
cargo audit
```

## Contributing

We welcome contributions! Here's how to get started:

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/nextgcore/nextgcore.git
cd nextgcore

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and test
cd rust_src
cargo build
cargo test
```

### Contribution Guidelines

1. **Fork the repository** and create a feature branch
2. **Follow Rust conventions**: Use `cargo fmt` and `cargo clippy`
3. **Write tests**: All new features should include tests
4. **Update documentation**: Keep README and doc comments current
5. **Sign commits**: Use `git commit -s` for DCO sign-off

### Pull Request Process

1. Ensure all tests pass: `cargo test`
2. Run lints: `cargo clippy --all-targets`
3. Format code: `cargo fmt`
4. Update CHANGELOG.md if applicable
5. Submit PR with clear description of changes

### Areas for Contribution

- **Network Functions**: Enhance existing NF implementations
- **Protocol Support**: Add missing 3GPP procedures
- **Performance**: Profiling and optimization
- **Testing**: More unit and integration tests
- **Documentation**: Tutorials, architecture docs
- **Cross-Platform**: Test on different architectures

### Reporting Issues

Use GitHub Issues for:
- Bug reports (include logs and reproduction steps)
- Feature requests
- Documentation improvements

## WebUI

### Access

Open http://localhost:9999 in your browser.

### Default Credentials

- Username: `admin`
- Password: `1423`

### Features

- Subscriber management
- Network slice configuration
- Session monitoring
- Statistics and metrics

## Key Dependencies

- **tokio** - Async runtime
- **hyper** - HTTP/2 for SBI
- **tonic** - gRPC (optional)
- **serde** - Configuration parsing
- **tracing** - Structured logging
- **sctp-proto** - Pure Rust SCTP
- **mongodb** - Subscriber database

## References

### 3GPP Specifications

- [TS 23.501](https://www.3gpp.org/DynaReport/23501.htm) - System Architecture
- [TS 23.502](https://www.3gpp.org/DynaReport/23502.htm) - Procedures
- [TS 29.500](https://www.3gpp.org/DynaReport/29500.htm) - SBI Framework
- [TS 38.413](https://www.3gpp.org/DynaReport/38413.htm) - NGAP
- [TS 29.244](https://www.3gpp.org/DynaReport/29244.htm) - PFCP

### Related Projects

- [Open5GS](https://open5gs.org/) - Original C implementation
- [nextgsim](../nextgsim) - Companion UE/gNB simulator

## Troubleshooting

### Common Issues

**AMF not accepting gNB connections**
```bash
# Check AMF is listening on NGAP port
docker logs nextgcore-5gc-amf | grep "NGAP"
# Should show: "NGAP server listening on 0.0.0.0:38412"
```

**UPF not forwarding traffic**
```bash
# Verify UPF has TUN interface
docker exec nextgcore-5gc-upf ip addr show
# Verify IP forwarding
docker exec nextgcore-5gc-upf sysctl net.ipv4.ip_forward
```

**MongoDB connection issues**
```bash
# Check MongoDB health
docker logs nextgcore-5gc-mongodb
# Verify connectivity
docker exec nextgcore-5gc-amf ping -c 1 172.23.0.2
```

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.
