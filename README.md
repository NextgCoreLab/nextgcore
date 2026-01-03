# NextGCore - 5G/LTE Core Network (Rust Implementation)

NextGCore is a pure Rust implementation of a 5G/LTE mobile core network, derived from the Open5GS project.

## Key Features

- **Pure Rust** - No C library dependencies, enabling true cross-compilation
- **Cross-Platform** - Build for Linux (x86_64, ARM64), macOS, and more
- **Userspace SCTP** - Pure Rust SCTP implementation over UDP (no kernel SCTP required)
- **Async/Await** - Modern async runtime using Tokio
- **Container-Ready** - Optimized Docker images with minimal footprint

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
│   └── webui/          # WebUI Docker configuration
└── webui/              # Web-based management interface
```

## Building

### Prerequisites

- Rust 1.85 or later
- Docker and Docker Compose (for containerized deployment)

### Build from Source

```bash
cd rust_src
cargo build --release
```

### Cross-Compilation

Since NextGCore is pure Rust with no C dependencies, you can easily cross-compile:

```bash
# Add target
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64 Linux
cargo build --release --target aarch64-unknown-linux-gnu
```

### Build Docker Images

```bash
cd docker/rust

# Standard build (compiles inside containers)
./build.sh

# Fast build (pre-compile, then copy binaries)
./build-fast.sh
```

## Deployment

### Using Docker Compose

```bash
cd docker/rust

# Start all services (5GC + EPC)
docker compose up -d

# Start 5G Core only
docker compose -f docker-compose-5gc.yml up -d

# Start EPC only
docker compose -f docker-compose-epc.yml up -d
```

### Access WebUI

Open http://localhost:9999 in your browser.

Default credentials:
- Username: admin
- Password: 1423

## Network Functions

### 5G Core (5GC)
- **NRF** - Network Repository Function
- **AUSF** - Authentication Server Function
- **UDM** - Unified Data Management
- **UDR** - Unified Data Repository
- **PCF** - Policy Control Function
- **NSSF** - Network Slice Selection Function
- **BSF** - Binding Support Function
- **AMF** - Access and Mobility Management Function
- **SMF** - Session Management Function
- **UPF** - User Plane Function

### Evolved Packet Core (EPC)
- **HSS** - Home Subscriber Server
- **PCRF** - Policy and Charging Rules Function
- **MME** - Mobility Management Entity
- **SGW-C** - Serving Gateway Control Plane
- **SGW-U** - Serving Gateway User Plane

### Optional Components
- **SCP** - Service Communication Proxy
- **SEPP** - Security Edge Protection Proxy

## License

AGPL-3.0
