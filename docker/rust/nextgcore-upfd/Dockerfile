# NextGCore UPF (User Plane Function) - Rust Implementation
#
# The UPF handles:
# - User plane packet forwarding
# - GTP-U encapsulation/decapsulation
# - N4 PFCP interface with SMF
# - PDR/FAR/QER/URR rule processing
# - TUN interface for PDN connectivity
# - ARP/ND handling for UE IP addresses
#
# IMPORTANT: UPF requires privileged mode or NET_ADMIN capability
# for TUN interface creation and packet forwarding.
#
# Build:
#   docker build -f docker/rust/nextgcore-upfd/Dockerfile -t nextgcore-upf:latest .
#
# Run:
#   docker run -d --name upf \
#     --privileged \
#     --cap-add=NET_ADMIN \
#     -v /path/to/upf.yaml:/etc/nextgcore/upf.yaml:ro \
#     -p 2152:2152/udp \
#     -p 8805:8805/udp \
#     nextgcore-upf:latest

ARG RUST_VERSION=1.85
ARG DEBIAN_VERSION=bookworm

# =============================================================================
# Stage 1: Chef - Cargo dependency caching
# =============================================================================
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS chef

RUN cargo install cargo-chef --locked
WORKDIR /app

# =============================================================================
# Stage 2: Planner - Generate dependency recipe
# =============================================================================
FROM chef AS planner

COPY rust_src/ ./
RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 3: Builder - Build UPF binary
# =============================================================================
FROM chef AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    cmake \
    libssl-dev \
    libsctp-dev \
    libyaml-dev \
    libmongoc-dev \
    libbson-dev \
    libnghttp2-dev \
    libtins-dev \
    iproute2 \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY rust_src/ ./
RUN cargo build --release -p nextgcore-upfd
RUN strip --strip-all target/release/nextgcore-upfd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore UPF (Rust)"
LABEL org.opencontainers.image.description="User Plane Function for 5G Core"
LABEL org.opencontainers.image.source="https://github.com/nextgcore/nextgcore"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libsctp1 \
    libyaml-0-2 \
    libmongoc-1.0-0 \
    libbson-1.0-0 \
    libnghttp2-14 \
    libtins4.0 \
    iproute2 \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nextgcore && useradd -r -g nextgcore -s /bin/false nextgcore

RUN mkdir -p /etc/nextgcore /var/log/nextgcore /var/run/nextgcore && \
    chown -R nextgcore:nextgcore /etc/nextgcore /var/log/nextgcore /var/run/nextgcore

COPY --from=builder /app/target/release/nextgcore-upfd /usr/local/bin/nextgcore-upfd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-upfd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

# Note: UPF requires NET_ADMIN capability for TUN interface
# Cannot run as non-root user without capabilities
# USER nextgcore

# GTP-U (UDP) - N3 interface to gNB, N9 to other UPFs
# PFCP (UDP) - N4 interface to SMF
EXPOSE 2152/udp 8805/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x nextgcore-upfd || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-upfd"]
CMD ["-c", "/etc/nextgcore/upf.yaml"]
