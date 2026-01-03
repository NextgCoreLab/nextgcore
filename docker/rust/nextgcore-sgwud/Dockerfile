# NextGCore SGW-U (Serving Gateway - User Plane) - Rust Implementation
#
# The SGW-U handles (4G/LTE EPC):
# - GTP-U user plane data forwarding
# - S1-U interface with eNB
# - S5/S8 interface with PGW-U/UPF
# - Sxa PFCP interface with SGW-C
# - Packet forwarding based on PDR/FAR rules
#
# Build:
#   docker build -f docker/rust/nextgcore-sgwud/Dockerfile -t nextgcore-sgwu:latest .
#
# Run:
#   docker run -d --name sgwu \
#     --privileged \
#     --cap-add=NET_ADMIN \
#     -v /path/to/sgwu.yaml:/etc/nextgcore/sgwu.yaml:ro \
#     -p 2152:2152/udp \
#     -p 8805:8805/udp \
#     nextgcore-sgwu:latest

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
# Stage 3: Builder - Build SGW-U binary
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
RUN cargo build --release -p nextgcore-sgwud
RUN strip --strip-all target/release/nextgcore-sgwud

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore SGW-U (Rust)"
LABEL org.opencontainers.image.description="Serving Gateway User Plane for 4G/LTE EPC"
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

COPY --from=builder /app/target/release/nextgcore-sgwud /usr/local/bin/nextgcore-sgwud
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-sgwud

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

# Note: SGW-U requires NET_ADMIN capability for GTP-U handling
# Run as root or with appropriate capabilities
# USER nextgcore

# GTP-U (UDP) - S1-U interface to eNB, S5/S8 to PGW-U
# PFCP (UDP) - Sxa interface to SGW-C
EXPOSE 2152/udp 8805/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x nextgcore-sgwud || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-sgwud"]
CMD ["-c", "/etc/nextgcore/sgwu.yaml"]
