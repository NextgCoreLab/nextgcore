# NextGCore SGW-C (Serving Gateway - Control Plane) - Rust Implementation
#
# The SGW-C handles (4G/LTE EPC):
# - GTP-C signaling for bearer management
# - S11 interface with MME
# - S5/S8 interface with PGW-C/SMF
# - Sxa PFCP interface with SGW-U
# - Bearer context management
#
# Build:
#   docker build -f docker/rust/nextgcore-sgwcd/Dockerfile -t nextgcore-sgwc:latest .
#
# Run:
#   docker run -d --name sgwc \
#     -v /path/to/sgwc.yaml:/etc/nextgcore/sgwc.yaml:ro \
#     -p 2123:2123/udp \
#     -p 8805:8805/udp \
#     nextgcore-sgwc:latest

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
# Stage 3: Builder - Build SGW-C binary
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
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY rust_src/ ./
RUN cargo build --release -p nextgcore-sgwcd
RUN strip --strip-all target/release/nextgcore-sgwcd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore SGW-C (Rust)"
LABEL org.opencontainers.image.description="Serving Gateway Control Plane for 4G/LTE EPC"
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
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nextgcore && useradd -r -g nextgcore -s /bin/false nextgcore

RUN mkdir -p /etc/nextgcore /var/log/nextgcore /var/run/nextgcore && \
    chown -R nextgcore:nextgcore /etc/nextgcore /var/log/nextgcore /var/run/nextgcore

COPY --from=builder /app/target/release/nextgcore-sgwcd /usr/local/bin/nextgcore-sgwcd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-sgwcd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# GTP-C (UDP) - S11 interface to MME, S5/S8 to PGW-C
# PFCP (UDP) - Sxa interface to SGW-U
EXPOSE 2123/udp 8805/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x nextgcore-sgwcd || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-sgwcd"]
CMD ["-c", "/etc/nextgcore/sgwc.yaml"]
