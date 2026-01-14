# NextGCore SMF (Session Management Function) - Rust Implementation
#
# The SMF handles:
# - PDU session establishment, modification, release
# - UE IP address allocation
# - N4 PFCP interface with UPF
# - Policy enforcement coordination with PCF
# - SBI communication with AMF, PCF, UDM, CHF
# - GTP-C S5/S8 interface (for 4G interworking)
#
# Build:
#   docker build -f docker/rust/nextgcore-smfd/Dockerfile -t nextgcore-smf:latest .
#
# Run:
#   docker run -d --name smf \
#     -v /path/to/smf.yaml:/etc/nextgcore/smf.yaml:ro \
#     -p 7782:7782 \
#     -p 8805:8805/udp \
#     -p 2123:2123/udp \
#     nextgcore-smf:latest

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
# Stage 3: Builder - Build SMF binary
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
RUN cargo build --release -p nextgcore-smfd
RUN strip --strip-all target/release/nextgcore-smfd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore SMF (Rust)"
LABEL org.opencontainers.image.description="Session Management Function for 5G Core"
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

COPY --from=builder /app/target/release/nextgcore-smfd /usr/local/bin/nextgcore-smfd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-smfd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# SBI port
# PFCP (UDP) - N4 interface to UPF
# GTP-C (UDP) - S5/S8 interface for 4G interworking
EXPOSE 7782 8805/udp 2123/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:7782/nnrf-nfm/v1/nf-instances || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-smfd"]
CMD ["-c", "/etc/nextgcore/smf.yaml"]
