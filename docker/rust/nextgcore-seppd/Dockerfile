# NextGCore SEPP (Security Edge Protection Proxy) - Rust Implementation
#
# The SEPP handles:
# - Inter-PLMN security for roaming
# - N32 interface (N32c for control, N32f for forwarding)
# - TLS/PRINS security capability negotiation
# - Message filtering and protection between PLMNs
#
# Build:
#   docker build -f docker/rust/nextgcore-seppd/Dockerfile -t nextgcore-sepp:latest .
#
# Run:
#   docker run -d --name sepp \
#     -v /path/to/sepp.yaml:/etc/nextgcore/sepp.yaml:ro \
#     -p 7777:7777 \
#     nextgcore-sepp:latest

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
# Stage 3: Builder - Build SEPP binary
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
RUN cargo build --release -p nextgcore-seppd
RUN strip --strip-all target/release/nextgcore-seppd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore SEPP (Rust)"
LABEL org.opencontainers.image.description="Security Edge Protection Proxy for 5G Core Roaming"
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

COPY --from=builder /app/target/release/nextgcore-seppd /usr/local/bin/nextgcore-seppd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-seppd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# SBI port - N32 interface
EXPOSE 7777

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:7777/nnrf-nfm/v1/nf-instances || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-seppd"]
CMD ["-c", "/etc/nextgcore/sepp.yaml"]
