# NextGCore UDM (Unified Data Management) - Rust Implementation
#
# The UDM handles:
# - Subscriber data management
# - Authentication credential processing
# - Subscription data provisioning
# - SBI communication with AUSF, AMF, SMF
# - UDR interface for data storage
#
# Build:
#   docker build -f docker/rust/nextgcore-udmd/Dockerfile -t nextgcore-udm:latest .
#
# Run:
#   docker run -d --name udm \
#     -v /path/to/udm.yaml:/etc/nextgcore/udm.yaml:ro \
#     -p 7783:7783 \
#     nextgcore-udm:latest

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
# Stage 3: Builder - Build UDM binary
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
RUN cargo build --release -p nextgcore-udmd
RUN strip --strip-all target/release/nextgcore-udmd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore UDM (Rust)"
LABEL org.opencontainers.image.description="Unified Data Management for 5G Core"
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

COPY --from=builder /app/target/release/nextgcore-udmd /usr/local/bin/nextgcore-udmd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-udmd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# SBI port
EXPOSE 7783

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:7783/nnrf-nfm/v1/nf-instances || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-udmd"]
CMD ["-c", "/etc/nextgcore/udm.yaml"]
