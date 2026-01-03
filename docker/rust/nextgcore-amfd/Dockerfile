# NextGCore AMF (Access and Mobility Management Function) - Rust Implementation
# 
# The AMF handles:
# - UE registration and authentication coordination
# - Mobility management (handover, paging)
# - NGAP signaling with gNB (5G base stations)
# - SBI communication with other 5G core NFs
#
# Build:
#   docker build -f docker/rust/nextgcore-amfd/Dockerfile -t nextgcore-amf:latest .
#
# Run:
#   docker run -d --name amf \
#     -v /path/to/amf.yaml:/etc/nextgcore/amf.yaml:ro \
#     -p 38412:38412/sctp \
#     -p 7777:7777 \
#     nextgcore-amf:latest

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
# Stage 3: Builder - Build AMF binary
# =============================================================================
FROM chef AS builder

# Install build dependencies
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

# Build dependencies first (cached)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and build AMF
COPY rust_src/ ./
RUN cargo build --release -p nextgcore-amfd

# Strip debug symbols
RUN strip --strip-all target/release/nextgcore-amfd

# =============================================================================
# Stage 4: Runtime - Minimal runtime image
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore AMF (Rust)"
LABEL org.opencontainers.image.description="Access and Mobility Management Function for 5G Core"
LABEL org.opencontainers.image.source="https://github.com/nextgcore/nextgcore"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libsctp1 \
    libyaml-0-2 \
    libmongoc-1.0-0 \
    libbson-1.0-0 \
    libnghttp2-14 \
    libtins4.0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r nextgcore && useradd -r -g nextgcore -s /bin/false nextgcore

# Create directories
RUN mkdir -p /etc/nextgcore /var/log/nextgcore /var/run/nextgcore && \
    chown -R nextgcore:nextgcore /etc/nextgcore /var/log/nextgcore /var/run/nextgcore

# Copy binary from builder
COPY --from=builder /app/target/release/nextgcore-amfd /usr/local/bin/nextgcore-amfd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-amfd

# Environment variables
ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

# Switch to non-root user
USER nextgcore

# Expose ports
# 7777: SBI (HTTP/2)
# 38412: NGAP (SCTP) - N2 interface to gNB
EXPOSE 7777 38412/sctp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:7777/nnrf-nfm/v1/nf-instances || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-amfd"]
CMD ["-c", "/etc/nextgcore/amf.yaml"]
