# NextGCore PCRF (Policy and Charging Rules Function) - Rust Implementation
#
# The PCRF handles (4G/LTE EPC):
# - Policy and charging control rules
# - Diameter Gx interface with PGW/SMF
# - Diameter Rx interface with AF (Application Function)
# - QoS policy decisions for EPC
#
# Build:
#   docker build -f docker/rust/nextgcore-pcrfd/Dockerfile -t nextgcore-pcrf:latest .
#
# Run:
#   docker run -d --name pcrf \
#     -v /path/to/pcrf.yaml:/etc/nextgcore/pcrf.yaml:ro \
#     -v /path/to/freeDiameter:/etc/freeDiameter:ro \
#     -p 3868:3868 \
#     nextgcore-pcrf:latest

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
# Stage 3: Builder - Build PCRF binary
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
RUN cargo build --release -p nextgcore-pcrfd
RUN strip --strip-all target/release/nextgcore-pcrfd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore PCRF (Rust)"
LABEL org.opencontainers.image.description="Policy and Charging Rules Function for 4G/LTE EPC"
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

RUN mkdir -p /etc/nextgcore /etc/freeDiameter /var/log/nextgcore /var/run/nextgcore && \
    chown -R nextgcore:nextgcore /etc/nextgcore /etc/freeDiameter /var/log/nextgcore /var/run/nextgcore

COPY --from=builder /app/target/release/nextgcore-pcrfd /usr/local/bin/nextgcore-pcrfd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-pcrfd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# Diameter Gx/Rx port (TCP and SCTP)
EXPOSE 3868 3868/sctp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x nextgcore-pcrfd || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-pcrfd"]
CMD ["-c", "/etc/nextgcore/pcrf.yaml"]
