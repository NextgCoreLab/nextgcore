# NextGCore HSS (Home Subscriber Server) - Rust Implementation
#
# The HSS handles (4G/LTE EPC):
# - Subscriber authentication data (Milenage algorithm)
# - Subscriber profile management
# - Diameter S6a interface with MME
# - Diameter Cx/Swx interfaces for IMS
#
# Build:
#   docker build -f docker/rust/nextgcore-hssd/Dockerfile -t nextgcore-hss:latest .
#
# Run:
#   docker run -d --name hss \
#     -v /path/to/hss.yaml:/etc/nextgcore/hss.yaml:ro \
#     -v /path/to/freeDiameter:/etc/freeDiameter:ro \
#     -p 3868:3868 \
#     nextgcore-hss:latest

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
# Stage 3: Builder - Build HSS binary
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
RUN cargo build --release -p nextgcore-hssd
RUN strip --strip-all target/release/nextgcore-hssd

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore HSS (Rust)"
LABEL org.opencontainers.image.description="Home Subscriber Server for 4G/LTE EPC"
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

COPY --from=builder /app/target/release/nextgcore-hssd /usr/local/bin/nextgcore-hssd
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-hssd

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# Diameter S6a port (TCP and SCTP)
EXPOSE 3868 3868/sctp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x nextgcore-hssd || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-hssd"]
CMD ["-c", "/etc/nextgcore/hss.yaml"]
