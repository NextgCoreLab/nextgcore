# NextGCore MME (Mobility Management Entity) - Rust Implementation
#
# The MME handles (4G/LTE EPC):
# - UE attach/detach procedures
# - EMM (EPS Mobility Management) state machine
# - ESM (EPS Session Management) state machine
# - S1AP signaling with eNB (4G base stations)
# - S11 GTP-C interface with SGW-C
# - S6a Diameter interface with HSS
# - SGsAP interface with MSC/VLR (CSFB)
#
# Build:
#   docker build -f docker/rust/nextgcore-mmed/Dockerfile -t nextgcore-mme:latest .
#
# Run:
#   docker run -d --name mme \
#     -v /path/to/mme.yaml:/etc/nextgcore/mme.yaml:ro \
#     -v /path/to/freeDiameter:/etc/freeDiameter:ro \
#     -p 36412:36412/sctp \
#     -p 3868:3868 \
#     nextgcore-mme:latest

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
# Stage 3: Builder - Build MME binary
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
RUN cargo build --release -p nextgcore-mmed
RUN strip --strip-all target/release/nextgcore-mmed

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:${DEBIAN_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="NextGCore MME (Rust)"
LABEL org.opencontainers.image.description="Mobility Management Entity for 4G/LTE EPC"
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

COPY --from=builder /app/target/release/nextgcore-mmed /usr/local/bin/nextgcore-mmed
RUN chown nextgcore:nextgcore /usr/local/bin/nextgcore-mmed

ENV OGS_LOG_LEVEL=info
ENV OGS_LOG_PATH=/var/log/nextgcore

USER nextgcore

# S1AP (SCTP) - S1 interface to eNB
# Diameter S6a (TCP/SCTP) - interface to HSS
# GTP-C (UDP) - S11 interface to SGW-C
EXPOSE 36412/sctp 3868 3868/sctp 2123/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x nextgcore-mmed || exit 1

ENTRYPOINT ["/usr/local/bin/nextgcore-mmed"]
CMD ["-c", "/etc/nextgcore/mme.yaml"]
