# NextGCore Builder Image
# Builds all network functions in a single container
#
# Usage:
#   cd /path/to/nextg  # Parent directory containing nextgcore and nextgsim
#   docker build -f nextgcore/docker/rust/Dockerfile.builder -t nextgcore-builder .
#   docker create --name builder nextgcore-builder
#   docker cp builder:/app/binaries/. ./nextgcore/docker/rust/binaries/
#   docker rm builder

FROM rust:1.85-bookworm AS builder

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
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Install rustfmt for ASN.1 code generation
RUN rustup component add rustfmt

WORKDIR /app

# Copy both nextgcore and nextgsim source code
COPY nextgcore/src/ ./nextgcore/src/
COPY nextgsim/ ./nextgsim/

WORKDIR /app/nextgcore/src

# Build nextgcore binaries in release mode
RUN cargo build --release

# Build nextgsim binaries
WORKDIR /app/nextgsim
RUN cargo build --release --bin nr-gnb --bin nr-ue

# Strip binaries and copy to output directory
RUN mkdir -p /app/binaries && \
    for bin in /app/nextgcore/src/target/release/nextgcore-*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && ! [[ "$bin" == *.d ]]; then \
            strip --strip-all "$bin" && cp "$bin" /app/binaries/; \
        fi; \
    done && \
    strip --strip-all /app/nextgsim/target/release/nr-gnb && \
    strip --strip-all /app/nextgsim/target/release/nr-ue && \
    cp /app/nextgsim/target/release/nr-gnb /app/binaries/ && \
    cp /app/nextgsim/target/release/nr-ue /app/binaries/

# List built binaries
RUN ls -la /app/binaries/
