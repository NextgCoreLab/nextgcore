# NextGCore + NextGSim Rust Builder (multi-stage, multi-arch)
# Builds all binaries inside Docker, outputs only the binaries.
# Supports cross-compilation for linux/amd64 and linux/arm64.
#
# Build (single platform):
#   docker build -f Dockerfile.builder -t nextg-builder .
#   docker create --name builder nextg-builder /bin/true
#   docker cp builder:/out/. binaries/
#   docker rm builder
#
# Build (multi-platform with buildx):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f Dockerfile.builder -t nextg-builder .

# Use buildplatform for faster cross-compilation
FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake g++ protobuf-compiler \
    libstdc++-12-dev libclang-dev clang \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt

# Add cross-compilation support for ARM64
RUN if [ "$TARGETARCH" = "arm64" ] && [ "$(uname -m)" != "aarch64" ]; then \
        rustup target add aarch64-unknown-linux-gnu && \
        apt-get update && apt-get install -y --no-install-recommends \
            gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
            libc6-dev-arm64-cross && \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Add cross-compilation support for AMD64
RUN if [ "$TARGETARCH" = "amd64" ] && [ "$(uname -m)" != "x86_64" ]; then \
        rustup target add x86_64-unknown-linux-gnu && \
        apt-get update && apt-get install -y --no-install-recommends \
            gcc-x86-64-linux-gnu g++-x86-64-linux-gnu && \
        rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /build

# Copy both workspaces
COPY nextgcore/src /build/nextgcore/src
COPY nextgsim /build/nextgsim

# Set cross-compilation environment variables
ENV PKG_CONFIG_ALLOW_CROSS=1

# Configure cargo for cross-compilation
RUN mkdir -p ~/.cargo && \
    if [ "$TARGETARCH" = "arm64" ]; then \
        echo '[target.aarch64-unknown-linux-gnu]' >> ~/.cargo/config.toml && \
        echo 'linker = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config.toml && \
        echo '[env]' >> ~/.cargo/config.toml && \
        echo 'CC_aarch64_unknown_linux_gnu = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config.toml && \
        echo 'CXX_aarch64_unknown_linux_gnu = "aarch64-linux-gnu-g++"' >> ~/.cargo/config.toml; \
    fi

# Determine cargo target based on architecture
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        echo "aarch64-unknown-linux-gnu" > /tmp/cargo_target; \
    elif [ "$TARGETARCH" = "amd64" ]; then \
        echo "x86_64-unknown-linux-gnu" > /tmp/cargo_target; \
    else \
        uname -m | sed 's/x86_64/x86_64-unknown-linux-gnu/' | sed 's/aarch64/aarch64-unknown-linux-gnu/' > /tmp/cargo_target; \
    fi

# Build nextgcore (workspace root is nextgcore/src/)
WORKDIR /build/nextgcore/src
RUN CARGO_TARGET=$(cat /tmp/cargo_target) && \
    if [ "$(uname -m)" != "$(echo $CARGO_TARGET | cut -d- -f1)" ]; then \
        cargo build --release --target "$CARGO_TARGET" 2>&1; \
    else \
        cargo build --release 2>&1; \
    fi && \
    mkdir -p /out && \
    for bin in target/*/release/nextgcore-* target/release/nextgcore-*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && [ "${bin%.d}" = "$bin" ]; then \
            cp "$bin" /out/ 2>/dev/null || true; \
        fi; \
    done

# Build nextgsim gNB and UE
WORKDIR /build/nextgsim
RUN CARGO_TARGET=$(cat /tmp/cargo_target) && \
    if [ "$(uname -m)" != "$(echo $CARGO_TARGET | cut -d- -f1)" ]; then \
        cargo build --release --target "$CARGO_TARGET" --bin nr-gnb --bin nr-ue 2>&1 || true; \
    else \
        cargo build --release --bin nr-gnb --bin nr-ue 2>&1 || true; \
    fi && \
    cp target/*/release/nr-gnb /out/ 2>/dev/null || true && \
    cp target/*/release/nr-ue /out/ 2>/dev/null || true && \
    cp target/release/nr-gnb /out/ 2>/dev/null || true && \
    cp target/release/nr-ue /out/ 2>/dev/null || true

# Final stage: tiny image with only binaries
FROM debian:bookworm-slim
COPY --from=builder /out/ /out/
CMD ["/bin/true"]
