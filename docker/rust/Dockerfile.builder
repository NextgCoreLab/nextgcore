# NextGCore + NextGSim Rust Builder (multi-stage)
# Builds all binaries inside Docker, outputs only the binaries.
#
# Build:
#   docker build -f Dockerfile.builder -t nextg-builder .
#   docker create --name builder nextg-builder /bin/true
#   docker cp builder:/out/. binaries/
#   docker rm builder

FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake g++ protobuf-compiler \
    libstdc++-12-dev libclang-dev clang \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt

WORKDIR /build

# Copy both workspaces
COPY nextgcore/src /build/nextgcore/src
COPY nextgsim /build/nextgsim

# Build nextgcore (workspace root is nextgcore/src/)
WORKDIR /build/nextgcore/src
RUN cargo build --release 2>&1 && \
    mkdir -p /out && \
    for bin in target/release/nextgcore-*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && [ "${bin%.d}" = "$bin" ]; then \
            cp "$bin" /out/; \
        fi; \
    done

# Build nextgsim gNB and UE
WORKDIR /build/nextgsim
RUN cargo build --release --bin nr-gnb --bin nr-ue 2>&1 || true
RUN cp target/release/nr-gnb /out/ 2>/dev/null || true && \
    cp target/release/nr-ue /out/ 2>/dev/null || true

# Final stage: tiny image with only binaries
FROM debian:bookworm-slim
COPY --from=builder /out/ /out/
CMD ["/bin/true"]
