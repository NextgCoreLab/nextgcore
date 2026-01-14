#!/bin/bash
# Build all NF runtime images from pre-built binaries
set -e

cd "$(dirname "$0")"

echo "Building NF runtime images..."

docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-nrfd -t nextgcore-rust/nrf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-ausfd -t nextgcore-rust/ausf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-udmd -t nextgcore-rust/udm:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-udrd -t nextgcore-rust/udr:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-pcfd -t nextgcore-rust/pcf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-nssfd -t nextgcore-rust/nssf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-bsfd -t nextgcore-rust/bsf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-amfd -t nextgcore-rust/amf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-smfd -t nextgcore-rust/smf:latest .
docker build -f Dockerfile.runtime-local --build-arg NF_NAME=nextgcore-upfd -t nextgcore-rust/upf:latest .

echo "=== All images built ==="
docker images | grep nextgcore-rust
