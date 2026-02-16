#!/usr/bin/env bash
# NextG Kubernetes Teardown Script
# Deletes the Kind cluster and all resources
set -euo pipefail

CLUSTER_NAME="nextg"

echo "============================================"
echo "  NextG Kubernetes Teardown"
echo "============================================"

if ! command -v kind &>/dev/null; then
  echo "ERROR: kind is required but not installed."
  exit 1
fi

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Deleting Kind cluster: ${CLUSTER_NAME}"
  kind delete cluster --name "${CLUSTER_NAME}"
  echo "Cluster deleted."
else
  echo "Cluster '${CLUSTER_NAME}' does not exist."
fi

echo "Teardown complete."
