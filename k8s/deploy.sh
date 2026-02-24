#!/usr/bin/env bash
# NextG 5G/6G Kubernetes Deployment Script
# Deploys nextgcore (5G Core) and nextgsim (UE/gNB) on a Kind cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="nextg"
NAMESPACE="nextg-system"
NEXTGSIM_K8S="${SCRIPT_DIR}/../../nextgsim/k8s"

echo "============================================"
echo "  NextG 5G/6G Kubernetes Deployment"
echo "============================================"

# --- Prerequisites check ---
for cmd in kind kubectl docker; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is required but not installed."
    exit 1
  fi
done

# --- Step 1: Create Kind cluster ---
echo ""
echo "[1/9] Creating Kind cluster: ${CLUSTER_NAME}"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "  Cluster '${CLUSTER_NAME}' already exists, skipping creation."
else
  kind create cluster --config "${SCRIPT_DIR}/kind-config.yaml" --name "${CLUSTER_NAME}"
  echo "  Cluster created."
fi
kubectl cluster-info --context "kind-${CLUSTER_NAME}"

# --- Step 2: Load Docker images into Kind ---
echo ""
echo "[2/9] Loading Docker images into Kind cluster"

# Infrastructure images
INFRA_IMAGES=("mongo:6.0" "busybox:1.36" "prom/prometheus:v2.51.0" "grafana/grafana:10.4.0" "jaegertracing/all-in-one:1.55")
for img in "${INFRA_IMAGES[@]}"; do
  if ! docker image inspect "$img" &>/dev/null; then
    echo "  Pulling $img..."
    docker pull "$img"
  fi
  echo "  Loading $img..."
  kind load docker-image "$img" --name "${CLUSTER_NAME}" 2>/dev/null || true
done

# Core NF images
CORE_IMAGES=(nrf ausf udm udr pcf nssf bsf amf smf upf)
for nf in "${CORE_IMAGES[@]}"; do
  img="nextgcore-rust/${nf}:latest"
  if docker image inspect "$img" &>/dev/null; then
    echo "  Loading $img..."
    kind load docker-image "$img" --name "${CLUSTER_NAME}" 2>/dev/null || true
  else
    echo "  WARNING: Image $img not found locally. Build it first."
  fi
done

# Simulator images
SIM_IMAGES=("nextgsim-gnb:latest" "nextgsim-ue:latest")
for img in "${SIM_IMAGES[@]}"; do
  if docker image inspect "$img" &>/dev/null; then
    echo "  Loading $img..."
    kind load docker-image "$img" --name "${CLUSTER_NAME}" 2>/dev/null || true
  else
    echo "  WARNING: Image $img not found locally. Build it first."
  fi
done

# --- Step 3: Create namespace ---
echo ""
echo "[3/9] Creating namespace: ${NAMESPACE}"
kubectl apply -f "${SCRIPT_DIR}/base/namespace.yaml"

# --- Step 4: Deploy nextgcore ConfigMap ---
echo ""
echo "[4/9] Deploying nextgcore configuration"
kubectl apply -f "${SCRIPT_DIR}/manifests/configmap.yaml"

# --- Step 5: Deploy nextgcore NFs in dependency order ---
echo ""
echo "[5/9] Deploying nextgcore 5G Core Network Functions"

echo "  Deploying MongoDB..."
kubectl apply -f "${SCRIPT_DIR}/manifests/mongodb.yaml"
kubectl rollout status statefulset/mongodb -n "${NAMESPACE}" --timeout=120s

# --- Step 6: Initialize MongoDB ---
echo ""
echo "[6/9] Initializing MongoDB (subscribers + indexes)"
kubectl apply -f "${SCRIPT_DIR}/manifests/mongodb-init.yaml"
echo "  Waiting for MongoDB init job to complete..."
kubectl wait --for=condition=complete job/mongodb-init -n "${NAMESPACE}" --timeout=120s
echo "  MongoDB initialized."

# --- Step 7: Deploy Core NFs ---
echo ""
echo "[7/9] Deploying Core Network Functions"

echo "  Deploying NRF..."
kubectl apply -f "${SCRIPT_DIR}/manifests/nrf.yaml"
kubectl rollout status deployment/nrf -n "${NAMESPACE}" --timeout=120s

echo "  Deploying AUSF, UDM, UDR, PCF, NSSF, BSF..."
kubectl apply -f "${SCRIPT_DIR}/manifests/ausf.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/udm.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/udr.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/pcf.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/nssf.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/bsf.yaml"

echo "  Waiting for control plane NFs..."
for nf in ausf udm udr pcf nssf bsf; do
  kubectl rollout status deployment/${nf} -n "${NAMESPACE}" --timeout=120s
done

echo "  Deploying AMF..."
kubectl apply -f "${SCRIPT_DIR}/manifests/amf.yaml"
kubectl rollout status deployment/amf -n "${NAMESPACE}" --timeout=120s

echo "  Deploying SMF..."
kubectl apply -f "${SCRIPT_DIR}/manifests/smf.yaml"
kubectl rollout status deployment/smf -n "${NAMESPACE}" --timeout=120s

echo "  Deploying UPF..."
kubectl apply -f "${SCRIPT_DIR}/manifests/upf.yaml"
kubectl rollout status deployment/upf -n "${NAMESPACE}" --timeout=120s

# --- Step 8: Deploy monitoring stack ---
echo ""
echo "[8/9] Deploying Monitoring Stack (Prometheus, Grafana, Jaeger)"
kubectl apply -f "${SCRIPT_DIR}/monitoring/prometheus.yaml"
kubectl apply -f "${SCRIPT_DIR}/monitoring/grafana.yaml"
kubectl apply -f "${SCRIPT_DIR}/monitoring/jaeger.yaml"

echo "  Waiting for monitoring pods..."
for dep in prometheus grafana jaeger; do
  kubectl rollout status deployment/${dep} -n "${NAMESPACE}" --timeout=120s
done

# --- Step 9: Deploy nextgsim ---
echo ""
echo "[9/9] Deploying nextgsim Simulator (gNB + UE)"
kubectl apply -f "${NEXTGSIM_K8S}/configmap.yaml"

echo "  Deploying gNB..."
kubectl apply -f "${NEXTGSIM_K8S}/gnb.yaml"
kubectl rollout status deployment/gnb -n "${NAMESPACE}" --timeout=120s

echo "  Deploying UE..."
kubectl apply -f "${NEXTGSIM_K8S}/ue.yaml"
kubectl rollout status deployment/ue -n "${NAMESPACE}" --timeout=120s

# --- Final Status ---
echo ""
echo "============================================"
echo "  Deployment Status"
echo "============================================"
kubectl get pods -n "${NAMESPACE}" -o wide
echo ""
kubectl get services -n "${NAMESPACE}"
echo ""
echo "============================================"
echo "  Deployment Complete!"
echo "============================================"
echo ""
echo "Useful commands:"
echo "  kubectl get pods -n ${NAMESPACE}                    # List all pods"
echo "  kubectl logs -f deployment/amf -n ${NAMESPACE}      # AMF logs"
echo "  kubectl logs -f deployment/gnb -n ${NAMESPACE}      # gNB logs"
echo "  kubectl logs -f deployment/ue -n ${NAMESPACE}       # UE logs"
echo "  kubectl exec deployment/ue -n ${NAMESPACE} -- ping -c 3 10.45.0.1  # Test data plane"
echo ""
echo "Monitoring:"
echo "  Grafana:    http://localhost:3000   (admin/nextgcore)"
echo "  Prometheus: http://localhost:9090"
echo "  Jaeger:     http://localhost:16686"
echo ""
