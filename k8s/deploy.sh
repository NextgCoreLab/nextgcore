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

# udm.yaml mounts the Secret udm-hnet-keys at /etc/nextgcore/hnet, which is
# where configmap.yaml points the UDM for SUCI de-concealment. The mount is
# `optional: true`, so without this the UDM starts with NO key material and
# silently cannot de-conceal a SUCI -- deploy-eks.sh creates the Secret but
# this path never did.
HNET_DIR="${SCRIPT_DIR}/../docker/rust/configs/5gc/hnet"
if [ -f "${HNET_DIR}/curve25519-1.key" ] && [ -f "${HNET_DIR}/secp256r1-2.key" ]; then
  echo "  Creating udm-hnet-keys Secret (repo DEVELOPMENT keys - replace for real use)"
  kubectl create secret generic udm-hnet-keys \
    --namespace "${NAMESPACE}" \
    --from-file="curve25519-1.key=${HNET_DIR}/curve25519-1.key" \
    --from-file="secp256r1-2.key=${HNET_DIR}/secp256r1-2.key" \
    --dry-run=client -o yaml | kubectl apply -f -
else
  echo "ERROR: hnet keys not found under ${HNET_DIR}." >&2
  echo "       The UDM cannot de-conceal a SUCI without them." >&2
  exit 1
fi

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

# The UPF is applied BEFORE waiting on the SMF: the SMF's resolve-upf
# initContainer blocks until upf.<ns>.svc.cluster.local resolves, so waiting
# for the SMF first deadlocks -- the SMF can never become ready and the UPF is
# never applied. Only the UPF *Service* has to exist for DNS to resolve, not a
# ready UPF pod, so applying both and then waiting is enough.
echo "  Deploying SMF and UPF..."
kubectl apply -f "${SCRIPT_DIR}/manifests/smf.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/upf.yaml"

kubectl rollout status deployment/smf -n "${NAMESPACE}" --timeout=120s
kubectl rollout status deployment/upf -n "${NAMESPACE}" --timeout=120s

# --- Step 8: Deploy monitoring stack ---
echo ""
echo "[8/9] Deploying Monitoring Stack (Prometheus, Grafana, Jaeger)"
kubectl apply -f "${SCRIPT_DIR}/monitoring/prometheus.yaml"
# Grafana's admin password lives in a Secret, never in a manifest (#837). Create
# it with a generated value the first time; an existing one is kept.
if ! kubectl get secret grafana-admin -n "${NAMESPACE}" >/dev/null 2>&1; then
  # Piped, never in argv: an argv value shows in `ps` and under `bash -x`.
  openssl rand -base64 24 | tr -d '\n' \
    | kubectl create secret generic grafana-admin -n "${NAMESPACE}" \
        --from-file=password=/dev/stdin >/dev/null
  echo "  Created Secret grafana-admin with a generated Grafana admin password"
fi
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
# Every Service is ClusterIP (#1365): nothing is published on a node or host
# port. kubectl port-forward listens on 127.0.0.1 only.
echo "Monitoring and NRF (port-forward, then open the URL; 127.0.0.1 only):"
echo "  Grafana:    kubectl -n ${NAMESPACE} port-forward svc/grafana 3000:3000       -> http://localhost:3000"
echo "              (user admin; password: kubectl -n ${NAMESPACE} get secret grafana-admin -o jsonpath='{.data.password}' | base64 -d)"
echo "  Prometheus: kubectl -n ${NAMESPACE} port-forward svc/prometheus 9090:9090    -> http://localhost:9090"
echo "  Jaeger:     kubectl -n ${NAMESPACE} port-forward svc/jaeger 16686:16686      -> http://localhost:16686"
echo "  NRF SBI:    kubectl -n ${NAMESPACE} port-forward svc/nrf 7777:7777           -> http://localhost:7777"
echo ""
