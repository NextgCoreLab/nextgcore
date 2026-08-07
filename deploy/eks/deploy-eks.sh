#!/usr/bin/env bash
# Apply the NextG workload to an existing EKS cluster.
#
# The EKS counterpart of nextgcore/k8s/deploy.sh, minus everything Kind-specific
# (no `kind create cluster`, no `kind load docker-image`), plus the things EKS
# needs that Kind did not: an image registry, the UDM hnet Secret, a bound
# StorageClass, and a namespace Pod Security label.
#
# Usage:
#   ./deploy-eks.sh                              # control plane only (default)
#   ENABLE_DATAPLANE=true ./deploy-eks.sh        # privileged UPF w/ real TUN
#   DRY_RUN=true ./deploy-eks.sh                 # render + validate, apply nothing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NAMESPACE="nextg-system"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
ENABLE_DATAPLANE="${ENABLE_DATAPLANE:-false}"
DRY_RUN="${DRY_RUN:-false}"
# Swap MongoDB's gp3 PVC for an emptyDir. Needed on clusters without the EBS
# CSI driver, where the PVC would stay Pending and stall every NF behind its
# wait-for-mongodb initContainer. Data does not survive a pod restart; the
# mongodb-init Job re-seeds subscribers each deploy, so for an E2E run the DB
# is derived state. See patches/mongodb-ephemeral.yaml.
EPHEMERAL_STORAGE="${EPHEMERAL_STORAGE:-false}"

log()  { printf '\033[0;32m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn  ]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[fail  ]\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------

command -v kubectl >/dev/null || die "kubectl not found"

if [[ "${DRY_RUN}" != "true" ]]; then
  command -v aws >/dev/null || die "aws not found"
  ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
    || die "AWS credentials invalid or expired. Refresh them and retry."
  REGISTRY="${REGISTRY:-${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com}"

  CTX="$(kubectl config current-context 2>/dev/null || true)"
  [[ -n "${CTX}" ]] || die "no kubectl context set. Run: aws eks update-kubeconfig ..."

  # Deploying to the wrong cluster is the expensive mistake here, so make the
  # target explicit and require confirmation.
  cat <<EOF

  target cluster : ${CTX}
  namespace      : ${NAMESPACE}
  registry       : ${REGISTRY}/${REPO_PREFIX}
  tag            : ${IMAGE_TAG}
  data plane     : ${ENABLE_DATAPLANE}
  mongo storage  : $([[ "${EPHEMERAL_STORAGE}" == "true" ]] && echo "emptyDir (EPHEMERAL - data lost on restart)" || echo "gp3 PVC")

EOF
  read -r -p "Apply to this cluster? [y/N] " reply
  [[ "${reply}" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }

  kubectl cluster-info >/dev/null 2>&1 \
    || die "cannot reach the cluster API. Check credentials and endpoint access."
else
  REGISTRY="${REGISTRY:-000000000000.dkr.ecr.${REGION}.amazonaws.com}"
  log "DRY_RUN: rendering only, nothing will be applied."
fi

# --- render ----------------------------------------------------------------

RENDERED="$(mktemp -t nextg-eks-XXXXXX.yaml)"
trap 'rm -f "${RENDERED}" "${RENDERED}.tmp"' EXIT

log "rendering kustomize overlay..."
kubectl kustomize "${SCRIPT_DIR}" > "${RENDERED}" || die "kustomize render failed"

# Make each NF advertise its POD IP to the NRF instead of its bind address.
#
# k8s/manifests/configmap.yaml sets every NF's sbi.server[0].address to
# 0.0.0.0, and that one value is used for BOTH the listen socket and the
# NFProfile registered with the NRF (nextgcore-ausfd/src/app.rs:266 overrides
# args.sbi_addr from config; app.rs:1626 puts it into "ipv4Addresses"). Its own
# comment says that field exists so the profile advertises "a reachable endpoint
# (not 0.0.0.0)" -- the k8s config supplies exactly that.
#
# Confirmed against the live NRF before this fix:
#   "ipv4Addresses": ["0.0.0.0"]
#   nausf-auth ipEndPoints: [{"ipv4Address": "0.0.0.0", "port": 7777}]
# So discovery handed 0.0.0.0 to consumers. The AMF dialled 0.0.0.0:7777 --
# itself -- and every registration failed with "AUSF returned status 404". The
# AMF's AUSF_SBI_ADDR env var is a correct Service DNS name but is only the
# fallback; discovery "succeeds" with a useless address and wins.
#
# The listen socket stays on 0.0.0.0 (correct inside a pod); only the ADVERTISED
# address becomes the pod IP. An initContainer rewrites the mounted ConfigMap
# into an emptyDir, since a ConfigMap mount is read-only and the pod IP is not
# known until scheduling.
#
# Done post-render rather than as 9 near-identical kustomize patches: each NF
# needs its own container name, config filename and volumeMount set preserved
# (the UDM additionally mounts hnet keys, which a blanket volumeMounts replace
# would drop).
#
# Kind is NOT unaffected, contrary to what this comment used to claim: on a
# single-node Kind cluster the AMF resolved its peers through discovery, dialled
# 0.0.0.0:7777 -- itself -- and got 404 from its own SBI router, so every
# registration failed. The base manifests now carry an equivalent
# rewrite-advertise-addr initContainer plus AMF_SBI_ADDR from status.podIP.
log "rewriting NF advertise addresses to the pod IP..."
python3 - "${RENDERED}" <<'PY' > "${RENDERED}.tmp" || die "advertise-address rewrite failed"
import sys, yaml

# The NRF is excluded: it is the registry itself, reached by URI from each NF's
# config, and registers no profile. The UPF is excluded: it joins the SBI plane
# only when --nrf-uri is set (off by default) and its wrapper.sh owns its
# startup.
NFS = {'amf', 'ausf', 'bsf', 'nssf', 'pcf', 'smf', 'udm', 'udr'}

SCRIPT = r'''set -eu
echo "[advertise] pod IP: $POD_IP"
case "$POD_IP" in
  *[0-9].[0-9]*) ;;
  *) echo "[advertise] FATAL: POD_IP is not an IPv4 address: '$POD_IP'" >&2; exit 1 ;;
esac
cp "/tmp/config-template/${NF_NAME}.yaml" "/etc/nextgcore-resolved/${NF_NAME}.yaml"
# Anchored to `- address:` so client URIs and other keys are untouched.
sed -i "s|^\( *- address:\) *0\.0\.0\.0 *$|\1 $POD_IP|" "/etc/nextgcore-resolved/${NF_NAME}.yaml"
if grep -qE '^ *- address: *0\.0\.0\.0 *$' "/etc/nextgcore-resolved/${NF_NAME}.yaml"; then
  echo "[advertise] FATAL: a 0.0.0.0 advertise address survived:" >&2
  grep -nE '^ *- address: *0\.0\.0\.0 *$' "/etc/nextgcore-resolved/${NF_NAME}.yaml" >&2
  exit 1
fi
echo "[advertise] ${NF_NAME}.yaml advertise address set to $POD_IP"
'''

out, patched = [], []
for d in yaml.safe_load_all(open(sys.argv[1])):
    if not d:
        continue
    if d.get('kind') == 'Deployment' and d['metadata']['name'] in NFS:
        nf = d['metadata']['name']
        pod = d['spec']['template']['spec']

        # The base manifests now carry this initContainer themselves. Applying
        # it twice yields duplicate initContainer and volume names, which the
        # API server rejects, so do not re-add it.
        #
        # But a kustomize patch that REPLACES a container's volumeMounts (the
        # UDM's hnet-keys patch does) drops the base manifest's redirect to
        # config-resolved, leaving the container reading the un-rewritten
        # template while the initContainer writes the rewritten copy nobody
        # reads -- so the UDM silently advertised 0.0.0.0 again. Re-assert the
        # redirect here rather than trusting the render.
        if any(c.get('name') == 'rewrite-advertise-addr'
               for c in pod.get('initContainers', [])):
            cont = next((c for c in pod['containers'] if c['name'] == nf), None)
            if cont is None:
                sys.exit(f'{nf}: container not found')
            cfg_mount = next(
                (m for m in cont.get('volumeMounts', [])
                 if m.get('subPath') == f'{nf}.yaml'), None)
            if cfg_mount is None:
                sys.exit(f'{nf}: no {nf}.yaml config mount to redirect')
            cfg_mount['name'] = 'config-resolved'
            if not any(v.get('name') == 'config-resolved'
                       for v in pod.get('volumes', [])):
                pod.setdefault('volumes', []).append(
                    {'name': 'config-resolved', 'emptyDir': {}})
            patched.append(nf)
            out.append(d)
            continue

        # Find the container's existing config mount so we can redirect just it.
        cont = next((c for c in pod['containers'] if c['name'] == nf), None)
        if cont is None:
            sys.exit(f'{nf}: container not found')
        cfg_mount = next(
            (m for m in cont.get('volumeMounts', [])
             if m.get('subPath') == f'{nf}.yaml'), None)
        if cfg_mount is None:
            sys.exit(f'{nf}: no {nf}.yaml config mount to redirect')

        pod.setdefault('volumes', []).append(
            {'name': 'config-resolved', 'emptyDir': {}})
        pod.setdefault('initContainers', []).append({
            'name': 'rewrite-advertise-addr',
            'image': 'busybox:1.36',
            'env': [
                {'name': 'POD_IP',
                 'valueFrom': {'fieldRef': {'fieldPath': 'status.podIP'}}},
                {'name': 'NF_NAME', 'value': nf},
            ],
            'command': ['sh', '-c', SCRIPT],
            'volumeMounts': [
                {'name': cfg_mount['name'], 'mountPath': '/tmp/config-template',
                 'readOnly': True},
                {'name': 'config-resolved', 'mountPath': '/etc/nextgcore-resolved'},
            ],
        })
        # Point the container at the rewritten file, leaving every other mount
        # (logs, and the UDM's hnet Secret) exactly as it was.
        cfg_mount['name'] = 'config-resolved'
        cfg_mount.pop('subPath', None)
        cfg_mount['mountPath'] = f'/etc/nextgcore/{nf}.yaml'
        cfg_mount['subPath'] = f'{nf}.yaml'
        patched.append(nf)
    out.append(d)

missing = NFS - set(patched)
if missing:
    sys.exit(f'advertise rewrite missed: {sorted(missing)}')
yaml.safe_dump_all(out, sys.stdout, default_flow_style=False)
print(f'  patched: {", ".join(sorted(patched))}', file=sys.stderr)
PY
mv "${RENDERED}.tmp" "${RENDERED}"

# Swap MongoDB's PVC for an emptyDir. Done post-render rather than in
# kustomization.yaml so the default (a real gp3 volume) stays correct and the
# opt-out is a single explicit env var, matching the UPF data-plane swap below.
if [[ "${EPHEMERAL_STORAGE}" == "true" ]]; then
  warn "EPHEMERAL_STORAGE: MongoDB will use an emptyDir. Data is LOST on pod restart."
  warn "use this only when the cluster has no EBS CSI driver (PVC would stay Pending)."
  python3 - "${RENDERED}" <<'PY' > "${RENDERED}.tmp" || die "mongodb storage swap failed"
import sys, yaml
out = []
swapped = False
for d in yaml.safe_load_all(open(sys.argv[1])):
    if not d:
        continue
    if d.get('kind') == 'StatefulSet' and d['metadata']['name'] == 'mongodb':
        spec = d['spec']
        # Drop the claim template entirely; an emptyDir needs no provisioner.
        spec.pop('volumeClaimTemplates', None)
        pod = spec['template']['spec']
        vols = [v for v in pod.get('volumes', []) if v.get('name') != 'mongodb-data']
        vols.append({'name': 'mongodb-data', 'emptyDir': {}})
        pod['volumes'] = vols
        swapped = True
    out.append(d)
if not swapped:
    sys.exit('mongodb StatefulSet not found in rendered manifests')
yaml.safe_dump_all(out, sys.stdout, default_flow_style=False)
PY
  mv "${RENDERED}.tmp" "${RENDERED}"
fi

# Swap the control-plane-only UPF for the privileged variant. Done here rather
# than in kustomization.yaml so the default stays safe and the opt-in is a
# single explicit env var.
if [[ "${ENABLE_DATAPLANE}" == "true" ]]; then
  warn "data plane enabled: the UPF will run privileged with hostPath /dev/net/tun."
  warn "this requires a namespace at pod-security enforce=privileged and nodes"
  warn "labelled nextg.io/dataplane=true (CloudFormation EnableDataPlanePrivileges=true)."

  # Written to a temp file rather than heredoc'd into a pipeline: a heredoc on
  # `cmd | python3 - <<PY` overrides the piped stdin (shellcheck SC2259), so
  # the transform would read the script instead of the manifests.
  SWAP_PY="$(mktemp -t nextg-upf-swap-XXXXXX.py)"
  trap 'rm -f "${RENDERED}" "${RENDERED}.tmp" "${SWAP_PY}"' EXIT
  cat > "${SWAP_PY}" <<'PY'
import sys, yaml
patch = yaml.safe_load(open(sys.argv[1]))
ps = patch['spec']['template']['spec']
pc = ps['containers'][0]
out = []
for d in yaml.safe_load_all(open(sys.argv[2])):
    if not d:
        continue
    if d.get('kind') == 'Deployment' and d['metadata']['name'] == 'upf':
        spec = d['spec']['template']['spec']
        spec['nodeSelector'] = ps['nodeSelector']
        spec['volumes'] = ps['volumes']
        c = spec['containers'][0]
        c['command'] = pc['command']
        # wrapper.sh takes no args; leaving the --no-dataplane args in place
        # would defeat the whole point of this variant.
        c.pop('args', None)
        c['securityContext'] = pc['securityContext']
        c['volumeMounts'] = pc['volumeMounts']
        c['readinessProbe'] = pc['readinessProbe']
        c.pop('livenessProbe', None)
    out.append(d)
yaml.safe_dump_all(out, sys.stdout, default_flow_style=False)
PY
  python3 "${SWAP_PY}" "${SCRIPT_DIR}/patches/upf-dataplane.yaml" "${RENDERED}" \
    > "${RENDERED}.tmp" || die "UPF data-plane swap failed"
  mv "${RENDERED}.tmp" "${RENDERED}"
fi

# Rewrite the Kind-local image names to ECR. The base manifests use
# nextgcore-rust/<nf>:latest and nextgsim-<node>:latest, which do not exist on
# EKS - without this every pod ends in ErrImagePull.
log "rewriting image references to ${REGISTRY}/${REPO_PREFIX}..."
python3 - "${RENDERED}" "${REGISTRY}" "${REPO_PREFIX}" "${IMAGE_TAG}" <<'PY'
import re, sys
path, registry, prefix, tag = sys.argv[1:5]
src = open(path).read()
src, n1 = re.subn(r'nextgcore-rust/([a-z0-9]+):latest',
                  rf'{registry}/{prefix}/\1:{tag}', src)
src, n2 = re.subn(r'\bnextgsim-(gnb|ue):latest',
                  rf'{registry}/{prefix}/\1:{tag}', src)
# imagePullPolicy IfNotPresent is right for Kind (images side-loaded); on EKS
# it means a :latest tag is never refreshed after the first pull.
src, n3 = re.subn(r'imagePullPolicy: IfNotPresent',
                  'imagePullPolicy: Always', src)
open(path, 'w').write(src)
print(f'  {n1} core NF images, {n2} simulator images, {n3} pull policies')
PY

if [[ "${DRY_RUN}" == "true" ]]; then
  # Validated locally in Python, not with `kubectl apply --dry-run=client`:
  # that still needs REST mappings from the API server, so it cannot run
  # without credentials and would defeat the point of a dry run.
  log "validating rendered manifests offline..."
  python3 - "${RENDERED}" <<'PY' || die "validation failed"
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
errors, warnings = [], []
for d in docs:
    kind = d.get('kind'); name = d.get('metadata', {}).get('name', '?')
    where = f'{kind}/{name}'
    if not kind or not d.get('apiVersion'):
        errors.append(f'{where}: missing kind or apiVersion')
    if kind not in ('Namespace',) and not d.get('metadata', {}).get('namespace'):
        warnings.append(f'{where}: no namespace set')
    spec = d.get('spec', {})
    pod = spec.get('template', {}).get('spec') if kind in ('Deployment','StatefulSet','Job') else None
    if pod:
        # StatefulSet volumes also come from volumeClaimTemplates, which are
        # mounted by name without appearing in pod.volumes.
        vol_names = {v['name'] for v in pod.get('volumes', [])}
        vol_names |= {t['metadata']['name'] for t in spec.get('volumeClaimTemplates', [])}
        for c in pod.get('containers', []) + pod.get('initContainers', []):
            if ':' not in c.get('image', ''):
                errors.append(f'{where}/{c["name"]}: image has no tag')
            for m in c.get('volumeMounts', []):
                if m['name'] not in vol_names:
                    errors.append(f'{where}/{c["name"]}: volumeMount "{m["name"]}" has no matching volume')
            for probe in ('readinessProbe', 'livenessProbe'):
                p = c.get(probe)
                if p:
                    handlers = [h for h in ('exec','httpGet','tcpSocket','grpc') if h in p]
                    if len(handlers) != 1:
                        errors.append(f'{where}/{c["name"]}.{probe}: {len(handlers)} handlers {handlers}, need exactly 1')
            sc = c.get('securityContext', {})
            if sc.get('runAsNonRoot') and sc.get('privileged'):
                errors.append(f'{where}/{c["name"]}: runAsNonRoot with privileged')
            caps = sc.get('capabilities', {})
            if 'ALL' in caps.get('drop', []) and caps.get('add'):
                errors.append(f'{where}/{c["name"]}: drops ALL but adds {caps["add"]}')
        for v in pod.get('volumes', []):
            sources = [k for k in v if k != 'name']
            if len(sources) != 1:
                errors.append(f'{where}: volume "{v["name"]}" has {len(sources)} sources {sources}, need exactly 1')
    if kind == 'Service':
        for p in spec.get('ports', []):
            if p.get('port') == 38412 and p.get('protocol') != 'UDP':
                errors.append(f'{where}: NGAP 38412 is {p.get("protocol")}; must be UDP '
                              '(--sctp-backend defaults to userspace = sctp-proto over UDP)')
for w in warnings:
    print(f'  warn: {w}')
for e in errors:
    print(f'  ERROR: {e}')
print(f'  {len(docs)} manifests checked, {len(errors)} errors, {len(warnings)} warnings')
sys.exit(1 if errors else 0)
PY
  log "offline validation passed."
  OUT="${SCRIPT_DIR}/rendered.dryrun.yaml"
  cp "${RENDERED}" "${OUT}"
  log "wrote ${OUT}"
  warn "offline only: schema validation against the live API server was skipped."
  exit 0
fi

# --- namespace + pod security ---------------------------------------------

log "creating namespace..."
kubectl apply -f "${CORE_DIR}/k8s/base/namespace.yaml"

if [[ "${ENABLE_DATAPLANE}" == "true" ]]; then
  # The UPF cannot create a TUN device under baseline/restricted admission.
  log "labelling namespace pod-security enforce=privileged (data plane)..."
  kubectl label namespace "${NAMESPACE}" \
    pod-security.kubernetes.io/enforce=privileged --overwrite
else
  log "labelling namespace pod-security enforce=baseline..."
  kubectl label namespace "${NAMESPACE}" \
    pod-security.kubernetes.io/enforce=baseline --overwrite
fi

# --- UDM hnet secret -------------------------------------------------------

# Fixes a UDM crash-loop: configmap.yaml points the UDM at
# /etc/nextgcore/hnet/*.key but no manifest ever mounts them. These are the
# SUCI de-concealment private keys, so a Secret rather than a ConfigMap.
HNET_DIR="${CORE_DIR}/docker/rust/configs/5gc/hnet"
if [[ -f "${HNET_DIR}/curve25519-1.key" && -f "${HNET_DIR}/secp256r1-2.key" ]]; then
  log "creating udm-hnet-keys Secret from repo development keys..."
  kubectl create secret generic udm-hnet-keys \
    --namespace "${NAMESPACE}" \
    --from-file="curve25519-1.key=${HNET_DIR}/curve25519-1.key" \
    --from-file="secp256r1-2.key=${HNET_DIR}/secp256r1-2.key" \
    --dry-run=client -o yaml | kubectl apply -f -
  warn "those are the repo's DEVELOPMENT keys. Replace them for any real use."
else
  die "hnet keys not found under ${HNET_DIR}. The UDM will crash-loop without them."
fi

# --- apply -----------------------------------------------------------------

log "applying manifests..."
kubectl apply -f "${RENDERED}"

# Dependency order is enforced by each manifest's initContainers, so this loop
# reports progress rather than sequencing it. Failures here are usually image
# pulls or an unbound PVC.
log "waiting for MongoDB..."
kubectl rollout status statefulset/mongodb -n "${NAMESPACE}" --timeout=300s \
  || warn "MongoDB not ready. Check: kubectl describe pvc -n ${NAMESPACE} (gp3/EBS CSI bound?)"

log "waiting for the MongoDB init job..."
kubectl wait --for=condition=complete job/mongodb-init \
  -n "${NAMESPACE}" --timeout=180s || warn "init job did not complete"

log "waiting for the NRF (every other NF blocks on it)..."
kubectl rollout status deployment/nrf -n "${NAMESPACE}" --timeout=300s \
  || warn "NRF not ready"

for nf in ausf udm udr pcf nssf bsf amf smf upf; do
  log "waiting for ${nf}..."
  kubectl rollout status "deployment/${nf}" -n "${NAMESPACE}" --timeout=300s \
    || warn "${nf} not ready - kubectl logs -n ${NAMESPACE} deploy/${nf}"
done

for dep in prometheus grafana jaeger; do
  kubectl rollout status "deployment/${dep}" -n "${NAMESPACE}" --timeout=180s \
    || warn "${dep} not ready"
done

log "waiting for the gNB..."
kubectl rollout status deployment/gnb -n "${NAMESPACE}" --timeout=300s \
  || warn "gNB not ready - check the resolve-dns initContainer logs"

log "waiting for the UE..."
kubectl rollout status deployment/ue -n "${NAMESPACE}" --timeout=300s \
  || warn "UE not ready - check the resolve-dns initContainer logs"

# --- summary ---------------------------------------------------------------

echo
kubectl get pods -n "${NAMESPACE}" -o wide
echo
kubectl get svc -n "${NAMESPACE}"

cat <<EOF

Deployed.

Verify:
  kubectl logs -n ${NAMESPACE} deploy/nrf | grep -i register
  kubectl logs -n ${NAMESPACE} deploy/amf | grep -i ngap
  kubectl logs -n ${NAMESPACE} deploy/ue  | grep -iE '5GMM|REGISTERED'

Dashboards (no NodePort on EKS - port-forward):
  kubectl port-forward -n ${NAMESPACE} svc/grafana 3000:3000
  kubectl port-forward -n ${NAMESPACE} svc/prometheus 9090:9090
  kubectl port-forward -n ${NAMESPACE} svc/nrf 7777:7777
EOF

if [[ "${ENABLE_DATAPLANE}" != "true" ]]; then
  cat <<EOF

NOTE: the UPF is running with --no-dataplane, so there is no user-plane
forwarding and a UE ping will NOT work. Signalling (NGAP/NAS/PFCP/SBI,
registration, PDU session establishment) does work.

For a real data plane: redeploy the CloudFormation stack with
EnableDataPlanePrivileges=true, then ENABLE_DATAPLANE=true ./deploy-eks.sh
EOF
fi
