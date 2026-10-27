#!/usr/bin/env bash
# Apply the NextG workload to an existing EKS cluster.
#
# The EKS counterpart of nextgcore/k8s/deploy.sh, minus everything Kind-specific
# (no `kind create cluster`, no `kind load docker-image`), plus the things EKS
# needs that Kind did not: an image registry, the UDM hnet Secret, a bound
# StorageClass, and a namespace Pod Security label. Like k8s/deploy.sh it also
# creates the grafana-admin Secret when it is absent (#1100).
#
# Usage:
#   ./deploy-eks.sh                              # fresh: control plane only;
#                                                #   re-run: keeps the live modes
#   ENABLE_DATAPLANE=true ./deploy-eks.sh        # privileged UPF w/ real TUN
#   EPHEMERAL_STORAGE=true ./deploy-eks.sh       # MongoDB on emptyDir (no EBS CSI)
#   AMF_UE_CONTEXT_STORE=true ./deploy-eks.sh    # #686: UE contexts survive an AMF restart
#   RECREATE_MONGODB=true ./deploy-eks.sh        # allow recreating the mongodb
#                                                #   StatefulSet (data loss, see below)
#   DRY_RUN=true ./deploy-eks.sh                 # render + validate, apply nothing
#   VERIFY_WAIT=90 ./deploy-eks.sh               # how long not-Ready replacements are
#                                                #   re-checked before failing (#1353)
#   PROFILE=epc ./deploy-eks.sh                  # another profile (default 5g)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"

# shellcheck source=lib/image-tag.sh
source "${SCRIPT_DIR}/lib/image-tag.sh"
# shellcheck source=lib/profile.sh
source "${SCRIPT_DIR}/lib/profile.sh"
nextg_load_profile "${PROFILE:-5g}" || exit 1
NAMESPACE="${PROFILE_NAMESPACE}"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
# "auto" (the default) adopts the live install's mode, so a plain re-run never
# downgrades a data-plane install (#662): with a false default the UPF went
# back to --no-dataplane and the namespace to baseline, and UE traffic stopped
# with no error. A fresh install resolves auto to false. true/false force it.
ENABLE_DATAPLANE="${ENABLE_DATAPLANE:-auto}"
DRY_RUN="${DRY_RUN:-false}"
# Swap MongoDB's gp3 PVC for an emptyDir. Needed on clusters without the EBS
# CSI driver, where the PVC would stay Pending and stall every NF behind its
# wait-for-mongodb initContainer. Data does not survive a pod restart; the
# mongodb-init Job re-seeds subscribers each deploy, so for an E2E run the DB
# is derived state. See profiles/5g/patches/mongodb-ephemeral.yaml.
#
# "auto" (the default) adopts the live StatefulSet's storage (#657). Its
# volumeClaimTemplates are IMMUTABLE: an install created with an emptyDir that a
# re-run renders with a gp3 claim fails `kubectl apply` with "spec: Forbidden:
# updates to statefulset spec for fields other than ...", which stopped this
# script before its rollout waits and its image assertion. A fresh install
# resolves auto to false (gp3 PVC).
EPHEMERAL_STORAGE="${EPHEMERAL_STORAGE:-auto}"
# Changing an immutable StatefulSet field (storage mode, claim size or class)
# needs the StatefulSet deleted and recreated. Never done silently: MongoDB
# holds the subscriber data, and on an emptyDir install the recreate LOSES it
# (the mongodb-init Job re-seeds only the repo's test subscribers). A PVC
# install's claims are retained. Without this flag such a change stops the
# script before anything is applied.
RECREATE_MONGODB="${RECREATE_MONGODB:-false}"
# #686: the AMF stores every registered UE's context in MongoDB (collection
# amf_ue_contexts) and restores it after a restart (TS 23.501 §5.21.2.3). Off by
# default. The base manifest already pins the AMF's nfInstanceId, which restoration
# needs. The records hold NAS keys in clear, in the UDR's MongoDB.
AMF_UE_CONTEXT_STORE="${AMF_UE_CONTEXT_STORE:-false}"

log()  { printf '\033[0;32m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn  ]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[fail  ]\033[0m %s\n' "$*" >&2; exit 1; }

# --- image tags ------------------------------------------------------------

# Derived from the same two repositories build-and-push.sh reads, so the tags
# match without either script passing anything to the other. IMAGE_TAG still
# overrides (both groups), for a release tag or to redeploy an older build.
if [[ -n "${IMAGE_TAG:-}" ]]; then
  CORE_TAG="${IMAGE_TAG}"
  SIM_TAG="${IMAGE_TAG}"
  if [[ "${IMAGE_TAG}" == "latest" ]]; then
    warn "IMAGE_TAG=latest is MUTABLE: the kubectl apply below cannot detect a"
    warn "new image, so pods keep the old one and the rollout waits pass"
    warn "trivially against stale pods. Prefer the default SHA tags."
  fi
else
  CORE_TAG="$(nextg_image_tag "${CORE_DIR}")" || die "cannot derive nextgcore image tag"
  SIM_TAG="$(nextg_image_tag "${SIM_DIR}")"   || die "cannot derive nextgsim image tag"
  CORE_TAG="${CORE_TAG}${PROFILE_TAG_SUFFIX}"
  SIM_TAG="${SIM_TAG}${PROFILE_TAG_SUFFIX}"
fi

# --- preflight -------------------------------------------------------------

command -v kubectl >/dev/null || die "kubectl not found"

if [[ "${DRY_RUN}" != "true" ]]; then
  command -v aws >/dev/null || die "aws not found"
  ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
    || die "AWS credentials invalid or expired. Refresh them and retry."
  REGISTRY="${REGISTRY:-${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com}"

  CTX="$(kubectl config current-context 2>/dev/null || true)"
  [[ -n "${CTX}" ]] || die "no kubectl context set. Run: aws eks update-kubeconfig ..."

  # Resolve the "auto" modes from the live objects BEFORE the confirmation, so
  # the operator approves what will actually be applied. The rules live in
  # lib/live_modes.py with fixture tests.
  LIVE_STS_JSON="$(mktemp -t nextg-live-sts-XXXXXX.json)"
  LIVE_DP_JSON="$(mktemp -t nextg-live-dp-XXXXXX.json)"
  trap 'rm -f "${LIVE_STS_JSON}" "${LIVE_DP_JSON}"' EXIT
  kubectl get statefulset mongodb -n "${NAMESPACE}" -o json > "${LIVE_STS_JSON}" 2>/dev/null \
    || : > "${LIVE_STS_JSON}"
  : > "${LIVE_DP_JSON}"
  if [[ -n "${PROFILE_DATAPLANE_DEPLOYMENT}" ]]; then
    kubectl get deployment "${PROFILE_DATAPLANE_DEPLOYMENT}" -n "${NAMESPACE}" -o json \
      > "${LIVE_DP_JSON}" 2>/dev/null || : > "${LIVE_DP_JSON}"
  fi
  LIVE_STORAGE="$(python3 "${SCRIPT_DIR}/lib/live_modes.py" storage "${LIVE_STS_JSON}")"
  LIVE_DATAPLANE="$(python3 "${SCRIPT_DIR}/lib/live_modes.py" dataplane "${LIVE_DP_JSON}" \
    "${PROFILE_DATAPLANE_DEPLOYMENT:-upf}")"
  STORAGE_NOTE=""
  if [[ "${EPHEMERAL_STORAGE}" == "auto" ]]; then
    case "${LIVE_STORAGE}" in
      ephemeral) EPHEMERAL_STORAGE=true;  STORAGE_NOTE=" (auto: kept from the live StatefulSet)" ;;
      pvc)       EPHEMERAL_STORAGE=false; STORAGE_NOTE=" (auto: kept from the live StatefulSet)" ;;
      *)         EPHEMERAL_STORAGE=false; STORAGE_NOTE=" (auto: fresh install)" ;;
    esac
  fi
  DATAPLANE_NOTE=""
  if [[ "${ENABLE_DATAPLANE}" == "auto" ]]; then
    case "${LIVE_DATAPLANE}" in
      true)  ENABLE_DATAPLANE=true;  DATAPLANE_NOTE=" (auto: kept from the live ${PROFILE_DATAPLANE_DEPLOYMENT})" ;;
      false) ENABLE_DATAPLANE=false; DATAPLANE_NOTE=" (auto: kept from the live ${PROFILE_DATAPLANE_DEPLOYMENT})" ;;
      *)     ENABLE_DATAPLANE=false; DATAPLANE_NOTE=" (auto: fresh install)" ;;
    esac
  fi

  # Deploying to the wrong cluster is the expensive mistake here, so make the
  # target explicit and require confirmation.
  cat <<EOF

  target cluster : ${CTX}
  profile        : ${PROFILE_NAME}
  namespace      : ${NAMESPACE}
  registry       : ${REGISTRY}/${REPO_PREFIX}
  core NF tag    : ${CORE_TAG}
  gnb/ue tag     : ${SIM_TAG}
  data plane     : ${ENABLE_DATAPLANE}${DATAPLANE_NOTE}
  mongo storage  : $([[ "${EPHEMERAL_STORAGE}" == "true" ]] && echo "emptyDir (EPHEMERAL - data lost on restart)" || echo "gp3 PVC")${STORAGE_NOTE}
  AMF UE store   : ${AMF_UE_CONTEXT_STORE}

EOF
  read -r -p "Apply to this cluster? [y/N] " reply
  [[ "${reply}" =~ ^[Yy]$ ]] || { echo "aborted."; exit 0; }

  kubectl cluster-info >/dev/null 2>&1 \
    || die "cannot reach the cluster API. Check credentials and endpoint access."
else
  REGISTRY="${REGISTRY:-000000000000.dkr.ecr.${REGION}.amazonaws.com}"
  log "DRY_RUN: rendering only, nothing will be applied."
  # No cluster to read: "auto" renders a fresh install.
  [[ "${EPHEMERAL_STORAGE}" == "auto" ]] && EPHEMERAL_STORAGE=false
  [[ "${ENABLE_DATAPLANE}" == "auto" ]] && ENABLE_DATAPLANE=false
fi

# --- render ----------------------------------------------------------------

RENDERED="$(mktemp -t nextg-eks-XXXXXX.yaml)"
trap 'rm -f "${RENDERED}" "${RENDERED}.tmp" "${LIVE_STS_JSON:-}" "${LIVE_DP_JSON:-}"' EXIT

log "rendering kustomize overlay..."
# shellcheck disable=SC2086  # PROFILE_KUSTOMIZE_FLAGS is a word list
kubectl kustomize ${PROFILE_KUSTOMIZE_FLAGS} "${PROFILE_DIR}" > "${RENDERED}" \
  || die "kustomize render failed"

# Profile-specific transforms of the rendered manifests, in place (a no-op for
# 5g). Runs before the generic rewrites below, so it sees the Kind-local image
# names.
profile_postrender "${RENDERED}" || die "profile ${PROFILE_NAME} post-render failed"

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
if [[ -n "${PROFILE_ADVERTISE_NFS}" ]]; then
log "rewriting NF advertise addresses to the pod IP..."
ADVERTISE_NFS="${PROFILE_ADVERTISE_NFS}" \
python3 - "${RENDERED}" <<'PY' > "${RENDERED}.tmp" || die "advertise-address rewrite failed"
import os, sys, yaml

# The NRF is excluded: it is the registry itself, reached by URI from each NF's
# config, and registers no profile. The UPF is excluded: it joins the SBI plane
# only when --nrf-uri is set (off by default) and its wrapper.sh owns its
# startup.
# The set comes from the profile (PROFILE_ADVERTISE_NFS).
NFS = set(os.environ['ADVERTISE_NFS'].split())

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
fi

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

# #686: point the AMF at MongoDB for its UE context store. Post-render, like the
# swaps around it, so the default stays as it was and the opt-in is one env var.
if [[ "${AMF_UE_CONTEXT_STORE}" == "true" ]]; then
  log "AMF UE context store: on (MongoDB collection amf_ue_contexts)"
  python3 - "${RENDERED}" "${NAMESPACE}" <<'PY' > "${RENDERED}.tmp" || die "amf ue-context-store patch failed"
import sys, yaml
out = []
patched = False
for d in yaml.safe_load_all(open(sys.argv[1])):
    if not d:
        continue
    if d.get('kind') == 'Deployment' and d['metadata']['name'] == 'amf':
        ns = d['metadata'].get('namespace') or sys.argv[2]
        uri = f'mongodb://mongodb.{ns}.svc.cluster.local:27017/nextgcore'
        pod = d['spec']['template']['spec']
        for c in pod['containers']:
            if c['name'] == 'amf':
                env = [e for e in c.get('env', []) if e.get('name') != 'AMF_UE_CONTEXT_DB_URI']
                env.append({'name': 'AMF_UE_CONTEXT_DB_URI', 'value': uri})
                c['env'] = env
                patched = True
        inits = pod.get('initContainers', [])
        if not any(i.get('name') == 'wait-mongodb' for i in inits):
            inits.append({
                'name': 'wait-mongodb',
                'image': 'busybox:1.36',
                'command': ['sh', '-c',
                            f'until nc -z mongodb.{ns}.svc.cluster.local 27017; do '
                            'echo waiting for mongodb; sleep 2; done'],
            })
        pod['initContainers'] = inits
    out.append(d)
if not patched:
    sys.exit('amf Deployment not found in rendered manifests')
yaml.safe_dump_all(out, sys.stdout, default_flow_style=False)
PY
  mv "${RENDERED}.tmp" "${RENDERED}"
fi

# Swap the control-plane-only UPF for the privileged variant. Done here rather
# than in kustomization.yaml so the default stays safe and the opt-in is a
# single explicit env var.
if [[ "${ENABLE_DATAPLANE}" == "true" && -n "${PROFILE_DATAPLANE_DEPLOYMENT}" ]]; then
  warn "data plane enabled: the UPF will run privileged with hostPath /dev/net/tun."
  warn "this requires a namespace at pod-security enforce=privileged and nodes"
  warn "labelled nextg.io/dataplane=true (CloudFormation EnableDataPlanePrivileges=true)."

  # Written to a temp file rather than heredoc'd into a pipeline: a heredoc on
  # `cmd | python3 - <<PY` overrides the piped stdin (shellcheck SC2259), so
  # the transform would read the script instead of the manifests.
  SWAP_PY="$(mktemp -t nextg-upf-swap-XXXXXX.py)"
  trap 'rm -f "${RENDERED}" "${RENDERED}.tmp" "${SWAP_PY}" "${LIVE_STS_JSON:-}" "${LIVE_DP_JSON:-}"' EXIT
  cat > "${SWAP_PY}" <<'PY'
import sys, yaml
patch = yaml.safe_load(open(sys.argv[1]))
ps = patch['spec']['template']['spec']
pc = ps['containers'][0]
out = []
for d in yaml.safe_load_all(open(sys.argv[2])):
    if not d:
        continue
    if d.get('kind') == 'Deployment' and d['metadata']['name'] == sys.argv[3]:
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
  python3 "${SWAP_PY}" "${SCRIPT_DIR}/${PROFILE_DATAPLANE_PATCH}" "${RENDERED}" \
    "${PROFILE_DATAPLANE_DEPLOYMENT}" > "${RENDERED}.tmp" || die "UPF data-plane swap failed"
  mv "${RENDERED}.tmp" "${RENDERED}"
fi

# Rewrite the Kind-local image names to ECR. The base manifests use
# nextgcore-rust/<nf>:latest and nextgsim-<node>:latest, which do not exist on
# EKS - without this every pod ends in ErrImagePull.
log "rewriting image references to ${REGISTRY}/${REPO_PREFIX}..."
python3 - "${RENDERED}" "${REGISTRY}" "${REPO_PREFIX}" "${CORE_TAG}" "${SIM_TAG}" \
  "$(nextg_profile_sim_names)" <<'PY'
import re, sys
path, registry, prefix, core_tag, sim_tag, sim_names = sys.argv[1:7]
# Simulator image names come from the profile (PROFILE_SIM_IMAGES).
sim_alt = '|'.join(re.escape(n) for n in sim_names.split())
src = open(path).read()
# Two tags, because the core NFs and the simulator come from different
# repositories at different commits (see lib/image-tag.sh).
src, n1 = re.subn(r'nextgcore-rust/([a-z0-9]+):latest',
                  rf'{registry}/{prefix}/\1:{core_tag}', src)
src, n2 = re.subn(rf'\bnextgsim-({sim_alt}):latest',
                  rf'{registry}/{prefix}/\1:{sim_tag}', src)
# imagePullPolicy IfNotPresent is right for Kind (images side-loaded). On EKS an
# immutable SHA tag makes the choice moot for correctness -- a changed tag is a
# changed spec, so the pod is recreated and pulled regardless -- but Always is
# kept as defence in depth for an explicit IMAGE_TAG that is mutable.
src, n3 = re.subn(r'imagePullPolicy: IfNotPresent',
                  'imagePullPolicy: Always', src)
open(path, 'w').write(src)
print(f'  {n1} core NF images @ {core_tag}, {n2} simulator images @ {sim_tag}, '
      f'{n3} pull policies')
# A Kind-local image name left anywhere means a rewrite pattern missed, which on
# EKS is an ErrImagePull. Match on the SOURCE names rather than on a ':latest'
# suffix: IMAGE_TAG=latest is a supported (if discouraged) override, so a
# ':latest' that carries the registry prefix has been rewritten correctly and
# must not fail here.
missed = sorted(set(re.findall(r'image:\s*(nextgcore-rust/\S+|nextgsim-\S+)', src)))
if missed:
    sys.exit('image rewrite missed: ' + ', '.join(missed))
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
        # Issue #63: every SBI NF defaults to the PRODUCTION SBI profile. amf,
        # ausf, smf and udm then exit at startup without
        # /etc/nextgcore/tls/server.crt; udr, pcf, nssf and bsf start but cannot
        # load client.crt for their own NRF registration, so they are silently
        # undiscoverable. The dev opt-out only works on the NF's OWN container
        # -- it once sat on the busybox rewrite-advertise-addr init container in
        # ausf/smf/udm, and was missing outright from the other four.
        if kind == 'Deployment' and name in ('amf', 'ausf', 'smf', 'udm',
                                             'udr', 'pcf', 'nssf', 'bsf'):
            nf = next((c for c in pod.get('containers', []) if c['name'] == name), None)
            has_profile = nf is not None and any(
                e['name'] == 'NEXTGCORE_SBI_PROFILE' for e in nf.get('env', []))
            has_tls = nf is not None and any(
                m.get('mountPath', '').startswith('/etc/nextgcore/tls')
                for m in nf.get('volumeMounts', []))
            if not (has_profile or has_tls):
                errors.append(f'{where}/{name}: no NEXTGCORE_SBI_PROFILE and no TLS mount '
                              'on the NF container; it will refuse to start')
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
  OUT="${SCRIPT_DIR}/${PROFILE_DRYRUN_FILE}"
  cp "${RENDERED}" "${OUT}"
  log "wrote ${OUT}"
  warn "offline only: schema validation against the live API server was skipped."
  exit 0
fi

# --- immutable StatefulSet fields (#657) -----------------------------------
#
# Checked against the FINAL rendered manifest (after the storage swap) and
# before anything is applied (namespace, Secret, manifests), so a refused
# change leaves the cluster untouched instead of half-applied.
if [[ -s "${LIVE_STS_JSON:-}" ]]; then
  if ! STS_DIFF="$(python3 "${SCRIPT_DIR}/lib/live_modes.py" sts-diff \
        "${LIVE_STS_JSON}" "${RENDERED}" mongodb)"; then
    warn "the mongodb StatefulSet would change IMMUTABLE fields:"
    printf '         %s\n' "${STS_DIFF}" >&2
    if [[ "${RECREATE_MONGODB}" != "true" ]]; then
      die "refusing to recreate mongodb: it holds the subscriber data (live storage: ${LIVE_STORAGE}).
       Leave EPHEMERAL_STORAGE unset to keep the live mode, or re-run with
       RECREATE_MONGODB=true to delete and recreate the StatefulSet (an emptyDir's data is LOST)."
    fi
    warn "RECREATE_MONGODB=true: deleting statefulset/mongodb (PVCs are retained; an emptyDir's data is lost)"
    kubectl delete statefulset mongodb -n "${NAMESPACE}" --wait=true
  fi
fi

# --- namespace + pod security ---------------------------------------------

log "creating namespace..."
if [[ -n "${PROFILE_NAMESPACE_MANIFEST}" ]]; then
  kubectl apply -f "${CORE_DIR}/${PROFILE_NAMESPACE_MANIFEST}"
else
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
fi

if [[ -n "${PROFILE_POD_SECURITY}" ]]; then
  log "labelling namespace pod-security enforce=${PROFILE_POD_SECURITY} (profile ${PROFILE_NAME})..."
  kubectl label namespace "${NAMESPACE}" \
    "pod-security.kubernetes.io/enforce=${PROFILE_POD_SECURITY}" --overwrite
elif [[ "${ENABLE_DATAPLANE}" == "true" ]]; then
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
if [[ "${PROFILE_HNET_SECRET}" != "true" ]]; then
  log "profile ${PROFILE_NAME} needs no udm-hnet-keys Secret"
elif [[ -f "${HNET_DIR}/curve25519-1.key" && -f "${HNET_DIR}/secp256r1-2.key" ]]; then
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

# --- Grafana admin secret (#1100) ------------------------------------------

# k8s/monitoring/grafana.yaml takes its admin password from Secret
# grafana-admin and has no fallback (#837), so without it the pod sits in
# CreateContainerConfigError. Created as k8s/deploy.sh does: a generated
# password, only when the Secret is absent -- an existing one (the operator's
# own, or an earlier run's) is never overwritten. Keyed on the render, not the
# profile, so a profile without Grafana creates nothing.
GRAFANA_SECRET=false
if grep -q 'name: grafana-admin$' "${RENDERED}"; then
  GRAFANA_SECRET=true
  # --ignore-not-found: empty output means absent; any other failure (RBAC,
  # API) exits here rather than falling through to a create.
  existing="$(kubectl get secret grafana-admin -n "${NAMESPACE}" -o name --ignore-not-found)" \
    || die "cannot read Secret grafana-admin in ${NAMESPACE}"
  if [[ -n "${existing}" ]]; then
    log "keeping the existing grafana-admin Secret"
  else
    command -v openssl >/dev/null || die "openssl not found (needed to generate the Grafana admin password)"
    log "creating grafana-admin Secret with a generated password..."
    # Piped, never in argv: an argv value shows in `ps` and under `bash -x`.
    # `kubectl create` refuses an existing Secret, so a concurrent run cannot
    # replace one either.
    openssl rand -base64 24 | tr -d '\n' \
      | kubectl create secret generic grafana-admin -n "${NAMESPACE}" \
          --from-file=password=/dev/stdin >/dev/null \
      || die "could not create Secret grafana-admin"
  fi
fi

# --- apply -----------------------------------------------------------------

log "applying manifests..."
kubectl apply -f "${RENDERED}"

# Dependency order is enforced by each manifest's initContainers, so the
# profile's rollout waits report progress rather than sequencing it. Failures
# here are usually image pulls or an unbound PVC.
# --- re-resolve peers pinned by IP (#436) ------------------------------------
#
# Not used by PROFILE=5g any more: its NFs re-resolve Service names themselves
# (README "Peer addressing"). Kept for a profile whose peers still need a
# literal IP at start.
#
# Three dependents resolve a peer's POD IP once, in an init container: the SMF
# pins the UPF (resolve-upf), the gNB pins the AMF and the UPF, and the UE pins
# the gNB (resolve-dns). When the peer gets a new pod and the dependent does not
# -- always the case for gnb/ue when only the core's tag changed, since their
# apply is then a no-op -- the dependent keeps dialling a dead IP. On devtest1
# that failed the E2E at NG Setup on a healthy core.
#
# So restart a dependent that finished resolving AT OR BEFORE the moment a peer
# it pins became Ready -- headless DNS returns Ready endpoints only, so until
# then the lookup still yields the old pod. Creation order is not enough: on
# devtest1 an SMF and the new UPF were created in the same second and the SMF
# still pinned the dying UPF. The rule lives in lib/pinned_peers.py with fixture
# tests. One dependent at a time, each settling before the next resolves
# against it. The AMF is not here: it re-discovers through the NRF, and since
# #435 it evicts a dead peer on the first failure.
PEER_A_JSON="${RENDERED}.peer-a.json"
PEER_B_JSON="${RENDERED}.peer-b.json"
restart_if_resolved_before_ready() {
  local dependent="$1"; shift
  local peer
  kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${dependent}" -o json \
    > "${PEER_A_JSON}" 2>/dev/null || return 0
  for peer in "$@"; do
    kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${peer}" -o json \
      > "${PEER_B_JSON}" 2>/dev/null || continue
    if [[ "$(python3 "${SCRIPT_DIR}/lib/pinned_peers.py" "${PEER_A_JSON}" "${PEER_B_JSON}")" == restart ]]; then
      log "${dependent} resolved ${peer} before its current pod was Ready; restarting it to re-resolve"
      kubectl rollout restart "deployment/${dependent}" -n "${NAMESPACE}" >/dev/null
      kubectl rollout status "deployment/${dependent}" -n "${NAMESPACE}" --timeout=300s \
        || warn "${dependent} not ready after the re-resolve restart"
      return 0
    fi
  done
}

profile_rollout

# --- verify the running pods carry the images we just deployed --------------
#
# `kubectl rollout status` alone cannot establish this. With a mutable tag the
# apply is a no-op, no new ReplicaSet is written, and the rollout wait then
# passes TRIVIALLY against the pods that were already Running -- reporting
# success for a deploy that changed nothing. SHA tags make that far less likely
# (a changed tag is a changed spec), but "less likely" is not a check, and an
# explicit IMAGE_TAG can still be mutable.
#
# The rules live in lib/verify_images.py, each with a fixture test in
# lib/test_verify_images.py (#436): pods being replaced are skipped; a pod is
# judged by its own SPEC image, never by status.image or imageID -- both report
# an older tag or digest once a node holds a content-identical earlier build;
# and a replacement on the expected image that is not Ready is reported as a
# failing rollout, not as stale. What this cannot catch is a MUTABLE tag
# (IMAGE_TAG=latest) moving underneath an unchanged spec -- hence that warning.
log "verifying running pods match the deployed images..."
PODS_JSON="${RENDERED}.pods.json"
trap 'rm -f "${RENDERED}" "${RENDERED}.tmp" "${PODS_JSON}" "${PEER_A_JSON}" "${PEER_B_JSON}" "${LIVE_STS_JSON:-}" "${LIVE_DP_JSON:-}"' EXIT

# #1353: "replacements not Ready" (exit 2) can be a pod in a designed restart rather
# than a failing rollout -- PROFILE=epc's epc-peers-check.sh liveness restarts a pod
# whose recorded peer moved, which can happen after its rollout wait passed. So exit 2
# is re-checked for up to VERIFY_WAIT seconds; a real crash-loop is still not Ready at
# the end. A stale image (exit 1) fails at once.
VERIFY_WAIT="${VERIFY_WAIT:-90}"
[[ "${VERIFY_WAIT}" =~ ^[0-9]+$ ]] || die "VERIFY_WAIT must be a number of seconds: ${VERIFY_WAIT}"
verify_deadline=$(( $(date +%s) + VERIFY_WAIT ))
while :; do
  # #1354 review: fail closed. Unlisted pods are unverified pods, so a listing that
  # fails is retried within VERIFY_WAIT like a not-Ready verdict, and then fails the
  # deploy instead of reporting a success nothing checked.
  if ! kubectl get pods -n "${NAMESPACE}" -o json > "${PODS_JSON}" 2>/dev/null; then
    if [[ "$(date +%s)" -lt "${verify_deadline}" ]]; then
      warn "could not list pods in ${NAMESPACE}; retrying the image verification..."
      sleep 5
      continue
    fi
    die "could not list pods in ${NAMESPACE} for ${VERIFY_WAIT}s; the deployed images are unverified"
  fi
  verify_rc=0
  verify_out="$(python3 "${SCRIPT_DIR}/lib/verify_images.py" "${RENDERED}" "${PODS_JSON}" 2>&1)" \
    || verify_rc=$?
  if [[ "${verify_rc}" == 2 && "$(date +%s)" -lt "${verify_deadline}" ]]; then
    log "replacement pods not Ready yet (a restart in progress?); re-checking for up to ${VERIFY_WAIT}s..."
    sleep 5
    continue
  fi
  printf '%s\n' "${verify_out}"
  case "${verify_rc}" in
    0) ;;
    2) die "rollout failing: replacement pods are still not Ready after ${VERIFY_WAIT}s (see above)" ;;
    *) die "image verification failed" ;;
  esac
  break
done

# --- summary ---------------------------------------------------------------

echo
kubectl get pods -n "${NAMESPACE}" -o wide
echo
kubectl get svc -n "${NAMESPACE}"

profile_summary

if [[ "${GRAFANA_SECRET}" == "true" ]]; then
  cat <<EOS

Grafana login: user admin; the password is in Secret grafana-admin:
  kubectl -n ${NAMESPACE} get secret grafana-admin -o jsonpath='{.data.password}' | base64 -d
EOS
fi
