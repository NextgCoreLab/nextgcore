# NextG on EKS

An EKS-targeted deployment for the nextgcore 5G control/user plane plus the
nextgsim gNB/UE. This is a **lab / non-production** deployment. Read
"Known limitations" before pointing it at anything shared.

The existing `nextgcore/k8s/` manifests target **Kind** (`deploy.sh` calls
`kind create cluster` and `kind load docker-image`). This directory does not
replace them — it is a kustomize overlay on top of them plus the AWS
infrastructure they assume already exists.

```
deploy/eks/
├── cloudformation/
│   └── eks-cluster.yaml      VPC, EKS, node group, ECR, EBS CSI IRSA
├── kustomization.yaml        default entrypoint: includes profiles/5g
├── profiles/
│   ├── 5g/                   PROFILE=5g (default)
│   │   ├── kustomization.yaml  overlay (patches k8s/ + nextgsim/k8s/)
│   │   ├── patches/            per-concern strategic-merge patches
│   │   └── profile.env         namespace, images, features, rollout hooks
│   └── epc/                  PROFILE=epc (nextg-epc): EPC + LTE eNB/UE
├── e2e-internet.sh           UE -> internet check, PROFILE=5g|epc
├── lib/image-tag.sh          git-SHA image tag, shared by both scripts
├── lib/profile.sh            PROFILE loader, shared by both scripts
├── build-and-push.sh         build 12 images, push to ECR
├── deploy-eks.sh             apply the overlay in dependency order
└── README.md
```

## Profiles

Both scripts take `PROFILE=<name>` (default `5g`) and read
`profiles/<name>/`:

- `kustomization.yaml`: the overlay `deploy-eks.sh` renders.
- `profile.env`: sourced bash (loaded by `lib/profile.sh`) that sets:

| Variable | Meaning |
|---|---|
| `PROFILE_NAMESPACE` | namespace the profile deploys into (required) |
| `PROFILE_NAMESPACE_MANIFEST` | repo-relative manifest that creates it; empty: `kubectl create namespace` |
| `PROFILE_POD_SECURITY` | forced `pod-security.kubernetes.io/enforce` level; empty: baseline, or privileged with `ENABLE_DATAPLANE=true` |
| `PROFILE_KUSTOMIZE_FLAGS` | extra `kubectl kustomize` flags |
| `PROFILE_CARGO_FEATURES` | cargo features the binaries are built with (informational) |
| `PROFILE_TAG_SUFFIX` | appended to the SHA-derived tags (not to an explicit `IMAGE_TAG`) |
| `PROFILE_CORE_NFS` | core images, `<image>:<binary>`, packaged with `Dockerfile.nf` |
| `PROFILE_SIM_IMAGES` | simulator images, `<image>:<Dockerfile>:<context>:<binary>[,...]`, relative to nextgsim |
| `PROFILE_ADVERTISE_NFS` | NFs whose advertised SBI address is rewritten to the pod IP |
| `PROFILE_HNET_SECRET` | `true`: create the `udm-hnet-keys` Secret |
| `PROFILE_DATAPLANE_DEPLOYMENT` / `_PATCH` | what `ENABLE_DATAPLANE=true` swaps in |
| `profile_postrender <file>` | in-place transform of the rendered manifests (before the generic rewrites) |
| `profile_rollout()` / `profile_summary()` | rollout waits after apply; closing summary |

`CORE_BIN_DIR=<dir>` makes `build-and-push.sh` package core binaries from a
directory other than `nextgcore/binaries/`, e.g. a feature build's own output.

`PROFILE=5g` renders byte-identically to the overlay before profiles existed,
and `build-and-push.sh` issues the same docker/aws commands.
`DRY_RUN=true` writes `rendered.dryrun.yaml` for 5g and
`rendered.dryrun.<profile>.yaml` for the others.

## PROFILE=epc

`profiles/epc/` is `docker/rust/docker-compose-epc.yml`, the nightly EPC
stage, in namespace `nextg-epc`:
- mongodb + the shared subscriber seed;
- hss, pcrf, sgwc, sgwu, mme;
- pgwc (`smfd`) and pgwu (`upfd`);
- nextgsim's LTE `enb` and `lte-ue`.

**Configs.** The compose configs are mounted unmodified, from their real
paths (hence `--load-restrictor LoadRestrictionsNone`).
`profiles/epc/scripts/epc-run.sh`, the entrypoint of every pod, maps each
compose address `172.24.0.N` to this pod's IP (its own node) or to the peer's
pod IP from a headless Service. Both nextgcore's EPC configs and nextgsim's
`IpAddr` fields need literal IPs. The Services use
`publishNotReadyAddresses`, so the HSS and MME, which name each other,
cannot deadlock.

**Restarted peers.** The resolution runs at every container start. The
liveness probe `epc-peers-check.sh` fails when a recorded peer's IP changes,
so a restarted peer does not strand its dependents.

**Why pod IPs, not ClusterIPs.** GTP-C, PFCP and GTP-U peers address each
other by advertised F-TEID/F-SEID addresses. Per-flow kube-proxy NAT on those
UDP flows clashes in conntrack.

**S1-MME is kernel SCTP**, as in the nightly. mmed and lte-enb must be
built with their `kernel-sctp` features, and the nodes need the `sctp` kernel
module. The mme Service's `s1ap` port is `protocol: SCTP`; `S1AP_PROTOCOL`
overrides it. The images are built from those binaries:

```bash
# mmed with kernel SCTP, next to the six default-build EPC binaries
(cd src && cargo build --release -p nextgcore-mmed --features kernel-sctp)
mkdir -p /tmp/epc-binaries && cp src/target/release/nextgcore-mmed /tmp/epc-binaries/
for b in sgwcd sgwud hssd pcrfd smfd upfd; do cp binaries/nextgcore-$b /tmp/epc-binaries/; done
# nextgsim LTE eNB (kernel SCTP) and UE, into nextgsim/binaries/ (gitignored)
(cd ../nextgsim && cargo build --release -p nextgsim-enb --features kernel-sctp --bin lte-enb \
   && cargo build --release -p nextgsim-lte-ue --bin lte-ue \
   && mkdir -p binaries && cp target/release/lte-enb target/release/lte-ue binaries/)

PROFILE=epc CORE_BIN_DIR=/tmp/epc-binaries ./build-and-push.sh
PROFILE=epc ./deploy-eks.sh
PROFILE=epc ./e2e-internet.sh
```

**Privileges.** The namespace is `privileged`. sgwu and pgwu run privileged
with `/dev/net/tun`. lte-ue gets NET_ADMIN and `/dev/net/tun`. The sysctls
(`ip_forward`, loose `rp_filter`) are not on the kubelet's safe list, so a
privileged busybox init container writes them into the pod's network
namespace. No `hostNetwork`, NodePort or LoadBalancer is used.

## Images are tagged by git SHA, not `:latest`

Both scripts derive the tag from `git rev-parse --short=12 HEAD` of the
repository each image is built from — nextgcore for the 10 core NFs,
nextgsim for `gnb`/`ue`, since those are separate repos at separate
commits. A dirty tree appends `-dirty`. Neither script passes the tag to
the other: both read the same two repos, so they agree by construction
(`lib/image-tag.sh`).

**Why this matters.** With a mutable `:latest`, the Deployment spec text
is identical before and after a rebuild, so `kubectl apply` writes no new
ReplicaSet and the running pods keep the **old** image — while the script
exits 0, prints `Deployed.`, and its `kubectl rollout status` loop passes
trivially against those stale pods. Observed on devtest1: the running AMF
was `sha256:1338b825` while the freshly pushed tag was `sha256:2665d4ca`,
so an E2E run was reporting on code that had never been deployed.
`imagePullPolicy: Always` does not save this — with no spec change no
container is restarted, so nothing is re-pulled.

After the rollout waits, `deploy-eks.sh` additionally asserts that every
running container's image is the one the manifests asked for, and fails
with the bottom-up `rollout restart` command if any pod is stale. A
rollout wait alone cannot detect this.

To pin a release or redeploy an older build, set `IMAGE_TAG` on **both**
scripts; `IMAGE_TAG=latest` still works but warns.

## Why the addressing needed real work

The simulator's config types force literal IP addresses. From
`nextgsim/nextgsim-common/src/config.rs`:

```rust
pub struct AmfConfig {
    pub address: IpAddr,   // <-- not String
    pub port: u16,
}
pub struct GnbConfig {
    pub link_ip: IpAddr,
    pub ngap_ip: IpAddr,
    pub gtp_ip: IpAddr,
    pub upf_addr: Option<IpAddr>,
}
```

A DNS name like `amf.nextg-system.svc.cluster.local` **fails to deserialize**
into `IpAddr`, so the gNB cannot be handed a Service name. The UE is worse:
`gnb_search_list` is `Vec<String>`, but
`nextgsim-ue/src/rls/task.rs:104` does

```rust
.filter_map(|s| s.parse::<std::net::IpAddr>().ok())
```

so a hostname is **silently discarded**. The UE then starts with an empty
search list, finds no cell, and logs nothing that points at the config. That
is the single most confusing failure mode in this deployment, and it is why
the original manifests resolve names with `nslookup` + `sed` in an init
container.

### What this overlay changes

The `nslookup | grep -A1 | awk` pipeline is replaced with a resolver that:

1. Uses `getent hosts` instead of parsing `nslookup` output. `nslookup` output
   format varies between busybox versions and the `grep -A1 'Name:'` pattern
   breaks when the answer section is ordered differently.
2. Resolves **headless Service** DNS to pod IPs rather than a ClusterIP. The
   original pinned a ClusterIP into the config, which defeats kube-proxy for
   the NGAP/GTP-U path and goes stale if the Service is recreated. For the RLS
   and GTP-U paths that is not just inelegant: UDP flows to a ClusterIP are
   load-balanced per-flow, and the RLS heartbeat reconciliation assumes a
   stable peer.
3. Writes `link_ip`/`ngap_ip`/`gtp_ip` from the pod's own IP via the downward
   API, and fails loudly with a non-zero exit and a clear message if any
   substitution did not happen.
4. Validates that every substituted value parses as an IPv4 address before
   the main container starts, so a resolution failure surfaces in the init
   container instead of as a silent empty cell search 40 seconds later.

The AMF, UPF and gNB get **headless** Services (`clusterIP: None`) in this
overlay so their DNS resolves to pod IPs directly.

## NGAP transport: UDP, deliberately

`--sctp-backend` defaults to `userspace` — sctp-proto over **UDP**
(`nextgcore-amfd/src/lib.rs:280`, `ngap_path.rs:53-56`). Kernel SCTP exists
but requires the `kernel-sctp` build feature; requesting `kernel` without it
is a hard startup error by design (`ngap_path.rs:118-126`).

So port 38412 is declared `protocol: UDP` throughout this overlay. That is
correct for the matched nextgsim gNB and it is what the shipped binaries
support.

Two consequences worth stating plainly:

- **A third-party RAN cannot attach.** Real gNBs speak SCTP over IP proto 132.
  Interop needs binaries rebuilt with `--features kernel-sctp` and
  `--sctp-backend kernel`, plus SCTP support on the node and load balancer.
- The Helm chart at `nextgcore/deploy/helm/` declares 38412 as `protocol: UDP`
  for the same reason, and mounts a real config for all 10 NFs. Both gaps this
  section used to warn about are fixed (see #124). The chart deploys the
  **control plane only** — no gNB/UE, no monitoring — so prefer this overlay
  for a full EKS bring-up, and the chart when you want just a 5GC.

## Prerequisites

```bash
aws --version && kubectl version --client && docker --version
aws sts get-caller-identity          # must succeed
```

Prebuilt binaries must be present (they are committed):

- `nextgcore/binaries/nextgcore-*d` — 17 NF binaries
- `nextgsim/docker/binaries/nr-gnb`, `nr-ue`

## Deploy

```bash
# 1. Infrastructure (~15 min: EKS control plane is the slow part)
aws cloudformation deploy \
  --template-file cloudformation/eks-cluster.yaml \
  --stack-name nextg-eks \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      ClusterName=nextg \
      AllowedAdminCidr=$(curl -s https://checkip.amazonaws.com)/32

# 2. Credentials
aws eks update-kubeconfig --region us-west-2 --name nextg

# 3. Images -> ECR (tagged by git SHA; see below)
./build-and-push.sh

# 4. Workload (derives the same SHA tags, so needs no tag argument)
./deploy-eks.sh
```

### Re-running against an existing install

`ENABLE_DATAPLANE` and `EPHEMERAL_STORAGE` default to `auto`: a re-run keeps
whatever the live install has (a privileged data-plane UPF, an emptyDir or
PVC MongoDB), and the confirmation prompt says so. A fresh install resolves
`auto` to `false`. Set either to `true`/`false` to change the mode on purpose.

MongoDB's `volumeClaimTemplates` are immutable, so switching its storage, or
its claim's size or class, means deleting and recreating the StatefulSet. The
script checks the rendered StatefulSet against the live one before applying
anything, and refuses unless `RECREATE_MONGODB=true` is set. On an emptyDir
install the recreate loses the subscriber data; a PVC install keeps its
claims.

## Verify

```bash
kubectl get pods -n nextg-system -o wide
kubectl logs -n nextg-system deploy/nrf | grep -i register   # NF registrations
kubectl logs -n nextg-system deploy/amf | grep -i ngap       # gNB association
kubectl logs -n nextg-system deploy/ue  | grep -i "5GMM\|REGISTERED"
```

Expected on a default (no data plane) deploy: all pods `Running`, 10 NFs
registered with the NRF, the gNB associated over NGAP, and the UE reaching
`MM_REGISTERED` with a PDU session established. **`ping` from the UE will not
work** — see below.

## The user plane does not work by default

`EnableDataPlanePrivileges=false` (the default) means the UPF runs with
`--no-dataplane`. That flag is real (`nextgcore-upfd/src/main.rs:104`) and the
UPF wrapper already falls back to it when TUN creation fails.

Signalling — NGAP, NAS, PFCP, SBI, registration, PDU session establishment —
all works. **User-plane forwarding does not**, so a UE `ping` fails.

To get a real data plane the UPF needs `privileged: true`, `NET_ADMIN`,
`SYS_ADMIN` and a hostPath mount of `/dev/net/tun` to create its `ogstun`
device, plus `net.ipv4.ip_forward=1` and an iptables MASQUERADE rule. On a
managed cluster that means:

- Pod Security Admission on `nextg-system` must be `privileged`, not
  `baseline`/`restricted`.
- The node must permit it (no restrictive Karpenter/Auto-mode policy).
- Note `docker/rust/Dockerfile.core` sets `USER nextgcore`, while
  `docker-compose.yml` runs the UPF as `user: root`. The Kind manifest sets
  neither, so the wrapper's `ip`/`iptables` calls run as a non-root user and
  fail even where the capabilities would have allowed them. The overlay's
  data-plane patch sets `runAsUser: 0` to fix that.

Enable with `EnableDataPlanePrivileges=true` on the stack **and**
`ENABLE_DATAPLANE=true ./deploy-eks.sh`. Treat it as a separate exercise from
control-plane bring-up.

## Known limitations

Infrastructure (see `Outputs.Caveats` in the template):

- Public API endpoint enabled; defaults to `0.0.0.0/0` unless you override
  `AllowedAdminCidr`.
- Single NAT gateway — shared egress single point of failure.
- Node SG allows all protocols between nodes/pods. The 5G planes span UDP
  38412/4997/4998/2152/8805 and TCP 7777/9090 and pods talk pod-IP to pod-IP
  under the VPC CNI, so this is broad on purpose.
- Cluster admin granted to the account root principal. Narrow
  `DeployerAccessEntry` to a specific role.
- No KMS key for secrets encryption at rest.

Workload:

- **MongoDB is unauthenticated**, single replica, 1Gi EBS, no backup. The init
  Job seeds a bcrypt admin hash and a test subscriber's Ki/OPc. Those are test
  credentials from the Open5GS/UERANSIM defaults, but they are real key
  material in a ConfigMap — do not reuse on a shared cluster.
- The UDM's SUCI de-concealment private keys are moved into a Secret by this
  overlay (the Kind manifests reference `/etc/nextgcore/hnet/*.key` but never
  mount them, so the UDM crash-loops). A Secret is still base64, not
  encrypted — a real deployment wants KMS or an external secrets store.
- Single replica per NF. The NFs hold per-UE state in a process-global context
  and the NRF is the source of truth for topology; `replicas: 2` has not been
  validated and is not expected to work.
- PROFILE=5g deploys 10 of nextgcore's 28 NFs (the 5G control + user
  plane). The EPC tier is PROFILE=epc (see above).
- All 6G/AI features are off. That is the validated configuration — the
  84/84 E2E result is with every 6G flag disabled.
