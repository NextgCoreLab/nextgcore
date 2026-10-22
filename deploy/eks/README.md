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
│   └── 5g/                   PROFILE=5g (default)
│       ├── kustomization.yaml  overlay (patches k8s/ + nextgsim/k8s/)
│       ├── patches/            per-concern strategic-merge patches
│       └── profile.env         namespace, images, features, rollout hooks
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

## Peer addressing: Service names, re-resolved by the NFs

Every peer is named by its Service, and the process that dials it re-resolves
the name. So a single pod restart (new pod IP) recovers on its own, with no
dependent restarted by hand:

| dialler -> peer | config | re-resolved |
|---|---|---|
| SMF -> UPF (PFCP) | `UPF_PFCP_ADDR=upf.<ns>.svc.cluster.local` | before every Association Setup attempt (#658) |
| gNB -> AMF (NGAP) | `amf_configs[].address: amf.<ns>.svc...` | on every reconnect, and every 5 s (nextgsim #286) |
| gNB -> UPF (GTP-U) | `upf_addr: upf.<ns>.svc...` | per PDU session (the SMF's UL tunnel address) |
| UE -> gNB (RLS) | `gnb_search_list: [gnb.<ns>.svc...]` | at start, every 5 s, on losing the cell (nextgsim #286) |
| SBI consumers -> producers | NRF discovery | on a transport failure, with a resend to the new instance (#664, #669) |

The amf, gnb and upf Services are **headless** (`patches/headless-services.yaml`)
so the names resolve to pod IPs: that is what lets a moved pod be noticed, and
it keeps kube-proxy out of the NGAP/RLS/GTP-U UDP paths.

The gNB's own `link_ip`/`ngap_ip`/`gtp_ip` are still written from the pod IP by
an init container: the gNB advertises them in NGAP and GTP-U, and 0.0.0.0 is
not an address a peer can answer.

What a restart of each pod does now (validated on devtest1):
- **UPF**: the SMF re-resolves, sees the new Recovery Time Stamp, and releases
  each PDU session with 5GSM #39 "reactivation requested" (#667); the AMF
  delivers it (#666) and the UE re-establishes the session.
- **SMF**: the PFCP association is not released on shutdown (#677), so the UPF
  keeps forwarding while the new SMF associates.
- **AMF**: the gNB notices the move, releases its UEs and re-runs NG Setup; the
  UE's Service Request is rejected #9 and it registers again (#675).
- **gNB**: the UE re-resolves the gNB name. A UE that attached to the OLD gNB pod
  during a rolling update is still being fixed in nextgsim (see that repo's
  open issues).

Before these fixes the simulator's config types were `IpAddr` and the SMF's
`UPF_PFCP_ADDR` a `SocketAddr`, so init containers wrote each peer's IP at pod
start, and `deploy-eks.sh` had to restart dependents whose peer had moved
(#436). A pod restarted later, outside the script, stranded its dependents.

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

### UE to internet (`e2e-internet.sh`)

With the data plane on (`ENABLE_DATAPLANE=true`), check real traffic from the
UE through the PDU session:

```bash
PROFILE=5g ./e2e-internet.sh
```

It runs from an ephemeral `kubectl debug --target=ue --profile=netadmin`
netshoot container (no image change) and prints PASS/FAIL for `ping -I
uesimtun -c 10 8.8.8.8` (0% loss), `dig @8.8.8.8 -b <UE IP>` (DNS through the
tunnel), `curl --interface uesimtun` to the dig answer (200), and the UPF's
"Data plane stats" UL/DL counters (both must increase). A temporary policy
route (`from <UE IP> lookup 145`, `default dev uesimtun table 145`) keeps every
UE-sourced packet, DNS included, in the tunnel; it is removed on exit. Exit 0
only when every step passes.

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
- Only 10 of nextgcore's 28 NFs are deployed (the 5G control + user plane).
  The EPC tier (mme/hss/pcrf/sgwc/sgwu) has no simulator and is not included.
- All 6G/AI features are off. That is the validated configuration — the
  84/84 E2E result is with every 6G flag disabled.
