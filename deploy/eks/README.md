# NextG on EKS

An EKS-targeted deployment for the nextgcore 5G control/user plane plus the
nextgsim gNB/UE (PROFILE=5g), or the nextgcore EPC plus the nextgsim LTE eNB/UE
(PROFILE=epc). This is a **lab / non-production** deployment. Read
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
│       ├── kustomization.yaml  mongodb + epc.yaml + the unmodified compose configs
│       ├── epc.yaml            9 Deployments; 8 headless Services (not lte-ue)
│       ├── namespace.yaml      nextg-epc, pod-security privileged
│       ├── profile.env         namespace, images, features, rollout hooks
│       └── scripts/            epc-run.sh (entrypoint), epc-peers-check.sh (liveness)
├── e2e-internet.sh           UE -> internet check, PROFILE=5g|epc
├── lib/image-tag.sh          git-SHA image tag, shared by both scripts
├── lib/profile.sh            PROFILE loader, shared by both scripts
├── build-and-push.sh         build the profile's images (12 for 5g, 9 for epc), push to ECR
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
| `profile_build_hint()` | build commands `build-and-push.sh` prints when binaries are missing (checked before any AWS call) |

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

Every EPC Deployment (not mongodb or its init Job) has `nodeSelector: nextg.io/dataplane=true`, so
at least one node must carry that label (CloudFormation
`EnableDataPlanePrivileges=true` sets it on the node group; on an existing
cluster, `kubectl label node <n> nextg.io/dataplane=true`).

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
overrides it.

**Node prerequisite: the `sctp` module.** A container shares the node's
kernel, so this cannot be fixed in an image. Without it, mme fails to bind
36412. Load it on each `nextg.io/dataplane=true` node and persist it across
reboots:

```bash
# a fresh cluster has no nextg-epc yet; deploy-eks.sh re-applies this later
kubectl apply -f profiles/epc/namespace.yaml
# a one-shot pod: it runs and completes; delete the node-debugger-* pod kubectl names
kubectl debug node/<n> -n nextg-epc --profile=sysadmin --image=busybox -- \
  chroot /host sh -c 'modprobe sctp && echo sctp > /etc/modules-load.d/sctp.conf'
kubectl -n nextg-epc exec deploy/mme -- grep -w sctp /proc/modules   # after deploy
```

A newly launched node needs the same step (or launch-template userData).

The images are built from those binaries:

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
# EPHEMERAL_STORAGE=true where there is no EBS CSI driver / gp3 class (devtest1)
EPHEMERAL_STORAGE=true PROFILE=epc ./deploy-eks.sh
PROFILE=epc ./e2e-internet.sh
```

**Storage.** MongoDB uses the shared StatefulSet with a gp3 PVC. On a cluster
without the EBS CSI driver (no gp3 StorageClass), the PVC stays Pending and
mongodb never starts; deploy with `EPHEMERAL_STORAGE=true` (an emptyDir, so
the subscriber data does not survive mongodb-0 being recreated).

`PROFILE=epc ./e2e-internet.sh` checks, from the logs, S1 Setup, EMM-REGISTERED
and the same default-bearer EBI on the UE and the MME, then the same ping / DNS /
HTTPS / PGW-U counter steps as the 5G profile, on `lteuetun5`.

**Restarting a pod.** Deleting any one of the nine pods in the table below
recovers with no manual restart; the next `e2e-internet.sh` passes. Measured on
devtest1 (nextgcore cc8f97a, nextgsim 4a35c79), one deletion at a time; the
time runs from the delete to the first e2e PASS, retrying every e2e run plus
10 s:

| deleted | PASS after | recovers | how |
|---|---|---|---|
| pgwu | 124 s | on its own | the PGW-C's PFCP heartbeat sees the new Recovery Time Stamp, sends a Delete Bearer Request (cause 8); the MME detaches the UE (re-attach required) and the UE re-attaches |
| sgwu | 124 s | on its own | sgwc liveness-restarts; the MME sees the SGW-C restart counter change on Echo, detaches (re-attach required), and the UE re-attaches |
| pgwc | 73 s | on the UE's next uplink | the pods that track pgwc (sgwc, pcrf, mme) liveness-restart; the mme restart loses the UE contexts, so the UE's Service Request is rejected #9, the eNB releases the UE, and the UE re-attaches |
| sgwc | 39 s | on the UE's next uplink | mme liveness-restarts; then as for pgwc |
| mme | 130 s | on the UE's next uplink | enb liveness-restarts, the UE loses the radio link and camps again idle; then as for pgwc |
| enb | 113 s | on its own | lte-ue liveness-restarts and attaches afresh |
| hss | 74 s | on the UE's next uplink | mme (which tracks hss) liveness-restarts, losing the UE contexts; then as for pgwc |
| pcrf | 28 s | on its own | nothing tracks pcrf; the attached UE's bearer is unaffected, and the fresh attach of the next row (lte-ue) succeeded after it |
| lte-ue | 28 s | on its own | the new UE attaches afresh |

The hss, pcrf and lte-ue rows were measured later, on the same images.

**mongodb-0 is not in the table.** With `EPHEMERAL_STORAGE=true` (as above) its
emptyDir goes with the pod, so the subscriber the one-shot `mongodb-init` Job
seeded is lost and the next attach fails authentication at the HSS. Recover with
`kubectl -n <ns> delete job mongodb-init` first, then re-run `deploy-eks.sh`,
which runs the Job again. The delete is needed because the finished Job lingers
for 300 s (`ttlSecondsAfterFinished`); within that window `kubectl apply` leaves
it as it is and nothing is re-seeded. On a gp3 PVC the data survives.

**A long-lived deployment hangs (#724).** upfd deadlocks at its first periodic
usage report. smfd provisions a 3600 s Measurement Period by default, so a
PGW-U (or 5G UPF) that has carried traffic stops answering PFCP about an hour
later. Every new attach then fails (S5 cause 106). Until a build with #724's fix
is deployed, delete the pgwu pod (PROFILE=epc) or the upf pod in `nextg-system`
(PROFILE=5g) to recover.

"On the UE's next uplink": an MME restart loses the UE contexts, and the UE
stays EMM-REGISTERED and idle until it has data to send. No paging or periodic
TAU brings it back sooner. An idle UE with nothing to send stays down.

**Privileges.** The namespace is `privileged`. sgwu and pgwu run privileged
with `/dev/net/tun`. lte-ue gets NET_ADMIN and `/dev/net/tun`. The sysctls
(`ip_forward`, loose `rp_filter`) are not on the kubelet's safe list, so a
privileged busybox init container writes them into the pod's network
namespace. No `hostNetwork`, NodePort or LoadBalancer is used.

## Images are tagged by git SHA, not `:latest`

Both scripts derive the tag from `git rev-parse --short=12 HEAD` of the
repository each image is built from — nextgcore for the core NFs,
nextgsim for the simulator images (`gnb`/`ue`, or `lte-enb`/`lte-ue`), since
those are separate repos at separate commits. A dirty tree appends `-dirty`. Neither script passes the tag to
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
(`nextgcore-amfd/src/lib.rs:338`, parsed by `SctpBackend::parse` at
`ngap_path.rs:64`). Kernel SCTP needs the `kernel-sctp` build feature;
requesting `kernel` from a binary built without it is a hard startup error by
design (`ngap_path.rs:131-137`).

So port 38412 is declared `protocol: UDP` throughout this overlay. That is
correct for the matched nextgsim gNB and it is what the shipped binaries
support.

Two consequences worth stating plainly:

- **A third-party RAN cannot attach as deployed.** Real gNBs speak SCTP over
  IP proto 132. Interop needs `--sctp-backend kernel`, port 38412 declared
  `protocol: SCTP`, the `sctp` module on the node (see PROFILE=epc) and SCTP on
  the load balancer. It also needs an amfd built with `kernel-sctp`: the
  builder image (`docker/rust/Dockerfile.builder`, used by
  `docker/rust/build.sh` and CI) already builds amfd and mmed that way, but a
  plain `cargo build --release` does not.
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

The binaries must be built first. They are not committed: `nextgcore/binaries/`
and `nextgsim/binaries/` are gitignored, and `build-and-push.sh` fails
listing whatever is missing, with the commands to build it, before any AWS
call (#716).

- `nextgcore/binaries/`: `cd src && cargo build --release`, then copy the
  daemons from `src/target/release/`. The workspace builds all 28 NF daemons
  plus `nextgcore-webui`; PROFILE=5g packages 10 of them, PROFILE=epc 7.
  PROFILE=epc: mmed must be the kernel-sctp build (see PROFILE=epc above); the
  default build starts but binds nothing on 36412.
- `nextgsim/binaries/nr-gnb`, `nr-ue` (PROFILE=5g), or `lte-enb`, `lte-ue`
  (PROFILE=epc, see above). Both profiles build from the nextgsim repo root,
  as nextgsim's own CI does: `Dockerfile.ue-local` also COPYs
  `scripts/nr-ue-deregister.sh` (nextgsim #373, #1099). `nr-cli` is optional;
  the UE image ships it when `binaries/nr-cli` is present.

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
netshoot container (no image change). It finds the UE's PDU-session interface
(`<tun>`: the first `uesimtun*` with an IPv4 address, since nextgsim names
them `<tun_name><N>`; `TUN=<name>` pins one) and prints PASS/FAIL for `ping -I
<tun> -c 10 8.8.8.8` (0% loss), `dig @8.8.8.8 -b <UE IP>` (DNS through the
tunnel), `curl --interface <tun>` to the dig answer (200), and the UPF's
"Data plane stats" UL/DL counters (both must increase). A temporary policy
route (`from <UE IP> lookup 145`, `default dev <tun> table 145`) keeps every
UE-sourced packet, DNS included, in the tunnel; it is removed on exit. Exit 0
only when every step passes.

## The user plane does not work by default

`EnableDataPlanePrivileges=false` (the default) means the UPF runs with
`--no-dataplane`. That flag is real (`nextgcore-upfd/src/main.rs:132`) and the
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

- **MongoDB is unauthenticated**, single replica, 8Gi gp3 EBS (or an emptyDir with `EPHEMERAL_STORAGE=true`), no backup. The init
  Job seeds a test subscriber's Ki/OPc. Those are test credentials from the
  Open5GS/UERANSIM defaults, but they are real key material in a ConfigMap —
  do not reuse on a shared cluster.
- The UDM's SUCI de-concealment private keys are moved into a Secret by this
  overlay (the Kind manifests reference `/etc/nextgcore/hnet/*.key` but never
  mount them, so the UDM crash-loops). A Secret is still base64, not
  encrypted — a real deployment wants KMS or an external secrets store.
- Grafana's admin password is in Secret `grafana-admin`, which `deploy-eks.sh`
  creates with a generated password when it is absent and never overwrites
  (#1100; no credential is in any manifest). To use your own password, create
  that Secret (key `password`) before the first deploy. To read it:
  `kubectl -n nextg-system get secret grafana-admin -o jsonpath='{.data.password}' | base64 -d`.
  Grafana, Prometheus and Jaeger are ClusterIP Services on EKS, not the Kind
  manifests' NodePorts; reach them with `kubectl port-forward`.
- Single replica per NF. The NFs hold per-UE state in a process-global context
  and the NRF is the source of truth for topology; `replicas: 2` has not been
  validated and is not expected to work.
- PROFILE=5g deploys 10 of nextgcore's 28 NFs (the 5G control + user
  plane). The EPC tier, with nextgsim's LTE eNB/UE, is PROFILE=epc (see above).
- A long-lived deployment hangs at upfd's first periodic usage report, in
  both profiles (#724; see "A long-lived deployment hangs" above).
- All 6G/AI features are off. That is the validated configuration: the
  nightly gate (`docker-build`, `docker-e2e`, `docker-e2e-epc` in
  `.github/workflows/ci.yml`) runs with every 6G flag disabled, and
  `e2e-internet.sh` is the on-cluster check.
