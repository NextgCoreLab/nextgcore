# Fix: base k8s manifests cannot reach a passing E2E unattended

## Problem

Four defects, each verified live on Kind at `0cfb1fe`. Together they meant
`k8s/deploy.sh` could not complete without manual intervention, and even once
running, registration failed.

### 1. Every NF advertised `0.0.0.0` to the NRF

`k8s/manifests/configmap.yaml` sets each NF's `sbi.server[0].address` to
`0.0.0.0`. That single value feeds **both** the listen socket and the
`ipv4Addresses` in the NFProfile registered with the NRF. `0.0.0.0` is correct
for a listen socket inside a pod and useless as an advertised endpoint:
discovery "succeeds" and hands consumers an address they cannot dial.

Observed: the AMF resolved its peers through discovery, dialled `0.0.0.0:7777`
— itself — and got 404 from its own SBI router. Every registration failed.

This needs **two** mechanisms, not one:

- The 7 config-driven NFs (`ausf`, `bsf`, `nssf`, `pcf`, `smf`, `udm`, `udr`)
  take the address from YAML, so rewriting the mounted config fixes them.
- The **AMF does not**. `nextgcore-amfd/src/lib.rs:811` reads
  `AMF_SBI_ADDR` from the environment and passes it straight to
  `amf_nrf_register` (line 831); its YAML address is used for the listen
  socket only. `k8s/manifests/amf.yaml` hardcoded that env var to `0.0.0.0`,
  so a ConfigMap rewrite is a no-op for its profile.

`deploy/eks/deploy-eks.sh` already solved the first half post-render. Its
comment claimed "Kind is unaffected — there 0.0.0.0 happens to be reachable on
a single node"; this session disproved that.

### 2. `deploy.sh` deadlocked on UPF/SMF ordering

`deploy.sh` ran `kubectl rollout status deployment/smf` **before** applying
`upf.yaml`. The SMF's `resolve-upf` initContainer blocks until UPF DNS
resolves, so neither could proceed and the script exited 1. Only the UPF
*Service* has to exist for DNS to resolve — not a ready UPF pod.

### 3. The UDM had no SUCI de-concealment keys

`udm.yaml` mounts Secret `udm-hnet-keys` at `/etc/nextgcore/hnet`, which is
where `configmap.yaml` points the UDM. The mount is `optional: true` and base
`deploy.sh` never created the Secret — so the UDM started with no key material
and silently could not de-conceal a profile A/B SUCI. `deploy-eks.sh` creates
it; this path did not. (Issue #125.)

### 4. `mongodb-init` was not idempotent

The Job used `insertOne` against a unique `username` index, so a second
`deploy.sh` run aborted with
`E11000 duplicate key error ... username: "admin"` and CrashLoopBackOff'd —
even though the seed data was already correct.

## Fix

1. Add a `rewrite-advertise-addr` initContainer to the 7 config-driven NFs:
   copy the mounted ConfigMap into an emptyDir and `sed` the advertise address
   to `status.podIP`, failing closed if a `0.0.0.0` survives or `POD_IP` is not
   IPv4. A ConfigMap mount is read-only and the pod IP is unknown until
   scheduling, hence the emptyDir. Anchored on `- address:` so client URIs are
   untouched.
2. Set `AMF_SBI_ADDR` from a `fieldRef` on `status.podIP`.
3. Apply `upf.yaml` before waiting on the SMF; wait on both afterwards.
4. Create `udm-hnet-keys` in `deploy.sh` from the repo development keys, and
   fail loudly if they are missing.
5. Convert the three `insertOne` calls to
   `updateOne` + `$setOnInsert` + `upsert`, so a re-run never overwrites a
   changed password and never aborts.
6. Make the EKS overlay's post-render rewrite idempotent now that the base
   manifests carry the initContainer, and correct the "Kind is unaffected"
   comment.

## Non-goals

Multi-replica NFs, and durable NF state across restarts (issue #66). Every NF
keeps `replicas: 1` and memory-only state.

## Verification

`./k8s/deploy.sh` from a **deleted** namespace must exit 0 with no manual
steps, then:

- all 8 registered NFs advertise routable pod IPs (0 × `0.0.0.0`) on the first
  attempt, verified against the live NRF;
- no NF logs `Using defaults` — a soft WARN that leaves the pod Ready while it
  runs on built-in config;
- `k8s/e2e-test.sh` reports the 74/0/6 baseline;
- a manual `ping 8.8.8.8` from the UE, which the harness does not cover.

Result: exit 0, all 8 NFs on pod IPs, **74 passed / 0 failed / 6 skipped**, 0%
packet loss to 8.8.8.8.

The EKS overlay additionally needs its *rendered* output asserted, not merely a
successful render: the UDM's hnet kustomize patch replaces `volumeMounts`
wholesale, which silently dropped the redirect and restored the `0.0.0.0` bug
while `helm`/kustomize validation stayed green.
