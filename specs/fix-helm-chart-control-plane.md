# Fix: make the Helm chart render a working 5GC control plane

Resolves nextgcore #124 (partially — see Non-goals).

## Problem

`deploy/helm/nextgcore/` renders Deployments that cannot start. Every
claim in #124 was re-verified against the tree at `0cfb1fe`:

| Claim | Verified |
|---|---|
| No template mounts config | `grep -c volumeMounts` = 0 across all 10 NF templates |
| UPF ConfigMap uses a schema the binary cannot parse | emits `upf.tun.{ip,prefix}` + bare `pfcp.port`; binary wants `pfcp.server[].address/port`, `gtpu.server[]`, `session[].{subnet,gateway,dev}` |
| `TUN_IP`/`TUN_PREFIX` are dead | no `env::var` for either in `upfd`; they are clap args |
| UPF data plane cannot come up | no `/dev/net/tun`, no `hostPath`, no wrapper, no `runAsUser: 0` |
| GTP-U on ClusterIP | `values.yaml:88` → `type: ClusterIP` for 2152/UDP |
| Missing NFs / no seeded DB | 10 templates vs 13 workloads; no `mongodb-init` Job |

Two further defects #124 did not list:

- **The chart cannot render at all.** `Chart.yaml` declares a Bitnami
  `mongodb` dependency that is not vendored, so *every* `helm template`
  and `helm install` fails offline — including with
  `--set mongodb.enabled=false`:
  `Error: found in Chart.yaml, but missing in charts/ directory: mongodb`
- **9 templates use `httpGet` probes.** `nextgcore-sbi` serves h2c
  prior-knowledge only (no HTTP/1.1 fallback, no ALPN), so kubelet's
  HTTP/1.1 probe can never succeed and the liveness probe SIGKILLs a
  healthy NF roughly every 90s. This is the defect recorded in
  LEARNINGS 2026-07-31; `k8s/manifests/` uses `tcpSocket` for exactly
  this reason. The chart still carries the broken form.

## Fix

Bring the chart's **control plane** to parity with `k8s/manifests/`,
reusing the mechanisms already proven there and in `deploy/eks/`:

1. **Vendor the MongoDB dependency out.** Drop the Bitnami dependency
   from `Chart.yaml` and template a minimal `mongodb` StatefulSet +
   headless Service directly, mirroring `k8s/manifests/mongodb.yaml`.
   Rationale: the chart must render offline and in air-gapped CI; a
   remote 14.x.x floating dependency also makes renders
   non-reproducible.
2. **Mount real configs.** One ConfigMap carrying all 10 NF configs,
   sourced from the same content as `k8s/manifests/configmap.yaml`, with
   each NF mounting its own `<nf>.yaml` at `/etc/nextgcore/<nf>.yaml`
   via `subPath` and passing `args: ["-c", "/etc/nextgcore/<nf>.yaml"]`.
3. **Advertise the pod IP, not `0.0.0.0`.** Add the
   `rewrite-advertise-addr` initContainer (7 config-driven NFs) and set
   `AMF_SBI_ADDR` from `status.podIP` for the AMF, which reads that env
   var rather than its YAML (`amfd/src/lib.rs:811`).
4. **Correct the UPF.** Real config schema, the `wrapper.sh` ConfigMap,
   `/dev/net/tun` hostPath, `runAsUser: 0`, `POD_IP` for the N3/PFCP
   advertise address, and drop the dead `TUN_IP`/`TUN_PREFIX`.
5. **`tcpSocket` probes** everywhere, replacing all 18 `httpGet` probes.
6. **`clusterIP: None`** for the GTP-U/PFCP and NGAP Services, matching
   `deploy/eks/patches/headless-services.yaml`.
7. **Seed the subscriber DB.** Port the `mongodb-init` Job, using the
   idempotent upsert form (not `insertOne`).
8. **`udm-hnet-keys` Secret** from the repo development keys, so SUCI
   de-concealment has key material.

## Non-goals

- gNB/UE templates and the monitoring stack. The chart stays a
  *control-plane* deployment; the simulator remains on
  `k8s/`/`deploy/eks/`. `values.yaml` keeps `prometheus/grafana/jaeger`
  as disabled-by-default stubs rather than pretending to ship them.
- Multi-replica or HA anything. `replicas` stays 1; NF state is
  memory-only (issue #66).

## Verification

Each step below must pass, in order:

1. `helm lint deploy/helm/nextgcore` — clean.
2. `helm template` renders offline with no network access, and the
   rendered output has: 0 `httpGet`, 10 NF `volumeMounts`, a UPF config
   whose keys match `docker/rust/configs/5gc/upf.yaml`, and
   `clusterIP: None` on the GTP-U and NGAP Services.
3. `helm install` onto Kind, then `k8s/e2e-test.sh` against the release,
   plus a manual `ping 8.8.8.8` from the UE. Because the chart ships no
   gNB/UE, the simulator is supplied from `nextgsim/k8s/` pointed at the
   Helm-released AMF. Target: registration and PDU session establish,
   and the UPF gateway ping passes — i.e. the same control-plane
   assertions the base path reaches, no `FAIL` attributable to the
   chart.
4. The parity check that matters: diff the rendered NF Deployment
   pod-specs against `k8s/manifests/` for config mount, initContainers,
   probes, and advertise address. Anything the chart omits must be a
   documented non-goal, not an accident.

Rendering successfully is not evidence of working — the UDM regression
earlier in this session rendered `0 errors` while mounting the wrong
volume. Assert the final rendered values, and then install.
