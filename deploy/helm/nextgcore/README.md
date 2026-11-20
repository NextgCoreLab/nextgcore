# NextGCore 5G Core — Helm chart

Deploys the **control plane**: 10 NFs (NRF, AMF, SMF, UPF, AUSF, UDM, UDR, PCF,
NSSF, BSF) plus MongoDB and its subscriber-seeding Job.

## Scope

| Included | Not included |
|---|---|
| 10 control-plane NFs | gNB / UE simulator (`nextgsim/k8s/`) |
| MongoDB + subscriber seed Job | Prometheus / Grafana / Jaeger (`k8s/monitoring/`) |
| UPF data plane (TUN + NAT) | The other 18 NFs (SCP, SEPP, NWDAF, LMF, the EPC NFs, …) |

For a full stack including the simulator, use `k8s/` (Kind) or `deploy/eks/`
(EKS). Those are the paths the E2E suite targets directly.

## Install

```bash
# The UPF needs a privileged pod for its TUN device.
kubectl create namespace nextg-system
kubectl label namespace nextg-system \
  pod-security.kubernetes.io/enforce=privileged --overwrite

# The NRF and each NF's TLS Secret (#1617, below): prints the version.
ver="$(deploy/helm/nf-tls-secrets.sh nextg nextg-system \
  --set global.siteId=<a-name-unique-to-this-cluster>)"

helm install nextg deploy/helm/nextgcore -n nextg-system --wait \
  --set global.siteId=<a-name-unique-to-this-cluster> \
  --set global.nrfTls.secretVersion="$ver"
```

Set `global.siteId` (#753, #1617); the render fails without it unless every
NF's `nfInstanceId` is pinned. It salts each NF's derived `nfInstanceId`: the
AMF's is what the UDM keys the UE's UECM registration on, and each NF's
certificate names its own, so it must stay the same across upgrades and
restarts. (The chart used to fall back to the kube-system namespace UID through
`lookup`, which is empty under `helm template` and GitOps renderers, so the
certificates would name IDs `helm install` does not pin.)

## NF -> NRF TLS

The NRF serves its SBI over TLS and asks each client for a certificate (client
authentication optional). NFRegister, NFUpdate and NFDeregister bind to the
verified certificate identity: the URI SAN `urn:uuid:<nfInstanceId>` and the
RFC 9310 NFTypes extension of TS 33.310 §6.1.3c.3. Every NF of the chart dials
`https://<release>-nrf.<namespace>.svc.cluster.local:7777` presenting its own
certificate, and pins the `nfInstanceId` it names.

Each of `nrf amf smf ausf udm udr pcf nssf bsf` mounts Secret
`nf-tls-<nf>-<global.nrfTls.secretVersion>` at `/etc/nextgcore/certs` (mode
0440 to the pod's fsGroup), holding `ca.crt`, `<nf>.crt` and `<nf>.key`. The
chart creates no Secret, and a missing one keeps the pod in ContainerCreating
rather than letting it start without an identity. The IDs and types to issue
for are in the rendered ConfigMap `<release>-nf-identities`:

```bash
helm template nextg deploy/helm/nextgcore -n nextg-system --set global.siteId=<site> \
  | yq 'select(.metadata.name == "nextg-nf-identities").data."nf-identities.txt"'
```

- **Development:** `deploy/helm/nf-tls-secrets.sh <release> <namespace> [values
  flags]` renders the chart, issues the dev PKI
  (`docker/rust/certs/generate-dev-certs.sh`) for that table and creates the
  Secrets of a new version (or keeps the current one), then prints the version.
  The CA key stays in a temporary directory that is deleted on exit. Re-run it
  after changing `global.siteId`, a `nfInstanceId`, the release name or the
  namespace: the IDs change, so the certificates must too.
- **Production, and any use of `global.sbiProfile=production` with OAuth2:**
  issue each certificate from your own PKI. Since #1667 an NF needs a proven
  identity at the NRF before NFRegister, and that proof is this certificate, so
  each NF needs its own: URI SAN `urn:uuid:<nfInstanceId>` of its line,
  RFC 9310 NFTypes `<nfType>`, keyUsage digitalSignature, EKU serverAuth and
  clientAuth, validity 3 years or less. Set `global.nrfTls.serverName` to
  `""` so each NF verifies the NRF as the Service FQDN it dials, and issue the
  NRF's certificate for that FQDN: the dev default `nrf` accepts any NRF
  certificate of your CA that names `DNS:nrf`, which with one CA across sites
  is every site's NRF. Create `nf-tls-<nf>-<version>` (any 16 hex digits) with keys
  `ca.crt`, `<nf>.crt`, `<nf>.key`, and set `global.nrfTls.secretVersion`. Never
  put the CA key in the cluster.
- **Superseded versions** each still hold a private key. Once every pod runs on
  the new version, delete the others with
  `k8s/nf-tls-secrets.sh --prune <namespace> <version>`. It keeps any version a
  pod or workload template still mounts, and refuses (deleting nothing) when
  `<version>` itself is not in the namespace or the namespace's workloads
  cannot be listed. Do not run it during a `helm upgrade` or `helm rollback`:
  it reads what mounts each version once, then deletes, so a rollback to a
  revision whose ReplicaSet was at 0 in between loses that revision's Secrets
  (re-issue them with `nf-tls-secrets.sh`).

Each NF runs one pod (`replicas > 1` fails the render) with strategy Recreate:
two pods under one `nfInstanceId` are one NF instance at the NRF, and a rolling
update's old pod would deregister the ID its replacement just registered.

Then follow the `NOTES.txt` output — it prints the one out-of-band step (the
SUCI de-concealment Secret) and the checks worth running.

No `helm dependency build` is needed: the chart vendors nothing and renders
offline.

## Verifying it actually works

Rendering is not evidence. Two checks catch the failures that hide behind a
green `helm install`:

```bash
# 1. Every NF must advertise a routable pod IP, never 0.0.0.0. The NRF serves
#    TLS; nrf.crt names DNS:nrf (global.nrfTls.serverName).
kubectl exec -n nextg-system deploy/nextg-nrf -- \
  curl -s --http2 --cacert /etc/nextgcore/certs/ca.crt \
  --resolve nrf:7777:127.0.0.1 https://nrf:7777/nnrf-nfm/v1/nf-instances

# 2. No NF may have fallen back to built-in defaults. This is a WARN, and the
#    pod still reports Ready, so it is easy to miss.
for nf in nrf amf smf ausf udm udr pcf nssf bsf; do
  kubectl logs -n nextg-system deploy/nextg-$nf --tail=80 2>&1 \
    | grep -H --label="$nf" 'Using defaults'
done
```

## Values worth knowing

| Key | Default | Why you would change it |
|---|---|---|
| `upf.dataPlane.enabled` | `true` | `false` for control-plane-only where the node cannot provide `/dev/net/tun` (Kind on macOS). No user plane: a UE ping will not work. |
| `mongodb.persistence.enabled` | `true` | `false` on clusters with no CSI driver, where a PVC stays Pending. Data is lost on restart. |
| `mongodb.enabled` / `mongodb.externalUri` | `true` / `""` | Point at an existing MongoDB. The seed Job still runs against it. |
| `global.siteId` | `""` | Set it, always (see Install): the render fails while it is empty and any NF's id is derived. Salts every derived NF instance id. |
| `<nf>.nfInstanceId` | `""` | Pin an NF's id outright, e.g. to match a certificate your PKI issued. `<nf>.replicas` must stay 1: every pod would share the id, and the render fails on purpose. |
| `global.nrfTls.secretVersion` | `""` | The nf-tls Secret version the pods mount (see NF -> NRF TLS). Empty: `nf-tls-<nf>`, which nothing creates. |
| `global.nrfTls.serverName` | `nrf` | The name the NRF's certificate is checked against (the dev `nrf.crt` names `DNS:nrf`). `""`: the Service FQDN. |
| `amf.ueContextStore.enabled`, `amf.ueContextStore.dbUri` | `false`, `""` | #686: the AMF stores every registered UE's context in MongoDB and restores it after a restart, so a returning UE keeps its 5G-GUTI, security context and PDU sessions. `dbUri` empty means the chart's MongoDB. The records hold NAS keys in clear, so MongoDB needs the same access control as the UDR's subscriber keys. |
| `udm.durableState.enabled`, `udm.durableState.type` | `false`, `pvc` | #1885: udmd's state file (#1836), so its SDM subscriptions, UDR am-data subscriptions and queued am-data changes survive a restart. See "UDM durable state" below. |
| `global.plmn` | 999-70 | Must match the simulator's PLMN. #2069: `mcc` (3 digits) and `mnc` (2 or 3) are quoted strings, rendered quoted; pass them with `--set-string`. A number is refused, since its leading zeros are already lost (an unquoted `070` is even octal 56) and MNC 70 and 070 are different PLMNs. `subscriber.imsi` must start with them. |
| `nrf.nfSetAllowlist` | unset (derived) | #2052: rendered as `nrf.nf_set_allowlist` (#1719, #2035). Unset, one entry for the chart's AMF: the AMF Set NF Set ID of its GUAMI (`global.plmn`, `amf.config.amfId`; by default `set001.region02.amfset.5gc.mnc070.mcc999`), type AMF, and the AMF's `nfInstanceId` only. Under `global.sbiProfile=production` the NRF refuses an AMF's GUAMIs without such an entry. Set a list of `{nf_set_id, nf_types, nf_instance_ids}` to add other AMFs or NF sets; it replaces the derived entry, so keep the chart's AMF in it (the render fails otherwise). Under `global.sbiProfile=production` every entry must name its `nf_instance_ids` (#2069): an id-less entry would admit any certificate of its type. |
| `global.sbiProfile` | `dev` | #2069: read as the NFs read it: `production`/`prod` (any case) or `dev`/`development`/`insecure`/`local`/`test`; any other value fails the render. Only a key left out takes the default `dev`, and a bare `sbiProfile:` (null) in a values file counts as left out, because helm drops a null key before the chart sees it. So it renders `dev`; to mean production, write `sbiProfile: production` (#2136). an empty value (`--set global.sbiProfile=` with an unset variable) or a non-string (`false`, `0`) also fails the render, because the NFs read each of those as production (R41 on #2114). #2052: under `dev` the NSSF config renders `oauth2.require: false` (this chart issues no tokens). Under `production` it renders `require: true`, so the NSSF verifies Bearer tokens against the NRF's JWKS (TS 33.501 §13.4.1) like the production profile's other NFs; the NRF must issue tokens (`global.sbiProfile=production` with OAuth2, above). |
| `subscriber.*` | test IMSI | Must match the UE's USIM config. |
| `amf.service.headless`, `upf.service.headless` | `true` | Leave alone. NGAP and GTP-U are UDP; kube-proxy's per-flow balancing plus a conntrack timeout breaks both. |
| `<nf>.service.type` | `ClusterIP` | Leave alone (#1365). The SBI and `/metrics` are unauthenticated in the dev profile; NodePort or LoadBalancer opens them on every node IP or to the load balancer's audience. Reach a Service from a workstation with `kubectl -n <ns> port-forward svc/<release>-nrf 7777:7777`, which listens on 127.0.0.1. CI renders the defaults and fails on any non-ClusterIP Service. |

## UDM durable state

Off by default: udmd runs memory-only and logs `no UDM state file` at start.
`--set udm.durableState.enabled=true` mounts a volume at
`udm.durableState.mountPath` (`/var/lib/nextgcore`) and sets
`NEXTGCORE_UDM_STATE_FILE` to `<mountPath>/<fileName>`
(`/var/lib/nextgcore/udm-state.json`). The pod's `fsGroup: 999` makes it writable
by the image's non-root user. No securityContext changes, and nothing is
exposed.

| `udm.durableState.type` | Volume | Survives |
|---|---|---|
| `pvc` (default) | PersistentVolumeClaim `<release>-udm-state` (`persistence.size` 1Gi, `persistence.storageClass` empty = the cluster default, `persistence.accessMode` ReadWriteOnce), or `persistence.existingClaim` | a container restart and pod re-creation (a delete, a rollout, a node loss) |
| `emptyDir` | an emptyDir | a container restart only. A deleted, evicted or rescheduled pod starts with no state. For clusters with no provisioner. |

One writer per file: the state is one udmd instance's. With durable state on,
the render fails for `udm.replicas > 1` and for a `ReadWriteMany` or
`ReadOnlyMany` claim. The Deployment is `Recreate`, so a rollout stops the old pod
before the new one mounts the claim. `Recreate` does not cover a `kubectl delete
pod` or a node drain: the replacement starts while the old pod terminates, and on
the same node a ReadWriteOnce claim lets both mount it for the grace period.
`persistence.accessMode=ReadWriteOncePod` closes that window where the CSI driver
supports it.

The chart's claim is deleted with the release (`helm uninstall`). To keep the
state across a reinstall, create the claim yourself and set
`persistence.existingClaim`. CI renders the chart with durable state off, `pvc`
and `emptyDir` (`deploy/check_udm_state_volume.py`) and checks both refusals.

## Verified

When the chart was fixed (#136): against Kind, `helm install --wait` then the simulator from `nextgsim/k8s/`
pointed at the release: **74 passed / 0 failed / 6 skipped** on
`k8s/e2e-test.sh`, and 0% packet loss from the UE to 8.8.8.8 through the GTP-U
tunnel. Design notes and the full defect list are in
`specs/fix-helm-chart-control-plane.md`.
