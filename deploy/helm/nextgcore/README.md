# NextGCore 5G Core — Helm chart

Deploys the **control plane**: 10 NFs (NRF, AMF, SMF, UPF, AUSF, UDM, UDR, PCF,
NSSF, BSF) plus MongoDB and its subscriber-seeding Job.

## Scope

| Included | Not included |
|---|---|
| 10 control-plane NFs | gNB / UE simulator (`nextgsim/k8s/`) |
| MongoDB + subscriber seed Job | Prometheus / Grafana / Jaeger (`k8s/monitoring/`) |
| UPF data plane (TUN + NAT) | The 16 non-core NFs (SCP, SEPP, NWDAF, LMF, …) |

For a full stack including the simulator, use `k8s/` (Kind) or `deploy/eks/`
(EKS). Those are the paths the E2E suite targets directly.

## Install

```bash
# The UPF needs a privileged pod for its TUN device.
kubectl create namespace nextg-system
kubectl label namespace nextg-system \
  pod-security.kubernetes.io/enforce=privileged --overwrite

helm install nextg deploy/helm/nextgcore -n nextg-system --wait
```

Then follow the `NOTES.txt` output — it prints the one out-of-band step (the
SUCI de-concealment Secret) and the checks worth running.

No `helm dependency build` is needed: the chart vendors nothing and renders
offline.

## Verifying it actually works

Rendering is not evidence. Two checks catch the failures that hide behind a
green `helm install`:

```bash
# 1. Every NF must advertise a routable pod IP, never 0.0.0.0.
kubectl exec -n nextg-system deploy/nextg-nrf -- \
  curl -s --http2-prior-knowledge \
  http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances

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
| `global.plmn` | 999-70 | Must match the simulator's PLMN. |
| `subscriber.*` | test IMSI | Must match the UE's USIM config. |
| `amf.service.headless`, `upf.service.headless` | `true` | Leave alone. NGAP and GTP-U are UDP; kube-proxy's per-flow balancing plus a conntrack timeout breaks both. |

## Verified

Against Kind, `helm install --wait` then the simulator from `nextgsim/k8s/`
pointed at the release: **74 passed / 0 failed / 6 skipped** on
`k8s/e2e-test.sh`, and 0% packet loss from the UE to 8.8.8.8 through the GTP-U
tunnel. Design notes and the full defect list are in
`specs/fix-helm-chart-control-plane.md`.
