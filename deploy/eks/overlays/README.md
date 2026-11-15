# Demo overlays (nextgcore#1395, nextgsim#458)

Every demo runs on EKS from its own kustomize overlay here, in its own
namespace `nextg-demo`. None of them touches the shipped profiles: those carry no
`demo:` block, and CI fails if one appears (`deploy/check_no_demo_block.py`).

```
deploy/eks/overlays/
├── demo/               the demo-OFF base: the 6G profile, in nextg-demo
│   ├── kustomization.yaml
│   └── namespace.yaml
└── demo-<key>/         one demo: the base plus only that demo's changes
    ├── kustomization.yaml
    ├── toggles.yaml    the nextg-demo-toggles ConfigMap (below)
    ├── *.yaml          extra NFs, a second gNB, config patches (optional)
    └── scenario.sh     the demo's seeded acceptance run (optional, executable)
```

**Why not `k8s/overlays/`?** The overlays include the 6G EKS profile, which
includes `k8s/`. kustomize rejects an overlay under `k8s/` that reaches `k8s/`:
"cycle detected: candidate root ... contains visited root".

## Running one

```bash
k8s/demo-check.sh off off           # the demo-off control (this directory's demo/)
k8s/demo-check.sh <key> <mode>      # deploy/eks/overlays/demo-<key>, mode <mode>
k8s/demo-check.sh <key> off         # demo-<key>'s topology and scenario, no demo: block
DEMO_VARIANT=<arm> k8s/demo-check.sh <key> <mode>   # a scenario arm that is not a mode
```

`<key> off` is a demo's own demo-off arm: the post-render drops the toggles
and refuses a `demo:` block anywhere, and demo-check makes the demo-off
assertions (no banner, no `[demo:` line, no `nextg_demo_enabled`). No demo can
register a mode named `off`: `nextgcore-demo` and `nextgsim-demo` refuse it. `DEMO_VARIANT` reaches `scenario.sh` (for
example a fault it injects), is recorded in `verdict.txt`, and the artefacts
go to `<key>/<mode>+<variant>/`.

`k8s/demo-check.sh` does the whole run:

1. deploys the overlay with `PROFILE=demo deploy/eks/deploy-eks.sh`;
2. runs the base e2e (`PROFILE=demo deploy/eks/e2e-internet.sh`) and the
   demo's `scenario.sh`, if it has one;
3. captures the logs, `/metrics`, events and images into
   `/tmp/eks-val/demos/<key>/<mode>/<UTC>/`;
4. prints PASS or FAIL;
5. deletes the namespace.

Read its header for the knobs (`KUBE_CONTEXT`, `KEEP`, image tags).

## Writing `demo-<key>/`

`kustomization.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../demo
  - toggles.yaml
  # - senfd.yaml          # an extra NF the demo needs, ClusterIP only
patches: []               # config or Deployment patches only this demo needs
```

`toggles.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nextg-demo-toggles
data:
  key: <key>                     # equals the directory's <key>
  targets: amf.yaml gnb.yaml     # config files (ConfigMap data keys) that get the block
```

### What the post-render does with the toggles

`deploy/eks/profiles/demo/demo_toggles.py` runs as the profile's post-render,
after the 6G profile's own. It merges this block into every target:

```yaml
demo:
  enabled: true
  <key>:
    enabled: true
    mode: <mode>      # from the run (demo-check.sh <key> <mode>), not the overlay
```

It then drops the toggles ConfigMap. So one overlay serves every mode.

### Validation

- **At render, by the post-render.** It refuses a mismatched key, a missing
  mode, a target that isn't in exactly one ConfigMap, or a config that already
  has a `demo:` block. It also refuses a `demo:` block anywhere in the demo-off
  render.
- **At startup, by the NF itself.** Whether the key and mode are valid is the
  NF's call: an unknown one fails startup (`nextgcore-demo`, `nextgsim-demo`),
  and `demo-check.sh` then reports a FAIL.

### Rules (the #458 convention)

- **ClusterIP only.** CI renders every `demo*` overlay through
  `deploy/check_no_exposure.py`. A NodePort, LoadBalancer, hostPort,
  hostNetwork or Ingress fails it.
- **No new runtime endpoint on a nextgcore NF.** Modes switch by config plus
  restart, which is a new `demo-check.sh` run.
- **`scenario.sh` contract.** It gets `NAMESPACE`, `DEMO_KEY`, `DEMO_MODE`,
  `DEMO_VARIANT` (empty unless set) and `OUT` in its environment, and `KUBECONFIG` points at the run's cluster. Exit 0
  means the demo's assertions held. Write anything it captures under `$OUT`.
