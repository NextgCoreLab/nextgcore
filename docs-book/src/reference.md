# Features & APIs

Reference material lives in three generated/maintained artifacts on the docs site:

## Supported-Features Matrix

The [feature matrix](../features.html) lists, per Network Function, the services actually served,
key procedures, the governing 3GPP spec, and an honest status badge:

- **implemented** — wired into the live dispatch path and handled
- **partial** — surface exists but some operations are stubbed or gated
- **prototype** — non-normative / off-wire research code (6G, NTN, etc.)

The matrix is extracted from the live router/handler code, not from claims.

## OpenAPI Specifications

The [API index](../api.html) serves 31 OpenAPI specs from `docs/openapi/*.yaml`, covering the
SBI service surfaces (Namf, Nsmf, Nudm, Npcf incl. UE Policy, Nausf incl. SoR/UPU protection,
Nnrf incl. the `/oauth2/token` endpoint, and more). Regenerate the index with:

```bash
bash docs/scripts/update-api-docs.sh
```

## Observability

Every NF exposes Prometheus metrics on port 9090 (`/metrics`) and OpenTelemetry traces
(Jaeger in the Docker/K8s stacks). The Docker Compose stack wires both up automatically.

## Validation status

E2E validation runs against the matched NextGSim UE/gNB simulator (84/84 suite, including a
UE→UPF GTP-U data-plane path). This proves internal consistency of the pair — it is **not**
third-party conformance certification. 6G/Rel-20 items are research prototypes; no frozen
Rel-20 Stage-3 specs exist.
