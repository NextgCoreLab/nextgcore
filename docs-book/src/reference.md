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

The shipped configs expose Prometheus metrics on port 9090 (`/metrics`), and NFs export
OpenTelemetry traces to `OTEL_EXPORTER_OTLP_ENDPOINT` (Jaeger in the Docker/K8s stacks). See
[Observability & Troubleshooting](observability.md).

## Validation status

E2E validation runs nightly against the matched nextgsim simulators: 5G registration, PDU
session, paging, Service Request, de-registration and UDM-triggered re-registration, each with a
UE→UPF ping through the GTP-U tunnel, and an LTE attach with a ping through the default bearer
(see `docs/ci-and-release.md`). This proves internal consistency of the pair — it is **not**
third-party conformance certification. 6G/Rel-20 items are research prototypes; no frozen
Rel-20 Stage-3 specs exist.
