# Introduction

**NextGCore** is a research-faithful 5G core network implemented in Rust. It provides **28 network function (NF) binaries** — a 5G Standalone (SA) control and user plane, an AI/analytics overlay, and a **4G/EPC core** (MME, HSS, SGW-C, SGW-U, PCRF, with `smfd`/`upfd` as PGW-C/PGW-U) — built on **23 shared libraries**, six of which are codecs generated from the 3GPP ASN.1.

The project has a **3GPP Release 15** baseline with selected **Release 16/17/18** features (RACS, MBS multicast, NSACF slice admission, LMF positioning, RedCap admission, XR QoS, SNPN, MINT disaster roaming, UAV Service-Level-AA per TS 23.256). Any 6G/Release-20 items (ISAC, federated learning, PQC, semantic communications) are **non-normative research prototypes** — no frozen Rel-20 Stage-3 specifications exist, and those modules are informed by TR 22.870 use cases only.

## At a Glance

| Metric | Value |
|---|---|
| Network Functions | 28 binaries (23 5GC/Rel-17+ NFs, 5 EPC NFs) + a WebUI |
| Shared libraries | 23 (6 generated ASN.1 codecs: NGAP, S1AP, NRPPa, LPP, NR RRC, LTE RRC) |
| Language | Rust (plus `aws-lc-sys`, the C crypto library under rustls) |
| OpenAPI specs on the site | 31 |
| 3GPP target | Rel-15 core, selected Rel-16/17/18 features |
| 6G / Rel-20 | Non-normative research prototypes only |

## Architecture

NextGCore follows the 3GPP Service-Based Architecture (SBA), organized in layers:

- **SBI control plane** — AMF, SMF, NRF, AUSF, UDM, UDR, PCF, NSSF, BSF communicating over HTTP/2 + JSON with TLS. NRF issues real ES256/RS256 JWS OAuth2 access tokens and verifies Client Credentials Assertions (CCA-JWS, ES256) per TS 33.501 §13.3.8.3. NGAP and S1AP messages are encoded and decoded by codecs generated from the TS 38.413 / TS 36.413 ASN.1 (`nextgcore-ngap-gen`, `nextgcore-s1ap-gen`), built with [NextgCoreLab/asn1-codegen](https://github.com/NextgCoreLab/asn1-codegen).
- **Routing and inter-PLMN security** — SCP for indirect communication and load balancing; SEPP for zero-trust N32c/N32f roaming with AES-128-GCM PRINS selective IE protection, per-PLMN trust scoring, and rate limiting (TS 33.501 / TS 29.573); a WebUI for subscriber management (MongoDB backend).
- **Data plane** — UPF with 5-tuple SDF filtering, QoS enforcement, GTP-U tunneling, and PFCP-driven usage reporting, connected to the control plane via NGAP / PFCP / GTP-U.
- **EPC (4G) layer** — MME, SGW-C, SGW-U, HSS, PCRF, and `smfd`/`upfd` as PGW-C/PGW-U. A real LTE UE attaches through nextgsim's eNB in the nightly CI. EPS-5GS interworking over N26 covers idle-mode context transfer and connected-mode handover in both directions. The dual 5G/LTE core is a deliberate, permanent design decision.
- **AI & analytics overlay** — NWDAF (4-layer analytics engine per TS 23.288: real-time anomaly detection → ONNX prediction → prescriptive recommendations → autonomous actions), DCCF data-collection coordination, EES edge enabler (TS 23.558), LMF positioning (TS 23.273), MBSMF multicast/broadcast (TS 23.247), NSACF slice admission, and PIN personal-IoT management (TS 23.542). The Rel-16+ NFs also include NEF, EASDF, TSCTSF and UCMF (RACS, TS 29.673/29.675).

Shared infrastructure includes `nextgcore-app` (`nf_common_init()` for common NF bootstrap) and `nextgcore-sbi` / `nextgcore-dbi`, which gate experimental 6G behavior behind a `6g-extensions` Cargo feature.

## Key Capabilities

- **5G SA procedures** — UE registration with SUCI concealment and 5G-AKA (TS 23.502 §4.2.2), PDU session establishment with PCC-driven QoS and PFCP (TS 23.502 §4.3.2), paging and Service Request from CM-IDLE and CM-CONNECTED (§4.2.3), UE- and network-initiated de-registration, Xn and N2 handover with path switch (§4.9.1), URSP delivery (TS 29.525 / TS 24.501 Annex D), and fail-closed SoR/UPU protection (TS 33.501 §6.14/6.15).
- **AI-native operation** — ML model lifecycle management with ONNX inference, intent-based automation, and event subscriptions for consumer NFs.
- **Cloud native** — Docker Compose for development (20 5GC NFs in `docker-compose.yml`, the EPC in `docker-compose-epc.yml`), Kind manifests, a Helm chart and an EKS deployment, Prometheus metrics and Jaeger tracing.

## Validation Honesty

Be clear about what the test results mean:

- NextGCore is validated with **matched simulators and 3GPP/RFC golden vectors**, plus Docker-based end-to-end tests that run nightly. It has **not** been certified by any third-party conformance body.
- A feature listed as "implemented" means the module exists and passes its tests — it is **not** a claim of full 3GPP conformance. Rel-15/16 NAS, SBI, and N4 are the most spec-faithful; some Rel-17/18 encodings are bespoke and simulator-only.
- All 6G/Rel-20 material is prototype research code and should never be treated as standards-conformant.

See the [Feature Matrix](../features.html) for per-feature status at this level of granularity.

## Where to Go Next

- [Project landing page](../index.html) — overview, workflows, and quick start
- [Feature Matrix](../features.html) — per-NF and per-feature implementation status
- [API Docs](../api.html) — the 31 OpenAPI specifications

To build from source, note that the Cargo workspace root is `nextgcore/src/` (not `nextgcore/`):

```bash
cd nextgcore/src
cargo build --workspace
cargo test --workspace
```

See the [Contributing guide](contributing.md) for prerequisites (the pinned Rust 1.95.0 toolchain, a C compiler and cmake) and Docker-based E2E testing.
