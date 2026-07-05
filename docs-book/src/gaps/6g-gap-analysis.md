# NextGCore — 6G Readiness and Missing-Component Register

**Standards baseline:** 3GPP Rel-18/19; ITU-R IMT-2030 (IMT for 2030 and beyond).

**Status.** This document reflects the current codebase. NextGCore ships **24 network-function binaries** (19 5G Core + 5 4G/EPC) and **17 shared libraries**, validated by unit tests and a matched-simulator Docker end-to-end run covering registration, PDU-session establishment, and user-plane data. Items in the 6G evolution register below are **non-normative research prototypes**: there is no frozen 3GPP Rel-20 / 6G Stage-3 specification to conform to. Each missing or partial component is itemized with a stable task ID and a tracked implementation issue.

---

## 1. Implemented network functions and libraries

The following inventory reflects what the codebase implements today. Behaviour is exercised by unit tests and the matched-simulator E2E; it is not third-party conformance-certified.

**5G Core — control plane:** AMF, SMF, PCF, AUSF, UDM, UDR, NSSF, NRF, BSF, SCP, SEPP.

**5G Core — user plane:** UPF (TUN device, GTP-U, PFCP session management).

**5G Core — analytics, edge, exposure and slicing:** NWDAF (`nextgcore-nwdafd`), NSACF (`nextgcore-nsacfd`), DCCF (`nextgcore-dccfd`), EES (`nextgcore-eesd`), LMF (`nextgcore-lmfd`), MB-SMF (`nextgcore-mbsmfd`), PIN (`nextgcore-pind`).

**4G/EPC interworking:** MME, HSS, SGW-C, SGW-U, PCRF.

**Shared libraries (17):** `nextgcore-sbi` (SBI HTTP/2), `nextgcore-pfcp`, `nextgcore-nas`, `nextgcore-ngap`, `nextgcore-s1ap`, `nextgcore-sctp`, `nextgcore-gtp`, `nextgcore-diameter`, `nextgcore-crypt`, `nextgcore-dbi`, `nextgcore-tun`, `nextgcore-ipfw`, `nextgcore-asn1c`, `nextgcore-app`, `nextgcore-proto`, `nextgcore-metrics`, `nextgcore-core`.

Security and service-based-architecture baselines already in place include SBI OAuth2 (`/oauth2/token`), TLS on the SBI plane, NRF-based registration/discovery, and wired NAS security.

---

## 2. Missing-component register (6G / Rel-18+ evolution)

The table itemizes each missing or partial capability required for the 6G / IMT-2030 evolution. Every row has a stable task ID and a tracked implementation issue.

- **Status — Missing:** not started; scoped in the linked issue.
- **Status — Partial:** a baseline or prototype exists; the linked issue scopes the remainder.
- **Status — Research:** dependent on 3GPP work that is not yet frozen; the linked issue captures a bounded design/spike.

| Task ID | Component | Missing / partial capability | Reference | Status | Tracking |
|---|---|---|---|---|---|
| NGC-6G-01 | AI-native analytics (NWDAF) | NWDAF NF exists; ML model serving and federation are scaffolding, not a working inference path | TS 23.288 | Partial | [#26](https://github.com/NextgCoreLab/nextgcore/issues/26) |
| NGC-6G-02 | Enhanced network slicing | Slice admission (NSACF) exists; no slice SLA monitoring or assurance loop | TS 28.530 / 28.541 | Missing | [#27](https://github.com/NextgCoreLab/nextgcore/issues/27) |
| NGC-6G-03 | Service-Based Architecture 2.0 | SBI transport beyond HTTP/2 (HTTP/3/QUIC or gRPC) | ITU-R IMT-2030 | Missing | [#15](https://github.com/NextgCoreLab/nextgcore/issues/15) |
| NGC-6G-04 | Edge computing (EASDF) | Edge Application Server Discovery, local breakout, latency-aware UPF selection | TS 23.548 | Missing | [#21](https://github.com/NextgCoreLab/nextgcore/issues/21) |
| NGC-6G-05 | Zero-trust security / PQC | mTLS and OAuth2 in place; post-quantum key exchange in the SBI TLS path is missing | TR 33.871 | Partial | [#17](https://github.com/NextgCoreLab/nextgcore/issues/17) |
| NGC-6G-06 | Digital twin | Read-only network-state export foundation for modelling and planning | ITU-R IMT-2030 | Missing | [#25](https://github.com/NextgCoreLab/nextgcore/issues/25) |
| NGC-6G-07 | Intent-driven management | Declarative intent → policy translation with a closed loop over analytics | ITU-R IMT-2030 | Missing | [#24](https://github.com/NextgCoreLab/nextgcore/issues/24) |
| NGC-6G-08 | Compute-aware networking | Compute/load-aware UPF selection in the SMF | Rel-19 study | Missing | [#20](https://github.com/NextgCoreLab/nextgcore/issues/20) |
| NGC-6G-09 | Network energy saving | Per-NF energy/utilisation metrics and an NF idle/sleep hook | TS 23.501 (NES) | Missing | [#22](https://github.com/NextgCoreLab/nextgcore/issues/22) |
| NGC-6G-10 | Non-terrestrial networks | NTN timing/constellation types exist in `nextgcore-proto` but are not wired into any NF procedure | Rel-17/18 NTN | Partial | [#18](https://github.com/NextgCoreLab/nextgcore/issues/18) |
| NGC-6G-11 | Deterministic networking (TSN) | TSCTSF control-plane NF and DS-TT/NW-TT translator scaffolding | TS 23.501 | Missing | [#23](https://github.com/NextgCoreLab/nextgcore/issues/23) |
| NGC-6G-12 | Integrated sensing (ISAC) | Core-side sensing data pipeline and exposure | ITU-R IMT-2030 | Research | [#16](https://github.com/NextgCoreLab/nextgcore/issues/16) |
| NGC-6G-13 | Network exposure (NEF) | Nnef_EventExposure and northbound monitoring/device-triggering APIs | TS 23.502 / 29.522 | Missing | [#19](https://github.com/NextgCoreLab/nextgcore/issues/19) |

Progress against this register is tracked on the [issue tracker](https://github.com/NextgCoreLab/nextgcore/issues); the code and the tracker are the source of truth.

---

## 3. Foundations for 6G evolution

The current architecture provides a solid base for the work above:

- **Pure Rust** across all NFs and libraries — memory and concurrency safety with predictable performance.
- **Tokio async runtime** throughout, enabling high-throughput, low-latency I/O.
- **Consistent finite-state-machine architecture** across NFs, so features extend systematically.
- **Modular library design** — 17 shared libraries with clear separation of concerns evolve independently.
- **Working user plane** — the UPF provides TUN, GTP-U, and PFCP session management.
- **Modern service-based stack** — HTTP/2 SBI client/server with NRF registration/discovery, OAuth2, and TLS.
- **Comprehensive NAS library** — 5GS and EPS message support with security contexts.
- **Metrics framework** — a Prometheus-compatible metrics library wired across NFs, with OpenTelemetry tracing.
