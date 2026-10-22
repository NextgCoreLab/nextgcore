# NextGCore Protocol Libraries - 6G Gap Analysis

## Overview

Analysis of 9 protocol libraries under `nextgcore/src/libs/` assessing 5G completeness and 6G readiness.

> **STALENESS NOTICE (updated 2026-10, pre-0.2.0):** This snapshot is badly out of date and, for NGAP/S1AP/PFCP/5GSM, misleading. The biggest change since 0.1.0: NGAP, S1AP, NRPPa, LPP, NR RRC and LTE RRC are now **codecs generated from the 3GPP ASN.1** (`nextgcore-ngap-gen`, `-s1ap-gen`, `-nrppa-gen`, `-lpp-gen`, `-nr-rrc-gen`, `-lte-rrc-gen`, built by NextgCoreLab/asn1-codegen; each `asn/PROVENANCE.md` names the spec version). The hand-written S1AP codec (#555, #560), NRPPa codec (#527), LPP codec and the UPER engine only it used (#563) are deleted, and so are the E1AP/F1AP/XnAP modules (#459). `nextgcore-s1ap` now holds only the typed S1AP structs mmed works with. `nextgcore-ngap` and the APER engine `nextgcore-asn1c` remain, with their hand-written builders kept as test oracles for the generated codec; deleting them is tracked in #417. Other changes since 0.1.0: every NAS decoder returns `Err` on short input (#612), fixed-layout IEs decode within their length (#631), TV IEs are coded as TV (#639); the PFCP Cause table is complete (#128) and 65 IE numbers were corrected (#327); the SCTP userspace backend carries the PPID verbatim with a patched `sctp-proto` in `src/vendor/` (#468), the kernel server reassembles partial deliveries (#517), and the dead userspace client was removed (#441); Diameter rejects a Message Length below 20 (#617); SBI has a feature-gated HTTP/3 prototype (`http3`, #28) and hybrid X25519MLKEM768 TLS (`pqc-tls`, #30).
>
> State at 0.1.0 (2026-07): `nextgcore-ngap` is NOT a stub - its hand-written builders/parsers drove the live N2 interface then. `nextgcore-s1ap` had builder/parser/ie/types, not a 6-LOC stub. `nextgcore-nas` implements 5GSM (`FiveGsmMessage`: PDU Session Establishment/Modification/Release) in addition to 5GMM (`FiveGmmMessage`). `nextgcore-pfcp` (~8,900 LOC) has grouped IEs (`CreatePdr/CreateFar/CreateQer/CreateUrr/CreateBar`) and Session Establishment/Modification/Deletion. `nextgcore-sbi` has working OAuth2 (`oauth.rs`), TLS (`tls.rs`), SCP (`scp.rs`), heartbeat, multipart, and gRPC modules. The table and per-library sections below are a historical baseline.

| Library | Maturity | LOC (approx) | Tests | 5G Coverage | 6G Ready |
|---------|----------|--------------|-------|-------------|----------|
| nextgcore-sbi | High | ~1800 | 5 | 70% | Low |
| nextgcore-nas | Medium | ~3500 | 6+ | 40% | None |
| nextgcore-ngap | High | ~13,300 | 20+ | typed NGAP structs; hand-written builders/parsers kept as test oracles (live N2 is `nextgcore-ngap-gen` since 0.2.0) | Low |
| nextgcore-gtp | Medium | ~2200 | 8+ | 55% | None |
| nextgcore-pfcp | Low | ~1200 | 4+ | 25% | None |
| nextgcore-sctp | High | ~2750 | 60+ | 85% | Low |
| nextgcore-s1ap | Medium | ~5,700 | - | typed S1AP structs only since #514; codec is `nextgcore-s1ap-gen` | None |
| nextgcore-diameter | High | ~3800 | 15+ | 75% | N/A |
| nextgcore-asn1c | High | ~3200 | 20+ | 65% | None |

---

## 1. nextgcore-sbi (Service Based Interface)

**Spec**: 3GPP TS 29.500 series

### What is implemented
- HTTP/2 client (`SbiClient`) with connection pooling and GET/POST/PUT/DELETE/PATCH
- HTTP/2 server (`SbiServer`) with `SbiRequestHandler` trait
- `ProblemDetails` (RFC 7807)
- 52 `SbiServiceType` variants, 37 `NfType` variants
- 42 `SbiAppError` variants with HTTP status mapping

### What was missing at snapshot time (now largely landed)
- **TLS/mTLS**: `tls.rs` client/server config
- **OAuth2 token exchange**: `oauth.rs` (`OAuth2Client`, `TokenCache`, `JwksCache`, `AccessTokenRequest`/`AccessTokenResponse`)
- **SCP routing**: `scp.rs`
- **NF heartbeat**: `heartbeat.rs`
- Also added: `multipart.rs`, `grpc.rs`, `pubsub.rs`, `overload.rs`, `security.rs`

### 6G gaps
- No **SBI 2.0** / gRPC / service mesh support
- No **event-driven / pub-sub** messaging

---

## 2. nextgcore-nas (Non-Access Stratum)

**Spec**: 3GPP TS 24.501 (5GS), TS 24.301 (EPS)

### What is implemented
- 24 5GMM message type variants; full encode/decode for 4 (RegistrationRequest/Accept/Reject, AuthenticationRequest)
- Full NIA1/2/3 and NEA1/2/3 security algorithms
- MobileIdentity (SUCI/5G-GUTI/IMEI/5G-S-TMSI/IMEISV)

### Status update (2026-07)
- 5GMM (`FiveGmmMessage`) codec coverage expanded well beyond the original 4 messages (registration/auth/security-mode/dereg/service/config-update builders present)
- **5GSM**: implemented (`FiveGsmMessage`: PDU Session Establishment Request/Accept/Reject, Modification Request/Command, Release)
- EPS NAS: still types-only (no full EPS encoder/decoder)

### 6G gaps
- No AI/ML capability NAS IEs
- No ISAC NAS signaling
- No sub-THz band parameters

---

## 3. nextgcore-ngap

At 0.1.0: ~13,300 LOC across `builder.rs`, `parser.rs`, `ie.rs`, `types.rs`, `transfer.rs`, `mbs_transfer.rs`, driving the live N2 interface (alongside the APER core in `nextgcore-asn1c/src/ngap/`). Since then amfd, smfd and mbsmfd build and decode NGAP with the generated `nextgcore-ngap-gen` codec; the hand-written builders/parsers are the oracles its tests compare against (#417).

---

## 4. nextgcore-gtp (GPRS Tunneling Protocol)

12 typed GTPv2-C message builders, 65 IE types. GTPv1-U G-PDU implemented.

Missing: Many GTPv2-C messages, no GTP-U extension header support, no TEID pool.

---

## 5. nextgcore-pfcp (Packet Forwarding Control Protocol)

~8,900 LOC. Session Establishment/Modification/Deletion plus grouped IEs implemented (`CreatePdr`, `CreateFar`, `CreateQer`, `CreateUrr`, `CreateBar` in `types.rs`; `create_pdrs`/etc in `message.rs`). UPF decodes and applies these on the live N4 path.

---

## 6. nextgcore-sctp -- Most Production-Ready

Dual implementation (pure Rust `sctp-proto` over UDP, the default; native kernel SCTP behind the `kernel` feature, which amfd and mmed expose as `kernel-sctp`). ~60 unit tests. Full lifecycle management.

Missing: Multi-homing, PR-SCTP. 6G: `quic.rs` defines a QUIC transport API, but it is a placeholder with no QUIC library behind it.

---

## 7. nextgcore-s1ap

At 0.1.0: ~5,700 LOC (`builder.rs`, `parser.rs`, `ie.rs`, `types.rs`). Since #514 the crate holds only the typed message structs, Cause/Criticality values and the `S1apMessage` union (`cause.rs`, `error.rs`, `message.rs`, `types.rs`); every S1AP PDU is encoded and decoded by `nextgcore-s1ap-gen`.

---

## 8. nextgcore-diameter

Full RFC 6733 base protocol. 7 interface modules (S6a, Gx, Gy, Rx, Cx, SWx, S6b) with message builders.

At the 2026-02-07 snapshot: no transport layer and no peer state machine. Both exist now (`transport.rs`, `peer.rs`, plus `restart.rs` for Origin-State-Id restart detection, #286/#366, and alternate-peer failover, #332).

---

## 9. nextgcore-asn1c (ASN.1 Codec)

Full APER encoder/decoder (`per.rs`) and the hand-written NGAP module (`src/ngap/`). Its S1AP module is gone (#555), as is the NRPPa module (#527). Production code no longer calls it directly (#576); it is reached through `nextgcore-ngap` and as a test dependency, until #417 deletes it.

Missing: XnAP/F1AP/E1AP codecs.

The earlier hand-written E1AP/F1AP/XnAP modules were removed (#457): they were not
ASN.1 PDUs (no PDU CHOICE, open type or ProtocolIE-Container) and had no consumers.
A future codec should be generated from the 3GPP ASN.1 (TS 38.463 / 38.473 / 38.423)
with the forked compiler, as `nextgcore-ngap-gen` does for NGAP (#417).

---

## Summary: Critical Gaps

### Priority 1 - Complete 5G Foundation

| Gap | Library | Impact |
|-----|---------|--------|
| Complete NAS 5GMM encode/decode (20 remaining msgs) | nextgcore-nas | Blocks registration/mobility |
| ~~Implement 5GSM (PDU Session messages)~~ (done before 0.1.0: `FiveGsmMessage`) | nextgcore-nas | — |
| ~~PFCP grouped IEs (PDR/FAR/QER/URR) + Session Modification~~ (done before 0.1.0) | nextgcore-pfcp | — |
| ~~NGAP message builders~~ (done: generated codec, `nextgcore-ngap-gen`) | nextgcore-ngap | — |
| ~~SBI TLS/mTLS and OAuth2~~ (done: `tls.rs`, `oauth.rs`, the `production` SBI profile) | nextgcore-sbi | — |

### Priority 2 - 6G Protocol Evolution

| Gap | Library | Description |
|-----|---------|-------------|
| SBI 2.0 / gRPC support | nextgcore-sbi | Service mesh, event-driven architecture |
| QUIC transport option | nextgcore-sctp | Potential SCTP replacement in 6G |
| UPF programmability (P4-like) | nextgcore-pfcp | In-network computing |
| XnAP/F1AP/E1AP codecs | nextgcore-asn1c | RAN disaggregation support |
