# NextGCore Protocol Libraries - 6G Gap Analysis

## Overview

Analysis of 9 protocol libraries under `nextgcore/src/libs/` assessing 5G completeness and 6G readiness.

> **STALENESS NOTICE (updated 2026-07):** This snapshot is badly out of date and, for NGAP/S1AP/PFCP/5GSM, misleading. `nextgcore-ngap` is NOT a stub - it is ~13,300 LOC (`builder.rs`/`parser.rs`/`ie.rs`/`types.rs`/`transfer.rs`/`mbs_transfer.rs`) driving the live N2 interface. `nextgcore-s1ap` is ~5,700 LOC (builder/parser/ie/types), not a 6-LOC stub. `nextgcore-nas` implements 5GSM (`FiveGsmMessage`: PDU Session Establishment/Modification/Release) in addition to 5GMM (`FiveGmmMessage`). `nextgcore-pfcp` (~8,900 LOC) has grouped IEs (`CreatePdr/CreateFar/CreateQer/CreateUrr/CreateBar`) and Session Establishment/Modification/Deletion. `nextgcore-sbi` has working OAuth2 (`oauth.rs`), TLS (`tls.rs`), SCP (`scp.rs`), heartbeat, multipart, and gRPC modules. The table and per-library sections below are a historical baseline.

| Library | Maturity | LOC (approx) | Tests | 5G Coverage | 6G Ready |
|---------|----------|--------------|-------|-------------|----------|
| nextgcore-sbi | High | ~1800 | 5 | 70% | Low |
| nextgcore-nas | Medium | ~3500 | 6+ | 40% | None |
| nextgcore-ngap | High | ~13,300 | 20+ | live N2 codec (builder/parser/IE/transfer) | Low |
| nextgcore-gtp | Medium | ~2200 | 8+ | 55% | None |
| nextgcore-pfcp | Low | ~1200 | 4+ | 25% | None |
| nextgcore-sctp | High | ~2750 | 60+ | 85% | Low |
| nextgcore-s1ap | Medium | ~5,700 | - | S1AP builder/parser/IE/types | None |
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

~13,300 LOC across `builder.rs`, `parser.rs`, `ie.rs`, `types.rs`, `transfer.rs`, `mbs_transfer.rs`. Full NGAP message builders/parsers driving the live N2 interface (alongside the APER core in `nextgcore-asn1c/src/ngap/`).

---

## 4. nextgcore-gtp (GPRS Tunneling Protocol)

12 typed GTPv2-C message builders, 65 IE types. GTPv1-U G-PDU implemented.

Missing: Many GTPv2-C messages, no GTP-U extension header support, no TEID pool.

---

## 5. nextgcore-pfcp (Packet Forwarding Control Protocol)

~8,900 LOC. Session Establishment/Modification/Deletion plus grouped IEs implemented (`CreatePdr`, `CreateFar`, `CreateQer`, `CreateUrr`, `CreateBar` in `types.rs`; `create_pdrs`/etc in `message.rs`). UPF decodes and applies these on the live N4 path.

---

## 6. nextgcore-sctp -- Most Production-Ready

Dual implementation (pure Rust + kernel). ~60 unit tests. Full lifecycle management.

Missing: Multi-homing, PR-SCTP. 6G: No QUIC transport alternative.

---

## 7. nextgcore-s1ap

~5,700 LOC (`builder.rs`, `parser.rs`, `ie.rs`, `types.rs`) - S1AP message builders/parsers, no longer a stub.

---

## 8. nextgcore-diameter

Full RFC 6733 base protocol. 7 interface modules (S6a, Gx, Gy, Rx, Cx, SWx, S6b) with message builders.

**Critical missing**: No transport layer (TCP/SCTP), no peer state machine.

---

## 9. nextgcore-asn1c (ASN.1 Codec)

Full APER encoder/decoder. NGAP (53 procedure codes, 14+ message values) and S1AP (67 procedure codes, 16+ message values).

Missing: Many typed NGAP IEs, fragmented length, XnAP/F1AP/E1AP codecs.

---

## Summary: Critical Gaps

### Priority 1 - Complete 5G Foundation

| Gap | Library | Impact |
|-----|---------|--------|
| Complete NAS 5GMM encode/decode (20 remaining msgs) | nextgcore-nas | Blocks registration/mobility |
| Implement 5GSM (PDU Session messages) | nextgcore-nas | Blocks data sessions |
| PFCP grouped IEs (PDR/FAR/QER/URR) + Session Modification | nextgcore-pfcp | Blocks UPF control |
| NGAP message builders | nextgcore-ngap | Blocks N2 interface |
| SBI TLS/mTLS and OAuth2 | nextgcore-sbi | Blocks secure deployment |

### Priority 2 - 6G Protocol Evolution

| Gap | Library | Description |
|-----|---------|-------------|
| SBI 2.0 / gRPC support | nextgcore-sbi | Service mesh, event-driven architecture |
| QUIC transport option | nextgcore-sctp | Potential SCTP replacement in 6G |
| UPF programmability (P4-like) | nextgcore-pfcp | In-network computing |
| XnAP/F1AP/E1AP codecs | nextgcore-asn1c | RAN disaggregation support |
