# NextGCore Protocol Libraries - 6G Gap Analysis

## Overview

Analysis of 9 protocol libraries under `nextgcore/src/libs/` assessing 5G completeness and 6G readiness.

| Library | Maturity | LOC (approx) | Tests | 5G Coverage | 6G Ready |
|---------|----------|--------------|-------|-------------|----------|
| ogs-sbi | High | ~1800 | 5 | 70% | Low |
| ogs-nas | Medium | ~3500 | 6+ | 40% | None |
| ogs-ngap | Stub | ~6 | 0 | 0% | None |
| ogs-gtp | Medium | ~2200 | 8+ | 55% | None |
| ogs-pfcp | Low | ~1200 | 4+ | 25% | None |
| ogs-sctp | High | ~2750 | 60+ | 85% | Low |
| ogs-s1ap | Stub | ~6 | 0 | 0% | None |
| ogs-diameter | High | ~3800 | 15+ | 75% | N/A |
| ogs-asn1c | High | ~3200 | 20+ | 65% | None |

---

## 1. ogs-sbi (Service Based Interface)

**Spec**: 3GPP TS 29.500 series

### What is implemented
- HTTP/2 client (`SbiClient`) with connection pooling and GET/POST/PUT/DELETE/PATCH
- HTTP/2 server (`SbiServer`) with `SbiRequestHandler` trait
- `ProblemDetails` (RFC 7807)
- 52 `SbiServiceType` variants, 37 `NfType` variants
- 42 `SbiAppError` variants with HTTP status mapping

### What is missing (5G)
- **TLS/mTLS**: Config fields exist but not wired to hyper
- **OAuth2 token exchange**: No token management
- **SCP routing**: No Service Communication Proxy support
- **NF heartbeat**: No NF status heartbeat/keep-alive

### 6G gaps
- No **SBI 2.0** / gRPC / service mesh support
- No **event-driven / pub-sub** messaging

---

## 2. ogs-nas (Non-Access Stratum)

**Spec**: 3GPP TS 24.501 (5GS), TS 24.301 (EPS)

### What is implemented
- 24 5GMM message type variants; full encode/decode for 4 (RegistrationRequest/Accept/Reject, AuthenticationRequest)
- Full NIA1/2/3 and NEA1/2/3 security algorithms
- MobileIdentity (SUCI/5G-GUTI/IMEI/5G-S-TMSI/IMEISV)

### What is missing (5G)
- Only 4/24 5GMM message types have full codec (17% complete)
- **5GSM**: Zero implementation
- EPS NAS: Types defined but no encoder/decoder

### 6G gaps
- No AI/ML capability NAS IEs
- No ISAC NAS signaling
- No sub-THz band parameters

---

## 3. ogs-ngap -- STUB LIBRARY

Only a comment in `lib.rs`. All NGAP types live in `ogs-asn1c/src/ngap/`.

---

## 4. ogs-gtp (GPRS Tunneling Protocol)

12 typed GTPv2-C message builders, 65 IE types. GTPv1-U G-PDU implemented.

Missing: Many GTPv2-C messages, no GTP-U extension header support, no TEID pool.

---

## 5. ogs-pfcp (Packet Forwarding Control Protocol)

Basic session lifecycle messages. 255 IE types defined but only ~20 decoded.

**Critical missing**: Session Modification, Session Report, grouped IEs (PDR, FAR, QER, URR, BAR).

---

## 6. ogs-sctp -- Most Production-Ready

Dual implementation (pure Rust + kernel). ~60 unit tests. Full lifecycle management.

Missing: Multi-homing, PR-SCTP. 6G: No QUIC transport alternative.

---

## 7. ogs-s1ap -- STUB LIBRARY

Same situation as ogs-ngap.

---

## 8. ogs-diameter

Full RFC 6733 base protocol. 7 interface modules (S6a, Gx, Gy, Rx, Cx, SWx, S6b) with message builders.

**Critical missing**: No transport layer (TCP/SCTP), no peer state machine.

---

## 9. ogs-asn1c (ASN.1 Codec)

Full APER encoder/decoder. NGAP (53 procedure codes, 14+ message values) and S1AP (67 procedure codes, 16+ message values).

Missing: Many typed NGAP IEs, fragmented length, XnAP/F1AP/E1AP codecs.

---

## Summary: Critical Gaps

### Priority 1 - Complete 5G Foundation

| Gap | Library | Impact |
|-----|---------|--------|
| Complete NAS 5GMM encode/decode (20 remaining msgs) | ogs-nas | Blocks registration/mobility |
| Implement 5GSM (PDU Session messages) | ogs-nas | Blocks data sessions |
| PFCP grouped IEs (PDR/FAR/QER/URR) + Session Modification | ogs-pfcp | Blocks UPF control |
| NGAP message builders | ogs-ngap | Blocks N2 interface |
| SBI TLS/mTLS and OAuth2 | ogs-sbi | Blocks secure deployment |

### Priority 2 - 6G Protocol Evolution

| Gap | Library | Description |
|-----|---------|-------------|
| SBI 2.0 / gRPC support | ogs-sbi | Service mesh, event-driven architecture |
| QUIC transport option | ogs-sctp | Potential SCTP replacement in 6G |
| UPF programmability (P4-like) | ogs-pfcp | In-network computing |
| XnAP/F1AP/E1AP codecs | ogs-asn1c | RAN disaggregation support |
