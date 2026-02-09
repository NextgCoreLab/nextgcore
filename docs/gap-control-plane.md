# NextGCore Control Plane NFs -- 6G Gap Analysis

> Generated: 2026-02-07 | Scope: AMF, SMF, NRF, SCP

---

## Summary

| NF | Binary | Source Files | Role | Completeness | 6G Readiness |
|----|--------|-------------|------|-------------|--------------|
| AMF | nextgcore-amfd | 18 | Access & Mobility Management | **35%** | Low |
| SMF | nextgcore-smfd | 19 | Session Management | **30%** | Low |
| NRF | nextgcore-nrfd | 10 | NF Repository | **65%** | Low |
| SCP | nextgcore-scpd | 7 | Service Communication Proxy | **15%** | Low |

---

## 1. AMF (nextgcore-amfd)

**Role**: Access and Mobility Management Function -- NGAP interface to gNB, NAS security, registration, handover.

### Architecture

- 18 source files including dedicated modules for NGAP, GMM, NAS security, SBI, metrics
- `AmfApp` struct with `Arc<RwLock<AmfContext>>`, mpsc event channels, timer manager
- CLI: clap with config path, log level, NGAP bind address
- Property tests included

### Key Modules

| Module | Lines (est.) | Status |
|--------|-------------|--------|
| `context.rs` | Large | Implemented (gNB pool, UE pool, AMF ID, GUAMI, PLMN, TAI, security config) |
| `amf_sm.rs` | Medium | FSM: Initial/Operational/Final, 6 event types dispatched |
| `gmm_sm.rs` | Medium | FSM: sub-states for registration, authentication, security mode |
| `ngap_sm.rs` | Medium | FSM: NGAP interface state transitions |
| `gmm_handler.rs` | Large | Stubbed (registration, auth, security mode, service request handlers) |
| `gmm_build.rs` | Large | Stubbed (NAS message builders for registration accept/reject, auth, security mode) |
| `ngap_handler.rs` | Large | Stubbed (NG Setup, Initial UE, NGAP message dispatch) |
| `ngap_build.rs` | Large | Stubbed (NGAP message builders) |
| `ngap_asn1.rs` | Medium | NGAP ASN.1 helpers |
| `ngap_path.rs` | Medium | NGAP send/receive path stubs |
| `nas_security.rs` | Medium | NAS security context, algorithm selection |
| `namf_handler.rs` | Medium | SBI handler for Namf services (stubbed) |
| `sbi_path.rs` | Medium | SBI send functions (stubbed) |
| `metrics.rs` | Small | AMF-specific Prometheus metrics |
| `timer.rs` | Medium | Timer management |

### SBI Routes

| Service | Status |
|---------|--------|
| namf-comm | Scaffolding (N1N2 message transfer routing) |
| namf-evts | Scaffolding (event exposure) |

### Stubs & Gaps

- GMM handlers: Registration/auth/security mode logic scaffolded but core processing stubbed
- NGAP handlers: NG Setup response, Initial UE Message dispatch scaffolded but incomplete
- SBI client: All outbound calls (to AUSF, UDM, PCF, NSSF) are stubs
- NRF integration: Registration/discovery not implemented
- NGAP ASN.1: Helpers exist but not wired to full encode/decode

### Completeness: **35%**

Strong context model and FSM hierarchy. Multiple handler modules with function signatures and partial logic, but core 5G procedures (registration, authentication, PDU session) are incomplete.

---

## 2. SMF (nextgcore-smfd)

**Role**: Session Management Function -- PDU session lifecycle, PFCP to UPF, GTP-C, SBI.

### Architecture

- 19 source files with dedicated modules for N4/PFCP, GSM, GTP, binding
- HTTP/2 SBI server using `ogs-sbi` crate
- Supports both 5GC and EPC modes (GTP-C Gn interface)
- Property tests included

### Key Modules

| Module | Status |
|--------|--------|
| `context.rs` | Implemented (UE, Session, Bearer, QoS Flow contexts) |
| `smf_sm.rs` | FSM: Initial/Operational/Final, SBI event routing by service name |
| `gsm_sm.rs` | FSM: GSM sub-states for PDU session establishment/modification/release |
| `pfcp_sm.rs` | FSM: PFCP association states (WillAssociate/Associated/Exception) |
| `gsm_handler.rs` | Stubbed (PDU session create/update/release handlers) |
| `gsm_build.rs` | Stubbed (NAS SM message builders) |
| `n4_handler.rs` | Stubbed (PFCP session response handlers) |
| `n4_build.rs` | Stubbed (PFCP session request builders) |
| `gtp_handler.rs` | Stubbed (GTP-C response handlers for S5/S8) |
| `gtp_build.rs` | Stubbed (GTP-C request builders) |
| `gn_handler.rs` | Stubbed (Gn interface for EPC interworking) |
| `gn_build.rs` | Stubbed (Gn request builders) |
| `pfcp_path.rs` | PFCP send stubs |
| `gtp_path.rs` | GTP-C send stubs |
| `binding.rs` | PCC rule to QoS flow binding logic (partial) |

### SBI Routes

| Service | Method | Path | Status |
|---------|--------|------|--------|
| nsmf-pdusession | POST | /sm-contexts | Implemented (routes to GSM handler) |
| nsmf-pdusession | PATCH | /sm-contexts/{id}/modify | Implemented |
| nsmf-pdusession | POST | /sm-contexts/{id}/release | Implemented |
| nsmf-event-exposure | POST | /subscriptions | Scaffolding |

### Completeness: **30%**

SBI server with comprehensive HTTP/2 routing, full context model with UE/Session/Bearer/QoS Flow hierarchy, 3 FSMs. All protocol handlers (PFCP, GTP-C, GSM) are scaffolded but stubbed.

---

## 3. NRF (nextgcore-nrfd)

**Role**: NF Repository Function -- NF registration, discovery, subscription management.

### Architecture

- 10 source files, lib.rs exports public API
- HTTP/2 SBI server, fully functional NF management
- Two FSMs: NrfSm (main) and NfSm (per-NF instance)

### Key Modules

| Module | Status |
|--------|--------|
| `context.rs` | **Fully implemented** (NF profiles, service discovery, subscription management) |
| `nrf_sm.rs` | **Fully implemented** (Initial/Operational/Final) |
| `nf_sm.rs` | **Fully implemented** (Registered/Suspended states, heartbeat tracking) |
| `nnrf_handler.rs` | **Mostly implemented** (NF register, update, deregister, discover, subscribe, notify) |
| `nnrf_build.rs` | **Implemented** (NF profile JSON, discovery result, search result) |
| `sbi_path.rs` | **Implemented** (SBI server lifecycle, request routing) |
| `timer.rs` | Implemented (heartbeat, subscription, NF validity timers) |

### SBI Routes

| Service | Method | Path | Status |
|---------|--------|------|--------|
| nnrf-nfm | PUT | /nf-instances/{id} | **Working** (NF registration) |
| nnrf-nfm | PATCH | /nf-instances/{id} | **Working** (NF heartbeat/update) |
| nnrf-nfm | DELETE | /nf-instances/{id} | **Working** (NF deregistration) |
| nnrf-nfm | GET | /nf-instances/{id} | **Working** (NF profile retrieval) |
| nnrf-disc | GET | /nf-instances | **Working** (NF discovery with query params) |
| nnrf-nfm | POST | /subscriptions | **Working** (status subscriptions) |
| nnrf-nfm | DELETE | /subscriptions/{id} | **Working** (unsubscribe) |

### Completeness: **65%**

The most functional NF in nextgcore. Full NF lifecycle management with HTTP/2 server. Weakened by: notification delivery not fully implemented, no TLS/mTLS, no OAuth2 token management.

---

## 4. SCP (nextgcore-scpd)

**Role**: Service Communication Proxy -- request routing, NF discovery delegation, load balancing.

### Architecture

- 7 source files, minimal implementation
- Forwards SBI requests between NF consumers and producers

### Key Modules

| Module | Status |
|--------|--------|
| `context.rs` | Partial (ScpContext with association list) |
| `scp_sm.rs` | FSM: Initial/Operational/Final |
| `sbi_path.rs` | Partial (request forwarding scaffolding) |
| `sbi_response.rs` | Partial (response routing) |

### Completeness: **15%**

Minimal scaffolding. The core SCP function (request routing with NF discovery delegation) is largely unimplemented.

---

## 6G Gap Analysis

### Common Gaps Across All Control Plane NFs

| Gap | AMF | SMF | NRF | SCP |
|-----|-----|-----|-----|-----|
| NRF integration | Stub | Stub | N/A | Stub |
| SBI client calls | Stub | Stub | Partial | Stub |
| TLS/mTLS | None | None | None | None |
| OAuth2 | None | None | None | None |
| Metrics/observability | Defined | None | None | None |
| Config parsing | Partial | Partial | Partial | Partial |

### 6G-Specific Gaps

| Capability | Impact on Control Plane |
|------------|------------------------|
| **SBA 2.0 / Service Mesh** | SCP should evolve into service mesh sidecar; NRF needs service mesh integration |
| **AI-native networking** | AMF needs AI-assisted mobility prediction; SMF needs ML-based QoS optimization |
| **Intent-based management** | All NFs need intent translation interfaces |
| **Network slicing evolution** | AMF/SMF need NSACF interaction; NRF needs slice-aware discovery |
| **Zero-trust security** | All NFs need mTLS, OAuth2, continuous verification |
| **Edge computing / MEC** | SMF needs edge-aware session management; AMF needs local breakout support |
| **Digital twin** | All NFs need state export for digital twin synchronization |
| **Energy efficiency** | All NFs need power-state management and green scheduling |
| **NTN support** | AMF needs satellite access handling; SMF needs NTN-specific QoS |

### Recommendations

1. **Complete NRF first** -- Already 65% done; other NFs depend on it
2. **AMF registration flow** -- Core 5G procedure, prerequisite for everything
3. **SMF PDU session establishment** -- Basic data session support
4. **SBI client infrastructure** -- All NFs need working HTTP/2 client calls
5. **TLS/mTLS** -- Security baseline before any deployment
6. **SCP routing** -- Enable service mesh architecture for 6G readiness
