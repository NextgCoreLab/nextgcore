# NextGCore EPC (4G) Network Functions - Gap Analysis

> Generated: 2026-02-07 | Scope: 5 EPC NFs ported from Open5GS C to Rust

## Executive Summary

This document analyzes the implementation status of 5 EPC (4G LTE) Network Functions
in the nextgcore project. These NFs form the Evolved Packet Core and are critical for
EPC interworking in any 6G migration path.

| NF | Lines | Files | Completeness | Status |
|---|---:|---:|---:|---|
| **HSS** (nextgcore-hssd) | 3,359 | 10 | ~20% | Scaffolding only |
| **MME** (nextgcore-mmed) | 16,513 | 21 | ~75% | Near-functional |
| **PCRF** (nextgcore-pcrfd) | 2,657 | 8 | ~40% | Partial |
| **SGW-C** (nextgcore-sgwcd) | 5,097 | 13 | ~55% | Structural |
| **SGW-U** (nextgcore-sgwud) | 4,963 | 10 | ~50% | Structural |
| **Total** | **32,589** | **62** | **~50%** | |

**Marker counts**: Zero explicit `todo!()`, `unimplemented!()`, or `TODO` comments across
all NFs. Stub areas are instead marked with `// Note:` comments (41 total: HSS 15, MME 1,
PCRF 11, SGW-C 11, SGW-U 3) describing what the real implementation should do.

---

## 1. HSS (nextgcore-hssd)

**Role**: Home Subscriber Server - subscriber data, authentication vectors, location updates.

### Architecture

| Component | File | Lines | Status |
|---|---|---:|---|
| Main loop | main.rs | 306 | Implemented (init/run/shutdown, 100ms poll) |
| State machine | sm.rs | 290 | 3 states (Initial/Operational/Final); DB poll placeholder |
| Context | context.rs | 738 | Implemented (IMSI/IMPI/IMPU hash tables, subscriber CRUD) |
| Events | event.rs | 184 | 4 event types defined |
| Timers | timer.rs | 302 | Implemented (add/stop/delete/restart) |
| Diameter stats | fd_path.rs | 318 | Implemented (AtomicU64 counters for Cx, S6a, SWx) |
| S6a interface | s6a_path.rs | 291 | **Stubbed** |
| Cx interface | cx_path.rs | 335 | **Stubbed** |
| SWx interface | swx_path.rs | 565 | Partially implemented |

### Protocol Interfaces

| Interface | Spec | Handlers | Status |
|---|---|---|---|
| S6a (MME-HSS) | 3GPP TS 29.272 | AIR, ULR, PUR, CLR, IDR | All **stubbed** |
| Cx (I/S-CSCF-HSS) | 3GPP TS 29.229 | UAR, MAR, SAR, LIR | All **stubbed** |
| SWx (AAA-HSS) | 3GPP TS 29.273 | MAR, SAR | **Partial** |

### Completeness: ~20%

Data model and infrastructure are in place. All actual Diameter protocol handling is missing.

---

## 2. MME (nextgcore-mmed)

**Role**: Mobility Management Entity - control plane signaling, NAS security, bearer management.

### Architecture

16,513 lines across 21 files. **5 FSMs** fully defined (MmeFsm, EmmFsm, EsmFsm, S1apFsm, SgsapFsm).

### Protocol Interfaces

| Interface | Spec | Status |
|---|---|---|
| S1AP (eNB-MME) | 3GPP TS 36.413 | **Fully implemented** |
| NAS EMM | 3GPP TS 24.301 | **Fully implemented** |
| NAS ESM | 3GPP TS 24.301 | **Fully implemented** |
| NAS Security | 3GPP TS 33.401 | **Fully implemented** (EIA0-3, EEA0-3) |
| S11 (MME-SGW) | 3GPP TS 29.274 | **Partial** (handlers done, session builds stubbed) |
| S6a (MME-HSS) | 3GPP TS 29.272 | **Partial** (response handlers done, send stubbed) |
| SGsAP (MME-VLR) | 3GPP TS 29.118 | **Fully implemented** |
| SBc-AP (MME-CBC) | 3GPP TS 29.168 | **Partial** |

### Completeness: ~75%

The most complete NF. NAS layer (EMM + ESM + Security) is production-quality. Main gaps are
in Diameter and GTP-C outgoing message construction. 25 proptest properties.

---

## 3. PCRF (nextgcore-pcrfd)

**Role**: Policy and Charging Rules Function - PCC rule management, QoS authorization.

### Completeness: ~40%

Session lifecycle management works. Diameter protocol layer and actual policy decision
logic (PCC rule derivation) are the major gaps. 11 `// Note:` markers.

---

## 4. SGW-C (nextgcore-sgwcd)

**Role**: Serving Gateway Control Plane - GTP-C signaling between MME and PGW, PFCP toward SGW-U.

### CUPS Architecture

Implements CUPS split per 3GPP TS 29.244:
- PFCP Session Establishment/Modification/Deletion with PDR/FAR IE construction
- 11 modify flag combinations handled
- Session Report (DLDR and ERIR)

### Completeness: ~55%

All handler logic and message builders complete. Gap is in SM dispatch, socket I/O, and event loop.

---

## 5. SGW-U (nextgcore-sgwud)

**Role**: Serving Gateway User Plane - GTP-U packet forwarding.

### PFCP Rule Processing

All 10 `process_*` functions (create/update/remove PDR/FAR/QER/BAR) are stubs.

### Completeness: ~50%

PFCP state machine and message codec are solid. Core user-plane function (packet matching
against PDR rules and applying FAR forwarding actions) is entirely absent.

---

## 6G Relevance Assessment

### Reuse Potential for 6G

| Component | Reuse Level | Target 6G NF |
|---|---|---|
| NAS Security (MME) | High | AMF/SEAF |
| PFCP SM + handlers (SGW-C/U) | High | SMF/UPF (N4 interface) |
| GTP-U header codec (SGW-U) | High | UPF (N3/N9 interfaces) |
| Context data models (all) | Medium | Adapt for 5GC/6G data model |
| FSM framework (all) | Medium | Template for any NF |

### Recommended Priority

Complete MME first (closest to functional), then SGW-C + SGW-U together (CUPS pair),
then HSS (or consider 5GC UDM integration), and PCRF last (or replace with 5GC PCF).
