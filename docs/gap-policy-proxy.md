# NextGCore Policy, Proxy & User-Plane NF Gap Analysis

> Generated: 2026-02-07 | Scope: PCF, BSF, SEPP, UPF | Target: 6G readiness assessment

---

## 1. Summary

| NF | Binary | Role | Source Files | Total Lines | Completeness | 6G Readiness |
|----|--------|------|-------------|-------------|-------------|--------------|
| PCF | nextgcore-pcfd | Policy Control Function | 12 | ~5,456 | **70%** | Low |
| BSF | nextgcore-bsfd | Binding Support Function | 10 | ~3,246 | **65%** | Low |
| SEPP | nextgcore-seppd | Security Edge Protection Proxy | 12 | ~3,912 | **55%** | Low |
| UPF | nextgcore-upfd | User Plane Function | 15 | ~9,839 | **60%** | Low |

**Markers found**: 0 `todo!()`, 0 `unimplemented!()`, 0 `TODO`, 0 `FIXME` across all 49 source files.

---

## 2. PCF -- Policy Control Function

### 2.1 Architecture

- **Dependencies**: ogs-core, ogs-sbi, ogs-dbi, ogs-app, tokio, clap, uuid
- **Context**: `OnceLock<Arc<RwLock<PcfContext>>>` singleton with RwLock<HashMap> pools for UE AM, UE SM, Sessions, App sessions

### 2.2 SBI Routes & Handlers

| Service | Method | Path | Status |
|---------|--------|------|--------|
| npcf-am-policy-control | POST | /policies | Implemented -- creates AM policy |
| npcf-am-policy-control | GET/DELETE | /policies/{id} | Implemented |
| npcf-smpolicycontrol | POST | /sm-policies | Implemented -- creates SM policy |
| npcf-smpolicycontrol | GET/DELETE/PATCH | /sm-policies/{id} | Implemented |
| npcf-policyauthorization | POST | /app-sessions | Implemented |
| npcf-policyauthorization | GET/DELETE/PATCH | /app-sessions/{id} | Implemented |

### 2.3 Completeness: 70%

12 SBI handler endpoints with real CRUD logic. However, no real NRF registration, no UDR connectivity, and mock policy data.

### 2.4 6G Gaps

- No intent-based policies or AI-driven policy inference
- No energy-aware policies or green networking support
- No semantic communication policy framework

---

## 3. BSF -- Binding Support Function

### 3.1 Completeness: 65%

5 SBI endpoints with 4 fully implemented. PATCH is a no-op. No database persistence, no NRF integration.

---

## 4. SEPP -- Security Edge Protection Proxy

### 4.1 Completeness: 55%

N32c handshake protocol fully modeled. N32f forwarding (core SEPP function) not implemented. PRINS explicitly unsupported (returns 501).

### 4.2 6G Gaps

- No zero-trust continuous verification
- No post-quantum cryptography in capability negotiation
- No AI threat detection on roaming traffic

---

## 5. UPF -- User Plane Function

### 5.1 Architecture

15 source files, ~9,839 lines. Full PFCP server, GTP-U forwarding, TUN device, ARP/ND proxy.

### 5.2 PFCP Message Handlers

All session message types implemented (Establishment, Modification, Deletion). Full PDR/FAR/URR/QER/BAR parsing.

### 5.3 Data Plane Components

| Component | Status |
|-----------|--------|
| TUN device (Linux) | Implemented |
| GTP-U header build/parse | Implemented |
| IP packet parsing | Implemented |
| Uplink/Downlink forwarding | Implemented |
| ARP/ND proxy | Implemented |
| IP spoofing detection | Implemented |

### 5.4 Completeness: 60%

Main event loop dispatchers are empty stubs, PDR/FAR rule matching not wired to forwarding path, QoS not enforced, URR threshold reporting missing.

### 5.5 6G Gaps

- No compute-aware networking or in-network AI/ML
- No programmable data plane (P4/eBPF)
- No deterministic networking / TSN integration
- No energy-aware forwarding

---

## 6. Cross-Cutting 6G Readiness

| 6G Capability | PCF | BSF | SEPP | UPF |
|---------------|-----|-----|------|-----|
| AI/ML integration | None | None | None | None |
| Intent-based management | None | N/A | N/A | N/A |
| Zero-trust security | N/A | N/A | None | N/A |
| Post-quantum crypto | N/A | N/A | None | N/A |
| Compute-aware networking | N/A | N/A | N/A | None |
| Energy awareness | None | None | None | None |
| Deterministic networking | N/A | N/A | N/A | None |

**Overall 6G readiness: Low.** Priority areas: programmable UPF, intent-based PCF, zero-trust SEPP with PQC.
