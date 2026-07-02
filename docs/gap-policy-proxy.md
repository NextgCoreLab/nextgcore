# NextGCore Policy, Proxy & User-Plane NF Gap Analysis

> Generated: 2026-02-07 | Scope: PCF, BSF, SEPP, UPF | Target: 6G readiness assessment

> **STALENESS NOTICE (updated 2026-07):** This 2026-02-07 snapshot is superseded. SEPP now implements N32f forwarding (`sbi_path.rs`: `N32fPeerClient` registry, `register_n32f_client`) and the N32-c cert/JOSE path (`jose.rs` X.509 subjectPublicKeyInfo extraction, TS 29.573 6.1.5). UPF's PDR/FAR matching is wired into the forwarding path (`data_plane.rs`: `match_pdr_with_packet` -> `apply_far`, uplink+downlink) and async event loops dispatch PFCP-session/report events; the matched-sim E2E carries real user-plane data (ping through GTP-U, 0% loss). PCF delivers URSP/UPDP UE-policies over Namf N1N2 (`build_ue_policy_n1n2_request`, `ue_policy` module). PCF/BSF are now lib+bin crates. Treat the "completeness %" claims below as a historical baseline.

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

- **Dependencies**: nextgcore-core, nextgcore-sbi, nextgcore-dbi, nextgcore-app, tokio, clap, uuid
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

12 SBI handler endpoints with real CRUD logic. Since this snapshot PCF added URSP/UPDP UE-policy delivery over Namf_Communication N1N2 (`sbi_path.rs`: `build_ue_policy_n1n2_request`, `ue_policy` module, TS 24.501 Annex D UPDP). NRF-registration / UDR-connectivity depth still partial.

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

N32-c handshake fully modeled. N32f forwarding is now implemented (`sbi_path.rs`: `N32fPeerClient` registry, `register_n32f_client`, forwarding client) and the N32-c JOSE/cert path landed (`jose.rs`: X.509 `subjectPublicKeyInfo` extraction, TS 29.573 6.1.5 / TS 33.501 13.2.4).

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

PDR/FAR rule matching is wired into the forwarding path (`data_plane.rs`: `match_pdr_with_packet` selects a PDR by precedence + SDF, `apply_far` applies the FAR action for uplink and downlink); the async event loops dispatch PFCP-session and session-report events (`main.rs`). QoS/URR enforcement depth remains partial.

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
