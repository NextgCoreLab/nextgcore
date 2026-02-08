# Data Management & Identity NFs -- 6G Gap Analysis

This report covers four nextgcore network functions responsible for subscriber data, authentication, and slice selection.

| NF | Binary | Primary 3GPP Service | Source Files | Lines (approx) |
|----|--------|---------------------|-------------|----------------|
| UDM | nextgcore-udmd | nudm-uecm, nudm-sdm, nudm-ueau | 13 (.rs + Cargo.toml) | ~5,700 |
| UDR | nextgcore-udrd | nudr-dr | 8 | ~2,030 |
| AUSF | nextgcore-ausfd | nausf-auth | 13 | ~4,050 |
| NSSF | nextgcore-nssfd | nnssf-nsselection, nnssf-nssaiavailability | 11 | ~3,500 |

---

## 1. nextgcore-udmd (Unified Data Management)

### 1.1 Dependencies

`ogs-core`, `ogs-crypt`, `ogs-sbi`, `ogs-dbi`, `ogs-app`, `tokio`, `clap`, `serde`, `serde_json`, `env_logger`, `log`, `ctrlc`, `anyhow`, `uuid`

### 1.2 FSM States & Transitions

| State Machine | States | Transitions |
|--------------|--------|-------------|
| UdmSm (main) | Initial, Operational, Final | Initial -> Operational (on entry), Operational -> Final (on fini) |
| UdmUeSm (per-UE) | Initial, Operational, Exception, Final | Initial -> Operational -> Exception (on error) -> Final |
| UdmSessSm (per-session) | Initial, Operational, Exception, Final | Initial -> Operational -> Exception (on error) -> Final |

Three-level FSM hierarchy. The main SM creates/destroys UE sub-SMs which in turn manage session sub-SMs.

### 1.3 SBI Server Routes (main.rs)

| Service | Resource | Methods | Status |
|---------|----------|---------|--------|
| nudm-ueau | generate-auth-data | POST | Implemented (mock auth vectors) |
| nudm-ueau | auth-events | POST, DELETE | Implemented |
| nudm-uecm | registrations/amf-3gpp-access | PUT, PATCH, GET, DELETE | Implemented |
| nudm-uecm | registrations/smf-registrations | PUT, DELETE | Implemented |
| nudm-sdm | am-data | GET | Implemented (hardcoded response) |
| nudm-sdm | smf-select-data | GET | Implemented (hardcoded response) |
| nudm-sdm | sm-data | GET | Implemented (hardcoded response) |
| nudm-sdm | nssai | GET | Implemented (hardcoded response) |
| nudm-sdm | sdm-subscriptions | POST, DELETE | Implemented |

### 1.4 SBI Client Calls

| Target | Service | Purpose | Status |
|--------|---------|---------|--------|
| UDR | nudr-dr | Subscription data queries | Stub (discover_and_send placeholder) |
| NRF | nnrf-nfm | NF registration/heartbeat | Stub (log-only) |
| NRF | nnrf-disc | NF discovery | Stub (log-only) |

### 1.5 Handler Assessment

| Handler Module | Functions | Implementation Level |
|---------------|-----------|---------------------|
| nudm_handler.rs (1067 lines) | 10 handlers (UEAU get/confirm, UECM amf-reg/update/get/dereg, smf-reg/dereg, SDM sub create/delete) | **Functional** -- input validation, context updates, response building. Auth vector generation uses zeroed placeholder bytes. |
| nudr_handler.rs (779 lines) | 6 handlers (auth GET/PATCH, context, provisioned am/smf-sel/sm) | **Partial** -- processes responses, updates UE context, but auth key material is placeholder. SQN management is stubbed. |

### 1.6 Stub / Placeholder Indicators

- `todo!()` / `unimplemented!()`: **0**
- `// Note:` comments marking stubs: **26** across 7 files
- Key stubs: auth vector generation (no real Milenage), SBI client HTTP sending, NRF integration, SQN management

### 1.7 Completeness: **~65%**

**Evidence:** Full FSM hierarchy, comprehensive handler logic with input validation, context management with SUCI/SUPI hash maps, timer infrastructure, HTTP/2 server with request routing. Weakened by: placeholder auth vectors (no Milenage/TUAK), no real SBI client HTTP calls, NRF integration stub-only, SDM GET responses hardcoded.

---

## 2. nextgcore-udrd (Unified Data Repository)

### 2.1 Dependencies

`ogs-sbi` only. **No `ogs-dbi`** -- the database integration crate is missing entirely.

### 2.2 FSM States & Transitions

| State Machine | States | Transitions |
|--------------|--------|-------------|
| UdrSm (main) | Initial, Operational, Final | Initial -> Operational -> Final |

Single-level FSM only. No per-UE or per-session sub-state-machines.

### 2.3 SBI Server Routes (udr_sm.rs)

| Service | Resource | Methods | Status |
|---------|----------|---------|--------|
| nudr-dr | subscription-data/.../authentication-data | GET, PATCH | Stub (log only) |
| nudr-dr | subscription-data/.../context-data | GET, PUT, DELETE | Stub (log only) |
| nudr-dr | subscription-data/.../provisioned-data/am-data | GET | Stub (log only) |
| nudr-dr | subscription-data/.../provisioned-data/smf-selection | GET | Stub (log only) |
| nudr-dr | subscription-data/.../provisioned-data/sm-data | GET | Stub (log only) |
| nudr-dr | policy-data | various | Stub (log only) |

### 2.4 SBI Client Calls

None. UDR is a data-serving NF that does not initiate outbound SBI calls.

### 2.5 Handler Assessment

| Handler Module | Functions | Implementation Level |
|---------------|-----------|---------------------|
| nudr_handler.rs (532 lines) | 4 handlers (auth, context, provisioned, policy) | **Stub** -- all handlers log the request and call `send_success_response()` placeholder. No database queries. |

### 2.6 Completeness: **~20%**

**Evidence:** Has correct SBI routing structure and handler dispatch, but every handler is a stub. The absence of `ogs-dbi` in Cargo.toml means zero database capability.

---

## 3. nextgcore-ausfd (Authentication Server Function)

### 3.1 FSM States & Transitions

| State Machine | States | Transitions |
|--------------|--------|-------------|
| AusfSm (main) | Initial, Operational, Final | Initial -> Operational -> Final |
| AusfUeSm (per-UE) | Initial, Operational, Deleted, Exception, Final | Initial -> Operational -> Deleted (on auth delete), Exception (on error) -> Final |

### 3.2 SBI Server Routes (main.rs)

| Service | Resource | Methods | Status |
|---------|----------|---------|--------|
| nausf-auth | ue-authentications | POST | Implemented (discovers UDM, returns auth context) |
| nausf-auth | ue-authentications/{id}/5g-aka-confirmation | PUT | Implemented (validates RES*, returns KSEAF) |
| nausf-auth | ue-authentications/{id}/eap-session | POST | Stub (returns mock EAP success) |
| nausf-auth | ue-authentications/{id} | DELETE | Implemented (removes auth context) |

### 3.3 Completeness: **~55%**

**Evidence:** Uses real `ogs_crypt::kdf` for HXRES* and KSEAF calculation. Weakened by: RES* comparison always succeeds, EAP-AKA' fully stubbed, SBI client HTTP sending not implemented.

---

## 4. nextgcore-nssfd (Network Slice Selection Function)

### 4.1 SBI Server Routes (main.rs)

| Service | Resource | Methods | Status |
|---------|----------|---------|--------|
| nnssf-nsselection | network-slice-information | GET | Implemented (hardcoded allowed NSSAI) |
| nnssf-nssaiavailability | nssai-availability/{nfId} | PUT, PATCH, DELETE | Implemented (basic JSON handling) |
| nnssf-nssaiavailability | subscriptions | POST, DELETE | Implemented (creates UUID-based subscription) |

### 4.2 Completeness: **~55%**

**Evidence:** Full context with NSI and Home lists with S-NSSAI hash lookups, roaming scenario logic. Weakened by: NS selection response is hardcoded, SBI client calls not implemented, NRF integration stub-only.

---

## 5. Cross-NF Completeness Summary

| NF | Completeness | FSM | SBI Server | SBI Client | Handlers | Context | Tests |
|----|-------------|-----|------------|------------|----------|---------|-------|
| UDM | ~65% | 3-level | Full routing | Stub | Functional (mock crypto) | Full (UE/Sess/SDM) | Yes |
| UDR | ~20% | 1-level | Routing only | N/A | All stubs | Empty | Minimal |
| AUSF | ~55% | 2-level | Full routing | Builders done, send stub | Functional (real KDF, mock comparison) | Full (UE auth) | Yes |
| NSSF | ~55% | 1-level | Full routing | Stub | Functional (real NSI lookup) | Full (NSI/Home) | Yes |

---

## 6. 6G Gap Analysis

### 6.1 Zero-Trust Architecture

| Gap | Current State | Required for 6G |
|-----|--------------|----------------|
| Mutual TLS authentication | TLS config params exist but optional | Mandatory mTLS between all NFs |
| Per-request authorization | No OAuth2 token validation | OAuth2/JWT bearer token validation per TS 33.501 |
| Continuous verification | Static auth (authenticate once) | Continuous trust evaluation with behavioral analysis |

### 6.2 Enhanced Network Slicing (NSACF Integration)

| Gap | Current State | Required for 6G |
|-----|--------------|----------------|
| NSACF (Slice Admission Control) | Not present | UDM/NSSF must interact with NSACF |
| Dynamic slice instantiation | Static NSI information | Runtime slice creation/deletion |
| Slice SLA monitoring | No SLA metrics | QoS/SLA monitoring per slice |
| Quantum-safe crypto | Placeholder crypto | Must support CRYSTALS-Kyber, CRYSTALS-Dilithium |

---

## 7. Priority Recommendations

### Critical (must-fix for 5G compliance)

1. **UDR database integration** -- Add `ogs-dbi` dependency, implement actual database queries
2. **AUSF real auth verification** -- Implement actual RES* comparison
3. **UDM Milenage/TUAK** -- Replace placeholder auth vector generation
4. **SBI client HTTP sending** -- Implement actual HTTP/2 client calls

### High (5G feature parity)

5. **NRF integration** -- Implement NF registration, heartbeat, and discovery for all 4 NFs
6. **EAP-AKA' support in AUSF** -- Implement EAP-AKA' authentication method
7. **NSSF NSSAI persistence** -- Store NSSAI availability data
8. **SDM actual data retrieval** -- UDM SDM GET handlers should query UDR

### Medium (6G readiness)

9. **mTLS enforcement** -- Make mutual TLS mandatory
10. **NSACF client interface** -- Add NSACF interaction to NSSF and UDM
11. **Post-quantum crypto preparation** -- Design crypto abstraction layer for PQC
