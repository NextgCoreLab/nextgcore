# NextGCore 6G Gap Analysis Report

**Date:** 2026-02-07
**Scope:** Comprehensive source code analysis of all 17 network functions and 18 shared libraries
**Standards Reference:** 3GPP Rel-18/19, ITU-R IMT-2030 Framework

---

## Executive Summary

NextGCore is a pure Rust port of the Open5GS C codebase implementing 12 5G Core (5GC) network functions and 5 EPC network functions, supported by 18 shared libraries. The project has established strong foundational infrastructure -- FSM frameworks, SBI HTTP/2 server/client, PFCP protocol library, NAS message encoding/decoding, and a working UPF data plane -- but the majority of service-specific handlers remain stubbed. There are **316 documented TODOs** across 8 phases required to reach basic 5G operational parity, and **zero 6G-specific features** exist in the codebase.

The gap to a 6G-ready core network is therefore two-layered:

1. **Layer 1 (5G Completion):** ~17 weeks of work to implement timer management, SBI infrastructure, error responses, NRF integration, and service-specific handlers across all NFs.
2. **Layer 2 (6G Evolution):** Entirely new capabilities required for AI-native networking, SBA 2.0, compute-aware networking, digital twins, intent-driven management, enhanced slicing, zero-trust security, green networking, NTN support, and TSN integration.

**Overall 5G Implementation Completeness: ~25%**
**6G Readiness: 0%**

---

## 1. Network Function-by-NF Analysis

### 1.1 5G Core Network Functions

| NF | Source Files | FSM | SBI Server | SBI Client | Service Handlers | Config | Tests | Completeness |
|-----|-------------|-----|------------|------------|------------------|--------|-------|-------------|
| **AMF** | 18 | Working (6 event types) | Scaffolding | Scaffolding | Stubbed (NGAP dispatch noted) | YAML parsing (GUAMI, TAI, PLMN, security) | Basic | **35%** |
| **AUSF** | ~8 | Working + UE sub-FSMs | Routing (nausf-auth) | Routing (nudm-ueau) | Stubbed (UE lookup by SUCI/SUPI) | Basic | Comprehensive (845 lines) | **25%** |
| **BSF** | ~6 | Working | Routing (nbsf-management) | NRF stubs | Stubbed (PCF binding CRUD) | Basic | Basic | **20%** |
| **NRF** | ~8 | Working | **Functional** (full HTTP/2 routing) | N/A | **Working** (NF registration, discovery, subscriptions) | Basic | Good | **65%** |
| **NSSF** | ~6 | Working | Routing (nnssf-nsselection v2) | H-NSSF response | Stubbed | Basic | Basic | **20%** |
| **PCF** | ~8 | Working + AM/SM sub-FSMs | Routing (3 services) | NUDR/BSF response | Stubbed (AM policy, SM policy, policy auth) | Basic | Comprehensive (890 lines) | **25%** |
| **SCP** | ~6 | Working | Minimal (forwards via sbi_path) | NF discovery | Stubbed | Basic | Basic | **15%** |
| **SEPP** | ~8 | Working + Handshake sub-FSMs | Routing (n32c-handshake) | N32c response | Partial (find_or_create returns None) | Basic | Basic | **20%** |
| **SMF** | ~12 | Working (14 event types) | **Functional** (comprehensive HTTP/2 routes) | Scaffolding | Stubbed (PDU session CRUD, event exposure) | YAML parsing | Basic | **30%** |
| **UDM** | ~8 | Working + UE/Session sub-FSMs | Routing (3 services, v2 SDM) | NUDR response routing | Stubbed (SUPI extraction works) | Basic | Basic | **20%** |
| **UDR** | ~6 | Working (stateless) | Routing (nudr-dr) | N/A | Delegated to nudr_handler | Basic | Basic | **25%** |
| **UPF** | ~10 | Working + Exception state | N/A (PFCP) | N/A | **Working** (TUN, GTP-U, session mgmt) | Basic | Good | **55%** |

### 1.2 EPC Network Functions

| NF | Source Files | FSM | Protocol Interfaces | Service Handlers | Completeness |
|-----|-------------|-----|---------------------|------------------|-------------|
| **HSS** | 10 | Working + DB poll timer | S6a/Cx/SWx (Diameter) init/fini scaffolding | Stubbed (AIR/ULR/PUR/CLR/IDR structures defined) | **25%** |
| **MME** | 21 | Working (5 FSMs: MME, EMM, ESM, S1AP, SGsAP) | S1AP/S11/S6a/SGsAP init scaffolding | Comprehensive type definitions, handlers stubbed | **30%** |
| **PCRF** | 8 | Working + Exception state | Gx/Rx (Diameter) init/fini scaffolding | Stubbed | **15%** |
| **SGW-C** | 13 | Working + PFCP sub-FSM (5 states) | S11/S5C/SXA event routing | Stubbed (GTP message types documented) | **25%** |
| **SGW-U** | 10 | Working (returns SgwuSmResult) | SXA (PFCP) event routing | Stubbed (dispatch to PFCP node) | **20%** |

### 1.3 Shared Libraries

| Library | Purpose | Status | Key Types/Features |
|---------|---------|--------|-------------------|
| **ogs-sbi** | SBI HTTP/2 | **Functional** | Client, Server (hyper/h2), ProblemDetails, NfInstance, discovery context, TLS config |
| **ogs-pfcp** | PFCP protocol | **Functional** | Header/IE/Message encode/decode, Session/Association/Heartbeat types, TS 29.244 |
| **ogs-nas** | NAS protocol | **Functional** | 5GMM + EPS message build/parse, security context, Registration/Auth/SMC messages |
| **ogs-core** | Core utilities | **Functional** | 26 modules: list, hash, pool, pkbuf, timer, FSM, TLV, socket, poll, TCP/UDP |
| **ogs-metrics** | Prometheus metrics | **Functional** | Counter/Gauge/Histogram, labels, Prometheus HTTP server |
| **ogs-ngap** | NGAP protocol | **Minimal** | Only lib.rs stub (ASN.1 APER note) |
| **ogs-s1ap** | S1AP protocol | Scaffolding | ASN.1 encoding via ogs-asn1c |
| **ogs-sctp** | SCTP transport | **Working** | sctp-proto 0.6 integration (migration complete per must_be_implemented.txt) |
| **ogs-gtp** | GTPv2-C protocol | Scaffolding | GTP-C message building |
| **ogs-diameter** | Diameter protocol | Scaffolding | FreeDiameter integration stubs |
| **ogs-crypt** | Crypto functions | Scaffolding | Auth vector generation |
| **ogs-dbi** | Database interface | Scaffolding | MongoDB integration stubs |
| **ogs-tun** | TUN device | **Working** | Used by UPF for data plane |
| **ogs-ipfw** | IP firewall/NAT | **Working** | Used by UPF for NAT |
| **ogs-ffi** | C FFI bindings | Scaffolding | FreeDiameter/ASN.1 C library bridges |
| **ogs-asn1c** | ASN.1 compiler | Scaffolding | NGAP/S1AP ASN.1 types |
| **ogs-app** | Application framework | Scaffolding | Common app initialization |
| **ogs-proto** | Protocol definitions | Scaffolding | Shared protocol types |

---

## 2. Critical 5G Gaps (from todo.txt Analysis)

The project documents 316 TODOs across 8 phases. These represent the prerequisite work before any 6G features can be considered.

### Phase 1: Timer Management + SBI Infrastructure (CRITICAL, ~40 TODOs)
- **Timer Manager:** No centralized async timer system. All NFs use placeholder `thread::sleep` polling loops.
- **SBI Event Loop:** Event queue dispatch from SBI server to state machines is not wired.
- **Impact:** Without timers, no NF can perform registration retries, heartbeats, or session timeouts.

### Phase 2: Error Response Framework (HIGH, ~50 TODOs)
- **ProblemDetails:** Library type exists in ogs-sbi but no NF generates proper 3GPP error responses.
- **HTTP Status Codes:** Server helper functions exist (`send_bad_request`, `send_not_found`, etc.) but are unused.
- **Impact:** No interoperability with compliant clients; no error recovery.

### Phase 3: NRF Integration (HIGH, ~35 TODOs)
- **NRF Server:** Functional (registration, discovery, subscriptions work).
- **NRF Clients:** No NF registers itself with NRF on startup, no NF performs NF discovery.
- **Impact:** Service-based architecture is non-functional without NRF integration.

### Phase 4: Service-Specific Handlers (MEDIUM, ~80 TODOs)
- **AMF:** NGAP message dispatch to sub-FSMs, NAS message processing, UE context management.
- **SMF:** N4 session establishment with UPF, PDU session lifecycle, QoS rule installation.
- **AUSF/UDM/UDR:** Authentication vector generation, subscriber data retrieval, database queries.
- **PCF:** Policy decision logic, PCC rule generation, QoS flow binding.
- **Impact:** No actual mobile connectivity possible.

### Phase 5: SCP/SEPP Routing (MEDIUM, ~40 TODOs)
- **SCP:** Request forwarding, load balancing, service mesh capabilities.
- **SEPP:** N32 interface, PRINS/TLS security, message filtering.
- **Impact:** No inter-PLMN roaming or service mesh support.

### Phase 6: Protocol Libraries - NGAP/S1AP (MEDIUM, ~20 TODOs)
- **ogs-ngap:** Only a single-line stub. ASN.1 APER encoding not implemented.
- **ogs-s1ap:** Scaffolding only.
- **Impact:** AMF cannot communicate with gNBs; MME cannot communicate with eNBs.

### Phase 7: EPC/Diameter (LOW, ~25 TODOs)
- **ogs-diameter:** FreeDiameter integration is stub-only.
- **HSS/PCRF:** S6a, Cx, SWx, Gx, Rx handlers are all stubbed.
- **Impact:** No EPC authentication or policy control.

### Phase 8: UPF Enhancements (LOW, ~5 TODOs)
- **UPF:** Already the most complete NF. Remaining work: URR (usage reporting), QER (QoS enforcement), FAR enhancements.

---

## 3. 6G Gap Analysis per ITU-R IMT-2030 and 3GPP Rel-18/19

### 3.1 AI/ML-Native Network Automation (NWDAF)

**Current State:** No NWDAF NF exists. No AI/ML infrastructure. No data collection pipelines. No analytics framework.

**Gaps:**
- No NWDAF binary or scaffolding in `src/bins/`
- No ML model serving infrastructure (ONNX runtime, TensorFlow Serving integration)
- No data collection APIs (Nnwdaf_AnalyticsInfo, Nnwdaf_EventsSubscription)
- No analytics exposure to consumers (AMF, SMF, PCF, NSSF)
- No Federated Learning support for distributed model training
- No real-time inference pipeline for anomaly detection, load prediction, or QoE optimization
- No MTLF (Model Training Logical Function) or AnLF (Analytics Logical Function) decomposition
- **3GPP Rel-18 NWDAF Phase 3:** Root cause analysis, QoE prediction, network energy saving analytics
- **6G Extension:** Autonomous network operations, self-healing, predictive resource management

**Priority:** CRITICAL for 6G -- AI-native networking is a cornerstone of IMT-2030.

### 3.2 Enhanced Network Slicing

**Current State:** NSSF has basic scaffolding for `nnssf-nsselection` (v2 API). AMF context defines `SNssai` type. No slice isolation, lifecycle management, or SLA assurance.

**Gaps:**
- No slice admission control or resource reservation
- No Network Slice Instance (NSI) lifecycle management (creation, activation, deactivation, termination)
- No Network Slice Subnet Instance (NSSI) management
- No slice SLA monitoring or assurance framework
- No per-slice QoS enforcement (PCF policies are stubbed)
- No slice-level analytics (requires NWDAF)
- No inter-slice resource sharing or isolation enforcement
- No slice template/blueprint management
- **3GPP Rel-18:** Enhanced NSSF for slice-specific authentication, NSACF (Network Slice Admission Control Function)
- **6G Extension:** Dynamic micro-slicing with sub-ms granularity, AI-driven slice orchestration, intent-based slice management

**Priority:** HIGH -- Network slicing is fundamental to both 5G-Advanced and 6G.

### 3.3 Service-Based Architecture (SBA) 2.0

**Current State:** ogs-sbi library provides functional HTTP/2 client/server with hyper. NRF has working NF registration and discovery. No other NF uses SBI client for NRF registration or service discovery.

**Gaps:**
- No service mesh capabilities (SCP is minimal stub)
- No event exposure framework (NSEF - Network Service Exposure Function)
- No API gateway / rate limiting / request routing
- No service authorization (OAuth 2.0 tokens not implemented)
- No event subscription/notification framework
- No bulk operations or batch API support
- No HTTP/3 (QUIC) support
- **3GPP Rel-18:** Enhanced SBA with indirect communication via SCP, service routing
- **6G Extension:** SBA 2.0 with native gRPC/protocol buffers, GraphQL APIs, event-driven architecture, serverless NF execution, WebAssembly NF plugins

**Priority:** HIGH -- SBA 2.0 is an architectural pillar of 6G.

### 3.4 Multi-Access Edge Computing (MEC) / Edge Intelligence

**Current State:** No edge computing support. No EASDF (Edge Application Server Discovery Function). No edge NF deployment model.

**Gaps:**
- No EASDF NF
- No edge discovery and selection
- No local breakout / local data path management
- No UPF selection based on edge proximity
- No edge application lifecycle management
- No edge-cloud orchestration
- No latency-aware traffic steering
- **3GPP Rel-18:** Enhanced EASDF, edge computing phase 2
- **6G Extension:** Distributed AI at the edge, compute-aware networking (see 3.8), ultra-low-latency edge processing (<1ms)

**Priority:** HIGH -- Edge computing is critical for 6G's ultra-low-latency and immersive use cases.

### 3.5 Zero-Trust Security Architecture

**Current State:** SBI server has TLS config fields (private_key, cert, verify_client) but no implementation. No authentication, authorization, or integrity protection between NFs.

**Gaps:**
- No mTLS between NFs (SBI server TLS config is unused)
- No OAuth 2.0 client credentials flow for NF authorization
- No NF token validation
- No security context management for UE sessions
- No NAS security (library types exist but not wired to NFs)
- No SUPI/SUCI privacy (AUSF handler stubbed)
- No security event logging or audit trail
- No SEPP N32 security (PRINS or TLS not implemented)
- **3GPP Rel-18:** Enhanced network security, AKMA (Authentication and Key Management for Applications)
- **6G Extension:** Zero-trust architecture with continuous authentication, AI-driven threat detection, quantum-safe cryptography (post-quantum algorithms), decentralized identity management (DID/SSI)

**Priority:** CRITICAL -- Zero-trust is non-negotiable for 6G deployment.

### 3.6 Digital Twin Network Functions

**Current State:** No digital twin capability. No simulation, modeling, or state replication infrastructure.

**Gaps:**
- No digital twin framework or data model
- No real-time network state mirroring
- No what-if scenario simulation
- No predictive maintenance capabilities
- No network topology modeling
- No protocol behavior simulation
- **6G Requirement:** Digital twins of physical network for planning, optimization, and autonomous operations
- Requires integration with AI/ML (3.1), metrics collection (partially exists via ogs-metrics), and comprehensive state export

**Priority:** MEDIUM-HIGH -- Emerging 6G requirement per ITU-R IMT-2030.

### 3.7 Intent-Driven Network Management

**Current State:** No intent management. All configuration is imperative (YAML files, CLI arguments).

**Gaps:**
- No intent translation engine (natural language / policy to configuration)
- No intent lifecycle management (creation, conflict resolution, verification)
- No closed-loop automation (monitor -> analyze -> plan -> execute)
- No declarative network configuration framework
- No policy conflict detection and resolution
- **6G Requirement:** Operators express desired outcomes; network autonomously achieves them
- Requires AI/ML (3.1), digital twins (3.6), and comprehensive telemetry

**Priority:** MEDIUM -- Important for 6G operational efficiency.

### 3.8 Compute-Aware Networking (CAN)

**Current State:** No compute awareness. UPF selection is not implemented. No resource monitoring.

**Gaps:**
- No compute resource discovery and monitoring
- No compute-aware traffic steering
- No workload placement optimization
- No compute resource abstraction layer
- No joint compute-communication optimization
- **3GPP Rel-19:** Compute-aware networking study items
- **6G Extension:** Native compute-communication convergence, distributed computing fabric

**Priority:** MEDIUM -- Growing importance in 6G for edge and AI workloads.

### 3.9 Green Networking / Energy Efficiency

**Current State:** No energy management. No NF sleep/wake capabilities. No traffic-adaptive resource scaling.

**Gaps:**
- No energy-aware NF scheduling
- No NF sleep mode or dynamic scaling
- No traffic prediction for energy optimization (requires NWDAF)
- No energy consumption metrics collection
- No carbon-aware workload placement
- **3GPP Rel-18:** Network energy saving (NES) features
- **6G Extension:** Zero-energy devices support, energy harvesting integration, sustainable networking targets

**Priority:** MEDIUM -- ITU-R IMT-2030 includes sustainability as a key design principle.

### 3.10 Non-Terrestrial Networks (NTN) Support

**Current State:** No NTN support. No satellite, HAPS, or UAV integration.

**Gaps:**
- No NTN-specific timing/delay compensation in AMF/SMF
- No discontinuous coverage handling
- No satellite ephemeris data management
- No NTN-specific mobility management
- No store-and-forward mechanism for intermittent connectivity
- No NTN-specific QoS profiles
- **3GPP Rel-17/18:** NTN phases 1 & 2 for NR-NTN and IoT-NTN
- **6G Extension:** Ubiquitous 3D coverage (terrestrial + NTN + aerial), seamless handover across domains

**Priority:** MEDIUM -- Critical for 6G's ubiquitous coverage vision.

### 3.11 Time-Sensitive Networking (TSN) Integration

**Current State:** No TSN support. No deterministic networking capabilities.

**Gaps:**
- No TSN translator functions (DS-TT, NW-TT)
- No IEEE 802.1Q integration
- No deterministic QoS guarantees
- No time synchronization (gPTP/IEEE 1588)
- No TSN bridge configuration
- **3GPP Rel-16/17:** 5G TSN integration
- **6G Extension:** Native deterministic networking, ultra-reliable low-latency (<100us), factory automation support

**Priority:** MEDIUM -- Important for industrial 6G use cases.

### 3.12 Integrated Sensing and Communication (ISAC)

**Current State:** No sensing capability. This is a fundamentally new 6G capability.

**Gaps:**
- No sensing NF or sensing data management
- No joint radar-communication waveform support
- No sensing data collection and processing pipeline
- No location/environment sensing service exposure
- **6G Requirement:** Radio signals used simultaneously for communication and sensing (radar, positioning, imaging)
- Requires new RAN-core interfaces beyond current NGAP

**Priority:** LOW (near-term) / HIGH (6G target) -- A defining 6G feature per ITU-R IMT-2030.

---

## 4. Cross-Cutting Infrastructure Gaps

### 4.1 Observability Stack
- **Metrics:** ogs-metrics provides Prometheus Counter/Gauge/Histogram framework. Not wired to any NF except AMF (has metrics field).
- **Logging:** Uses `env_logger` + `log` crate. No structured logging (JSON). No distributed tracing.
- **Tracing:** No OpenTelemetry integration. No span propagation across NF boundaries.
- **Gap:** Need structured logging, distributed tracing (OpenTelemetry), and metrics integration across all NFs.

### 4.2 Configuration Management
- **Current:** Each NF has its own YAML parsing (AMF and SMF have manual line-by-line parsers). No unified config framework.
- **Gap:** Need centralized configuration management, hot-reload, environment variable override, config validation.

### 4.3 Deployment and Orchestration
- **Current:** Standalone binaries with `clap` CLI parsing. No containerization files. No Helm charts.
- **Gap:** Need Dockerfiles, Kubernetes manifests, Helm charts, operator pattern for lifecycle management.

### 4.4 Testing Infrastructure
- **Current:** Unit tests exist for most NFs (FSM state transitions, type creation). No integration tests. No end-to-end tests.
- **Gap:** Need integration test framework (multi-NF), protocol conformance tests, performance benchmarks, chaos testing.

### 4.5 Database Layer
- **Current:** ogs-dbi has MongoDB stubs. HSS and PCRF reference MongoDB for subscriber data.
- **Gap:** No working database integration. Need MongoDB driver implementation, schema management, connection pooling.

---

## 5. Prioritized Roadmap

### Phase A: 5G Foundation (Estimated effort: 17 weeks per todo.txt)

| Step | Work Items | Dependencies | Priority |
|------|-----------|-------------|----------|
| A1 | Timer management system + SBI event loop wiring | None | CRITICAL |
| A2 | Error response framework (ProblemDetails integration) | A1 | HIGH |
| A3 | NRF client integration for all NFs | A1, A2 | HIGH |
| A4 | NGAP/S1AP ASN.1 encoding library | A1 | HIGH |
| A5 | AMF: NGAP handler, NAS processing, UE context | A1, A3, A4 | HIGH |
| A6 | SMF: N4/PFCP session establishment with UPF | A1, A3 | HIGH |
| A7 | AUSF/UDM/UDR: Authentication and subscriber data | A1, A3 | HIGH |
| A8 | PCF: Policy decision engine, PCC rules | A1, A3 | MEDIUM |
| A9 | SCP: Request forwarding, load balancing | A1, A3 | MEDIUM |
| A10 | SEPP: N32 security, message filtering | A1, A3 | MEDIUM |
| A11 | EPC: Diameter integration, HSS/MME handlers | A1 | LOW |
| A12 | UPF: URR, QER, FAR enhancements | A6 | LOW |

### Phase B: 5G-Advanced / Pre-6G (New development)

| Step | Work Items | Dependencies | Priority |
|------|-----------|-------------|----------|
| B1 | mTLS + OAuth 2.0 for NF-to-NF security | A3 | CRITICAL |
| B2 | NWDAF NF (data collection, basic analytics) | A3, A5, A6 | HIGH |
| B3 | Enhanced slicing (NSACF, slice SLA monitoring) | A3, A5, A8 | HIGH |
| B4 | Observability (OpenTelemetry, structured logging) | A1 | HIGH |
| B5 | Database layer (MongoDB driver, schema management) | A7 | HIGH |
| B6 | EASDF + edge computing support | A3, A6 | MEDIUM |
| B7 | NTN timing/mobility extensions | A5 | MEDIUM |
| B8 | TSN integration (DS-TT, NW-TT stubs) | A6 | MEDIUM |
| B9 | Containerization (Docker, K8s, Helm) | All A-phase | MEDIUM |

### Phase C: 6G Core Evolution

| Step | Work Items | Dependencies | Priority |
|------|-----------|-------------|----------|
| C1 | SBA 2.0 (gRPC/protobuf, event-driven, HTTP/3) | B4 | HIGH |
| C2 | AI-native NWDAF (ML model serving, federated learning) | B2 | HIGH |
| C3 | Zero-trust architecture (continuous auth, post-quantum crypto) | B1 | HIGH |
| C4 | Digital twin framework | B2, B4 | MEDIUM |
| C5 | Intent-driven management engine | B2, C4 | MEDIUM |
| C6 | Compute-aware networking | B6 | MEDIUM |
| C7 | Green networking (energy-aware scheduling, NF sleep) | B2, B4 | MEDIUM |
| C8 | ISAC support (sensing NF, data pipeline) | C1 | LOW |
| C9 | Dynamic micro-slicing (<ms granularity) | B3, C2 | LOW |

---

## 6. New 6G Network Functions Required

The following NFs do not exist in the codebase and must be created for 6G:

| New NF | Purpose | 3GPP Reference | 6G Relevance |
|--------|---------|----------------|-------------|
| **NWDAF** | Network Data Analytics | TS 23.288 | AI-native core, predictive automation |
| **EASDF** | Edge Application Server Discovery | TS 23.548 | Edge computing, MEC integration |
| **NSACF** | Network Slice Admission Control | TS 23.502 Rel-17 | Slice SLA assurance |
| **TSCTSF** | Time-Sensitive Communication and TSN System | TS 23.501 Rel-17 | Deterministic networking |
| **DCCF** | Data Collection Coordination Function | TS 23.288 Rel-17 | Analytics data pipeline |
| **MFAF** | Messaging Framework Adaptation Function | TS 23.288 Rel-17 | Analytics messaging |
| **AF** | Application Function (generic) | TS 23.501 | Application-network integration |
| **NEF** | Network Exposure Function | TS 23.502 | Capability exposure to 3rd parties |
| **CHF** | Charging Function | TS 32.240 | Converged charging |
| **Digital Twin NF** | Network digital twin management | ITU-R IMT-2030 | Simulation, planning, optimization |
| **Intent Engine** | Intent-to-configuration translation | ITU-R IMT-2030 | Autonomous network operations |
| **Sensing NF** | ISAC data management | ITU-R IMT-2030 | Integrated sensing and communication |

---

## 7. Recommendations

### 7.1 Immediate (0-3 months)
1. **Complete Phase A1-A3** (timer management, SBI event loop, error responses, NRF integration). This unblocks all other work.
2. **Implement ogs-ngap** ASN.1 encoding to enable AMF-gNB communication.
3. **Wire ogs-metrics** to all NFs for basic observability.
4. **Add mTLS** between NFs as a security baseline.

### 7.2 Short-term (3-6 months)
5. **Complete Phase A5-A8** (AMF, SMF, AUSF/UDM/UDR, PCF handlers) for basic mobile connectivity.
6. **Implement NWDAF** with data collection from AMF/SMF/UPF as the foundational 6G capability.
7. **Deploy observability stack** (OpenTelemetry, structured logging, Prometheus dashboards).
8. **Begin containerization** (Dockerfiles, CI/CD pipeline).

### 7.3 Medium-term (6-12 months)
9. **Complete SBA 2.0 planning**: Evaluate gRPC/HTTP3 as SBI transport alongside HTTP/2.
10. **Implement enhanced slicing** with NSACF and slice SLA monitoring.
11. **Build edge computing** support with EASDF and latency-aware UPF selection.
12. **Prototype digital twin** framework using network state exports and metrics.

### 7.4 Long-term (12-24 months)
13. **AI-native NWDAF** with ML model serving, federated learning, autonomous operations.
14. **Zero-trust evolution** with post-quantum cryptography, continuous authentication.
15. **Intent-driven management** engine with natural language policy translation.
16. **ISAC support** pending 3GPP standardization progress.

---

## 8. Architecture Strengths for 6G Evolution

Despite the gaps, the project has several architectural strengths that position it well for 6G:

1. **Pure Rust:** Memory safety, concurrency safety, and performance characteristics align with 6G requirements for reliability and efficiency.
2. **Tokio async runtime:** All NFs use async I/O, which enables high-throughput, low-latency processing required for 6G.
3. **Clean FSM architecture:** Consistent state machine pattern across all NFs enables systematic feature extension.
4. **Modular library design:** 18 shared libraries with clear separation of concerns enable independent evolution.
5. **Working data plane (UPF):** TUN device, GTP-U, PFCP session management provide a solid user plane foundation.
6. **Working SBI stack:** HTTP/2 server/client with hyper/h2 provides a modern SBA foundation.
7. **Comprehensive NAS library:** Both 5GS and EPS NAS message support with security context.
8. **Metrics framework:** Prometheus-compatible metrics collection exists and needs wiring, not creation.

---

*Report generated by deep source code analysis of 17 NFs and 18 shared libraries across ~50,000 lines of Rust code.*
