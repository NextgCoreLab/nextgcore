# NextGCore Infrastructure Libraries -- 6G Gap Analysis

> Generated: 2026-02-07 | Scope: 9 infrastructure libraries under nextgcore/src/libs/

---

## Overview

| Library | Purpose | Modules | Completeness | 6G Readiness |
|---------|---------|---------|-------------|--------------|
| ogs-core | Core runtime (data structures, networking, timers) | 31 | **85%** | Medium |
| ogs-app | Application framework (config, init) | 4 | **80%** | Low |
| ogs-crypt | 3GPP cryptographic algorithms | 10 | **80%** | Low |
| ogs-dbi | MongoDB database interface | 5 | **70%** | Low |
| ogs-ffi | FFI bindings for C comparison testing | 2 | **90%** | N/A |
| ogs-metrics | Prometheus metrics collection | 5 | **75%** | Medium |
| ogs-tun | TUN/TAP device management | 4 | **80%** | Low |
| ogs-ipfw | IP firewall rule parsing | 3 | **85%** | Low |
| ogs-proto | Common protocol definitions (PlmnId, AmfId, etc.) | 4 | **90%** | Low |

---

## 1. ogs-core -- Core Runtime

**Port of**: lib/core/ from C implementation

### Modules (31)

| Category | Modules | Status |
|----------|---------|--------|
| Data Structures | `list` (doubly-linked), `hash` (hash table), `pool` (object pool), `rbtree` (red-black tree), `queue` (thread-safe) | Complete |
| Networking | `sockaddr`, `socket`, `sockopt`, `poll` (epoll), `tcp`, `udp` | Complete |
| Buffers | `pkbuf` (packet buffer), `tlv` (TLV encoding) | Complete |
| State Machine | `fsm` (finite state machine) | Complete |
| Timers | `timer` (timer wheel), `async_timer` (async timer for NF event loops) | Complete |
| Utilities | `errno`, `log`, `memory`, `strings`, `time`, `conv`, `rand`, `uuid`, `signal`, `thread` | Complete |

### 6G Gaps

| Gap | Details |
|-----|---------|
| No async I/O primitives | `poll` module uses sync epoll; NFs need full async support |
| No distributed timer | Timer wheel is process-local; 6G needs distributed coordination |
| No structured logging | Basic log module; needs OpenTelemetry-compatible structured logging |
| No lock-free data structures | Hash/list use locks; high-performance 6G data paths need lock-free alternatives |

### Completeness: **85%** -- Most comprehensive library; direct C port with all data structures

---

## 2. ogs-app -- Application Framework

### Modules (4)

| Module | Key Types | Status |
|--------|----------|--------|
| `yaml.rs` | `OgsYamlDocument`, `OgsYamlIter` | Complete |
| `config.rs` | `OgsGlobalConf`, `OgsLocalConf`, `OgsPlmnId`, `MaxConf`, `TimeConf` | Complete |
| `context.rs` | `OgsApp`, `OgsAppContext`, `LoggerConf`, `PoolConf`, `MetricsConf` | Complete |
| `init.rs` | `OgsAppInitializer`, command line options, initialize/terminate | Complete |

### 6G Gaps

| Gap | Details |
|-----|---------|
| No dynamic reconfiguration | Config is read once at startup; 6G needs runtime reconfiguration |
| No intent-based config | Imperative YAML only; no declarative intent translation |
| No config versioning | No support for config rollback or A/B deployment |

### Completeness: **80%**

---

## 3. ogs-crypt -- Cryptographic Library

### Modules (10)

| Module | Algorithm | Spec | Status |
|--------|-----------|------|--------|
| `milenage.rs` | Milenage (f1-f5, f1*/f5*) | TS 35.206 | Complete |
| `kasumi.rs` | KASUMI block cipher | TS 35.202 | Complete |
| `snow3g.rs` | SNOW 3G stream cipher | TS 35.216 | Complete |
| `zuc.rs` | ZUC stream cipher | TS 35.221 | Complete |
| `aes.rs` | AES-128 operations | FIPS 197 | Complete |
| `aes_cmac.rs` | AES-CMAC | RFC 4493 | Complete |
| `sha.rs` | SHA-1, SHA-256, SHA-384, SHA-512 | FIPS 180 | Complete |
| `kdf.rs` | Key derivation functions | TS 33.501 | Complete |
| `ecc.rs` | Elliptic curve (ECIES Profile A) | TS 33.501 | Complete |
| `base64.rs` | Base64 encoding/decoding | RFC 4648 | Complete |

### 6G Gaps

| Gap | Severity |
|-----|----------|
| **No post-quantum cryptography** (ML-KEM, ML-DSA) | Critical |
| No ZUC-256 (256-bit variant) | High |
| No SNOW5G (next-gen stream cipher) | Medium |
| No ECIES Profile B (secp256r1) | Medium |
| No hybrid key exchange (classical + PQC) | Medium |

### Completeness: **80%** for 5G | **0%** for post-quantum

---

## 4. ogs-dbi -- Database Interface

### Modules (5)

| Module | Key Functions | Status |
|--------|--------------|--------|
| `types.rs` | Subscriber data types, auth info | Complete |
| `mongoc.rs` | `OgsMongoc`, `OgsDbi` MongoDB client | Partial (connection mgmt) |
| `subscription.rs` | Auth info, SQN update, subscription data | Partial |
| `session.rs` | PDU session data queries | Partial |
| `ims.rs` | MSISDN, IMS data queries | Partial |

### 6G Gaps

| Gap | Details |
|-----|---------|
| No graph database support | 6G knowledge graphs need Neo4j/similar |
| No time-series database | Analytics and metrics storage |
| No distributed database | Single MongoDB instance only |
| No data federation | Cross-operator data sharing |

### Completeness: **70%**

---

## 5. ogs-ffi -- FFI Bindings

Testing utility for C comparison. Provides stub bindings by default, optional generated bindings.

### Completeness: **90%** | N/A for 6G

---

## 6. ogs-metrics -- Prometheus Metrics

### Modules (5)

| Module | Key Types | Status |
|--------|----------|--------|
| `context.rs` | Metrics context, global registry | Complete |
| `server.rs` | HTTP server for `/metrics` endpoint | Complete |
| `spec.rs` | Metric specification (Counter, Gauge, Histogram) | Complete |
| `instance.rs` | Metric instances with labels | Complete |
| `types.rs` | MetricType enum, label types | Complete |

### 6G Gaps

| Gap | Details |
|-----|---------|
| No OpenTelemetry support | Only Prometheus; 6G needs OTel for traces + logs + metrics |
| No AI-native observability | No anomaly detection or predictive alerting |
| No distributed tracing | No span/trace context propagation |
| No SLA metric enforcement | No automated SLA violation detection |

### Completeness: **75%** -- Functional Prometheus metrics; needs OTel for 6G

---

## 7. ogs-tun -- TUN Device Management

### Modules (4)

| Module | Status |
|--------|--------|
| `types.rs` | TUN device types | Complete |
| `io.rs` | Read/write operations | Complete |
| `linux.rs` | Linux TUN/TAP via ioctl | Complete |
| `macos.rs` | macOS utun support | Partial |

### Completeness: **80%**

---

## 8. ogs-ipfw -- IP Firewall Rules

### Modules (3)

| Module | Key Functions | Status |
|--------|--------------|--------|
| `types.rs` | `IpfwRule` struct | Complete |
| `rule.rs` | `compile_rule()` parser | Complete |
| `packet_filter.rs` | SDF filter matching | Complete |

### Completeness: **85%** -- Functional for 3GPP flow descriptions

---

## 9. ogs-proto -- Protocol Definitions

### Modules (4)

| Module | Key Types | Status |
|--------|----------|--------|
| `types.rs` | `PlmnId`, `AmfId`, `Guami`, `SNssai`, `Tai`, `Supi`, `Gpsi`, `Dnn` | Complete |
| `conv.rs` | BCD encoding, hex conversion, IP address conversion | Complete |
| `event.rs` | Event types for NF communication | Complete |
| `timer.rs` | Timer ID types and constants | Complete |

### 6G Gaps

| Gap | Details |
|-----|---------|
| No 6G-specific types | Missing: ISAC config, semantic comm parameters, SHE compute descriptors |
| No NTN types | No satellite orbit parameters, timing advance types |
| No AI/ML types | No model metadata, inference request/response types |

### Completeness: **90%** for 5G

---

## Cross-Library 6G Readiness Summary

| Capability | Current Support | Gap Severity |
|------------|----------------|-------------|
| Post-quantum crypto | None | Critical |
| OpenTelemetry observability | None (Prometheus only) | High |
| Dynamic reconfiguration | None | High |
| Async I/O throughout | Partial (ogs-core has sync poll) | High |
| Structured logging | None | Medium |
| Distributed coordination | None | Medium |
| Graph/time-series DB | None (MongoDB only) | Medium |
| 6G protocol types | None | Medium |
| Lock-free data structures | None | Low |

### Priority Recommendations

1. **Add post-quantum crypto** to ogs-crypt (ML-KEM, ML-DSA)
2. **Add OpenTelemetry** alongside Prometheus in ogs-metrics
3. **Migrate to full async I/O** in ogs-core networking modules
4. **Add dynamic config reload** to ogs-app
5. **Add 6G types** to ogs-proto (ISAC, NTN, AI/ML, semantic comm)
6. **Add ZUC-256** to ogs-crypt for 256-bit security
