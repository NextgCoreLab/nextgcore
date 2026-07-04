# The AI and Analytics Stack

NextGCore's landing page opens with the phrase "the first AI-native 5G/6G Core Network." This chapter is the honest, code-grounded account of what that phrase actually maps to in the repository. The short version: there is **one** live analytics computation in the whole codebase — NF-load prediction by ordinary least-squares linear regression inside `nextgcore-nwdafd` — and a data-collection broker (`nextgcore-dccfd`) that no in-repo NF talks to. Everything else the marketing calls "AI" (ONNX inference, a four-layer analytics engine, anomaly detection, prescriptive/autonomous actions, intent-based automation, federated learning) is either library-only scaffolding that no runtime path reaches, or aspirational copy with no corresponding Rust code at all. The point of this page is to tell you exactly which is which, with a file-and-function reference for every claim, so you can re-derive it yourself.

> **Honesty note:** Everything described here is validated only by this project's own unit tests (including strict-peer tests that run the real `nextgcore-nrfd` notify pipeline against the real NWDAF router in-process) plus the matched-simulator Docker E2E suite (84/84 green as of 2026-07-02). It is **not** third-party certified, and there is no frozen 3GPP Rel-20 / 6G Stage-3 specification for any of the "6G" items to be conformant to. Note further that `nextgcore-nwdafd` and `nextgcore-dccfd` are **not even part of the Docker E2E health gate** (`e2e-test.sh` waits on `mongodb nrf udr udm ausf pcf nssf bsf smf amf upf gnb ue` — the analytics NFs are covered by unit/strict-peer tests only). See [Gap Analysis: 6G](../gaps/6g-gap-analysis.md) for the wider 6G posture; this chapter cross-links it rather than repeating it.

## Marketing claims vs. what the code does

The audited AI/6G surface is **7 NF binaries** (NWDAF, DCCF, EES, LMF, MB-SMF, NSACF, PIN — the set `docs/index.html` itself enumerates at its NRF component card). Before the component tour, here is the claim-by-claim verification the rest of the chapter substantiates. Every "reality" cell was checked by reading the named source; a repo-wide grep for the marketing keywords (`onnx`, `z-score`, `4-layer`, `prescriptive`, `reinforcement`, `autonomous action`) returns **zero hits in Rust source**.

| Landing-page claim (`docs/index.html`) | Code reality | Where verified |
|---|---|---|
| "NWDAF with 4-layer analytics engine (real-time anomaly detection, predictive load forecasting, prescriptive optimization, autonomous actions)" | Single-layer. One analytic (`NF_LOAD`) computed by OLS linear regression; no anomaly/prescriptive/autonomous layer exists in any runtime path. | `analytics.rs::compute_nf_load`; `context.rs` `SUPPORTED_EVENTS` |
| "ML model lifecycle management with ONNX inference" | No ONNX anywhere. `MlModel`/`MlModelRegistry`/`FeedbackCollector` are in-memory structs with **no runtime caller** (only `#[cfg(test)]`). Model URLs handed to consumers are synthetic placeholders. | `ml_service.rs` (`MlModelRegistry`, `synthetic_model_url`) |
| "Intent-Based Automation … RL-based learning from outcomes" | An intent→policy translator exists in PCF but is `#[allow(dead_code)] mod intent_policy` — "not wired to any live handler," a static match table, no RL. | `nextgcore-pcfd/src/lib.rs`; `nextgcore-pcfd/src/intent_policy.rs::translate` |
| "Federated Analytics … model transfer … privacy-preserving computation" | `FederationManager` + FedAvg (`FlAggregationRound::aggregate`) exist but `federation` is only `pub mod federation;` — never instantiated by any code path. | `federation.rs`; `main.rs:23` |
| "NWDAF L1 Z-score anomaly detection → anomaly score 78/100" (workflow diagram) | `record_anomaly`/`get_anomalies` exist but are called only from tests; `ABNORMAL_BEHAVIOUR` is not in `SUPPORTED_EVENTS`, so the query/subscription surface returns 204 / declares it failed. | `analytics.rs::record_anomaly`; `context.rs::SUPPORTED_EVENTS` |
| "ONNX trajectory model → UE moving NE at 30km/h" (workflow diagram) | `predict_mobility` is a most-visited-next-cell counter (no model), and is test-only; `UE_MOBILITY` answers 204 on the wire. | `analytics.rs::predict_mobility`; `sbi_handler.rs::handle_analytics_info_query_with_ctx` |
| "DCCF … brokers NWDAF analytics requests at scale" | DCCF is a standalone subscribe/fan-out broker; **no in-repo NF calls its `Ndccf` APIs**, and NWDAF collects from the NRF directly, not via DCCF. | `nextgcore-dccfd/src/main.rs`; `nrf_collector.rs` |

The remainder of this chapter is the substantiation.

## Components involved

| NF | Binary | AI/analytics depth in this repo | Config page |
|---|---|---|---|
| **NWDAF** | `nextgcore-nwdafd` | The only NF with a live analytics computation. One event (`NF_LOAD`) via OLS regression; ML/mobility/anomaly/federation code present but not on any served path. | [NWDAF](../configuration/nwdaf.md) |
| **DCCF** | `nextgcore-dccfd` | Data-collection broker: subscribe + fan-out + context-document CRUD. No analytics; no in-repo producer or consumer. | [DCCF](../configuration/dccf.md) |
| **EES** | `nextgcore-eesd` | Edge Enabler Server (Application Context Relocation, EAS/ECS registration). Not analytics/ML; filed under "AI-Native" on the landing page but it is a Rel-17/18 edge NF. | [EES](../configuration/ees.md) |
| **PIN** | `nextgcore-pind` | Personal IoT Network management. Not analytics/ML; a Rel-18 IoT NF. | [PIN](../configuration/pin.md) |
| **LMF / MB-SMF / NSACF** | `-lmfd` / `-mbsmfd` / `-nsacfd` | Positioning, multicast session mgmt, slice admission. Grouped with "AI-Native functions" on the site for marketing, but they are conventional Rel-16/17 control NFs, not intelligence. | [LMF](../configuration/lmf.md), [MB-SMF](../configuration/mbsmf.md), [NSACF](../configuration/nsacf.md) |

The rest of this chapter deep-dives only the two NFs that genuinely belong to an "analytics stack" — NWDAF and DCCF. The others are conventional NFs documented on their own config pages.

## NWDAF: the one live analytics path (NF_LOAD)

The single source of truth for what NWDAF can actually produce is one constant:

```rust
// src/bins/nextgcore-nwdafd/src/context.rs
pub const SUPPORTED_EVENTS: &[AnalyticsId] = &[AnalyticsId::NfLoad];
```

`AnalyticsId` (`context.rs`) recognizes 16 TS 29.520 `NwdafEvent` tokens on the wire (`NF_LOAD`, `UE_MOBILITY`, `SLICE_LOAD_LEVEL`, …), but `is_supported()` reads `SUPPORTED_EVENTS`, so only `NF_LOAD` has a live collector and computation. Three wire surfaces derive from this constant: the NRF profile advertisement, the AnalyticsInfo query, and the events-subscription dispatcher — described below.

### Router and served APIs

`nwdaf_sbi_request_handler` in `main.rs` matches the request path against a fixed table (default SBI port `7815`, `Args` in `main.rs`):

```text
GET    /nnwdaf-analyticsinfo/v1/analytics            -> handle_analytics_info_query
POST   /nnwdaf-eventssubscription/v1/subscriptions   -> handle_subscription_create
GET|PUT|DELETE  …/subscriptions/{id}                 -> get/update/delete
POST   /nnwdaf-mlmodelprovision/v1/subscriptions     -> handle_ml_prov_subscription_create
PUT|DELETE      …/subscriptions/{id}                 -> ml_prov update/delete
POST   /nnwdaf-nfstatus-notify/v1/notify             -> nrf_collector::handle_nf_status_notify
```

The `/models` resource deliberately does not exist — `POST /nnwdaf-mlmodelprovision/v1/models` returns 404 (`ML Model Provision` is modeled as a Subscribe/Notify resource only, per code comments citing TS 29.520). The last route, `/nnwdaf-nfstatus-notify/v1/notify`, is a NextGCore-chosen callback URI (callback URIs are consumer-chosen), not a TS 29.520 resource.

### Where the data comes from: NRF, not the RAN

The marketing workflow shows gNBs streaming "UE measurements (RSRP, RSRQ, SINR)" into NWDAF. In code, the **only** data source is the NRF's view of NF load. The collector is armed in `main()` and subscribes to the NRF:

1. `main()` sets `NrfCollectorConfig` (nrf_uri + a callback of `http://<sbi-addr>:<sbi-port>/nnwdaf-nfstatus-notify/v1/notify`) then calls `nrf_collector::subscribe_nf_status` — `main.rs`.
2. `subscribe_nf_status` POSTs an `Nnrf_NFManagement` NFStatusSubscribe `SubscriptionData` to `{nrf}/nnrf-nfm/v1/subscriptions`. The body (`build_nf_status_subscription_body`, `nrf_collector.rs`) sets `reqNfType: "NWDAF"` and `reqNotifEvents: [NF_REGISTERED, NF_DEREGISTERED, NF_PROFILE_CHANGED]` and **omits** `subscrCond` so every NF matches (per code comments citing TS 29.510 §5.2.2.5). Every failure is non-fatal — logged and retried on the dispatcher tick (`maybe_renew_nrf_subscription`).
3. The NRF then POSTs `NotificationData` back to the callback. `parse_notification_data` (`nrf_collector.rs`) fail-closes on a missing mandatory `event`/`nfInstanceUri` (400) but ignores unknown fields, and extracts `nfProfile.load` (0–100) or a `profileChanges` `/load` add/replace/remove.
4. `ingest_notification` (`nrf_collector.rs`) turns each observed load into an `NfLoadSample` with `cpu = load/100` via `AnalyticsEngine::ingest_nf_load`; `NF_DEREGISTERED` calls `remove_nf_instance`, so a departed NF's analytics go dark rather than serving stale numbers.

```text
   NRF ──NFStatusNotify (load=40)──▶ /nnwdaf-nfstatus-notify/v1/notify
                                         │  parse_notification_data
                                         ▼
                                   ingest_notification
                                         │  cpu = load/100
                                         ▼
                        AnalyticsEngine.nf_samples[instance]  (ring buffer, MAX_SAMPLES=100)
```

### The computation: OLS linear regression (not ML)

`AnalyticsEngine::compute_nf_load` (`analytics.rs`) is the entire "analytics engine." For an instance's last ≤5 samples it fits `y = a + b·x` by ordinary least squares, projects one step ahead for `predicted_load` (clamped to [0,1]), and computes the coefficient of determination R² as `confidence`. The module header and the function docstring both state this in the source: *"All analytics in this module use ordinary least-squares linear regression … No ML model is used … `confidence` … reflects how well the predictor fits the observed data, NOT trained-model accuracy."* A single sample yields `confidence = 0.0`; a flat series yields `1.0`.

`compute_event_infos` (`notification_dispatcher.rs`) shapes the result into the TS 29.520 `NfLoadLevelInformation` array: `nfType`, `nfInstanceId`, `nfCpuUsage`/`nfLoadLevelAverage` = `round(mean_cpu·100)`, `nfLoadLevelpeak` = `round(peak_cpu·100)`, `confidence` = `round(R²·100)` as an integer 0–100, and `nfStatus` as the object form (`statusRegistered`/`statusUnregistered`) only when an NRF profile is cached. No samples → an empty array, never a fabricated entry.

### Query path (Nnwdaf_AnalyticsInfo)

`handle_analytics_info_query_with_ctx` (`sbi_handler.rs`) enforces the honesty gate:

1. Missing `event-id` → 400 `MANDATORY_QUERY_PARAM_INCORRECT`.
2. Unrecognized token (outside the 16-value `AnalyticsId` enum) → 400 `INVALID_ANALYTICS_TYPE`.
3. Recognized-but-unsupported token (anything not in `SUPPORTED_EVENTS`, i.e. everything except `NF_LOAD`) → **204 No Content** with an empty body.
4. `NF_LOAD` with an optional `event-filter` (JSON `nfInstanceIds`/`nfTypes`) computes from the shared engine; malformed filter JSON → 400; no matching data → 204; otherwise 200 with an `AnalyticsData` object.

### Subscription + dispatcher path (Nnwdaf_EventsSubscription)

`parse_events_subscription` (`sbi_handler.rs`) requires `notificationURI` (exact casing) and a non-empty `eventSubscriptions[]`, else 400. A subscription is always accepted (201), but every subscribed event with no live collector is declared failed in the response body via `fail_event_reports` → `failEventReports[] { event, failureCode: "UNAVAILABLE_DATA" }`. A background task (`spawn_dispatcher`, tick `DEFAULT_DISPATCH_INTERVAL_SECS = 30 s`) runs `dispatch_notifications`:

1. Renew the NRF collector subscription if needed (`maybe_renew_nrf_subscription`).
2. For each active, non-expired, due subscription (`AnalyticsSubscription::is_due_for_notification`, honoring `repetition_period_secs`, default 60 s), build `eventNotifications[]` via `build_event_notifications`.
3. `build_event_notifications` skips any event not in `SUPPORTED_EVENTS`, skips any event whose computed `*Infos` array is empty, and for `THRESHOLD` events applies edge-triggered gating (`threshold_crossed` + `extract_level`, which only exposes a scalar for `NF_LOAD`). PERIODIC events with data are always emitted.
4. POST the `NnwdafEventsSubscriptionNotification` body to the consumer's `notificationURI`; on success update `last_notification_time`. Network errors are logged and never abort the cycle.

Note a stale in-code comment: `NotificationMethod::Threshold`'s docstring in `context.rs` says threshold evaluation is "deferred … the dispatcher currently fires periodically regardless of method," but the dispatcher (`build_event_notifications` + `threshold_crossed`, nwafd-07) does implement threshold gating. Trust the dispatcher code, not that comment.

## NWDAF: the parts that are library-only (not served)

These modules compile and have unit tests, but **no runtime path reaches them** — they are honest scaffolding, and this chapter flags them so nobody mistakes their existence for a served capability.

- **ML model registry & feedback loop** (`ml_service.rs`): `MlModel`, `MlModelRegistry` (register/deploy/`best_deployed`/`deprecate_others`), and the `FeedbackCollector`/`FeedbackRegistry` accuracy-driven retrain loop are all exercised only under `#[cfg(test)]`. A grep for their constructors outside `ml_service.rs` returns nothing. What the served `Nnwdaf_MLModelProvision` path actually does: `parse_ml_model_prov_subsc` stores a subscription and the dispatcher POSTs `build_ml_model_prov_notif_body`, whose model URL is `synthetic_model_url` — explicitly documented as *"a stable, well-formed placeholder … no downloadable model artefact exists behind it."*
- **UE mobility, abnormal behaviour, QoS sustainability** (`analytics.rs`): `predict_mobility` (a most-visited-next-cell counter, not a model), `record_anomaly`/`get_anomalies`, and the `QosSustainabilityPrediction` struct (which has no computation function at all) are called only from `analytics.rs`'s own tests. Because their events are absent from `SUPPORTED_EVENTS`, the wire surface answers 204 (query) or `UNAVAILABLE_DATA` (subscription).
- **Federation / federated learning / DCCF-MFAF-ADRF integration** (`federation.rs`): `FederationManager`, `FlAggregationRound::aggregate` (element-wise FedAvg mean), and the `FederationPeerType` enum (including `Dccf`, `Mfaf`, `Adrf`) exist, but `main.rs` only declares `pub mod federation;` — nothing constructs a `FederationManager`. ADRF and MFAF have no binaries in `src/bins/`, so neither is a real NF. The labels do appear in more than one place: `federation.rs` (`FederationPeerType` variants, `federation.rs:24-26`), the SCP's `NfType` table (`nextgcore-scpd/src/context.rs:40,46` and `proxy.rs:248`), the core `nextgcore-sbi` `NfType` enum (`MFAF` is a variant at `types.rs:264`, stringified at `:308`), and ADRF is named in `nextgcore-dccfd`'s own module doc-comment (`nextgcore-dccfd/src/main.rs:5`). But those are enum tokens and comments — not a running ADRF/MFAF NF.

## DCCF: a standalone data broker

`nextgcore-dccfd` (default SBI port `7816`, `Args` in `main.rs`) is a Data Collection Co-ordination Function that brokers between data producers and analytics consumers — in principle. `dccf_request_handler` (`main.rs`) serves:

```text
GET  /healthz                                          -> {"status":"ok"}
POST /ndccf-datamanagement/v1/subscriptions            -> create subscription (notifyUri)
GET|DELETE  …/subscriptions/{id}                       -> lookup / delete
POST /ndccf-datamanagement/v1/notify                   -> ingest + fan-out to subscribers
POST /ndccf-contextdocument/v1/contexts                -> create analytics context
GET|DELETE  …/contexts/{id}                            -> lookup / delete
```

The data flow on the `notify` route:

1. A producer POSTs a body to `/ndccf-datamanagement/v1/notify`.
2. `dccf_context_fanout_notify` (`context.rs`) returns every registered subscription that has a non-empty `notify_uri` — with **no filtering by event type, data key, or subscription predicate**. Every subscriber gets every notification.
3. The handler wraps the raw body as `{"data": <body>}` and POSTs it (fire-and-forget `tokio::spawn`) to each subscriber's callback URI, then returns 204.

State lives in a process-wide `DccfContext` (`context.rs`): a set of subscription IDs, an ID→callback map, and a set of analytics-context IDs. It is entirely in-memory and lost on restart.

**The load-bearing honesty point:** nothing in this repository consumes DCCF. A grep for the `Ndccf` service paths finds no client-side caller outside `nextgcore-dccfd` itself (the only other hits are the SBI type registry and the SCP's `NfType` enum). NWDAF's own load collector subscribes to the **NRF** directly (`nrf_collector.rs`), not through DCCF. So DCCF is a correct-looking broker with no in-repo producers or consumers — it is validated only by its own unit and OAuth2 strict-peer tests.

## The 6G research prototypes

The "6G" surface beyond NWDAF/DCCF is deliberately non-normative — there is no frozen Rel-20 Stage-3 wire spec to conform to, and the landing page carries that disclaimer inline. In code it amounts to:

- **Intent-based policy** — `nextgcore-pcfd/src/intent_policy.rs` (`IntentPolicyTranslator::translate`) maps a `PolicyIntent` (MaxThroughput, MinLatency, MinEnergy, …) to a `GeneratedPolicy` via a static match table. `nextgcore-pcfd/src/lib.rs` gates it as `#[allow(dead_code)] mod intent_policy` with the comment *"Future-use intent-policy translation (Rel-20 research scaffolding): not wired to any live handler."* There is no conflict detection, no RL, and no SBI surface. See the PCF page: [PCF](../configuration/pcf.md).
- **`6g-extensions` cfg gates** — the landing page states `cfg(feature = "6g-extensions")` gates live in `nextgcore-sbi` and `nextgcore-dbi`, but only half of that is code-backed. The feature and its `#[cfg(feature = "6g-extensions")]` gates exist in `nextgcore-sbi` (`Cargo.toml:12`, `src/lib.rs:44,51,67,87`) and — the actual second crate — `nextgcore-app` (`Cargo.toml:12`, `src/lib.rs:11,13`). A grep of `src/libs/nextgcore-dbi` returns **nothing**: `nextgcore-dbi` carries no such feature or gate, so the landing page's `nextgcore-dbi` attribution is not code-backed. What does exist is a pair of compile-time feature flags for optional Rel-18+ SBI/app extensions, not a running subsystem.

For ISAC, PQC, semantic communications, and the other TR 22.870-inspired items, the concrete assessment lives in [Gap Analysis: 6G](../gaps/6g-gap-analysis.md) — refer there rather than treating any of them as an implemented core-network capability.

## Simplifications and known gaps

Every item here is grounded in a specific source location.

- **One analytic, one algorithm.** Only `NF_LOAD` is live (`SUPPORTED_EVENTS`), computed by OLS linear regression (`compute_nf_load`). "Confidence" is regression R², not model accuracy — stated in the source docstrings.
- **No ONNX / no trained models / no four-layer engine.** Grep confirms zero occurrences in Rust source. The ML registry and feedback loop (`ml_service.rs`) have no runtime callers; provisioned model URLs are `synthetic_model_url` placeholders.
- **Anomaly / mobility / QoS analytics are test-only.** `record_anomaly`, `predict_mobility`, `QosSustainabilityPrediction` (`analytics.rs`) are unreachable from any served route; the wire answers 204 / `UNAVAILABLE_DATA`.
- **Federation is dead code.** `federation.rs` is declared but never instantiated; ADRF/MFAF have no binaries.
- **NWDAF ingests from the NRF only.** No gNB/AMF/SMF measurement collection exists despite the marketing workflow; the sole source is `NFProfile.load` via NFStatusNotify (`nrf_collector.rs`).
- **DCCF fan-out is unconditional.** `dccf_context_fanout_notify` sends every notification to every subscriber with a callback URI — no event/predicate matching.
- **DCCF capacity check is advisory.** `dccf_context_add_subscription_with_uri` returns `false` at capacity, but the POST handler in `main.rs` discards that boolean and always answers `201 Created`; over-capacity subscriptions are silently dropped rather than rejected.
- **DCCF advertises fewer services than it serves.** `register_with_nrf` (`main.rs`) publishes only the `ndccf-datamanagement` NF service, even though the router also serves `ndccf-contextdocument`; and `ContextDocument` DELETE returns 204 unconditionally (`dccf_context_remove_analytics_context` never reports absence).
- **All analytics state is in-memory.** Both NFs lose every subscription and sample on restart — no state files (NWDAF page confirms this).
- **Threshold-method docstring is stale.** `NotificationMethod::Threshold` in `context.rs` claims evaluation is deferred; the dispatcher actually implements it (`threshold_crossed`).

## How it is validated

There is no third-party certification. The evidence is unit tests, in-process strict-peer tests, and the Docker E2E suite:

- **NWDAF regression + shaping** — `analytics.rs` `#[cfg(test)] mod tests` (`test_nf_load_analytics`, `test_confidence_reflects_fit_quality`, `test_mobility_prediction`, `test_samples_bounded`); `notification_dispatcher.rs` tests (`test_notify_body_shape`, `test_per_instance_infos_and_filters`, `test_nf_load_info_spec_shape`, `test_threshold_predicate_directions`).
- **Real NRF → real NWDAF over the wire** — `main.rs` `mod g21_strict_peer_tests::test_g21_strict_peer_nrf_load_ingestion` drives the actual `nextgcore-nrfd` notify pipeline (`nrf_nnrf_nfm_send_nf_status_notify_all_async`, `apply_json_patch`) into the real NWDAF SBI server and asserts the reported average tracks a 40→60→70 PATCH sequence and goes dark (204) on deregistration.
- **NFStatusNotify ingestion** — `nrf_collector.rs` tests use golden TS 29.510 `NotificationData` bodies (`test_notify_nf_registered_full_profile_ingests_load`, `..._profile_changed_load_replace_and_add`, `..._deregistered_drops_instance`) plus fail-closed cases (missing `event`, out-of-range load → 400).
- **ML-provision + honesty gates** — `sbi_handler.rs` tests (`test_ml_prov_subscribe_201`, `test_honesty_unsupported_event_get_204`, `test_honesty_subscription_fail_event_reports`); `ml_service.rs` codec tests (`test_build_ml_prov_notif_body_shape`).
- **OAuth2 enforcement** — `main.rs` `mod oauth2_h8_tests` (NWDAF) and `main.rs` `mod oauth2_h8_tests` (DCCF): 401 on missing/wrong-audience Bearer, pass-through on a valid ES256 token.
- **DCCF broker** — `nextgcore-dccfd/src/context.rs` tests (`test_subscription_lifecycle`, `test_fanout_with_callback_uris`).
- **Docker E2E** — `docker/rust/e2e.sh` → `e2e-test.sh` (84/84 on 2026-07-02). As noted above, this suite's health gate does **not** include NWDAF or DCCF, so their coverage is the unit/strict-peer tests, not the end-to-end registration/data-plane run described in [Observability & Troubleshooting](../observability.md).
