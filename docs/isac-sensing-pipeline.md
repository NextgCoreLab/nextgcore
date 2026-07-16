# ISAC Sensing Data Pipeline (Design Note)

> **Non-normative 6G research.** 3GPP ISAC work is study-stage only (SA1
> TR 22.837; SA2 Rel-19 study, TR 23.700-series) — **no frozen Stage-3
> specification or normative SBI exists** for any interface described here.
> This is a research shape, not a conformance target. Tracking issue:
> [#16](https://github.com/NextgCoreLab/nextgcore/issues/16).

## Flow

```
producer (gNB/UE sensing engine)
    │  POST /nnwdaf-sensingdata/v1/results   (JSON SensingResult)
    ▼
nwdafd collection endpoint  ──►  bounded in-memory ring buffer (100 results)
    │                             in NwdafContext
    ├── publishes SbiEventCategory::Isac ("SENSING_RESULT") on the NF-owned
    │   pub-sub broker (nextgcore-sbi pubsub, 6g-extensions)
    ├── increments the ISAC_SENSING_RESULTS counter
    │   (AiMetricCategory::IsacSensing, nextgcore-metrics ai_native)
    ▼
consumer: GET /nnwdaf-analyticsinfo/v1/analytics?event-id=ISAC_SENSING
    → 200 {"isacSensingSummary": {ingestedTotal, buffered, latest}}
    → 204 when nothing has been ingested
```

Everything is behind the `sensing` cargo feature of `nextgcore-nwdafd`
(off by default; it also enables `nextgcore-sbi/6g-extensions` for the
pub-sub bus). The default build and default nwdafd behaviour are unchanged.

## Design choices

- **One canonical type set.** `nextgcore-proto::isac` (serde-capable) is the
  wire type; the duplicate non-serde `SensingResult`/`SensingConfig` that
  lived in `nextgcore-proto::types` was removed, and the isac types are
  re-exported at the proto crate root.
- **Reuse nwdafd, not a new NF.** NWDAF is the natural analytics sink; a
  future NEF (no `nextgcore-nefd` exists today) would re-expose the summary
  northbound to AFs — out of scope here.
- **`ISAC_SENSING` is not a TS 29.520 `NwdafEvent`.** The analytics GET
  intercepts the token before `AnalyticsId` parsing so the real TS 29.520
  surface stays untouched.
- **Bounded store, NF-context lock rules.** `RwLock<VecDeque>` capped at 100
  (matching `AnalyticsEngine::MAX_SAMPLES` house style); callers take the
  outer context read lock first, then exactly one interior lock at a time.
- **Event bus liveness.** There was no `EventBroker` instance anywhere in the
  tree; nwdafd now owns one, making `SbiEventCategory::Isac` the first live
  event category. Delivery is in-process bookkeeping (matched subscribers
  returned/counted) — no outbound notification HTTP yet.

## Verification

```bash
cargo test -p nextgcore-nwdafd --features sensing sensing   # 3 tests: round-trip, event, fail-closed
cargo build -p nextgcore-nwdafd                             # default build unchanged
```
