# Intent-Driven Closed-Loop Policy (Design Note)

> **Non-normative 6G research.** Intent-driven, closed-loop network
> management ("declare an outcome, let the core measure and self-adjust")
> is a 6G / autonomous-networks research theme. **No frozen Rel-20 Stage-3
> specification exists for it**; the closest normative anchor is the
> Rel-17/18 intent-management work (TS 28.312), with TS 23.288 §6.9 /
> TS 29.520 (NWDAF analytics) and TS 23.503 / TS 29.512 (PCF policy) as the
> surrounding machinery. This is a research shape for education, not a
> conformance target.
> Tracking issue: [#24](https://github.com/NextgCoreLab/nextgcore/issues/24).

## Intent schema

One declarative intent, one outcome: *keep slice X latency below N ms*.
Declared as a `pcf.intent` YAML block (see `docker/rust/configs/5gc/pcf.yaml`):

```yaml
pcf:
  intent:
    enabled: true            # default false; controller never starts when false
    sst: 1                   # target slice S-NSSAI SST
    sd: "000001"             # target slice S-NSSAI SD (informational in the spike)
    max_latency_ms: 20.0     # THE declared outcome
    poll_interval_secs: 30
    aggressiveness: 0.5      # SlaPolicyAdapter tuning knob, clamped to 0..=1
    nf_load_latency_ms_per_pct: 0.5   # synthetic latency proxy slope (see below)
```

At startup the block is deserialized into the **existing**
`PolicyIntent { intent_type: MinLatency, constraints: [MaxLatencyMs(N)] }`
(`intent_policy.rs` — previously `#[allow(dead_code)]` scaffolding, now
consumed by the loop) and translated once by `IntentPolicyTranslator` into
the baseline `GeneratedPolicy` (5QI 1, ARP 2, 10 ms DRX for `MinLatency`).

## The monitor → decide → act loop

```
        pcf.intent YAML ──► PolicyIntent ──► IntentPolicyTranslator ──► baseline GeneratedPolicy
                                                                              │
  ┌─────────────────────── controller task (tokio, every poll_interval_secs) ─┴──────────┐
  │                                                                                      │
  │ MONITOR  GET /nnwdaf-analyticsinfo/v1/analytics?event-id=QOS_SUSTAINABILITY (204 today)
  │          GET /nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD  ──► Observation     │
  │          (NWDAF found via NRF discovery: nnrf-disc, target-nf-type=NWDAF)            │
  │ DECIDE   Observation ──► AnalyticsState (populated) ──► AnalyticsPolicyEngine (log)  │
  │          Observation ──► SlaFeedback ──► SlaPolicyAdapter::adapt (DRX tightened)     │
  │ ACT      adapted GeneratedPolicy ──► SessionData ──► build_sm_policy_decision        │
  │          + structured log: "monitor → observed=… target=… action=…"                  │
  └──────────────────────────────────────────────────────────────────────────────────────┘
```

The decide row reuses code that was previously dead or test-only
(`intent_policy.rs`, `AnalyticsState` / `AnalyticsPolicyEngine` in
`context.rs`); the act row reuses the production `sm_policy_build.rs`
decision builder. The loop (`intent_loop.rs`) only connects them.

## The latency observation is a synthetic proxy (caveat)

The intent semantically wants the QoS-sustainability analytic, and the loop
does ask for it first — but today's `nwdafd` **serves real data only for
`NF_LOAD`** (`SUPPORTED_EVENTS = [NF_LOAD]`; `QOS_SUSTAINABILITY` is a
recognised token that always answers 204 no-data, and neither this build's
dead `QosSustainabilityPrediction` struct nor TS 29.520's
`QosSustainabilityInfo` carries a direct latency member). So the loop falls
back to the one live analytic and models observed latency as:

```
observed_ms = worst nfLoadLevelAverage (percent) × nf_load_latency_ms_per_pct
```

This is **illustrative only** — the same honesty rule as the NES synthetic
power model (`docs/NES.md`). When `nwdafd` grows a real QoS-sustainability
computation, `observe_nwdaf` is the single place to swap the source.

## Scope limits

- **One intent, one outcome.** No general intent engine, no multi-intent
  conflict resolution (out of scope per the issue).
- **Polling GET**, not `Nnwdaf_EventsSubscription` subscribe/notify.
- **Tighten-only.** A violated target shrinks DRX via `SlaPolicyAdapter`
  (aggressiveness-weighted, 5 ms floor); a reading back within target does
  not relax the policy (no hysteresis in the spike).
- **The re-issued decision is produced and logged, not delivered.** The
  adjusted `SmPolicyDecision` is built through the production
  `build_sm_policy_decision`; pushing it to an SMF over
  `Npcf_SMPolicyControl` UpdateNotify needs a per-session sweep plus a
  parts-taking notify variant (today's `…update_notify` re-derives from
  UDR) — a follow-up, not the spike.
- **`AnalyticsPolicyEngine` is observability-only** in the loop: its
  congestion reaction (throttle) can oppose a min-latency intent, so its
  verdict is logged (`engine=…`) but not applied.
- DRX and energy mode have no TS 29.512 `SmPolicyDecision` representation;
  they stay loop-internal.

## Observability

One structured log line per iteration (the acceptance signal):

```
intent-loop: monitor → observed=40.0ms(nf-load-proxy) target=20.0ms action=adapt(drx 10ms→5ms; rebuilt SmPolicyDecision intent-1) (slice sst=1 engine=CongestionAvoidance/Throttle)
```

(That example is self-consistent: 80% NF load × 0.5 ms/% slope = 40 ms
observed; latency ratio 2.0 × aggressiveness 0.5 halves the 10 ms DRX to its
5 ms floor; load ≥ 75% also trips the analytics engine's congestion verdict.)

`action` is one of `none(no-analytics)`, `none(within-target)`,
`none(no-headroom; …)` (still violated but DRX already at the adapter's 5 ms
floor — no false "adapt" claim, no identical decision rebuild), or
`adapt(…)`.

## Verification

```sh
# default build/behavior unchanged (feature off, block ignored)
cargo build -p nextgcore-pcfd
# feature build + the closed-loop unit tests (incl. the end-to-end iteration)
cargo test -p nextgcore-pcfd --features intent-loop intent_loop
```

Live demo: build pcfd with `--features intent-loop`, set
`pcf.intent.enabled: true`, and run it against a stack with NRF + NWDAF up
(NWDAF needs NRF NFStatusNotify traffic to have NF_LOAD samples); the PCF
then logs the `monitor → observed=… target=… action=…` line each poll.
