# Slice SLA Observe-Only Assurance (Design Note)

> **Non-normative prototype.** Slice management & assurance align with
> TS 28.530 / TS 28.541 and the underlying admission state is TS 29.536
> (NSAC), but this loop is a research shape for education — **observe-only,
> no remediation**, and no frozen closed-loop-assurance Stage-3 applies.
> Tracking issue: [#27](https://github.com/NextgCoreLab/nextgcore/issues/27).

## What it does

A feature-gated (`sla-observe`, off by default) observer task inside
`nextgcore-nsacfd` evaluates a **configured per-slice SLA descriptor**
against the live per-slice KPIs the NSACF already maintains — the
admitted-UE and PDU-session utilization percentages derived from its
TS 29.536 admission sets — and emits an observable signal on breach:

- a `log::warn!` **breach transition** line (and `info` on clear) —
  transitions only, no per-tick spam;
- Prometheus-text metrics (three gauges plus one counter): `nextgcore_slice_sla_ue_utilization_pct`,
  `nextgcore_slice_sla_pdu_utilization_pct`, `nextgcore_slice_sla_breached`
  (0/1), `nextgcore_slice_sla_breach_transitions_total` — served on
  `/metrics` **only if `metrics_port` opts in** (reusing the generic
  `nextgcore_metrics::nes_energy::serve_metrics` helper; by default **no
  listener is bound**).

Admission behavior is untouched: the observer only reads
`quotas_snapshot()` copies under short locks.

## Config (`nsacf.yaml`, off by default)

```yaml
nsacf:
  sla:
    enabled: true              # default false
    poll_interval_secs: 30
    metrics_port: 9090         # 0/absent = no listener (default)
    slices:
      - sst: 1
        sd: "000001"           # optional, hex like slice_quotas.sd
        max_ue_utilization_pct: 80.0
        max_pdu_utilization_pct: 80.0
```

The `sla` block is captured as a **raw YAML value** in the typed config
(same hardening as pcfd's `intent` block): a malformed block warns and
disables the observer but can never break the `slice_quotas` provisioning
parse — which would otherwise reject every admission. Invalid slice entries
(missing `sst`, bad hex `sd`, no positive threshold) are skipped with a
warning. Slices without a configured SLA are not evaluated (opt-in per
slice); a configured SLA without a provisioned quota is skipped at debug.

## Design choices

- **KPI source: NSACF admission counters.** Per the issue, the first KPI is
  what the NSACF already measures (`ue_utilization`/`pdu_utilization`).
  Slices whose quota is uncapped (`max_ues` absent → `u64::MAX`) evaluate
  to ~0% utilization — a threshold on an uncapped count is meaningless, so
  configure SLAs only for capped slices.
- **Why not `nextgcore_metrics::ai_native::SlaMonitor`:** its `SlaKpi` set
  (latency/loss/throughput/availability…) contains nothing nsacfd can
  measure today; mapping admission utilization onto one of them would
  mislabel the signal. When NWDAF-fed per-slice KPIs exist (NWDAF currently
  serves `NF_LOAD` only), this observer is the adoption point.
- **Observe-only:** breach → signal, nothing else. Automatic remediation
  (EAC activation, quota tuning) is explicitly out of scope here.

## Verification

```sh
cargo build -p nextgcore-nsacfd                           # default unchanged
cargo test  -p nextgcore-nsacfd --features sla-observe    # incl. breach/clear + lenient-config tests
```
