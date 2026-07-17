# Network Energy Saving (NES) — issue #22

**Status: non-normative research prototype, off by default.** 3GPP defines
the NF-profile `nfStatus` values used here (`REGISTERED`/`SUSPENDED`,
TS 23.501/TS 29.510) and the energy-efficiency KPI families (TS 28.310),
but there is **no frozen Rel-20 Stage-3 "6G NES" feature** — the sleep
policy and the power numbers below are prototypes for research/education.

## What it does

With the `nes` cargo feature enabled on the reference NF (**udmd**) *and*
an `nes.enabled: true` config block, the NF runs an idle/sleep loop built
from three reusable pieces:

- `nextgcore_sbi::nes::NesMachine` — a pure state machine:
  `Active → (idle > threshold) → Draining → (in-flight settled) →
  Suspended`, and `Suspended → (inbound activity) → Active`.
  **Graceful drain:** the suspend transition never fires while requests are
  in flight; if the drain window expires with work pending, the sleep
  attempt aborts back to `Active` — no request is ever dropped.
- `nextgcore_sbi::heartbeat` NES plumbing — the heartbeat worker now emits
  the NF's *live* status (`build_status_patch`; default `REGISTERED` is
  byte-identical to the historical patch), can be paused
  (`set_heartbeat_paused`, for the deregister action), and
  `patch_nf_status` issues the one-off transition PATCH.
- `nextgcore_metrics::nes_energy` — live energy gauges + a minimal real
  HTTP/1.1 `/metrics` listener (the legacy `MetricsServer` is a
  non-binding stub).

Sleep is reflected to the NRF by one of two config-selectable actions:

| `action` | on suspend | on resume |
|---|---|---|
| `suspend` (default) | PATCH `nfStatus=SUSPENDED`; heartbeats continue, advertising `SUSPENDED` | PATCH `nfStatus=REGISTERED` |
| `deregister` | pause heartbeats + `DELETE /nnrf-nfm/v1/nf-instances/{id}` | re-register under the same NF instance ID + unpause heartbeats |

**nrfd change:** the NRF previously treated *any* heartbeat PATCH as a
liveness signal and flipped a `SUSPENDED` profile back to `REGISTERED` —
which would instantly undo a self-suspension. `handle_nf_update` now honors
a PATCH whose body itself sets `nfStatus=SUSPENDED` (self-suspension) and
skips the reactivation; the liveness timer still re-arms, so a
sleeping-but-heartbeating NF is not auto-deregistered.

## Config (`udm.yaml`, off by default)

```yaml
udm:
  nes:
    enabled: true            # default false — absent block = complete no-op
    idle_threshold_secs: 300 # no inbound SBI activity before draining
    drain_timeout_secs: 10   # max wait for in-flight work; expiry aborts
    poll_interval_secs: 5
    action: suspend          # suspend | deregister
    metrics_port: 9090       # /metrics listener
    # synthetic power model knobs:
    capacity_rps: 100.0
    idle_power_w: 5.0
    max_power_w: 25.0
```

Build: `cargo build -p nextgcore-udmd --features nes`. With the feature
off (the default build) behavior is byte-for-byte unchanged: no new
metrics listener, no NRF status changes, the heartbeat JSON is identical.

## Metrics (`curl http://<nf>:9090/metrics`)

TS 28.310-aligned family (labels `nf_type`, `nf_id`):
`energy_consumption_watts`, `energy_consumed_joules_total`,
`energy_data_volume_bits_total`, `energy_efficiency_bits_per_joule`,
`energy_sleep_ratio`, plus the new `nf_utilization_ratio` (0.0–1.0).

## Synthetic power model (caveat)

There are **no hardware energy counters** in this core; the numbers are a
documented synthetic model computed each poll tick:

```
utilization = min(1.0, requests_this_tick / (capacity_rps * dt))
power_w     = suspended ? 0.1 * idle_power_w
                        : idle_power_w + (max_power_w - idle_power_w) * utilization
joules     += power_w * dt
data_bits  += requests_this_tick * 8192   # 1 request ≈ 8 kbit proxy
sleep_ratio = time_suspended / observed_time
```

Treat every derived KPI (bits/J in particular) as illustrative only.
