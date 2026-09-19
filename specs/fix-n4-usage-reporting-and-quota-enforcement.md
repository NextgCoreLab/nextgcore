# nextgcore #80 (smfd + upfd): N4 usage reporting and Volume/Time Quota enforcement

Verified against `main` @ `ca17e80`.

#80 spans the SMF (provisioning) and the UPF (parsing, enforcement, reporting). Its cites were
verified at `76ea248` and **have drifted substantially** — two of its seven criteria are already met,
because #306 landed the Measurement Period half in the interim. TS 29.244 §5.2.2, §5.2.2.2.2,
§7.5.2.4, §8.2.13, §8.2.14, §8.2.17, §8.2.19, §8.2.40, §8.2.41.

## Verified against current main

| claim in the issue | site on `ca17e80` | still true? |
|---|---|---|
| `pfcp_session_establish` emits no Create URR and no `urr_id` on the PDRs | `smfd/src/main.rs:1819` (was `:1136`); builds NodeID + F-SEID + DNN + S-NSSAI + QER(s) + PDR/FAR ×2 + BII, **no `CREATE_URR`**; `ul_pdr`/`dl_pdr` leave `urr_ids` at its `Default` empty vec | **yes** |
| `create_urrs` is populated only in tests | `smfd/src/n4_build.rs:1110` declares it; only writer is `:2542`, a test | **yes** |
| `build_create_urr` is unreachable on the live path | `n4_build.rs:1558`; reached from `build_session_establishment_request_full` (`:1200`) and the modification builder (`:1303`), neither of which the live establish path uses | **yes** |
| `UrrParams` carries no quota fields | **NO** — `n4_build.rs:1546` already has `volume_quota`, `time_quota` and `quota_validity_time`, and `build_create_urr` already emits all three (`:1577`, `:1587`, `:1595`) | **already met on the builder side** |
| upfd `parse_create_urr` never parses Volume Quota (IE 73) / Time Quota (IE 74) | `upfd/src/n4_build.rs:1641`; parses URR_ID, MEASUREMENT_METHOD, REPORTING_TRIGGERS, VOLUME_THRESHOLD, TIME_THRESHOLD, MEASUREMENT_PERIOD — **no VOLUME_QUOTA, no TIME_QUOTA**. The constants exist unused at `:137`/`:138` | **yes** |
| the Measurement Period IE (64) is never parsed | **NO — void.** `upfd/n4_build.rs:1713` parses it; #306 added it | **VOID (already met)** |
| `trigger_periodic` is decoded then dropped; `measurement_period_secs` is always `None` | **NO — void.** `ParsedCreateUrr.measurement_period_secs` (`:1740`) is propagated into `DataPlaneUrr` at both construction sites (`upfd/main.rs:907` establish, `:1034` create-URR) via `set_reporting`, and read by the periodic harvest at `data_plane.rs:2954` | **VOID (already met)** |
| `ParsedCreateUrr` / `DataPlaneUrr` carry no quota fields | `upfd/n4_build.rs:1729` and `data_plane.rs:1145` — measurement period YES, quota NO | **partly: quota still missing** |
| `record()` only sets `threshold_exceeded` | `data_plane.rs:1270`; no quota concept at all | **yes** |
| `record_urrs`' return value is discarded at both forwarding sites | `data_plane.rs:1827` returns `bool`; discarded at `:2374` (UL) and `:2592` (DL) | **yes** (cites moved from `:2235`/`:2447`) |
| upfd's PFCP transport is real, so criterion 5 has a working transport (issue comment) | `pfcp_path.rs` binds a real `UdpSocket`; `send_urr_report` (`:2260`) builds a real Session Report Request and is driven by a live task (`upfd/main.rs:426`) | **yes — the comment is correct** |

| `UrrParams` can express a Measurement Period | **NO** — it had no such field and `build_create_urr` emitted no IE 64. See finding 3 | **the SMF could not send a cadence at all** |

### Findings the issue does not state

**1. The report path exists and works; only its trigger is a lie.** `send_urr_report`
(`pfcp_path.rs:2260`) already builds a conformant Session Report Request with a `UsageReport` carrying
`VolumeMeasurement`, and a live 10-second task drives it (`upfd/main.rs:419-455`). But it hardcodes
`trigger.volume_threshold = true` for **every** report (`pfcp_path.rs:2286`) — so a periodic report
(which #306 made reachable) is already being mislabelled on the wire as a threshold report today. The
`UsageReportTrigger` type has `periodic_reporting`, `volume_quota` and `time_quota` members
(`upfd/n4_build.rs:244`, `:252`, `:253`) and `add_usage_report_trigger` encodes all of them correctly
(`:602`, `:626`, `:629`). Only the caller never sets them. This is a **pre-existing wire defect** that
criterion 5 cannot be satisfied without fixing, so it is fixed here.

**2. `UrrParams` already has the quota fields, so criterion 1's builder half is a wiring job.** The
issue reads as though the SMF builder needs quota support. It has it. What is missing is a live caller.

**3. The SMF could not send a Measurement Period at all.** `UrrParams` had no field for it and
`build_create_urr` never emitted IE 64. So the SMF could set the `PERIO` trigger and had no way to say
*how often* — and the UPF, which has parsed the IE since #306, would have found none and left
`measurement_period_secs` at `None`. #80 records the receiving half of this ("the Measurement Period IE
is itself never parsed", now void) and misses the sending half, which was still open. Criterion 6 is
unsatisfiable without it: a periodic report cannot fire from a cadence that was never provisioned.
Found by the compiler — the first draft read `SMF_URR_MEASUREMENT_PERIOD` into a variable with nowhere
to put it, and the `unused_variables` warning was the tell.

**4. The quota-exhaustion report must not wait for the 10-second tick.** The existing harvest is
polled. A quota that stops forwarding at T and reports at T+10s leaves the CP function unaware for ten
seconds that a subscriber was cut off — and TS 29.244 §5.2.2.2.2 has the UP function report *when* the
quota is exhausted. So exhaustion raises an immediate event through the existing
`UpfReportEvent` channel (`data_plane.rs:1895`), which is the mechanism Downlink Data Reports and
Error Indication Reports already use. A new `UsageReport` variant rather than a second channel.

## Decision 1: the enforcement lands ON, with no cargo feature

#80's "feature-gate advice" asks for an off-by-default `usage-quota` cargo feature. **Rejected**, and
the issue's own comment argues against it: a cargo-feature-gated path falls outside
`cargo test --workspace`, which is the CI gate, so the on-path would ship unexercised. This project has
a recorded decision against exactly that (`smfd/udm.rs:35-41`, and the CI job comment at
`.github/workflows/ci.yml:67-73`).

Nor is a runtime switch needed to protect the E2E, because **enforcement is unreachable unless a quota
is provisioned**. The SMF provisions a URR with measurement and thresholds but **no quota** by
default: `volume_quota` and `time_quota` stay `None` unless a quota is configured
(`SMF_URR_VOLUME_QUOTA` / `SMF_URR_TIME_QUOTA`). With no quota, `record` cannot report exhaustion and
the forwarding sites behave exactly as they do today. So the default deployment gets *measurement and
reporting* — the capability that was entirely absent — and *enforcement* only where an operator asked
for a quota by setting one. That is the production-grade shape: the gate is the provisioned value,
which is what TS 29.244 makes the gate, not a build flag.

One consequence stated rather than left implicit: the matched-sim E2E now sees a Create URR it did not
see before. That is the point of criterion 1, and a UPF that ignores an IE it understands is required
to accept it (§7.5.2.4 makes Create URR a normal grouped IE, not a feature-gated one).

## Decision 2: URR provisioning is unconditional; the quota is configured

The SMF installs **one URR per session** (URR ID 1), volume + duration measurement method, with
`VOLTH | TIMTH | PERIO` triggers always, plus `VOLQU` / `TIMQU` only when a quota is configured. Bound
to **both** the UL and DL PDRs, so `record_urrs` sees traffic in both directions against one
accumulator — which is what a session-level volume allowance means.

One URR rather than one per direction: TS 29.244's Volume Threshold and Volume Quota IEs each carry
total/uplink/downlink fields (§8.2.13, §8.2.40), so a single rule already expresses per-direction
limits. Two rules would double the reports and make "total" ambiguous.

Reporting triggers and thresholds come from config with documented defaults rather than from the PCF's
`chgDecs`: the PCF's charging decision today carries `ratingGroup` / `meteringMethod` and **no
volume**, so deriving a quota from it would invent one. Sourcing a quota from the CHF is what #80's own
References defer as a follow-up.

## Decision 3: exhaustion drops the packet and is reported once, not per packet

When `record` finds a quota exhausted it returns `Exhausted` and **latches** the state
(`quota_exhausted: AtomicBool`). The forwarding sites then drop the packet — counted in
`stats.dropped_packets`, the same counter a no-PDR-match drop uses, so an operator's existing counter
tells the truth. The report is raised **once**, on the transition into exhaustion, because a
quota-exhausted session under load would otherwise raise one Session Report Request per packet and
DoS the SMF with the news that it is out of quota.

**The latch is cleared by `set_quotas` and deliberately NOT by `reset_counters`.** That distinction
matters more than it looks: `reset_counters` runs every time a usage report is harvested, *including
the report that announces the exhaustion*. Clearing the latch there — which the first draft did — would
have the 10-second harvest silently un-gate every exhausted session as a side-effect of reporting it, so
a subscriber would be cut off for at most one harvest interval and then resume, forever. That is not a
quota. A consumed allowance stays consumed until the CP function grants more through an Update URR,
which is TS 29.244 §5.2.2.2.2's own model: the UP function stops and reports, the CP function decides.
Guarded by `only_a_re_provisioned_quota_resumes_forwarding_not_a_report`, which asserts both halves.

`record`'s return type changes from `bool` to a three-state enum (`UrrOutcome::{Continue,
ThresholdExceeded, QuotaExhausted}`). A second `bool` would have the two call sites decide which
boolean means "drop", and they got that wrong once already by discarding the one that existed.

## Decision 4: the DL site is asserted separately from the UL site

The issue's comment asks for this explicitly and it is right: they are different call sites
(`data_plane.rs:2374` and `:2592`) reached by different code, and one fix reads as both. So there are
two enforcement tests, not one parameterised over a direction.

## Acceptance criteria

- [x] **real** — `pfcp_session_establish` emits a Create URR (volume+duration measurement,
      `VOLTH|TIMTH|PERIO` triggers, `+VOLQU|TIMQU` when a quota is configured) and both PDRs carry the
      URR ID. Guarded by `the_establishment_request_provisions_a_urr_bound_to_both_pdrs`, which decodes
      the **real wire payload** the live path builds.
- [x] **real** — `parse_create_urr` decodes Volume Quota (IE 73) and Time Quota (IE 74). Guarded by
      `volume_and_time_quota_round_trip_through_the_wire`, which encodes with the SMF's own
      `build_create_urr` and parses with the UPF's `parse_create_urr` — a round trip across the two
      daemons' codecs rather than against a hand-built buffer, so an encoder/decoder disagreement
      cannot hide.
      **Measurement Period (IE 64) is VOID**: #306 already parses it (`n4_build.rs:1713`). The test
      asserts it anyway, as a regression guard for a value this change now depends on.
- [~] **partly void** — `ParsedCreateUrr` and `DataPlaneUrr` gain quota fields (**real**);
      `DataPlaneUrr.measurement_period_secs` is populated when PERIO is set (**VOID** — already done at
      `upfd/main.rs:907` and `:1034` via `set_reporting`, added by #306). The measurement-period half is
      closed by explanation plus a regression assertion, not by new work.
- [x] **real** — an exhausted volume quota stops forwarding UL **and** DL traffic. Two tests, one per
      direction, driving real packets through the real forwarding functions and asserting the
      **dropped-packet counter moved and the peer received nothing**.
- [x] **real** — the UPF emits a usage report carrying VOLQU (or TIMQU) on exhaustion. Guarded by
      asserting the `UpfReportEvent::UsageReport` raised on the transition, and by a codec test that the
      VOLQU bit reaches octet 2 bit 1 of the Usage Report Trigger IE. This also fixes the pre-existing
      defect that every report claimed `volume_threshold`.
- [x] **real** — with PERIO and a Measurement Period set, a periodic report fires. The harvest existed
      (#306); what did not exist is the report being **labelled** periodic on the wire. Guarded by
      `a_periodic_report_is_labelled_perio_not_volth`.
- [x] **real, reinterpreted** — "clippy and tests green with the feature both off and on". There is no
      feature (Decision 1), so this becomes: green with a quota provisioned and without one. Both
      states are inside `cargo test --workspace`, which is what the issue's comment asks for.

Two criteria were **void** (Measurement Period parsing, and the PERIO/period propagation), both closed
by #306 in the interim. One (criterion 1's builder half) was **already met** — `UrrParams` had the
quota fields all along.

## Verification

`cargo test --workspace`: **6654 passed / 0 failed** (baseline 6639 on `ca17e80`; upfd 291 → 307,
smfd 504 → 509). `cargo clippy --workspace` introduces **no new warning in either crate** — upfd is at
zero and smfd's one (`await_holding_lock` at `main.rs:556`) is pre-existing startup code this change
does not touch. `cargo clippy -p nextgcore-easdfd --features dns-udp --all-targets` clean;
`cargo fmt --all -- --check` clean; `cargo test -p nextgcore-easdfd --features dns-udp` green
(51 passed).

| revert | expected to break | result |
|---|---|---|
| the establish path stops adding the Create URR | `the_establishment_request_provisions_a_urr_bound_to_both_pdrs` | **1 failed** |
| the **UL** PDR stops carrying the URR ID | same (fails on "PDR #0") | **1 failed** |
| the **DL** PDR stops carrying the URR ID | same (fails on "PDR #1") | **1 failed** |
| `build_create_urr` stops emitting the Measurement Period | `a_create_urr_carries_quotas_thresholds_and_the_measurement_period` | **1 failed** |
| `parse_create_urr` stops parsing Volume Quota | `volume_and_time_quota_round_trip_through_the_wire` | **1 failed** |
| the **UL** forwarding site discards `record_urrs`' verdict again | `an_exhausted_volume_quota_stops_forwarding_uplink_traffic` | **1 failed** |
| the **DL** forwarding site discards it | `an_exhausted_volume_quota_stops_forwarding_downlink_traffic` | **1 failed** |
| `reset_counters` clears the exhaustion latch again | `only_a_re_provisioned_quota_resumes_forwarding_not_a_report` | **1 failed** |
| the report trigger goes back to hardcoded `volume_threshold` | `a_periodic_report_is_labelled_perio_not_volth` | **1 failed** |
| the event-driven quota report resets the counters | `the_event_driven_quota_report_carries_volqu_and_does_not_reset_counters` | **1 failed** |

Ten reverts, ten bites — but only after **one of them caught a test of mine that did not guard what it
claimed**, which is worth recording in full because it is the general trap rather than a local slip.

### The uplink enforcement test passed with uplink enforcement disabled

`an_exhausted_volume_quota_stops_forwarding_uplink_traffic`, as first written, passed `tun_fd = -1`
(copying its sibling tests) and asserted `dropped_packets == 1` and `ul_packets == 0`. Under the
sabotage that ignores the uplink verdict — i.e. **the exact pre-#80 bug the test exists to catch** —
it still passed.

The mechanism: with the gate bypassed the packet reaches the TUN write, `libc::write(-1, …)` fails
with `EBADF`, and `handle_uplink_packet`'s failure branch increments `dropped_packets` and skips
`ul_packets`. Both assertions were therefore satisfied by the *write failing* rather than by the
*gate firing*. `dropped_packets` in this harness conflates "policy refused the packet" with "the fake
fd could not be written to", and `ul_packets == 0` is a negative that the error path satisfies too.

Two changes make it bite: a real writable fd (`/dev/null`), so a forwarded packet takes the success
branch and is countable; and a **control packet** through that same fd on a quota-free session first,
asserting `ul_packets == 1`. Only once a forward is demonstrably observable does `ul_packets` still
being 1 afterwards mean the quota stopped the next one. The sabotage now fails with
`left: 2, right: 1` — a direct observation of the packet being forwarded.

The DL test did not have the problem, because it binds a real gNB socket and so already had a
positive signal. `an_exceeded_threshold_reports_but_keeps_forwarding` hit the same `tun_fd = -1` trap
from the other direction and failed honestly on first run; it is fixed the same way.

## Ceilings

- **The quota comes from config, not from the CHF or the PCF.** `Nchf_ConvergedCharging` quota
  management is #80's own declared follow-up. Until then a quota is an operator-set per-deployment
  value, not a per-subscriber balance.
- **No Quota Holding Time, no Quota Validity Time enforcement.** `UrrParams` carries
  `quota_validity_time` and the builder emits it, but the UPF neither parses nor enforces it. Named
  rather than half-built: it needs its own timer semantics (§8.2.113).
- **Enforcement is per-session, not per-flow.** One URR bound to both PDRs means the allowance is the
  session's. A per-PCC-rule quota needs one URR per rule and a PCF that asks for one.
- **The drop is a drop, not a redirect.** TS 29.244 §8.2.26 also allows a FAR to redirect exhausted
  traffic to a top-up portal. That is a FAR change driven by the CP function, not something the UP
  function may decide alone.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only, so every assertion is in-process against
  the real codecs and the real forwarding functions.
