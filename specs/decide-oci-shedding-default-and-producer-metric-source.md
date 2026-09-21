# Decide the consumer OCI shedding default, and where the producer overload metric comes from

**Issue:** nextgcore #273 (a `decision` follow-up to #65 / PR #272)
**Verified against:** nextgcore `main` @ `5941ab0`
**Spec basis:** TS 29.500 §5.2.3.2.9, §6.4.2.2, §6.4.3.1, §6.4.3.2, §6.4.3.4.1–§6.4.3.4.5.2,
§6.4.3.5.1–§6.4.3.5.2; TS 29.510 §5.2.2.3.2 (`NFProfile.load`).
Spec text read at `6g_docs/specs/29500-j70.txt`; every quotation below cites a line there.

## Read this first: the issue's central premise is WRONG, and it changes the answer

#273 asks Q1 partly on the ground that

> `Period-of-Validity` is optional (§6.4.3.3) and an OCI otherwise applies until superseded

It is **not optional**. `29500-j70.txt:2577` reads, verbatim:

> "Period-of-Validity" (Mandatory parameter): Period of validity is a timer that is measured
> in seconds. Once the timer expires, the OCI becomes invalid.

and §6.4.3.4.1 repeats it at `:6723`:

> The OCI shall always include the Overload Timestamp, Overload Reduction Metric, OCI Period
> of Validity and Scope parameters

#272's spec and code both call it optional and cite §6.4.3.3 for that; §6.4.3.3 is
"Frequency of Conveyance" (`:6626`) and says nothing about the parameter's optionality. So the
cite was wrong as well as the claim.

This is load-bearing. The issue's sub-question — "should shedding be ON only when the OCI carries
an explicit `Period-of-Validity`?" — reads like a conservative hedge that sacrifices conformance
for safety. Given the real spec text it is the *opposite*: honouring only a validity-bearing OCI
honours **every conformant producer in full**, and declines only headers that are already
malformed. There is nothing to trade away. That is why it is taken.

## Verified against current main

| claim in the issue | check on `5941ab0` | still true? |
|---|---|---|
| shedding is OFF by default, opt-in via `SbiClient::with_overload_shedding()` | `client.rs:452`, `overload.rs:337` (`new()` → `OverloadControl::default()`, `enabled: false`) | yes — **real**, and inverted by this change |
| recording + reselection ON by default | `client.rs:692-735` `send_with_overload_reaction` | yes |
| 30s ceiling for a validity-less OCI | `overload.rs:269` `DEFAULT_OCI_VALIDITY` | yes |
| `OverloadReporter` wired into the SBI server, emission tested | `server.rs:199` `with_overload_reporter`, stamped at `convert_response_with_identity`; `responses_carry_oci_when_the_nf_reports_overload` | yes |
| **nothing sets a metric**, so the producer half is reachable but not driven | grep `set_reduction_metric` outside `overload.rs` → only that one test | yes — **real**, and closed by this change |
| `Period-of-Validity` is optional (§6.4.3.3) | `:2577` says **Mandatory**; §6.4.3.3 is about conveyance frequency | **NO — void.** See above |
| "the transport cannot honestly judge NF overload" | §6.4.3.1 `:6565`: overload is "e.g. when the internally available resources ... are not sufficient"; "How an NF ... identifies that it is overloaded is implementation specific" | yes — the issue's reasoning is sound and is followed |
| the recorded convention is "ON except where the behaviour drops traffic" | `specs/fix-pcrfd-release-restarted-pcef-gx-sessions.md:84-86` | yes |

### Found while verifying: #272's reaction could never fire against a conformant producer

Not in the issue, and it invalidates the framing of Q1 on its own.

§6.4.3.4.1 makes the **scope mandatory** (`:6723`) and Table 6.4.3.4.5.2-1 (`:6839`) fixes the
permitted values. #272's `effective_oci` acted only on the **unscoped** entry —
`per_target.get("")` — so *every conformant OCI was recorded and then ignored*. Q1 as posed ("should
shedding default ON?") was therefore not yet a live question: flipping the default alone would have
changed nothing on the wire, because no conformant header reached the shedding decision.

Found by writing the producer half first: this tree's own NFs emit `NF-Instance`, the end-to-end
test went green on emission and red on reaction, and the scope filter was why. It is fixed here
because Q1 cannot be answered without it — see "What changed", decision 1b.

## Decision 1 (Q1): shed by default, but only against an OCI that declares its validity

`ShedPolicy::BoundedOnly`, the default, resolved process-wide from
`NEXTGCORE_SBI_OVERLOAD_SHED` and overridable per client.

* An OCI **with** `Period-of-Validity` is shed against, probabilistically on the reduction metric,
  when no alternate producer exists. This is §6.4.3.5.2's "failing the request and treating it as
  if it was rejected by the destination entity" (`:7170`), and §6.4.2.2's `shall abate (by
  divertion or throttling)` (`:6504`). Reselection still outranks it, per §6.4.3.5.1's preference
  for "redirecting some of request messages to an alternative NF if possible" (`:7143`).
* An OCI **without** one is recorded, drives reselection, expires under the 30s ceiling, and
  **never** sheds, at any metric.

### Why the split, and why it costs nothing

The conformance argument is one-sided once the spec text is read: `Period-of-Validity` is
mandatory, so "shed only a bounded OCI" and "shed every conformant OCI" are the same set. The
issue's hedge is free.

The safety argument survives intact. The hazard #272 named is real — a peer sending
`Overload-Reduction-Metric: 100` in error and then going quiet — and it is a hazard *only* for the
validity-less shape, because a declared validity is the producer's own bound on its mistake. #272
bounded that case with a 30s local ceiling, and the ceiling is the reason this is safe but NOT a
reason to shed against it: **the ceiling is this consumer's invention, not the producer's
declaration.** Inventing a number and then dropping traffic on the strength of it is a different act
from honouring a number a producer sent. So the ceiling bounds the record and the reselection; only
a declaration licenses a drop.

Net effect on the recorded house convention ("defaults ON except where the behaviour drops
traffic"): the convention is honoured rather than overridden. The behaviour that drops traffic is
now gated on a **producer's explicit, time-bounded, spec-mandated instruction** — not on a switch
being flipped. There is no input a peer can send that wedges a default consumer off a healthy NF:
a validity-less 100% cannot shed at all, and a bounded one expires when the producer said it would.

### Rejected options for Q1

| option | why not |
|---|---|
| **Leave shedding OFF, document the gap** (#272's answer, and the lazy one) | This is the substance of #65's complaint — §6.4.2.2 says `shall abate`, and a default deployment did not. Worse, it is not even a *stable* position: an operator flipping `with_overload_shedding()` got `ShedPolicy::Always`, i.e. straight to the dangerous unbounded case with no intermediate. Documenting a mandatory behaviour as absent is a conformance claim this tree does not get to make. |
| **Shed against any non-zero metric** (`ShedPolicy::Always`) | Retained as an opt-in, rejected as the default. It is the only posture in which a single malformed header from one peer can stop this consumer talking to a healthy NF for 30s at a time, renewed on every response. The gain over `BoundedOnly` is abatement toward producers that are *already* violating §6.4.3.4.1 — the weakest possible reason to accept that risk. |
| **Shed only when the metric exceeds a floor** (e.g. ≥ 50) | Silently disobeys a conformant instruction. §6.4.3.5.2 (`:7170`) says the recipient "shall reduce the number of request messages by that percentage" — a 20% request answered with 0% reduction is a decision to under-abate, taken here, invisibly, against a producer that stated its need. §6.4.3.4.3 already tells *senders* not to churn on small variations (`:6772`); it does not license receivers to ignore small ones. |
| **Adaptive throttling per Annex A** (`:110799`) | Annex A is explicitly informative and describes a §6.4.2.2 *status-code*-driven algorithm keyed on observed accept/reject ratios — a different, complementary solution to the OCI-header one (§6.4.3.1 `:6556`: "The solution is independent from the Overload Control based on HTTP status codes"). It needs per-producer request/rejection accounting this crate does not keep. Worth doing; not this issue, and not a substitute for honouring an explicit metric. |
| **Make it a cargo feature** | A gated module rots uncompiled, and CI would exercise one state. The tree's recorded preference is a runtime switch; `NEXTGCORE_SBI_OVERLOAD_SHED` is one. |

### Decision 1b: which OCI scopes gate a request (forced by 1, and a defect fix)

An OCI is acted on when its scope covers **every** request this consumer could send to that
target — `NF-Instance` ("All services of the NF instance", Table 6.4.3.4.5.2-1) or `NF-Set` ("All
services of all NF instances of the NF set") — or when it names no scope at all. Among those, the
finest wins, per §6.4.3.4.1 (`:6683`, `:6707`): "should perform overload
control ... considering the OCI received with the finer scope".

Narrower scopes stay recorded but do not gate:

* `S-NSSAI` / `DNN` (§6.4.3.4.5.2.2) describe traffic identified in the request **body**, which
  this layer never sees. Unchanged from #272 decision 3, and its reasoning is still right.
* `NF-Service-Instance` / `NF-Service-Set` name a service instance or set that only NRF discovery
  can map onto the endpoint being dialled.
* A single header carrying `NF-Instance` **and** `DNN` — which §6.4.3.4.5.2.2 NOTE 1 (`:6919`)
  requires of an SMF reporting per-DNN overload — is **not** widened to all traffic merely because
  it also names the instance. Every declared parameter must be whole-target. This is the trap the
  obvious `any()` implementation falls into, and it is pinned.

Scope **values** are not verified: this consumer does not know its producers' NF Instance IDs
without discovery, so a scope is taken as the producer's word about itself — the same trust the
reduction metric already requires.

## Decision 2 (Q2): all three sources, with the NF's own load gauge as the automatic one

The issue says the options are not exclusive. They are wired that way. `OverloadReporter` now has
three inputs and reports `max(operator_floor, nf_metric)`:

1. **Per-NF explicit, from the load gauge each NF already computes** —
   `OverloadReporter::report_load` converts an `NFProfile.load` percentage (TS 29.510 §5.2.2.3.2)
   into a reduction metric: silent below `LOAD_OVERLOAD_THRESHOLD` (80%), then ramping linearly to
   100% at full. Driven from `spawn_heartbeat_worker_with_load`'s tick, which is the one place in
   this tree where **every** registering NF already computes a real capacity percentage — 17 call
   sites, each passing its own definition (AMF: registered UEs vs `max_num_of_ue`; SMF: UEs +
   sessions vs their configured maxima; UPF: PFCP sessions). So this is option 1, not option 2: the
   number is the NF's own, and the shared code only carries it.
2. **NF-set-directly** — `set_reduction_metric`, unchanged from #272, for an NF that knows
   something its load gauge does not (N2 backlog, PFCP queue depth).
3. **Operator-driven** — `set_operator_metric`, a floor for planned drain-down. It raises the
   reported metric and can never lower one the NF's own state justifies, so a drain cannot mask a
   real overload and a real overload cannot cancel a drain.

The emitted OCI is the conformant shape: `Timestamp` (§6.4.3.4.2 — regenerated per emission,
because a cached one makes every response look like the same OCI and §6.4.3.4.2 (`:6748`) says a
receiver "shall discard" an OCI that is not more recent), `Period-of-Validity` defaulting to 30s
(six heartbeat ticks: five may be lost before a peer's enforcement lapses while this NF is still
overloaded), and `NF-Instance` scope taken from the registered instance ID.

**The two halves are held together by a test, not by hope.** A default producer must emit something
a default consumer will act on; `the_emitted_oci_is_shed_eligible_at_a_default_consumer` and
`an_nf_above_its_load_threshold_reports_overload_to_a_default_consumer` assert exactly that, so the
two defaults cannot drift apart while both keep passing their own tests.

### Which NFs drive it

`amfd` and `smfd`, each with one line — `with_self_overload_reporting()` — beside their existing
`SbiServerConfig` setup. They were chosen because their gauges are genuine *capacity* ratios against
configured maxima whose exhaustion is a hard failure (`amf_ue_add` / `smf_ue_add` return `None` at
100%, which a peer cannot anticipate), and because they are the busiest SBI producers in a 5GC
control plane. Every other NF opts in with the same line; the plumbing is already theirs, since
their heartbeat worker publishes the metric whether or not their server emits it.

### Rejected options for Q2

| option | why not |
|---|---|
| **A generic transport signal** (in-flight streams vs `max_concurrent_streams`) — the issue's option 2 | Rejected outright, as the issue argues, and the argument is stronger than "it under-reports". It lies in **both** directions: an AMF with a saturated N2 queue and idle SBI concurrency reports 0, and an AMF merely waiting on a slow UDR reports overload it does not have. §6.4.3.1 (`:6565`) defines overload in terms of the NF's own resources. A wrong number in a mandatory header is worse than no number, because a peer cannot tell it is wrong. |
| **Request latency in the transport** | Same defect, worse: latency is dominated by the *downstream* NFs this producer depends on. Reporting a UDR's slowness as an AMF overload makes consumers abate toward the one NF that was fine. |
| **Operator-only** — the issue's option 3 | Does nothing under unplanned load, which is when §6.4 exists. Kept as source (3) *because* planned drain-down is a real need the automatic source cannot express; rejected as the only source. |
| **A new per-NF overload input defined from scratch** (queue depths, admission-control counters) | More accurate in principle, and rejected as this change's scope. It needs a per-NF decision about inputs and thresholds — 19 of them — and would land the mechanism and 19 judgement calls in one PR. The load gauge is already computed, already spec-anchored (§5.2.2.3.2), and already per-NF. A finer input is a strict refinement later, at `set_reduction_metric`, with no wire change. |
| **Making `with_self_overload_reporting()` implicit** (i.e. `overload_reporter: None` means the process reporter) | Tried, measured, reverted. The reporter is process-global, so one test raising the metric made every other server in the same test binary stamp OCI; two unrelated `server.rs` tests failed in parallel while passing alone. The production analogue is a daemon's in-process server emitting overload because something else in the process simulated load. An explicit line per daemon cannot surprise anything that did not ask. |

## What changed

| area | change |
|---|---|
| `overload.rs` | `ShedPolicy` (`BoundedOnly` default / `Always` / `Never`), `SHED_POLICY_ENV`, `set_shed_policy_override` / `reset_shed_policy_override`; `OverloadControl` carries a policy instead of a bool; `OverloadRegistry::with_policy` / `without_shedding` / `shed_policy` |
| `overload.rs` | `scope_applies_to_whole_target` + `scope_precedence`; `effective_oci` selects the finest whole-target scope instead of only the unscoped entry |
| `overload.rs` | `OverloadReporter` gains `report_load`, `set_operator_metric`, `set_scope`, a conformant `Default` (validity 30s, not 0), and emits `Timestamp` + scope; `DEFAULT_REPORTED_VALIDITY_SECS`, `LOAD_OVERLOAD_THRESHOLD` |
| `overload.rs` | `self_overload_reporter()` process-global + `SELF_REPORTER_TEST_LOCK` / `lock_self_reporter()` declared beside it |
| `heartbeat.rs` | `publish_overload_from_load`; the worker records the OCI scope from the NF instance ID and publishes the gauge on **every** tick, before the NRF-unreachable and NES-paused `continue`s |
| `server.rs` | `SbiServerConfig::with_self_overload_reporting()` |
| `client.rs` | `without_overload_shedding()`, `with_shed_policy()`; `with_overload_shedding()` re-documented as "widen to `Always`", no longer "turn abatement on" |
| `amfd`, `smfd` | one line each: `with_self_overload_reporting()` |

Nothing outside `nextgcore-sbi` names `OverloadControl`, `ShedPolicy`, `Oci` or `Lci` (grep), so the
`OverloadControl::enabled` field removal has no caller outside this crate.

## Guards inverted rather than deleted

| guard | asserted before | asserts now |
|---|---|---|
| `the_default_client_records_oci_but_does_not_shed` | a default client sends into a declared overload | a default client **sheds** a conformant OCI, and still sends against a validity-less one. Kept as one test over two producers: the contrast IS decision 1, and a split pair would let one half be deleted while the other still read as a complete guard |
| `an_oci_without_a_validity_period_expires_under_the_ceiling` | the ceiling bounds a validity-less OCI | same, now under `ShedPolicy::Always` so the ceiling is the only thing that can end the shedding — under the default this OCI never sheds, and the expiry assertion would pass with the ceiling deleted |
| `scoped_oci_is_recorded_but_only_the_unscoped_one_decides` | only a totally unscoped OCI decides | `NF-Instance`/`NF-Set` decide; `DNN`, `NF-Service-Set`, and `NF-Instance`+`DNN` together still do not |
| `test_overload_disabled_never_sheds` | the **default** controller never sheds | an explicitly `disabled()` one never sheds, including against a bounded OCI |
| `responses_carry_oci_when_the_nf_reports_overload` | unchanged — still passes as written | (kept; the explicit-reporter path it covers is untouched) |

## Verification

Every behavioural claim was revert-verified: the change was undone, the **named** test was watched
to fail, then restored.

| revert applied | tests that FAILED |
|---|---|
| `ShedPolicy::BoundedOnly` admits nothing (pre-#273 default) | `the_default_policy_sheds_a_bounded_oci_and_never_an_unbounded_one`, `the_default_registry_sheds_only_against_a_conformant_oci`, `the_emitted_oci_is_shed_eligible_at_a_default_consumer`, `the_default_client_records_oci_but_does_not_shed`, `an_nf_above_its_load_threshold_reports_overload_to_a_default_consumer` ✓ |
| `BoundedOnly` admits an unbounded OCI too | `the_default_policy_sheds_...`, `the_default_registry_sheds_...`, `the_default_client_records_oci_but_does_not_shed` ✓ |
| `report_load` always stores 0 (metric source undriven) | `a_load_gauge_becomes_a_reduction_metric_above_the_threshold`, `the_emitted_oci_is_shed_eligible_...`, `the_operator_floor_raises_but_never_masks_a_real_overload`, `an_nf_above_its_load_threshold_...` ✓ |
| the heartbeat tick no longer calls `publish_overload_from_load` | `an_nf_above_its_load_threshold_reports_overload_to_a_default_consumer` ✓ |
| `with_self_overload_reporting()` is a no-op | `an_nf_above_its_load_threshold_...` ✓ |
| `scope_applies_to_whole_target` returns `false` for any scope (#272's rule) | `scoped_oci_is_recorded_but_only_the_unscoped_one_decides`, `the_emitted_oci_is_shed_eligible_...`, `the_finest_whole_target_scope_decides`, `an_nf_above_its_load_threshold_...` ✓ |
| the operator floor is ignored in `reduction_metric` | `the_operator_floor_raises_but_never_masks_a_real_overload` ✓ |
| the default reporter validity is 0 again (the `AtomicU64::default()` trap) | `a_default_reporter_declares_a_validity_period`, `the_emitted_oci_is_shed_eligible_...`, `an_nf_above_its_load_threshold_...` ✓ |

### One test was rewritten because it proved less than it looked like

`an_nf_above_its_load_threshold_reports_overload_to_a_default_consumer` first called
`publish_overload_from_load` itself. It passed with the heartbeat tick's own call to that function
deleted — i.e. it asserted the *function* worked while leaving the **wiring** unpinned, which is
exactly the reachable-but-undriven defect the test exists to close. Rewritten to move an
`AtomicU8` gauge the worker polls, and to wait on the reporter with `poll_until`; only then did
revert 4 bite. Recovery is asserted the same way — the gauge drops, the tick withdraws the OCI — so
the assertion is a transition and cannot be satisfied by a reporter that never reacted.

### Process-global test state

`self_overload_reporter()` is a `OnceLock<Arc<OverloadReporter>>`. Its lock,
`SELF_REPORTER_TEST_LOCK`, is declared **beside the global in `overload.rs`**, not inside any `mod
tests`, and both holders (`heartbeat`'s new end-to-end test and
`test_registered_nf_instance_id_plumbing`, which now writes the scope via the worker) take that one
lock through `lock_self_reporter()`. A `std::sync::Mutex` held across awaits with
`#[allow(clippy::await_holding_lock)]`, matching `smfd`'s `STORE_LOCK` and for the same stated
reason: a second `tokio` lock over one variable is the split the convention forbids. Distinct
literal NF instance IDs per test, commented, because the scope lives on the one shared reporter.

## Workspace state

`6689 passed / 0 failed` (main @ `5941ab0`: `6679`), `cargo clippy --workspace --all-targets`
0 errors, `cargo fmt --all --check` clean, `cargo test -p nextgcore-easdfd --features dns-udp`
51 passed and its clippy 0 errors. Load average 11.4 during the full run.

## Ceilings

* **No wire interop.** Verified against this tree's own client and server. "Conformant" means
  "matches the TS 29.500 prose quoted above", not "was accepted by another vendor's NF".
* **The OLC-H feature is not advertised to the NRF.** §6.4.3.6.1 (`:7186`) says an NF supporting
  OLC-H "shall indicate the feature support" at `NFRegister`/`NFUpdate` (TS 29.510 §6.1.6.2.2), and
  the NRF "shall indicate" it to discovering consumers. Neither is done: the registration path
  builds its `NFProfile` per daemon, and nrfd would have to carry the flag through discovery. §6.4.3.2
  (`:6622`) makes this benign on the wire — the OCI is sent "regardless of whether the peer supports
  the feature" (`:6622`), and an unsupporting receiver ignores it — but a consumer cannot yet *learn* that a
  discovered producer honours OCI. Named, not fixed.
* **17 NFs publish a metric; 2 emit it.** Every registering NF's heartbeat worker now drives the
  process reporter, but only `amfd` and `smfd` call `with_self_overload_reporting()`. The other 15
  compute the number and do not put it on their responses. One line each, deliberately not applied
  blind: an NF whose gauge is not a capacity ratio would emit overload it does not have. `nwdafd`'s
  gauge, for instance, is `subscription_count()` capped at 100 — a count, not a percentage, so 100
  subscriptions would read as 100% load and ask peers for a 100% reduction. It must not opt in
  until its gauge is fixed.
* **Thresholds are not configurable.** `LOAD_OVERLOAD_THRESHOLD` (80%) and
  `DEFAULT_REPORTED_VALIDITY_SECS` (30s) are constants. §6.4.3.4.3 makes the metric's computation
  "implementation specific", so these are legitimate choices, but an operator cannot retune them
  without a rebuild. The operator floor (`set_operator_metric`) is the runtime lever that exists.
* **Reduction is per-target, not rate-proportional.** §6.4.2.2 (`:6502`) also asks a consumer to
  "monitor the amount of rejected and timed-out traffic, in comparison to the accepted traffic" and
  to improve the ratio over time. This change performs the §6.4.3.5.2 Loss algorithm on the stated
  metric, which §6.4.3.5.1 (`:7159`) mandates ("shall support and use the 'Loss' algorithm"), but
  keeps no accept/reject accounting, so the adaptive half of §6.4.2.2 and Annex A remain undone.
* **Consumer-emitted OCI is not implemented.** §6.4.3.4.1 (`:6715`) lets a *consumer* report its own
  overload to a producer in a service request, so a producer throttles its notifications. This change
  is producer-emits / consumer-reacts only. The `OverloadReporter` would serve unchanged; the missing
  piece is stamping it on outbound requests and reacting to it in notification senders.
* **Alternate targets are still empty by default**, so reselection stays live-but-inert until an NF
  passes the producers it discovered (#272's ceiling, unchanged). This matters more now: with no
  alternates, a conformant OCI goes straight to shedding rather than rerouting, which is the
  §6.4.3.5.1-preferred outcome. Per-daemon NRF-discovery plumbing, not in this change.
* **Scope values are unverified** (see decision 1b). A producer could scope an OCI to another NF's
  instance ID and this consumer would apply it to itself. Verifying needs discovery.
* GitNexus impact analysis unrunnable (no MCP server connected). `nextgcore/CLAUDE.md`'s mandate to
  run `gitnexus_impact` before editing stays unsatisfiable. Blast radius by grep:
  `OverloadControl::enabled` field readers (1, a test in this crate); `with_overload_shedding`
  callers (1 test); `effective_oci` callers (5, all in this crate); `overload_reporter` construction
  sites (3 production + 4 test); `spawn_heartbeat_worker_with_load` callers (17 daemons, all
  unchanged and all now publishing); no crate outside `nextgcore-sbi` names any overload type.
