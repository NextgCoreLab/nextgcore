# nextgcore #215 (sgwud): URR measurement and Usage Reporting

Verified against `main` @ `506fae5` (after #205, #242, #95, #204). Every cite in the issue still
holds.

## Verified against current main

| claim in the issue | check on `506fae5` | still true? |
|---|---|---|
| `SessionEstablishmentRequest` has no URR field | `sxa_handler.rs:40-56` — `create_pdrs`/`create_fars`/`create_qers`/`create_bar` only | yes |
| `SessionModificationRequest` likewise | `sxa_handler.rs:207-236` | yes |
| the only URR presence is `PfcpSess.urr_ids`, populated **only in a unit test** | `context.rs:103`; `grep -rn 'urr_ids' bins/nextgcore-sgwud/` found one test writer | yes |
| `apply_far` counts no bytes or packets | `gtp_path.rs:657` | yes |
| the USAR bit is exercised only in a unit test | `sxa_build.rs` `report_type()` bit 2, no data-path setter | yes |
| mirror available: upfd's `DataPlaneUrr` | `bins/nextgcore-upfd/src/data_plane.rs:1123` | yes |

## Read this first: the reports are built and go nowhere

**`pfcp_path::send_pfcp_request` is a logging placeholder.** It formats one debug line and returns,
with a comment describing what a real implementation would do (`pfcp_path.rs:297`). Every Session
Report Request the SGW-U produces — Downlink Data Report, Error Indication Report, and now Usage
Report — is built correctly and then dropped on the floor. That is issue **#217** ("sgwud: no PFCP
transport at all"), already filed.

So what lands here is the measurement, the trigger evaluation, and the IE encoding, all
in-process-verifiable; what does **not** land is a Usage Report reaching an SGW-C. Stating it up front
rather than letting the PR read as end-to-end usage reporting: this is the same shape as #210, where a
correct fix was a wire no-op, and the lesson from that session was to lead with it.

The measurement itself is not a no-op — an operator inspecting the SGW-U's logs sees the counts and
the triggers — but SGW-CDR volume (TS 32.251) still has no input until #217.

## What was added

| area | change |
|---|---|
| `context.rs` | `SgwuUrr` (provisioning + counters + UR-SEQN), `Volume`, `UsageReportTrigger`, `measurement_method` / `reporting_trigger` flag modules, `now_unix_secs`; `SgwuPdr.urr_ids`; a `urr_list` store with `urr_install` / `urr_find` / `urr_find_for_sess` / `urr_remove` / `urr_drain_for_sess` / `urr_record` / `urr_take_report`; `sess_register_urr` / `sess_unregister_urr`; URR cleanup in `sess_remove` |
| `sxa_handler.rs` | `CreateUrrRequest`, `UpdateUrrRequest`; `create_urrs` on establishment, `create_urrs` / `update_urrs` / `remove_urrs` on modification; `CreatePdrRequest.urr_ids`; `process_create_urr` / `process_update_urr` / `process_remove_urr`; `take_usage_report`, `usage_report_from`, `take_final_usage_reports` |
| `gtp_path.rs` | `measure_and_report`, called on the two paths where a packet is **handled** |
| `sxa_build.rs` | `UsageReport`; `UserPlaneReport.usage_reports` + `with_usage_reports`; `build_usage_report_ie` (IE 79 / 80), `usage_report_trigger_octets`, `volume_measurement_octets`, `push_ie` / `push_u32_ie`; `build_session_deletion_response` now takes the final reports |
| `pfcp_path.rs` | `send_session_deletion_response` drains the final reports before the response is built |

## Decision 1: counters live in the store, not on the rule

`SgwuPdr` and `SgwuQer` are `Clone` and `pdr_find` / `qer_find` hand out **copies**, so a counter on a
returned rule is a counter nobody reads. Mutation therefore goes through `SgwuContext::urr_record`,
which holds the store's write lock — the same shape `mbr_allows` already uses for the QER token bucket.

`urr_take_report` allocates the UR-SEQN **and** resets the period in one locked operation, rather than
a read-then-reset pair: two packets crossing the threshold concurrently would otherwise both build a
report from the same counters and double-count the volume.

## Decision 2: QER-dropped traffic is NOT counted — the call the issue asks for

The issue says: *"Decide deliberately whether a packet dropped by a closed gate or an exceeded MBR is
counted — TS 29.244 measures what the UP function handles, and counting dropped traffic as volume would
over-bill."*

**Not counted.** `apply_far` measures *after* the QER decision, on the two paths that return
`Forwarded` or `Buffered`. Also not counted: a FAR whose Apply Action is DROP, and a forwarding attempt
that fails (`forward_gpdu` errors — nothing reached the peer).

The reasoning, stated because the asymmetry is the point: §5.2.2.1 has the UP function measure "the
network resources usage", and a packet it discarded consumed none of the resource being billed.
Over-billing a subscriber for traffic the network refused to carry is the worse of the two errors;
under-counting a dropped packet costs the operator nothing it was entitled to.

**Buffered traffic IS counted, once, at buffering time.** A buffered packet has been accepted and will
be delivered when the buffer flushes, so it is handled; counting it again on flush would double-bill,
which is why the flush path does not measure.

## Decision 3: a threshold is only reportable when its trigger bit is set

`SgwuUrr::reportable` checks Volume Threshold, Volume Quota, Time Threshold and Measurement Period
**only** when the corresponding Reporting Triggers bit is set. TS 29.244 §8.2.41 makes that IE the CP
function's *request*, so treating a provisioned threshold as reportable without its trigger bit would
report where the CP asked for silence.

Volume Quota is treated as reportable in the same way a threshold is, and is **not** enforced by
dropping: TS 29.244 makes enforcement a FAR/QER matter, and having a URR silently start discarding
traffic would be a forwarding change the CP function never asked this rule for.

## Decision 4: re-provisioning keeps the measurement, and keeps the UR-SEQN

`urr_install` carries over the counters, the packet timestamps, the period start and the next UR-SEQN
when the id is already present. A Create URR for an existing id, or an Update URR, must not zero the
volume measured so far — that would lose billable traffic on every reprovisioning, in a way a charging
function cannot detect. The UR-SEQN is carried for a different reason: a sequence number that restarts
is one the CP function cannot use to order or de-duplicate reports.

An Update URR for an **unknown** id is `RULE_CREATION_MODIFICATION_FAILURE`, matching how Update
PDR/FAR/QER already answer; creating it here would install a URR whose unspecified members the SGW-C
never provisioned.

## Decision 5: URR operations are ordered around the PDR operations

Create/Update URR run **before** Create PDR, and Remove URR **after** the PDR operations. TS 29.244
§7.5.2 does not fix IE order within a message, so a single-message provisioning where the SGW-C put
Create PDR first would otherwise install a PDR naming a URR that does not exist yet.

## Decision 6: an idle URR still reports at deletion

`take_final_usage_reports` renders every URR the session held, including ones that measured nothing. A
zero report and no report are different statements to a charging function, and only the first says
"this rule was installed and saw no traffic". They are drained **at the point the deletion response is
built** (`send_session_deletion_response`), because `sess_remove` discards URRs and collecting
afterwards would always report nothing.

## Acceptance criteria

- [x] Create/Update/Remove URR parsed in `SessionEstablishmentRequest` and `SessionModificationRequest`
      and stored in a URR type/store; `PfcpSess.urr_ids` populated **in production** —
      `create_urr_installs_the_rule_and_populates_sess_urr_ids`,
      `update_urr_keeps_the_measurement_and_remove_urr_takes_it_out`.
      *Note on "parsed":* sgwud has **no byte-level PFCP parser** — there is no PFCP transport at all
      (#217), and the request structs are populated by callers. "Parsed" therefore means the IEs are
      modelled on the request types and processed into the store, which is the whole of what exists to
      extend.
- [x] `apply_far` counts bytes and packets against installed URRs —
      `forwarded_traffic_crosses_a_volume_threshold_and_reports_with_advancing_ur_seqn`.
- [x] Usage Report IEs emitted in Session Report Requests (USAR set **from the data path**) and in the
      Session Deletion Response, with a monotonic UR-SEQN —
      `session_report_request_carries_a_usage_report_ie` (IE 80 + the USAR report-type bit),
      `session_deletion_response_carries_final_usage_reports` (IE **79**, and asserts IE 80 is
      *absent*), and `UserPlaneReport::with_usage_reports` sets the bit alongside the reports so the two
      cannot drift.
- [x] A test drives traffic past a configured volume threshold and asserts a Usage Report with the
      expected counts and an advancing UR-SEQN — the first test above: 100+100 stays silent, the third
      packet reports **300** bytes (the whole period, not the last packet) at UR-SEQN 0, counters reset,
      the next crossing reports UR-SEQN 1.
- [x] A test pins whether QER-dropped traffic is counted, matching the documented decision —
      `traffic_dropped_by_a_closed_qer_gate_or_a_drop_far_is_not_counted`, which also shows the **same
      packet with enforcement off IS counted**, so the zero is the gate's doing rather than a broken
      measurement path.
- [x] Workspace lint and test suites pass.

## Verification

Workspace **5995 passed / 0 failed / 6 ignored** (baseline `5982` on `506fae5`; +13 tests, sgwud 98 →
111). `cargo clippy -p nextgcore-sgwud --all-targets` clean (zero warnings), `cargo clippy --workspace`
0 errors, `cargo fmt --all -- --check` clean.

Eight reverts:

| revert | expected to break | result |
|---|---|---|
| `measure_and_report` returns early, so nothing is counted | both data-path tests | **2 failed** |
| measure **before** the QER decision, i.e. count dropped traffic | `traffic_dropped_by_a_closed_qer_gate_or_a_drop_far_is_not_counted` | **1 failed** (`must NOT be billed`) |
| `urr_take_report` does not advance the UR-SEQN | `forwarded_traffic_...advancing_ur_seqn` | **1 failed** |
| `urr_install` drops the carry-over, zeroing on re-provision | `re_creating_an_existing_urr_keeps_the_measurement` | **1 failed** — *see below* |
| the deletion response emits no Usage Report IEs | 2 `sxa_build` tests | **2 failed** |
| the VOLTH trigger encodes into the TIMTH bit | `every_usage_report_trigger_has_its_own_bit`, `session_report_request_carries_a_usage_report_ie` | **2 failed** |
| `process_create_urr` stops calling `sess_register_urr` | `create_urr_installs_the_rule_and_populates_sess_urr_ids` | **1 failed** (`not only by a test`) |
| `reportable()` ignores the trigger bits | `a_threshold_without_its_trigger_bit_does_not_report` | **1 failed** |

**The fourth revert found a hole in my own coverage.** Removing `urr_install`'s carry-over broke **no
test**: the Update-URR test I had written passes either way, because `process_update_urr` reads the
existing URR through `urr_find` first, so the counters survive without the store's help. The carry-over
actually guards a **re-Create** — a Create URR for an id already installed, which starts from a fresh
request and has nothing to read. Fixed by adding
`re_creating_an_existing_urr_keeps_the_measurement`; re-running the revert against it: **1 failed**,
with the named message. Same shape as the false guards the #210 session recorded — a test that looked
like it covered a claim and covered a neighbouring one.

**A flaky test I introduced and fixed.** `SGWU_QER_ENFORCEMENT` is process-global, and until now only
one test touched it, so there was nothing to race with. Adding a second made the pre-existing
`closed_qer_gate_drops_when_enforcement_is_enabled` fail intermittently — **1 failure in 6 runs**, with
`a CLOSED gate must drop, got Forwarded`: one test's `remove_var` landing while the other had it set.
Fixed with a module-level `QER_ENFORCEMENT_ENV_LOCK` held by all three tests; **30 of 30 runs green**
afterwards. This is the same class as the carried `gtp_path` race over `SGWU_GTPU_N3_REQUESTS`, and it
is worth noting that it only became visible because I looped the suite rather than trusting one green
run.

## Ceilings

* **No Usage Report reaches an SGW-C.** See the second section: `send_pfcp_request` is a logging
  placeholder and #217 is the missing transport. This is the honest headline. The corollary is that
  everything here is verified in-process; there is no wire capture, and no test asserts a byte sequence
  arriving anywhere.
* **No Query URR / Query All URRs** (TS 29.244 §5.2.2.3), so the CP function cannot ask for an
  on-demand report and a Remove URR **discards** its residual volume. Logged at `warn` with the amount,
  because emitting an unrequested report would invent a message the SGW-C did not ask for while
  discarding silently would lose volume. Worth its own issue.
* **No periodic reporting timer.** `measurement_period` and `time_threshold` are stored and *evaluated*,
  but only when a packet arrives — `reportable` is called from `urr_record`. A URR whose period expires
  on an **idle** session therefore does not report until the next packet, and a fully idle session never
  reports at all. Doing it properly needs a timer in `timer.rs` driving the URR store, which is a
  separate change; the PERIO trigger is honoured, just lazily.
* **Volume Quota is reported, not enforced.** Reaching a quota produces a report; it does not start
  dropping traffic. That matches TS 29.244 putting enforcement in the FAR/QER, but an operator expecting
  a hard cut-off at quota exhaustion will not get one from the SGW-U.
* **No `EVENT` measurement.** `measurement_method::EVENT` is defined and stored but nothing counts
  events, and Event Threshold / Event Quota triggers are neither evaluated nor reported. Only volume and
  duration are measured.
* **Nothing survives a restart.** sgwud reads and writes no state file, so unreported volume is lost on
  restart — for URRs specifically that is lost revenue, not just lost state.
* **`urr_record` takes the store's write lock per packet.** Fine at the scale sgwud is tested at, and it
  is what the copy-on-find rule stores force, but it is a per-packet contended lock and would want
  revisiting before any throughput claim. upfd's `DataPlaneUrr` uses atomics behind an `Arc` for exactly
  this reason; matching that here would mean changing how sgwud stores every rule, which no issue has
  asked for.
* GitNexus impact analysis unrunnable (no MCP server connected — 44th consecutive PR). Blast radius by
  grep: `apply_far` has one caller, `build_session_deletion_response` had one (now passing reports),
  `SgwuPdr` construction sites were enumerated and all updated, and nothing outside `nextgcore-sgwud`
  names any of the new types.
