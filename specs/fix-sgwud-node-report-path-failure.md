# nextgcore #217 (sgwud): report a detected GTP-U path failure with a PFCP Node Report

Verified against `main` @ `2c49dd4`.

#217 was filed when sgwud had no PFCP transport at all. **Its premise is stale and its
deliverable is not** — the re-scope comment on the issue said so at `b1b2bb5`, and this spec
re-verified every part of it. TS 23.007 §20.3.4 / §20.3.5.1, TS 29.244 §7.4.5 / §8.2.68 / §8.2.83.

## Verified against current main

| claim in the issue | site on `2c49dd4` | still true? |
|---|---|---|
| `pfcp_open()` opens no socket; sends are `Ok(())` stubs | **NO** — `pfcp_open` binds, `SxaNode::request` does real I/O with T1/N1 | **false: #59 fixed it** |
| no PFCP receive loop in `main.rs` | **NO** — `SxaNode::run` is the loop | **false: #59 fixed it** |
| `grep -rn "NodeReportRequest" src/bins/` returns 0 constructions | grep: still **0** | yes |
| `grep -c NODE_REPORT` over sgwud's `pfcp_path.rs` is 0 | still **0** | yes |
| the codec is complete: `NodeReportRequest` / `NodeReportResponse` with roundtrip test | `libs/nextgcore-pfcp/src/message.rs:1218` | yes |
| `NodeReportType` with the `upfr` bit, `UserPlanePathFailureReport { remote_gtpu_peers }` | `types.rs:3412`, `:3503` | yes |
| detection is in place: `failed_gtpu_paths()`, `note_echo_unanswered` is the hook | `gtp_path.rs:434`, `:389` | yes |
| the transport's `is_response_type` already routes type 13 | `pfcp_path.rs:1582` — `13` is in the list | yes |

So the prerequisite the issue worried about (#61's detection) exists, and the blocker it was
filed for (#59's transport) is gone. What was missing is exactly the message it is named for.

## Decision 1: the report is node-level and goes to every associated peer

A Node Report is not session signalling. It carries no SEID (TS 29.244 §7.2.2.1 clears the S
flag), and a failed GTP-U path affects **every** session forwarding over it — including sessions
belonging to a different CP function. So it is addressed to the node's associated peers rather
than to one session's SGW-C.

That forced two changes to #59's transport:

- `SxaNode::request` now takes `seid: Option<u64>`. It used to pass `Some(seid)` unconditionally,
  so a node-level message would have gone out with the S flag set and a SEID of 0 — a malformed
  header, not a zero SEID. The revert of this fails both wire tests.
- `QueuedRequest` gained a destination (`Addr` | `AssociatedPeers`) and a response sink
  (`Session(id)` | `NodeReport`). The fan-out is resolved in the **drain task**, not by the
  synchronous caller: the peer table is behind an async lock, and resolving it at enqueue time
  would report to a peer that had gone away in between. The sink matters because routing a Node
  Report Response into `handle_session_report_response` would look up session 0 and log a
  rejection for a session that never existed.

## Decision 2: the synchronous data path still only enqueues

Unchanged from #59's Decision 2, and it is why this works at all: detection happens on
`gtp_path`'s GTP-U receive thread, which runs a blocking socket and cannot await. The report is
built and enqueued synchronously; the node's task performs the I/O with T1/N1.

The path-table mutex is **released before** the report is queued. Holding a data-path lock across
the enqueue is how the forwarding threads would come to wait on the control plane.

## Decision 3: report the TRANSITION, and report the recovery too

`note_echo_unanswered` already had the transition guard (`state.unanswered > limit &&
!state.failed`), so the report hangs off that rather than off "is this path failed". Every
subsequent probe round for a peer already down re-enters the function; reporting each time would
be a Node Report storm at the Echo cadence for one dead eNB. Asserted with several further failing
rounds producing no second report.

Recovery is reported with UPRR (§20.3.5.1) for the reason the failure is reported at all: an SGW-C
that suspended or tore down state on the failure has no other way to learn it can stop. An
answered Echo on a **healthy** path is not a transition and reports nothing — the same storm,
inverted, and it has its own assertion.

## Decision 4: "nobody to report to" is an error to the caller, not a log line in the task

First written as a `targets.is_empty()` check in the drain task. **The revert of that did not
bite** — with no targets the send loop simply does nothing, so removing the check changed only a
log line, and the test asserting "nothing reaches the wire" passed either way.

So the check moved to the synchronous caller, where `node.associated_peer_count()` (the existing
sync gauge the metrics render uses) answers it without a lock. `send_node_report_request` now
returns `Err("no associated SGW-C: there is nobody to report the path to")`, and `gtp_path`'s
`report_path_transition` logs it at `warn` **naming which path went unreported** — which the
drain task could never have done, because by then all it has is a message type. That is now a
revert-covered guard instead of a diagnostic.

## Decision 5: `SXA_NODE` and `OUTBOUND` become settable, with one test lock

They were `OnceLock`s — first-wins, never cleared. Survivable while the only synchronous sender
was a Session Report addressed by the session's own CP F-SEID; **not** survivable for a Node
Report, which is addressed to *the installed node's* associated peers and can therefore only be
asserted against the node the test actually opened. Under `#[tokio::test]` each test has its own
runtime and its own socket, which is the same wall #289 hit in smfd with `PFCP_CLIENT`, and this is
the same shape and the same reasoning.

What changes for the running SGW-U: nothing. `main` opens one node and runs it once.

`SXA_TEST_LOCK` is declared beside the two globals — one lock for both, since they are always
installed together — and the guard clears them on acquire as well as on drop. Two consequences
worth stating:

- `a_session_report_without_a_running_transport_is_an_error_not_a_silent_ok` became
  **deterministic**. It used to accept either outcome because a sibling's node could legitimately
  have installed a queue; now the guard clears first, so the error is the only correct answer.
- `main.rs`'s `test_pfcp_path_open_close` calls `pfcp_open`, which installs the global too. It now
  takes the same guard. This was found the hard way: the Node ID test passed alone and failed in
  the full run, because that test overwrote the node it was asserting against. **The set of tests
  that can reach a process-global is wider than the module that declares it.**

## Decision 6: fix the carried `SGWU_GTPU_N3_REQUESTS` race rather than step around it

Adding a report call to `note_echo_unanswered` made a **pre-existing** `gtp_path` flake visible: 1
failure in 23 runs, in `path_state_is_per_peer` and `path_fails_only_after_exceeding_n3_requests`.

Neither was my code. `failed_gtpu_paths()` returns the WHOLE table, so two tests failing different
peers concurrently each see the other's peer — the symptom is an assertion about peer B reporting
peer A, which reads as a per-peer bug in the code under test. `N3-REQUESTS` is worse: a
process-wide env var, so one test lowering it changes how many Echoes another needs. The file
already carried a comment predicting this ("Same shape as the carried `gtp_path` race over
`SGWU_GTPU_N3_REQUESTS`") beside a lock added for the QER-enforcement env var.

`GTPU_PATH_TEST_LOCK` is declared beside `GTPU_PATHS` and taken by the three tests that assert on
the table as a whole. 1-in-23 before, **0 in 60 after**. No test takes both it and
`SXA_TEST_LOCK`, so there is no lock-ordering cycle.

## Acceptance criteria

- [x] sgwud has a real PFCP transport — met by **#59**, re-verified here, not re-implemented.
- [x] A detected GTP-U path failure produces a Node Report Request with `upfr` set and the failed
      peer(s) in a User Plane Path Failure Report —
      `a_failed_gtpu_path_is_reported_once_over_the_wire`.
- [x] The report fires on the failed **transition**, not once per probe round; five further failing
      rounds produce no second report (same test).
- [x] Path recovery produces a corresponding report —
      `a_recovered_gtpu_path_is_reported_with_uprr`, which also asserts that an answered Echo on a
      healthy path reports nothing.
- [x] A test captures the encoded bytes on a socket and decodes them as a valid
      `NodeReportRequest` — `count_node_reports_about` decodes every candidate datagram off the
      peer socket and asserts the header carries **no SEID**; the Node ID half is
      `a_node_report_names_this_sgwus_own_node_id`.
- [x] Workspace lint and test suites pass — below.

## Verification

`cargo test --workspace`: **6295 passed / 0 failed** (baseline 6290 on `2c49dd4`; sgwud 121 → 126).
`cargo clippy --workspace --all-targets` introduces no new warning; `cargo fmt --all -- --check`
clean. sgwud's own suite: **30 consecutive green runs** after Decision 6's lock.

| revert | expected to break | result |
|---|---|---|
| the failure report call removed from `note_echo_unanswered` | `a_failed_gtpu_path_...`, `a_recovered_...` | **2 failed** |
| report on every round instead of the transition | `a_failed_gtpu_path_is_reported_once_...` | **1 failed** |
| the recovery report removed from `note_echo_answered` | `a_recovered_gtpu_path_is_reported_with_uprr` | **1 failed** |
| `upfr` and `uprr` both set (the bit not discriminated) | both wire tests | **2 failed** |
| the node-level message carries `Some(0)` as its SEID | both wire tests | **2 failed** |
| the Node ID is not ours (`9.9.9.9`) | `a_node_report_names_this_sgwus_own_node_id` | **1 failed** |
| the empty-peer-list refusal removed | `a_node_report_with_no_peers_is_refused` | **1 failed** |
| the no-association check removed | `a_path_failure_with_no_associated_peer_...` | **1 failed** |

Eight reverts, eight bites — after one that did not, which is Decision 4: the no-peer case as a
log line in the drain task was unfalsifiable, and moving the check to the caller is what turned it
into a guard. The lock in Decision 6 is verified the other way round, by frequency: 1 failure in
23 runs before, 0 in 60 after.

### A pre-existing whole-workspace flake, measured and not fixed here

`cargo test --workspace` fails roughly **1 run in 5** in `nextgcore-smfd`, in tests that share the
process-global `UDM_SBI_ADDR` / `UDM_SBI_PORT` env fallback
(`udm::tests::the_smf_registers_with_the_udm_and_fetches_sm_data`,
`tests::the_create_subscribes_to_sm_data_and_the_release_deregisters_and_unsubscribes`). smfd's own
suite is green 6/6 in isolation; only the whole-workspace run provokes it.

**Verified as baseline, not introduced**: a worktree at `main` with none of these changes failed 2
of 9 whole-workspace runs in the same two tests. This branch touches no smfd file. CI's single
`cargo test` retry hides it, which is why it has not been noticed. Filed as its own issue rather
than fixed in this PR — it is another daemon, and folding an unrelated env-var race into #217
would make this diff's revert story unreadable.

## Ceilings

- **The Node Report Response is decode-and-log, and the log is not asserted.** The wire tests
  answer every report they receive, so `node_report_response_received` is genuinely executed — but
  its only output is a log line, so a revert of the logging is invisible and no guard claims
  otherwise. The criterion asked for exactly this ("a decode-and-log arm rather than new
  plumbing"). A rejected report is logged at `warn` naming that the SGW-C is not acting on the
  failure; making that assertable would need either a log-capture harness or a metrics counter,
  neither of which #217 asks for.
- **The `state == Associated` filter on the fan-out is defensive only.** The single insert path
  (`handle_association_setup_request`) sets `Associated` in the same statement, so a peer cannot be
  in the table in another state today. No revert covers the filter, because no reachable path
  produces the case it excludes.
- **Only the transitioning peer is reported**, not the whole `failed_gtpu_paths()` set. Reporting
  the set would re-report peers already reported on every new failure. TS 29.244 §7.4.5 permits
  several Remote GTP-U Peers in one report, and `send_node_report_request` takes a slice, so
  batching is a caller change if a future issue wants it.
- **The Echo probe cadence is 60s by default**, so in a deployment the report follows the failure
  by up to N3+1 probe intervals. Unchanged by this issue; the tests drive
  `note_echo_unanswered` directly rather than waiting for the prober.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only, so every wire assertion here is a
  loopback datagram between a bound node and a test socket in one process — not an SGW-U container
  reporting to an SGW-C container.
- **sgwud still has one live control path and one decorative one.** `sm::SgwuStateMachine` and
  `timer::TimerManager` remain undriven in production (carried from #59); this issue adds no timer
  and no event, so that gap is unchanged.
