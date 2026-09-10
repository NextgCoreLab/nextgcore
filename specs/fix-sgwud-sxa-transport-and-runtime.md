# nextgcore #59 (sgwud): a real Sxa PFCP transport and a daemon that stays alive

Verified against `main` @ `5fa92a4`.

#59 was written against `76ea248`. Every claim in it was re-checked here; all of them still
hold, and two more were found. TS 29.244 §4.1 / §6.2.2.2 / Table 7.5.2.1-1, TS 23.007 §19A.

## Verified against current main

| claim in the issue | site on `5fa92a4` | still true? |
|---|---|---|
| `pfcp_open()` only logs "In actual implementation: Create UDP sockets…" | `pfcp_path.rs:141` | yes |
| `pfcp_close()` is log-only | `:155` | yes |
| `send_pfcp_response` / `send_pfcp_request` are no-ops with no socket I/O | `:285`, `:303` | yes |
| `handle_pfcp_recv` reads only `data[1]`, decodes no IE, invokes no handler | `:369` | yes |
| `main()` falls through to cleanup and returns `Ok(())` — the process exits 0 | `main.rs:61-76` | yes |
| `main()` is not even `async` | `main.rs:17` `fn main()` | yes, and worse than stated |
| the restoration hook is reachable only from the FSM's own tests | `pfcp_sm.rs:398` | yes |
| no metrics endpoint, no SIGTERM handling | grep: nothing | yes |
| `nextgcore-pfcp` is already a dependency but unused on the wire | `Cargo.toml:16` | yes |
| `docker-compose-epc.yml` probes `sgwu` with `kill -0 1` | anchor at `24-26`, applied at `130` | yes |
| no E2E script drives an MME↔SGW↔PGW path | `grep -c mme e2e-test.sh` → 0 | yes |
| **criterion 8's attach is reachable** | **NO — mmed binds no UDP socket at all** | **false, see below** |
| **`sess_remove_all_for_pfcp_node` can match a session** | **NO — nothing ever set `pfcp_node_id`** | **false, see below** |

## The two things the issue did not know

**1. `sess_remove_all_for_pfcp_node` would have removed nothing.** It filters on
`SgwuSess.pfcp_node_id == Some(id)`, and `grep` finds no writer of that field anywhere:
`sess_add` never set it. So even once the restoration hook became reachable, it would have
matched zero sessions and reported success. The establishment path now tags every session with
the node id of the peer that established it, and a revert of just that tag fails a named test.

**2. Criterion 8 cannot be satisfied, and it is not a matter of effort.** It asks for an E2E stage
that "completes an MME↔SGW-C↔SGW-U↔SMF(PGW) attach". `mmed` binds **no UDP socket at all**
(`rg 'UdpSocket::bind' bins/nextgcore-mmed/src` → nothing outside tests), which is #51's whole
subject: there is no S11 GTP-C endpoint to originate the Create Session Request from. No SGW-U
change can make that attach happen. The criterion is therefore split into its own issue naming
#51 (and #52 for the S5/S8 leg) as its blockers, and this spec states that rather than shipping a
script that cannot pass. The other eight criteria are met.

## Decision 1: the library codec, and `sxa_build`'s bodies are kept

The issue asks to "replace the `PfcpMessage { msg_type, seid, data }` shape with codec-backed
header/IE encoding". Half of that was already right: `data` is a flat TLV IE sequence, which is
what a PFCP message body **is** — `build_cause_ie` writes type/length/value correctly, and so do
its siblings. What was missing was the header, the socket, and the dispatch.

So: `PfcpHeader` (library) encodes and decodes every header in both directions, the library's
message decoders parse every inbound body, and `sxa_build` keeps producing response bodies. What
was NOT done is a second hand-rolled header codec — smfd already has one and upfd another, and a
third copy is how they drift.

## Decision 2: the synchronous data path enqueues; the async node sends

`gtp_path` is the user plane: `std::thread::spawn` with a blocking socket. It calls
`send_session_report_request` in five places, and that function must stay synchronous — putting a
per-packet executor in front of GTP-U forwarding is a far larger change than this issue.

So the sync API encodes the message and enqueues it; the node's task performs the socket I/O with
T1/N1 retransmission and feeds the response back into `handle_session_report_response`. The
enqueue **fails loudly** when no transport is running, which is the opposite of the stub it
replaces: `send_pfcp_request` returned `Ok(())` after logging, so every Downlink Data Report the
data path produced was discarded while its caller believed it had been sent.

## Decision 3: peer failure runs the FSM's restoration, not a bypass of it

Criterion 5 asks for "the FSM path that invokes `sess_remove_all_for_pfcp_node`", so each peer
owns a `PfcpStateMachine` that the transport drives: association walks it
Initial → WillAssociate → Associated, and failure sets `restoration_required` and dispatches an
FSM entry, which is the arm that calls `pfcp_restoration()`. Calling
`sess_remove_all_for_pfcp_node` directly would have been three lines shorter and would have left
the FSM exactly as dead as it was.

Three live paths reach it: N consecutive unanswered Heartbeat Requests, an inbound Association
Release, and a peer whose Recovery Time Stamp changed. Three misses rather than one, so a single
lost datagram cannot flush a live peer's sessions.

## Decision 4: `NEXT_NODE_ID` is process-global, not per node

Found by a failing test, not by design. Node ids started at 1 per `SxaNode`, and the session store
is process-global — so two nodes both minted id 1 and one node's
`sess_remove_all_for_pfcp_node(1)` removed the other's sessions. A running daemon has one node, so
this could only bite where several exist at once (the tests), which is exactly where it would have
been read as a flake.

## Decision 5: the health probe asks the runtime, not the association

`kill -0 1` asks whether PID 1 exists — true of an SGW-U that had opened its sockets and returned
from `main`. The probe now curls the metrics endpoint for `sgwu_up 1`, which only the live runtime
renders. Deliberately **not** `sgwu_pfcp_associations`, which the same body carries: the SGW-C
associates after both containers are up, so gating liveness on it would report the SGW-U unhealthy
during every normal bring-up. Association belongs to readiness, which compose has no separate
notion of.

## Decision 6: the library's `CreateUrr` gains `volume_quota`

TS 29.244 §8.2.14 has the same wire structure as the §8.2.13 Volume Threshold, and the library
modelled neither the field nor the IE — while `sgwud`'s `CreateUrrRequest.volume_quota` exists and
is enforced. So a Volume Quota an SGW-C provisions decoded to nothing, and the SGW-U enforced a
quota of zero while looking provisioned. Ten lines in the shared codec rather than a second
decoder beside it; `upfd` gets it for free.

## Acceptance criteria

- [x] sgwud binds UDP/8805 and runs a receive loop; the process stays alive instead of returning
      `Ok(())` — `the_sxa_socket_is_really_bound`, plus `main`'s `shutdown_signal().await`.
- [x] An inbound Heartbeat Request is decoded via `nextgcore-pfcp` and answered —
      `an_inbound_heartbeat_request_is_answered_with_our_recovery_time_stamp`.
- [x] Association Setup and Session Establishment are fully decoded (IEs, not the type byte) and
      dispatched into `sxa_handler`, producing a correctly encoded response on the wire —
      `an_association_setup_request_is_accepted_and_the_peer_recorded`,
      `a_session_establishment_request_creates_a_session_and_is_answered`.
- [x] `send_pfcp_request`/`send_pfcp_response` perform real socket I/O with T1/N1 retransmission —
      `a_request_retransmits_on_t1_and_completes_on_the_answer`.
- [x] Loss of peer heartbeats triggers the FSM path that invokes
      `sess_remove_all_for_pfcp_node`, reachable from the running daemon —
      `peer_failure_runs_the_fsm_restoration_and_removes_that_nodes_sessions` (Decision 3).
- [x] `main()` shuts down gracefully on SIGTERM/Ctrl-C and exposes a metrics endpoint —
      `shutdown_signal`, `serve_metrics`, `the_metrics_render_reports_sessions_and_associations`.
- [x] `docker-compose-epc.yml` uses a functional SGW-U probe instead of `kill -0 1` (Decision 5).
- [ ] ~~A new EPC stage in `e2e-test.sh` completes an MME↔SGW-C↔SGW-U↔SMF(PGW) attach~~ —
      **split out**: mmed has no S11 endpoint to originate it (#51). Filed as its own issue.
- [x] Test expectation: a real PFCP Heartbeat and Session Establishment Request are sent to a
      running sgwud and the decoded responses asserted. The **EPC E2E half** of this criterion
      moves with criterion 8.

## Verification

Workspace **6288 passed / 0 failed** over three consecutive runs (baseline 6285 on `5fa92a4`;
sgwud 110 → 120 after deleting 8 stub tests and adding 10 wire tests, nextgcore-pfcp +1).
`cargo clippy -p nextgcore-sgwud -p nextgcore-pfcp --all-targets` zero warnings;
`cargo fmt --all -- --check` clean.

The transport tests drive **real datagrams through a bound socket** and decode the answers with the
library codec, which is what the issue's test expectation asks for.

| revert | expected to break | result |
|---|---|---|
| the Heartbeat Request is not answered | `an_inbound_heartbeat_request_is_answered_...` | **1 failed** |
| the Establishment is decoded but not dispatched into `sxa_handler` | `a_session_establishment_request_...` | **1 failed** |
| the session is not tagged with its peer's node id | same | **1 failed** |
| the FSM restoration is not run on peer failure | `peer_failure_runs_the_fsm_restoration_...` | **2 failed** |
| restart detection fires on ANY re-association | `a_changed_recovery_time_stamp_flushes_...` | **1 failed** |
| no T1 retransmission (single attempt) | `a_request_retransmits_on_t1_...` | **1 failed** |
| the version check removed | `an_unsupported_version_is_answered_...` | **1 failed** |
| the gate-status octet not inverted | `the_library_ie_mapping_preserves_...` | **1 failed** |
| the library's Volume Quota decode arm removed | `a_create_urr_carries_its_volume_quota_over_the_wire` | **1 failed** |

### The revert that did not bite the first time

Removing the library's Volume Quota **decode** arm initially left the whole suite green. The mapping
test builds the library struct directly and reads the field back, so it asserts the mapping and
says nothing about the codec — a guard covering the neighbouring claim, and its comment
("must reach the rule store") overclaimed. The fix is a ROUND-TRIP test in the library, where the
defect would be; the sgwud comment now says which half it covers and points at the other.

## Ceilings

- **Update QER / Remove QER / Update URR / Remove URR are not decoded.** The IE types exist in the
  library; the structs do not, and `SessionModificationRequest` models none of them. So those lists
  arrive EMPTY however the SGW-C populated them, and `sxa_handler`'s code for them stays reachable
  only in-process. Named at the mapping site and filed separately rather than hand-decoded beside
  the library decoder.
- **Create BAR and PFCPSEReq-Flags are not mapped** for the same reason (the library's establishment
  message models neither). Left absent rather than defaulted: a BAR this SGW-U claimed to have
  installed would make buffering look configured.
- **No EPC E2E stage** (criterion 8, above). The compose probe change is therefore verified by
  inspection and by the metrics-render test — the Docker jobs are `workflow_dispatch`-only, so CI
  does not exercise it on this PR, and no script was added that could not be run.
- **The FSM is driven for association and restoration only.** `sm.rs`'s outer `SgwuStateMachine`
  and the `event.rs` dispatch layer are still driven by nothing in production; the transport handles
  its own message dispatch. Folding those together (or deleting them) is not in these criteria.
- **`gtp_path` remains synchronous**, so a Session Report crosses a queue rather than being awaited
  by its producer. A report enqueued microseconds before shutdown can be dropped; the queue is
  unbounded, so the data path never blocks on the control plane.
- **Heartbeats are answered for peers this SGW-U never associated with** (TS 29.244 §6.2.2.2 says
  answer at any time) but such a peer is not tracked, so its Recovery Time Stamp is not compared.
