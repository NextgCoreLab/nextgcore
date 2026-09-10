# nextgcore #54 (sgwcd): gate the S11 responses on Sxa, and drive the DDN end to end

Verified against `main` @ `91687ae`.

Every claim in #54 still holds (cites re-located below). The issue also **understates the
problem in two ways that had to be fixed for its own criteria to mean anything**, and those
are the findings this spec leads with. TS 23.401 §5.3.2.1 / §5.3.4.2, TS 29.274 §7.2.2 /
§7.2.11.2 / §7.2.11.3, TS 29.244 §7.5.x / §8.2.50.

## Verified against current main

| claim in the issue | site on `91687ae` | still true? |
|---|---|---|
| the Create Session Response is sent with `REQUEST_ACCEPTED` before any PFCP response | `gtp_path.rs:1039-1075` (was `:700-737`) | yes |
| the in-code NOTE admits the send must move to the Sxa response handler | same block | yes |
| `handle_session_establishment_response` has no production caller | `sxa_handler.rs:97`; only `main.rs`'s `#[cfg(test)]` | yes |
| `pfcp_open` opens no socket; `send_pfcp_message` only logs | `pfcp_path.rs:82`, `:255` | yes |
| Delete Session removes state and answers accepted unconditionally | `gtp_path.rs:1236-1248` | yes |
| `handle_session_report_request` classifies DLDR and has zero callers | `sxa_handler.rs:279`; `grep` → none | yes |
| `send_downlink_data_notification` is reachable only from `mod tests` | `gtp_path.rs:330` | yes |
| the DDN Ack handler only warns; the Data Notification Delay is parsed and dropped | `s11_handler.rs:452`, `s11_parse.rs:229` | yes |
| a DDN Failure Indication is parsed and only logged | `gtp_path.rs:685` | yes |

## Finding 1: sgwcd's Sxa messages were not PFCP at all

`sxa_build`'s helpers emitted **no IE headers**. `build_create_pdr` pushed a bare PDR id, a
bare interface octet and a bare TEID with nothing in front of them; the establishment body
began with eight raw bytes of SEID; `build_session_report_response` pushed the cause as a
lone octet. One of the comments even read *"Remote IP would be added here"*.

That was invisible precisely because the transport discarded every buffer: **nothing ever
parsed these bodies, including our own tests.** The moment a socket exists, the SGW-U — which
has decoded with the shared `nextgcore-pfcp` codec since #59 — finds **zero IEs**, creates a
session with no PDRs and no FARs, and answers `REQUEST_ACCEPTED`. Gating the S11 response on
that answer would have been gating it on a lie.

So `sxa_build` is rebuilt on the library's message types — the same decision #59 took for the
SGW-U, one codec per interface rather than a second hand-rolled one that drifts. The guard is
a decode: the stand-in SGW-U's recorded Establishment body is parsed with
`SessionEstablishmentRequest::decode` and asserted to carry the CP F-SEID, non-empty
`create_pdrs`/`create_fars`, a PDR id on every rule and an F-TEID in the PDI.

## Finding 2: nothing in sgwcd ever allocated a PDR or FAR id

`SgwcTunnel.pdr_id` and `far_id` are `Option`, and `grep` finds **no writer anywhere in the
daemon**. Every tunnel that ever existed carried `None`. The old builders wrote them under
`if let Some(...)`, so the ids were simply omitted — and with the rebuilt builder a rule with
no id cannot be emitted at all, which is how this surfaced: three new tests failed on
`expect("pdr id")` before any of them reached an assertion about #54.

`next_pdr_id()` / `next_far_id()` now allocate where the tunnel's TEID is allocated. Both are
process-wide rather than per-session, deliberately: TS 29.244 scopes the ids to the session,
but a per-session counter restarts at 1 for every session, and a stale rule matched by id
across a re-establishment is the kind of collision that reads as a data-path bug rather than
an id-space one — the shape #59 hit with `NEXT_NODE_ID`.

## Decision 1: the CP-side transport is #59's, mirrored

One bound UDP socket, transactions matched on sequence number with T1 = 3s and N1 = 2 (the
same budget sgwud uses, so the two ends of one interface do not disagree about how long a
message may take), an association **initiated** toward the SGW-U (TS 29.244 §6.2.6.2 makes
the CP function the initiator), inbound Heartbeat Requests answered, and inbound Session
Report Requests dispatched into `sxa_handler`.

`request` takes `seid: Option<u64>` for the same reason #217 needed it: a node-level message
clears the S flag, and a SEID field of 0 would be a malformed header rather than a zero SEID.

The synchronous S11 dispatch **enqueues**; the async node performs the I/O. `gtp_path`'s GTP-C
server runs on OS threads with a blocking socket and cannot await, exactly like sgwud's data
path — so `main` became `#[tokio::main]`, the event loop `await`s instead of
`thread::sleep`ing (blocking a worker for 100ms at a time would stall the Sxa task on a
single-threaded runtime), and shutdown waits for the receive loop.

## Decision 2: what the S11 answer needs travels with the PFCP transaction

`S11Continuation` carries `(peer, seq, teid)` — and the session id for a deletion — so the
response can be built when the PFCP answer lands. The alternative, looking the MME up from
the session at that point, cannot work: the **sequence number** must be echoed and only the
request knew it.

A transaction that never completes is not silence: `sxa_response::fail` answers the MME with
`REMOTE_PEER_NOT_RESPONDING`, which names which peer failed and stops the procedure hanging
until the MME's own GTP-C timer fires.

## Decision 3: a refusal KEEPS the local session

On a refused deletion the SGW-C answers the mapped cause and does **not** remove its context.
Removing it while the SGW-U still holds the session would leak the user plane with nothing
left to address it by (TS 23.007 §17), and the MME can retry. The same rule applies to a
deletion whose transaction timed out.

## Decision 4: with no S5/S8 leg, the SGW-C answers the MME itself

`handle_session_establishment_response` returns `SendGtpToPgw` on success — TS 23.401
§5.3.2.1 has the SGW-C now send a Create Session Request to the PGW. **That leg does not
exist in this tree**: `grep` finds no PGW client and `SgwcSess.pgw_addr` has no writer, which
is #52's subject. So the success arm answers the MME directly. Stated here rather than left
implied, because a reader comparing the handler's return value to what happens will otherwise
think the PGW step was forgotten.

## Acceptance criteria

- [x] The Create Session Response is emitted from the Sxa response path, not from
      `dispatch_create_session_request`; the in-code NOTE is gone —
      `no_create_session_response_until_the_sgwu_answers` observes the "not yet" half
      against a stand-in SGW-U that holds its answer for 400ms.
- [x] A non-accepted PFCP cause yields a mapped GTP cause via `gtp_cause_from_pfcp`, not a
      hard-coded `REQUEST_ACCEPTED` — `a_refused_user_plane_yields_a_mapped_gtp_cause`.
- [x] Delete Session gates `sess_remove` **and** the returned cause on the PFCP deletion
      result — `a_refused_deletion_keeps_the_session_and_says_so`.
- [x] `handle_session_report_request` has a production caller, and a DLDR drives
      `send_downlink_data_notification` toward the MME —
      `a_downlink_data_report_pages_the_ue`, which also asserts the report is answered so
      the SGW-U does not retransmit.
- [x] On DDN Ack failure **or** a DDN Failure Indication a PFCP Session Modification is sent
      to drop the buffered packets and the DDN-outstanding flag is cleared; the parsed Data
      Notification Delay is applied before the next DDN — three tests:
      `a_refused_ddn_discards_the_buffered_packets`,
      `a_ddn_failure_indication_discards_the_buffered_packets`,
      `the_data_notification_delay_throttles_the_next_ddn`.
- [x] Tests assert no Create Session Response until the PFCP response, the mapped cause on a
      simulated failure, and a DLDR producing a DDN through a non-`#[cfg(test)]` path — all
      of the above, driven through the real router and a real socket in both directions.

## Verification

`cargo test --workspace`: **6315 passed / 0 failed** over three consecutive runs (baseline
6306 on `91687ae`; sgwcd 75 → 81, plus 2 new `sxa_build` codec tests, minus 1 test replaced).
`cargo clippy --workspace --all-targets` introduces no new warning; `cargo fmt --all --
--check` clean. sgwcd's own suite: 5 consecutive green runs.

| revert | expected to break | result |
|---|---|---|
| the establishment body goes back to bare values (no IE headers) | `no_create_session_response_...` | **1 failed** |
| PDR / FAR ids are not allocated | that plus the three DDN tests | **4 failed** |
| the establishment response no longer answers the MME | every gated test | **7 failed** |
| a refused user plane is answered `REQUEST_ACCEPTED` anyway | `a_refused_user_plane_...` | **1 failed** |
| a refused deletion removes the session and reports accepted | `a_refused_deletion_...` | **1 failed** |
| a Downlink Data Report no longer pages the UE | `a_downlink_data_report_...` + 2 | **3 failed** |
| the DDN Acknowledge is only logged again | the discard and the throttle tests | **2 failed** |
| the DDN Failure Indication is only logged again | `a_ddn_failure_indication_...` | **1 failed** |

Eight reverts, eight bites.

### Tests this changed, and why

- **`test_create_session_request_accepted_over_socket` was DELETED**, not disabled: it
  asserted that a Create Session Request is answered `REQUEST_ACCEPTED` immediately, which is
  the behaviour this issue removes. Its replacement asserts everything it did (sequence
  number, MME TEID, cause, Sender F-TEID, the bearer context's allocated S1-U endpoint) **and**
  that nothing is sent until the SGW-U answers. The deletion is accounted for at the site.
- **`test_duplicate_request_answered_from_cache` and `test_full_session_lifecycle_over_socket`
  were converted** to drive the stand-in SGW-U. Their properties are unchanged; they simply
  cannot get a response any more without a peer that answers. Per the recorded rule (twice now
  the old test was right and the new code was wrong), each was checked against the spec first:
  in both cases the *expectation* is what #54 legitimately changes, not the assertion.
- **`S11_SERVER` became settable**, with the S11 clear folded into the existing Sxa test guard
  rather than given a second lock — one agreement about both globals, so there is no lock
  order to get wrong. The gated answer is sent through the process-global server, so a test
  driving a gated procedure has to be able to install its own; an install-once `OnceLock`
  makes every test after the first answer through a closed socket. Same finding as #217's.

## Ceilings

- **Modify Bearer and Release Access Bearers are NOT gated.** Both send a PFCP Session
  Modification and answer the MME immediately, as before. TS 23.401 §5.3.3 arguably wants the
  same treatment, but #54's criteria name Create and Delete, and gating them means deciding
  what a partially-applied modification should answer — a decision, not a mechanical change.
  The plumbing is now in place: `S11Continuation` gains a variant and the enqueue passes it.
  A rejected modification is logged at `warn` rather than dropped silently, which it was.
- **No S5/S8 leg** (Decision 4). The SGW-C answers the MME instead of contacting a PGW; #52
  is that work, and #303 is the E2E that needs both.
- **No heartbeat monitor on the CP side.** Inbound Heartbeat Requests are answered (§6.2.2.2
  requires it), but this SGW-C does not probe the SGW-U, so it learns of a dead peer only when
  a transaction times out. #61 did the equivalent for upfd; nothing in #54's criteria asks for
  it here.
- **The association is attempted once at startup and is not retried.** A slower SGW-U leaves
  the SGW-C associated-less until the first session request fails; the log says so. Retry
  belongs with the heartbeat monitor above.
- **A queued request is addressed to one configured SGW-U** (`SGWC_SGWU_ADDR`). Multi-SGW-U
  selection is not modelled anywhere in sgwcd, so this is not a regression — but a Session
  Report from a peer we did not send to is still dispatched, which is the shape of the
  peer-scoping #59 added on the UP side.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only, so every assertion here is a
  loopback datagram between a bound socket and a stand-in in one process, not an SGW-C
  container talking to an SGW-U container. The compose probe for `sgwc` is unchanged; the
  daemon now stays alive, which is what makes any probe meaningful at all.
- **`sm.rs` / `pfcp_sm.rs` remain decorative** on this side too: the transport handles its own
  dispatch, and the FSMs are driven by nothing in production. Carried from before this issue,
  and the same ceiling #59 recorded for sgwud.
