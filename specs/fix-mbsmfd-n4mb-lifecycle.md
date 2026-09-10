# nextgcore #76 (mbsmfd): honour the N4mb control plane and keep MB-UPF state consistent

Verified against `main` @ `6f1f6a9`.

## Verified against current main

Every cite in the issue re-located and confirmed:

| claim | site on `6f1f6a9` | still true? |
|---|---|---|
| the recv loop logs `unsolicited PFCP … ignoring` and drops UP-initiated messages | `n4mb.rs:230` | yes |
| `release_session` has **zero callers** | `rg 'release_session'` → definition only | yes |
| DELETE removes local state only | `handle_mbs_session_release` → `session_remove` | yes |
| TERMINATE sets `ReleasePending` then immediately zeroes `n4mb_session` | `context.rs` `session_context_terminate` | yes |
| START re-creates the N4mb session unconditionally | `session_activate_n4mb` allocated a fresh `local_seid` every call | yes |
| `ExtMbsSession` carries only `mbsSessionId`, `serviceType`, `ingressTunAddr` | `types.rs:94-106` | yes |
| a missing mandatory `serviceType` is defaulted (`_ => Multicast`) | `handle_mbs_session_create` | yes |
| `ingressTunAddr` is `format!("{:#010x}", gtp_teid)` | as cited | yes |
| a no-TMGI create returns a hardcoded TMGI; `session_add` has no duplicate check | `context_tmgi_from`, `session_add` | yes |
| `apply_patch_data` inspects only `/mbsServiceArea`, for any op | `types.rs:154-175` | yes |
| ContextUpdate rejects anything without `mbsSessionId.tmgi` with `400` | as cited | yes |

## Decision 1: the report is answered on the socket, the consequence is applied elsewhere

`handle_up_initiated` runs in the recv loop **before** the pending-table lookup, answers a
Heartbeat Request and a Session Report immediately, and queues the report. The main loop drains
the queue and applies the activation.

Split that way for a specific reason: the UP is waiting for the response (TS 29.244 §6.2.3.2 and
§7.5.8 both make it mandatory), and activating a session needs the context lock — whose writers
call back into this node. Doing the activation inline would put a lock acquisition inside the
socket loop with a re-entrancy path through it.

Two details that are easy to get wrong and are pinned:

* **The response echoes the request's sequence number** and goes to `src`, not to the configured
  `upf_dest`. §7.2.2.4 has a response carry the sequence number of the request it answers, and a
  response must go back to whoever asked; using the configured destination would silently swallow
  a request from a UP whose source port differs.
* **Dispatch precedes the waiter lookup.** The other order would let a Heartbeat Request arriving
  mid-transaction steal the waiter for an in-flight Session Establishment — which would surface as
  a UPF timeout. `an_inbound_request_does_not_steal_a_pending_waiter` sends a heartbeat with
  sequence number 1, which is also the first the node itself uses.
* **Reports are drained, not peeked.** Leaving them would have the 100ms loop re-activate an
  already-active session on every tick, and `session_activate_on_downlink_data` reports whether the
  state actually *changed* for the same reason.

## Decision 2: release is three steps, and the order is the criterion

`session_mark_release_pending` (under the lock) → the PFCP Session Deletion (an `await`) →
`session_clear_n4mb`. `session_context_terminate` no longer clears.

The old code cleared **first**, which discarded the remote SEID the deletion has to be addressed
to — so nothing could delete the session on the MB-UPF even in principle. `session_remove`'s log
line said "releasing N4mb SEID" while releasing nothing.

`release_n4mb_transport` returns whether the deletion was *acknowledged* but clears local state
either way. The session is leaving this MB-SMF regardless, and keeping a context whose UPF
counterpart may or may not exist would leave the two sides disagreeing with no path back. A
possible leak is named in the log rather than left silent. A session whose establishment never
completed has no UP-allocated SEID, so there is nothing to delete and it is cleared without a
request — distinguished from "no N4mb context at all" by `Option<u64>` rather than a sentinel.

## Decision 3: a duplicate TMGI is refused, not overwritten

`session_add` returns `None` when the TMGI is already in use. The overwrite left the earlier
session in `session_list` reachable by **nothing** — its TMGI resolved to the new session, so it
could never be found or deleted, and its MB-UPF session could never be released. A TMGI identifies
one MBS session, so a second create for the same one is the consumer's error, and refusing keeps
the existing session findable.

## Decision 4: the `anyOf` on `MbsSession` is deliberately NOT enforced

TS 29.571 makes `MbsSession` `anyOf [mbsSessionId, tmgiAllocReq]`. Enforcing it would refuse a
create carrying neither — and #76's criterion 7 requires exactly that create to **succeed** by
allocating from `TmgiPool`. The two cannot both hold, so an absent `tmgiAllocReq` is read as an
implicit request.

This was found by *breaking a test*: enforcing the `anyOf` turned
`test_router_release_fires_notify_path`'s `{"mbsSession":{"serviceType":"MULTICAST"}}` create into
a `400`. Recorded here rather than silently, because a conformance suite exercising the `anyOf`
will see it accepted.

## Decision 5: only a service-area REDUCTION gets the 200 + `redMbsServArea` body

The outcome now depends on the RFC 6902 `op`: `replace` and `remove` can reduce, `add` cannot.
TS 29.532 §5.3.2.3 gives that body to a reduction — it is the MB-SMF telling the consumer which
part of the requested area it could not serve. Returning it for an addition tells the consumer its
enlarged area was cut back to exactly what it asked for, which is a different statement and one it
may act on by re-requesting.

`move`/`copy`/`test` are accepted and applied to nothing: refusing a legal op would reject a
conformant patch, while acting on one whose semantics need a source document this NF does not keep
would be inventing behaviour.

## Decision 6: SSM resolution is a scan, not a second index

`session_find_by_ssm` walks the session map. Sessions are capped at `max_sessions` and ContextUpdate
is not a per-packet path, so the cost is irrelevant — whereas a second index over the same sessions
would be a second set of invariants to keep in step with `session_add`/`session_remove`, which is
precisely the class of bug the duplicate-TMGI overwrite was.

The consumer's SSM is stored as the **wire type** (`types::Ssm`), not parsed into
`std::net::IpAddr`: TS 29.571's `IpAddr` is a choice of two optional textual members, so matching
on the received form is what makes a lookup agree with what was stored. It is also distinct from
`n4mb_session.ll_ssm_src`/`ll_ssm_dst`, which are the lower-layer SSM the MB-SMF *allocates*.

An SSM resolves to the session's own TMGI, so the whole downstream handler stays keyed on one
identifier. An SSM no session carries is a `404` (a real lookup miss), not a `400`.

## An existing test pinned the defect, and the modal verb decided it

`test_context_terminate_releases_n4mb` asserted that `session_context_terminate` leaves
`n4mb_session` as `None` — i.e. it pinned the discard-the-SEID shortcut as the requirement.

Per the recorded discriminator, the governing clause's modal verb settles it: TS 29.244 §7.5.4 has
the CP function **send** a Session Deletion Request to release a PFCP session, and TS 23.247
§7.1.1.4 has releasing an MBS session tear down the associated MB-UPF resources. Not a "may". So
the assertion was pinning a shortcut past a mandatory message, and inverting it is legitimate. The
flip is recorded at the site with that citation.

What makes the inversion safe to believe: the two **handler-level** tests that assert the
post-handler state — `test_router_context_update_amf_release_golden_204` and
`mbs_context_update_strict_peer_release_204` — pass **unchanged**, because the handler now drives
the release and clears afterwards. Only this function's own contract narrowed. And they turn out to
be the guard for the new wiring: revert 2 below removes the three `release_n4mb_transport` calls and
both fail.

## Acceptance criteria

- [x] A Heartbeat Request produces a Heartbeat Response —
      `a_heartbeat_request_is_answered_with_a_heartbeat_response`, asserting the datagram the UP
      receives (type, echoed sequence number, non-zero Recovery Time Stamp).
- [x] A Session Report Request produces a Session Report Response and drives activation —
      `a_session_report_is_answered_and_queued_for_the_session_driver` (response addressed to the
      request's SEID; the report surfaced and drained) plus `apply_n4mb_reports` →
      `session_activate_on_downlink_data`.
- [x] DELETE sends a Session Deletion Request before removing local state —
      `a_session_deletion_request_is_transmitted_to_the_up_allocated_seid` (the request on a real
      socket, addressed to the **UP-allocated** SEID) and the three-step order in
      `release_n4mb_transport`, guarded by revert 2.
- [x] Last-consumer TERMINATE sends the deletion and clears afterwards — same driver, both
      terminate legs; `test_context_terminate_marks_release_pending_without_discarding_the_seid`
      pins that the SEID survives long enough to be used.
- [x] A repeated START does not allocate a new SEID —
      `a_repeated_start_reuses_an_established_n4mb_session`, including that an
      `EstablishmentPending` session IS re-drivable (that is the retry path).
- [x] A missing `serviceType` is `400`; a full `ExtMbsSession` round-trips; `ingressTunAddr` is
      structured — `create_refuses_a_missing_service_type_and_answers_a_structured_ingress_address`,
      `a_full_ext_mbs_session_round_trips_its_write_only_members`, and the `TunnelAddress`
      serialisation pinned in `test_create_rsp_data_roundtrip`.
- [x] A no-TMGI create allocates from `TmgiPool` and a second does not overwrite the first —
      `two_no_tmgi_creates_get_two_sessions_from_the_pool` (both still retrievable) and
      `a_duplicate_tmgi_create_is_refused_and_the_first_session_survives`.
- [x] PATCH of `activityStatus`/QoS is applied with the spec-correct `200`/`204`, and an addition
      does not return the reduction body — `activity_status_qos_and_security_are_applied_rather_than_acknowledged`,
      `an_added_service_area_is_not_reported_as_a_reduction`.
- [x] ContextUpdate for an SSM-identified session is accepted —
      `a_context_update_identified_by_ssm_is_accepted`, plus the `404`-on-unknown-SSM and
      `400`-on-neither cases.
- [x] clippy and the mbsmfd suite pass — mbsmfd at **zero** clippy warnings.

## Verification

Workspace **6270 passed / 0 failed** (baseline 6258 on `6f1f6a9`; +12 — 95 in mbsmfd, was 83),
easdfd's `dns-udp` feature still 51/0. `cargo clippy --workspace --all-targets` and `cargo fmt
--all -- --check` clean. Five consecutive mbsmfd runs green (the crate has process-global session
state).

| revert | expected to break | result |
|---|---|---|
| UP-initiated dispatch removed | the three n4mb inbound tests | **3 failed** |
| the three `release_n4mb_transport` calls removed | the two pre-existing handler tests | **2 failed** |
| activation no longer idempotent | the repeated-START test | **1 failed** |
| duplicate TMGI overwrites again | the duplicate-TMGI test | **1 failed** |
| `serviceType` defaulted again | the create-validation test | **1 failed** |
| an `add` reported as a reduction | the reduction test | **1 failed** |
| SSM-identified ContextUpdate refused | the SSM test | **1 failed** |
| `activityStatus` ignored | the PATCH-applied test | **1 failed** |
| `ingressTunAddr` carries no usable address | the create-validation test | **1 failed** |
| the Session Report answered but not surfaced | the report test | **1 failed** |

No false guards this round. Revert 2 is the interesting one: it confirms two tests written for an
*earlier* issue are the wiring guard for this one, which is why inverting the third was safe.

## Ceilings

* **The DELETE/TERMINATE call sites are not covered end to end through a socket.** `N4MB_NODE` is a
  `tokio::OnceCell` whose destination is read from the environment at first bind, and existing create
  tests reach it first, so a test cannot point the process's node at its own fake MB-UPF. This is the
  same `OnceLock`-shaped harness limitation as #289 in smfd. What *is* verified: the deletion on a
  real socket at the node (`release_session`), the three-step ordering in the context, and the
  handler wiring via revert 2 against the two pre-existing handler tests.
* **The activation is applied from the 100ms main loop, not from the report itself**, so a report
  and its activation are up to 100ms apart. Deliberate (see Decision 1); a report already answered
  on the wire is not time-critical to apply, but it is not instantaneous either.
* **`mbsServiceArea` and `mbsServInfo` are stored as raw JSON.** The shapes are unions
  (NCGI/TAI lists; a QoS request with several optional members) and re-modelling them without a
  consumer for every member would be a model that reads as enforced and is not. What IS read out of
  `mbsServInfo` is the 5QI and `mbrDl`, and only those.
* **The `anyOf` on `MbsSession` is not enforced** — see Decision 4.
* **No last-consumer ref-counting.** #76's criterion 4 says "last-consumer TERMINATE", and
  `nfcInstanceId` is still not tracked as a per-session consumer set, so *any* TERMINATE releases the
  transport rather than only the last consumer's. The issue lists that under its gap 7 alongside SSM;
  the SSM half is done and the ref-counting half is not, because it needs a decision about whether a
  join implicitly registers a consumer (nothing in the tree registers one today). Worth its own issue.
* **The tail sub-claims #76 itself flags as unverified are still unverified**: Status/ContextStatus
  notification inertness, non-spec GET routes, relative `Location` headers, and pool exhaustion
  answering `400`. Untouched, and the issue says to treat them as plausible-not-confirmed.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `apply_patch_data` gained a parameter (1 production + 5 test call sites, all updated);
  `session_remove` has 1 production caller; `session_context_terminate` has 2; `MbsSession` gained
  one field with one writer and one reader.
