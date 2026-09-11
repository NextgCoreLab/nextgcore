# nextgcore #51 (mmed): a functional S11 GTP-C endpoint on the shared codec

Verified against `main` @ `76cefd2`. TS 29.274 §7.2.1, §7.6, §8.4, §8.12, §8.17, §8.22,
Tables 7.2.1-1 / 7.2.7-1 / 7.2.9.1-1; TS 23.007 §18, §20; TS 23.401 §5.3.2.1.

#51 is accurate in every particular. Nothing in it is stale.

## Verified against current main

| claim in the issue | site on `76cefd2` | still true? |
|---|---|---|
| `gtp_open()` binds no UDP socket | `gtp_path.rs:62` sets a bool | yes |
| every `send_*` drops the message into a `_pkbuf` local | **eleven** of them | yes |
| no `Gtp2XactMgr` instantiated by mmed | grep: referenced only by sgwcd | yes |
| sequence numbers hardcoded to 0 | `write_gtp_header_with_teid(..., 0)` in every builder | yes |
| two senders substitute `ctx.next_pool_id()` for the sequence | DDN Ack and Release Access Bearers | yes |
| the CSR omits Sender F-TEID and Bearer Contexts | it emits 8 IEs, neither of them | yes |
| the MBR is invoked with an empty bearer slice | `&[]` at the call site | yes |
| DSR passes a literal `5` as the LBI | yes | yes |
| RAT Type hardcoded to literal `6`, twice | yes | yes |
| Indication `[0x00, 0x08, 0x00]` leaves OI unset | confirmed against §8.12: the bit is in the second content octet | yes |
| `GtpCause::from` collapses 66, 68, 73, 74-78, 94 to `Reserved` | yes — twelve values | yes |
| `esm_cause_from_gtp` omits 78 | yes | yes |
| hand-rolled `GtpBuffer` duplicates the tested library codec | `s11_build.rs:229-344` | yes |
| Echo builders exist and are never called | yes; no path management at all | yes |
| `mme.gtpc` is unread by the config loader | `config.rs`'s module doc says so and names this issue | yes |

## Decision 1: mirror sgwcd's server rather than design a second one

The two are the two ends of the same interface. A second design would be two answers to
"how long may an S11 message take" and "when is a peer down", and the shared
`Gtp2XactMgr` — referenced only by sgwcd and never instantiated here, which is why mmed
had no T3-RESPONSE/N3-REQUESTS budget at all — is what makes them agree.

So `GtpcServer` is structurally sgwcd's: a bound `UdpSocket` with a 100 ms read timeout,
a receive thread, and a T3/N3 poll thread that also drives Echo because it already ticks.
Synchronous (OS threads, blocking socket) for the same reason sgwcd is: the NAS and S1AP
paths that originate these messages are synchronous, and putting an executor in front of
them is a far larger change than this issue.

**Not copied blindly.** sgwcd's restart-triggered context deletion is deliberately absent:
deleting this MME's UE contexts because the SGW restarted is a decision about subscriber
state that #51 does not own, and a Recovery counter changes on a reordered datagram too.
The restart is recorded and logged loudly instead.

## Decision 2: the process-wide server is a `OnceLock`, like the S6a queue

The twelve senders are called from synchronous NAS/S1AP code that threads no transport
handle. `fd_path` already solved this shape for the S6a request queue, so the S11 server
follows it rather than inventing a second convention. `None` means the socket was never
bound, and every send then **reports that** instead of returning `Ok` — which is the
whole defect being fixed, so a silent no-op would have reintroduced it one layer up.

## Decision 3: the restart counter is persisted

TS 23.007 §18 needs the counter to survive the restart it signals — a value that resets
to the same number every start tells a peer nothing changed. mmed now persists it exactly
as sgwcd does (`MME_RESTART_COUNTER_FILE`, atomic write-then-rename, `MME_RESTART_COUNTER`
override for tests). The first draft of this spec documented "nothing persists it" as a
known gap; that was the lazy answer when the sibling already had the code.

## Decision 4: the builders take the sequence number and the local address

Both were reached for rather than passed:

- The sequence number was a literal `0` in the builder, so the transport could not own
  correlation. It is now a parameter, allocated by `Gtp2XactMgr`.
- The Sender F-TEID's address was going to come from `mme_self()`. A builder that reads a
  process global cannot be exercised without one, and the sender already holds the context
  that knows it — so it is a parameter, and the sender prefers the **socket's own bound
  address** over configuration, because a mismatch sends the SGW's response somewhere
  nothing is listening.

## Decision 5: the Linked EPS Bearer ID and the RAT Type come from state

- **LBI**: the lowest EBI of the session, because `materialise_subscribed_sessions`
  allocates one default bearer per APN from the bottom of the range. A session with no
  bearers is an `Err` naming the session, not a fallback to `5` — TS 29.274 Table 7.2.9.1-1
  makes the IE mandatory and naming the wrong bearer tears down the wrong PDN connection.
- **RAT Type**: a new `MmeUe::rat_type`, defaulted to E-UTRAN at UE creation rather than
  left at `Default`'s `0`, which is a reserved value a conformant SGW would reject.
  **It only ever holds E-UTRAN today**, because S1 is the only access this MME has and no
  inter-RAT arrival exists (#62). The field is still the right structure — there is now one
  place that decides it — but this spec will not claim it is sourced from anything richer
  than "the access we have".

## Decision 6: the CSR refuses to build without a Bearer Context

TS 29.274 Table 7.2.1-1 makes it mandatory and sgwcd's parser `require()`s it. Building the
message anyway produces a request the peer must reject, which is strictly worse than an
error at the call site: the failure moves from this MME's log to a wire exchange and a
cause the operator has to correlate back. Same for the MBR without an eNB S1-U F-TEID —
sending that context would ask the SGW to switch the downlink tunnel to nowhere.

## Decision 7: a correlated response is applied; an uncorrelated one is not

`handle_datagram` matches the response against the transaction manager **before**
dispatching. An uncorrelated datagram is one this MME did not ask for, and letting it reach
the handler would allow a stray packet to mutate session state.

For a Create Session Response that correlates, the SGW's S11 control TEID and each
bearer's S1-U endpoint are written onto the context — the TEID because every later Modify
Bearer / Delete Session Request has to be addressed to it (parsed and dropped, the MME
could create a session and never modify or delete it), and the S1-U endpoint because it is
the downlink tunnel the eNB is given at Initial Context Setup. The session is found by the
**local TEID in the header**, not by anything in the body: that TEID is the one this MME
told the SGW to use, so it is the only field a malformed body cannot misattribute.

## Verification

Five new tests, each driving a **real bound socket** with its real receive and T3/N3
threads. A test that stubbed the transport would assert the half that already worked.

| claim | how it was made to fail | result |
|---|---|---|
| the CSR carries a Sender F-TEID | delete the `add_ie` | **fails** |
| …and a Bearer Context | skip `add_bearer_context` | **fails** |
| RAT Type comes from the UE context | encode a literal `0` | **fails** |
| the wire sequence is the allocated one | make `new_message` write `0` | **fails** |
| a response is correlated by sequence number | match on `seq + 1` | **fails** |
| T3-RESPONSE retransmits an unanswered request | drop the retransmit send | **fails** |
| an Echo Request is answered | short-circuit the Echo branch | **fails** |
| the restart counter advances across starts | pin `next` to 1 | **fails** |
| Indication sets OI | `indication.oi = false` | **fails** |
| every declared GTP cause is distinguishable | remove the `78` arm | **fails** |
| GTP 78 reaches the UE as ESM 27 | remove the mapping | **fails** |

Eleven reverts, eleven bites — **after three corrections, all of them mine and all worth
recording**:

- The first sequence-number revert **PASSED**: it changed the sequence *registered* with
  the transaction manager, not the one written to the wire. The test asserts the wire, so
  the patch never touched what was under test. Rewritten to patch `new_message`, it bites.
- The first correlation revert **DID NOT COMPILE** (`Ok(_) => None` left the `Option`'s type
  unresolvable), and the harness said so rather than reporting a pass.
- The two ESM-cause reverts reported `0 tests, 318 filtered out` — the harness's snapshot
  predated the tests it was reverting, so `restore()` deleted them before running. Caught
  only because the harness prints the test count; `UNCLEAR` plus a count is what made it
  visible, where a bare "did not fail" would have read as a decorative test.

Workspace: mmed 315 → 320 tests, whole workspace **6329 passed / 0 failed**,
`cargo clippy --workspace` 0, `cargo fmt --check` clean.

## Ceilings

- **The attach procedure still does not complete.** `nas_eps_send_attach_accept` has **no
  caller** — verified by grep, and `nas_dispatch.rs:801-803` says why. This PR makes the S11
  exchange real; wiring the Create Session Response into an Initial Context Setup plus an
  Attach Accept is #46's subject, and #46 was deliberately reordered *after* this one for
  exactly that reason (its criterion 4 asks for the GUTI IE to be emitted "in the normal
  flow", which the attach path cannot do while the accept is unreachable).
- **Criterion 3 is verified against a MIRRORED mandatory-IE list, not against sgwcd's
  parser.** `sgwcd` is a binary with no lib target, so its `require()` is unreachable from
  mmed's tests; the list is copied from `s11_parse.rs:85-120` with that cite, and it will
  not notice if sgwcd adds a requirement. Closing this properly needs lib targets on both
  daemons, which no criterion asks for.
- **Two decoders remain for one message.** The library decodes for correlation and Recovery;
  `s11_handler`'s own IE walk decodes for content. Criterion 7 names `s11_build.rs`'s
  *builder*, which is gone, so this is out of scope — but it is the same duplication #304
  and #306 argued against, and it is now load-bearing because the socket feeds it.
- **The dispatchers act on Create Session Response and Downlink Data Notification only.**
  Modify Bearer / Delete Session / Release Access Bearers responses are correlated, parsed
  and logged; nothing updates state from them, because what should change is bearer
  lifecycle that #46 and #48 own.
- **`rat_type` only ever holds E-UTRAN** (see Decision 5).
- **No restart-triggered context deletion** (see Decision 1).
- **No E2E.** Loopback datagrams between one bound socket and a stand-in peer in one
  process. A real mmed↔sgwcd exchange is #303, whose other blocker is #52.
