# fix(amfd): the unwired 5GMM NAS procedures — UCU/T3555, the §4.4.4.3 exceptions, ngKSI, emergency, the reachability timers and T3346

Closes #72; splits its criteria 4–6 to #352, which #72's own suggested approach asks for
("Recommend splitting into independently mergeable workstreams", and it names the inter-AMF
piece as "the most architectural").

## What was already done before this PR

**Criterion 10 (T3512 from configuration) was already met.** #72 says "T3512 is hardcoded to
9 minutes (`gmm_build.rs:343`, `:412-430`)". On main, `build_registration_accept` reads
`context.t3512_value` — applied from `amf.time.t3512.value` — through
`encode_gprs_timer3_seconds`, which picks the coarsest exact GPRS-Timer-3 unit and refuses
rather than rounds. Verified before starting, so no work was done for it.

Every other criterion's cite had drifted 200–300 lines but was still substantively open.

## Criterion 7 — ngKSI selection

`nas_ksi` was forced to 0 immediately before building the Authentication Request, so the AMF
always advertised key set identifier 0. The collision this causes is not exotic: 0 is the
value the AMF hands out first, so it is the value a re-authenticating UE is most likely to
already hold.

`select_ngksi(ue_ksi)` returns `(ue_ksi + 1) % 7`, and 0 when the UE reported 7 ("no key
available", which is not a key set and so is never *selected*). Asserted over the whole
input domain rather than at a sample, because the property is "different from what the UE
reported" and the interesting inputs are the two boundaries.

`nas_tsc` stays 0 and is now documented as such: this is a **native** 5G context, not one
mapped from EPS (TS 24.501 §9.11.3.32).

## Criterion 3 — the integrity-check-failure exceptions (§4.4.4.3)

The discard sat *after* the security context had been resolved, under a comment asserting
that the exceptions were "handled before security establishment". They were not: a MAC-failed
mobility REGISTRATION REQUEST or SERVICE REQUEST on an existing context reached that discard,
which is the one thing §4.4.4.3 says must not happen to them.

The decision is now a pure function, `integrity_failure_action(msg_type, has_context)`,
separate from the handler — because that mapping *is* the conformance requirement, and pulling
it out lets it be asserted over its whole domain instead of by driving one message through a
server:

| message | action | why the alternative is worse |
|---|---|---|
| REGISTRATION REQUEST on an existing context | re-authenticate | a UE whose context has diverged can only ever produce a failing MAC, so discarding leaves it permanently unable to register. Nothing from the message is applied; the UE must pass a fresh authentication first. |
| SERVICE REQUEST on an existing context | SERVICE REJECT #9, plain | tells the UE to register again rather than keep asking for service on a context the network cannot verify. Plain because the context that would protect it is the one that failed. |
| anything else | discard | corruption or an attacker; acting on it is what integrity protection exists to prevent. |

`has_context` is part of the mapping: without a security context there is nothing the check
could have failed against, so even the excepted types are discarded.

## Criteria 1 and 2 — UE Configuration Update and T3555

The live procedure is **5G-GUTI reallocation after a Service Request** (TS 33.501 §6.12.3),
which is the moment that matters for identity privacy: the UE has just used the identity it
was paged with. NAS-based reallocation *is* the UE Configuration Update procedure, which is
why this is the caller criterion 1 asks for.

- `T3555` joins `NasProcTimer`, so it inherits the existing arm/retransmit/abort machinery
  rather than growing a second timer path.
- A `0x55` CONFIGURATION UPDATE COMPLETE arm stops T3555 and commits the new GUTI. Before
  this the type had no arm at all, so a conformant UE's acknowledgement was logged as
  "Unhandled 5GMM message type 0x55" and the command was retransmitted four more times.
- The abort keeps the **old** GUTI: the UE never acknowledged, so it is still addressable by
  the identity it has. TS 24.501 §5.4.4.3's fuller answer — both GUTIs valid, because the
  COMPLETE may merely have been lost — needs a GUTI-indexed lookup to act on, which is #352.
  Recorded in a comment at the arm, and in #352's "what #72 left ready for it".
- Off unless `AMF_GUTI_REALLOCATION` is set. #72 asks for exactly this ("each can ship behind
  an off-default gate until wired end-to-end"), and a runtime switch rather than a cargo
  feature keeps both states inside `cargo test --workspace`, which is the CI gate.

**One line is not covered by a test, and here is which.** `arm_retx` runs after
`send_nas_pdu(...)?`, so arming requires a PDU that reached the transport, and the unit-test
server deliberately has no gNB association. The revert-verify pass caught this: deleting the
arm failed nothing. The response was to split the procedure into
`build_guti_reallocation_command` (asserted on its bytes: message type, the acknowledgement
request, the 5G-GUTI IE) and a thin send-and-arm, so everything except that one line is
covered, and to say so here rather than imply otherwise. The E2E path is what would cover it.

## Criterion 8 — emergency

`handle_emergency_registration` had no caller outside its own unit tests, so an EMERGENCY
registration was processed as an ordinary one. The registration path now routes it, and the
`EmergencyHandler` lives on the NGAP server so there is somewhere to record the context.

No new "is emergency" flag: `AmfUe.registration_type` is assigned from the same request a few
lines further on and already carries the answer — it is how `nas_security::nia0_permitted`
reads it. A second field would be a copy that can disagree.

The branch falls through to the normal flow deliberately: authentication, security mode and
Registration Accept are the same procedure. What differs is that the emergency context now
exists, so the emergency DNN / P-CSCF are available to the session that follows.

Found while wiring it: `EmergencyHandler` keys contexts by `u32` while the AMF UE NGAP ID is
40 bits, so the call site truncates. Filed as **#353** with the collision's consequences
rather than widened here.

## Criterion 9 — the reachability timers

`MobileReachable` and `ImplicitDeregistration` had enum variants, no `TimerConfig`, and
`AmfTimerConfigs::get` fell through to `None` for both — so nothing could start them.

- Both get a `TimerConfig`, and `with_reachability_from(t3512_secs)` derives them from the
  **configured** T3512 with `AMF_MOBILE_REACHABLE_SECS` / `AMF_IMPLICIT_DEREG_SECS` as
  overrides. The default is T3512 + 4 min, which is the relationship TS 24.501 §5.3.7
  describes: a UE registering periodically must not be found unreachable merely because its
  next registration has not fallen due.
- `0` **disables** a timer. Treating 0 as "expire immediately" would implicitly deregister
  every UE the moment it went idle.
- The live sequence is modelled as one deadline plus a phase (`ReachabilityPhase`), so
  "mobile-reachable, then implicit-dereg, never both" is structural rather than an invariant
  two independent timers have to maintain. Started on UE Context Release Complete — the moment
  the N1 connection is gone — and driven from the same poll as the retransmission timers, so
  there is one clock in this path.
- Implicit deregistration removes the NAS state *and* the global context's RAN-UE/AMF-UE
  entries, or it would free one and leave the other holding an id.

## Criterion 11 — T3346 and 5GMM cause #22

`build_registration_reject`/`build_service_reject` emitted `t3346_value: None`, so the AMF had
no NAS-level overload defence at all: every refused UE came straight back.

- `encode_gprs_timer2_seconds` mirrors the existing Timer-3 encoder's policy exactly —
  coarsest exact unit, `None` rather than a rounded value — because a UE told to wait the
  *wrong* time acts on it with full confidence.
- `*_with_backoff` builders carry it; the originals delegate with `None`, so no existing
  caller changed. Attaching a back-off to a non-congestion cause logs a warning: a UE handed
  both "illegal UE" and "come back in 60 s" has been told two contradictory things.
- The posture lives in a new `congestion` module: occupancy against
  `AMF_NAS_CONGESTION_THRESHOLD` (0 = never, the default) or an operator declaration via
  `AMF_NAS_CONGESTION`. **EMERGENCY registrations are exempt**, which is why the check sits at
  the top of the registration path rather than at the reject sites — §5.3.5 forbids shedding
  emergency services, and that must not depend on which reject site is reached.
- `send_overload_start` / `send_overload_stop` get their **first production caller**: both were
  `pub async fn` with no callers anywhere, so the AMF could declare congestion to a UE while
  telling the RAN nothing. Sent on transitions only, so a sustained overload does not
  re-broadcast on every poll.

Per-UE jitter on the back-off is deliberately absent and documented in the module: TS 24.008
§10.5.7.4a's spread-the-retries guidance is a fairness design choice, not a conformance
requirement, and it makes the value untestable without injecting a seed.

## Tests

+22 workspace tests. Every behaviour revert-verified against its own named assertion:

| revert | fails with |
|---|---|
| ngKSI back to a forced 0 | "ngKSI 0 collides with the UE's 0" |
| the §4.4.4.3 mapping back to a blanket discard | "the SERVICE REJECT branch must attempt a send" |
| the `0x55` arm removed (back to the catch-all) | "the COMPLETE must stop T3555" |
| the UCU omits the acknowledgement request | "acknowledgement must be requested: `[7e, 00, 54, 77, …]`" |
| the UCU omits the 5G-GUTI | "the new 5G-GUTI must be carried: `[7e, 00, 54, d1]`" |
| the emergency branch removed | 2 tests, incl. the congestion-exemption one |
| `ImplicitDeregistration` dropped from `get` | "mobile-reachable expiry must START the implicit deregistration timer" |
| the reject back to `t3346_value: None` | "the T3346 IE must be present" |

Two test-hygiene notes, both from this repo's own recent history:

- My first attempt appended the new tests **after** the last `}` of `ngap_path.rs`, which put
  them inside `#[cfg(all(test, feature = "ntn"))] mod ntn_retx_tests` — so `cargo test` never
  compiled them and every revert "passed". Moved into the real `mod tests`. This is the same
  hazard as a feature-gated code path shipping unexercised, one level up.
- The congestion posture is process-global, so its test lock is declared **beside it** in
  `congestion.rs` as `pub(crate)`, and `ngap_path`'s test takes that same lock. A lock private
  to `congestion.rs`'s `mod tests` could not order against a test in another module — which is
  precisely the defect #346 fixed in nssfd.

Workspace **6581 passed, 0 failed** (main: 6559). `cargo clippy --workspace` 0 errors,
`cargo fmt --all --check` clean.
