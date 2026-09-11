# nextgcore #46 (mmed): attach/TAU accept correctness

Verified against `main` @ `ce8a56a` (i.e. after #51). TS 24.301 §5.4.1, §5.5.1.3.4.3,
§5.5.3.2.4, §9.9.2.1, §9.9.3.10, §9.9.3.11, §9.9.3.12, §9.9.3.16, §9.9.3.44, §9.9.3.45;
TS 29.272 §7.3.1, §7.3.134; TS 23.401 §4.3.17.3, §5.3.2.1.

**Two of the eight criteria were already done**, by work that landed after #46 was filed.
The other six were exactly as described.

## Verified against current main

| criterion | site | still true? |
|---|---|---|
| 1. ULA APN configs persisted as `MmeSess` + `MmeBearer` | `materialise_subscribed_sessions` exists, is called from `fd_path.rs:1261`, and is tested | **already done** |
| 2. `process_apn_configurations` uses the UE context, no `_mme_ue` | takes `mme_ue`, fills `mme_ue.session` | **already done** |
| 3. `MmeUe` carries the subscribed RAU/TAU timer; T3412 from it | no such field; `nas_path.rs:260`/`:599` hardcode 3600; `s6a_handler.rs:160` is a comment saying the field "would need to be added" | yes |
| 4. production GUTI/M-TMSI allocator | nothing writes `next.m_tmsi`; `nas_dispatch.rs:191` says so and names this issue | yes |
| 5. `build_guti_reallocation_command` + a 0x51 handler | enum values only; 0x51 shared a match arm with TAU Complete and committed nothing | yes |
| 6. attach result from the attach type; emergency branch | `emm_build.rs:413` writes the literal `AttachType::EpsAttach`; no emergency path | yes |
| 7. TAU update result from the TAU type/SGs; bearer status populated | `0x00` hardcoded; the caller always passed `0` | yes |
| 8. the four unit tests | criterion 1's persistence test exists but asserts only APN/EBI/QCI — not ARP or APN-AMBR | partly |

## Decision 0: #46 was reordered to run AFTER #51, because of a dead function

Criterion 4 asks for the GUTI IE to be emitted "in the normal (non-test) flow". While
verifying, `nas_eps_send_attach_accept` turned out to have **no caller at all** — grep
confirmed it, and `nas_dispatch.rs:801-803` explained why: bearers are established over
S11, which did not exist. Implementing criterion 4's attach half against a dead function
would have been a correct fix in an unreachable place.

So this issue was parked, #51 was implemented first, and this spec is written against a
tree where the S11 exchange is real. The attach accept still has no caller — that is
#51's stated ceiling and is not #46's to close — so criterion 4 is satisfied **via the
TAU path**, which is reachable (`nas_dispatch.rs` sends a TAU Accept today), and the
attach path allocates the GUTI at Attach Request so it is staged whenever the accept
becomes sendable. The spec says which is which rather than implying both.

## Decision 1: the subscription wins, then configuration, then the old default

`t3412_from(subscribed, configured)` is a **pure** function so the ordering is testable:
`mme_self().time` is a plain field set at construction, so a test cannot vary the
configured value, and the precedence is the part worth pinning.

A deployment that configures nothing and a subscription that states nothing get 3600 —
the value that used to be hardcoded — so nothing changes for anyone who was relying on
it. A subscription with no timer leaves the field at `0` rather than overwriting a
previous value, which is what keeps the configured fallback reachable.

## Decision 2: a GUTI is STAGED, then committed when the UE acknowledges

`allocate_guti` writes `next`; `commit_staged_guti` promotes it to `current`. The split
matters in both directions:

- Promoting early would make `mme_ue_find_by_s_tmsi` match a UE on an identity it has not
  been told about.
- Never promoting — which is what happened before, since nothing allocated *or* committed
  — leaves that lookup permanently dormant, so every returning UE must re-identify by
  IMSI. That is the confidentiality the GUTI exists to provide, lost at the first mobility
  event.

The M-TMSI comes from a **process-global** counter, checked against the pool: it is the
key `mme_ue_find_by_s_tmsi` looks up by, so a duplicate makes one UE unreachable and
resolves the other to the wrong context. `0` is never issued, because `TmsiInfo::m_tmsi`
uses `None`/zero for "no GUTI allocated" and handing one out would produce a UE holding a
GUTI the accept builder refuses to emit.

With no served GUMMEI configured, allocation **refuses** rather than inventing an identity
no eNB could route.

## Decision 3: a combined attach without an SGs association is refused with a reason

TS 24.301 §5.5.1.3.4.3 is explicit: answer "EPS only" **and** set EMM cause #18 "CS domain
not available". A hardcoded EPS-only result told the UE the network declined without
saying why, so it had no reason to attach to the CS domain over another access.

Whether an SGs association exists is tested with `mme_ue.csmap_id` — the same test the
Extended Service Request path already uses to refuse CS fallback, so this is the tree's
existing notion of "is there a VLR" rather than a new one. The same test decides the EPS
update result, where reporting "combined TA/LA updated" without a VLR would tell the UE it
is reachable for CS services it cannot receive.

ISR (update results 4 and 5) is deliberately never signalled: it needs an S3/S4 SGSN
association this MME does not have.

## Decision 4: the emergency branch recognises and records, and says what it does not do

TS 24.301 §9.9.3.11 attach type 3 is now recognised and recorded on the context, and
§9.9.3.10's result is correct for it (there are two results and three types, so an
emergency attach is an EPS-only attach).

**What it does not do, stated because the difference matters:** emergency bearer services
are not implemented. §5.5.1.3 lets an emergency attach proceed for an unauthenticated or
unsubscribed UE with EIA0/NIA0 and an emergency APN, and none of that exists here — so an
emergency attach still follows the normal authentication and subscription path and will
fail wherever that fails. The flag makes the case visible instead of silently
indistinguishable, and it logs at `warn` saying exactly this. Claiming more would be the
dishonest option; implementing §5.5.1.3 properly is a separate piece of work.

## Decision 5: the 0x51 arm is split from TAU Complete

They shared one match arm, and neither committed anything — sharing the arm is what hid
that. Now each says what it does, and a GUTI Reallocation Complete with nothing staged is
a `warn` naming the disagreement ("the UE acknowledged an identity this MME did not
allocate") rather than a silent no-op.

## Verification

| claim | how it was made to fail | result |
|---|---|---|
| the subscribed RAU/TAU timer is recorded from the ULA | delete the assignment | **fails** |
| the subscribed APN-AMBR reaches the session | drop `sess.ambr = …` | **fails** |
| the subscribed ARP reaches the bearer | drop `bearer.qos = …` | **fails** |
| T3412 is encoded from the value given | encode 3600 regardless | **fails** |
| the subscription outranks configuration | drop the `subscribed > 0` branch | **fails** |
| a combined attach with a VLR yields a combined result | return EPS-only | **fails** |
| a combined attach without one carries EMM cause #18 | suppress the cause IE | **fails** |
| the EPS update result follows the TAU type and the VLR | write `0x00` | **fails** |
| the bearer-status bitmap sets a bit per active EBI | drop the `|=` | **fails** |
| a GUTI is staged, not committed, until acknowledged | drop the promotion | **fails** |
| M-TMSIs are unique | return a constant | **fails** |
| the reallocation command carries the staged GUTI | write `0` for the M-TMSI | **fails** |
| 0x51 commits the staged GUTI | short-circuit the commit | **fails** |

Thirteen reverts, thirteen bites — after **one correction**: the "T3412 prefers the
subscription" revert first reported PASSED because I pointed it at the S6a population test
rather than at a test of the precedence, and no test of the precedence existed. That is
what prompted splitting `t3412_from` out as a pure function; the claim had been written and
not verified.

One test failure was mine and not the code's: the GUTI-reallocation test read the M-TMSI at
`msg[9]` when §9.9.3.12's content layout (0xf6, PLMN×3, group id×2, code, M-TMSI×4) puts it
at `msg[10]`. The builder was right.

mmed 320 → 338 tests. Workspace **6347 passed / 0 failed**, `clippy --workspace` 0,
`fmt --check` clean.

## Ceilings

- **The attach accept still has no caller.** Criterion 4's "GUTI IE emitted in the normal
  flow" is satisfied through the **TAU** path only; the attach path stages the GUTI at
  Attach Request so it is ready, but the accept that would carry it is unreachable until
  something drives Initial Context Setup from a Create Session Response. That is #51's
  recorded ceiling.
- **Emergency attach is recognised, not implemented** (Decision 4). This is the one
  criterion where the letter is met and the spirit is bounded, and the code says so at
  `warn` on every emergency attach.
- **The configured-T3412 branch is untested against a real context**, because
  `mme_self().time` is set at construction and cannot be varied from a test. The precedence
  is tested purely; the wiring from `mme.time.t3412` into it is read, not exercised.
- **The SGs outcome is "is there a CS map", not "did the location update succeed".**
  `handle_location_update_accept` and `build_location_update_request` have only test
  callers, so mmed never actually performs an SGs location update — there is no outcome to
  consult. `csmap_id` is the strongest signal that exists today and is what the CSFB path
  already uses; a real outcome needs the SGs procedure to be driven, which no criterion
  here asks for.
- **No GUTI reallocation is ever *initiated*.** The command builder and the 0x51 handler
  exist and are tested, but nothing decides to rotate a GUTI outside an attach or a TAU —
  §5.4.1's standalone procedure has the machinery and no trigger.
- **`eps_bearer_context_status` reports what the caller passes.** The TAU path now passes
  the UE's real bearers; the attach path has no caller to pass anything.
