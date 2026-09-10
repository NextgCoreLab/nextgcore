# nextgcore #291 (smfd/amfd): return an EPS bearer identity when its session ends

Verified against `main` @ `eb3490e`.

#291 was split out of #117, which implemented both halves of EBI *assignment* and neither half of the
release. TS 29.518 §6.1.6.2.5, TS 24.301 §9.3.2.

## Verified against current main

| claim in the issue | site on `eb3490e` | still true? |
|---|---|---|
| `releasedEbiList` is implemented on the AMF side, release-before-assign | `namf_server.rs:1994`, order comment at `:1969` | yes |
| `assign_ebi_releases_before_it_assigns_so_a_freed_ebi_is_reusable` verifies it | `namf_server.rs` tests | yes |
| the SMF never sends one (`rg releasedEbiList src/bins/nextgcore-smfd/`) | nothing | yes |
| the assignable space is 5..=15, eleven per UE | `context.rs:2129` `EBI_ASSIGNABLE` | yes |
| `next_free_ebi` is lowest-free, so the space does not *look* exhausted early | `namf_server.rs:1953` | yes |
| `request_ebi` treats every failure as non-fatal, so the leak is silent | `eps_iwk.rs:103` | yes |
| `handle_sm_context_release` is where the sender belongs | `main.rs:4563` | yes |
| **"a dereg that drops the context already frees them"** | **NO — nothing drops the context** | **false** |

That last row is the finding that changed the shape of this fix, and the issue asked for exactly this
check ("worth *verifying* rather than assuming, because if the context is reused rather than dropped
the EBIs survive").

## The verification that mattered: the backstop did not exist

`amf_ue_remove` has **no production caller**. `grep` finds its definition, `amf_ue_remove_all` (context
teardown), and three test call sites — nothing else. `handle_deregistration_request_nas` releases the
PDU sessions, purges the UDM registration, answers the UE and calls `finish_deregistration`, which
drops the NAS state (`ue_auth_state`) and releases the NG UE context. The stored `AmfUe` — and every
`AssignedEbi` recorded on it — survives all of it.

So before this change the ONLY thing that could ever free an EBI was an SMF-side release that did not
exist. The leak was not bounded by the UE's registration lifetime as the issue hoped; it was bounded
by the AMF process lifetime.

## Decision 1: the AMF frees a UE's EBIs on deregistration — implemented, not just considered

The issue lists this as "consider whether". Given the finding above it is implemented, because
without it the SMF-side release is a single point of failure for an eleven-wide space: one lost
request leaks one identity forever. `release_all_ebis_on_deregistration` lives in `namf_server.rs`
beside `handle_assign_ebi`, so the rules about who owns the identity space stay in one module.

It is not an invention: TS 23.502 §4.2.2.3.2 has deregistration release every PDU session the UE has,
and an EPS bearer identity exists only to map one of those sessions into EPS. A UE with no sessions
holds no EBIs.

## Decision 2: the wiring point is `finish_deregistration`, not `gmm_handler`

`gmm_handler::handle_deregistration_request(&mut AmfUe, ..)` looks like the natural home — it already
takes the UE mutably. It has **no production caller**: `grep` finds its definition and its own test.
The NGAP path handles deregistration itself. Putting the backstop there would have produced a tested
change that never runs, which is the defect this repo keeps finding (#276's `create_dns_context`
shipped that way for a month).

`finish_deregistration` is the common tail of both deregistration directions (UE-initiated, and the
network-initiated one after the Accept), and it still holds `ue_auth_state` — which is where the SUPI
keying the stored `AmfUe` comes from. The call goes before `ue_auth_state.remove`, for that reason.

## Decision 3: a failed release is logged with the identity named, and NOT retried

The issue offers a bounded retry queue (like #111's in nefd) as the alternative. Logging wins, and
Decision 1 is what makes that sufficient rather than merely cheap:

- The session is going away either way, so the SMF cannot keep the teardown open waiting.
- A retry queue that survives what it needs to survive means durable state: a queue held in memory is
  lost by exactly the restart most likely to have dropped the request in the first place, and #191's
  snapshot does not model one. That is a bigger change than this issue, for a case the backstop covers.
- With the AMF freeing on deregistration, a lost release leaks one identity until the UE deregisters
  instead of forever. Eleven lost releases inside one registration would still exhaust the space, and
  the log names the identity and the consequence so the operator can see it happening.

## Decision 4: the disabled leg returns early, so `false` means "lost", not "not attempted"

Found by revert 2, not by reading. `release_ebi` returns `bool`, and with the leg off the shared
`post_assign_ebi` returned `None` — so the caller's log path named a LEAKED identity for a deployment
that cannot have one. `release_ebi` now checks `enabled()` first and returns quietly. The call site
ignores the bool either way; the value of the fix is that the log is a true statement.

## Acceptance criteria

- [x] Releasing a session whose binding carries an EBI sends an `assign-ebi` request with that EBI in
      `releasedEbiList`; asserted **over the wire from the release handler** —
      `releasing_a_session_returns_its_ebi_to_the_amf`.
- [x] Twelve sequential establish/release cycles for one UE keep succeeding; a test asserts the
      twelfth gets an EBI rather than a `403` —
      `twelve_establish_release_cycles_keep_getting_an_ebi_and_twelve_without_release_do_not`, which
      also pins the other direction (eleven unreleased sessions exhaust the space).
- [x] A failed release request does not fail the session release, and the leaked identity is named in
      the log — `a_failed_ebi_release_does_not_fail_the_session_release`.
- [x] Whether AMF deregistration frees `assigned_ebis` is verified and stated either way — it did
      **not**, and now does (Decisions 1 and 2).
- [x] With interworking disabled, the release path sends nothing —
      `a_disabled_interworking_leg_releases_no_ebi`.

## Verification

Workspace **6278 passed / 0 failed** over three consecutive runs (baseline 6272 on `eb3490e`; +6 —
smfd 456 → 459, amfd 433 → 436). `cargo clippy -p nextgcore-smfd -p nextgcore-amfd --all-targets`
clean; `cargo fmt --all -- --check` clean.

| revert | expected to break | result |
|---|---|---|
| the `release_ebi` call made unreachable in `handle_sm_context_release` | `releasing_a_session_returns_its_ebi_to_the_amf` | **1 failed** |
| a failed release made fatal to the session release | `a_failed_ebi_release_does_not_fail_the_session_release` | **2 failed** (and exposed Decision 4) |
| the dereg backstop call made unreachable in `finish_deregistration` | `deregistration_frees_the_ues_ebis_through_the_ngap_tail` | **1 failed** |
| the dereg clear not persisted (`amf_ue_update` dropped) | both dereg tests | **2 failed** |
| `handle_assign_ebi`'s `releasedEbiList` no longer frees (i.e. #117's release undone) | the twelve-cycle test + 2 existing | **3 failed** |

The last row is worth noting: the twelve-cycle test now guards #117's release path as well as this
change, so an AMF-side regression that silently stopped freeing would fail here rather than in a
deployment eleven session-lifetimes later.

## Ceilings

- **The release is asserted from the release handler; the ASSIGNMENT's call site still is not.** Every
  create test runs with the interworking leg off, so `request_ebi`'s call site in
  `handle_sm_context_create` is exercised only on its `None` arm. #289 gave the crate the UPF stand-in
  that makes closing this a test away rather than a harness away; it is not in this issue's criteria.
- **The twelve cycles are AMF-side.** They drive `assign-ebi` through the real router twelve times with
  a release between, which is what the SMF now sends — but no test drives both daemons in one process,
  so "the SMF's release makes the AMF's twelfth assignment succeed" is proven in two halves that meet
  at the wire format, not end to end. The docker E2E is where an end-to-end version would live.
- **`releasedEbiList` carries exactly one identity**, because this SMF authorises one default QoS flow
  per session (`request_ebi` asks for one ARP). A session with several flows would need the list to
  carry several, and nothing in the tree creates one.
- **Nothing frees an EBI when the AMF loses the UE without a deregistration** — an implicit
  detach/timeout path that drops `ue_auth_state` without running `finish_deregistration` would leave
  the identities held. The mobile-reachable and implicit-dereg timers are #72's scope.
