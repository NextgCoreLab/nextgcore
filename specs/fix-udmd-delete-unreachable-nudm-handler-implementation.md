# nextgcore #236 (udmd): delete the second, unreachable Nudm UECM/SDM/UEAU implementation

Verified against `main` @ `4ec257a`. Every claim in the issue's reference table still held exactly as
written — re-run of the `grep -rn '<fn>' --include='*.rs' src/ | grep -v nudm_handler.rs` count reproduced
seven zeros and two ones (`sess_sm.rs:261`, `:268`), and the line cites had not drifted.

`Closes #236`.

## The question the issue said to answer first

> Confirm whether the `sess_sm` / `udm_sm` session state machine is meant to be driven at all. If it is
> dead too, that is the larger finding and should be settled first — deleting the handlers while leaving a
> state machine that calls them is the wrong order.

**It is dead, and the proof is one grep: nothing in the tree constructs a `UdmEvent::sbi_server` or a
`UdmEvent::sbi_client`.** Both constructors exist (`event.rs:183`, `:203`) and have zero callers —
not in production code, not in tests. The chain that would reach the two surviving handlers is

```
UdmEventId::SbiServer  ->  udm_sm::handle_sbi_server_event   (udm_sm.rs:127)
                       ->  udm_sm::handle_nudm_request       (:234)
                       ->  udm_sm::handle_sess_request       (:351)
                       ->  sess_sm::dispatch                 (:399)
                       ->  nudm_handler::udm_nudm_uecm_handle_smf_registration
```

and its first link never fires. The only event the daemon ever dispatches is `UdmEvent::sbi_timer`, built
in `app.rs:3220` inside `run_event_loop_async` from an expired timer. So `UdmSmContext` *is* constructed
and initialised in production (`app.rs:333-334`), but its `ue_sms` and `sess_sms` maps are permanently
empty and only its timer branch is ever entered. The live Nudm surface is `app.rs::udm_sbi_route`
dispatching to `uecm.rs` and `app.rs`'s own handlers, exactly as the issue says.

That answer makes the deletion order safe: there is no live state machine to break.

It also means the *state machine itself* is the larger finding, and it is filed separately rather than
folded in here — see "Follow-up filed" below.

## What was removed

Nine handlers, each with a live counterpart already serving the same procedure:

| removed from `nudm_handler.rs` | live implementation |
|---|---|
| `udm_nudm_uecm_handle_amf_registration` | `uecm::process_amf_registration` (`uecm.rs:531`) |
| `udm_nudm_uecm_handle_amf_registration_update` | `uecm::process_amf_registration_update` (`:680`) |
| `udm_nudm_uecm_handle_amf_registration_get` | `uecm::process_amf_registration_get` (`:656`) |
| `udm_nudm_uecm_handle_smf_registration` | `uecm::process_smf_registration` (`:769`) |
| `udm_nudm_uecm_handle_smf_deregistration` | `uecm::process_smf_deregistration` (`:868`) |
| `udm_nudm_ueau_handle_result_confirmation_inform` | `app::handle_auth_event` (`app.rs:2949`) |
| `udm_nudm_sdm_handle_subscription_create` | `app.rs::handle_sdm_subscribe` (routed at `app.rs:804`) |
| `udm_nudm_sdm_handle_subscription_delete` | the `sdm-subscriptions` DELETE arm (`app.rs:805`) |
| `udm_nudm_sdm_handle_subscription_provisioned` | the `ue-context-in-smf-data` GET arm (`app.rs:817`) |

Plus everything that only fed them: the seven request structs
(`Amf3GppAccessRegistrationRequest`, `Amf3GppAccessRegistrationModificationRequest`, `GuamiRequest`,
`PlmnIdRequest`, `SmfRegistrationRequest`, `SdmSubscriptionRequest`, `AuthEventRequest`), the private
helpers `parse_amf_id` and `guami_matches`, and the two `HandlerResult` constructors nothing else used
(`created`, `not_found`) with `http_status::NOT_FOUND`.

`nudm_handler.rs` goes 1001 lines -> 186, and what is left is exactly what has a live caller:
`HandlerResult` / `http_status` (returned by `nudr_handler.rs`) and `hex_to_bytes` / `bytes_to_hex` (used
by `app.rs`, `sor.rs`, `upu.rs`, `nudr_handler.rs`).

### Two things found in passing, both beyond what the issue reported

**`buffer_to_u64` and `u64_to_buffer` had no caller at all, not even a dead one.** They were exercised
only by four of their own tests. They are the same class as the handlers but with a shorter blast radius,
and criterion 2 ("whatever remains has a live caller") covers them, so they went too.

**The `ue-context-in-smf-data` pair is the one place where the dead copy was the *more* dishonest of the
two.** `udm_nudm_sdm_handle_subscription_provisioned` returned `HandlerResult::ok()` with the body
comment "In real implementation, this would return actual SMF context data" — i.e. it answered success
while producing nothing. The live route answers 501. Deleting the dead one removes a fabricated success,
not a capability. (The resource itself is one of the absent SDM data sets tracked by #226; this change
does not touch that.)

## `sess_sm.rs`: the two call sites, and why they were not repointed

The issue's step 2 offers "point its two call sites at `uecm::process_smf_registration` /
`process_smf_deregistration` so there is one implementation". **Deliberately not done**, because the
state machine is unreachable: repointing dead code at the live functions would give
`uecm::process_smf_registration` an apparent second caller and make the state-machine path read as
integrated when nothing drives it. Naming the live implementation in a doc comment carries the same
information without the false call graph.

Instead the two arms got the treatment `ue_sm.rs` already carries from the earlier `udmd-04` pass — the
handler call removed, the structure kept, a doc comment saying the live HTTP dispatcher owns the
procedure. `sess_sm.rs` is simply the file that pass missed; `ue_sm.rs:228-273` and `:333` are the
precedent this now matches.

Two details recorded in those comments because they say something about the code that was there:

* the `PUT` arm built a **default-constructed** `SmfRegistrationRequest` under the comment "In
  production, parse SmfRegistrationRequest from HTTP body". The parsing was never written, so had the arm
  ever been reached it would have registered an SMF with no instance id, no PSI, no S-NSSAI and no DNN —
  and `udm_nudm_uecm_handle_smf_registration` would have rejected its own caller with
  `400 No smfInstanceId`.
* `handle_nudr_dr_response` hardcoded the HTTP method to `"PUT"` and the status to `204` rather than
  reading either from the response it was dispatched for, so it could only ever report one outcome.

## Verification

Workspace: **5931 passed / 0 failed** over two consecutive clean full runs, against a `main` baseline of
**5938 / 0** taken on this branch before any edit. The difference is exactly the seven deleted tests
(`test_handler_result_created`, `test_parse_amf_id`, `test_guami_matches`, `test_buffer_to_u64`,
`test_u64_to_buffer`, `test_buffer_to_u64_conversion`, `test_u64_to_buffer_roundtrip`), each of which
tested a symbol this change removes. `cargo clippy --workspace` and `cargo fmt --all -- --check` clean.

### A pre-existing flake was hit on the way, and it is written down rather than dismissed

The **first** whole-workspace run failed with two failures in `nextgcore-sgwud`
(`gtp_path::tests::path_fails_only_after_exceeding_n3_requests` and `::path_state_is_per_peer`) — a crate
this change does not touch. Recorded rather than waved away, because the rule here is to treat a failure
in an untouched crate as a real signal until proven otherwise, and to write down any dismissal.

It is proven unrelated two ways: `bins/nextgcore-sgwud/Cargo.toml` declares no dependency on
`nextgcore-udmd`, so the `sgwud` test binary is identical to `main`'s; and the pair reproduces on its own
at ~40% (5 failures in 12 runs of `cargo test -p nextgcore-sgwud gtp_path`).

Root-caused to two independent process-global races, both in `gtp_path.rs`:

* **the env var.** `n3_requests()` (`:362`) reads `SGWU_GTPU_N3_REQUESTS` on every call, and three
  concurrent tests set it to *different* values — `"3"` at `:1257`, `"1"` at `:1283`, `"1"` at `:1308` —
  each removing it at the end. A sibling flipping it to `1` makes the `N3=3` test's second probe exceed the
  threshold. The resulting message, "2 unanswered must not yet be a failure with N3=3", reads exactly like
  the off-by-one TS 23.007 §20.3.1 defect the test exists to pin, which is the recorded hazard of a harness
  failure wearing the shape of the bug it guards.
* **the whole-map assertion.** `failed_gtpu_paths()` (`:434`) returns every failed peer in the
  process-global `GTPU_PATHS` map (`:345`), so `assert_eq!(failed_gtpu_paths(), vec![dead])` (`:1316`, and
  the same shape at `:1270`) holds only while no other test has a failed path. The observed
  `left: [10.61.0.1, 10.61.0.3]` is the other test's peer leaking in. Distinct peers do not help; the
  shared *view* is the problem.

The fix is the guard pattern this repo already uses (`pind/src/main.rs:970`, `easdfd/src/main.rs:690`,
`eesd/src/auth.rs:81`, `udmd`'s `test_support::CONTEXT_GUARD`) plus peer-scoped assertions instead of
whole-map equality. Deliberately **not** done here: it is another crate and another defect, and folding it
into a udmd deletion would make this diff unreviewable against #236. It has no tracker item yet.

**On revert-verification.** This change adds no behaviour, so there is no behavioural claim to make a
test fail against — the recorded rule is about guards for new behaviour, and inventing a guard for a
deletion would be the decorative-test failure mode the project already records. What stands in for it
here is stronger than a test: *the compiler*. Every claim of the form "X had no caller" is falsified at
build time if it is wrong, and `cargo check -p nextgcore-udmd --all-targets` plus the whole-workspace
build are the check. The one claim the compiler cannot make is "and no caller reaches it at runtime
either", which is what the `UdmEvent::sbi_server`-has-no-constructor grep answers instead.

## Ceiling

`sess_sm.rs`'s two remaining stubs, and `ue_sm.rs`'s three, are unreachable and stay that way. This
change does not make the state machine reachable, does not delete it, and does not test it beyond the
four existing state-transition tests it already had. That is the follow-up's job.

## Follow-up filed: #242

**The state-machine trio's whole SBI half is unreachable, and `udmd`'s `nudr_handler.rs` is dead behind
it.** All five public functions of `bins/nextgcore-udmd/src/nudr_handler.rs` now have zero external
callers: four already did before this change, and the fifth
(`udm_nudr_dr_handle_smf_registration`) was reached only from the `sess_sm.rs` arm this change strips.
That is ~1000 more lines of the same class as #233 / #234 / #236, but deleting it belongs with the
decision about the state machine that referenced it — settling one without the other repeats the
wrong-order mistake #236 warned about. Filed as its own issue rather than expanded into this PR, so the
diff stays reviewable against the issue that asked for it. Note `udrd` and `pcfd` have their own,
*live* `nudr_handler` modules; this is a `udmd`-only finding.
