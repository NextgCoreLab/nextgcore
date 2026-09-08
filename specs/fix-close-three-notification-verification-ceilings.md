# Close the three notification verification ceilings from the 2026-09-08 five-PR run

Verified against `main` @ `4ec257a`. No issue number: this is the tracked follow-up the #90 / #96 / #98 specs
each recorded as a ceiling rather than papering over.

All three had the same shape — **a producer that is wired and type-checked while nothing observes its output
arriving** — which is the recorded "the helper is tested and the wiring is not, and the better the helper's
test the more convincing the illusion" pattern. They are closed in one change because the fix for each is the
same move (drive the real handler, read a stub consumer, then delete the call line and confirm the test
fails) and doing them together means writing the stub-consumer shape once.

## (a) `pcfd` #90 — the UE-policy delivery events

`handle_ue_policy_n1_notify` fires `SUCCESS_UE_POL_DEL_SP` / `UNSUCCESS_UE_POL_DEL_SP` on the terminal
outcomes. `tests/strict_peer_updp_result.rs` already drove that handler through amfd's **real**
`N1MessageNotify` builder, but only asserted the delivery *state* — the Npcf_EventExposure feed was invisible.

Three tests added to that file. Each creates the subscription through pcfd's **real SBI router**
(`POST /npcf-eventexposure/v1/subscriptions`), so the create path is part of what is proved, then drives the
same real handler and reads a stub consumer:

* a matching-PTI COMPLETE puts exactly one `SUCCESS_UE_POL_DEL_SP` report on the feed, carrying the
  association's SUPI and an RFC 3339 UTC `timeStamp`;
* a matching-PTI REJECT reports `UNSUCCESS_UE_POL_DEL_SP` — and **must not** carry `delivFailure`, because
  TS 29.522 `Failure` enumerates northbound delivery failures and a D.6.3 UE-side rejection is not one of
  them, so mapping it would misreport the reason;
* **the negative**, which is what makes the other two mean something: a wrong-PTI COMPLETE is a stale or
  duplicate command (TS 24.501 D.2.1.6) with the delivery still in flight, so it must report **nothing**.

### A race found and fixed while writing these

The first run failed with **four** notifications where one was expected, including the wrong event token. The
pcfd context is process-global and the delivery events fire from this very handler, so each test's firing was
POSTed to every test's subscription — including the three *pre-existing* tests in the file, one of which
fires `SUCCESS_UE_POL_DEL_SP` itself.

Fixed by taking `nextgcore_pcfd::test_support::CONTEXT_GUARD` in **all six** tests in the file — the three
new ones and the three that were already there, because they are producers too — and by deleting each new
subscription before releasing the guard so a later firing cannot be POSTed at a stub that has already
stopped. Confirmed with 8 consecutive clean runs of the file. The guard is poison-tolerant so one failing
test does not turn its siblings into misleading second failures.

## (b) `bsfd` #98 — the UE-binding notifications

`subscribe_register_deregister_delivers_notifications` proved the **PDU-session** pair end-to-end against a
stub callback. The **UE-binding** pair was wired and its SUPI/event matching covered, but no test saw a
`PCF_UE_BINDING_REGISTRATION` or `_DEREGISTRATION` arrive.

Mirrored for `/nbsf-management/v1/pcf-ue-bindings`. The load-bearing assertion is not that a notification
arrives — it is that it carries **`pcfForUeInfo` and not `pcfForPduSessInfos`**. `BsfEventNotification`
models the two binding kinds with different members, so using one for the other would tell a consumer the
wrong resource changed, and a test that only counted notifications would pass either way. The deregistration
half asserts the identity member is present too, so a consumer can tell *which* PCF binding went away.

A SUPI distinct from the PDU-session test's is used, so the two cannot cross-report through the
process-global context even when run concurrently.

## (c) `nsacfd` #96 — the two subscribe-time dispatches

The task named "the `immediateFlag` report and the immediate EAC notification". Re-checking what was already
covered mattered here, because the picture was better than the task recorded and the gap was narrower and
more specific:

| already covered | by |
|---|---|
| an EAC notification following a mode **transition** | `test_http_slice_ee_subscription_and_eac_notification` (observes a real receiver) |
| the mode-list construction and the first/repeat decision | `eac_mode_list_and_first_subscription_detection` (pure logic) |

What nothing observed was the two dispatches that happen **at subscribe time**, both via `tokio::spawn` and
so invisible to a test that checks only the `201`/`204`:

1. **the `immediateFlag` report** (TS 29.536 §5.3.2.2.2). The new test subscribes with
   `eventTrigger: REACHING_THRESHOLD`, `notifThreshold: 90` and **zero occupancy** — so the trigger gate
   would suppress the report. It arrives only because `immediateFlag` bypasses the gate, which is the whole
   point of §5.3.2.2.2 and cannot be seen from the 201. The `SACEventReport` shape is asserted
   (`eventFilter.sst`, `sliceStautsInfo.reachedNumUes`) so it cannot pass on a bare POST.
2. **the immediate EAC notification on a FIRST subscription** (§5.2.2.2.2), with the §6.1.6.2.4
   `eacModeList` map shape asserted — not the old `eacMode` scalar.

Both negatives are included: a subscription **without** `immediateFlag` reports nothing at subscribe time,
and a **repeat** EAC subscription from the same `nfId` is not re-notified (an AMF re-sends its
`eacNotificationUri` on every `NumOfUEsUpdate`, so re-notifying each time would flood it).

## Verification

Workspace: **5943 passed / 0 failed** across three consecutive runs (baseline 5938). The five added tests are
three in `pcfd` and one each in `bsfd` and `nsacfd` — the `nsacfd` one covers four claims (two positives and
their two negatives) in a single test because they share one receiver and the ordering between them is part of
what is asserted. `cargo clippy --workspace` and `cargo fmt --all -- --check` clean. Three runs because the
new tests bind ports and touch process-global state.

**Nine claims revert-verified — and for this change the reverts *are* the deliverable**, since the whole point
is that the observers can fail. Each producer was deleted or inverted and the observing test confirmed to fail:

| # | producer reverted | test that bit |
|---|---|---|
| 1 | `pcf_report_pc_event` call deleted | `a_delivered_ue_policy_reports_success_to_a_real_subscriber` |
| 2 | the `Rejected` arm mapped to `None` | `a_rejected_ue_policy_reports_unsuccess_to_a_real_subscriber` |
| 3 | the non-terminal arm made to report `SUCCESS` | `a_non_terminal_outcome_reports_nothing` |
| 4 | `spawn_bsf_notifications` for UE-binding registration deleted | `ue_binding_register_deregister_delivers_notifications` |
| 5 | `pcfForUeInfo` swapped for `pcfForPduSessInfos` | same |
| 6 | the `if immediate { … }` block deleted | `subscribe_time_dispatches_actually_arrive_at_the_consumer` |
| 7 | `immediate` forced to `true` | same (the negative half) |
| 8 | the first-subscription EAC dispatch deleted | same |
| 9 | `first` forced to `true` | same (the repeat negative) |

Each revert was checked for a unique anchor, for compiling, and for the named test actually running before
its result was trusted. Reverts 3, 7 and 9 are the *inverted* kind — they make the producer fire when it
should not — which is what proves the three negative assertions are load-bearing rather than satisfied by a
path that never arrives.

## Ceilings

* **The un-driveable middle is still elided in (a).** The NGAP uplink NAS path needs live SCTP, so the test
  builds the exact `N1MessageNotify` amfd's `forward_ul_updp_to_pcf` emits and feeds it to pcfd's real
  router. That was already true of the three pre-existing tests in the file; these three inherit it.
* **No test drives a real PCF/BSF/NSACF process**, only their real handlers in-process. A misconfigured
  listener or a callback URI that is wrong only in deployment stays out of reach.
* **`nsacfd`'s repeat-subscription negative is time-bounded** (a 600 ms drain) rather than proven for all
  time. A re-notification arriving later than that would be missed. Bounded windows are the only option for a
  "nothing happens" assertion about a spawned task; the window is generous relative to the loopback delivery
  the positive assertions measure in the same test.
