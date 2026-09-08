# Fix nsacfd Slice-EE: subscription modify, report triggers, immediate EAC, typed service

Closes nextgcore #96. Cites re-located against `main` at `c353f09`.

## 1. Subscription modification (criteria 1–2)

`PATCH` and `PUT` on `/nnsacf-slice-ee/v1/subscriptions/{id}` both fell through to
`send_method_not_allowed` → 405, so a consumer had to delete and re-create to
change anything.

- **PATCH is RFC 6902 JSON Patch**, `application/json-patch+json`, per the
  OpenAPI's `PartialModifySubscription` — *not* an RFC 7396 merge-patch, which is
  what the issue's "JSON-merge/JSON-patch style" left open. The wrong media type
  is refused with 415 rather than applied as something else.
- Applied to a **clone** of the reconstructed document and committed only if the
  result still validates, so a patch that removes a mandatory member is rejected
  without leaving a half-modified subscription.
- **PUT** replaces the whole `SACEventSubscription`.
- Neither resets `report_count`, `over_threshold` or `last_report_at`: a
  modification is not a new subscription, so a consumer cannot refresh its
  `maxReports` budget by patching.
- An unknown `{id}` is 404 on both verbs.

`validate_subscription_doc` and `build_subscription` were factored out of the
create handler so PUT replaces through **exactly the same parse** as create. Two
parsers would be two places for a trigger field to be forgotten, which is how all
six came to be dropped in the first place.

## 2. Report triggers (criteria 3–5)

The trigger fields were never read and `spawn_event_reports` fanned out a report
to **every** matching subscriber on **every** admit/release.

**Where each field lives matters, and the issue lists them together:**
`eventTrigger`, `notifThreshold`, `notificationPeriod` and `immediateFlag` are on
the nested `event` (`SACEvent`); `notifyCorrelationId`, `maxReports` and `expiry`
are on the **top-level** `SACEventSubscription`. Reading them all from one object
would have silently found none.

- **`THRESHOLD` is edge-triggered**, not level-triggered: a report goes out when
  occupancy *crosses* `notifThreshold`, and the edge re-arms when it falls back
  below. Sub-threshold churn is silent and a sustained over-threshold condition
  reports once rather than on every admit. **Any** single met `SACInfo` member
  crosses, so a consumer that sets two is not silenced by requiring both.
- **`PERIODIC`** is paced by `notificationPeriod`; with no period it reports per
  event, since it cannot be paced.
- A `THRESHOLD` trigger with **no** threshold degenerates to report-each-change —
  the honest reading of "the consumer asked for THRESHOLD but gave none", rather
  than silently never reporting.
- An **unrecognised** trigger token is edge-triggered, not rejected:
  `SACEventTrigger` is an `anyOf` over the enum plus a free-form string.
- **`maxReports` and `expiry` are terminal**: `ReportDecision::Exhausted` means
  *remove the subscription*, not "not now". Distinguishing that from `Suppress` is
  the point of the three-way enum.
- **`notifyCorrelationId`** is echoed when the consumer set one, absent when not.
- **`immediateFlag`** sends exactly one report to that **named** subscription at
  subscribe time, bypassing the trigger — the consumer asked for the current state
  rather than for a change. Other matching subscriptions are untouched by a
  subscribe.

`report_decision` is a **pure function** so the periodic case is observable
without sleeping and the threshold edge without driving admissions — the two
properties a notification-count test cannot separate.

Bookkeeping is one method (`subscription_note_report`) rather than three, so a
caller cannot charge the report and forget the edge, which would make a sustained
condition report on every admit. The suppressed path calls
`subscription_note_threshold` to re-arm **without** charging, or a level that fell
back below the threshold would never re-arm and the next crossing would be silent.
Both happen **before** the spawned send: a burst of admits would otherwise each
pass the `maxReports` check before any of them incremented the counter.

## 3. Immediate EAC notification (criterion 6)

`eac_subscription_set` registered the callback and sent nothing, so a consumer did
not learn the current EAC mode until the next **transition** — for a stable slice,
never. Per TS 29.536 §5.2.2.2.2 the NSACF now immediately POSTs an
`EacNotification` carrying the current mode of **every** NSAC-subject slice ("the
most recent EAC Modes for the subscribed S-NSSAIs"), not only the one that most
recently transitioned.

Only on the **first** subscription: an AMF that re-sends `eacNotificationUri` on
every `NumOfUEsUpdate` must not be re-notified each time, which is why
`eac_subscription_exists` was added. With no slice quotas configured nothing is
sent — an empty `eacModeList` would assert "no slices" rather than "nothing
configured yet".

## 4. Typed service and NF profile (criteria 7–8)

- `SbiServiceType::NnsacfSliceEe` added, so a consumer can select the exposure
  service by type. Only `NnsacfNsac` existed.
- Both services now carry **per-service `allowedNfTypes`**: `nnsacf-nsac` to
  `[AMF, SMF, SCP]`, `nnsacf-slice-ee` to `[NEF, NWDAF, AF, DCCF, SCP]`. **AF and
  DCCF were missing** and TS 29.536 §5.3.2.2.2 names both as legitimate Slice-EE
  consumers, so the NRF would not issue either a token scoped to the service. The
  NF-level list is the union.
- Service names come from the typed enum rather than string literals, so the
  registered name cannot drift from the one consumers select by.
- `apiFullVersion` is one named constant `NSACF_API_FULL_VERSION = "1.3.0"`,
  matching both vendored OpenAPI documents' `info.version` (`1.3.0-alpha.1`). It
  was a hardcoded `1.1.0` **on both services**, telling the NRF this NSACF
  implements an older revision than the contract it is built against.

## 5. Shared RFC 6902 engine

PATCH needs a JSON Patch applier. One already existed as a private module in
`nextgcore-nssfd`; rather than make a second hand-rolled RFC 6902 implementation —
two places for one pointer- or escaping bug to live — it was **moved** to
`nextgcore_sbi::json_patch` and nssfd's two call sites repointed. Both
TS 29.531 Nnssf_NSSAIAvailability and TS 29.536 `PartialModifySubscription` use it.

## Verification

- Workspace: **5933 tests pass, 0 fail**, across **three consecutive full-suite
  runs**; `cargo clippy --workspace` clean; `cargo fmt --all --check` clean.
- **18 behavioural claims individually revert-verified.**
- Four reverts did not bite first time. Two were **real coverage gaps**: removing
  the PATCH and PUT *route arms* left the modify test green, because it called the
  handlers directly — the recorded "the helper is tested and the wiring is not"
  pattern. `modify_verbs_are_routed_not_405` now drives
  `nsacf_sbi_request_handler` and asserts the verbs are not 405 (and that a verb
  the resource genuinely lacks still is). The other two were harness bugs of mine.
- **One claim is type-enforced rather than revert-provable**, stated rather than
  faked: removing the `SbiServiceType::NnsacfSliceEe => "nnsacf-slice-ee"` arm
  from `to_name` makes the match non-exhaustive, so no build exists where the
  variant lacks a name — the recorded "a type change cannot be revert-tested" case.
  The `from_name` half **is** revert-proven.

### Two pre-existing races fixed rather than left

The whole-workspace run (which the per-crate runs cannot see) surfaced two
failures in **nssfd**, neither in the crate this issue is about:

1. **A defect I introduced in #94**, now fixed: the availability-authorization
   escape hatch permitted an **empty** `{nfId}`. The hatch is for a missing
   *caller identity*; an empty `nfId` names no document, so there is nothing it
   could be authorized to write whatever the posture. `test_availability_put_empty_nf_id_403_not_authorized`
   caught it, and it is now guarded explicitly.
2. **A pre-existing process-global race**:
   `test_http_nsselection_registration_scenario` does not take the guard its
   restriction-setting siblings take, so a sibling's `[sst 1]`
   PLMN-supported-S-NSSAI restriction could filter every requested slice out,
   leaving a body-less response that surfaced as an `unwrap` panic pointing
   nowhere near the sibling. I had seen this once during #93 and wrongly dismissed
   it as an ordering artifact; seeing it twice is the signal. Fixed by taking the
   guard those tests **already** take, per the recorded rule that a private lock
   cannot order tests that do not know about it.

### Verification ceilings

- `emit_reports_for`'s delivery is `tokio::spawn`ed, so the trigger *decisions* are
  tested through the pure `report_decision` and the store bookkeeping, not by
  counting bytes arriving at a stub consumer. A stub-consumer test would add a
  timing dependency for the periodic case without proving more about the gate.
- The `immediateFlag` and immediate-EAC *dispatch* is wired and type-checked; the
  mode-list construction and first-subscription detection are tested, but no test
  observes the POST landing on a stub callback.
- The NRF profile's `allowedNfTypes`/`apiFullVersion` are not asserted by a test
  (nsacfd's registration is not harnessed); they are verified by inspection against
  the vendored OpenAPI. The issue itself flags this as a secondary detail.
- GitNexus impact analysis was **not run** — no MCP server connected.

## Files

- `src/libs/nextgcore-sbi/src/types.rs` — `NnsacfSliceEe`
- `src/libs/nextgcore-sbi/src/json_patch.rs` (moved from nssfd) + `lib.rs`
- `src/bins/nextgcore-nssfd/src/main.rs` — repointed at the shared engine; the
  empty-`nfId` hatch fix; the race guard
- `src/bins/nextgcore-nsacfd/src/context.rs` — trigger state on
  `SacSubscription`, `ReportDecision`, `over_threshold_now`, `report_decision`,
  report bookkeeping, `eac_subscription_exists`, `eac_mode_list`
- `src/bins/nextgcore-nsacfd/src/main.rs` — PATCH/PUT handlers and routes, shared
  validate/build, gated `emit_reports_for`, immediate EAC, NRF profile
- `docs-book/src/configuration/nsacf.md`
