# nextgcore #83 (UDM): SDM and EE notification producers, subscribe validation, EE patch

Verified against `main` @ `6105306`. Every defect the issue describes was still present as written.

`Closes #83`, with criteria 3 and 4 split to **#226** — see "Split".

## Gap: both event-exposure surfaces were facades (criteria 2, 5)

The load-bearing defect. A consumer could `POST` an `SdmSubscription` or an `EeSubscription`, get `201`,
and then hear nothing ever again, because **no code path in the crate produced a notification**.
`lib.rs` and `context.rs` both carried comments admitting it. The only outbound notification in udmd was
the UECM deregistration one, which serves a different purpose entirely.

### What triggers a notification

The UDM is mostly a read-through to the UDR, so it observes few writes of its own. The ones it does
observe are the UECM lifecycle transitions — an AMF or SMF registering, updating or deregistering — and
those *are* changes to a monitored SDM resource (the UE's context data set) as well as EE-reportable
events. Both producers therefore hook the same four sites in `uecm.rs`. That is coherent rather than
coincidental: one transition, two audiences.

`notify_ue_context_change` is shaped so any future data-set write can call it without knowing about
subscriptions.

### Decisions worth review

* **On by default, with an off switch (`UDM_NOTIFY_DISABLE`).** The issue suggests off-by-default
  feature gates. Rejected, and not for the usual "a cargo feature hides its tests from CI" reason
  alone: the argument for gating *new outbound traffic* does not apply here, because a notification is
  only ever sent to a `callbackReference` a consumer explicitly subscribed with. A deployment that
  subscribes to nothing sees no new traffic at all. The switch exists for the case where a consumer
  subscribes and then cannot cope with being notified.
* **A distinct changed-resource and EE event type per transition.** AMF transitions change
  `ue-context-in-amf-data`, SMF ones `ue-context-in-smf-data`; registration reports
  `UE_REACHABILITY_FOR_DATA` and deregistration `LOSS_OF_CONNECTIVITY`. Collapsing either into one
  value would wake every subscriber on every transition, or make the report unable to say what
  happened.
* **`monitoredResourceUris` narrows, but an EMPTY list does not.** Subscribing to a UE without naming
  resources is a whole-UE subscription, not a subscription to nothing. (At *subscribe* time an empty
  list is refused — see below — so the empty case only arises for subscriptions created before this
  change or through another path.)
* **EE scope matching covers exact-SUPI and `anyUE` only.** A subscription's `ue_identity` may also be
  a GPSI or an external group id, and resolving those needs identifier translation this UDM does not
  implement (tracked on #85). Matching them by guesswork would deliver **another UE's events**, so they
  are skipped rather than approximated.
* **Delivery is best-effort and never fails the triggering operation**, but it is `await`ed rather than
  spawned, so the notification is ordered after the UDR write it reports: a subscriber that reacts by
  reading the data set must not find the state the notification is about missing.
* **The context lock is released before any `.await`.** Holding a `RwLock` across the outbound HTTP call
  would deadlock the subscribe path against the notify path.

`udm_sbi_send_dereg_notification` was generalised into `udm_sbi_send_callback_notification`: all three
notifications are "POST this JSON to the absolute URI the consumer gave us", and one implementation
means a fix to the URI parsing or the client reaches every notification the UDM sends.

## Gap: SDM Subscribe accepted invalid subscriptions (criterion 1)

The routed handler read `nfInstanceId`, `callbackReference` and `monitoredResourceUris` and then
inserted the subscription regardless, answering `201`. A consumer with a bug in its subscribe request
got a subscription id back, monitored nothing, and had no way to tell. `nudm_handler.rs` already
contained exactly these checks — nothing routed to them.

An **empty** `monitoredResourceUris` is refused as well as an absent one: the schema's `minItems` is 1,
and an empty list is the shape a consumer produces when its own resource list came out empty, which is
a bug to surface rather than a whole-UE subscription to infer.

## Gap: EE UpdateEeSubscription discarded its patch (criterion 6)

It answered `204` and dropped the body, so a consumer could "modify" `monitoringConfigurations` forever
while the stored subscription never changed — lifecycle management that reports success and diverges
from state.

`apply_ee_patch` handles the `PatchItem` array form and, leniently, a merge-patch object. Two choices:
**`remove` and `replace` on an absent member are errors, not silent no-ops** (a consumer patching a
path that is not there has a wrong idea of the stored subscription, and `204` would confirm it); and a
patch that changes `callbackReference` **updates the cached copy too**, or the next notification would
go to the old URI.

## Split: criteria 3 and 4 → #226

#83's own *Suggested approach* marks this separable: "the multi-data-set/missing-data-set work is
additive read-side … it may reasonably be split into a separate lower-priority issue since the
load-bearing defect is the missing notification producers." Following the recorded convention for an
author-marked split, it is filed as #226 and the parent closes.

Worth noting for #226's priority: `ue-context-in-amf-data` is now more interesting than it was, because
the producer added here reports changes to exactly that data set on every AMF transition. A subscriber
is told the resource changed and then cannot read it.

## Verification

**11 new tests** (2 in `app`, 8 in `notify`, 1 in `uecm`). udmd 136 → 148 passed. Workspace
`cargo test --workspace` green; `cargo clippy --workspace` (the CI gate) clean, zero warnings;
`cargo fmt --all --check` clean.

**Revert-verified: 20 reverts, 20 bit** — after fixing the harness twice and, more importantly, after
one revert exposed a genuine hole.

**The hole: the UECM wiring was untested.** Removing the `notify_ue_context_change` call from
`process_amf_registration` left **every notify test green**, because all of them called the producer
directly. The producer was covered nine ways and the line that invokes it was not covered at all —
precisely the recorded lesson that extracting logic into a tested helper leaves the wiring untested.
`uecm::tests::amf_registration_notifies_sdm_and_ee_subscribers` now drives a real
`process_amf_registration` against a mock UDR and a stub callback server, and the revert of that single
line fails it with `left: 0, right: 2`.

**A second finding, about test isolation rather than product code.** The notify tests were flaky at
roughly one run in four, failing with an `HTTP/2 connection error` that reads as the producer sending
nothing. Cause: `app.rs`'s `test_http_generate_auth_data_flows` sets the process-global SBI profile
override to `Dev` and never resets it, so these tests inherited **production TLS or plaintext depending
on test order** while talking to a plaintext loopback stub. Two changes: declare the profile in the
stub-server helper rather than inherit it, and serialize on the crate-wide `CONTEXT_GUARD` — the lock
that sibling already takes — instead of a private lock that only serialized the new tests against each
other. Stable over six consecutive runs after that. The tests also clear subscriptions **up front**
rather than at the end, so a panicking test cannot leak an `anyUE` subscription into the next one.

**Not verified:** no live consumer. The producers are asserted against in-process stub SBI servers
reading real POST bodies off the wire, which covers the callback-URI parsing, the client and the body
shapes, but not a conformance-tested peer. The SDM producer fires only on UECM transitions — a change
to a data set written through some other path would not notify, because no such path exists in udmd
today; that is a property of the crate rather than of this change, and the entry point is shaped to be
called from one when it appears. Docker E2E is skipped by CI. GitNexus impact analysis, which CLAUDE.md
mandates, was **not run** — no MCP server connected; twelfth consecutive PR to record it.
