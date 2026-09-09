# nextgcore #112 (dccfd): Ndccf_DataManagement wire conformance and producer-subscription coordination

Verified against `main` @ `08bd7ab` (after #65/#272 and #106/#274). Every cite in the issue still
held — dccfd had not been touched since `76ea248`.

## Verified against current main

| claim in the issue | check on `08bd7ab` | still true? |
|---|---|---|
| the callback is read from `"notifyUri"` | `main.rs:125` | yes |
| only `(sub_id, notify_uri)` is stored | `context.rs:12-18` `DccfSubscription` has exactly those two fields | yes |
| the `201` is a bespoke `{"subscriptionId":..,"status":"ACTIVE"}` with no `Location` | `main.rs:133-134` | yes |
| a missing/unparseable body still yields `201` | `main.rs:129` `unwrap_or_default()` | yes |
| `PUT` falls through to `405` | `main.rs:141-159` matches only GET/DELETE | yes |
| the notify fan-out wraps the body as `{"data": <string>}` | `main.rs:181` | yes |
| `dccf_context_fanout_notify` returns every subscription with a non-empty URI | `context.rs:135` | yes |
| no `dataSub`/`anaSub` parsing, no NRF discovery, no producer-subscription state | grep across the crate → nothing | yes |
| `notifCorrId` is never parsed, stored or echoed | grep → no occurrence in the crate | yes |

## Which schema is authoritative

TS 29.574's OpenAPI file is **not vendored**. Its data model is the same as `Nnwdaf_DataManagement`,
whose file **is** vendored, so everything below was read out of
`6g_docs/specs/TS29520_Nnwdaf_DataManagement.yaml`:

* `NnwdafDataManagementSubsc`: `required: [notifCorrId, notificURI]`, `oneOf: [anaSub | dataSub]`
* `POST /subscriptions` → `201` + `Location` (`required: true`) echoing the resource
* `PUT /subscriptions/{subscriptionId}` → `UpdateNWDAFDataSubscription`
* `NnwdafDataManagementNotif`: `required: [notifCorrId, notifTimestamp]`,
  `oneOf: [dataNotification | dataReports | fetchInstruct]`
* the callback is `'{$request.body#/notificURI}'`

Members whose types come from yamls that are *also* absent (`DataSubscription` from TS 29.575,
`FormattingInstruction` / `ProcessingInstruction` from TS 29.574) are passthrough
`serde_json::Value` — the repo's established convention for a cross-spec leaf, because modelling a
schema nobody can check against invents a contract.

## The anchor: one character

`notificURI` — `notific`, not `notif`, and `URI` uppercase. Note that `rename_all = "camelCase"`
produces `notificUri`, which is *also* wrong, so the member needs an explicit
`#[serde(rename = "notificURI")]`. That single character is the whole defect: a conformant consumer's
URI was never captured, the stored URI stayed empty, and the empty-URI filter in the fan-out dropped
that consumer from every notification. It subscribed, got a `201`, and was never told anything, with
no error surface anywhere.

## Decision 1: `serde(default)` on two members the yaml marks required

Without it, an absent `notifCorrId` / `notificURI` is a **parse** error, which the handler can only
report as `INVALID_MSG_FORMAT`. TS 29.500 wants `MANDATORY_IE_MISSING` for a missing mandatory IE, and
that distinction is what tells a consumer whether its JSON is malformed or merely incomplete. So
absence deserialises to an empty string and `validate()` names the offending member. Empty strings
count as absent, because an empty callback URI is exactly the un-notifiable state being fixed.

## Decision 2: the fan-out key, and what an indeterminate scope gets

`SubscriptionScope { events, target }` replaces "any non-empty URI".

* From `anaSub` the extraction is **exact**: `NnwdafEventsSubscription` is vendored, so
  `eventSubscriptions[].event` is read directly.
* From `dataSub` it is a documented **heuristic**: that schema is not vendored, so every string under
  a key named `event`, `eventId` or `type`, at any depth, is collected. Depth-bounded at 16 —
  `dataSub` is peer-supplied on the request path.
* An inbound producer notification is scoped the same way, from
  `eventNotifications[].event`.

Matching requires an event intersection, and a `target` named on **both** sides must agree. A side
that named no target does not constrain, because it constrained nothing.

**A subscription whose scope cannot be determined matches nothing, not everything.** Delivering to it
— the old behaviour — is the cross-consumer disclosure defect. It is logged at warn on create, naming
the consequence and what to supply, so a scope-less subscriber is *visible*, which an over-broad
delivery is not.

## Decision 3: coordination is a runtime switch, not a cargo feature

The issue suggests a cargo feature (`dccf-coordination`) and criterion 7 is marked
"(Feature-gated)". **Deviation, deliberate:** it is a runtime switch (`--coordination` /
`DCCF_COORDINATION`, default off) instead, because CI builds default features — a cargo feature would
leave the coordination path **uncompiled in CI**, where it would rot unnoticed. A runtime switch means
one `cargo test` run compiles and exercises **both** states, which is a stronger reading of criterion
8 ("passes with the feature both off and on") than running the suite twice.

Default **off**, honouring the issue's "keep the current registry as the default until the new path is
validated": coordination makes `subscribe` perform outbound signalling that can fail or stall, and
nothing in this stack exercises dccfd end to end. `coordination_off_creates_no_producer_subscription`
guards that default with the same request the ON test uses.

## Decision 4: coordination requires the consumer to name its producer

`targetNfId` present → `GET {nrf}/nnrf-nfm/v1/nf-instances/{targetNfId}` (TS 29.510 NF profile
retrieval, which nrfd serves), pick that profile's event-exposure service, POST the **consumer's own**
subscription body with `notificationURI`/`notifCorrId` rewritten to this DCCF.

Forwarding the consumer's body rather than synthesising one matters: the DCCF is subscribing *on its
behalf*, not inventing a subscription.

`targetNfId` absent → coordination is skipped with a log line. Doing otherwise needs an
event→producer-NF-type table (TS 23.288 §6.2), and for most NWDAF events that mapping is genuinely
ambiguous — `SERVICE_EXPERIENCE` can come from an AF or the NEF, `NF_LOAD` from OAM or the NRF.
Guessing would create producer subscriptions on the wrong NF. The consumer subscription still
succeeds: its contract is with the DCCF, and refusing it would make an unresolvable producer look
like a malformed request.

The event-exposure service is found by **name** (`eventexposure` / `evts` / `eventssubscription`)
rather than from a hardcoded list of NF types, so a producer family this DCCF has never heard of still
works.

Producer subscriptions are **refcounted** by consumer: the last consumer to unsubscribe deletes the
producer resource, so one consumer's unsubscribe cannot cut off another's data.

## What was added / changed

| area | change |
|---|---|
| `data_mgmt.rs` (new) | `DataManagementSubsc` + `validate()`, `SubscValidationError` with per-member details, `DataManagementNotif`, `SubscriptionScope` (`from_subsc`, `from_notification`, `matches`), the depth-bounded event sweep |
| `coordination.rs` (new) | `enable_coordination`, `CoordinationConfig`, `ensure_producer_subscription`, `delete_producer_subscription`, NF-profile retrieval, event-exposure endpoint selection, `split_uri` |
| `context.rs` | `DccfSubscription` gains `notif_corr_id`, `scope`, `resource`; `ProducerSubscription`; `dccf_context_store_subscription` / `_get_subscription` / `_subscription_ids`; `dccf_context_fanout_notify_scoped`; producer claim/record/release/count; the crate-wide `GLOBAL_TEST_LOCK` |
| `main.rs` | `handle_dm_subscribe` / `_update` / `_unsubscribe` / `_notify`, `parse_subsc`, `bad_request`, `rfc3339_now`, `DM_SUBSCRIPTIONS_PATH`; the PUT route arm; GET echoes the stored resource |
| `Cargo.toml` | `serde` (the wire types are derived, not hand-built from `Value`) |

The pre-#112 unkeyed `dccf_context_fanout_notify` is retained as `#[cfg(test)]` only, so it cannot be
reintroduced into production by accident.

## Verification

Every guard revert-verified: undo the fix, watch the **named** test fail, restore.

| guard | revert applied | result |
|---|---|---|
| `the_callback_member_is_spelled_notific_uri`, `a_conformant_subscription_receives_its_notifications` | `rename = "notifyUri"` | FAILED ✓ |
| `fanout_is_keyed_on_the_subscribed_event` | filter on non-empty URI only | FAILED ✓ |
| `invalid_subscribe_bodies_are_rejected_with_problem_details` | `validate()` call removed | FAILED ✓ |
| `create_returns_location_and_the_spec_resource` | `Location` header removed | FAILED ✓ |
| `put_updates_the_subscription_and_its_scope` | PUT stores the new body but keeps the OLD scope | FAILED ✓ |
| `overlapping_consumers_share_one_producer_subscription` | reuse check dropped (always create) | FAILED ✓ |
| `a_conformant_subscription_receives_its_notifications` | notify with the old `{"data": ...}` envelope | FAILED ✓ |

The PUT revert is worth naming: storing the new body while leaving the stale scope in place passes a
GET-only assertion, so the test also asserts the recomputed scope no longer contains the old event.

### A flake I caused, and the fix the repo already knows

`context::tests::test_subscription_lifecycle` — a **pre-existing** test — started failing
intermittently: my new `clear_subscriptions()` helper wipes the process-global subscription map, and
that test had its own private guard, so the two modules were two disjoint agreements about the same
variable. One green run proved nothing; the failure was order-dependent.

Fixed by hoisting **one** crate-wide `GLOBAL_TEST_LOCK` into `context.rs` and having both test modules
take it — the same resolution recorded for seppd in #100, and the reason a second lock is not the fix.
Every pre-existing test in `context::tests` now takes it too, not only the fan-out ones. 5 consecutive
runs green.

## Workspace state

`6090 passed / 0 failed` (main: `6071`), `cargo clippy --workspace --all-targets` 0 errors,
`cargo clippy -p nextgcore-dccfd --all-targets` **0 warnings** (criterion 8 asks for none, not just
no errors — `result_large_err` on `parse_subsc` was fixed by boxing, as eesd's `parse_json_body`
does), `cargo fmt --all --check` clean.

## Ceilings

* **Coordination is off by default, so the DCCF still de-duplicates nothing in a default
  deployment.** The mechanism exists, is tested, and is one flag away; that flag is the operator's
  call, not this change's.
* **Coordination needs `targetNfId`.** A consumer that names no target gets no producer subscription,
  by design (see Decision 4). The event→producer-NF-type mapping is deliberately absent.
* **`dataSub` scope extraction is a heuristic** over an unvendored schema. A `dataSub` whose event
  identifier sits under a key not named `event`/`eventId`/`type` yields an empty scope, and that
  consumer receives nothing — logged at warn, but silent on the wire. Vendoring TS 29.575 would let
  this become exact.
* **Only `dataNotification` is produced.** `dataReports` and `fetchInstruct` are modelled but never
  emitted; the DCCF forwards, it does not summarise or store-and-instruct.
* **No ADRF interaction.** `adrfId` / `adrfSetId` are parsed and echoed but nothing is stored to an
  ADRF, so a consumer asking for storage is not served — it is also not told that, which is the
  weakest point left in the contract.
* **`formatInstruct` / `procInstruct` are echoed, not applied.** Data is forwarded verbatim.
* **The producer subscription is created but never refreshed**, and its expiry is not tracked. A
  producer that expires the subscription silently stops the data.
* **No user-consent enforcement.** `dataCollectPurposes` / `checkedConsentInd` are parsed and ignored;
  TS 23.288 makes consent checking conditional on local policy, and there is no consent source here.
* **No wire interop.** The coordination test uses loopback `SbiServer`s standing in for the NRF and
  the producer — real HTTP and a real `SbiClient`, but this tree's own server on both ends.
* GitNexus impact analysis unrunnable (no MCP server connected — 49th consecutive PR). Blast radius
  by grep: `dccf_context_fanout_notify` had exactly one production caller (rewritten) and two test
  callers (kept, now `cfg(test)`); `dccf_context_add_subscription_with_uri` keeps its signature for
  the `Ndccf_ContextDocument` side; `DccfSubscription` is constructed in three places, all in this
  crate; no crate outside `nextgcore-dccfd` names any type touched here.
