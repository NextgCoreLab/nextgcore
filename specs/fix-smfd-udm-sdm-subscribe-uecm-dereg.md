# nextgcore #293 (smfd): close the UDM loop — deregister, subscribe, and act on the notification

Verified against `main` @ `3799767`.

#293 was split out of #79, which implemented the two UDM operations its criteria named
(`Nudm_UECM_Registration`, `Nudm_SDM_Get sm-data`) and neither of the two that close the loop.
TS 29.503 §5.2.2.3 / §5.2.2.4 / §5.3.2.4, TS 23.502 §4.3.2.2.1.

## Verified against current main

| claim in the issue | site on `3799767` | still true? |
|---|---|---|
| the UECM registration is a PUT and nothing deletes it (`rg smf-registrations`) | `udm.rs:332` PUT only | yes |
| `sm-data` is fetched once, at establishment | `main.rs:2845` | yes |
| the SMF serves no `Nudm_SDM_Notification` handler | no `sdm` route in `smf_sbi_request_handler` | yes |
| subscribing without one would notify into a 404 | the router's fallback is `send_not_found` | yes |
| both hooks belong in `handle_sm_context_release` and read off `PolicyBinding` | `main.rs:4563` | yes |
| `handle_sm_policy_notify` already re-authorises an existing session's N4 QER | `main.rs:5149` | yes |
| the same decision about a failed teardown as #291 | #291 landed while this was open; same answer reused | yes |

## Decision 1: the notification is a trigger to RE-READ, not a patch to apply

TS 29.503's `ModificationNotification` carries `notifyItems[].changes[]` as operation / path /
newValue triples over the `sm-data` document. Honouring that literally means implementing a patch
interpreter over `dnnConfigurations`, which is a **free-form map keyed by DNN** — so a path this SMF
fails to understand yields "no change" indistinguishably from "nothing changed", and a partially
understood patch applies half an edit. Both failure modes are silent.

Instead the handler re-reads the authoritative document with the same `fetch_sm_data` the
establishment path uses, and applies the result through the same `apply_subscribed_baseline`. One
behaviour to keep correct instead of two, and the notification's role is to say *when* and *for which
resource*. A test asserts the re-read actually happens (the recorded `GET /sm-data`), so this is not
a claim about intent.

## Decision 2: the re-read is scoped to the session's own S-NSSAI, which needed two new binding fields

`sm-data` is one entry per S-NSSAI and `parse_sm_data` falls back to the **first** entry when none
matches. So a re-read that lost the session's S-NSSAI would apply *another slice's* session-AMBR and
look like a successful update — the exact class of half-truth this backlog keeps finding.

`PolicyBinding` carried no S-NSSAI (the create path had it in locals only), so `sst: u8` and
`sd: Option<String>` are now stored on it. The `sd` is kept as the **hex string as received** rather
than the parsed `u32` the session record holds: `parse_sm_data` compares it to the UDM's document as
a string, and re-formatting `u32` → hex would risk a case/width mismatch against the value the AMF
actually sent.

The guard is a decoy: `sm_data_with` returns an ARRAY whose first entry is a different slice with
different values, so every test asserting the real values also asserts the scoping. Reverting to the
old hardcoded `(1, None)` fails a named test.

## Decision 3: with a PCF configured, the SMF does NOT apply a subscription-driven change

This is the precedence question #293 asks to be answered either way.

TS 23.503 §6.1.3.2 makes the PCF the authority on session-AMBR and default QoS, and the
**subscription is one of its inputs**. Re-deriving the session's QoS from the subscription behind the
PCF's back would have the SMF enforce something the PCF never authorised — a conformance defect
rather than a degradation, which is the same reasoning #79 recorded for the establishment-time
precedence (`PCF` then `subscription` then `config default`).

So a notification for a session with an `sm_policy_id` is accepted (`204`), logged, and **not
applied**. The change reaches such a session when the PCF re-authorises it, which the PCF learns to
do from its own policy-data subscription to the UDR — not from the SMF.

**Consequence, stated rather than left implicit:** in a deployment whose PCF does not subscribe to
policy-data changes, an administrative edit will not reach a PCF-authorised live session at all. That
is a PCF-side gap, not an SMF-side one, and it is filed as its own follow-up. The alternative — the
SMF forwarding the change to the PCF — was rejected because there is no such operation: an SMF sends
`SmPolicyUpdateContextData` for triggers the PCF subscribed to, and "the subscribed QoS changed" is
not one of them.

## Decision 4: a failed teardown is logged with what is left behind, not retried

Same answer and the same reasoning as #291, which landed while this was open: the session is leaving
either way, and a retry queue that survives what it needs to survive means durable state. What
differs is the consequence named in each log line, because the two leaks are not the same:

- a stale **serving-SMF record** makes a procedure resolving the serving SMF through the UDM resolve
  a *released* session to this SMF (it answers `404 CONTEXT_NOT_FOUND` at best), self-heals when the
  same `pduSessionId` is reused, and is permanent for one that never is;
- a stale **SDM subscription** keeps the UDM notifying a callback URI whose `smContextRef` no longer
  resolves. The handler answers `404` to exactly that, deliberately, because that is what tells a
  conformant UDM to stop.

A `404` from either delete is treated as success: it means the UDM does not hold the resource, which
is the state the call wanted.

## Decision 5: the handler ships in the same change as the subscribe, and the callback URI is per session

#79 left the subscribe out because subscribing creates a resource on the UDM whose notifications go
to a callback URI, and an SMF that serves no handler would create a resource that notifies into a
`404` — strictly worse than not subscribing, because the UDM then retries against us. So the route
(`POST /nsmf-callback/v1/sdm-notify/{smContextRef}`) is part of this change, and
`subscribe_sm_data`'s `callback_uri` parameter is the caller's proof that it has one.

The URI is **per SM context** because the SMF chooses its shape and a notification has to name the
live session it applies to. The subscription id comes from the `Location` header and is stored on the
binding, so the release can delete the resource it created; a subscribe that succeeds without naming
an id is reported as an orphan rather than stored as an empty string.

## Acceptance criteria

- [x] Releasing a session sends a UECM DELETE for its `pduSessionId`, asserted over the wire **from
      the release handler** — `the_create_subscribes_to_sm_data_and_the_release_deregisters_and_unsubscribes`.
- [x] A failed deregistration does not fail the session release, and names the leaked record —
      `a_failed_udm_teardown_does_not_fail_the_session_release`.
- [x] The SMF serves a `Nudm_SDM_Notification` callback that applies a changed session-AMBR /
      default 5QI to a live session, asserted by driving the callback and reading back the session —
      `a_sdm_notification_applies_the_changed_ambr_to_a_live_session`.
- [x] `Nudm_SDM_Subscribe` is sent at establishment and `Unsubscribe` at release, and neither is sent
      unless the callback route exists (Decision 5 — the route is in the same commit, and the
      notification test drives it to a `204`, which no unknown-endpoint fallback can produce).
- [x] The PCF-present precedence question is answered — Decision 3, and guarded: the same
      notification against a PCF-authorised session changes nothing.
- [x] With `SMF_UDM` unset, none of the above is sent —
      `a_disabled_udm_leg_neither_deregisters_nor_unsubscribes`.

## Verification

Workspace **6283 passed / 0 failed** (baseline 6278 on `3799767`; +5 — smfd 459 → 464). `cargo clippy
-p nextgcore-smfd --all-targets` zero warnings; `cargo fmt --all -- --check` clean.

Six whole-workspace runs: **five green at 6283, one failure that is not this change** —
`amfd::ngap_path::tests::modify_release_notify_and_modify_indication_all_relay_to_the_smf` failed
once with `Failed to bind: Address already in use`, the `free_port` TOCTOU flake CI already documents
and retries for. This branch touches no amfd file. Recorded rather than re-run until it disappeared.

| revert | expected to break | result |
|---|---|---|
| the UECM DELETE removed from the release path | `the_create_subscribes_..._deregisters_and_unsubscribes` | **1 failed** |
| the unsubscribe removed from the release path | same | **1 failed** |
| the subscribe removed from the create path | same | **1 failed** |
| the subscription id stored as `None` on the binding (the orphan case) | same | **1 failed** |
| the PCF-precedence early return removed | `a_sdm_notification_applies_the_changed_ambr_to_a_live_session` | **1 failed** |
| the session's own `session_ambr` left stale by the notification | same | **1 failed** |
| the binding left stale by the notification | same | **1 failed** |
| the re-read scoped to a hardcoded `(sst 1, sd None)` again | same (via the decoy entry) | **1 failed** |

## Ceilings

- **The notification handler applies session-AMBR and default 5QI, and nothing else.** `SubscribedSmData`
  models only those plus the ARP priority level (#79's deliberate narrowing), so a change to any other
  `DnnConfiguration` member is fetched, ignored and not reported as ignored. Widening the struct
  without widening what enforces it would make more members *read* as implemented.
- **The ARP priority level is re-read but not re-applied.** It reaches `PolicyDecision` and is used at
  establishment (for the EBI request, #117); a mid-session ARP change does not re-drive that, because
  re-requesting an EBI would mean releasing and re-assigning one for a session that is up.
- **A binding restored from a pre-#293 snapshot has `sst: 0`**, so a notification for it re-reads
  unscoped and `parse_sm_data` falls back to the first entry — i.e. exactly the pre-#293 behaviour,
  for restored sessions only. Not worth a snapshot version bump: `#[serde(default)]` absorbs the new
  members, which is the recorded bar for not bumping.
- **The PCF-side half is out of scope and filed separately** (Decision 3): nothing makes a PCF
  re-authorise a live session when the subscription changes.
- **No test drives a UDM and a PCF together**, so "a PCF-authorised session ignores the notification"
  is asserted with a seeded `sm_policy_id` rather than against a live PCF association.
