# Fix nssfd Nnssf_NSSAIAvailability: caller-bound authorization, subscription expiry, create validation, wire shape

Closes nextgcore #94.

Cites re-located against `main` at `0216b13` (the issue verified them at
`76ea248`, and PR #238 had since moved much of `nssfd/main.rs`).

## 1. Authorization did not bind the caller to the resource

`nf_authorized_for_availability` was `!nf_id.trim().is_empty()` — it checked only
that the **path segment** was non-empty, and accepted-then-ignored the `tai`
argument. So any reachable NF could `PUT`/`PATCH`/`DELETE` **another AMF's**
slice-availability document, which is the document the NSSF uses to decide which
S-NSSAIs that AMF may serve.

### The missing piece: there was no attestable identity to bind to

The server verified the bearer token and then **discarded the claims** —
`OAuthVerifier::authorize` returned `Ok(())`. A producer could therefore enforce
"a valid token exists" but never "the caller is who this resource belongs to".

`authorize` now returns the verified `sub`, and the server records it on
`SbiRequest.oauth2_subject`, mirroring the `peer_cert_nf_instance_id` field #186
added for the same reason: **an identity this process attested**. Both are used,
certificate first (bound to the connection rather than bearer-presentable).

Authorization now requires `caller == {nfId}` (case-insensitive; TS 29.510
`nfInstanceId` is a UUID whose hex may arrive in either case). `caller: None` is a
**denial** inside the policy function; whether an unauthenticated deployment may
opt out is decided by the caller, where the operator's explicit choice is visible.

### Fail-closed on an unevaluable policy

The poisoned-lock arm fell back to the default-allow policy, so **one panicking
sibling request** — all it takes to poison a `std` lock — disabled the
authorization check for every later availability write. It now denies (403
`NOT_AUTHORIZED`). Extracted as `policy_unevaluable_response` because poisoning
the process-global context lock inside a test would poison it for every parallel
test in the binary, which is the avalanche the recorded poisoned-mutex learning
describes; the call site is pinned by a source guard living in `context.rs`
instead of `main.rs`, since a guard that greps its own file matches its own
needle.

### OAuth2 defaults to ON

`nssf.sbi.oauth2.require` defaulted to `false`, so the shipped default posture
both accepted token-less requests and — having no identity to bind to — left the
availability bypass wide open. It now defaults to **enabled**, and an absent
`oauth2` section means enforce.

Following the #63 precedent exactly, the dev opt-out landed in **the same
commit** as the flip: `docker/rust/configs/5gc/nssf.yaml`, the k8s ConfigMap and
the Helm ConfigMap each gained an explicit `require: false` with a comment stating
the consequence. Flipping first would have broken all three and looked like a code
bug. A deployment that opts out logs a startup WARNING and a WARNING on **every**
availability write, so the posture is visible in the log rather than only in the
config (the #64 escape-hatch pattern).

One knob governs authentication and the caller binding together, because binding
is only meaningful against an authenticated identity; two knobs could disagree.

## 2. Subscription expiry was inert

`SUBSCRIPTION_VALIDITY` was unused, create started no timer, the
`SubscriptionValidity` handler logged and returned, and `subscriptions_matching`
filtered only on `tai_list`. `to_created_json` echoed the consumer's `expiry` and
assigned none — so a consumer was told its subscription was valid until an instant
the NSSF then ignored, forever.

- The NSSF **assigns** the expiry, bounded by `SUBSCRIPTION_VALIDITY` (24 h). A
  consumer-requested value wins only when **earlier**, so a consumer cannot extend
  its own subscription past what the producer will keep.
- `subscriptions_matching` filters expired subscriptions, so one stops being
  **served** immediately.
- A sweep on the **existing run-loop tick** (every 60 s) stops it being **stored**.
  A sweep rather than a timer per subscription: the loop already exists, a
  per-subscription timer needs its own cancellation story on delete/patch, and a
  sweep is correct after a restart where no timer survived. Both mechanisms are
  kept deliberately — the filter alone would accumulate records forever, the sweep
  alone would leave a window in which an expired subscription is still notified.
- The `nssf_sm` handler now actually removes, so an armed timer is not a claim the
  NSSF fails to honour.

An **unparseable** expiry is treated as NOT expired: refusing to serve a
subscription because the NSSF cannot read its own timestamp would turn a
formatting bug into silent notification loss.

## 3. Create validation, and one deviation from the issue

Only `nfNssaiAvailabilityUri` and `event` are mandatory (TS 29.531
Table 6.2.6.2.8-1; the OpenAPI's `required` list). `taiList` was rejected as
missing, so a conformant consumer subscribing to **all** TAIs got a 400 — while
`subscriptions_matching` already treated an empty list as "all TAIs". The
semantics existed; only the validation disagreed.

**Deviation, stated deliberately:** the issue proposes requiring `taiList` *for
the status-change event specifically*. The spec imposes no such conditional, so
adding one would 400 a legal request; `taiList` is optional for every event
instead. (The issue also names the event `SNSSAI_STATUS_CHANGE`; the enum token is
`SNSSAI_STATUS_CHANGE_REPORT`, and the OpenAPI spelling is what is implemented.)

`additionalEvents` is parsed and `acceptedEvents` is returned. It lists **only
events with a real producer**: `spawn_availability_notifications` fires on an
availability change and nothing else, so `SNSSAI_STATUS_CHANGE_REPORT` is the only
reportable token. An unreportable *additional* event is simply absent from
`acceptedEvents` rather than rejected — `NssfEventType` is an `anyOf` over the
enum plus a free-form string, so an unknown token is forward-compatibility. A
subscription whose events are **all** unreportable is refused, because it could
never fire. Note the contrast with #90's Npcf_EventExposure: there TS 29.523
defines no per-item failure report, so only the empty case could be signalled;
here `acceptedEvents` gives a conformant way to report partial acceptance.

## 4. Wire shape and the missing config surface

- `restrictedSnssaiList` entries serialize under **`sNssaiList`**, which
  `RestrictedSnssai` marks required; it was `sNssais`, which any strict consumer
  would reject.
- That bug was **latent** because `set_plmn_snssai_restrictions` had no caller
  outside `#[cfg(test)]` — an operator could not configure a restriction at all.
  A new `nssf.snssai_restrictions[]` block is that production surface; an entry
  with an incomplete `home_plmn` is skipped with a warning rather than installed
  under a guessed PLMN.
- Authorized entries now carry `taiList`, `taiRangeList` and `nsagInfos` through.
  They were dropped, so an entry scoped by a TAI **range** came back scoped by
  nothing and the consumer could not tell which TAIs the authorization covered.

## 5. Shared `DateTime` conversion

Expiry needs RFC 3339 ↔ epoch in both directions. **Six copies** of one or both
functions already existed (`nrfd`, `udmd`, `eesd`, `bsfd`, `pcfd`, and the seventh
nssfd was about to add). Per the recorded "count the implementations" rule the
canonical pair now lives in `nextgcore-sbi::datetime` — the crate every NF already
depends on for wire types, and `DateTime` is a wire type.

Deliberately **not** migrated in this change: rewriting six daemons' timestamp
handling is its own blast radius and the copies differ in signature (`u64` vs
`i64`) and strictness. The module documents itself as the migration target. A
non-UTC offset is **rejected** rather than read as UTC, because misreading an
offset shifts a deadline by hours.

## Verification

- Workspace: **5926 tests pass, 0 fail**, across **three consecutive full-suite
  runs**; `cargo clippy --workspace` clean; `cargo fmt --all --check` clean.
- **19 behavioural claims individually revert-verified.**
- Four reverts did not bite first time; three were bugs in my revert harness
  (a non-unique anchor, a wrong package, a non-compiling revert) and **one was a
  real coverage gap**: reverting the server's `oauth2_subject = Some(sub)` left
  nssfd's authorization tests green, because those tests set the field on a
  hand-built request — they proved nssfd *uses* it, nothing proved the server
  *sets* it. That is the recorded "the helper is tested and the wiring is not"
  pattern; two end-to-end tests in `nextgcore-sbi` now drive a real server with a
  real token and assert the handler observes the verified `sub`, and that an
  unverified bearer header does **not** become an identity.
- Two pre-existing tests pinned the defects and were **inverted, not deleted**,
  with comments recording the flip: one asserted `restricted[0]["sNssais"]`, and
  the availability-lifecycle test asserted the consumer's `2030-01-01` expiry was
  echoed back verbatim.
- Existing availability tests were updated to present an **attested identity**
  (what a real AMF does) rather than by weakening the check. The end-to-end HTTP
  lifecycle test cannot present a server-side identity, so it now **declares** the
  opt-out posture explicitly, serialised behind a posture guard so the
  process-global flag cannot race parallel tests.

### Flake I made more likely, stated plainly

During the first full-workspace run, `scpd`'s
`test_delegated_token_rejection_maps_to_403` failed with
`Address already in use (os error 98)`. That is the **probe-and-drop TOCTOU** in
the shared `nextgcore_sbi::test_support::free_port`, already recorded in
LEARNINGS: it binds a port to learn it is free, drops the listener, then hands the
port out, so another binder can take it in between. It did not reproduce in six
runs of `scpd` alone, nor in three subsequent full-workspace runs, and it is not
caused by this change — but my two new port-binding tests raise the pressure that
triggers it. The recorded remedy (a helper that **keeps** the binding) changes a
shared signature used across many crates and is not attempted here; it is worth
its own issue.

### Other verification ceilings

- The poisoned-lock path is verified by the extracted response plus a source
  guard, not by poisoning the real lock — see above for why.
- The 60 s run-loop sweep interval is not exercised by a test (no harness drives
  `run_event_loop_async`); `sweep_expired_subscriptions` itself is tested directly.
- GitNexus impact analysis was **not run**: no GitNexus MCP server is connected,
  so `nextgcore/CLAUDE.md`'s mandate remains unsatisfiable.

## Files

- `src/libs/nextgcore-sbi/src/message.rs` — `SbiRequest.oauth2_subject`
- `src/libs/nextgcore-sbi/src/server.rs` — `authorize` returns the verified `sub`;
  the server records it; two end-to-end plumbing tests
- `src/libs/nextgcore-sbi/src/datetime.rs` (new) + `lib.rs`
- `src/bins/nextgcore-nssfd/src/context.rs` — caller-bound authorization, expiry
  predicate, expiry-aware matching, sweep, `accepted_events`, the call-site guard
- `src/bins/nextgcore-nssfd/src/main.rs` — request-bound authz + fail-closed,
  OAuth2 default flip, create validation, restriction config, `sNssaiList`,
  locality members
- `src/bins/nextgcore-nssfd/src/nssf_sm.rs` — the validity handler now removes
- `docker/rust/configs/5gc/nssf.yaml`, `k8s/manifests/configmap.yaml`,
  `deploy/helm/nextgcore/templates/configmap.yaml` — explicit dev opt-out
- `docs-book/src/configuration/nssf.md`
