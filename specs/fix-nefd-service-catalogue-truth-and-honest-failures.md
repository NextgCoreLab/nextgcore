# nextgcore #111 (nefd): serve the advertised service, stop fabricating success, stop masking failure

Verified against `main` @ `71418a5`. The issue was written at `76ea248`; every cite was re-located
(line numbers have drifted) and all three defects still hold.

## Verified against current main

| claim in the issue | site on `71418a5` | still true? |
|---|---|---|
| the profile advertises `nnef-eventexposure` | `build_nf_profile` → `"serviceName": "nnef-eventexposure"`; self-instance built with `SbiServiceType::NnefEventexposure` | yes |
| no AF-facing `nnef-eventexposure` route; only the producer sink | router had three arms; `["nnef-eventexposure","v1","notify",id]` was the only one under that root, so `POST .../subscriptions` hit the `send_not_found` fallthrough | yes |
| Device Triggering fabricates `TRIGGERED` | `NefTriggerTransaction::new(scs_as_id, "TRIGGERED", ..)` plus a second `"TRIGGERED"` literal echoed into the body | yes — **two** literals, which is worse than the issue says |
| southbound failure masked on create | `attempt_southbound_subscribe` returned `Option<SouthboundRef>`; `None` covered four distinct causes and the caller returned `201` for all of them | yes |

## Decision 1: implement the advertised service rather than stop advertising it

Criterion 2 sanctions either. Implemented, because the alternative is worse here: the
`/nnef-eventexposure/v1/notify/{id}` path is a **callback the NEF hands to producers**, not a service
it offers, so dropping the advertisement would have left the NEF advertising nothing over SBI while
the machinery to serve something already existed. `POST/DELETE /nnef-eventexposure/v1/subscriptions`
now exists.

**It is one subscription, not two.** `handle_nnef_event_exposure_create` validates the TS 29.591
mandatory IEs (`notifUri`, `notifId`, `nefEventSubs[].eventId`), maps the event onto the equivalent
TS 29.122 MonitoringType, and hands the translated body to the **same** create handler, which is now
parameterised on a `NorthboundApi`. That parameterisation is the point: the failure semantics below,
the anyUE guard from #110 and the target resolution apply to both APIs by construction rather than by
being reimplemented and drifting.

An `eventId` outside the served set is **`501` naming it**, and a multi-event request is `501` too
(one southbound leg per subscription, so serving only the first would be the fabricated-success shape
this issue exists to remove).

## Decision 2: `deliveryResult` becomes `UNKNOWN`, from one constant

`TRIGGERED` is a **positive** lifecycle state in TS 29.122 §5.10 — the trigger was accepted for
delivery. Reporting it with no delivery path told the AF the message was on its way and left it unable
to distinguish "queued" from "silently dropped", which is the failure device triggering exists to
prevent. `UNKNOWN` is the honest value: the transaction was accepted and stored, and the NEF genuinely
does not know an outcome it never attempted.

`DEVICE_TRIGGERING_STUB_RESULT` is one constant because there were **two** separate `"TRIGGERED"`
literals — the stored transaction and the echoed body — so a fix applied to one would have left the
other claiming success. The test now asserts they agree.

The issue suggests a `device-triggering-stub` feature gate. Not added: a gate whose off-state is
"return `501`" adds a build configuration to protect against a value that is now correct in every
build. `UNKNOWN` cannot ship fabricated success, which is what the gate was for.

## Decision 3: `Option` → a three-way outcome, and only one of the three is accepted

`attempt_southbound_subscribe` now returns `SouthboundOutcome`:

| outcome | cause | northbound |
|---|---|---|
| `Live(ref)` | producer accepted, id extractable | `201`, subscription live |
| `Deferred` | **no producer URI configured** | `201`, leg retained as `pending`, reconciler retries |
| `Failed { retryable, detail }` | attempted and cannot be established | `503` retryable / `500` not, cause `SUBSCRIPTION_NOT_ESTABLISHED` |

The split that matters is `Deferred` vs `Failed`: a deployment that has not wired its AMF/UDM yet is a
**configuration state**, not a request error, so rejecting it would break the shipped default. A
producer that was asked and could not deliver is a request the NEF cannot honour.

`retryable` picks the status: a transport failure is the NEF's dependency being unavailable (`503`), a
producer answering unusably is `500`. Both are TS 29.500 §5.2.7 statuses; neither is `201`.

Note the fourth cause the old `None` also covered — **the producer accepted and returned no
extractable subscription id** — is now `Failed`, not success. Accepting it would have orphaned a
producer-side subscription the NEF can never unsubscribe *and* left the AF unable to delete it.

## Decision 4: a deferred leg is expired, not retried forever

`PendingSouthbound` retains the built subscribe request plus `since`. `reconcile_pending_subscriptions`
sweeps them, promotes any that reach their producer, and **expires** — removes — any past
`NEF_PENDING_LEG_DEADLINE_SECS` (default 300).

Expiry removes the subscription because an AF whose subscription is *gone* can re-create it, whereas
one holding a subscription that will never notify has no signal at all. That is the same reasoning as
rejecting a hard failure at create time, applied to the deferred case.

The sweep returns a `ReconcileReport` rather than only logging, so it is assertable without waiting on
a timer. A promotion that finds the subscription deleted mid-retry unsubscribes the producer leg rather
than orphaning it.

## Acceptance criteria

- [x] Advertised service names match the mounted routes; a test asserts no advertised service resolves
      to `send_not_found` — `every_advertised_service_name_has_a_northbound_route` walks
      `build_nf_profile`'s `nfServices` and drives each through the real router, asserting `!= 404`. It
      posts a deliberately-invalid body so it tests **routing**, not validation: a `400` proves a route
      exists and rejected the body, where a `404` would prove nothing is mounted.
- [x] `POST /nnef-eventexposure/v1/subscriptions` returns a spec-shaped response —
      `nnef_event_exposure_subscribe_is_served_and_unsupported_events_are_refused`: `201` with a
      Location under the API it was created on, DELETE-able through the same API, `501` naming an
      unsupported `eventId`, and `400` for each missing mandatory IE.
- [x] Device Triggering no longer reports `TRIGGERED` — the pre-existing test **pinned the defect** and
      was inverted with the flip recorded at the assertion; it now also asserts the stored and echoed
      values agree.
- [x] A create whose southbound producer is unreachable does not return `201` —
      `a_southbound_failure_is_not_reported_as_created` (`503`, cause asserted, and no subscription
      left behind), plus `southbound_failure_statuses_distinguish_transient_from_unusable` for the
      `500`/`503` mapping.
- [x] A reconciler exists for deferred legs —
      `a_deferred_leg_is_pending_and_the_reconciler_expires_it`: accepted as `201` and marked pending,
      still pending inside the deadline (retried, not discarded on first failure), **expired and
      removed** past it, and a no-op sweep when nothing is pending.
- [x] `cargo test -p nextgcore-nefd` and workspace clippy pass.

## Verification

Workspace **6000 passed / 0 failed / 6 ignored** (baseline `5995` on `71418a5`; +5 tests, nefd 52 →
57). `cargo clippy -p nextgcore-nefd --all-targets` clean (zero warnings), `cargo clippy --workspace`
0 errors, `cargo fmt --all -- --check` clean.

Five reverts:

| revert | expected to break | result |
|---|---|---|
| a `Failed` leg is stored instead of rejected | `a_southbound_failure_is_not_reported_as_created` | **1 failed** |
| `DEVICE_TRIGGERING_STUB_RESULT` back to `"TRIGGERED"` | `device_triggering_create_returns_201_with_transaction` | **1 failed** (`a positive lifecycle state must not be reported`) |
| a `Deferred` leg is not retained | `a_deferred_leg_is_pending_and_the_reconciler_expires_it` | **1 failed** (`the leg must be retained for retry`) |
| the reconciler never expires a stale leg | same test | **1 failed** (`a leg past its deadline must be expired`) |
| the `nnef-eventexposure` subscriptions route removed | catalogue-truth + subscribe tests | **2 failed** (`advertised service 'nnef-eventexposure' has no northbound route (got 404)`) |

**Two test-infrastructure defects this work exposed, both process-global-state hazards.** They cost
real time and match the learning recorded earlier today almost exactly:

1. **`reset_context` did not clear the southbound producer URIs.** The first test to point the context
   at a producer leaked it into every later test, which then attempted a real HTTP call and **panicked
   inside the SBI client**. Six pre-existing tests failed that way. `reset_context` now clears the
   endpoints — the hazard appeared the moment a second party touched the shared thing, which is the
   recorded shape.
2. **The shared `block_on` helper had no timer/IO drivers**, with a doc comment justifying it as "the
   handlers under test do no real I/O (no producer URIs are configured)" — true until a test configured
   one, at which point `tokio::time::timeout` panicked with *"timers are disabled"* rather than
   returning a connection error. Enabling the drivers costs nothing and removes the class.

Also worth recording: the first draft of the failure test asserted `500` for a syntactically odd
producer URI, on the assumption it would fail to parse. `parse_host_port` **accepts** it (host plus a
default port) and the connect then fails, so it lands on `503`. The test now asserts what the code
does and says why, rather than what I assumed the branch was.

## Ceilings

* **The `Nnef_EventExposure` surface is minimal and says so.** Three event IDs are served
  (`LOCATION_REPORT`, `UE_REACHABILITY`, `LOSS_OF_CONNECTIVITY`) because those are what the T8 side and
  the southbound machinery support; everything else is `501` **by name**. One event per subscription,
  also `501`. That is honest but it is not the whole of TS 29.591: no `PATCH`, no subscription
  retrieval, no `supportedFeatures` negotiation, and the response echoes the translated body rather
  than a `NefEventExposureSubsc` re-serialisation.
* **`notifId` is reused as the ownership key** for the Nnef API, standing in for T8's `{scsAsId}` path
  segment because the TS 29.591 path carries no consumer identity. With northbound auth configured the
  authenticated owner still wins (#110); without it, ownership degrades to the `notifId` the consumer
  supplied, which is a routing-level check and not a security one — the same caveat #110 documented for
  `scsAsId`.
* **The reconciler retries on a fixed interval with no backoff**, and treats "still unreachable" and
  "now failing outright" identically because the clock that matters is how long the AF has held an
  un-notifiable subscription. A producer that starts rejecting after a deferral is therefore retried
  until the deadline rather than failed fast.
* **The reconciler is never driven in a test through its spawned loop** — only by calling
  `reconcile_pending_subscriptions` directly. The `tokio::spawn` in `run()` is unverified, the same
  ceiling every spawned worker in this tree has.
* **Device Triggering still has no delivery leg.** `UNKNOWN` is honest, not fixed: there is no SMSF/T4
  path, and this change does not add one. An AF gets a truthful "I don't know" instead of a false
  "queued".
* **No test drives a live producer**, so `Live` is exercised only by the promotion path's absence — the
  promote branch of the reconciler and `subscription_promote` are covered by construction (the code is
  reached when a producer answers) but not by a test with a stub AMF. That is the largest untested
  branch in this change.
* GitNexus impact analysis unrunnable (no MCP server connected — 45th consecutive PR). Blast radius by
  grep: `attempt_southbound_subscribe` has two callers (the create handler and the reconciler),
  `handle_monitoring_subscription_create` has three (two router arms and the Nnef translation), and
  `NefMonitoringSubscription`'s new field is `#[serde(default)]` so an existing state file loads.
