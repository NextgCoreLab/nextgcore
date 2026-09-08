# Fix bsfd Nbsf_Management: Subscribe/Unsubscribe/Notify, and a spec-clean surface

Closes nextgcore #98. Cites re-located against `main` at `6761ec8`.

## 1. The subscription surface (criteria 1–3, 5)

`/subscriptions` and `/subscriptions/{subId}` were entirely unrouted, falling
through to 405. The only thing resembling a subscription was a `bsfd-13` 501 stub
on `pcfBindings/{id}/subscriptions` — **a path TS 29.521 does not define** — so a
consumer that followed the spec got a 405 and one that followed the stub got a 501.

- `POST /subscriptions` → **201 + `Location`**.
- `PUT /subscriptions/{subId}` → **200** with the replacement, **404** unknown.
- `DELETE /subscriptions/{subId}` → **204**, **404** unknown.
- A defined resource reached with the wrong method answers 405 **with an `Allow`
  header** (the shared helper #229 added), rather than the bare 405 the
  fallthrough gave.
- The 501 stub is gone.

`BsfSubscription` requires **four** members — `events`, `notifUri`,
`notifCorreId`, `supi` — not the two a reader might assume. PUT parses through
exactly the same function as POST, so a replacement cannot skip a validation the
create enforced, and the `subId` is preserved so the resource URI the consumer
holds stays valid.

A `notifUri` that is not an absolute `http(s)` URI is refused **at ingress**,
where the consumer can see it, rather than failing silently at every notification.

## 2. Notify (criterion 4)

Nothing was emitted anywhere, so even a subscriber that existed received nothing.
Notifications now fire on all four transitions this BSF observes: PDU-session
binding register/deregister and UE binding register/deregister.

- **`BsfNotification`'s `oneOf`** is either `bindingIds` alone, or `notifCorreId`
  **and** `eventNotifs` together. The second form is emitted, so both members are
  always present — `eventNotifs` without `notifCorreId` satisfies neither branch.
- The notification carries the **binding identity** (`pcfForPduSessInfos` for a
  PDU-session binding, `pcfForUeInfo` for a UE binding), not just an id, so a
  consumer can tell **which** PCF now serves the session. That is the point of a
  PCF watching for a binding created by a different PCF. The two binding kinds use
  different members and using one for the other would misreport which resource
  changed.
- Only members actually held are emitted; a `pcfFqdn` the BSF does not have stays
  absent rather than being placeheld.
- **Matching is per-SUPI**, because `supi` is a *required* subscription member: a
  binding for another UE, an event the subscription did not request, a binding
  with no SUPI, and an expired subscription all match nothing. Fanning every change
  out to every subscriber would leak one UE's binding activity to a consumer
  watching another.
- **Only the four events with a producer are reportable.**
  `SNSSAI_DNN_BINDING_REGISTRATION`/`_DEREGISTRATION` have none — nothing here
  tracks an S-NSSAI/DNN binding as a resource distinct from the PDU-session
  binding — so a subscription naming *only* those is refused rather than accepted
  and never fired. An **unrecognised** token alongside a reportable one **is**
  accepted: `BsfEvent` is an `anyOf` over the enum plus a free-form string.
- Delivery is **fire-and-forget per subscriber** with bounded timeouts, so a
  subscriber that is down adds no latency to, and cannot fail, the binding CRUD
  that produced the event.
- The deregistration notification is emitted **after** the removal has happened,
  so a subscriber is never told a binding is gone while it is still discoverable;
  the session is read before removal because afterwards there is nothing left to
  describe it with.

## 3. Spec-clean surface (criteria 6–7)

- **`PcfBinding` no longer carries `expiry`.** TS 29.521's `PcfBinding` schema does
  not define one — `expiry` belongs to the **subscription** resource — so emitting
  it made every binding response fail strict schema validation. The value is still
  held on the session and still arms the TTL timer; it is simply not a wire member
  of this resource.
- **`GET /pcfBindings/{bindingId}` is no longer served.** The spec defines only
  `DELETE` and `PATCH` there. It answers **405 with `Allow: DELETE, PATCH`** rather
  than a bare 404, so a consumer learns the resource exists and which verbs it
  takes. Discovery via `GET /pcfBindings?...` is untouched.

The TTL expiry timer and its cleanup path are left intact, as the issue directs.

## Verification

- Workspace: **5938 tests pass, 0 fail**, across **three consecutive full-suite
  runs**; `cargo clippy --workspace` clean; `cargo fmt --all --check` clean.
- **18 behavioural claims individually revert-verified.**
- **Four pre-existing tests pinned the non-spec surface and were inverted, not
  deleted**, each with a comment recording the flip: the 501-stub test now asserts
  the stub is gone and the spec resource is served; two tests that asserted `200`
  from the undefined individual `GET` now assert it is refused; and a lifecycle
  test that used that `GET` as an existence probe after `DELETE` now confirms
  removal via a second `DELETE` returning 404 — the `GET` answers 405 whether or
  not the binding exists, so it can no longer serve as a probe.
- One revert did not bite and it was a **real weakness in my own test**: the
  "PcfBinding carries no `expiry`" assertion was satisfied trivially because the
  create body supplied no `expiry`, so `sess.expiry` was `None` and reinstating the
  bespoke insertion changed nothing. The test now supplies one, and the revert
  bites.

### Cross-crate consumers I should have grepped for first

Removing the individual `GET` broke **two pcfd strict-peer tests** that used it to
read a binding back after a PATCH. This is precisely the recorded lesson that a
correctness fix is a breaking change to whoever consumed the incorrect behaviour,
and the consumers live in a different crate — I found them from the
whole-workspace run rather than from a grep, which is the wrong order.

Both are repointed at **discovery by UE address**, which is the spec-defined read
and is also the *stronger* assertion: it proves the new address is **indexed** and
therefore findable by an AF, not merely stored on the record. A second, smaller
trap surfaced there too: those tests call `bsf_sbi_request_handler` directly, so
`http.params` is never populated from the query string (that happens in the
server's request conversion), and the parameters have to be set explicitly or
discovery sees no UE address and answers 400.

### Verification ceilings

- The notify round-trip is asserted end-to-end against a real stub consumer for
  the **PDU-session** binding events. The **UE**-binding events are wired and
  type-checked, and their matching is covered by the scoping test, but no test
  observes a UE-binding notification arriving at a callback.
- Subscriptions are **in-memory only**: they are not written to the durable
  snapshot, so they do not survive a restart. The issue asks that a subscription be
  "persisted"; the BSF's own binding persistence is itself best-effort and the
  daemon never initialises MongoDB (documented in `bsf.md`), so adding a durable
  subscription store would mean adopting that layer for a new resource. Called out
  rather than silently skipped.
- GitNexus impact analysis was **not run** — no MCP server connected.

## Files

- `src/bins/nextgcore-bsfd/src/context.rs` — `BsfSubscription`, its matching
  predicate, and the subscription store
- `src/bins/nextgcore-bsfd/src/lib.rs` — the `/subscriptions` routes and handlers,
  `spawn_bsf_notifications`, the two event-info builders, `split_notify_uri`,
  removal of the 501 stub, the bespoke `expiry` and the undefined individual `GET`
- `src/bins/nextgcore-pcfd/tests/strict_peer_bsfd.rs` — two consumers repointed at
  discovery
- `docs-book/src/configuration/bsf.md`
