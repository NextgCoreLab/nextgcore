# nextgcore #88 (PCF): the spec app-session delete, the fabricated 201, and the absent events / P-CSCF surfaces

Verified against `main` @ `2c7c589`. Every defect reproduced as described.

`Closes #88`.

## Gap 1: the spec deregistration was dispatched to create (criteria 1, 2)

The load-bearing defect. `("npcf-policyauthorization", "app-sessions", "POST")` carried **no path-depth
guard**, so `POST /app-sessions/{appSessionId}/delete` — TS 29.514 §4.2.4.2's own deregistration custom
operation — matched it. A conformant AF teardown therefore *created a second app session* and left the
original AF PCC rules installed on the UE's PDU session. `POST /app-sessions/pcscf-restoration` landed in
the same arm.

`route_policy_authorization` now matches on `(parts.len(), method)`, so every arm pins its exact depth and
`pcscf-restoration` is matched before anything treats `parts[3]` as an `appSessionId`. The non-spec bare
`DELETE /app-sessions/{id}` is kept: it predates the custom operation and is harmless.

## Gap 2: a binding failure was reported as success (criteria 3, 4, 5)

`handle_app_session_create` read only `ueIpv4`, and when nothing bound it minted
`uuid::Uuid::new_v4()`, stored no context, and answered **201 with a Location**. The AF believed
authorisation had succeeded while no PCC rule existed and the `appSessionId` it was handed was not
addressable — so it could neither retry nor fall back.

Now: validate first, then bind, then store.

* **`notifUri` and `suppFeat` are mandatory** and the UE address is a **`oneOf`** — zero *and* more than
  one are both `400` (TS 29.514 Table 5.7.3-1). `AscReqData` carries the three address members as three
  options rather than an enum precisely so "more than one" is reportable instead of silently resolved by
  picking the first.
* **An unbindable address is `403 PDU_SESSION_NOT_AVAILABLE`**, and the handler returns before anything is
  stored.
* **`ueIpv6` binds by prefix containment.** The AF sends a full address while a session holds a prefix, so
  an exact-string lookup against `ipv6prefix_hash` could never match — `sess_find_by_ipv6_ue_addr` scans
  and masks. The mask honours a non-byte-aligned prefix length: rounding up would reject a legitimate
  address, rounding down would bind the AF request to a neighbouring UE's session.
* **The SM policy create now reads `ipv6AddressPrefix`** (TS 29.512 `SmPolicyContextData`). It read only
  `ipv4Address`, so no session ever held an IPv6 prefix and `ueIpv6` binding could not have worked
  whatever the AF sent. Three lines, and the criterion is unreachable without them.

### `ueMac`: validated, and honestly unbindable

The criterion asks for `ueMac` to "resolve a session equivalently to `ueIpv4`". It cannot, and inventing a
way would be worse than saying so: **nothing in this tree ever sends a MAC address to the PCF** — no
`macAddr`/`ueMac` field exists in pcfd or smfd — so there is no session attribute to match against. Adding
one would be a field with no producer, the dead-code shape this repo's learnings warn about.

So `ueMac` is accepted as a valid `oneOf` member, validated like the others, and then **fails the binding**,
which TS 29.514 §4.2.2.2 answers with `403 PDU_SESSION_NOT_AVAILABLE` — the same answer a wireline
deployment would get from a PCF that has no such session. The test covers it alongside the two IP forms.
This is the deviation from the letter of the criterion, and it is deliberate.

## Gap 3: events-subscription and P-CSCF restoration did not exist (criteria 6, 7)

Neither had a router arm, a parser, or a handler; `evSubsc` was never read anywhere in `pcfd`.

**`PUT`/`DELETE /app-sessions/{id}/events-subscription`** (TS 29.514 §4.2.6). The `EventsSubscReqData` is
stored **verbatim** on the app session rather than parsed into fields: the PCF only needs to know which
events were subscribed and where to send them, and re-serialising a parsed copy would drop members a
future trigger may need. `events` is validated (`minItems: 1`, each entry needs an `event`) — a
subscription naming no event would be stored and then never match anything. `201` + `Location` on create,
`200` on modification.

**The trigger and the notification.** A resource allocation on create or modify delivers an
`EventsNotification` to `{notifUri}/notify`:
`SUCCESSFUL_RESOURCE_ALLOCATION` when the media components produced PCC rules, `RES_ALLO_FAILURE` when
they produced none. Those are the two outcomes this PCF can actually observe, and reporting the second as
the first would tell an IMS AF a bearer exists that does not. The notification goes to the
subscription's own `notifUri` when it carried one, else the app session's — the AF may point events at a
different endpoint. An event the AF did **not** subscribe to is not pushed, and the test proves the
silence after a `DELETE`.

**`POST /app-sessions/pcscf-restoration`** (TS 29.514 §4.2.5). `PcscfRestorationRequestData` is a `oneOf`
over `ueIpv4`/`ueIpv6`, so the UE is identified the same way an app session is; the PCF resolves that
session and pushes an SM policy update to its SMF, which is the mechanism it has for saying "this
session's policy changed" (TS 23.380 §5.4 has the network re-establish the IMS PDU session). `204`, as the
spec defines no response body. A UE address that resolves nothing is a **`404`**: a `204` would report a
restoration that did not happen.

### No feature gate

The issue suggests gating the events / P-CSCF work behind an off-by-default cargo feature. Rejected, per
the recorded decision: a cargo feature puts its tests outside `cargo test --workspace`, which is this
repo's gate, so the gated path would ship unexercised. And the risk the gate would manage does not exist
here — the new surfaces are new routes on paths that previously 404'd or were mis-routed, and the only
change to the stable create/modify path is that it now refuses what it used to fake.

## Two existing tests changed shape (not weakened)

Both pinned behaviour this issue calls a defect, which is the recorded "tests that pin the defect they
should have caught" pattern:

* `app_session_create_without_media_components_is_backward_compatible` sent an **unbindable** `ueIpv4` and
  asserted `201`. Its actual claim is about the response body shape, so the UE IP is now bound to a real
  session; the shape assertion is untouched and the fabrication is gone.
* `app_session_create_emergency_emits_asc_resp_data` sent **no UE address at all**. TS 29.514 requires one
  on every create, emergency included, so the body was non-conformant and only passed because nothing
  validated it. A bound `ueIpv4` was added; the `ascRespData` claim is untouched.

**A test-helper bug found on the way:** `make_request` folded every method that was not GET/DELETE into
**POST**, so a test asking for `PUT` or `PATCH` was silently routed as a POST. No existing test used either
— which also means the app-session `PATCH` arm had never been exercised through the router — and my first
events-subscription test failed with a `405` because of it. Every method is now mapped explicitly, and an
unsupported one panics rather than being quietly rewritten.

## Verification

* Workspace `cargo test`: **5875 passed, 0 failed** (from 5867). `cargo clippy -p nextgcore-pcfd
  --all-targets`: 0 warnings. `cargo fmt --all --check`: clean. pcfd's suite run **6 consecutive times**,
  green each time.
* **Revert-verified** — restoring the three defects (unguarded create arm, fabricated 201 on an unbindable
  address, no events notification) fails **6** of the 7 new tests, each on its own assertion.
* The events test captures the notification on a **real local AF listener** over HTTP rather than
  inspecting an intent, and declares the Dev SBI profile because the stub speaks plaintext h2c — without
  that the delivery count reads as "the PCF sent nothing", which is the recorded stub-transport lesson.
* Global `app_count()` assertions were deliberately **not** used: the PCF context is process-global and
  `cargo test` runs these in parallel, so a count would be another test's business. The tests assert on
  identity (`app_find_by_app_session_id`) and on observables a create cannot avoid (`201`, a `Location`
  header, an `appSessionId` in the body).

## Not in scope

* The remaining `AfEvent` values (`AC_TY_CH`, `PLMN_CH`, `QOS_NOTIF`, `USAGE_REPORT`, ...): each needs a
  trigger this PCF does not observe. The two implemented are the ones it can report truthfully.
* `GET /app-sessions/{id}/events-subscription`: not defined by the OpenAPI (PUT and DELETE only).
* Full P-CSCF restoration semantics — releasing and re-establishing the IMS PDU session — need an SM policy
  trigger this PCF does not model. What it does is notify the serving SMF, and the doc comment says so.
