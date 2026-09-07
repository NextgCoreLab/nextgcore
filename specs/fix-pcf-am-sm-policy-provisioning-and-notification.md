# nextgcore #89 (PCF): the discarded AM update, the unprovisioned policy, the wrong SM envelope, and the missing BSF update

Verified against `main` @ `795ca81`. Every defect reproduced as described.

`Closes #89`.

## Gap 1: the AM policy Update was a no-op on the wire (criterion 1)

`handle_am_policy_update` deserialised the body into `let _update_data` and never
read it again, then answered a `PolicyAssociation`-shaped `{polAssoId, supi, triggers: []}`. So a
consumer could move its notification endpoint, change its GUAMI or ask for different triggers, and the PCF
would keep using the old ones while answering `200`.

Now the `PolicyAssociationUpdateRequest` is applied — `notificationUri` (with its alternate endpoints),
`guami`, `triggers` — the provisioned policy is **re-evaluated**, and the response is the type TS 29.507
defines for the `200`: a **`PolicyUpdate`**, carrying `resourceUri`. That URI is what lets a consumer
holding several associations correlate the answer, and it was absent entirely.

`amfId` is parsed from its 6 hex digits into the context's `AmfId` (region / set / pointer per
TS 23.003 §2.10.1); a malformed value leaves the stored GUAMI alone rather than zeroing it.

## Gap 2: the policy was never provisioned (criterion 2)

Create emitted `"servAreaRes": null` and `"rfsp": null` — values no `ServiceAreaRestriction` /
`RfspIndex` schema accepts, so a strict AMF's validator rejected the body — and the GET answered
`{polAssoId, supi, triggers: []}`, dropping the **mandatory** negotiated `suppFeat` along with every
policy member.

`provision_am_policy` reads the UDR's AM subscription data (a new
`pcf_udr_get_am_subscription_data` client) and provisions `ueAmbr`, `rfsp` and `servAreaRes` **as
present members only** — absent ones are simply not in the map, which is how the response stops emitting
nulls. Two validations, both refusing to forward a value the consumer would reject:

* `rfspIndex` outside `1..=256` is dropped, because outside that range it is not an `RfspIndex`.
* a `serviceAreaRestriction` with `restrictionType` **xor** `areas` is dropped: TS 29.571 makes them
  both-or-neither.

`ueAmbr` falls back to the local subscriber DB, which is where the pre-#89 code read it and all it can
supply.

One builder (`build_policy_association`) now renders both the create and the GET, so the two
representations of one resource cannot disagree again.

**What this core can actually provision.** nextgcore's own UDR am-data carries `subscribedUeAmbr`,
`gpsis` and `nssai` — **not** `rfspIndex` or `serviceAreaRestriction`, because the subscriber model has
no such fields. So against the real UDR those two are absent (never null), and the test that proves the
provisioning path supplies them from a mock UDR. Populating them for real is a UDR/subscriber-model
change, not a PCF one.

## Gap 3: notifications never fired, and were unreliable (criteria 3, 4)

`pcf_sbi_send_am_policy_control_notify` had **no caller** anywhere in the crate, hardcoded
`"triggers": []`, and delivered through a single fire-and-forget POST.

* **Wired**: an AM policy update that changes anything now invokes it.
* **Real body**: it POSTs the same `PolicyUpdate` the update returns, with the association's actual
  triggers. `triggers` is `nullable` with `minItems: 1` in the schema, so an **empty list is omitted**
  rather than sent as `[]` — an empty array is not a valid value there, and sending one is how the old
  body claimed "no triggers" while meaning "we never populated this".
* **Reliable** (TS 29.500 §6.10): three attempts per endpoint with 0/100/400 ms backoff, then each of the
  consumer's alternate endpoints in turn. A **4xx is not retried** — the consumer understood the request
  and rejected it, so resending the same bytes cannot help; only transport failures and 5xx are.
  Alternates come from `altNotifIpv4Addrs` / `altNotifIpv6Addrs` / `altNotifFqdns`, rendered with the
  primary's scheme and path so a retry hits the same resource on a different host (IPv6 literals
  bracketed).

The retry is exposed as `send_notification_reliably` so a caller that needs the outcome — or a test that
needs determinism — can await it instead of spawning.

## Gap 4: the SM policy GET had the wrong envelope (criterion 5)

It answered a flat `SmPolicyDecision`-shaped object with **no SUPI anywhere**. TS 29.512 §5.3 makes the
Individual SM Policy resource an `SmPolicyControl` whose two **required** members are `context`
(`SmPolicyContextData`) and `policy` (`SmPolicyDecision`), so a strict SMF could not parse it and never
learned whose session it was.

`context` now carries the session's real SUPI plus `pduSessionId`, `dnn`, `sliceInfo`, the UE addresses
and the notification URI; `policy` carries the decision.

## Gap 5: no BSF update on an IP change (criterion 6)

Only register and deregister existed, so a UE that changed IP left the BSF advertising a binding that no
longer matched — an AF-influenced lookup through the BSF then resolved the wrong session.
`pcf_update_bsf_binding` (`PATCH /pcfBindings/{bindingId}`, Nbsf_Management_Update, TS 29.521 §4.2.3)
plus `pcf_sess_update_bsf_binding`, called from the SM policy update when `ipv4Address` /
`ipv6AddressPrefix` differs from what the session holds.

The PATCH is sent as **`application/merge-patch+json`** (TS 29.521 §5.2). Our own bsfd tolerates
`application/json`, but a strict BSF answers `415` for it — and `client.patch_json` sends
`application/json`, so this would have been a latent interop failure invisible against our own peer.

## No feature gate for the corrected wire shapes

The issue suggests gating the AM/SM response-shape corrections behind `pcf-policy-conformant` for a
phased rollout. Rejected, per the recorded decision: a cargo feature puts its tests outside
`cargo test --workspace`, this repo's gate, so the conformant path would ship unexercised — and it is the
path a conformant peer needs. The shapes being corrected are ones a strict validator already rejects, so
there is no lenient peer to protect that is not already broken.

## Verification

* Workspace `cargo test`: **5884 passed, 0 failed** (from 5875). `cargo clippy -p nextgcore-pcfd
  --all-targets`: 0 warnings; workspace clippy: 0 errors. `cargo fmt --all --check`: clean. pcfd's suite
  run **6 consecutive times**, green each time.
* **Revert-verified**, each against the named test: discarding the update request, emitting `null` for
  `servAreaRes`, flattening the SM GET body → 4 tests fail; single-attempt notification with no
  alternates → the retry test fails; removing the BSF call site → the wiring test fails.
* **The revert pass found a real hole.** Deleting `pcf_sess_update_bsf_binding` from the SM update
  handler left every test green: the strict-peer test called the *client function* directly, so nothing
  covered the *call site*. That is the recorded "a tested helper leaves the wiring untested" lesson, and
  the fix is `sm_policy_update_wires_the_bsf_binding_update` — it drives the REAL create and update
  handlers and then reads the binding back out of the REAL bsfd, so only an update that actually reaches
  the BSF passes.
* The BSF legs are **strict-peer** against bsfd's real handler, not a mock, per the standing rule at the
  top of `tests/strict_peer_bsfd.rs`: a lenient BSF mock is what hid the missing-`pcfIpEndPoints` defect
  for months, and it would have accepted the wrong PATCH content type too.
* **A flake fixed on the way:** the NRF URI is process-global, so the two wire tests in
  `strict_peer_bsfd.rs` (and `discover_and_send_udr_mock` in the lib) raced — the loser discovered an
  NRF that the winner had already stopped and failed with connection-refused. All of them now serialize on
  the crate's existing `test_support::CONTEXT_GUARD` rather than a new private lock the other side would
  not know about.

## Not in scope

* Populating `rfspIndex` / `serviceAreaRestriction` in the subscriber model and the UDR's am-data (see
  above) — the PCF provisions whatever the UDR gives it.
* AM policy triggers beyond `UE_AMBR_CH` being *computed* by the PCF: consumer-requested triggers are
  applied and echoed, but only the AMBR mismatch is one this PCF detects on its own.
* Retry/alternate handling for the SM-policy and policy-authorization notifications: they now route
  through the same `spawn_notification` helper, so they inherit the retry; wiring their consumers'
  alternate endpoints through needs those requests' `altNotif*` members, which is a separate change.
