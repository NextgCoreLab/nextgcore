# nextgcore #68 (NRF): SubscrCond matching, HAL NF list, Bootstrapping, PUT event

Verified against `main` @ `d2b0304`. The issue's cites are from `76ea248` and PR #219 moved most of
them again, so every site was re-located before being touched.

`Closes #68`. This ships the four gaps PR #219 left open, and with them the whole issue. #219 shipped
criteria 1–3 and 8 (subscription PATCH, suspend notification, timers re-armed on restore); this ships
criteria 4, 5, 6, 7 and 9.

## Gap: `SubscrCond` collapsed to match-all (criterion 5)

The worst of the four, and not a wire-shape problem — a delivery one.

`SubscrCond` is a `oneOf` over **17** condition schemas (TS 29.510 §5.2.2.5.2). The old model was a
three-field struct — `nfType`, `serviceName`, `nfInstanceId` — populated by reading those three keys
out of whatever object arrived. A conformant `NfSetCond`, `AmfCond`, `NfGroupCond`,
`NetworkSliceCond`, `GuamiListCond`, `ScpDomainCond` or any of the `conditionType`-tagged conditions
carries **none** of those three keys, so it parsed to a condition with all three fields `None`.
`subscription_matches` then fell through every `if let` and returned `true`.

So a subscriber that asked for one NF set received a notification for **every NF in the registry** —
and it looked like it was working, because notifications arrived.

The model is now the discriminator plus the condition object verbatim:

```rust
pub struct SubscrCond { pub kind: SubscrCondKind, pub raw: serde_json::Value }
```

Keeping `raw` rather than re-flattening is the same shape as the recorded decision to store a
received JSON object as-is and match on a canonical key. It also fixes a quieter bug: the 201 body
used to be rebuilt from the three parsed fields, so a consumer reading back its own subscription saw
a condition narrower than the one it sent.

`subscr_cond_matches` has **no catch-all `=> true` arm**. Every one of the 17 arms compares real
criteria against the profile document the NRF already stores verbatim in `NfProfile::attributes`,
which is what makes the deep conditions matchable at all (`amfInfo.guamiList`, `nfSetIdList`,
`sNssais`, `nwdafInfo.taiRangeList`, the per-type `*Info.groupId`).

Three decisions inside that are worth review:

* **A condition this NRF cannot evaluate is refused at subscribe time with 400, not accepted.**
  Two criteria fall in this bucket. `UpfCond.taiList`: TS 29.510 `UpfInfo` carries `smfServingArea`,
  `sNssaiUpfInfoList` and `interfaceUpfInfoList` and **no TAI list**, so a UPF profile holds nothing
  to compare a TAI against — the condition's prose promises something its own profile schema does not
  supply, which is the recorded "29.5xx disagrees with itself" pattern again. And `NefCond`'s
  AF/identifier-range criteria, which match against nested `gpsiRanges` /
  `externalGroupIdentifiersRanges` structures. Accepting either would leave only silent options:
  notify for every NF, or for none. A visible refusal naming the criterion (`cause:
  SUBSCR_COND_NOT_SUPPORTED`) is the honest one, and it follows the recorded principle that an NF
  should advertise only what it can actually serve. **This is a deliberate deviation**: those
  conditions are spec-valid and we answer 400. Criterion 5 explicitly permits it ("or rejects
  unknown/malformed conditions with 400"), but it is the judgement most worth a second opinion.
* **A `conditionType`-tagged condition is restricted to the NF type it names.** `UPF_COND` must not
  match an AMF merely because the AMF carries no `upfInfo` to contradict it. Without this the
  match-all hole reopens for exactly the four conditions whose criteria are all optional.
* **A pattern-only `TacRange` does not match.** `TacRange` is `start`/`end` **or** `pattern`; the
  pattern form is not evaluated, and treating an unevaluated pattern as a hit would widen the serving
  area to everything — the failure mode this change exists to remove. Failing closed on one range
  form is the recoverable direction; failing open reintroduces the bug.

The identity comparators compare significant members rather than whole JSON values, because an
insignificant spelling difference must not make two identical values differ: `sd` absent ≡ `sd:
"ffffff"` (TS 23.003: no differentiator), TAC `"0001"` ≡ `"1"` (hex, 3–4 digits), hex case ignored for
`sd`/`tac`/`amfId`, and a stray `nid` on one side of a PLMN ignored.

## Gap: `reqNotifEvents` and `notifCondition` dropped on parse (criterion 4)

Both were parsed nowhere, so a subscriber that asked only for `NF_DEREGISTERED` still received every
registration and profile change, and `notifCondition` had no effect at all. Both are now parsed,
persisted, echoed, and **enforced at all four notify-all call sites** — enforcing at one and not the
others would have been the same bug with a smaller blast radius.

`notifCondition` is expressed over top-level NFProfile attributes, so an RFC 6902 path is reduced to
its first segment (`/nfServices/0/priority` → `nfServices`). A change touching several attributes is
notified when **any** is monitored; dropping it would lose a change the subscriber asked for. An empty
change list is not narrowed, because a complete-replacement notification carries the profile instead
of a change list.

The schema's `not: required: [monitoredAttributes, unmonitoredAttributes]` is enforced: a body
carrying both is a 400 rather than silently resolved in one direction.

## Gap: `validityTime` read as an integer duration (criterion 4)

`validityTime` is a `DateTime` string. The create path read it with `as_u64`, so **every conformant
proposal silently fell through to the 24h default** — the consumer's request had no observable effect.
It is now parsed as RFC 3339 (reusing `rfc3339_to_epoch`, added by #219 for the PATCH path), clamped
to the NRF's own maximum so a consumer cannot pin a subscription open indefinitely, and a
non-conformant form — a bare integer, a malformed string, a past time — is a 400.

Rejecting the integer form is a behaviour change for any out-of-tree consumer that was relying on the
wrong reading. Nothing in this tree sends it (`nwdafd` only ever *reads* `validityTime`, and reads it
as RFC 3339 already), and the spec type is unambiguous.

## Gap: `GET /nf-instances` was neither HAL nor filtered (criterion 6)

Three things wrong, all invisible to a lenient client: the media type was `application/json` rather
than `application/3gppHal+json`; `_links` carried bare strings under a mis-spelled `items` (the
`UriList` schema names it `item`, and the values are `LinksValueSchema` — `{ href }` objects); and the
`nf-type`/`limit`/`page` parameters were ignored outright, the request being bound as `_request`. A
consumer paging a large registry silently received the whole list on every page.

Now: correct media type, `item` as an array of `Link` objects, `self` as a `Link`, `totalItemCount`
over the **filtered** set so a consumer can tell how many pages remain, and the three parameters
applied.

Two judgement calls: results are **sorted by instance id** before paging, because without a total
order two requests for page 2 can return different overlapping sets from the same registry (the
backing store is a `HashMap`); and an **unusable `limit`/`page` is a 400, not an ignored parameter** —
ignoring it returns a page the consumer did not ask for and cannot detect, which is precisely the old
behaviour. `page` without `limit` is refused for the same reason.

## Gap: no Bootstrapping service (criterion 7)

`GET /bootstrapping` has a single path segment, so it never reached the service match — it fell out at
the `parts.len() < 3` guard as a 404. It is now matched ahead of that guard and returns
`BootstrappingInfo` in `application/3gppHal+json`, with the six registered relation types of Table
6.4.6.3.3.1-1 (`self`, `manage`, `subscribe`, `discover`, `authorize`, `retrieve-key`) as absolute
hrefs, plus `ETag`/`Cache-Control`.

`oauth2Required` reports `require_oauth2_server` — the posture actually enforced — rather than a
literal, so the answer cannot drift from behaviour.

**Served unconditionally, not behind the feature gate the issue suggests.** §5.5 makes the service
optional and the issue floats an off-default gate; both a cargo feature and an off-by-default switch
were rejected. A cargo feature would put the tests outside `cargo test --workspace`, which is the CI
gate, so the code would ship unexercised. An off-by-default runtime switch would leave the gap open
for every deployment that did not know to flip it. The endpoint is read-only and publishes only what
an unauthenticated peer must be able to read for bootstrapping to mean anything. `/bootstrapping` is
outside `oauth2_protected_path`, so it stays reachable when server-side OAuth2 is on — required, since
a consumer reads this document to *find* the token endpoint. A test asserts that non-gating directly.

`If-None-Match` is honoured with a 304. The yaml declares the parameter but does not enumerate a 304
response; the parameter has no other purpose, so the conditional is answered rather than accepted and
ignored. The `ETag` is FNV-1a over the body, deliberately not `DefaultHasher` — that is documented as
unstable across Rust releases and would silently invalidate every cached document on a toolchain bump.

## Gap: a `PUT` replacement announced itself as a new registration (criterion 9)

`handle_nf_register` always dispatched `NF_REGISTERED`, even when `is_new == false`. TS 29.510
§5.2.2.3.1A: a complete replacement is a change, not an appearance. Subscribers were told a producer
had just appeared that had been registered all along — which is what a consumer's "new NF available"
handling keys on.

## Verification

**32 new tests** (9 in `sbi_path`, 10 in `main`, 13 more assertion groups inside those). Workspace
`cargo test --workspace` **green**; `cargo clippy --workspace` (the CI gate) clean with **zero**
warnings; `cargo fmt --all --check` clean.

**Revert-verified: 21 reverts, 21 bit.** Each fix was individually undone and the named test watched
to fail, then restored — including both halves of the `PUT` event fix separately (the mapping
function *and* the handler passing `is_new`, since testing only the mapping would leave the part that
was actually wrong unpinned), and the paging sort, re-run three times because a missing sort could
otherwise pass on map order. Full list in the PR body.

The `PUT`-replacement test is **end-to-end over a real HTTP/2 subscriber**, not a unit test of the
event mapping: the notification is delivered by a `tokio::spawn`ed call, so the only way to observe
which event the handler chose is to be the subscriber and read it off the wire.

Two tests register profiles under a deliberately non-spec `nfType` (`NRFD68-HAL-LIST`,
`NRFD68-PUT-EVENT`). `nf_manager()` is process-global and other tests in the same binary write to it;
a unique type is what keeps the assertions from being perturbed, per the recorded
process-global-state learning. It is a test fixture, not a wire claim.

**One pre-existing clippy warning fixed in passing** (`main.rs` `needless_borrows_for_generic_args`,
introduced by #219 in a test this change sits next to).

**Not verified:** no live consumer, NF or restart was exercised beyond the in-process HTTP/2 server.
The `reqNotifEvents` and `notifCondition` gates are pinned at the predicate and at all four call
sites, but no test drives a real subscriber through a filtered notification, so their end-to-end
behaviour rests on the call-site wiring being read correctly rather than observed. Docker E2E is
skipped by CI. GitNexus impact analysis, which CLAUDE.md mandates, was **not run** — no MCP server is
connected, so that mandate is currently unsatisfiable and this is the eighth consecutive PR to record
it.
