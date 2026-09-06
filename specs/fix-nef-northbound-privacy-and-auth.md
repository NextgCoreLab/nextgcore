# nextgcore #110 (NEF): stop leaking the SUPI, stop widening to anyUE, authenticate the northbound surface

Verified against `main` @ `ad24340`. The issue's line cites are from `76ea2481`; nefd has
changed since (#197 added persistence), so every cite below was re-verified.

Closes #110. Severity: **critical** — the only open issue where a permanent subscriber
identifier crosses the operator trust boundary to a third party, which is the same class
as #118 and why the production-readiness criterion ranks it first.

## The three defects, re-verified against current main

**1. Scope widening to `anyUE`.** `build_southbound_subscribe` takes `supi`, `msisdn` and
`external_id`, but its AMF arm reads **only `supi`** and does
`match supi { Some(s) => subscription["supi"] = s, None => subscription["anyUE"] = true }`
(`main.rs:670-673`). `msisdn`/`external_id` are accepted by the signature and never used
on that path. So an AF that names one UE by `msisdn` or `externalId` — both valid TS
29.122 targets — gets a **network-wide feed for every UE**. The UDM arm has the same shape
via its `.unwrap_or_else(|| "anyUE")` ueIdentity fallback (`main.rs:687`).

**2. SUPI exposure to AFs.** `build_monitoring_notification` copies the producer report's
`supi` verbatim into the AF-bound TS 29.122 `MonitoringNotification` (`main.rs:854-858`),
with an inline comment admitting no SUPI→GPSI mapping exists, and
`forward_notification_to_af` POSTs it unchanged (`main.rs:873-893`). **A test currently
pins the leak**: `build_monitoring_notification_maps_amf_reports` asserts
`report["supi"] == "imsi-001010000000001"` (`main.rs:1675`).

**3. No northbound authN/authZ.** No OAuth2 anywhere; TLS is opt-in and server-cert only
with `verify_client` never set (`main.rs:237-247`). `{scsAsId}` is taken straight from the
URL path (`main.rs:308-320`) and the delete ownership check compares only against that
spoofable segment (`main.rs:499`), so any caller can delete another AF's subscriptions by
naming their `scsAsId`. The module doc admits it (`main.rs:5-7`).

## Two blockers the issue's suggested approach does not account for

**There is no GPSI→SUPI resolution anywhere in this repo.** The issue says to resolve via
UDM. `udmd` *routes* `id-translation-result` but returns **501 not implemented**
(`bins/nextgcore-udmd/src/app.rs:641-642`, tagged `udmd-12`), and the in-repo
`docs/openapi/nudm-sdm.yaml` is a trimmed subset that does not define the operation at
all. Implementing the UDM side belongs to #85 (`udmd`: unrouted Nudm services), not here.

This does **not** block the security fix, and that distinction is the whole design:

| defect | needs UDM? |
|---|---|
| anyUE widening | **no** — stop deriving scope from *absence* of an identity |
| SUPI leak | **no** — substitute the GPSI **the AF itself supplied**, already on the record |
| no authN/authZ | **no** |
| *making* msisdn/externalId targeting functional | yes |

So all three defects close now. nefd gains the resolver and calls it; when UDM cannot
resolve (including our own udmd's 501) the northbound create is **rejected** and no
southbound subscribe is issued — which is criterion 2's exact requirement. Against this
repo's own UDM that means GPSI-targeted monitoring answers an honest error instead of a
covert surveillance feed. Filed as a follow-up dependency on #85.

**Criterion 6 mentions "read"; there is no read operation.** The router serves POST and
DELETE on subscriptions only — no GET. The missing GET belongs to #111 (advertised
Nnef_EventExposure unrouted), so this PR does not add one; the auth gate covers every
route that exists, and will cover a GET the moment #111 adds it.

## The change

### Widening becomes structurally impossible, not merely gated

Rather than keeping the `None => anyUE` arm and guarding the caller, the target becomes an
explicit enum:

```rust
enum SouthboundTarget { Supi(String), AnyUe }
```

`build_southbound_subscribe` takes it by value, so "no identity" is **not representable**
and a caller must *choose* `AnyUe`. That is stronger than a handler-side check, which a
later refactor could bypass, and it satisfies criterion 3's wording literally: `anyUE` is
now reachable only from an explicit request for it.

This also settles a question the issue leaves open — *what does "the AF explicitly
requested any-UE scope" mean northbound?* For `LOCATION_REPORTING` / `UE_REACHABILITY` /
`LOSS_OF_CONNECTIVITY`, **TS 29.122 has no any-UE form**: these are per-UE monitoring
types and the target is mandatory. So the northbound handler never constructs `AnyUe`, and
a request with no resolvable target is `400 MANDATORY_IE_MISSING`. `externalGroupId` (TS
29.122's *group* form) is rejected as unsupported rather than silently widened — mapping
it to TS 29.518 `groupId` needs a group→internal mapping this repo does not have, and
inventing one is how the original defect happened. Filed as a follow-up.

The `AnyUe` variant is kept rather than deleted because it is a faithful TS 29.518
encoding that a future group/any-UE feature will need; the existing translation tests stay
valid and simply pass `AnyUe` explicitly. (Deleting it was the alternative; keeping a
correct encoder and removing the *implicit path to it* is the smaller, truer change.)

### The SUPI never reaches the AF

`build_monitoring_notification` stops copying `supi`. It substitutes the **GPSI the AF
itself used**, which requires no lookup because the NEF already stores the original
request: `NefMonitoringSubscription.raw` holds the AF's `MonitoringEventSubscription`
verbatim. The subscription record gains a parsed `af_target` so the notification path does
not re-parse `raw` per report.

If the AF supplied no external identity (it targeted by the NextGCore `supi` extension),
the identity field is **omitted** rather than filled with the SUPI — the AF already knows
which UE it asked about, and the subscription's `self` link identifies the subscription.

A guard test asserts the serialised outbound body contains no `supi` key on any path.

### Northbound authentication, and identity that is not caller-supplied

* OAuth2 producer verification ported from the `dccfd`/`nwdafd` pattern
  (`oauth2_required()` + `apply_oauth2_enforcement`), audience scoped to `NEF`, enabled by
  `NEXTGCORE_SBI_OAUTH2_REQUIRE` or `nef.sbi.oauth2.require`.
* mTLS via the existing `SbiServerConfig::verify_client` / `verify_client_cacert`.
* **The owning client identity comes from the authenticated credential, not the URL.**
  #195 already surfaces the verified peer certificate's NF instance ID as
  `SbiRequest.peer_cert_nf_instance_id` (`libs/nextgcore-sbi/src/message.rs:424`,
  populated at `server.rs:917-933`), so the ownership check prefers that, then the
  token subject, and falls back to the path `{scsAsId}` **only when no authentication is
  configured at all**. Create records the authenticated identity; delete compares against
  it, so client A supplying B's `{scsAsId}` gets 404.

**Default-off, deliberately.** OAuth2/mTLS follow the sibling-NF default-off staging the
issue's own "Feature-gating" section allows, so the matched-sim E2E stays byte-unchanged.
The SUPI stripping and the anyUE fix are **unconditional** — they are privacy corrections,
not optional capabilities, exactly as the issue directs.

## Verification plan

Per-criterion tests, all in `bins/nextgcore-nefd/src/main.rs`:

1. `msisdn_target_resolves_to_supi_and_never_any_ue` — resolved GPSI produces `supi`, no
   `anyUE` key.
2. `an_unresolvable_gpsi_is_rejected_and_issues_no_southbound_subscribe`.
3. `no_northbound_input_can_produce_any_ue` — the structural claim: every target-shaped
   input (absent, msisdn, externalId, supi, externalGroupId) either resolves to a `Supi`
   or is a 400.
4. `af_bound_notification_never_contains_supi` — drives a producer report carrying `supi`
   through `build_monitoring_notification` and asserts no `supi` key in the serialised
   body, plus the AF's own GPSI where one was supplied.
5. `unauthenticated_requests_are_refused_when_enforcement_is_on` — 401/403 on every route.
6. `ownership_is_derived_from_the_authenticated_identity` — A cannot delete B's
   subscription while supplying B's `{scsAsId}`.
7. Workspace clippy + the nefd suite pass.

Plus revert-verification on the two privacy fixes, since those are the ones a later edit
could silently undo.

## Verification (actual)

Nine new tests; workspace **5696 passed / 0 failed**, `cargo test --workspace` exit 0, no
compile errors (checked for `^error`, not only for a `test result:` line). `cargo fmt --all
--check` clean; `cargo clippy --workspace --all-targets` exit 0 with no warning in nefd.

**Two existing tests pinned the defects and were inverted, not deleted:**

* `build_monitoring_notification_maps_amf_reports` asserted
  `report["supi"] == "imsi-001010000000001"` — a permanent subscriber identifier crossing
  the operator trust boundary was a *tested expectation*. It now asserts the opposite plus
  the echoed AF identity.
* `loss_of_connectivity_ue_identity_fallbacks` asserted that no identity produced
  `/nudm-ee/v1/anyUE/...`, i.e. it pinned "absence of an identity means every UE". Replaced
  by `loss_of_connectivity_uses_the_resolved_supi_not_a_gpsi`, since GPSI handling moved
  out of the builder.

**Revert-verified (three claims, each checked by making the change and watching the named
test fail):**

| revert | test that fails |
|---|---|
| restore `out["supi"] = supi.clone()` | `build_monitoring_notification_maps_amf_reports` **and** `af_bound_notification_never_contains_supi` |
| restore `None => SouthboundTarget::AnyUe` | `no_northbound_input_can_produce_any_ue` |
| drop the `auth.oauth2` guard on reading `sub` | `a_bearer_subject_is_trusted_only_under_enforcement` |

That last one matters most: without the guard, `authenticated_client_id` becomes an
impersonation primitive — an unauthenticated caller sets any `sub` it likes and owns
another client's subscriptions.

Criterion 5 is tested against a **mounted server**, not by calling handlers: nefd's
handlers never check a token, because nextgcore-sbi answers 401 before dispatch. A
handler-level test could not observe the property at all.

**One test bug caught in review, worth recording.** The first version of
`no_northbound_input_can_produce_any_ue` checked only `built.body` for `anyUE`. The AMF
carries the identity in the body but the **UDM carries it in the resource path**
(`/nudm-ee/v1/{supi}/...`), so an `anyUE` on the UDM surface would have passed unseen. It
now checks path and body together.

**Not verified:** no AF or UDM was involved — the resolver's success path is tested against
the TS 29.503 response *shape*, not a live UDM (there is none that implements it). No mTLS
handshake was performed: `is_owned_by` is tested directly because a unit test cannot mint a
verified peer certificate, so the cert-identity plumbing is covered by #195's tests plus
reading, not by execution here. CI skips the Docker E2E.

## Definition of done

- [x] `anyUE` unreachable from northbound input, enforced by the type, not a check
- [x] AF-bound notifications carry no `supi` on any path
- [x] Every existing route rejects unauthenticated callers when enforcement is on
- [x] Ownership derived from the authenticated credential, not `{scsAsId}`
- [x] GPSI resolution attempted via TS 29.503 `id-translation-result`; failure rejects
- [x] Docs updated; the udmd-501 dependency and the `externalGroupId` gap recorded

## Follow-ups this turned up

* **#85 dependency:** `udmd` answers `id-translation-result` with 501, so GPSI-targeted
  monitoring is refused against nextgcore's own UDM. Making it *succeed* needs the UDM
  side. The security fix does not wait on it.
* **`externalGroupId`:** TS 29.122's group form is refused rather than served. Supporting
  it needs a group→internal mapping this repo lacks; inventing one is how the original
  widening happened.
* **No `docs-book/src/configuration/nef.md`:** nefd has no dedicated config page, so this
  is documented in `overview.md`. A full page is worth writing, but inventing an
  exhaustive reference was out of scope here.
* Criterion 6's "read" has no route to protect — nefd serves POST and DELETE only. A GET
  belongs to #111.
