# nextgcore #85 (UDM): the Nudm service surface, TS 29.500 error semantics, and one NF profile

Verified against `main` @ `72776d4` (i.e. after #84 landed). Two of the issue's cites had already been
fixed by earlier PRs and are recorded below rather than re-fixed.

`Closes #85`.

## What was already fixed before this PR

The issue was filed at `76ea248`. Two items no longer reproduce:

* **`nudm-sdm` advertised at `v1` in `app.rs`** — `build_udm_nf_profile` already advertised `v2`, pinned
  by `test_nrf_profile_advertises_nudm_sdm_at_v2`.
* **The SDM subscription `Location` header** — already `/nudm-sdm/v2/...`.

Everything else reproduced exactly as described.

## Gap 1: `405` was the answer to every question (criteria 1, 2)

Every unmatched path in the router — a mistyped resource, an entirely unknown service, a known resource
addressed with the wrong verb — came out as `405 METHOD_NOT_ALLOWED` with **no `Allow` header**. That is
two distinct defects:

* A consumer branching on `RESOURCE_URI_NOT_FOUND` (TS 29.500 §5.2.7.1) never saw it, and a typo'd URI
  looked like a supported resource.
* `Allow` is mandatory on a 405 (RFC 9110 §15.5.6, restated by TS 29.500 §5.2.7.1). Without it a 405
  tells the consumer only that it guessed wrong.

Two new helpers in `nextgcore-sbi`: `send_method_not_allowed_with_allow` and
`send_resource_uri_not_found`. The existing `send_method_not_allowed` is **unchanged** — it has 171 call
sites across 26 crates and cannot know a resource's method set, so changing its signature would be a
workspace-wide refactor with no bearing on this issue. Its doc comment now points at the new helper, and
the other NFs' Allow-less 405s remain their own issues' business.

In udmd, one `unmatched(allowed, method, uri)` decides both answers from a per-service resource table:
`Some(methods)` ⇒ `405` + `Allow`, `None` ⇒ `404 RESOURCE_URI_NOT_FOUND`. The tables (`uecm_allowed_methods`,
`sdm_allowed_methods`, `ueau_allowed_methods`, `ee_allowed_methods`, `pp_allowed_methods`,
`mt_allowed_methods`) are the single statement of what this UDM serves, so a route arm and its error
answer cannot drift apart.

**Decision worth review:** the tables list the resources this UDM *serves*, not every resource TS 29.503
defines. A spec-defined data set this UDM does not implement (`trace-data`, `sms-data`, the `lcs-*`
family, ...) answers `404 RESOURCE_URI_NOT_FOUND` rather than `501`. Those are #226's to add as real
resources; enumerating them here as 501 stubs would double the table and then have to be unwound. The
four *services* the issue explicitly asks to stub are different — see below.

## Gap 2: six of the ten Nudm services were unrouted (criterion 3)

`nudm-pp` and `nudm-mt` are now **served**, not stubbed:

**Nudm_PP** (TS 29.503 §5.6) — `GET`/`PATCH /{ueId}/pp-data` and `PUT`/`GET`/`DELETE
/{ueId}/pp-data-store/{afInstanceId}`, as read/write-through to the Nudr `subscription-data/{ueId}/pp-data`
and `pp-data-store/{afInstanceId}` resources (TS 29.505 §5.2.13). Provisioned parameters belong in the
UDR: an AF provisions them once and every later read must see them, so a UDM-local copy would be lost on
restart and invisible to a second UDM. `5g-vn-groups` and `mbs-group-membership` are recognised and
answer `501` — group management needs a group store this core does not have.

**Nudm_MT** (TS 29.503 §5.10) — `GET /{supi}?fields=...` (`QueryUeInfo`). This is a **proxy** operation:
the information asked for is the AMF's, so the UDM resolves the serving AMF from the stored
`amf-3gpp-access` registration and calls Namf_MT `ProvideDomainSelectionInfo` (TS 29.518 §5.4.2.3) on
*that* AMF — asking an arbitrary one would answer with another AMF's view of a UE it does not serve. The
test proves this against **amfd's real `namf_request_handler`** over HTTP, not a mock, because a mock
would only pin this UDM's idea of the AMF's response shape.

Three judgement calls in `QueryUeInfo`:

* **`fields` is enforced.** It is a required query parameter; without it the request does not say what to
  retrieve, so it is `400 MANDATORY_IE_MISSING`.
* **Only `tadsInfo` is supported, and an unsupported field is named in a `501`.** `userState` is the
  AMF's CM/RM state, reported through Namf_EventExposure rather than Namf_MT, and `5gSrvccInfo` is SRVCC
  subscription data no provisioning path in this core populates. Deriving `userState` from "a registration
  record exists" would be a guess presented as a fact — the recorded *absent, never fabricated* rule. The
  501 names the field so a consumer can retry with the subset that works.
* **`provide-loc-info` answers `501`** naming its missing dependency: it proxies Namf_Location
  `ProvideLocationInfo`, and amfd implements `provide-pos-info` only.

`nudm-niddau`, `nudm-rsds`, `nudm-ssau` and `nudm-ueid` answer `501` on their **defined operations** and
`404` on anything else, so "this UDM does not do that yet" is distinguishable from "that is not a Nudm
operation".

**`nudm-ueid` Deconceal deliberately stays a 501, and this is the call most worth a second opinion.** The
SIDF machinery it needs already exists in this UDM (`deconceal_suci`), so serving it is perhaps fifteen
lines — but the operation returns a **SUPI for a SUCI to whoever asks**, and this repo's SBI OAuth2
enforcement is off by default (#187). Implementing it now would turn the UDM into an unauthenticated SUPI
oracle in every default deployment. That is the one case where the recorded "runtime switch defaulting
ON" preference does not apply: unlike #68's Bootstrapping, which publishes only what an unauthenticated
peer must read for bootstrapping to work at all, this publishes the identity the SUCI exists to conceal.
The router carries that reasoning as a comment so the next agent does not read the 501 as an oversight.

### `id-translation-result` moved service, and now works

`GET .../id-translation-result` was routed under **`nudm-uecm`**. TS 29.503 defines `GetSupiOrGpsi` on
**Nudm_SDM** (`GET /nudm-sdm/v2/{ueId}/id-translation-result`, `IdTranslationResult`), so a conformant
consumer would never have found it — and once the resource tables existed, leaving it there meant
encoding the wrong table. It is now an SDM resource, and it is implemented rather than 501:

* **GPSI → SUPI** via the Nudr `identity-data` resource (TS 29.505 §5.2.19), the only source that can
  resolve that direction. This is what a NEF needs to target a UE named by `msisdn-`/`extid-`; nextgcore
  #110 refuses such a subscription today *because* this operation was unrouted, which is the open
  TASKS-backlog item this closes.
* **SUPI → GPSI** falls back to the `gpsis` member of the UE's `am-data` when `identity-data` is absent —
  which works against nextgcore's own UDR **today**.
* `supi` is `IdTranslationResult`'s only required member, so a translation that cannot establish one is a
  `404 USER_NOT_FOUND`, never a partial result. `requested-gpsi-type` filters, so a consumer that asked
  for an external identifier is not handed an MSISDN.

## Gap 3: two divergent NF profiles, and `nudm-ee` undiscoverable (criteria 4, 5, 7)

`app.rs` and `sbi_path.rs` each hand-wrote a service list. They disagreed on `nudm-sdm`'s version, and
**neither advertised `nudm-ee`** — a fully routed service no consumer could discover, so AMF/SMF event
subscriptions had no producer to bind to.

One table, `UDM_ADVERTISED_SERVICES`, now feeds both the typed self-instance in `udm_sbi_open` and the
JSON profile in `build_udm_nf_profile`; `udm_nrf_register` renders through the same builder instead of
formatting the self instance by hand. `app.rs`'s builder is a thin wrapper that supplies the operator
knobs from the context. All six served services are advertised, `nudm-sdm` at `v2` and the rest at `v1`,
with `apiFullVersion` derived from the URI version rather than written out twice.

`heartBeatTimer` and `allowedNfTypes` come from `udm.sbi.nrf_profile` in the YAML
(`NfProfileConfig`), whose defaults are the previous literals — an unconfigured deployment registers
byte-identically. The docker overlay documents the block with those defaults.

## Verification

* Workspace `cargo test`: **5856 passed, 0 failed** (from 5849). `cargo clippy --workspace
  --all-targets`: 0 errors, 0 warnings in the touched crates. `cargo fmt --all --check`: clean. udmd's
  suite run 5 consecutive times, green each time (its tests share the process-global context).
* **Revert-verified**, each against the named test:
  * `unmatched`'s `None` arm returning 405 instead of 404 → `test_http_nudm_error_semantics` and
    `test_http_id_translation_result_both_directions` fail.
  * dropping the `Allow` header → `test_http_nudm_error_semantics` fails.
  * removing `nudm-ee` from `UDM_ADVERTISED_SERVICES` → `test_nrf_profile_is_single_sourced_and_configurable`
    fails, printing the five-service list.
  * answering `QueryUeInfo` from the UDM's own data instead of proxying to the AMF →
    `test_http_nudm_pp_and_mt_are_served` fails (`left: "GUESSED"`).
* The routing assertions drive the **real router over HTTP**, because "returns 405 / 404 / 501" is a
  routing claim a handler-level test cannot falsify.

## Dependency on #87, stated plainly

The Nudm_PP resources and `identity-data` live under UDR `subscription-data/`, and **udrd implements
neither** — as does the non-3GPP/SMSF/IP-SM-GW `context-data` set #84 added. That is #87
("udrd data_store: most TS 29.505/29.519 ... resources unimplemented"), the next eligible issue by
number. Until it lands, against nextgcore's own UDR: `PATCH pp-data` and the `pp-data-store` writes
answer from the UDR's 404 rather than persisting, and GPSI → SUPI translation cannot resolve. The tests
here use a mock UDR that implements the resources generically, so they prove the UDM's half and say
nothing about the UDR's. The SUPI → GPSI direction works against the real UDR today.

## Not in scope

* `GET /nudm-sdm/v2/{supi}` (multiple data sets) and the unimplemented SDM data sets — **#226**.
* `GET .../registrations` (`RegistrationDataSets`) and `nwdaf-registrations` — not served, so they answer
  `404 RESOURCE_URI_NOT_FOUND`.
* The Allow-less 405s in the other 25 crates that call `send_method_not_allowed`.
* In-repo OpenAPI stubs for the six previously-unrouted services (`docs/openapi/` has three Nudm files);
  the 3GPP originals under `6g_docs/specs/` were used as the source of truth for every path and schema
  cited here.
