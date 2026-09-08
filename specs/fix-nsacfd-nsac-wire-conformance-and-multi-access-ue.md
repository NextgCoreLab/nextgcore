# nextgcore #95 (nsacfd): NSAC request wire conformance and multi-access UE tracking

Verified against `main` @ `8dadcd3` (after #205 and #242). The issue was written at `76ea248`; every
cite was re-located, and **one has already been fixed** since.

## Verified against current main

| claim in the issue | cite in the issue | site on `8dadcd3` | still true? |
|---|---|---|---|
| `PduACRequestData.nf_id` is a non-`Option` `String`; `pgwFqdn` / `nsacServiceArea` / `supportedFeatures` absent | `main.rs:616-623` | `main.rs:627-634` | yes |
| `parse_request_body` maps any serde missing-field to `400 MANDATORY_IE_MISSING` | `main.rs:800-813` | `main.rs:800-825` | yes |
| `handle_pdu_ac_update` deserialises straight into `PduACRequestData` | `main.rs:934-937` | `main.rs:973-977` | yes |
| `AcuOperationItem` carries only `update_flag` + `snssai` | `main.rs:565-568` | `main.rs:576-579` | yes |
| `UeACRequestInfo` lacks `additionalAnType` and the roaming IEs | `main.rs:573-581` | `main.rs:584-592` | **partly** — see below |
| `ue_access: HashMap<String, AccessType>` — one access per SUPI | `context.rs:192` | `context.rs:192` | yes |
| `admit_ue` inserts a single `AccessType` | `context.rs:570-620` | `context.rs:750-800` | yes |
| `release_ue` drops the SUPI on the first DECREASE | `context.rs:626-650` | `context.rs:806-830` | yes |
| `handle_local_configs_update` needs a bespoke `localConfigurations` array, answers `200` + body | `main.rs:1263-1332` | `main.rs:1302-1372` | yes |
| `handle_roaming_quotas_query` ignores the mandatory IEs, reads `snssais`, answers a non-spec body | `main.rs:1340-1398` | `main.rs:1379-1437` | yes |

**Already fixed since the issue was written.** It says `UeACRequestInfo` "carries `supi`, `an_type` and
`acu_operation_list`" and implies `anType` is required. It is already `Option<String>` with an explicit
accept-and-default comment (nsacf-05). So only `additionalAnType` and the six roaming IEs were missing,
not `anType` handling — a smaller gap than the issue reads, and worth saying so rather than "fixing"
something that was not broken.

## Decision 1: no feature flag — the spec shape is the only shape

The suggested approach offers to *"gate the spec-conformant wire behind a feature flag (e.g.
`nsac-conformant-wire`) during transition, **defaulting off** until callers migrate."* **Not done, and
the deviation is deliberate.**

Two reasons. First, it contradicts the issue's own acceptance criteria, which are unconditional
("LocalConfigurations update accepts an `ACUpdateData` request and returns `204`"); a conformance fix
that ships switched off is the "looks implemented in review" defect this issue family exists to
remove. Second, the flag's stated purpose — *"if preserving the current bespoke endpoints for existing
tooling matters"* — has no subject: `grep -rn 'local-configs\|roaming-quotas'` across `src/`,
`docs-book/` and `docker/` finds **no consumer of either endpoint anywhere in the tree except
nsacfd's own tests**. There is no tooling to preserve, so a flag would add a permanent second wire to
support a hypothetical caller.

The tests that did exercise the bespoke shapes were migrated in lockstep, as the issue requires.

## Decision 2: `quotaType`'s presence is mandatory, its value is not validated

`QuotaUpdateRequestData` requires `quotaType`, and that is enforced: absent or empty is
`400 MANDATORY_IE_MISSING`. The **value** is accepted as given and logged.

TS 29.536's `QuotaType` enumeration is not in the vendored OpenAPI set (the module header already
records that `TS29536_Nnsacf_*.yaml` is absent), so an allow-list here would be invented. Inventing one
risks rejecting a conformant peer — which is **gap 1 of this very issue committed in a new place**.
Presence is checkable without the enumeration; value conformance is not.

`plmnId` is held to a higher bar, and the asymmetry is intentional: `PlmnId`'s own shape *is* known
(`mcc` + `mnc`, both mandatory), so a `plmnId` of `{}` or `null` is not a PLMN and must not satisfy a
mandatory IE. A mandatory IE that any value satisfies is decorative.

## Decision 3: per-access ceilings ride along on `ACUpdateData`, and a partial update keeps them

`maxUes3gpp` / `maxUesN3gpp` / `maxPdu3gpp` / `maxPduN3gpp` are an nsacf-05 NextGCore extension, not
part of `ACUpdateData`. They are read from the same object as additional optional members, so becoming
conformant does not delete an operator capability. A consumer that sends none is unaffected.

`ACUpdateData` is a single **object** where the bespoke wire was a full-configuration **array**, which
changes what "omitted" means: an update naming only `maxPdusNumber` must not widen the UE ceiling to the
default or erase the per-access ceilings a previous call installed. Every ceiling therefore falls back
**per field** to the existing quota's value, and only a brand-new S-NSSAI reaches the 10000 / 50000
defaults.

## Decision 4: multi-access membership, and the mirror-image hazard it creates

`ue_access` becomes `HashMap<String, AccessSet>`, where `AccessSet` is a two-`bool` `Copy` struct rather
than a `HashSet<AccessType>` — `AccessType` has exactly two variants, so that *is* the whole domain, and
`current_ues_access` scans every member on every admission check.

- **INCREASE is now idempotent per ACCESS, not per SUPI.** An INCREASE naming an access the UE already
  holds is a no-op; one naming a new access adds it, subject to that access's ceiling, without a second
  aggregate count. Before this the whole request was swallowed the moment the SUPI was known, so a UE
  that later attached over non-3GPP was never recorded on it.
- **A per-access ceiling still binds for an existing member**, and a rejected operation applies
  *nothing* — no partial application, so the consumer's view of which accesses are registered cannot
  silently diverge from the NSACF's.
- **DECREASE removes only the named accesses**; the entry (and the aggregate count, and any EAC
  transition) goes only when the last one does. That is the new
  `ReleaseOutcome::AccessReleased`, distinct from `Released` because the aggregate did not move.
- **UPDATE replaces the set** rather than adding to it. An AMF reporting `anType: NON_3GPP_ACCESS` with
  no `additionalAnType` is stating the UE's current access; treating that as an addition would leave a
  stale 3GPP registration nothing could ever clear. An empty set is refused — a release is not an
  update.
- **`currentUes3gpp + currentUesN3gpp` may now exceed `currentUes`.** That is correct: the aggregate
  counts registered UEs, the buckets count registrations per access. It is why the aggregate stays its
  own set rather than being derived by summing.

**The mirror-image hazard, and the one place the accept-and-default rule must not be reused.** With
per-access releases, an access-unaware consumer that omits `anType` on a DECREASE would — under the
plain nsacf-05 default-to-3GPP — release nothing for a UE registered over non-3GPP and leave it
registered **forever**: the exact inverse of the premature-removal bug being fixed. So a DECREASE that
names *neither* `anType` *nor* `additionalAnType` releases **every** access. A consumer that names one
is stating which it is deregistering and gets exactly that.

An unrecognised `additionalAnType` is **ignored with a warning**, not defaulted to 3GPP: claiming a
registration the consumer never asserted is worse than dropping an unknown one. (`anType` keeps its
existing default-to-3GPP behaviour, which nsacf-05 established and this issue does not revisit.)

## Decision 5: the per-access counts moved to the admin resource

`QuotaUpdateResponseData` carries `{snssai, maxUesNumber, maxPdusNumber}` — ceilings only — so making
`roaming-quotas` conformant removed the only wire-observable source of `currentUes3gpp` /
`currentUesN3gpp`. They are added to `GET /nnsacf-nsac/v1/slice-quotas/{id}`, the admin-only inspection
resource that already exposes `currentUes`. Without them there is no way to *test over the wire* that a
dual-access UE counts once against the aggregate and once in each bucket, which is the acceptance
criterion's whole point.

## Persistence

`uesAccess` is written as an **array** of `AccessType` strings. `AccessSet::from_json` still accepts the
bare string the previous build wrote, so a pre-#95 state file loads with each member's single access
preserved; an undecodable entry defaults to 3GPP as before, never to the empty set — which would break
the `ues` ↔ `ue_access` invariant and make the next DECREASE deregister a UE it should not.

## Acceptance criteria

- [x] `POST /slices/pdus` with `pduACRequestInfo` but no `nfId` is accepted — `test_http_ac_missing_nf_id`
      asserts `204`, and the same test keeps the `400` for the UE resource where `nfId` **is** mandatory.
- [x] `PduACRequestData` deserialises `pgwFqdn`, `nsacServiceArea`, `supportedFeatures` — same test
      round-trips a body carrying all three.
- [x] LocalConfigurations accepts `ACUpdateData`, returns `204` with an empty body, rejects a body with
      no `snssai` as `400 MANDATORY_IE_MISSING` —
      `test_http_local_configs_update_is_ac_update_data_and_204`, which also rejects a body carrying
      *only* the old `localConfigurations` envelope (the discriminating case: a handler still accepting
      the old shape would pass a plain-`{}` check).
- [x] RoamingQuotas accepts `QuotaUpdateRequestData`, rejects a body missing any of `snssai` / `plmnId` /
      `quotaType`, returns `{snssai, maxUesNumber, maxPdusNumber}` —
      `test_http_roaming_quotas_is_quota_update_data`, which drops each IE **one at a time** (an
      implementation checking only `snssai` would pass an all-empty-body check), rejects four malformed
      `plmnId` shapes, and asserts the bespoke `roamingQuotas` / `supportedFeatures` members are **gone**
      rather than merely joined by the new ones.
- [x] A dual-access UE survives the first DECREASE and leaves the counted set on the second —
      `test_http_dual_access_ue_survives_first_decrease` (count 1 → 1 → 0 over the wire) and
      `dual_access_ue_is_counted_once_and_released_last` (context level, plus the fully-idempotent
      INCREASE and the member-absent third release).
- [x] `UeACRequestInfo` deserialises `additionalAnType` and all six roaming IEs —
      `test_http_ue_ac_roaming_ies_round_trip`, which proves the body was *applied* (both buckets hold
      the UE, reachable only via `additionalAnType`) rather than merely accepted.
- [x] `cargo test -p nextgcore-nsacfd` and workspace clippy are green.

## Verification

Workspace **5976 passed / 0 failed / 6 ignored** (baseline `5966` on `8dadcd3`; +10 tests, nsacfd 59 →
69). `cargo clippy -p nextgcore-nsacfd --all-targets` adds no warning, `cargo clippy --workspace` 0
errors, `cargo fmt --all -- --check` clean.

Eight reverts:

| revert | expected to break | result |
|---|---|---|
| `release_ue` drops the whole entry regardless of access (gap 4) | dual-access wire + context tests | **2 failed** |
| `additionalAnType` never read (gap 4) | roaming-IE + dual-access wire tests | **2 failed** |
| `release_set` falls back to the 3GPP default instead of `all()` | `test_http_decrease_without_an_type_releases_every_access` | **1 failed** |
| `PduACRequestData.nf_id` back to a non-`Option` `String` (gap 1) | `test_http_ac_missing_nf_id` | **1 failed** |
| local-configs answers `200` with a body again (gap 2) | ACUpdateData + per-access-counting tests | **2 failed** |
| `quotaType` defaults instead of being enforced (gap 3) | `test_http_roaming_quotas_is_quota_update_data` | **1 failed** |
| `AccessSet::from_json` refuses the legacy bare string | legacy-state-file + AccessSet tests | **2 failed** |
| `parse_access_limits_or_keep` → `parse_access_limits` (per-field carry-over) | *nothing, at first* | **see below** |

**The last revert found a hole in my own coverage.** Dropping the per-field carry-over broke **no
test**: the `maxUesNumber`-is-kept assertion covered only the aggregate ceiling, which is handled by
separate code, so the per-access ceilings could be silently erased by a partial update and every test
still passed. Fixed by adding a *behavioural* guard — install `maxUes3gpp: 1`, send a ceiling-free
`ACUpdateData`, then assert the second 3GPP admission is still refused `403` — because the per-access
ceilings appear on no response body and so cannot be asserted by reading one back. Re-running the
revert against the new guard: **1 failed**, with the named message. Same shape as the #210 session's
false guards: an assertion that looked like it covered a claim and did not.

Also removed as part of the migration: `local_config_json`, which rendered the bespoke
`localConfigurations` response entry and has no reader now that the endpoint answers `204`.

## Ceilings

* **Per-PLMN roaming quotas are not implemented.** `plmnId` is validated (both `mcc` and `mnc`
  required) and logged, but the quota returned is the **slice-level** one — there is no per-PLMN quota
  store, and adding one is a feature rather than the wire-conformance this issue scopes. A partner
  HPLMN NSACF will get a well-formed `QuotaUpdateResponseData` that does not vary by visited PLMN.
  This is the most likely thing to be mistaken for done.
* **`quotaType` does not select which counter is returned.** `QuotaUpdateResponseData` defines both
  `maxUesNumber` and `maxPdusNumber`, so both are always emitted; the request's `quotaType` is logged
  and otherwise unused. If TS 29.536 intends the response to be scoped by it, that needs the
  enumeration this tree does not have.
* **The roaming IEs are parsed, not acted on.** `ueRegInd`, `nsacMode` and `numberExceedInfo` in
  particular have procedural meaning in §5.2.2.2.2 that is not implemented; they round-trip so a
  conformant request is not rejected, and are logged so a deployment using them is diagnosable.
* **PDU sessions remain single-access.** `pdu_access` is still one `AccessType` per session key, which
  is correct — a PDU session has one access — but it means `ReleaseOutcome::AccessReleased` is
  unreachable on the PDU path. Matched explicitly there rather than by `_`, so giving PDU sessions a
  multi-access model later is a compile error instead of a silently dropped report.
* **The requester-NF resilience item the issue defers is still deferred.** Its note (an inter-AMF
  INCREASE-then-DECREASE against a SUPI keyed only by identity can double-free the count) says to track
  it separately as a medium resilience item, and #95 does not touch it. Worth noting that multi-access
  membership makes the window *narrower* — a DECREASE now removes only the named access — but does not
  close it: two AMFs on the same access still collide.
* **No test drives a real SMF or AMF**, so all wire assertions are made by the in-crate `SbiClient`
  against a live in-process server. That is the same ceiling every nsacfd test has.
* **New-test S-NSSAI allocation is manual.** The nsacfd context is process-global across the test
  binary, so the six new tests use SSTs 60-66, which no other test touches. A collision does not fail
  loudly — it shows up as a neighbouring test seeing quota state it did not create, which is how the
  first draft of this change broke `test_http_ue_admission_lifecycle` (I had reused SST 99).
* GitNexus impact analysis unrunnable (no MCP server connected — 42nd consecutive PR). Blast radius by
  grep: `admit_ue` / `release_ue` / `update_ue_access` have exactly one production caller each
  (`handle_ue_ac_update`), `ue_access` is touched only inside `context.rs`, and `ReleaseOutcome` is
  matched in two places, both updated.
