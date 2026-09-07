# nextgcore #87 (UDR): the TS 29.505 / 29.519 / 29.504 resources that answered 404 or 405

Verified against `main` @ `50878f0` (i.e. after #84 and #85 landed). Every defect reproduced as described.

`Closes #87` — as **one** PR, not the five sub-issues the text proposes. The repo's own convention is that
an umbrella closes only when a whole-issue PR lands (five merged part-PRs moved the open count 72→69 on
2026-08-21, while two whole-issue PRs each closed one), and these five parts are the same shape of work
against the same store, so splitting them would have produced five reviews of the same CRUD pattern and
left #87 open.

## Gap 1: `amf-non-3gpp-access` did not exist, and `smf-registrations` was non-conformant

`handle_context_data` branched on `amf-3gpp-access` and `smf-registrations` and sent everything else to
`send_not_found("Unknown context resource")`. So non-3GPP AMF registration state had nowhere to live —
and it is exactly where the UDM producer merged in **#84** writes.

`AmfAccessSlot` now carries which access a request addresses. The 3GPP slot keeps its dedicated store map
(and therefore its snapshot key, so no state file moves); the non-3GPP one lives in the new generic
document store. The two are separate documents, so a write to one is invisible to a read of the other —
the same property #84 fixed on the UDM side, now enforced on both.

Two smaller conformance fixes on `smf-registrations` (TS 29.505 §5.2.4):

* the `201` now carries the required **`Location`** header **and** the created `SmfRegistration`
  representation. A bare `201` leaves the consumer without the URI of the resource it just created.
* **`PATCH` is implemented** (it was a flat `405`). The `pduSessionId` identifies the resource, so a patch
  that would change it is refused rather than silently moving the document to another key.

Also added, from the same tree: `smsf-3gpp-access`, `smsf-non-3gpp-access`, `ip-sm-gw` (single documents)
and the `sdm-subscriptions` / `ee-subscriptions` collections.

## Gap 2: the resources #85's producers read and write

Beyond the issue's enumerated criteria, and stated plainly because it is an addition: this PR also
implements the Nudr resources the **#85** UDM producers depend on — `pp-data`, `pp-data-store/{afInstanceId}`
(TS 29.505 §5.2.13) and `identity-data` (§5.2.19). #85 shipped the UDM half of Nudm_PP and of
`id-translation-result` two PRs ago with the dependency recorded in both its spec and its PR; leaving
them out here would have meant closing the issue that owns the UDR's TS 29.505 coverage while the
producers merged an hour earlier still had no store.

`identity-data` is the interesting one. It answers in **both directions from one subscriber record**,
because the subscriber-DB query is `{<idType>: <idValue>}` over a single document — so an `msisdn-`
identifier resolves the same subscriber as its `imsi-`. That reverse direction is what lets a NEF
translate a GPSI an AF gave it into the SUPI every other 5GC interface needs, and it is why nextgcore
**#110** refuses `msisdn`-targeted monitoring subscriptions today.

Two consequences worth review:

* **`identity-data` is dispatched before the SUPI-shaped validation.** `handle_subscription_data` rejects
  a `msisdn-` `{ueId}` with `400 INVALID_SUPI`, which is right for every resource keyed by a SUPI and
  wrong for the one resource TS 29.505 defines for "SUPI **or** GPSI". It is therefore routed first.
* **The DBI test store gained a subscriber-identity mirror.** `nextgcore-dbi`'s `test_store` existed to
  "let NF crates exercise their real Nudr handlers without a MongoDB instance", but covered only the
  authentication functions — so identity resolution had no hermetic test. `provision_subscriber` +
  `subscription_data` extend it, faithfully to the Mongo query (a GPSI resolves the same document as the
  SUPI). It answers **only when a test has provisioned an identity**, so enabling the store for the
  authentication tests leaves every other handler's view of the subscriber DB unchanged.

## Gap 3: policy-data — PATCH, the filter, and four absent documents

`handle_policy_data` handled `ues/{ueId}/{am-data,sm-data,ue-policy-set}` with GET and PUT only.

* **PATCH on all three** (TS 29.519 §5.2: `am-data` :143, `sm-data` :333, `ue-policy-set` :484, all `405`
  before). An absent document starts empty rather than 404ing: PATCH is how a PCF provisions a delta, and
  refusing the first one would mean a document could only ever be created by a full PUT the consumer may
  not have.
* **`snssai` / `dnn` filtering on the `sm-data` GET.** Matching is **field-wise on `sst`/`sd`**, not by map
  key: the key spelling (`"01-000001"`) is a UDR-side convention while the consumer sends a JSON `Snssai`,
  so keying the filter on it would make the filter depend on how this UDR happens to format it. A filter
  that selects nothing is a **404**, not an empty `SmPolicyData` a PCF would install as "no policy
  applies". Note the issue is mistaken that these parameters are mandatory — the in-tree OpenAPI marks
  both `required: false` (the cited lines 24-42 belong to `/policy-data/ues/{ueId}`) — so an absent filter
  still returns the whole document, unchanged.
* **The absent documents**: `sm-data/{usageMonId}`, `subs-to-notify[/{subsId}]`,
  `plmns/{plmnId}/ue-policy-set`, `sponsor-connectivity-data/{sponsorId}` and `bdt-data[/{bdtReferenceId}]`.
* **`PolicyDataChangeNotification`.** A policy change now notifies **both** subscription trees, because
  they have different audiences: a `/subscription-data/subs-to-notify` subscriber (the UDM) gets the
  `DataChangeNotify`, a `/policy-data/subs-to-notify` subscriber (the PCF) gets the
  `PolicyDataChangeNotification`. Emitting only the first is why a PCF could subscribe and never hear
  anything — and the subscribe endpoint did not exist at all.

### The `200 {}` vs `404` question, settled

**Kept as `200 {}`** for `am-data` and `ue-policy-set` on an unprovisioned subscriber, and pinned by a
test so the decision is visible rather than incidental. Reasons: every member of those documents is
optional, so "this subscriber has no AM policy data" is a representable answer; a `404` would *also* be
the answer for "no such subscriber", collapsing two facts a PCF may want to distinguish; and this repo's
own PCF already consumes the `200 {}` form, so flipping it is a cross-NF behaviour change this issue does
not ask for. `sm-data` keeps its `404` for an unknown subscriber, since it has a derived default and
absence there means the subscriber itself is missing.

## Gap 4: five application-data datasets

`bdtPolicyData`, `iptvConfigData`, `serviceParamData`, `am-influence-data`, `af-qos-data-sets` and
`eas-deploy-data`, all through one handler: they differ only in their mandatory members, which come from
`application_dataset_required` (and are empty for the three whose schemas mark nothing required, rather
than invented).

**Spelling, deliberately not the issue's.** TS 29.519 §5.6 names the last two `af-qos-data-sets` and
`eas-deploy-data`; the issue's `af-qos-data` and `eas-deployment-data` appear nowhere in the OpenAPI.
Routing the informal names would advertise a surface no conformant consumer asks for, so the spec names
are what is implemented and tested.

## Gap 5: `Nudr_GroupIDmap` was unrouted

The router 404'd every service but `nudr-dr`. `/nudr-group-id-map/v1/nf-group-ids` now answers the
`NFType -> NfGroupId` map, with `/nf-group-ids/subscriptions` CRUD.

**The mapping comes from configuration** (`udr.group_id_map`, longest SUPI prefix wins), because NF-group
assignment is an operator decision made by SUPI range: TS 29.504 defines no verb that provisions it, and
deriving a group id from the SUPI would invent a topology this core does not have. With no config the GET
answers `404 DATA_NOT_FOUND` — never a fabricated group id. `/routing-ids` is **recognised and refused
with 501** for the same reason: there is no routing-id data model here to answer from.

## One store, not fifteen maps

The new resources share a single `(collection, key) -> document` map with four accessors. Fifteen typed
fields would each have meant a new snapshot key, a new `restore_from` arm and three near-identical
accessors — for resources that differ only in their name. The pre-existing typed maps are untouched, so
no on-disk snapshot key moves and a state file written before this change still loads.

## Verification

* Workspace `cargo test`: **5867 passed, 0 failed** (from 5856). `cargo clippy --workspace --all-targets`:
  0 errors, 0 warnings in the touched crates. `cargo fmt --all --check`: clean. udrd's suite run **6
  consecutive times**, green each time.
* **Revert-verified**, each against the named test:
  * unrouting `amf-non-3gpp-access` → `test_http_amf_non_3gpp_access_round_trip` fails.
  * dropping the `Location`/body from the `smf-registrations` 201 →
    `test_http_smf_registration_put_location_body_and_patch` fails.
  * making the `snssai` filter return everything → `test_filter_sm_policy_data_matches_on_snssai_fields`
    and `test_http_policy_data_patch_filter_and_notify` fail.
  * unrouting the group-id-map service → `test_http_group_id_map_service` fails.
  * emitting only the `DataChangeNotify` and not the `PolicyDataChangeNotification` →
    `test_http_policy_data_patch_filter_and_notify` fails on the 5s notification timeout.
* **A flake I introduced and fixed, worth recording:** the identity-data test first called
  `test_store::provision_subscriber` / `disable()` directly, which raced every other test using the
  store — `disable()` is a process-global kill switch, so two unrelated tests failed intermittently in
  different ways (a 404 for a just-provisioned identity, and a `None` stored SQN in an auth test). The fix
  is the crate's existing `DbiTestStore` RAII guard, which serializes on `DBI_BACKEND_LOCK` and restores
  on drop. Six consecutive green runs are the evidence, not one.

## How the #84 / #85 / #87 chain is covered

The three PRs are two halves of the same features, and no single test spans both processes: udrd's
`udr_sbi_request_handler` lives in its binary, so udmd cannot drive it in-process the way it drives
amfd's real handler. What is pinned instead is that **both sides assert the same literal TS 29.505
resource strings** — udmd's tests assert the exact UDR path key its client builds
(`.../context-data/amf-non-3gpp-access`, `.../identity-data`, `.../pp-data-store/{af}`), and udrd's tests
assert the same literals on its routes. A drift on either side fails a test on that side. The full
cross-process path remains the Docker E2E's to prove, and CI skips that.

## Not in scope

* Restart-resilient persistence for the new documents is inherited (they ride the existing snapshot), but
  the store remains in-memory when no `state_path` is configured — unchanged.
* Subscription/registration **expiry** sweep: still absent, as the issue notes; no expiry logic was added.
* `policy-data/ues/{ueId}/operator-specific-data`, `slice-control-data`, `mbs-session-pol-data`,
  `pdtq-data`, `group-control-data`; `application-data/dnai-eas-mappings`, `ecs-address-roaming`,
  `ueid-mappings`, `non3gpp-device-Id`. All spec-defined, none named by this issue's criteria.
