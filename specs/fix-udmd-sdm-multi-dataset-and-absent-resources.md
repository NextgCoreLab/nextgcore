# nextgcore #226 (udmd): the SDM multi-data-set GET and the absent SDM data-set resources

Verified against `main` @ `4ec257a`. `Closes #226`.

## The issue's diagnosis was right; two of its details had drifted

**Right:** `GET /nudm-sdm/v2/{supi}` was unrouted and the query string is stripped before routing, so
`dataset-names` had to be read through the SBI query accessor.

**Drifted:** the issue describes a `parts.len() >= 4` guard on the `nudm-sdm` arm. PR #229 restructured the
router, so there is no such guard now — instead `route_nudm_sdm` reads `parts.get(3)`, gets `None` for the
three-part whole-UE path, and falls to the catch-all. The *effect* is what the issue says, and slightly worse
than "not found": since #229 it is `404 RESOURCE_URI_NOT_FOUND` rather than `405`, which asserts the URI names
nothing at all.

**Wrong, and it changed the implementation:** criterion 1's example is
`GET /{supi}?dataset-names=am-data,sm-data`. Those are **path segments**, not TS 29.503 `DataSetName` values —
the enum is `AM`, `SMF_SEL`, `SM`, `UEC_AMF`, … Decisive in-repo evidence rather than just the spec: **`udrd`
already implements the spec tokens** for the same query parameter on its own combined provisioned-data GET
(`parse_dataset_names`, udrd-03, matching on `"AM"` / `"SMF_SEL"` / `"SM"`). Following the issue's spelling
would have put two different vocabularies on the two ends of one parameter. This is the recorded rule that the
tree and the spec outrank the issue text on naming, applied to a query value rather than a resource.

The path-segment spelling is therefore **refused with 400** naming the accepted set, not silently dropped: a
consumer that asked for a data set and received a body without it would read the absence as "this subscriber
has none".

## Criterion 1 — the multi-data-set GET

`("", "", "GET")` is now an arm of `route_nudm_sdm`, handled by `handle_get_subscription_data_sets`.

**The provisioned data sets are fetched with ONE combined UDR read, not a per-data-set fan-out.** `udrd`
already implements the `dataset-names` filtering *and* the `SubscriptionDataSets` member naming
(`amData` / `smfSelData` / `smData`). Re-implementing the fan-out in udmd would have made two places decide
which member name a data set contributes, and they would eventually disagree — the same duplication this
codebase keeps filing issues about.

Two decisions inside it:

* **The forwarded `dataset-names` is always explicit**, even when the consumer sent no filter. Forwarding
  "everything" would mean udmd silently starts returning any member udrd later grows, without this UDM having
  agreed to serve it.
* **`UEC_AMF` is merged separately**, because it lives under the UDR's `context-data`, not `provisioned-data`,
  so the combined read cannot supply it. Its absence is **not** an error for the multi-set retrieval: a UE with
  no AMF registration legitimately has no such data set, and failing the whole request for it would deny the
  consumer the members that *are* available. A missing *subscriber*, by contrast, fails the whole request with
  `404 DATA_NOT_FOUND` — there is no partial answer to give, and `200 {}` would say "this subscriber has no
  data" rather than "no such subscriber".

`sdm_allowed_methods` also learned the whole-UE resource, so a non-GET on it is `405` with an `Allow` header
rather than `404` — the distinction #85 introduced, which would otherwise have been reintroduced for the one
resource this change adds.

## Criterion 2 — `ue-context-in-amf-data`

A read-through of the UDR's `context-data/amf-3gpp-access`, which the UECM path already writes, so no new
storage. Shared with the multi-set retrieval through one `read_ue_context_in_amf_data` helper, so the
individual GET and the `uecAmfData` member cannot answer differently for the same UE.

This is the data set the #83 SDM notification producer reports on **every AMF registration and
deregistration**, so before this change a subscriber was told the resource changed and then could not read it.
That asymmetry is why the issue calls this the one to do first.

`404 DATA_NOT_FOUND` when the UE has no registration: the data set does not exist *for that UE*, which is a
different statement from the operation not existing.

## Criterion 3 — the remaining data sets, as read-throughs rather than stubs

Twelve TS 29.503 per-SUPI SDM data sets are now routed to the UDR:
`ue-context-in-smf-data`, `ue-context-in-smsf-data`, `sms-data`, `sms-mng-data`, `trace-data`,
`lcs-privacy-data`, `lcs-mo-data`, `lcs-bca-data`, `v2x-data`, `prose-data`, `mbs-data`, `uc-data`.

**Deliberately not 501s.** Whether a data set exists for a subscriber is the *data layer's* answer, so routing
the read means this UDM reports what the UDR says instead of a status the router invented. `udrd` serves three
provisioned data sets today, so the rest relay its `404` as `DATA_NOT_FOUND` — a **derived** answer, and one
that starts returning data the moment udrd grows a source, with no change here. It also replaces the previous
`405`, which claimed these resources do not exist.

`ue-context-in-smf-data`'s old `send_not_implemented` is gone with them. The issue notes #229 deliberately left
these out of `sdm_allowed_methods` so they could be added as real resources rather than 501 stubs that then
have to be unwound — that is what this does.

### Two resource names in the issue do not exist in TS 29.503

`trace` and `lcs` are `trace-data` and the `lcs-privacy-data` / `lcs-mo-data` / `lcs-bca-data` triple. Routed
under the spec names.

### `shared-data` and `group-data` are out of scope, with a reason

Both appear in the issue's "absent" list, but neither is a per-SUPI resource: TS 29.503 puts them at
`/shared-data` and `/group-data`, they are keyed by shared-data-id / group-id rather than by SUPI, and neither
has any provisioning surface in this tree (no `udrd` collection, no webui field). Implementing them means
inventing a data source, which is a feature rather than a routing fix. Named here so the omission is visible
rather than looking like an oversight.

## Verification

Workspace: **5941 passed / 0 failed** across three consecutive runs (baseline 5938; three tests added).
`cargo clippy --workspace` and `cargo fmt --all -- --check` clean.

All three tests drive the **real router over HTTP** against the mock UDR, because every criterion here is a
*routing* claim and a handler-level test cannot fail when a route arm is missing — which is precisely the
defect being fixed.

**Eight claims revert-verified**, each with a unique anchor, a compiling revert, and the named test confirmed
to have run:

| # | claim | test that bit |
|---|---|---|
| 1 | the whole-UE GET is routed | `sdm_multi_data_set_get_is_routed_and_fans_out` |
| 2 | the provisioned subset is merged into the body | same |
| 3 | an unknown `dataset-names` token is refused | same |
| 4 | a non-GET on the whole-UE resource is 405 with `Allow` | same |
| 5 | `ue-context-in-amf-data` reads the stored registration | `ue_context_in_amf_data_reads_the_stored_registration` |
| 6 | `UEC_AMF` is merged as `uecAmfData` | same |
| 7 | the twelve remaining data sets are routed | `every_routed_sdm_data_set_answers_a_derived_status` |
| 8 | an unknown path is still `RESOURCE_URI_NOT_FOUND` | same |

Claims 4, 5 and 8 are the ones that keep the others honest: 4 stops the new resource regressing #85's
404-vs-405 distinction, 5 asserts the "before registration" 404 as well as the "after" 200 so the handler
cannot pass by answering 200 unconditionally, and 8 proves routing twelve resources did not turn the router
into an accept-anything.

## Ceilings

* **The combined provisioned-data read is tested against the mock UDR, not against `udrd`'s real handler.**
  What is proved is udmd's assembly, filtering and member merging; that udrd filters `dataset-names` correctly
  is udrd's own test's job (udrd-03). udmd does not dev-depend on udrd, so an in-process strict-peer test would
  need that dependency added first.
* **The twelve read-throughs are only observed returning the UDR's 404**, because no UDR in this tree serves
  them. Their success path is type-checked and structurally identical to the three that do work, but unobserved
  — if udrd grows one of these data sets, that is the moment to assert a 200 through it.
* **`SubscriptionDataSets` is assembled, not schema-validated.** The in-repo `docs/openapi/nudm-sdm.yaml` is a
  trimmed subset defining only `amData` and `smfSelData`, so there is nothing in the tree to validate the
  fuller body against; the member names come from TS 29.503 and from what `udrd` already emits.
