# nextgcore #207 (scpd Model D): select the producer endpoint by service name and API version

Verified against `main` @ `645dcc7`. The issue's cites are from `562b4a1`; all three were
re-verified and all three still hold, at the same line numbers.

## Verified against current main

| claim in the issue | site on `645dcc7` | still true? |
|---|---|---|
| `select_nf_instance` filters by **health only**, then priority/capacity/load | `bins/nextgcore-scpd/src/sbi_path.rs:145-174` | yes |
| the endpoint is taken from the first service unconditionally | `sbi_path.rs:439-478` (`first_service`), consumed at `proxy.rs:1232-1237` | yes |
| `grep -c 'INVALID_API\|apiVersionInUri\|api_version' bins/nextgcore-scpd/src/sbi_path.rs` → `0` | — | yes, `0` |

The suggested approach's preconditions were checked too, per the
verify-the-approach-not-just-the-cites rule: `UriComponents` (`libs/nextgcore-sbi/src/message.rs:20`)
does already expose `api_name` and `api_version`, so the "thread the API major version from
`UriComponents`" step is followable as written. That is the one part of the suggestion that
survived unchanged.

## Decision 1: per-service endpoints on the candidate, not a second parse

`NfInstanceCandidate` collapsed the whole profile to one `(scheme, port, prefix)` triple taken
from `nfServices[0]`, so there was nothing to match against. The fix keeps every service:

```rust
pub struct NfServiceEndpoint {
    pub service_name: String,
    pub versions: Vec<String>,   // versions[].apiVersionInUri
    pub scheme: UriScheme,
    pub port: u16,
    pub prefix: String,
}
```

and `NfInstanceCandidate` gains `services: Vec<NfServiceEndpoint>`. The existing
`scheme`/`port`/`prefix` fields are **kept** as the profile-level fallback rather than removed:
a profile that registers no `nfServices` at all still has to be routable, and those fields are
already what `parse_search_result` synthesises for it (port 7777, `http`, no prefix). Removing
them would have made a serviceless profile unroutable — a regression the issue does not ask for
and that no acceptance criterion covers.

The alternative was to re-parse the SearchResult JSON at selection time. Rejected: the
candidates are **cached** (`DiscoveryCache`, per-entry `validityPeriod` TTL), the raw JSON is
not, so a cache hit would have had nothing to re-parse and would have silently kept the old
first-service behaviour. That is the same cache-state-dependent divergence #208 exists to fix,
and reproducing it here would have been self-defeating.

## Decision 2: silence in the profile means "any", not "none"

`versions` is optional in TS 29.510, and **every** NF profile fixture in this tree omits it.
So:

* a service with an empty `versions` list matches any requested version;
* a candidate with no `services` list matches any request and keeps its profile-level endpoint;
* a `None` requested service name or version matches everything.

Reading a missing optional field as "supports no version" would have turned this change into a
fleet-wide outage: every existing producer would have started answering `400 INVALID_API`. The
strictness has to attach to what the profile actually *says*, which is the same reasoning
recorded for the RFC 3339 offset decision — refuse only what is genuinely undecidable.

`apiFullVersion` is deliberately **not** consulted to synthesise a major version. Deriving `v1`
from `1.R15.1.1` is a guess about a string this codebase has no other reader for, and a wrong
guess produces an `INVALID_API` for a conformant producer. An entry with no `apiVersionInUri`
is skipped, which folds into the "declares none" case above.

## Decision 3: two filter stages, because the consumer is owed two different answers

```
stage 1  candidates offering the requested serviceName   -> else ServiceNotOffered
stage 2  ...of those, those serving the requested version -> else UnsupportedApiVersion
stage 3  existing health/priority/capacity ordering WITHIN the stage-2 set
```

Collapsing the stages would have been shorter and wrong: "no producer serves `nudm-ueau`" and
"`nudm-uecm` exists but only at `v1`" are different facts, and only the second is
`INVALID_API` (TS 29.500 Table 5.2.7.2-1). The first is a discovery failure — the NRF returned
nothing usable for the service — and stays `502 NF_DISCOVERY_FAILURE`. Telling a consumer
`NF_DISCOVERY_FAILURE` when its own requested version is the problem sends it to retry
something that cannot succeed; telling it `INVALID_API` when the NRF is simply empty sends it
to change a URI that is correct.

Stage 3 runs *inside* the matched set, so a single-service producer selects exactly as before.

Note the two stages are **not** independent: stage 2's predicate re-applies the name match, so
deleting stage 1 alone changes no routing outcome — only the error variant. That was found by
reverting stage 1 and watching only the error-taxonomy test fail (see Verification).

## Decision 4: the request URI is authoritative for the service name

`3gpp-Sbi-Discovery-service-names` is a *list*, and the issue names it first. It is used only
as a fallback, and only when it names exactly one service. The URI is what will actually be
sent to the producer, so `/nudm-uecm/v1/registrations` names the service being invoked with no
ambiguity; picking an element out of a multi-valued header would reinstate exactly the
arbitrary choice this change removes.

## Decision 5: cache the SearchResult before selecting from it

`discovery_cache.put` moved to *before* selection. The cache holds what the NRF answered, which
stays valid for other requests even when it cannot serve this one's API version. And a cache
hit that cannot serve the request falls through to a fresh NRF query rather than erroring from
possibly-stale data: the TTL is the SearchResult's own `validityPeriod` (up to an hour), so a
producer offering the requested version may well have registered since. The error, when it
comes, is raised against current data.

## Acceptance criteria

- [x] `select_nf_service_endpoint` matches `serviceName` and API major version, and takes the
      endpoint from the matching `NFService`.
- [x] A test with a two-service producer on differing ports/prefixes asserts the requested
      service's endpoint is used — `test_model_d_addresses_the_requested_services_endpoint`
      (end to end, two live producers) and
      `test_select_endpoint_uses_the_requested_services_endpoint` (unit, both directions).
- [x] An unsupported API version yields `400 INVALID_API` rather than a forwarded request —
      `test_model_d_unsupported_api_version_is_400_invalid_api`, which asserts a **zero hit
      count on a live producer**, so the 400 cannot be a forward that happened to fail.
- [x] Single-service producers are byte-unchanged; all pre-existing selection tests pass
      untouched (the two scpd-01 tests were re-pointed at the new function, same assertions).
- [x] Workspace lint and the scpd suite pass.

## Verification

Workspace `5958 passed / 0 failed / 6 ignored` (baseline `5950`; +8 tests). `cargo clippy
--workspace` and `cargo fmt --all -- --check` clean — including the one `needless_lifetimes`
warning this change introduced and then removed, since CI gates on errors only and a warning
left behind is a broken window.

Three claims revert-verified:

| revert | expected to break | result |
|---|---|---|
| endpoint taken from `services.first()` instead of the matched entry | the two endpoint tests | **2 failed** |
| `service_version_matches` always `true` | the two version tests | **2 failed** |
| `service_name_matches` always `true` | endpoint + taxonomy + ordering tests | **4 failed** |

**The revert caught a false guard in my own test.** `test_select_endpoint_uses_the_requested_services_endpoint`
first used a fixture where the two services declared *different* versions (`v1` and `v2`), and
it **passed** with service-name matching disabled — the version filter alone resolved the
endpoint, so the test proved nothing about the thing it is named for. The fixture now gives
both services the same `v1`, making the name the only discriminator, and the same revert then
fails it. This is the recorded hazard exactly: a green test that looks like a guard and is not.
The reason is written at the fixture so it is not "simplified" back.

A fourth revert (deleting filter stage 1) was **inconclusive as a routing test and conclusive
as a taxonomy one**: only `test_select_endpoint_distinguishes_version_from_service_mismatch`
failed, because stage 2 re-applies the name predicate. Recorded in Decision 3 rather than
reported as a pass.

## Ceilings

* No test drives a producer that registers the same service **twice** with different endpoints
  (legal in TS 29.510 as separate `serviceInstanceId`s). The code takes the first matching
  entry; nothing pins that choice.
* `apiFullVersion` is unread, so a producer declaring only `apiFullVersion` and no
  `apiVersionInUri` is treated as version-agnostic rather than matched precisely.
* `select_nf_instance_round_robin` was **not** made service-aware. It has no caller on the
  proxy path (`grep` finds only the `main.rs` re-export), so making it match would have been
  untested code; flagged rather than half-done.
* GitNexus impact analysis unrunnable — no MCP server connected, so `nextgcore/CLAUDE.md`'s
  mandate to run `gitnexus_impact` before editing `select_nf_instance` and
  `gitnexus_detect_changes` before committing could not be satisfied. Blast radius was
  established by grep instead: `NfInstanceCandidate` has no constructor outside
  `sbi_path.rs`, and `select_nf_instance`'s only non-test callers were `proxy.rs::discover`
  and the two re-exports in `main.rs`.
