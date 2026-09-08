# nextgcore #208 (scpd): keep producer routing metadata across a cache hit, preserve a downstream Producer-Id, and fix up a retargeted Location

Verified against `main` @ `69ec2f3` (after #207, #211 and #209 — same file). The issue's cites
are from `562b4a1`; all three still hold, one at a moved site.

## Verified against current main

| claim in the issue | site on `69ec2f3` | still true? |
|---|---|---|
| a cache hit constructs the producer with `nf_set_id: None, nf_group_id: None` | `proxy.rs:1325-1326` (moved by #209 from `:1145`) | yes |
| `relayable_response_headers` copies everything but hop-by-hop; `grep -c 'Location\|absolut'` over `proxy.rs` → `0` | `:543-549` | yes, `0` |
| the relay sets `3gpp-Sbi-Producer-Id` with `set_header`, replacing any downstream value | `:1725` | yes |

## Decision 1: fix the cause, not the symptom — parse set/group onto the candidate

The issue suggests "carry `nf_set_id`/`nf_group_id` in the discovery-cache entry so a hit
reconstructs the same producer identity as a miss". Done one level earlier: the fields are parsed
in `parse_search_result` onto `NfInstanceCandidate`, which *is* what the cache stores.

The difference matters. Adding them to the cache entry alongside a separate JSON read on the
fresh path leaves **two** code paths that must agree, which is the shape that produced the bug.
Parsing them onto the candidate makes the cache-hit and cache-miss arms build an identical
`DiscoveredProducer` **by construction** — there is no second source to diverge from.

Consequently `extract_set_and_group` and `group_id_from_profile` are **deleted** from `proxy.rs`
and their logic moved to `sbi_path.rs` as `nf_set_id_from_profile` / `nf_group_id_from_profile`,
called during parsing. `discover` no longer reads the raw `SearchResult` for anything but
`validityPeriod`.

This also fixes a second, unreported instance of the same bug that #209 had just created:
`forward_with_reselection` reports each producer's *own* identifiers, and on a cache hit every
alternate would also have carried `None`.

## Decision 2: preserve a downstream `Producer-Id`, do not append

§6.10.3.4 allows preserving or appending. The SCP now **leaves** an existing value alone and logs
that it did.

The reason to prefer the existing value is that it is more authoritative, not merely first: a
producer naming itself is first-hand, and a downstream SCP's value is derived from the profile of
the instance *it* selected. Ours is derived from the profile *we* read, which for a chain of SCPs
describes a hop rather than the endpoint. Appending would produce a multi-valued header whose
consumer-side parsing is unspecified in this codebase (`producer_id()` returns one `String`), so
it would create a value nothing here can read.

## Decision 3: add `3gpp-Sbi-Target-apiRoot`; do not absolutise the `Location`

§6.10.4 permits either. Three reasons for the header:

1. **Additive.** Absolutising rewrites a header the producer set, destroying what it said. Adding
   leaves the `Location` intact, so a consumer that ignores the fix-up is no worse off than
   today.
2. **It keeps the follow-up flowing through the SCP.** An absolute `Location` naming the producer
   invites the consumer to address it directly, silently abandoning binding stickiness, producer
   selection and the delegated token acquisition the SCP exists to perform. That is a worse
   outcome than the problem being fixed.
3. **It round-trips through code that already exists**, and is therefore testable end to end.
   `route()` reads `3gpp-Sbi-Target-apiRoot` on a *request*, so a consumer echoing the value back
   with the relative `Location` path takes the Model C path to the same producer with no new
   handling. Nothing in this tree would consume an absolute `Location`, so that alternative could
   only have been asserted, not exercised.

Scope is narrow and each edge is tested: only on a **2xx**, only when the SCP **retargeted**
(Model D or sticky binding — not Model C, where the consumer named the target), and only when the
`Location` is **relative** (an absolute one is already addressable). A 2xx with no `Location` gets
nothing, because there is no resource URI to follow up on.

`RelayContext` was introduced to carry `producer_id` / `group_id` / `retargeted` into the relay:
`forward_once` was at five positional parameters, three of them `Option`, and `retargeted` is not
derivable from the others (Model C and a Model D producer with an empty instance id both give
`producer_id: None`).

## Acceptance criteria

- [x] `nfSetId`/`nfGroupId` survive a discovery-cache hit; a test asserts the relayed
      `Producer-Id` is the same on a cache miss and on the following hit —
      `test_producer_id_is_identical_on_a_cache_miss_and_the_following_hit`, which asserts both
      the expected value **and** equality of the two.
- [x] A downstream-supplied `3gpp-Sbi-Producer-Id` is not overwritten —
      `test_a_downstream_producer_id_is_not_overwritten`, asserting the producer's exact value
      rather than merely that the header is present.
- [x] A relative `Location` on a 2xx after retargeting is handled, with the choice documented —
      `3gpp-Sbi-Target-apiRoot` is added;
      `test_relative_location_after_retargeting_gains_a_usable_target_apiroot` also **feeds the
      value back** and asserts the follow-up reaches the producer holding the resource.
- [x] Workspace lint and the scpd suite pass.

Beyond the criteria: two negative tests bound the fix-up
(`test_absolute_location_gets_no_target_apiroot`, `test_model_c_relative_location_is_not_annotated`),
because a fix-up applied too widely is its own defect.

## Verification

Workspace `5976 passed / 0 failed / 6 ignored` (baseline `5971` after #209; +5 tests). `cargo
clippy --workspace` and `cargo fmt --all -- --check` clean, zero warnings.

Five claims revert-verified — including **both directions** of the `Location` fix-up, since a
present-but-over-broad fix-up would have passed a presence-only check:

| revert | expected to break | result |
|---|---|---|
| cache-hit arm hardcodes `None` again | cache-miss-vs-hit test | **1 failed** |
| `set_header` overwrites the downstream `Producer-Id` | downstream test | **1 failed** |
| no `Location` fix-up at all | relative-Location round-trip test | **1 failed** |
| fix-up applied to **every** 2xx, Model C included | Model C negative test | **1 failed** |
| fix-up applied to absolute `Location`s too | absolute negative test | **1 failed** |

## Ceilings

* No test drives a **chain of two SCPs**, so "a downstream SCP's `Producer-Id` is preserved" is
  exercised with a producer standing in for the downstream SCP. The code path is the same header
  read, but the topology is simulated.
* The sticky-binding path is marked `retargeted: true` and therefore gets the `Location` fix-up,
  but no test exercises a relative `Location` on a sticky reselection specifically — the Model D
  test covers the same code.
* `Location` is matched case-insensitively only because `SbiHttpMessage::get_header` is
  case-insensitive; nothing pins that a producer sending `location:` lowercase is handled, beyond
  that shared helper's own tests.
* Nothing validates that the conveyed apiRoot is what a *conformant* consumer would echo — the
  round-trip test proves it works against **this** SCP's `route()`, which is the strongest claim
  available without a third-party consumer.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `extract_set_and_group` had one caller before deletion, and `NfInstanceCandidate` is still
  constructed only in `sbi_path.rs`.
