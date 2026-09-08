# nextgcore #211 (scpd): report the delegated-discovery failure conditions distinctly

Verified against `main` @ `f3152bc` (i.e. **after** #207 landed, which is the same file and the
same function). The issue's cites are from `562b4a1`; two of the three still hold verbatim and
one moved, because #207 restructured the empty-result path.

## Verified against current main

| claim in the issue | site on `f3152bc` | still true? |
|---|---|---|
| NRF transport failure → `502` cause `TARGET_NF_NOT_REACHABLE` | `proxy.rs:1262` (`upstream_error_response(&nrf.to_uri(), …)`) → `:568-582` | yes — and `grep -n NRF_NOT_REACHABLE` over the crate returns nothing |
| NRF non-200 → `502 NF_DISCOVERY_FAILURE` | `proxy.rs:1264-1271` | yes |
| empty/unusable `SearchResult` → `502 NF_DISCOVERY_FAILURE` | **moved**: now `endpoint_selection_error_response` `:630-641`, reached from `:1300` | yes, at a new site |

The move matters and is the reason #211 was done immediately after #207 rather than in parallel:
#207 replaced the inline `ok_or_else` with a three-variant `EndpointSelectionError` mapper, so
the "empty SearchResult" status is now decided in one function alongside the `INVALID_API` case
#207 added. Editing the old site would have compiled and changed nothing reachable.

## Decision 1: the status carries "can a retry help", the cause carries "which node"

Five delegated-discovery outcomes, each a distinct `(status, cause)` pair:

| condition | status | cause | change |
|---|---|---|---|
| no NRF configured / invalid NRF URI | 503 | `NRF_NOT_AVAILABLE` | unchanged |
| NRF unreachable or timing out | **504** | **`NRF_NOT_REACHABLE`** | was 502/504 `TARGET_NF_NOT_REACHABLE` |
| NRF answered non-200 | 502 | `NF_DISCOVERY_FAILURE` | unchanged |
| empty `SearchResult` / service not offered | **404** | `NF_DISCOVERY_FAILURE` | was 502 |
| requested API version unserved | 400 | `INVALID_API` | added by #207 |

`TARGET_NF_NOT_REACHABLE` is now reserved for producer-side unreachability, and
`upstream_error_response` says so in its doc comment so the next reader does not reuse it for
the NRF.

The two axes are deliberate. **Cause** names the node that failed: reporting an NRF outage as
`TARGET_NF_NOT_REACHABLE` sends the operator to investigate a producer that is up, which is the
most expensive kind of wrong answer here. **Status** answers "will a retry help": 5xx for
infrastructure (NRF down, NRF erroring), 4xx for the consumer's own input (criteria matched
nothing, version unserved).

## Decision 2: 404, and the cause is *not* invented

`404 Not Found` for an empty `SearchResult`, with the cause left as the spec's existing
`NF_DISCOVERY_FAILURE` rather than a new string. Two things to be explicit about:

* **The status is reasoned, not quoted.** TS 29.500 §6.10.8.2 requires the conditions be
  reported distinctly; it does not hand out a status per row that this spec can cite verbatim.
  `404` is chosen because the condition is "nothing matched your criteria" — semantically a
  not-found, and a client-side fact. `400` was rejected: the consumer's request is
  well-formed. `503` was rejected: nothing is temporarily unavailable.
* **No new cause string was minted.** `NF_DISCOVERY_FAILURE` is shared with the NRF-error row
  on purpose. Inventing a cause the spec does not define would put a value on the wire that no
  conformant consumer can interpret, which is worse than sharing a defined one — the two rows
  are already distinguishable by status, which is what the acceptance criterion asks for.

Known cost, stated rather than hidden: a consumer now sees `404` from the SCP for "no producer
found" and `404` from a *producer* for "resource not found". They are distinguishable — the
SCP's carries `Server: SCP-<fqdn>` (stamped on every SCP-originated discovery error in
`handle`) and a ProblemDetails with cause `NF_DISCOVERY_FAILURE`, while a producer 404 is
relayed verbatim with the producer's own body — but a consumer that reads only the status
cannot tell them apart. Accepted: the alternative is keeping `502`, which is the defect.

## Decision 3: both a refused connection and a timeout are 504

`nrf_unreachable_response` does not split them the way `upstream_error_response` does. To the
consumer they are the same actionable fact (the NRF is not answering, retry may help), and the
distinction the issue cares about is NRF-vs-producer, not refused-vs-timed-out. The underlying
`SbiError` is still in the `detail` string for an operator.

## Acceptance criteria

- [x] A transport failure to the NRF yields `504` with cause `NRF_NOT_REACHABLE` —
      `test_unreachable_nrf_is_504_nrf_not_reachable`, which also asserts the cause is **not**
      `TARGET_NF_NOT_REACHABLE`.
- [x] An empty `SearchResult` yields a discovery-specific 4xx — `404`,
      `test_nrf_returning_no_candidates_is_404_discovery_failure` (the pre-existing test,
      **inverted**).
- [x] A genuine NRF error response still yields `502 NF_DISCOVERY_FAILURE` —
      `test_nrf_error_response_is_502_discovery_failure`.
- [x] `TARGET_NF_NOT_REACHABLE` is used only for producer-side unreachability —
      `test_target_nf_not_reachable_is_still_used_for_the_producer` pins that the Model C path
      *still* reports it, so the reservation is a narrowing and not a removal.
- [x] Tests assert status **and** cause for all three, distinguishing them from one another —
      `test_three_discovery_failures_are_pairwise_distinct` drives all three against the same
      helper and asserts the pairs are pairwise unequal.
- [x] Workspace lint and the scpd suite pass.

## One pinned-behaviour test inverted

`test_nrf_returning_no_candidates_is_502` → `…_is_404_discovery_failure`. The flip and its
reasoning are recorded at the test, per the repo's practice: the old assertion pinned the
defect, not the requirement. It made "your criteria matched nothing" indistinguishable from
"the NRF is down" and from "the producer is unreachable" — which is the entirety of #211.

## Docs corrected, including a staleness #207 introduced

`docs-book/src/configuration/scp.md:86` documented "NRF non-200 or no usable NF instance →
**502** `NF_DISCOVERY_FAILURE`". That single clause was wrong **twice**: once from this change,
and once already from #207, which added the `INVALID_API` path and service/version matching
without touching the page. #207 shipped a docs staleness and this change fixes it rather than
leaving it for a drift check — the same failure #252 hit and the reason its lesson exists. The
bullet is now three: admission, producer selection, and a five-row failure table.

## Verification

Workspace `5962 passed / 0 failed / 6 ignored` (baseline `5958` after #207; +4 tests). `cargo
clippy --workspace` and `cargo fmt --all -- --check` clean, zero warnings.

Three claims revert-verified — and each revert was also checked against the *pairwise* test,
which is the one that would catch a future collapse:

| revert | expected to break | result |
|---|---|---|
| NRF query back through `upstream_error_response` | unreachable + pairwise | **2 failed** |
| empty-result rows back to `502 Bad Gateway` | inverted test + pairwise | **2 failed** |
| NRF-error row changed to `404` (collapsing it into the empty case) | NRF-error + pairwise | **2 failed** |

The third revert is a pin on *unchanged* behaviour, so reverting it means changing it — worth
running anyway, because a test asserting a value the code never varies proves nothing until you
vary it.

## Ceilings

* Nothing drives a real NRF that accepts the TCP connection and then stalls mid-response, so
  `SbiError::Timeout` on the NRF path is covered by the `nrf_unreachable_response` unit path
  and by the refused-connection case, not by an observed timeout.
* The 404 / producer-404 ambiguity in Decision 2 is argued, not tested: no test asserts a
  consumer can distinguish them, because doing so would assert on `Server` header plumbing
  that `test_scp_originated_error_carries_server_header` already covers separately.
* #209 (alternate-producer reselection) also touches `upstream_error_response`'s
  connection-refused mapping and lands **after** this. Its branch must re-verify these five
  rows rather than assume them — specifically, #209 changes the *producer* exhaustion case to
  `504`, which must not be allowed to collide with `NRF_NOT_REACHABLE`'s row.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `upstream_error_response` has two callers (the NRF query, now removed, and `forward`),
  `endpoint_selection_error_response` one.
