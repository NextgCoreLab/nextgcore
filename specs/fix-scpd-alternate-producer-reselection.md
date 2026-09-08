# nextgcore #209 (scpd): fail over to an alternate producer, and 504 when the set is exhausted

Verified against `main` @ `cb26714` (i.e. after #207 and #211, which are the same file). The
issue's cites are from `562b4a1`; all three still hold, at new line numbers, and the third
changed shape.

## Verified against current main

| claim in the issue | site on `cb26714` | still true? |
|---|---|---|
| `forward()` issues one `client.send_request(fwd)` and returns on `Err` | `proxy.rs:1600`, error arm `:1601-1607` | yes |
| the rest of the candidate list is parsed and discarded | `discover` took only the ranked head (`:1423`) | yes |
| connection-refused maps to `502 TARGET_NF_NOT_REACHABLE` | `upstream_error_response` `:568-582` | yes |

**Approach precondition that had changed:** the issue says to "keep the ordered candidate list on
the discovery result". After #207 there *is* no ordered list — `select_nf_service_endpoint`
returned one `SelectedEndpoint` and dropped the rest. So the first step was building the ranked
list (`rank_nf_service_endpoints`), which the issue assumes already exists.

## Decision 1: `ForwardOutcome`, because a single `SbiResponse` cannot express "try elsewhere"

`forward` returned `SbiResponse` for every case — a producer 500, a refused connection and a
token failure all came back as *an answer*. Reselection is impossible on top of that, which is
why the split is the first change rather than a refactor bolted on afterwards:

```rust
enum ForwardOutcome {
    Answered(SbiResponse),          // the producer answered, at any status
    Undeliverable(Undeliverable),   // provably never arrived; another candidate may serve it
    Final(SbiResponse),             // no other candidate could improve on this
}
```

`forward_once` returns it; `forward` (Model C / sticky, no alternates) collapses it back to the
**pre-existing** mapping so those paths are unchanged; `forward_with_reselection` (Model D)
loops.

`Final` is not a synonym for "error". A delegated token the NRF refused is `Final` because the
token is minted for `(consumer, target NF **type**, scope)` — every instance of that type would
be refused identically, so reselecting would only repeat the NRF round-trip.

## Decision 2: reselect only on a provably pre-send failure

The issue offers a choice: "restrict reselection to failures that provably occurred before the
request was sent (connect refused), **or** document the exposure." Taking the first option, so
there is no exposure to document:

| `SbiError` | replayable | why |
|---|---|---|
| `ConnectionError` | **yes** | produced only by TCP connect (`client.rs:452`) and the HTTP/2 handshake (`:514`, `:529`) |
| `TlsError` | **yes** | server-name validation and TLS handshake (`:457`, `:465`) |
| `Timeout` | no | produced by the connect phase (`:451`, `:464`) **and** the send/response phase (`:892`) — cannot tell "never sent" from "sent, still working" |
| `HyperError` | no | `:893`, after `send_request` began |
| everything else | no | request-shape errors; another producer would reject identically |

`Timeout` is the load-bearing exclusion. It *looks* like a transport failure, and replaying a
`POST` on one could duplicate a registration or a charging record. `test_a_timeout_does_not_reselect`
pins that a live sibling stays untouched when the first candidate times out.

## Decision 3: an open circuit reselects instead of shedding

This is the interaction the issue names: "the breaker stops *repeatedly* hitting a dead
producer, but it does not retry a different one, so the first request after the circuit opens
still fails." An Open circuit therefore returns `Undeliverable` (nothing was sent, so it is
trivially pre-send) and the Model D path tries the next candidate. The dead producer stays
protected — `test_an_open_circuit_reselects_rather_than_shedding` asserts its hit count does
**not** move while the sibling's does.

If *every* candidate is shed by its own breaker, the answer stays **503** rather than becoming
504: nothing was put on the wire, so that is load shedding and "retry shortly" is true — the
breakers will half-open. Only an attempt list containing a real transport failure yields 504.

## Decision 4: 504 on exhaustion in Model D, 502 still in Model C

The issue asks for 504 on exhaustion. The asymmetry with Model C is deliberate and worth
stating, since it is the same underlying `ConnectionError`:

* **Model D** — the SCP owns selection. Exhausting the whole candidate set means the SCP's
  upstream is not answering, which is what 504 says.
* **Model C / sticky** — the *consumer* pinned the target. There is no set to exhaust, so the
  failure is that one hop and keeps its 502.

`(504, TARGET_NF_NOT_REACHABLE)` does not collide with #211's `(504, NRF_NOT_REACHABLE)`: the
cause still names which node failed, which was #211's whole point. Asserted in
`test_model_d_exhausted_candidates_is_504_distinct_from_discovery_failure`.

## Decision 5: rank by re-running the rule, not by sorting

`rank_nf_service_endpoints` builds the order by calling `select_best` repeatedly and removing
the winner, rather than sorting on `(priority, -available_capacity)`. `select_best` breaks a
capacity tie with `max_by_key`, which yields the **last** maximum; a descending sort yields the
first. Re-running the real rule makes "the ranked head IS the single pick" true by construction
instead of by reproducing a tie-break that would drift.
`test_ranked_endpoints_head_matches_the_single_pick` uses a fixture with a deliberate tie and
pins the whole order, so the tie-break is documented rather than incidental.

**The pool rule is applied once, up front, and that was found by a failing test.** The first
version let the loop run until the pool emptied — and because `select_best` falls back to "all
candidates" when none are healthy, that handed back every `SUSPENDED` instance as a last-resort
alternate once the healthy ones were exhausted. A `SUSPENDED` NF must not be selected
(TS 29.510 `nfStatus`), so that would have traded a reachability problem for a conformance one.
The healthy-if-any pool is now computed before ranking, with the reasoning at the site;
`test_ranked_endpoints_exclude_unhealthy_while_a_healthy_one_exists` pins it. The pre-existing
leniency — use everything when the NRF reports nothing healthy at all — is untouched, because
that is a different case.

## Decision 6: the bound is operable, and it is logged when it bites

`max_producer_attempts`, default **3** (selected producer plus two alternates), clamped to ≥ 1,
and wired through the established YAML path (`scp.max_producer_attempts` → `config.rs` →
`main.rs` → `ScpProxyConfig`) with a commented-out entry in the shipped `scp.yaml`. A tuning
field reachable only from Rust would be close to a dead field; every sibling knob
(`max_cache_entries`, `cache_ttl`, the timeouts) already follows this path.

When the bound leaves candidates untried, that is logged at `warn` with both counts. Trying 3
of 9 and then reporting "could not reach any producer" would overstate what the SCP did.

## Acceptance criteria

- [x] A forwarding transport failure triggers reselection before any error is returned.
- [x] A test with two candidates, the first refusing connections, asserts the second served the
      request — `test_model_d_reselects_the_next_candidate_when_the_first_refuses`, which also
      asserts the relayed `Producer-Id` names the **second** instance.
- [x] Connection-refused with no remaining candidates returns `504`, distinguished by a test
      from a `502` discovery error — both driven in one test and asserted unequal.
- [x] Reselection does not fire on a producer-generated 4xx/5xx —
      `test_model_d_does_not_reselect_on_a_producer_error`, with a **live** second candidate at
      hit count 0, so "did not reselect" is distinguished from "reselected and also failed".
- [x] The idempotency decision is documented in code — `is_provably_undelivered`'s doc comment
      cites the exact `client.rs` lines for each variant, and
      `test_only_pre_send_failures_are_replayable` pins it.
- [x] Workspace lint and the scpd suite pass.

Beyond the criteria: the circuit-breaker interaction the issue flags in prose but does not list
as a criterion is implemented and tested, and the attempt bound is operator-configurable.

## Verification

Workspace `5971 passed / 0 failed / 6 ignored` (baseline `5962` after #211; +9 tests). `cargo
clippy --workspace` and `cargo fmt --all -- --check` clean, zero warnings.

Five claims revert-verified:

| revert | expected to break | result |
|---|---|---|
| stop after the first candidate (no reselection) | reselect + bound + circuit tests | **3 failed** |
| exhaustion keeps the single-target mapping (502) | exhaustion + bound tests | **2 failed** |
| treat a producer 5xx as `Undeliverable` | producer-error + circuit + 2 pre-existing | **4 failed** |
| add `Timeout` to `is_provably_undelivered` | timeout + unit tests | **2 failed** |
| open circuit returns `Final` 503 again | circuit test | **1 failed** |

The third revert is worth noting: it also broke two **pre-existing** tests
(`test_circuit_breaker_opens_sheds_load_then_probes`, `test_relayed_500_carries_no_producer_id`),
which is independent evidence that "a producer that answered is relayed" was already load-bearing
behaviour and not merely a new assertion of mine.

#211's handoff note asked this branch to re-verify its five failure rows rather than assume them.
Done: `test_three_discovery_failures_are_pairwise_distinct` and
`test_unreachable_nrf_is_504_nrf_not_reachable` both still pass, and the new exhaustion pair is
explicitly asserted distinct from the discovery-error pair.

## Docs corrected — including a much older staleness found on the way

`docs-book/src/configuration/scp.md` gains the reselection rules, the new failure row, and the
`scp.max_producer_attempts` key. Adding that key exposed a **pre-existing** contradiction on the
same page, which had to be resolved rather than shipped alongside:

* the intro said configuration is "CLI flags and environment variables only" and "the daemon
  does not parse" the YAML;
* the honesty note said the daemon "reads the YAML config file only to log its byte count", that
  `main.rs` holds a `// In C: scp_context_parse_config()` placeholder, and that "no
  `#[derive(Deserialize)]` config structs exist anywhere in the crate";
* a "YAML parameters" section read "**None.**";
* and five keys were listed as inert.

All of that is false as of `cb26714`: `config.rs` exists with serde structs, and `main.rs` reads
the SBI address/port, NRF URI, `fqdn`, `nf_instance_id`, both timeouts, the cache bounds and
`sbi.tls.enabled`/`cert`/`key`. Only `tls.ca` and `tls.min_version` remain unread. The page now
carries a live-vs-inert table, the corrected precedence, and an explicit note that the previous
claim no longer holds. This is scoped to the config-parsing claims — the `-k/--kill` and
`-l/--log-file` stub claims are left alone, having not been re-verified here.

## Ceilings

* No test exercises a **TLS** handshake failure driving reselection; `TlsError` is covered by
  the unit predicate only, because the mock producers are plaintext.
* Reselection is not applied to the Model C or sticky-binding paths, by design (no candidate
  set). An `nf-set` Routing-Binding *could* in principle reselect among learnt set members;
  that is scpd-11's surface, not this one, and is left alone.
* `select_nf_instance_round_robin` still has no caller and was not made rank-aware.
* Ports 1 and 2 on loopback are used as "refuses immediately" in tests, following the
  pre-existing `test_unreachable_target_is_502_problem`. Should something ever listen there the
  tests would fail loudly rather than silently pass.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep: `forward`
  had three call sites (all in `handle`), and `DiscoveredProducer` was constructed only inside
  `discover`.
