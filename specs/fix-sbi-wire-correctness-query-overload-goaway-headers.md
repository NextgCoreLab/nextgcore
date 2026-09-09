# nextgcore #65 (nextgcore-sbi): query percent-decode, overload reaction, GOAWAY drain, header multiplicity

Verified against `main` @ `60eecd6` (after #205, #242, #95, #204, #215, #111, #267, #105, #100).
The issue's cites are from `76ea248`, so every line number drifted; one whole claim is now **stale**.

## Verified against current main

| claim in the issue | check on `60eecd6` | still true? |
|---|---|---|
| `send_once` builds the query by raw `format!` with no percent-encoding (`client.rs:753-768`) | now `client.rs:799-824` | **NO — already fixed by #101**, which routes both key and value through `uri_encode::encode_query_value` |
| the request `uri` is `req.uri().path()` only, discarding the query (`server.rs:544`) | `server.rs:563` | yes |
| the query is split and stored raw with no decoding (`server.rs:562-568`) | `server.rs:581-584` | yes |
| a parameter lacking `=` is dropped | `server.rs:583` `if let Some((key, value)) = pair.split_once('=')` | yes |
| nssfd carries a local `percent_decode` (`main.rs:481-519`, `:658-666`) | `main.rs:657-680` (the cite drifted ~180 lines) | yes |
| mbsmfd feeds the raw param to `serde_json::from_str` (`main.rs:1350-1351`) | `main.rs:1356-1357` | yes |
| `OverloadControl::enabled` defaults false and nothing consumes OCI/LCI | `overload.rs:12`; grep for `Oci::parse` outside `overload.rs` → **nothing** | yes |
| `stop()` only fires `shutdown_tx`; no GOAWAY, nothing drained | `server.rs:955-965`, connections spawned detached at `:904`/`:931` | yes |
| headers are `HashMap<String, String>`, collapsing repeats | `message.rs:192` | yes |
| `SNssai.sd` is `Option<[u8;3]>` and the type is publicly re-exported | `message.rs:876`, `lib.rs:85-88` | yes |

Two things the issue did not name, found while verifying:

* **nrfd's decoder is used for two different surfaces, and is wrong for one of them.**
  `nrfd/main.rs:379` maps `+` to a space and was applied to *query* values (`:1752`, `:2205`) as
  well as to the `application/x-www-form-urlencoded` token body (`:3113`). `+` is a space only in
  the form encoding; in an RFC 3986 query component it is a literal plus. So a query value carrying
  a base64 token or an RFC 3339 offset (`+02:00`) was silently corrupted. This is the exact hazard
  `uri_encode`'s module docs predicted for the *encode* direction, in the decode direction.
* **nssfd's shim would have become a double-decode.** Once the server decodes,
  `percent_decode(params.get(k))` decodes twice, and a value whose plaintext legitimately contains
  `%20` (sent as `%2520`) turns into a space nobody sent. So removing the per-NF shims is a
  correctness requirement of this change, not tidying that could be deferred.

## Read this first: the encode half was already done, the decode half was the defect

The issue's headline is "the client composes query strings by raw `format!` … and the server drops
the query string and never percent-decodes". Only the second half is true today. #101 fixed the
client in the one place every SBI query passes through.

That matters for how the fix is shaped: there was nothing to add on the emit side, and the
`encode_query_value` / `encode_form_value` **pair** #101 deliberately kept separate (they differ on
`+`, and merging them corrupts one surface) dictated the shape of the decoders. This change adds
`decode_query_value` / `decode_form_value` as the mirror pair, with the same anti-deduplication
guard pinning the one input they disagree on.

## What was added / changed

| area | change |
|---|---|
| `uri_encode.rs` | `decode_query_value` / `decode_form_value` (+ `hex_val`), mirroring the encoder pair. Byte-wise so multi-octet UTF-8 reassembles; malformed escapes pass through verbatim; infallible via lossy UTF-8 |
| `server.rs` `convert_request` | query keys **and** values percent-decoded with the QUERY decoder; `=`-less flags kept as present-but-empty; headers ingested with `append_header` so repeated field lines survive |
| `client.rs` `convert_response` | same `append_header` ingest, so a multi-scope OCI on a response is not collapsed |
| `message.rs` | `append_header` (RFC 9110 §5.3 comma-combining) and `get_header_all` (splits on top-level commas, quoted commas respected) |
| `overload.rs` | `OverloadRegistry` (consumer-side memory of which producers reported overload, per target × scope, with expiry), `SendDecision`, `DEFAULT_OCI_VALIDITY`, `OverloadReporter` (producer-side metric the SBI server stamps) |
| `client.rs` | `send_with_overload_reaction` around the existing send stack; `with_alternate_targets`, `with_overload_shedding`, `overload_registry()`; `ConnectTarget::base_uri`; binding learned from `3gpp-Sbi-Binding` and echoed as `3gpp-Sbi-Routing-Binding` |
| `error.rs` | `SbiError::OverloadShed`, reporting onward as 503 |
| `server.rs` | `RunningState` (accept shutdown + graceful watch + drain barrier), `serve_connection_gracefully`, `GRACEFUL_DRAIN_TIMEOUT`, `stop()` rewritten; `SbiServerConfig::with_overload_reporter` and OCI stamping in `convert_response_with_identity` |
| `message.rs` | TS 29.571 serde for the `CommonData` types: `hex3`, `hex3_opt`, `digits3`, `digits_var`; `Tai.plmn_id`/`Guami.amf_id` renamed to `plmnId`/`amfId` |
| nssfd, nrfd | local `percent_decode` copies deleted; nrfd's form body now uses `decode_form_value` and its query path `decode_query_value`; both stop decoding `http.params` |
| mbsmfd | no code change needed — the "shim" the issue names is correct once the server decodes; an end-to-end test now pins it |
| scpd | a comment claiming the client serialises params verbatim was false since #101; corrected |

## Decision 1: reselection is on by default, shedding is not

TS 29.500 §6.4.2.2 mandates abatement, and the recorded convention is that new behaviour ships as a
runtime switch **defaulting ON, except where the behaviour drops traffic**. Overload reaction has
both kinds in it, so it is split:

* **On by default:** recording an OCI, and *reselecting* to an alternate producer. Neither can lose
  a request — rerouting sends it somewhere healthier, and with no alternate configured (the
  default) the decision degrades to "send", which is byte-identical to the pre-change client.
* **Off by default:** *shedding*, i.e. failing a request locally without sending it. It is the
  spec's literal reaction, and it is the one that converts a producer's header into dropped
  requests here. A `metric: 100` with no `Period-of-Validity`, sent in error, would otherwise stop
  this consumer talking to a healthy producer indefinitely.

`the_default_client_records_oci_but_does_not_shed` is the guard on that default: same producer, same
OCI, one builder call different from the shedding test. Whether shedding should become the default
is a deployment-posture call for the maintainer and is filed separately as a `decision` issue.

## Decision 2: an absent Period-of-Validity gets a 30s local ceiling

§6.4.3.3 makes the parameter optional and says an OCI applies until superseded. Taken literally, a
producer that reported overload once and then went quiet is avoided **forever**. The ceiling makes
the worst case "wrong for 30 seconds"; a producer that is still overloaded restates the OCI on its
next response, which refreshes the entry. A *declared* validity is honoured as sent, however long —
the producer said what it meant.

## Decision 3: only the unscoped OCI decides; scoped ones are recorded

§6.4.3.3 allows an OCI to name a scope (`NF-Instance`, `S-NSSAI`, `DNN`). Matching a per-S-NSSAI or
per-DNN scope needs the request's S-NSSAI/DNN, which lives in the body and is not available at the
transport layer. So scoped occurrences are stored and countable (`live_count`) but do not gate
requests. The alternative — applying a per-DNN metric to every request — would shed traffic for a
reason the producer did not state.

## Decision 4: header multiplicity via RFC 9110 §5.3 combining, not a second map

`headers` is a `pub` field with **88 direct readers** across the tree. Changing its type to
`HashMap<String, Vec<String>>` is a mechanical edit at all 88, and adding a parallel multi-valued
map beside it creates two sources of truth that can disagree — the denormalised-pair hazard this
repo has already been bitten by. Instead occurrences are combined into one field value separated by
`, `, exactly the representation RFC 9110 §5.3 sanctions, and `get_header_all` splits them back.
Safe for OCI/LCI/Binding, whose grammars are `;`-separated and contain no commas. Documented as
unsuitable for `Set-Cookie` (SBI carries no cookies) and for singleton fields whose value may
contain a comma.

## Decision 5: the query is decoded into `params`, not re-attached to `header.uri`

The issue's suggested approach says to "preserve the raw query" on the request URI. Deliberately not
done: `header.uri` is what every daemon routes on, and the routers split it on `/` and match path
segments exactly, so a query suffix would land inside the last segment and break routing across 19
daemons. `http.params` is where every consumer already reads query values, and scpd's proxy copies
`http.params` into the forwarded request (`proxy.rs:1683`), which the client re-encodes — so
decode-in/encode-out is correct across a proxy hop as well.

## Verification

Every guard below was revert-verified: the change was undone, the **named** test was watched to
fail, then restored.

| guard | revert applied | result |
|---|---|---|
| `server_percent_decodes_query_parameters` | `set_param(key, value)` verbatim again | FAILED ✓ |
| `percent_encoded_tmgi_list_deallocates_and_does_not_400` (mbsmfd) | same | FAILED ✓ |
| `server_preserves_valueless_query_flags` | `continue` on a missing `=` | FAILED ✓ |
| `server_keeps_every_repeated_oci_occurrence` | `append_header` → `set_header` on ingest | FAILED ✓ (see below) |
| `stop_drains_an_in_flight_request` | `graceful_shutdown()` + drive → early `Ok(())` | FAILED ✓ |
| `responses_carry_oci_when_the_nf_reports_overload` | reporter never consulted | FAILED ✓ |
| `a_503_with_oci_reroutes_the_next_request_to_an_alternate` | `send_request` back to the pre-#65 body | FAILED ✓ |
| `shedding_stops_the_next_request_from_being_sent_at_all` | same | FAILED ✓ |
| `the_default_client_records_oci_but_does_not_shed` | same | FAILED ✓ |
| `a_learned_binding_is_echoed_on_the_next_request` | same | FAILED ✓ |
| `an_oci_on_a_success_response_is_recorded_and_acted_on` | same | FAILED ✓ (see below) |
| `scoped_oci_is_recorded_but_only_the_unscoped_one_decides` | `effective_oci` returns any live entry | FAILED ✓ (see below) |
| `an_oci_without_a_validity_period_expires_under_the_ceiling` | ceiling → effectively unbounded | FAILED ✓ |
| `snssai_serialises_sd_as_six_hex_characters`, `tai_and_guami_serialise_per_ts_29_571` | `with = "hex3"` / `hex3_opt` removed | FAILED ✓ |

### Three of my own guards proved nothing on the first attempt

1. **`server_keeps_every_repeated_oci_occurrence` passed with the fix reverted.** It drove the
   request through `SbiClient`, which stores headers in a map and can only emit **one field line per
   name** — so the two occurrences were comma-joined *before* the wire and the test was really
   exercising `get_header_all`'s splitting, not the server's ingest. Rewritten with a raw
   `hyper::client::conn::http2` client, where `Request::builder().header()` appends and two genuine
   field lines cross the wire. Only then did the revert bite.
2. **`metric_zero_on_a_success_response_clears_the_reaction` passed with the entire reaction
   reverted.** It asserted that *nothing happened* (no reroute), and an absence is satisfied by a
   code path that never arrives. Replaced by two positive tests:
   `an_oci_on_a_success_response_is_recorded_and_acted_on` (the alternate serving the second request
   is the only way it can pass) and `metric_zero_supersedes_a_live_reduction`, which asserts *both*
   states — Reselect while live, Send once withdrawn.
3. **`scoped_oci_is_recorded_but_only_the_unscoped_one_decides` passed with the scope logic
   reverted.** It used a default registry, where every branch ends in `Send` because shedding is
   off — the outcome was decided by the default posture, not by scope. Rewritten against a
   `with_shedding()` registry, which leaves scope as the only variable.

All three are the same failure mode from the other side: the test was reachable by a second route to
the expected outcome.

## Workspace state

`6052 passed / 0 failed` (main: `6024`), `cargo clippy --workspace --all-targets` 0 errors,
`cargo fmt --all --check` clean.

## Ceilings

* **No wire interop.** Everything is verified against this tree's own client and server. "Decodes
  conformantly" means "matches RFC 3986 and the TS 29.500 prose", not "was accepted by another
  vendor's NF".
* **GOAWAY is asserted by consequence, not by frame.** `stop_drains_an_in_flight_request` proves
  the in-flight stream completes and that `stop()` *waited* for it; `stop_refuses_new_connections`
  proves the listener closed. Neither reads the GOAWAY frame — hyper exposes no hook for the peer's
  view of it, so frame-level inspection would need a raw h2 client this crate does not otherwise
  use. The behaviour is pinned; the frame is inferred.
* **The drain has a 5s bound.** A peer holding a stream open past it is abandoned with a warn line
  naming the consequence. Unbounded waiting would hang `stop()`, which runs in test teardown and on
  the daemons' SIGTERM path.
* **`OverloadReporter` measures nothing.** It carries a metric the NF sets. No NF sets one yet, so
  the producer half is wired and reachable but not driven — a generic HTTP layer has no basis for
  deciding an AMF is overloaded, and inventing one from request latency would report overload the NF
  does not believe in. Filed as a follow-up rather than guessed at here.
* **Alternate targets are empty by default**, so reselection is live-but-inert until an NF passes
  the producers it discovered. That plumbing is per-daemon (each has its own NRF discovery path) and
  is not in this change.
* **`3gpp-Sbi-Callback` / `3gpp-Sbi-Message-Priority` emission is NOT included.** It appears in the
  issue's suggested approach item 4 but in **none** of its acceptance criteria. It is also already
  scoped in the backlog as cross-NF work needing a per-NF survey of which notifications exist. Not
  smuggled in here.
* **Binding reselection is the §6.12.2 echo, not NF-set resolution.** A learned `3gpp-Sbi-Binding`
  is conveyed back as `3gpp-Sbi-Routing-Binding` so an SCP can route on it. Resolving an `nfset` to
  addresses needs NRF discovery, which this crate does not have.
* **`get_header_all` splits on commas.** Correct for the list-valued fields it is meant for; wrong
  if applied to a singleton field whose value contains a comma (an IMF-fixdate `Date`). Documented
  at the accessor.
* **The `CommonData` types remain in-memory-only.** Nothing outside `nextgcore-sbi::context`
  constructs them and no NF serialises them to the wire today; each daemon has its own S-NSSAI /
  PLMN type. The serde fix makes the publicly re-exported shape correct for a future user rather
  than fixing a live wire defect. `PlmnId.mnc` keeps its stored width, so a 2-digit MNC cannot be
  padded into a different network.
* GitNexus impact analysis unrunnable (no MCP server connected — 47th consecutive PR).
  `nextgcore/CLAUDE.md`'s mandate to run `gitnexus_impact` before editing stays unsatisfiable.
  Blast radius by grep: `set_header` on an ingest path (2 sites, both changed); direct `.headers`
  field readers (88, all unaffected because the field type and its single-valued semantics are
  unchanged); `percent_decode` (3 definitions, 2 deleted, 1 was seppd's unrelated `b64url_decode`);
  `convert_response_with_identity` (3 production + 4 test call sites, all updated);
  `SbiService` construction (3 sites); no crate outside `nextgcore-sbi` names `OverloadControl`,
  `Oci`, `Lci`, or the `CommonData` types.
