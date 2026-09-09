# nextgcore #100 (seppd): N32-c handshake IEs, telescopic FQDN, dead security modules

Verified against `main` @ `b4c70e4` (after #205, #242, #95, #204, #215, #111, #267, #105). Every
cite in the issue still holds.

## Verified against current main

| claim in the issue | check on `b4c70e4` | still true? |
|---|---|---|
| the capability is renamed to lowercase `3gppSbiTargetApiRootSupported` | `n32c_build.rs:174` | yes |
| ...and typed `Option<i32>` | `n32c_build.rs:175` | yes |
| ...serialised as `Some(1)` / `None` | `n32c_build.rs:199-203`, `:248-252` | yes |
| ...read as `== Some(1)` | `n32_server.rs:185`, `:196` | yes |
| `SecParamExchReqData.sender` is a bare `String` with no `serde(default)` | `n32c_handler.rs:208-210` | yes |
| ...and an empty `sender` is refused `MANDATORY_IE_INCORRECT` | `n32c_handler.rs:704-706` | yes |
| no `/mapping` route, no telescopic handler | `grep -rn 'telescopic\|/mapping' bins/nextgcore-seppd/src/` → **nothing** | yes |
| `pqc_security.rs` (762 lines) and `zero_trust.rs` (336 lines) are declared and never called | `lib.rs:16`, `main.rs:27`; grep found zero call sites outside the module files | yes |

Two things the issue did not name, found while verifying:

* **`SecParamExchRspData.sender` has the identical defect.** Its schema also lists
  `required: [n32fContextId]` only, and `n32c_handler.rs:791` refused an empty one the same way.
  Fixing only the request leg would still fail parameter exchange against a conformant peer, just
  on the response leg. Fixed with it.
* **The `422`-style over-requirement is not the only reason the anchor is severe.** See below: the
  type error aborts the *whole* body parse, so the flag is not merely misread.

## Read this first: the anchor is a parse abort, not a misread flag

`3GppSbiTargetApiRootSupported` was wrong in two ways at once, and the type was the dangerous one.

The receiving struct typed the member `Option<i32>`. Deserialising a JSON `true` into an `i32` is a
serde **type error**, not a defaulted field — `#[serde(default)]` applies to an *absent* member, not
a mismatched one. So a conformant peer sending `3GppSbiTargetApiRootSupported: true` did not merely
have its capability read as `false`: the entire `SecNegotiateReqData` parse failed and the
handshake was rejected with `400 MANDATORY_IE_INCORRECT`. That happened in exactly the case where
the peer *does* support target-apiRoot forwarding.

The name compounded it: with the lowercase `g` spelling, even a peer sending the integer form under
the correct capital-G name would have had its member ignored.

Both directions had to change together (emit and accept), which is what this change does.

## What was added / changed

| area | change |
|---|---|
| `n32c_build.rs` | `target_apiroot_supported` renamed to `3GppSbiTargetApiRootSupported` and retyped `bool` with `#[serde(default)]` in both `SecurityCapabilityRequestJson` and `SecurityCapabilityResponseJson`; both `From` impls emit the boolean directly; always serialised, never skipped |
| `n32_server.rs` | both `*_data_from_json` read the boolean; `resolve_exchange_params_peer` + the pure `single_pending_peer`; `TELESCOPIC_MAPPING_PATH`, `query_param`, `handle_telescopic_mapping`, and the route in `sbi_consumer_handler` ahead of the target-apiRoot check |
| `n32c_handler.rs` | `SecParamExchReqData.sender` and `SecParamExchRspData.sender` are `Option<String>` with `#[serde(default)]`; both handlers resolve the peer with an association fallback instead of refusing; downstream `register_peer_ipx_sec_info` / `resolve_exporter_secret` take the resolved FQDN |
| `telescopic.rs` (new) | `TelescopicMapping`, `label_for`, `map_foreign_fqdn`, `resolve_label`, `mapping_count`, `clear_mappings`, `MAX_TELESCOPIC_MAPPINGS` |
| `context.rs` | `GLOBAL_TEST_LOCK` / `lock_global_test_state` (test-only) |
| deleted | `pqc_security.rs` (762 lines), `zero_trust.rs` (336 lines), and their `mod` declarations |

## Decision 1: the capability is always serialised, never skipped

The schema gives it `default: false`, so omitting it is equivalent to `false`. It is emitted
unconditionally anyway: an explicit `false` says the same thing without making a peer infer our
capability from an absence, and it makes the golden-JSON assertion possible for both values rather
than only for `true`.

## Decision 2: an omitted `sender` resolves to the association, not to a refusal

`sender` is optional, so it cannot be the only source of the peer's identity. Resolution order:

1. `sender` when present — the normal case, no inference.
2. the host of `senderApiRoot`, this tree's own extension carrying the requester's N32-c apiRoot.
3. the single SEPP node whose N32-c is negotiated but not yet established.

Step 3 is what the spec relies on implicitly: `exchange-params` arrives on the same N32-c TLS
connection as the capability negotiation, so the peer is known *from the connection* — an identity
this server does not currently plumb through to the handler. It is deliberately restricted to the
**single**-candidate case: with two peers mid-handshake, picking one would derive the N32-f key
hierarchy against the wrong exporter secret and produce a context that establishes and then cannot
decrypt anything. That failure is silent, which is worse than a 400.

When nothing resolves, the answer is `400`. That is not the over-rejection this issue is about: a
spec-valid body from a peer that sent `senderApiRoot`, or in any deployment with one handshake in
flight, is accepted.

A `sender` that *is* present but names a third party is still an FQDN mismatch — on an established
association that body is either misrouted or an impersonation attempt.

## Decision 3: the telescopic label is a hash, and the store is what reverses it

TS 23.003 §28.5.2 requires the foreign FQDN to be replaced by **one** label (RFC 2818 wildcard
certificates cover a single subdomain level only) and its NOTE 1 says outright that *"how a SEPP
constructs the label to replace the other PLMN FQDN is implementation specific"*.

`tl` + the first 16 octets of `SHA-256(normalised FQDN)` in hex:

* **One label, always legal.** 34 characters of `[a-z0-9]` starting with a letter, inside the
  63-octet DNS limit for *any* input — including FQDNs that already contain hyphens, which a
  dots-to-hyphens transliteration could not encode unambiguously.
* **Deterministic and FQDN-case-insensitive** (DNS names are; a trailing root dot is stripped).
  The same NF must never get two labels, or a sibling SEPP's §5.4.3 lookup fails for a mapping this
  SEPP really did issue.
* **Not invertible without the store** — which §5.4.3 already assumes: its own wording is
  "determine if there is an **existing mapping**", and its 404 is a defined outcome.

A collision (128 bits of digest) keeps the *stored* mapping and logs at `error`, because that
mapping is the one a sibling SEPP may already have handed out.

## Decision 4: exactly one query parameter, and the route is matched before forwarding

Both query parameters are declared optional, but §5.4.2 and §5.4.3 are distinct procedures each
driven by one of them. Neither present asks nothing; both present asks two contradictory questions,
and answering one silently would return a mapping the consumer did not unambiguously request. So:
exactly one, else `400`.

The route is matched **ahead of** the target-apiRoot check in `sbi_consumer_handler`. A mapping GET
carries no `3gpp-Sbi-Target-apiRoot`, so without that ordering it would be refused `400` as "not a
roaming request" — the service is served to NFs in *this* PLMN, not forwarded.

`seppDomain` absent is a `500`, not a `200` with only the label: the consumer's whole purpose is to
form `<label>.<seppDomain>`, and a label alone is an answer it cannot use.

## Decision 5: the dead modules are deleted, not wired

`pqc_security.rs` and `zero_trust.rs` are removed rather than connected. TS 33.501 §13.2 mandates
neither a bespoke zero-trust policy engine nor an application-layer PQC implementation, and PR #30
already provides post-quantum protection where it belongs — at the TLS layer, hybrid
X25519MLKEM768. Wiring a hand-rolled application-layer PQC path would add a second, unreviewed
cryptographic implementation to a security function; 1098 lines that present as SEPP security while
executing nothing is the more honest thing to delete.

## Acceptance criteria

- [x] The capability serialises as `3GppSbiTargetApiRootSupported` with a JSON boolean, never
      `0`/`1` — `the_target_apiroot_capability_is_a_boolean_under_the_capital_g_name` (both `true`
      and `false`, asserting the exact key text and rejecting `:1`, `:0`, `:"true"`, `:"false"`,
      and the lowercase name) and `the_response_capability_is_also_a_boolean_under_the_capital_g_name`.
- [x] A `SecNegotiateReqData` whose flag is boolean `true` deserialises and reads as supported —
      `a_conformant_boolean_capability_deserialises_and_reads_as_supported`, the regression that
      previously failed with a serde type error; covers `false` and the response leg too.
- [x] An absent flag deserialises to `false` without error —
      `an_absent_capability_defaults_to_false_and_the_old_lowercase_name_is_ignored`, which also
      pins that the old lowercase-integer form is **not** silently honoured (otherwise a peer
      running the old code would appear conformant).
- [x] An `exchange-params` request omitting `sender` deserialises and is accepted —
      `exchange_params_without_a_sender_deserialises_and_resolves_the_peer` (all three resolution
      steps, and the two-candidate refusal) and
      `exchange_params_accepts_an_omitted_sender_and_uses_the_association_fqdn`, which proves
      *which* FQDN the fallback resolves to by disabling the no-TLS fallback and depositing the
      exporter secret under one FQDN only.
- [x] `GET nsepp-telescopic/v1/mapping` is routed and returns a well-formed mapping —
      `the_telescopic_mapping_route_answers_both_procedures` drives §5.4.2 then §5.4.3 through the
      real SBI handler, plus the 404, both 400s and the 405; `telescopic.rs` unit-tests the label
      properties and the round trip.
- [x] `pqc_security.rs`, `zero_trust.rs` and their `mod` declarations are gone and the crate
      builds — the compiler is the guard here (a `mod` naming a deleted file cannot compile), and
      `grep -rn 'pqc_security\|zero_trust' src/` now matches only `nextgcore-app`'s unrelated
      `require_zero_trust` config field in `intent.rs`.
- [x] Workspace lint and test pass.

## Verification

Workspace **6024 passed / 0 failed / 6 ignored** (baseline `6021` on `b4c70e4`). Net **+3**: the
deleted modules took **17** tests with them (9 in `pqc_security`, 8 in `zero_trust`) and 10 new
tests were added, counted in both the lib and bin targets. `cargo clippy --workspace --all-targets`
0 errors, 0 warnings in `nextgcore-seppd`; `cargo fmt --all -- --check` clean. The seppd suite was
looped **30 times**, all green — see the flake section.

Twelve reverts:

| revert | expected to break | result |
|---|---|---|
| emit the lowercase `3gppSbi...` name again | the 4 capability guards | **4 failed** |
| retype the member `Option<i32>` (accept side) | the capability guards | **does not compile** — the guards assert on a `bool`, so the type is pinned by the test |
| emit the capability as an **integer** while keeping the `bool` field | `the_target_apiroot_capability_is_a_boolean...` | **1 failed** (`must be a JSON boolean, not :1`) |
| `sender` back to a bare `String` | the sender guards | **does not compile** (17 errors) — the guards construct `sender: None` |
| refuse an empty/absent `sender` in the handler again | `exchange_params_accepts_an_omitted_sender...` | **1 failed** |
| the omitted `sender` falls back to the LOCAL fqdn | same | **1 failed** |
| remove the telescopic route | `the_telescopic_mapping_route...` | **1 failed** |
| the label is not flattened (dots preserved) | the route guard + `the_label_is_always_a_single_legal_dns_label` | **2 failed** |
| the label is case-**sensitive** | 2 telescopic tests | **2 failed** |
| §5.4.2 does not store the mapping | the route guard + the round-trip test | **2 failed** |
| honour `foreign-fqdn` when both parameters are present | the route guard | **1 failed** |
| an unknown label answers 200 with an empty mapping | same | **1 failed** |
| `seppDomain` omitted from the §5.4.2 answer | the route guard + the round-trip test | **2 failed** |
| POST on the mapping path is forwarded instead of 405 | the route guard | **1 failed** |

**A flake I introduced, then a second flake in fixing the first.** Both worth recording because the
sequence is the lesson.

1. Every pre-existing test set `allow_insecure_no_tls` to `true`, so concurrent writers *agreed*
   and there was nothing to race. My new test needed `false` — to prove which FQDN the exporter
   secret is looked up under — and that turned agreement into a coin flip: **1–3 failures per run**
   with `UNAVAILABLE_PRINS_CONTEXT`. Exactly the shape of #215's `SGWU_QER_ENFORCEMENT` race: a
   *second* writer is what makes process-global state a bug.
2. I first fixed it with a lock in `n32c_handler`'s test module and another in `n32_server`'s — and
   it still failed, now **5 runs in 25**, in a *pre-existing* test
   (`test_enforce_tls_mode_peer_established_tls_accepted`). Two locks are two disjoint agreements
   about the same variable, and my `n32_server` test was clearing the shared node list that test
   depends on. Fixed properly two ways: **one** crate-wide `GLOBAL_TEST_LOCK` in `context.rs`, and
   `single_pending_peer` extracted as a **pure function over the node list** so the resolution-3
   behaviour is testable without touching the process-wide peer list at all. 30/30 green after.

The second flake is the more useful one: partial serialization of shared state reads as a fix and
is not one. Making the logic pure was what actually removed the hazard.

## Ceilings

* **No wire interop test.** The capability, the optional `sender` and the telescopic service are
  verified in-process; there is no second SEPP, no packet capture, and the docker E2E is
  `workflow_dispatch`-only. "Conformant" here means "matches the vendored OpenAPI and the TS
  prose", not "was accepted by another vendor's SEPP".
* **Upgrade asymmetry.** Peering this build against an older build of itself now negotiates the
  capability as `false` in both directions instead of `true` — no handshake fails, but
  target-apiRoot forwarding is not negotiated until both sides are upgraded. Emit and accept had to
  flip together; that is the cost.
* **`n32HandshakeId` is still not modelled** in either `SecNegotiate*Data`, though the schema
  defines it (`^[A-Fa-f0-9]{16}$`). Out of scope here, but it is the next handshake IE gap.
* **Telescopic mappings are in-memory, capped at 8192, and lost on restart.** At the cap new ones
  are not stored and §5.4.2 still answers (the label is a pure function of the input); the loss is
  a sibling SEPP's §5.4.3 lookup returning 404. After a restart, a peer holding a pre-restart
  telescopic FQDN must re-request the mapping. Nothing in the service is authenticated or
  rate-limited beyond what the SBI server already does, and every stored entry is remote-driven.
* **`--sender` is now load-bearing for the telescopic service.** Without it §5.4.2 answers 500. The
  shipped docker compose does pass `--sender`, but a deployment that omitted it previously worked
  and now has one endpoint that does not.
* **`appGrpId`-style cross-checks absent:** the service does not verify that the foreign FQDN is
  reachable, that it belongs to a PLMN this SEPP peers with, or that the requester is entitled to
  ask. It flattens what it is given.
* **Deleting `pqc_security.rs` removes 9 tests and `zero_trust.rs` 8.** The workspace test count
  net gain is only +3 for 10 new tests. A test count going *down* for deleted unreachable code is
  the same trade #242 made; noted so the delta is not mistaken for lost coverage.
* GitNexus impact analysis unrunnable (no MCP server connected — 46th consecutive PR).
  `nextgcore/CLAUDE.md`'s mandate to run `gitnexus_impact` before editing stays unsatisfiable.
  Blast radius by grep: every `SecParamExch*Data { sender: ... }` construction site and every
  `.sender` read was enumerated and updated (17 sites, all inside `nextgcore-seppd`); no crate
  outside seppd names `SecurityCapabilityRequestJson`, `SecParamExchReqData`, `pqc_security` or
  `zero_trust`.
