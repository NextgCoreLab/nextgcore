# nextgcore #276 (easdfd): give the DNS plane a socket a resolver can speak to

Verified against `main` @ `6198a75`.

#276 is the fifth criterion of #114, split out by that issue's own author because it is the one
sub-item with a dependency this tree does not have (a DNS wire codec), a field easdfd does not
store (the UE IP), and a gating requirement of its own.

## Verified against current main

| claim in the issue | site on `6198a75` | still true? |
|---|---|---|
| no UDP socket anywhere in the crate | `rg UdpSocket bins/nextgcore-easdfd/` → nothing | yes |
| `resolve_in_context` is the engine a listener would call | `context.rs:366` | yes |
| no DNS crate in the workspace | `rg 'hickory\|trust-dns\|domain =' Cargo.toml` → nothing | yes |
| `EasdfDnsContext` stores `supi` + `pduSessionId` only, so the UE IP must be added | `context.rs:165` | yes |
| the SMF creates DNS contexts (per #114) | **NO — see below** | **false** |

## The thing this issue could not have been delivered honestly without

#276's criterion 4 needs a UE's DNS context to be reachable from a UDP query, which needs the SMF
to send the UE's address on create. Checking that led somewhere else first:

**`easdf::create_dns_context` had no production caller.** At `main.rs:2961` the establishment path
read

```rust
// ---- #114: EASDF selection + DNS context (TS 23.501 §5.6.7) ----
// Off by default. Awaited BEFORE the binding is stored so the context id is
// recorded with it -- ...
let easdf_dns_context_id: Option<String> = None;
```

The comment describes an `await` that is not in the code. Introduced by `e9c823f` (PR #277,
closing #114), whose own commit message says it "gives the DNS plane a driver". The driver exists,
is 130 lines, and is tested over real HTTP by
`easdf::tests::the_dns_context_is_created_and_deleted_over_the_wire` — and nothing in production
ever called it. Because the id was permanently `None`, the release path's `delete_dns_context`
(wired correctly, at `main.rs:4419`) could never fire either, so **both** legs were dead.

This is "the helper is tested and the wiring is not — and the better the helper's test, the more
convincing the illusion", with the additional twist that #114's spec *names* the ceiling and
misjudges which side of it the call site fell on: it says "the create call site is verified **by
inspection** plus this no-orphan assertion". The inspection did not notice the call was absent.

Fixing it is a prerequisite here, not scope creep: with no context ever created, criterion 4's
"a query from a UE whose session has a DNS context" describes a state the running system could
never enter.

## Decision 1: the codec is hand-rolled, and it is NOT behind the feature

`dns_wire.rs` implements RFC 1035 message parse/build plus RFC 6891 EDNS(0) — header flags, QNAME
with compression *reading*, QTYPE/QCLASS, `A`/`AAAA` RRs, RCODEs, `TC` truncation against the
EDNS-negotiated or 512-byte ceiling. Hand-rolled rather than vendoring a DNS crate: this tree
already hand-rolls NAS, NGAP, PFCP and Diameter, adding a third-party dependency is a decision of
its own (as the issue notes), and the subset an EASDF needs is small because it answers address
queries and forwards everything else verbatim.

The codec is deliberately **outside** the `dns-udp` feature. It changes no network posture — the
reason #276 gives for gating — and keeping it out means all the parsing logic is compiled and
tested on every default CI run. That directly answers the project's recorded reason for preferring
runtime switches to cargo features (a gated path rots uncompiled).

Compression is read but only ever written as the one pointer to the question name at offset 12,
which is the only compression a single-question answer has available.

## Decision 2: the feature stands, and CI grew a step so it cannot rot

The recorded house rule is a runtime switch, not a cargo feature. #276 asks for a feature and gives
a reason specific to this sub-item: it binds a **privileged port**. That justification is accepted —
but the rot risk is real, so `ci.yml` gained `cargo test -p nextgcore-easdfd --features dns-udp` in
the test job and the matching `cargo clippy` in the lint job. The gated half is now built, linted
and tested on every PR; what the feature controls is whether a *deployment* opens the socket.

## Decision 3: a UDP query is attributed by source address, and by nothing else

`EasdfDnsContext` gains `ue_addresses: Vec<IpAddr>`, and `EasdfContext` gains a `ue_ip_index`
(UE address → context id) maintained by every mutation of the context map. `resolve_for_source`
is the UDP plane's entry point and returns the outcome, the report flag and the context id in one
lookup.

Three sub-decisions worth stating:

* **A collision goes to the newer context.** An SMF assigns a UE address to one live session at a
  time, so two contexts claiming one address means the older one's DELETE was lost; steering the
  live session with a dead session's rules is the worse error. The stale context itself is kept —
  only its claim on the address is released — because removing a resource the SMF did not delete
  would make its eventual DELETE answer 404. Both halves are pinned, including the subtle one:
  deleting the stale context must **not** un-map the live session.
* **An unknown source falls through to the static map**, never to another session's rules. Same
  leak `resolve_in_context` already refuses for an unscoped SBI query.
* **`ueIpv6Prefix` is refused, loudly.** Matching a source address against a prefix is a different
  operation from an exact lookup, and treating the network address as the UE's would answer for one
  address out of 2^64. It logs a warning and those sessions fall through to the static map.

## Decision 4: NODATA, not NXDOMAIN, for a name we serve but a type we do not

An `AAAA` query for an edge FQDN with only an `A` configured — or an `MX` query for one — answers
`NOERROR` with zero records. `NXDOMAIN` would assert the name does not exist, and a dual-stack
resolver told that would stop asking for the other family too. An unreachable upstream answers
`SERVFAIL` for the same class of reason: "I could not find out" is a different and much less sticky
statement than "it does not exist".

## Decision 5: a forward is relayed verbatim in both directions

The query bytes go to the upstream unchanged and its reply comes back unchanged, so the transaction
ID, the question, the EDNS OPT and any option this codec does not model all survive. A
parse-and-rebuild would silently drop the last of those. Replies from an address other than the one
dialled are dropped. This is a forwarder, not a resolver: no cache, no validation.

## Acceptance criteria

- [x] A `dns_wire` module parses a real query and builds a response; tests cover a **compressed
      name** (`a_compressed_name_is_followed_and_resumes_after_the_pointer`, plus
      `multiple_answer_records_decode_after_their_compressed_names` for the production path), an
      **unknown QTYPE** (`an_unknown_qtype_parses_and_is_answered_by_no_record`),
      **malformed/truncated** input in five shapes
      (`malformed_and_truncated_messages_are_rejected_distinguishably`) and an **EDNS(0) OPT**
      (`an_edns0_query_gets_an_opt_in_its_response_and_a_larger_ceiling`,
      `an_absurd_edns_payload_size_is_clamped_both_ways`).
- [x] A UDP listener resolves via the existing context/EAS-map/baseline path; a test sends a **real
      UDP query** and asserts an A-record answer — `a_real_udp_query_is_answered_with_an_a_record`,
      over a real socket in both directions.
- [x] A miss forwards when an upstream is configured and answers `NXDOMAIN` otherwise —
      `a_miss_forwards_to_the_upstream_and_nxdomains_without_one`, asserting the UE receives the
      *upstream's* address, not one the EASDF invented. Plus `an_unreachable_upstream_servfails`.
- [x] A query from a UE with a DNS context is scoped to that context's rules; **two UEs with
      different rules get different answers for the same FQDN** —
      `two_ues_get_different_answers_for_the_same_fqdn` (and a third source that matches neither),
      `resolve_for_source_scopes_to_the_sources_own_context`. Needed the UE IP on the context, the
      SMF-side send, and the dead create wiring above.
- [x] The listener is behind a `dns-udp` cargo feature, off by default; the workspace builds, tests
      and clippy pass **both** with and without it — and CI now runs both, so the claim stays true.
- [x] The `main.rs` module header no longer lists the UDP listener as deferred; it documents what
      the plane does and points at `dns_udp` for why the split is where it is.

Beyond the criteria: `docs-book/src/configuration/easdf.md` (new, in `SUMMARY.md`) documents the
`CAP_NET_BIND_SERVICE` requirement and the port override, the resolution precedence per transport,
and the answer table — the "say so in the docs" the suggested approach asks for. There was no EASDF
page at all before.

## Verification

Workspace **6224 passed / 0 failed** (baseline 6209 on `6198a75`; +15 in the default build), and
`cargo test -p nextgcore-easdfd --features dns-udp` **51 passed / 0 failed** (+9 more that exist
only with the feature). `cargo clippy --workspace --all-targets`, `cargo clippy -p nextgcore-easdfd
--features dns-udp --all-targets` and `cargo fmt --all -- --check` all clean, zero new warnings.

| revert | expected to break | result |
|---|---|---|
| `resolve_for_source` ignores the source address | the two scoping tests | **2 failed** |
| `ue_ip_index_remove` drops the mapping unconditionally | `a_colliding_ue_address_..._survives_the_stale_delete` | **1 failed** |
| the listener binds but never serves | `a_real_udp_query_is_answered_with_an_a_record` | **1 failed** |
| the `ueIpv4Address` member removed from the create body | `the_dns_context_is_created_and_deleted_over_the_wire` | **1 failed** |
| an `OPT` emitted even when the query carried none | 3 tests | **3 failed** |
| `TC` never set | `an_oversized_answer_set_is_truncated_with_the_tc_bit_set` | **1 failed** |
| **the smfd create call removed (i.e. #114's state restored)** | — | **425 passed, 0 failed** |

That last row is the honest one and is discussed under Ceilings.

### A lock split that produced a hang, not a flake

The UDP tests initially declared their own `tokio::Mutex` while `main.rs`'s tests already had a
`std::Mutex` over the same process-global context — two disjoint agreements about one variable. The
symptom was not a failed assertion: a UDP test called `easdf_context_final()` while a sibling
handler test was mid-flight, that sibling's *miss* became a *hit*, so no forward was sent, so the
fake upstream it was blocked on never received anything, and the run hung until the harness killed
it. The single lock now lives in `context.rs` beside the global it protects, with both modules
taking it, and the forward test's `upstream_task.await` is bounded by a timeout so a future
regression fails instead of hanging. Eight consecutive feature-suite runs green afterwards, because
one green run proves nothing about a process-global race.

## Ceilings

* **The smfd create CALL SITE is still not covered by a test, and the revert proves it.** Removing
  the call leaves all 425 smfd tests green. Reaching it needs `handle_sm_context_create` to get
  past its N4 leg, which needs an associated PFCP peer answering a Session Establishment Request,
  and the smfd harness has no UPF stand-in — two existing tests
  (`a_failed_establishment_creates_no_easdf_dns_context`, `a_failed_create_leaves_no_registered_sm_context`)
  say so in as many words and both add "if this ever becomes a 2xx the harness gained a UPF".
  Building one is a cross-module test-infrastructure change: `PFCP_CLIENT` is a `OnceLock`, so an
  installed client is permanent for the process, and `release_association` clears the process-global
  `pfcp_sessions` map that `pfcp_path`'s own `SESSION_MAP_LOCK` guards — a second disjoint lock
  about the same variable, which is precisely the mistake this PR already made once and fixed.
  Filed as its own issue rather than done here. What IS verified: the create body's contents over
  real HTTP, and that a failed establishment creates no context.
* **`ueIpv6Prefix` is unsupported**, so a v6-prefix-only session's UDP queries fall through to the
  static map. Warned at runtime and documented.
* **No TCP fallback.** A truncated answer is `TC`-flagged and a resolver that wants the rest must
  retry against an upstream over TCP, not against the EASDF. RFC 1035 permits UDP-only; stated
  because "supports DNS" would otherwise imply both.
* **No DNSSEC.** The `DO` bit is read and echoed and nothing is signed. An EASDF answering for an
  operator-configured edge FQDN is not the zone's signer.
* **The deployment surface is untested.** The EASDF is not a service in
  `docker/rust/docker-compose.yml` and ships no `easdf.yaml`, so nothing here is exercised by the
  docker E2E gate. Unchanged by this PR and stated in the new docs page.
* **TS 29.556 is still not vendored**, so `ueIpv4Address` and friends rest on the same
  multiple-accepted-spellings stance #114 established, not on a schema. The DNS wire format, by
  contrast, is checked against RFC 1035/6891.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `EasdfDnsContext` has 3 construction sites (2 handlers + tests), `resolve_for_source` has one
  production caller (`handle_datagram`), `create_dns_context` now has one.
