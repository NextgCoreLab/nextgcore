# nextgcore #114 (easdfd + smfd): DNS handling rules, the DNS-message report, Neasdf_BaselineDNSPattern, and the SMF driver

Verified against `main` @ `85a5cd1` (after #65, #106, #112). Every cite in the issue still held; easdfd had
not been touched since PR #35.

## Scope: four of five criteria, with the fifth split out at the author's direction

#114 says: *"This is a broad, multi-deliverable item and is best treated as an epic (see scope note
under Suggested approach)"*, and *"recommend tracking it as an epic and splitting. The highest-value
first sub-item is the SMF EASDF-selection + DNSContext-create leg together with handling-rule
evaluation."*

That author-marked split is honoured the way this repo already does it (the #108 → #171 precedent):
the coherent remainder lands here and closes the parent, and the separable part becomes its own issue.

| criterion | here |
|---|---|
| 1. `dnsHandlingRules` parsed and evaluated | **done** |
| 2. DNS-message report / Notify to the SMF | **done** |
| 3. `Neasdf_BaselineDNSPattern` CRUD + advertised | **done** |
| 4. UDP:53 DNS listener | **split → #276** |
| 5. SMF selects an EASDF, creates + deletes the DNS context | **done** |
| 6. off by default; workspace tests + clippy pass | **done** |

Criterion 4 is split because it is the one sub-item with a **dependency this tree does not have**: a
DNS wire codec (RFC 1035 QNAME compression, A/AAAA, RCODE, EDNS(0) OPT, `TC`/512-byte truncation).
`grep -rn 'hickory\|trust-dns' src/Cargo.toml` → nothing. It also needs a field easdfd does not
store (the UE IP, since a UDP query carries no context id, so the session must be found by source
address) and an SMF-side change to supply it. And it is the only sub-item the issue itself wants behind
a **cargo feature** — it binds a privileged port and changes the process's network posture. #276
carries all of that, with the analysis, its own acceptance criteria, and the note that everything it
depends on now exists.

## Verified against current main

| claim in the issue | check on `85a5cd1` | still true? |
|---|---|---|
| rules kept only as `EasdfDnsContext.raw`, "stored, not yet enforced" | `context.rs:61-64` | yes |
| `resolve_fqdn` matches only the static `eas_map` | `context.rs:163-181` | yes |
| the router has no report/Notify path toward the SMF | `main.rs:362-380` | yes |
| the NFProfile advertises only `neasdf-dnscontext` | `main.rs:591-599` | yes |
| no UDP socket is opened | only `SbiServer` is started | yes |
| nothing outside easdfd references EASDF beyond two enum entries | `grep -rn 'neasdf' src/bins/` → easdfd only | yes |

## Decision 1: the schema caveat, stated up front

TS 29.556 is **not vendored** in this repo (nor is TS 23.548). Unlike every other wire type in this
tree, these member names cannot be checked against an OpenAPI file — the issue says as much
("faithful paraphrases rather than verbatim quotes"). Two consequences, both deliberate:

* `DnsHandlingRule::from_json` accepts **several spellings** per member (`domainNames` /
  `dnsQueryMdt` / `fqdnList` / `fqdn`; `easIpAddresses` / `easAddresses` / `easIpv4Addrs`;
  `reportInd` / `dnsMessageReportInd` / `report`). Accepting a superset is the safer error: rejecting
  a conformant spelling would drop the rule silently and leave the context inert, which is the defect
  being fixed.
* `EasdfDnsContext.raw` is **kept** even though rules are now parsed, so the unrecognised remainder is
  recoverable rather than lost, and a later vendoring can tighten the parse without a data migration.

A rule that names no domain, or that neither answers nor forwards nor reports, is dropped **with a
warn** rather than stored — a rule that looks active and is not is worse than no rule.

## Decision 2: resolution precedence, and why a query must be scoped

Order: **session context rules → static EAS map → baseline DNS patterns → configured miss behaviour.**
Session-specific beats EASDF-configured, and explicit configuration beats a baseline default, which is
what TS 23.548 §6.2.3.2.2 implies.

The SBI query gained an optional `dns-context-id`. **Unscoped queries are answered from the static map
and baseline patterns only.** Consulting some session's rules for an unscoped query would leak one
subscriber's edge steering into another subscriber's answer — the same unkeyed-fan-out shape #112 just
fixed in dccfd. `a_context_rule_answers_an_fqdn_absent_from_the_eas_map` asserts both halves: scoped
resolves, unscoped is still a miss.

`fqdn_pattern_matches` is now shared by the EAS map and the rules, so `*.edge.example.com` cannot mean
two different things in the two places.

## Decision 3: the report is awaited, not spawned

A DNS-message report goes out **before** the DNS answer returns to the querier. An SMF that must install
a UL-CL toward the resolved EAS should not learn the address after the UE already has it. The cost is
latency on the answer path; the alternative is a race the SMF loses.

A rule asking for a report on a context with no notification URI logs a warn naming the consequence —
it cannot be delivered, and an undeliverable report is exactly the silent failure this issue is about.

## Decision 4: the SMF leg is a runtime switch, and it is placed after the N4 leg

**Runtime switch, not a cargo feature** (`SMF_EASDF` / `SMF_EASDF_EDGE_FQDN`, default off). Same
reasoning as #112's coordination switch: CI builds default features, so a cargo feature would leave
this path **uncompiled** in CI where it would rot. A runtime switch is compiled always and exercised in
both states by one `cargo test` run. Env-var driven because smfd has no clap `Args` struct.

**Edge FQDN patterns come from the operator** (`SMF_EASDF_EDGE_FQDN`). There is no other source of
truth in this tree, and guessing which FQDNs are edge-served would install rules for traffic the
operator never designated as edge. Enabling the switch with no pattern is logged at warn, because "on
but never creating a context" is otherwise invisible.

**The create call sits after the PFCP leg succeeds**, immediately before the binding is stored. A
context created for a session that then fails is an orphan the release path will never delete, because
release never runs for a session that never existed.
`a_failed_establishment_creates_no_easdf_dns_context` pins that.

**Discovery picks the service by name.** easdfd now advertises two services, so
`nfServices[0]` would start dialling whichever the NRF returned first — the same defect scpd's #207
fixed on the proxy path. `the_dnscontext_service_is_chosen_by_name` puts the baseline-pattern service
first in the profile, at a dead port, so selecting wrongly fails loudly.

**Every failure is non-fatal to the session.** A session without edge DNS steering still works;
refusing it would turn an EASDF outage into a service outage for edge DNNs.

## Decision 5: the SMF serves the callback it advertises

The SMF hands the EASDF a `notificationUri`, so `POST /nsmf-pdusession/v1/easdf-dns-reports` had to
exist — advertising a callback that 404s is the emit-side-without-a-sink defect this repo has recorded
before. The handler attributes the report to the session owning the context and records the EAS
address on the binding.

**Recorded, not acted on:** inserting a UL-CL toward the reported EAS is traffic-influence work with
its own N4 and PSA implications, and doing it half way — installing a rule that does not match — would
be worse than recording the fact and saying so. `easdf_reported_eas` is where that work will read from.

## What was added / changed

| area | change |
|---|---|
| `easdfd/context.rs` | `DnsHandlingRule` + `from_json` + `matches`, `fqdn_pattern_matches`, `EasdfDnsContext::{handling_rules, notify_uri, with_parsed}`, `resolve_in_context`, `dns_context_notify_uri`, the `baseline_patterns` store + CRUD + `resolve_baseline` |
| `easdfd/main.rs` | rule parsing on create **and** update; `dns-context-id` scoping; `send_dns_message_report`; `split_uri`; four baseline-pattern handlers + routes; the NFProfile now advertises both services |
| `smfd/easdf.rs` (new) | `EasdfConfig`, `enable`, `should_create`, `create_dns_context`, `delete_dns_context`, `discover_easdf`, `dnscontext_endpoint` |
| `smfd/context.rs` | `PolicyBinding::{easdf_dns_context_id, easdf_reported_eas}` |
| `smfd/main.rs` | the startup switch; the create call at establishment; the delete at release; `handle_easdf_dns_report` + its route |

## Verification

Every guard revert-verified: undo the change, watch the **named** test fail, restore.

| guard | revert applied | result |
|---|---|---|
| `a_context_rule_answers_an_fqdn_absent_from_the_eas_map` (+2 others) | `resolve_in_context` iterates an empty rule list | FAILED ✓ |
| `an_update_reparses_the_handling_rules` | update stores the body without `with_parsed` | FAILED ✓ |
| `a_reporting_rule_emits_a_dns_message_report` | the report emission short-circuited | FAILED ✓ |
| `baseline_dns_pattern_crud_and_nf_profile_advertisement` | the second service removed from the NFProfile | FAILED ✓ |
| `releasing_a_session_deletes_its_easdf_dns_context` | the delete call removed from `handle_sm_context_release` | FAILED ✓ (see below) |

### Another wiring hole in my own work

Removing the delete call from `handle_sm_context_release` **compiled and the whole suite still
passed**: `easdf::tests` drives `delete_dns_context` directly and says nothing about whether any
handler calls it — "the helper is tested and the wiring is not", the **third** time in this session.
`releasing_a_session_deletes_its_easdf_dns_context` closes it, and the revert then failed.

### And a `OnceLock` that could not be re-set

That new test then failed on its first run for a different reason: `EASDF_CONFIG` was a `OnceLock`, so
the sibling wire test had already installed its config and `let _ = set(c)` silently did nothing. My
test therefore dialled the sibling's (stopped) loopback NRF and no delete ever went out. Changed to a
`RwLock<Option<_>>` — production sets it once either way — and the switch tests share one
`tokio::sync::Mutex` (a `std` guard held across an await is
`clippy::await_holding_lock`). 3 consecutive full-suite runs green.

## Workspace state

`6102 passed / 0 failed` (main: `6090`), `cargo clippy --workspace --all-targets` 0 errors,
`clippy -p nextgcore-easdfd -p nextgcore-smfd --all-targets` 0 warnings, `cargo fmt --all --check`
clean. Both switch states are exercised in the one run.

## Ceilings

* **No DNS on the wire.** The EASDF still speaks only SBI; nothing a UE or resolver uses can reach it.
  That is #276, and it is the difference between "the DNS plane is implemented" and "the DNS plane's
  decisions are implemented". Only the latter is true after this change.
* **The create CALL SITE is verified by inspection, not by a test.** Reaching it needs a
  PFCP-responding UPF: without one `handle_sm_context_create` returns `504 UPF_NOT_RESPONDING` before
  the EASDF leg, and the smfd harness has no UPF stand-in (no existing test establishes a session
  either). What IS covered: the create leg over real HTTP (`easdf::tests`), the no-orphan property at
  the call site, and the release call site.
* **The report is recorded, never acted on.** No UL-CL, no PSA re-selection, no traffic influence.
* **Handling-rule members are a paraphrase.** TS 29.556 is not vendored; a conformant SMF using a
  spelling not in the accepted set has its rule dropped with a warn.
* **No `Neasdf_DNSContext` json-patch update** — PUT is a full replace, as before this change.
* **Baseline patterns are in-memory, capped by `max_dns_contexts`, and lost on restart**, like the DNS
  contexts.
* **The EASDF is still off by default** in the deployment, and the SMF leg is off by default too, so a
  default deployment behaves exactly as before.
* **No wire interop.** Loopback `SbiServer`s stand in for the SMF, the NRF and the EASDF — real HTTP,
  this tree's own server on both ends.
* GitNexus impact analysis unrunnable (no MCP server connected — 50th consecutive PR). Blast radius by
  grep: `resolve_fqdn` has 2 callers (both updated), `EasdfDnsContext::new` 2 (both now chained with
  `with_parsed`), `PolicyBinding` is constructed at 3 sites (all updated), and no crate outside
  `nextgcore-easdfd` / `nextgcore-smfd` names anything touched here.
