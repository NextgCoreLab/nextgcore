# nextgcore #101 (SCP Model D): encode the discovery query, and mint tokens for the consumer

Verified against `main` @ `8c15bb6`. The issue's cites are from `76ea248`; all four were
re-verified and all four still hold, at new line numbers.

**Two passes.** Pass 1 (`Refs #101`) shipped criterion 1, the discovery-encoding hard breaker;
it is documented below. Pass 2 (`Closes #101`) ships criteria 2, 3 and 4 — the delegated token
identity, scope and per-consumer cache — and files defects 3–7 as #207–#211. See "Pass 2" at
the end.

## Verified against current main

| # | defect | site |
|---|---|---|
| 1 | query params joined with no encoding, then `Uri::parse` | `libs/nextgcore-sbi/src/client.rs:806,811` |
| 2 | token request built from the SCP's own ids | `oauth.rs:1003`, `proxy.rs:653` (`NfType::Scp`) |
| 2 | consumer's `Authorization` stripped on the delegated path | `proxy.rs:1170` |
| 3 | no `3gpp-Sbi-Access-Scope` anywhere | grep finds none |
| 4 | `CacheKey = (String, String)` — no consumer identity | `oauth.rs:477` |

## Decision 1: two encodings, not one — do NOT deduplicate them

The repo already has **two** percent-encoders, and the reflex ("count the implementations
before writing the abstraction") would be to merge them. That would introduce a bug. They
differ, and both are right:

| | space | correct for |
|---|---|---|
| `oauth.rs::url_encode` (private) | `+` | `application/x-www-form-urlencoded` **body** — the token request |
| `pcfd::sbi_path::percent_encode` | `%20` | RFC 3986 **query component** |

In a strict RFC 3986 query, `+` is a *literal plus*, not a space. So encoding a discovery
factor with the form-style encoder would corrupt any value containing a space when a
conformant NRF parses it.

So: one shared module, **two clearly named functions**, and a test pinning that they differ
on space so nobody unifies them later:

* `encode_query_value` — RFC 3986 unreserved set, space → `%20`. Used by the SBI client's
  query builder and by pcfd (whose local copy is deleted).
* `encode_form_value` — same set but space → `+`. Used by the token request body.

The client's query builder is the right home for the fix rather than the `with_param` call
site in `proxy.rs`, exactly as the issue suggests: **every** SBI query benefits, and a
future caller cannot forget.

## Decision 2: use the consumer's identity only when it can be attested

Criterion 2 wants the token request to carry the consumer's identity. Doing that
unconditionally would **break the delegated path outright** against our own NRF, and the
issue's feature-gate advice does not go far enough to explain why:

After #64, the NRF's token endpoint requires client authentication — a **CCA keyed by
`nfInstanceId`**. If the SCP sends the *consumer's* `nfInstanceId` while signing the CCA with
the *SCP's* key, the NRF rejects the request. So "send the consumer's identity" and "sign with
our own key" are mutually exclusive; a blind flag would just turn the delegated path off.

TS 33.501 §13.4.1.3.2 resolves it: in Model D the **consumer's** CCA is conveyed. So the rule
is *never assert an identity you cannot attest*:

1. Consumer supplied its own CCA → use the consumer's `nfInstanceId`/`nfType` and forward
   that CCA. Conformant, and the NRF can verify it.
2. No consumer CCA, but the deployment has explicitly set
   `scp.delegated.trust_requester_identity` → use the consumer's identity anyway, for an NRF
   that does not require client authentication. Logged at startup.
3. Otherwise → keep the SCP's identity and log, once per consumer, that the token is
   SCP-attested rather than consumer-attested.

This is self-configuring rather than flag-driven: correct by default, conformant when the
inputs allow it, and it cannot regress a CCA-less deployment. The consumer identity comes
from `3gpp-Sbi-Discovery-requester-nf-instance-id` (optional) and
`-requester-nf-type` (already mandatory — `proxy.rs:961`, missing is a 400).

## Decision 3: a new method, not a changed signature

`OAuth2Client::get_token` is used by ~15 NFs. Rather than widen it, add
`get_token_on_behalf_of(consumer, target_nf_type, scope)`; `get_token` delegates to it with
the client's own identity as the consumer. Blast radius stays inside scpd, and the
non-delegated path is unchanged by construction.

`CacheKey` becomes `(consumer_id, target_nf_type, scope)`. For a normal NF the consumer is
always itself, so the key gains a constant component and caching behaves exactly as before —
a behaviour-preserving generalisation rather than a change.

## Split to follow-ups (defects 3–7) — planned, not yet filed

To be filed as separate issues, each named in the PR that closes #101 so the close is
auditable: producer
`NFService` selection by service name + API major version with `INVALID_API`; relay metadata
(`nf_set_id`/`nf_group_id`, `Producer-Id` overwrite, `Target-apiRoot`, `Location`
absolutisation); candidate reselection with connection-refused → 504; `3gpp-Sbi-Callback`
pass-through; and NRF error-status splitting (504 `NRF_NOT_REACHABLE` vs discovery 4xx).

Note the count arithmetic honestly: closing one issue while filing five follow-ups moves the
open count the **wrong way** (61 → 65), which is the understatement the repo's
issues-closed-vs-parts-closed learning warns about.

## Scope actually shipped: criterion 1 only, as `Refs #101`

**This PR ships the discovery-encoding breaker and nothing else.** #101 stays open.

The repo convention permits this: *"a safety-critical defect inside an umbrella may ship
alone, labelled `Refs #N`, with the PR stating why it did not wait and that the count
deliberately does not move."* This qualifies — criterion 1 is the hard breaker (a 502 before
the request leaves the process, so Model D discovery by slice/GUAMI/TAI/PLMN cannot work at
all), and it turned out to be cross-cutting infrastructure every SBI query benefits from.

Criteria 2-4 were deliberately NOT started, for a reason found while implementing:
`SbiClient::with_oauth2(oauth2, target_nf_type)` attaches the token automatically and has
**no per-request hook**, so a consumer-scoped token requires the delegated path in `proxy.rs`
to acquire and attach the token itself, bypassing that integration. That is a restructure of
`forward()`, not an incremental edit. The design is settled and recorded above (Decisions 2
and 3) so the next session does not re-derive it.

## What criterion 1 turned out to be

Not a one-line encode. Three things had to move together:

**1. Encode centrally in the client** (`client.rs`), so no call site can forget.

**2. Two encodings, kept distinct** - the finding in Decision 1. New shared
`nextgcore_sbi::uri_encode` with `encode_query_value` (space -> `%20`) and
`encode_form_value` (space -> `+`), and a test pinning that they differ so a later tidy-up
cannot merge them. pcfd's local copy now delegates to the shared one; it must still encode
because it builds URI **strings** by hand rather than going through `with_param`.

**3. The contract is asymmetric, and that trap is now documented on `with_param`.** A value
passed to `with_param`/`set_param` is RAW and the client encodes it; a hand-built URI string
bypasses the client and the caller must encode. Getting this wrong double-encodes
(`{` -> `%7B` -> `%257B`), and the peer's single decode yields `%7B`.

### Four tests were compensating for the defect

Encoding centrally broke four tests, and every one broke because it had been **hand-encoding
to work around a client that did not encode**:

* `nextgcore-nrfd` `test_http_lifecycle_register_discover_patch_deregister` passed a
  pre-encoded S-NSSAI with the comment *"percent-encoded"* - so it exercised a path no real
  consumer takes. It now passes the raw JSON and asserts the true round trip
  (client encodes -> nrfd's `percent_decode` reverses).
* three `nextgcore-bsfd` MBS tests did the same via a local `pct_encode_query` test helper,
  now deleted as unused.

Server-side decoding was already correct in both NFs - the gap was only ever on the client.
Worth recording: the defect was invisible in-repo precisely because the tests had been
written around it, which is why #101 needed a conformant *external* NRF to surface it.

## Verification (actual)

Workspace **5710 passed / 0 failed**, `cargo test --workspace` exit 0, no compile errors
(checked for `^error`, not only a `test result:` line). Four new tests in `uri_encode`.

* `a_json_discovery_factor_is_fully_encoded` - the #101 breaker: asserts none of
  `[ ] { } "` or space survives, against the exact expected encoding.
* `query_and_form_encoders_differ_on_space` - the anti-deduplication guard, plus a loop
  asserting the two agree on everything *except* space.
* `unreserved_passes_through_and_plus_is_escaped` - a literal `+` must not decode back to a
  space.
* `multibyte_utf8_is_encoded_per_octet` - RFC 3986 5.2.5, uppercase hex per 2.1.

**Not verified:** no conformant external NRF was involved - the encoding is asserted against
the RFC and against nextgcore's own decoders, not against a third-party NRF's parser, which
is the peer whose rejection motivated the issue. CI skips Docker E2E.

## Definition of done

- [x] Structured discovery factors survive `Uri::parse`, encoded centrally in the client
- [x] One shared encoder module; pcfd's duplicate delegates; the two encodings kept distinct
- [x] The raw-vs-pre-encoded contract documented where callers will read it
- [ ] Delegated token request carries the consumer's identity when attestable - **#101**
- [ ] `3gpp-Sbi-Access-Scope` populated; consumer CCA forwarded - **#101**
- [ ] `TokenCache` keyed by consumer - **#101**
- [ ] Defects 3-7 filed as separate issues - **#101**

## Follow-ups

* **#101 remains open** for criteria 2-4, with the design in Decisions 2 and 3 above. The
  open count deliberately does not move.
* Defects 3-7 still to be filed as separate issues per the issue's own instruction.

---

# Pass 2 (`Closes #101`): criteria 2, 3 and 4

Verified against `main` @ `562b4a1`. Decisions 2 and 3 above were implemented as written; two of
their stated premises turned out to be wrong, and both corrections are recorded here rather than
left for the next reader to trip over.

## Correction 1: the blast radius was 2 direct callers, not ~15

Decision 3 justified adding a method by "`OAuth2Client::get_token` is used by ~15 NFs". The real
count is **2** direct callers outside `oauth.rs` (`scpd/proxy.rs` and `sbi/client.rs`); 13 crates
reach it *indirectly* through `SbiClient::with_oauth2`. The decision still stands — a new method
keeps the non-delegated path unchanged **by construction** rather than by review, which is worth
more than the call-count argument it was justified with — but the number was wrong.

## Correction 2: `forward()` was already acquiring the token, so this was not a restructure

Pass 1 recorded the blocker as: `with_oauth2` "attaches the token automatically and has no
per-request hook, so a consumer-scoped token requires the delegated path to acquire and attach
the token itself, bypassing that integration. That is a restructure of `forward()`."

`forward()` **already** acquired the token itself, to prime the cache so L1's attach step would
not make a second NRF round-trip. And L1 attaches only when the request carries no
`Authorization` (`client.rs:596`). So the seam already existed: `forward()` sets the
`Authorization` header from the consumer-scoped token, and L1's attach becomes a no-op **by
construction** rather than by ordering luck. No restructure — roughly thirty lines.

This is worth noting as a pattern: the blocker recorded at the end of a long session was a
plausible reading of the code that one more look disconfirmed. It cost a session's hesitation.

## What shipped

**Criterion 2 — identity, per Decision 2's three-way rule.** `TokenConsumer { nf_instance_id,
nf_type, cca }` names who a token is for. `request_token_on_behalf_of` chooses the CCA by **who
the body names**, which is the load-bearing detail: the consumer's own CCA when it supplied one;
our key when the body names us; and **no assertion** when the body names a third party who gave
us nothing — because `build_cca` mints `sub` = `self.nf_instance_id`, so signing there would emit
a CCA whose subject contradicts the body. That is worse than sending none: it is a verifiable
proof of the wrong claim.

`ScpProxy::delegated_auth` resolves the three cases and logs case 3, so an operator can tell an
SCP-attested token from a consumer-attested one. `trust_requester_identity` (default off) is the
operator declaration for an NRF that does not require client authentication.

One asymmetry found while implementing: `requester-nf-type` is mandatory for delegated discovery
but `requester-nf-instance-id` is **optional**, so a consumer can be typed without being named. An
unnamed consumer cannot be asserted at all and falls to case 3 regardless of any CCA.

**Criterion 3 — scope and CCA.** `3gpp-Sbi-Access-Scope` now sets the token scope, winning over
the URI-derived service name. Both constants already existed in `constants.rs` with **zero**
readers — `CLIENT_CREDENTIALS` and `ACCESS_SCOPE` — the same dead-constant shape as
`3gpp-Sbi-Callback` (now #210). The consumer's CCA is stripped from the forwarded request: it
authenticates to the NRF's token endpoint and is not a producer-facing credential.

**Criterion 4 — cache.** `CacheKey` becomes `(consumer, target_nf_type, scope)`. For an ordinary
NF the consumer is always itself, so the key gains a constant component and caching is
behaviour-identical. `invalidate` replaces the retry path's `clear_cache`, because one consumer's
401 should not re-mint the whole fleet's tokens.

## Verification

Seven new tests. Workspace **5735 passed / 0 failed** (was 5728), `cargo test --workspace` exit 0,
checked for `^error` rather than only a `test result:` line. `cargo fmt --all --check` clean;
`cargo clippy --workspace` (the CI gate) exit 0.

**Revert-verified**, one at a time. Revert A reproduces the original defect body verbatim:

| revert | test that fails | observed wrong value |
|---|---|---|
| token names the SCP again | `delegated_token_asserts_the_consumer_identity_when_the_consumer_attests_it` | `nfInstanceId=scp-instance-1&nfType=SCP` |
| treat a missing CCA as trusted | `delegated_token_stays_scp_attested_without_a_consumer_cca` | consumer asserted unattested |
| mint our own CCA for a third party | (same as A) | consumer's CCA absent |
| ignore `Access-Scope` | `access_scope_header_sets_the_delegated_token_scope` | `scope=nudm-uecm` |
| consumer-agnostic cache key | `two_consumers_of_one_target_scope_each_get_their_own_token` (+ the `oauth` unit test) | 1 token request for 2 consumers |
| relay the CCA onward | (same as A) | `cca_leaked: true` |
| let L1 attach instead | (same as A) | a second, SCP-identity token request |

The scope test is built so that only reading the header can pass it: the URI says `nudm-uecm`
and the header says `nudm-sdm`. The protected-identity tests likewise assert on the **absence**
of `scp-instance-1` *and* the presence of the consumer, so a change that emits both cannot pass.

**Not verified:**

* No conformant external NRF was involved. The token request body is asserted against a mock NRF
  that records it — the same ceiling pass 1 recorded, and the reason #101 needed an external NRF
  to surface at all. In particular **case 1 has never been exercised against an NRF that actually
  verifies a consumer CCA**: the mock accepts any body, so what is proven is that the SCP *sends*
  the consumer's identity and assertion, not that a real NRF accepts them.
* `build_cca` returns `None` unless a signing key is configured, and the tests configure none, so
  the "our key, our identity" arm is covered only by the third-party-identity path.
* Docker E2E remains skipped by CI.
* GitNexus impact analysis, mandated by this repo's CLAUDE.md, was **not run** — no GitNexus MCP
  server was connected. Caller analysis was grep-based: 2 direct `get_token` callers, 13
  `with_oauth2` crates, `TokenCache` only re-exported and never used outside `oauth.rs`.

## Defects 3-7, now filed

* **#207** — producer `NFService` selected without matching service name or API version; no `INVALID_API`.
* **#208** — relay drops `nfSetId`/`nfGroupId` on a cache hit, overwrites `Producer-Id`, no `Target-apiRoot`/`Location` absolutisation.
* **#209** — no alternate-producer reselection; connection-refused returns 502 not 504.
* **#210** — `3gpp-Sbi-Callback` never inspected.
* **#211** — NRF-unreachable / NRF-error / empty-`SearchResult` all collapse to 502, and an unreachable NRF reports `TARGET_NF_NOT_REACHABLE`.

Count arithmetic, honestly: closing #101 while filing five follow-ups moves the open count the
**wrong way**. Pass 1 predicted 61 → 65; the actual backlog is larger now, so quote both numbers
when reporting rather than the issues-closed figure alone.

## Definition of done (pass 2)

- [x] Delegated token request carries the consumer's identity when attestable
- [x] `3gpp-Sbi-Access-Scope` populated; consumer CCA forwarded to the NRF and stripped from the producer request
- [x] `TokenCache` keyed by consumer; invalidation scoped to one consumer
- [x] Defects 3-7 filed as #207-#211
