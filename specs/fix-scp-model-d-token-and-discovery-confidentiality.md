# nextgcore #101 (SCP Model D): encode the discovery query, and mint tokens for the consumer

Verified against `main` @ `8c15bb6`. The issue's cites are from `76ea248`; all four were
re-verified and all four still hold, at new line numbers.

`Refs #101`, **not Closes** — see "Scope actually shipped" below. This ships criterion 1,
the discovery-encoding hard breaker. Criteria 2–4 and defects 3–7 remain open on #101, with
the design for 2–4 recorded here so it need not be re-derived.

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
