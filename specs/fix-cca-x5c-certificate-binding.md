# Carry `x5c` in the CCA and bind the signing certificate to the NF Instance ID

**Issue:** nextgcore #393 (ceiling of PR #391 / issue #187)
**Verified against:** nextgcore `main` @ `8676976`
**Spec basis:** TS 33.501 §13.3.8.2, §13.3.8.3; TS 33.310 §6.1.3c.3; RFC 7515 §4.1.6, RFC 7517, RFC 9509.
Spec text read at `6g_docs/specs/33501-k20.txt` (§13.3.8.1 at `:14325`, §13.3.8.2 at `:14355`,
§13.3.8.3 at `:14382`) and `6g_docs/specs/33310-j50.txt` (`:734`, `:735`, `:736`, `:716`, `:731`).

## Claim-vs-site-vs-still-true

Every claim in #393 re-located at `8676976`. The issue was filed hours ago against
`6ba388d`; `8676976` adds one intervening commit (#392/#394, NFProfile registration),
so the line numbers were re-checked rather than assumed.

| claim | where checked | still true? |
|---|---|---|
| `mint_cca` emits no `x5u` and no `x5c` | `oauth.rs:415` — header is the literal `br#"{"alg":"ES256","typ":"JWT"}"#` | **real** |
| `grep -n 'x5u\|x5c' oauth.rs` returns nothing | re-run at `8676976` → empty | **real** |
| the only `x5c` mention is a deviation note in `nrfd` | `nrfd/src/main.rs:2840` (comment on `verify_cca_binding`) | **real** |
| §13.3.8.2 makes one of `x5u`/`x5c` mandatory | `33501-k20.txt:14370-14380` | **real**, quoted below |
| §13.3.8.3's last bullet is the cert-to-instance-ID check | `33501-k20.txt:14401-14402` | **real**, quoted below |
| the NRF binds via `cca_trusted_keys` / `cca_trusted_keys_dir` instead | `nrfd/src/main.rs:106`, `:124`, `:3203-3217` | **real** |
| verification is fail-closed for an unknown issuer | `nrfd/src/main.rs:3207-3215` | **real** |
| `nextgcore_sbi::peer_cert` parses the URI SAN and can be reused | `peer_cert.rs:50` `nf_instance_id_from_der` — takes DER, strips `urn:uuid:` case-insensitively | **real**, and it is exactly the right shape |
| the NFs already load TLS certs, so cert material "is usually present" | `security.rs:74-81` (`NEXTGCORE_SBI_TLS_CERT` etc.) | **real but MISLEADING** — see below |
| #186 (the URI-SAN parser) is closed | `gh issue view 186` → CLOSED | **real** |
| #187 (CCA provisioning) is closed | `gh issue view 187` → CLOSED | **real** |
| #55 (nextgcore-talks-to-nextgcore) is cited as an open limitation | `gh issue view 55` → **CLOSED** (it is a diameter RFC-6733 issue, not the interop-ceiling issue) | **void as an open cite**; the *limitation* it describes is real and restated here on its own terms |
| CI skips Docker Build / E2E / EPC on a PR | `.github/workflows/ci.yml:111`, and `docker-e2e` `needs: docker-build` | **real** |
| #391's CI probe is positive + negative | `libs/nextgcore-sbi/examples/cca_token_probe.rs`, `ci.yml:338-353` | **real** |

### The one claim that changes the design

The issue says "the NFs already load TLS certs — `NEXTGCORE_SBI_TLS_CERT` and
friends — so the material is usually present". Two things are wrong with using
that as the CCA signing certificate, and both are load-bearing:

1. **Wrong key.** `NEXTGCORE_SBI_TLS_CERT` certifies the NF's *TLS* key pair.
   The CCA is signed with a *separate* ES256 key
   (`NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE`, a raw hex P-256 scalar,
   `oauth.rs:150-215`). A certificate over the TLS public key does not certify
   the CCA signing key, so putting it in `x5c` would assert a binding that does
   not exist — the verifier would validate a chain and then verify the JWS
   against a *different* key. That is worse than omitting `x5c`.
2. **Wrong profile.** TS 33.310 gives CCA signing certificates their own profile
   (`33310-j50.txt:716`, Table 6.1.3c.3-2): `keyUsage` = `digitalSignature`,
   `extendedKeyUsage` = `id-kp-jwt` (RFC 9509). The dev TLS certs are generated
   `extendedKeyUsage = serverAuth` (`docker/rust/certs/generate-dev-certs.sh`,
   the `v3_req` block) and carry **no URI SAN at all** — only DNS and IP SANs.
   So they cannot satisfy §13.3.8.3's last bullet even in principle: there is no
   NF Instance ID in them to compare against.

So `x5c` needs a certificate over the **CCA signing key**, carrying the NF
Instance ID in a URI SAN. That is a new artefact, not a reuse of an existing one,
and the design below says where it comes from.

## The spec reading

§13.3.8.2, `33501-k20.txt:14370-14380`, verbatim:

> The NF Service Consumer shall digitally sign the generated CCA based on
> its private key as described in RFC 7515 [45]. The signed CCA shall
> include one of the following fields:
>
> - the X.509 URL (x5u) to refer to a resource for the X.509 public key
>   certificate or certificate chain used for signing the client
>   authentication assertion, or
>
> - the X.509 Certificate Chain (x5c) include the X.509 public key
>   certificate or certificate chain used for signing the client
>   authentication assertion.

The "shall … one of the following" is an unconditional obligation with a free
choice of mechanism. There is no "if configured", no "may", and no condition
attached to either arm. **The sender picks which; the sender may not pick
neither.** This matters for the criterion table: criterion 1 asks for `x5c`
"when a chain is configured", which is weaker than the clause.

§13.3.8.3, `33501-k20.txt:14384-14402`, the full validation list in order:

> The verification of the CCA shall be performed by the receiving node,
> i.e., NRF or NF Service Producer in the following way:
>
> - It validates the signature of the JWS as described in RFC 7515 [45].
> - It validates the timestamp (iat) and/or the expiration time (exp) as
>   specified in RFC 7519 [44].
>
> If the receiving node is the NRF, the NRF validates the timestamp (iat)
> and the expiration time (exp).
> […]
> - It checks that the audience claim in the the CCA matches its own type.
> - It verifies that the NF instance ID of the NFc in the CCA matches the
>   NF instance ID in the public key certificate used for signing the CCA.

Four steps. The NRF already does the first three
(`verify_cca_signature` + `verify_cca_binding`, `nrfd/src/main.rs:2842`,
`:2940`). **Only the fourth is missing**, and it is unimplementable without
§13.3.8.2's certificate — which is precisely the dependency #393 identifies.

Where the "NF instance ID in the public key certificate" lives is *not* in
TS 33.501; it is in TS 33.310 `:734`:

> subjectAltName shall (in TLS client and server certificates, **and also in
> X.509 PKIX certificates used for signing validation of OAuth 2.0 JWT access
> tokens and/or CCA tokens**) contain a URI-ID with the URI for the NF Instance
> ID as an URN; this URI-ID shall contain the nfInstanceID of the Network
> Function instance using the format of the NFInstanceId as described in clause
> 5.3.2 of TS 29.571 [57].

and `:735` fixes the form as `urn:uuid:<uuid-v4>`. `:736` (NOTE 1a) states the
consequence of omitting it: "the identity of the NF instance can not be securely
validated". `peer_cert::nf_instance_id_from_der` already implements exactly this
extraction, for issue #186, over a DER certificate — so the §13.3.8.3 step is a
comparison, not a new parser.

## Decision 1: `x5c`, not `x5u`

**`x5c`.** The `x5u` arm is rejected, and not on grounds of convenience.

`x5u` is a URL in a JOSE header, supplied by the party being authenticated, that
the verifier must dereference to obtain the key it will then trust. On the NRF's
token endpoint that is:

- **A pre-authentication SSRF primitive.** The CCA arrives in the body of an
  unauthenticated `POST /nnrf-oauth2/v1/access-token` — authentication is what
  the CCA is *for*, so nothing has been established when the URL is read. An NRF
  that fetches `x5u` lets any party that can reach the token endpoint make the
  NRF issue an arbitrary outbound GET from inside the core network, to a host and
  port of the requester's choosing. The NRF sits on the SBI network with reach to
  every NF's management surface. Mitigating that means an allowlist of fetchable
  origins — at which point the operator is provisioning a per-peer trust list,
  which is the thing `x5u` was supposed to remove, and is strictly worse than
  `cca_trusted_keys_dir` because it is a list of *hostnames* rather than keys.
- **An availability coupling on the authentication path.** Every token request
  would block on an outbound HTTP fetch before the NRF can decide `invalid_client`.
  A CCA is deliberately short-lived (`CCA_DEFAULT_LIFETIME_SECS = 60`,
  `oauth.rs:388`) and minted per token request, so this is the hot path. A slow or
  hanging `x5u` host becomes an unauthenticated denial-of-service against the
  token endpoint: the attacker controls the URL, so the attacker controls the
  latency. Caching helps the repeat case and not the attack.
- **No offsetting benefit here.** `x5u`'s advantage is assertion size. A CCA is
  presented once per token request over a local SBI hop; a single P-256
  certificate is ~500 bytes base64, against a request that already carries a
  JWS. Trading that for an SSRF surface and a fetch on the auth path is not a
  trade worth making.

`x5c` inlines the chain (RFC 7515 §4.1.6: a JSON array of base64 — *not*
base64url — DER certificates, leaf first). The verifier needs no network, and the
latency is a chain validation the NRF would do anyway in the mTLS case.

**Rejected: both, with a preference.** §13.3.8.2 requires one; implementing two
input paths doubles the attack surface of the most security-sensitive parse in
the tree to satisfy a peer that no known implementation requires. If a
conformant third party ever sends `x5u`, this design *fails closed and says so*
(the NRF's refusal names `x5u` as unsupported rather than reporting a generic
malformed header), which is a legible ceiling rather than a silent one. That is
recorded as the ceiling below.

## Decision 2: the NRF binds the certificate to the instance ID, and it is the authority

This is the whole point of the issue, so it is stated as an enforced invariant
rather than a feature.

When a CCA carries `x5c`, the NRF:

1. Decodes the chain (RFC 7515 §4.1.6 base64 DER, leaf first). A malformed
   header is `invalid_client` — never a fall-through to the trust store, because
   "the certificate did not parse" must not be a route to the weaker path.
2. **Validates the chain to a configured CA** (`cca_trust_anchors`), at the
   current time, requiring `id-kp-jwt`-or-absent EKU per TS 33.310 `:731`.
   Chain validation uses `rustls-webpki` — the same verifier rustls already uses
   for TLS in this tree — rather than a hand-rolled path builder.
3. **Extracts the URI SAN from the validated leaf** via
   `peer_cert::nf_instance_id_from_der` and requires it to equal the CCA's `sub`
   (TS 33.501 §13.3.8.3 last bullet, TS 33.310 `:734`). A mismatch is
   `invalid_client` **naming both ids**.
4. Verifies the JWS signature against **the leaf certificate's public key** —
   not against the trust store. This is the step that makes the binding mean
   something: the chain says "this CA vouches that this key belongs to NF X", and
   the signature check says "NF X's key signed this assertion". Validating a
   chain and then verifying against a trust-store key would be theatre, because
   the certificate would constrain nothing.

Order matters and is asserted: the SAN check happens on the **validated** leaf,
after path building. Reading a SAN out of an unvalidated certificate and
comparing it to `sub` would authenticate anyone who can write both fields.

## Decision 3: `x5c` is authoritative when present; the trust store is the no-PKI path

The operator instruction was to leave no ambiguity about which mechanism is
authoritative. The rule, in one sentence: **if a CCA carries `x5c`, the
certificate decides, and the trust store is not consulted at all.**

Precedence, with the reason for each arm:

| CCA carries | `cca_trust_anchors` configured | outcome |
|---|---|---|
| `x5c` | yes | **certificate path is authoritative.** Chain validated, SAN bound to `sub`, JWS verified against the leaf key. The trust store is **not** consulted, even on failure. |
| `x5c` | no | **`invalid_client`.** The NF asserted a certificate binding the NRF cannot evaluate. Silently downgrading to the trust store would let a requester choose the weaker check by attaching a certificate — the classic downgrade. |
| no `x5c` | either | **trust store path**, exactly as today (`cca_trusted_keys` then `cca_trusted_keys_dir`), still fail-closed. |
| `x5u` | either | **`invalid_client`, naming `x5u` as unsupported.** Stated ceiling, not a silent gap. |

So `cca_trusted_keys_dir` becomes **the documented no-PKI mechanism, not a
second defence and not redundant**:

- It is **not redundant.** It is what makes plaintext dev and the docker overlay
  work with no CA at all, and removing it regresses #187. TS 33.501 §13.3.8.1
  (`:14342`) itself notes the CCA depends on cross-certification to work across
  PLMNs; a deployment with no PKI is a real deployment.
- It is **not a fallback from `x5c`.** A request that presents `x5c` never
  reaches it. That is the anti-downgrade property, and it is the reason this is
  a precedence table rather than a chain of `unwrap_or`.
- It is **subordinate in conformance terms.** Where both could apply — an NF with
  a CCA certificate *and* a published JWK — the certificate wins, because that is
  the mechanism §13.3.8.2/§13.3.8.3 specify. The trust store is the documented
  deviation, now confined to the no-PKI case and labelled as such in the config
  comments.

The consumer side mirrors this: an NF attaches `x5c` when a CCA *certificate* is
configured (`NEXTGCORE_SBI_CCA_CERT_FILE`, a PEM chain over the CCA signing key),
and omits it otherwise. `mint_cca` gains the chain as a parameter, so the header
stops being a fixed literal.

### Why the certificate is a new artefact and where it comes from

Per the claim table, the existing TLS certs certify the wrong key and carry no
URI SAN. So `NEXTGCORE_SBI_CCA_CERT_FILE` names a PEM chain over the **CCA
signing key**, with the instance ID in a URI SAN. Nothing generates such a
certificate today, and this change does not add a CA to the overlay: the dev
CA's `generate-dev-certs.sh` runs before any NF exists and therefore before any
CCA key exists, so it cannot certify one. That ordering problem is the same one
#187 solved for public JWKs by having each NF publish at startup, and solving it
for certificates needs a CA reachable at NF start (a real PKI, or CMPv2/ACME per
TS 33.310 §6.1.3c) — which is out of scope here and recorded as the ceiling.

**Consequence, stated plainly: the docker overlay continues to run the trust-store
path.** The `x5c` path is proven by in-process tests that build a real CA and a
real chain with `rcgen`, over the real `mint_cca`/token-handler code — not by the
overlay. Claiming otherwise would be the vacuous-assertion failure mode #187 hit.

## Criterion table

| # | criterion | disposition |
|---|---|---|
| 1 | `mint_cca` emits `x5c` when a chain is configured; header no longer a fixed literal | **implemented** — `mint_cca` takes `x5c_chain`; header is built, not literal |
| 2 | NRF validates the chain and asserts the §13.3.8.3 ID check, fail-closed, positive AND negative with the reason naming the mismatch | **implemented** — contrast-pair test; the error names both ids |
| 3 | trust-store path still works with no chain configured; overlay / #187 coverage does not regress | **implemented** — precedence table row 3; #187's tests unchanged and still pass |
| 4 | the deviation note at `nrfd/src/main.rs:2840` is updated or removed | **implemented** — rewritten to describe the implemented precedence and the remaining `x5u` ceiling |

## Testing

Per-PR, in-process, against the real token handler:

- **Contrast pair (the criterion-2 core).** One CA, two leaf certificates over
  two CCA keys: one with `urn:uuid:<consumer>`, one with
  `urn:uuid:<a-different-nf>`. The first authenticates and the NRF issues a
  token; the second is refused `invalid_client` with a reason naming both ids.
  Same CA, same code path, differing only in the SAN — so a pass cannot come
  from the chain failing for an unrelated reason.
- **Anti-downgrade.** A CCA with `x5c` against an NRF with no `cca_trust_anchors`
  is refused, *even when the trust store holds a good key for that NF*. This is
  the test that proves the precedence table is not an `unwrap_or`.
- **Authority.** A CCA whose `x5c` chain validates and whose SAN matches, but
  whose JWS was signed by a *different* key than the certificate certifies, is
  refused. This is what proves step 4 of Decision 2 verifies against the leaf
  key rather than the trust store.
- **Untrusted CA.** A chain from a CA the NRF does not configure is refused.
- **`x5u`.** A CCA carrying `x5u` is refused with a reason naming it unsupported,
  so the ceiling is asserted rather than described.
- **No regression.** #187's positive/negative trust-store tests are untouched and
  still pass; `mint_cca` with no chain produces the byte-identical header.

Every behavioural assertion is revert-verified: the change is broken, the NAMED
test is observed failing, and the change restored. Four reverts were run:

| what was broken | test observed failing | how it failed |
|---|---|---|
| deleted the `verified.nf_instance_id != nf_instance_id` arm | `a_cca_whose_certificate_names_another_nf_is_refused_and_its_own_is_accepted` | 200 where 400 asserted — the NRF **issued a token** for a certificate naming another NF |
| made the empty-anchors arm fall through to the trust store | `an_x5c_bearing_cca_is_refused_rather_than_downgraded_to_the_trust_store` | 200 where 400 asserted |
| returned the trust-store key instead of `verified.es256_verifying_key()` | `a_cca_signed_by_a_key_its_certificate_does_not_certify_is_refused` | 200 where 400 asserted |
| `OAuth2Client::new` no longer seeds the chain | `a_configured_chain_reaches_the_cca_a_client_actually_builds` | panicked at the `has_cca_cert_chain` assertion |
| checked `x5u` BEFORE `x5c` in the header parser | `a_header_with_both_fields_is_treated_as_x5c_not_x5u` | resolved to `Url` where `Chain` asserted |

The last one is why the parser's field order is documented as a security property
rather than left to look arbitrary: §13.3.8.2 asks for one field but nothing stops
a sender supplying both, and if `x5u` were read first an attacker could force the
URL-fetch treatment by adding a URL beside a legitimate chain.

One test also failed on first writing and was tightened rather than adjusted:
`an_expired_leaf_is_refused` initially passed validation 50 years in the future,
because rcgen's default validity window is 1975..4096. The fixture now sets an
explicit 30-day `notAfter`, so the `now` argument to `verify_x5c_binding` is
genuinely exercised.

### Counts and isolation

- `cargo test --workspace --no-fail-fast`: **6781 passed, 0 failed** (6 ignored).
  21 tests added (12 in `cca_x5c.rs`, 9 across `oauth.rs` and `nrfd`).
- `cargo fmt --all -- --check` clean; `cargo clippy --workspace` (what CI gates)
  reports **zero** warnings in any file this change touches — the 4 remaining
  warning sites are pre-existing, in `nextgcore-nas`, `nextgcore-eesd` and
  `nextgcore-smfd`.
- `nextgcore-sbi` and `nextgcore-nrfd` each looped **10×**: zero failures, at
  loadavg 1.2–5.0. The new `CCA_CHAIN_GUARD` is declared at module scope beside
  the global it protects, per the #308 rule, not inside `mod tests`.
- One pre-existing isolation flake was observed and is **not** from this change:
  `nextgcore-pcfd`'s `ue_policy_create_get_update_delete_lifecycle` failed once in
  a full-workspace run (`PTI 0x00 must be in the PCF range 80H-FEH`) and passes in
  isolation and across its own full suite. Cause is the process-global
  `AtomicU8` PTI counter at `pcfd/src/ue_policy.rs:534`. Untouched here; worth its
  own issue.

## Ceilings

1. **`x5u` is not implemented**, by the deliberate choice in Decision 1. A
   conformant peer that sends `x5u` instead of `x5c` is refused with a reason
   naming it. §13.3.8.2 permits the *sender* to choose, so a receiver that
   supports only `x5c` cannot verify such a peer's CCA. Accepting `x5u` needs the
   SSRF controls Decision 1 describes and is a separate issue.
2. **The docker overlay still exercises the trust store, not `x5c`**, because no
   CA in the tree can certify a CCA key that is generated at NF startup. Closing
   this needs CMPv2/ACME enrolment (TS 33.310 §6.1.3c, §9) or a CA service in the
   overlay. The `x5c` path's coverage is therefore in-process only — stated here
   rather than implied, because a scheduled-only stage that does not cover it
   reads as if it does.
3. **No CRL/OCSP.** Revocation is not checked; `rustls-webpki`'s
   `RevocationOptions` is the hook, and a deployment with a CRL distribution
   point has no way to configure it yet. This is a narrowing of the issue's
   third cost, not a removal of it.
4. **The chain is validated, the peer is still nextgcore.** Both sides of every
   test are this codebase, so a shared misreading of RFC 7515 §4.1.6's base64
   (not base64url) encoding would not surface. Mitigated by encoding with a real
   X.509 encoder (`rcgen`) and validating with the same `rustls-webpki` that
   validates TLS chains, rather than by a hand-written fixture.
