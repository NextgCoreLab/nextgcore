# nextgcore #186: recover the NF identity from a verified TLS peer certificate

Verified against `main` @ `bafec89`.

Closes #186. Removes the last "deliberately not in scope" caveat from the #63/#64
security work.

## The defect

`SbiServer` supported mTLS — `verify_client = true` plus a client CA — and rustls
verified the client's chain at handshake time. The verified certificate was then
**thrown away**.

So an NF that terminated TLS itself learned nothing about who had connected. The
only certificate identity any NF could consume arrived in an
`x-forwarded-client-cert` header from a TLS-terminating SCP or ingress. The
consequence was concrete rather than theoretical:
`nrf.sbi.oauth2.require_client_cert_binding` could only ever **reject** on a direct
connection, so a deployment that had done the hard part — per-NF certificates,
mutual TLS on every listener — still could not use it, and had to either insert an
SCP purely to translate a certificate into a header, or provision a *second*
credential (a CCA signing key per NF plus the matching public keys in the NRF's
trust store) to express an identity mutual TLS had already established.

## The fix

`nextgcore-sbi::peer_cert::nf_instance_id_from_der` extracts the URI
SubjectAltName (TS 33.310 puts the NF Instance ID there, conventionally as
`urn:uuid:<id>`), stripping the URN prefix case-insensitively per RFC 8141 and
returning any other URI form verbatim — truncating an `https://` service URI would
silently weaken the comparison for a deployment that identifies NFs that way.

It is surfaced as `SbiRequest::peer_cert_nf_instance_id`, threaded exactly like the
existing `tls_exporter_secret`: extracted once per connection at the accept site,
from the **same borrow** that already yields the RFC 5705 exporter secret and for
the same reason — it must happen before the stream moves into `TokioIo`. `None` for
plaintext, for TLS without client authentication, for a certificate with no URI SAN,
and for programmatically-built requests, so every existing call site is unaffected.

nrfd now **prefers** it over the forwarded header, and needs no trust declaration
to do so: rustls validated the chain during this process's own handshake, so there
is no terminator whose honesty has to be assumed. The `trust_forwarded_client_cert`
gate from #185 still governs the header path.

The module does no verification, deliberately. Chain validation, expiry and
revocation are rustls's job; a parser that also decided trust would be the wrong
shape.

## The dependency

`x509-cert 0.2` (RustCrypto), `default-features = false`. It builds on the same
`der 0.7.10` that `p256` already pulls in, so no second ASN.1 stack — `der
0.8.0-rc` was already in the lock before this change. Five crates are added in
total (`x509-cert`, `der_derive`, `flagset`, `tls_codec`, `tls_codec_derive`).

The alternative was a hand-rolled SAN extractor to avoid a dependency. Rejected:
this parses attacker-influenced bytes to produce a **security-relevant identity**,
and hand-writing X.509 parsing for that is the wrong trade at any dependency count.

## Verification

* `direct_mtls_surfaces_the_peer_nf_instance_id` — a real mTLS handshake against a
  production-profile listener, where the handler reports back the identity it saw
  and the test asserts it is the client certificate's `urn:uuid:` value with the
  prefix stripped. No header, no terminator. **Revert-verified:** removing the
  `peer_certificates()` extraction fails exactly this test and no other.
* `a_plaintext_connection_surfaces_no_peer_identity` — no certificate means `None`,
  not something a caller could act on.
* Six unit tests on the parser, all against **rcgen-generated** certificates rather
  than hand-written byte fixtures, so it is proven against a real encoder: URN
  extraction, case-insensitive prefix, non-URN URI passthrough, a DNS-only
  certificate yielding nothing, malformed input yielding `None` rather than
  panicking (empty, garbage, and a truncated valid certificate), and the
  normalisation rules in isolation.

Workspace **5670 passed / 0 failed** (baseline 5662), `cargo test` exit 0. fmt
clean; `cargo clippy --workspace --all-targets` 0 errors.

**Not verified:** no real 3GPP NF certificate was tested — only rcgen-generated
ones. If a vendor encodes the URI SAN differently (an `otherName`, say, or a bare
UUID with no URN prefix) this returns the wrong thing or nothing, and only interop
against a real certificate will show it.

## Definition of done

- [x] mTLS request with a URI-SAN certificate yields `Some(id)`; plaintext and
      no-client-certificate yield `None`.
- [x] The parser is exercised against generated certificates, not byte fixtures.
- [x] `require_client_cert_binding` is satisfiable on a direct mTLS connection.
- [x] A directly-verified certificate overrides the forwarded header.
- [x] Malformed input cannot panic.
- [x] The dependency decision is recorded with its reasoning.
