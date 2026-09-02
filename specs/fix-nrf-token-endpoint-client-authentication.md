# Fix: the NRF token endpoint must authenticate the consumer, and that authentication must be unforgeable

Closes `nextgcore#64` (gaps 1 and 2). Gaps 3, 4 and 5 landed in PRs 182, 183
and 184.

## Why gaps 1 and 2 cannot be split

Issue #64 gap 1 is "client authentication is default-off"; gap 2 is "there is no
TS 33.501 §13.4.1.1 subject/certificate binding". Shipping either alone leaves
the bypass fully open, because **both** of the NRF's authentication inputs are
forgeable today:

1. **The XFCC header is trusted unconditionally.**
   `extract_transport_client_nf_instance_id` (`main.rs:2100`) reads
   `x-forwarded-client-cert` from the request with no check that the peer is a
   trusted TLS terminator. The header's own doc comment states it "MUST be set
   only by the trusted terminator and stripped from any client-supplied copy at
   the trust boundary" — but nothing in this repo establishes that boundary:
   `grep -rn forwarded-client-cert docker/ deploy/ k8s/ configs/` returns
   nothing, and no SCP fronts the NRF token endpoint. So any client that can
   reach the NRF can send `x-forwarded-client-cert: URI=urn:uuid:<victim>` and
   be treated as mutually authenticated.
2. **A CCA's signature is not verified by default.** `cca_verify_signature`
   defaults `false`, so `verify_cca_binding` alone accepts any assertion whose
   *claims* say `sub == iss == nfInstanceId`. An attacker mints an unsigned CCA
   naming any registered NF and passes.

Turning gap 1's `require_client_auth` on against those two inputs buys nothing:
it demands evidence of identity and then accepts forged evidence. Conversely,
making the evidence unforgeable while leaving enforcement off leaves the
endpoint minting tokens for any registered `nfInstanceId`. The two are one
change.

## Spec basis

- **TS 33.501 §13.3.1** — the NRF and the NF Service Consumer shall mutually
  authenticate during the access token request.
- **TS 33.501 §13.4.1.1** — the NRF binds the token to the requester; the
  subject claim must correspond to the *authenticated* client identity, not a
  self-asserted `nfInstanceId`.
- **TS 33.501 §13.3.8.2/§13.3.8.3** — CCA construction and NRF-side validation,
  including the ES256 JWS signature.
- **TS 33.310** — the NF Instance ID travels in the certificate URI SAN.
- **RFC 9440 / Envoy XFCC** — a forwarded client-certificate header is
  trustworthy only when set by a terminator the receiver trusts.

## The change

### 1. `nextgcore-sbi`: consumers can actually authenticate (`oauth.rs`)

Under a secure default the NRF requires evidence of identity, so consumers need
a way to produce it. No NF in the tree mints a CCA today — `oauth.rs` has zero
CCA support, and every other `cca` hit in `src/` is a Diameter
Credit-Control-Answer.

- `mint_cca(key, nf_instance_id, audience, now, lifetime)` builds the
  TS 33.501 §13.3.8.2 assertion: JOSE header `{"alg":"ES256","typ":"JWT"}`,
  claims `sub = iss = nfInstanceId`, `aud` = the receiving NF type (`"NRF"`),
  `iat`, `exp`; signed ES256 over `base64url(header).base64url(payload)`.
- `AccessTokenRequest.cca` is carried in the form body as `cca=<jwt>` — the
  field `parse_token_request` already reads.
- `OAuth2Client` gains a CCA signing key. It is resolved **process-wide**,
  mirroring the existing `oauth2_standard_paths_default()` selector: an explicit
  `set_cca_signing_key()` override first, else the
  `NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE` env var, resolved once. This deliberately
  avoids touching the 16 `OAuth2Client::new` call sites — the same reasoning as
  PR 180's `--kill` fix, where a flag duplicated across 12 daemons was wrong in
  12 places at once.
- `load_or_create_es256_key(path)` moves into `nextgcore-sbi` so the NF CCA key
  and the NRF signing key (PR 184) share one loader. It keeps PR 184's
  contract exactly: hex-encoded raw 32-byte scalar, `0600`, generate only when
  **absent**, and a malformed file is an error, never a silent regeneration.
  nrfd's local copy is deleted in favour of it.

### 2. nrfd: make the authentication inputs unforgeable (`main.rs`)

- **XFCC trust gate.** New knob `nrf.sbi.oauth2.trust_forwarded_client_cert`,
  default **false**. `extract_transport_client_nf_instance_id` returns `None`
  unless it is on, so an untrusted deployment cannot be spoofed by a header.
  Enabling it warns loudly at startup that the header must be stripped at the
  trust boundary.
- **A CCA authenticates only when its signature verifies.**
  `enforce_client_authentication` is no longer handed "a `cca` field is
  present"; it is handed the outcome of `authenticate_token_client`, which
  returns an identity only for a CCA whose binding *and* ES256 signature
  verified against a key in `cca_trusted_keys`. `cca_verify_signature` defaults
  **true**; the existing fail-closed "no trusted key for this issuer" rejection
  is unchanged.
- **§13.4.1.1 subject binding.** The token `sub` is taken from the
  *authenticated* identity rather than from the request body, so the two cannot
  diverge structurally. Both binding checks (cert SAN and CCA `sub`) already
  force equality with the body `nfInstanceId`; deriving `sub` from the
  authenticated value means a future edit that loosens one of them cannot
  silently re-introduce a self-asserted subject.

### 3. nrfd: secure defaults with one documented escape hatch

- `require_client_auth` defaults **true**; `cca_verify_signature` defaults
  **true**.
- `NrfPolicy::from_yaml` stops using `unwrap_or(false)` on these knobs. That
  pattern overrides the struct default with `false` whenever an `oauth2:`
  section exists but omits the key — so a secure default would have been
  silently undone by any existing config file that mentions `oauth2:` at all.
  Absent keys now leave the default in place.
- Escape hatch: `nrf.sbi.oauth2.allow_unauthenticated_token_requests` (env
  `NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED`), default false. When set it disables
  the requirement and logs a `warn!` naming the consequence. This is the
  issue's "documented, explicitly-set escape hatch rather than silent
  default-off": the insecure posture is still reachable for the matched
  simulator and non-TLS dev, but it must be *asked for* and it announces itself.
- `require_client_cert_binding` stays default off. It mandates mTLS
  specifically, which a plaintext dev deployment cannot satisfy; the secure
  default is "authenticate somehow", not "authenticate by mTLS only".

## Acceptance criteria (from #64)

1. Default config, no verifiable client identity ⇒ `invalid_client`. — test
   `default_policy_rejects_unauthenticated_token_request`.
2. CCA/mTLS present but subject mismatched ⇒ rejected. — tests
   `cca_subject_mismatch_is_rejected`, `transport_identity_mismatch_is_rejected`.
3. (gap 3, landed in PR 182.)
4. (gap 4, landed in PR 184.)
5. (gap 5, landed in PR 183.)
7. Existing nrfd / nextgcore-sbi suites pass under the stricter defaults, with
   the documented override applied where a test asserts the legacy posture.

Additionally, covering the forgeability that made the split impossible:

- `unsigned_cca_does_not_authenticate` — a claim-valid but unsigned CCA is not
  accepted as authentication under the default policy.
- `xfcc_header_is_ignored_unless_trusted` — the header confers no identity
  unless `trust_forwarded_client_cert` is on.
- `token_subject_is_the_authenticated_identity` — `sub` comes from the
  authenticated identity.

## Consequences worth stating

**The NRF is not exempt from its own policy.** With `nrf.sbi.oauth2.require =
true` the NRF acquires tokens from itself for its outbound status
notifications, and that request now needs authentication like any other. It
deliberately does not self-exempt by `nfInstanceId`: a token request arriving
over the network claiming to be the NRF is indistinguishable from a spoofed one,
so exempting that identity would reopen the bypass. Operators enabling the
client side must give the NRF a CCA key and trust its own public key.

**The docker OAuth2 overlay opts out, explicitly.** It cannot satisfy the
secure default, and the reason is concrete: `cca_trusted_keys` is keyed by
`nfInstanceId`, but no NF in `docker-compose.yml` pins its instance ID, so every
NF mints a fresh UUID per start and there is no stable key to pre-register.
`nrf-oauth2.yaml` therefore sets `require_client_auth: false` with a comment
naming the three things needed to run it authenticated. That is a visible,
argued opt-out rather than a silent default — but it does mean the project's
only OAuth2 demonstration currently demonstrates the unauthenticated posture,
and pinning instance IDs plus provisioning per-NF keys should become its own
issue.

**`docs/book/` is not regenerated.** The repo commits mdBook output alongside
`docs-book/src`, but the locally-available mdBook version rewrites 50+ unrelated
files (renamed hash-suffixed assets, reflowed pages), which would bury the
change. Only the source `docs-book/src/configuration/nrf.md` is updated here;
the generated book needs a rebuild with the project's own mdBook version.

## Deliberately not in scope

**Surfacing the rustls-verified peer certificate onto `SbiRequest`.** When the
NRF terminates TLS itself with `verify_client = true`, the verified peer
certificate is available at `tls_stream.get_ref().1.peer_certificates()` — right
where the RFC 5705 exporter secret is already extracted (`server.rs:882`) — but
its URI SAN is never surfaced to handlers, so direct mTLS yields no identity.
Adding it needs an X.509 SAN parser (no such dependency is in the tree today)
and is additive: with this PR, mTLS-via-SCP authenticates through trusted XFCC
and direct connections authenticate through a signed CCA, so both deployment
shapes have a working path. The existing code comment at `main.rs:2095-2099`
already scopes this as an additive `nextgcore-sbi` extension; it should become
its own issue.
