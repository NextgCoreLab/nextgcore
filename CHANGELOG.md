# Changelog

All notable changes to **nextgcore** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Scope of validation.** nextgcore is a research/interop implementation, **not a
> production-certified 5G core.** Conformance is verified against 3GPP spec text,
> hand-derived golden byte-vectors, strict-peer tests (one NF driving another NF's
> real handler), and the matched-simulator end-to-end suite. It has **not** been run
> against a TTCN certification suite or an independent third-party gNB/UE/core.

## [Unreleased] — proposed v0.1.0

First release aligning the core with the 3GPP Rel-15/16/17/18 procedures and adding a
full matched-simulator data-plane validation path. 25 NF binaries + 17 shared libraries,
zero C dependencies. Dual 5G-SA / 4G-EPS (5GS↔EPS interworking retained).

### Added
- **One-command matched-sim E2E** (`docker/rust/e2e.sh`): disk preflight (#269 guard) →
  build → registration + PDU session + user-plane ping through the GTP-U tunnel. **84/84 green.**
- **Positioning** (lmfd↔amfd): LMF-initiated LPP/NRPPa over Namf_Communication N1N2,
  uplink NRPPa ingest, measurement-derived location fixes (TS 23.273 / 29.572 / 37.355 / 38.455).
- **UE policy** (pcfd): URSP delivery via a real UPDP codec and N1 chain (TS 24.501 Annex D / 24.526).
- **SoR/UPU Part B** (udmd/ausfd): SoR-MAC-IAUSF / UPU-MAC-IAUSF (TS 33.501 §6.14/6.15).
- **SIDF** (udmd): SUCI de-concealment at the UDM; the UDR only ever sees the SUPI (§6.12).
- **NRF security** (nrfd): CCA ES256-JWS verification + token-requester transport auth (TS 29.510 §13.3.8.3).
- **SEPP** (seppd): N32-c certificate signing-key path.
- **Standard OAuth2** on the SBI layer (`/oauth2/token`, TS 29.510).
- **Edge** (eesd): spec-exact ACInfoSubscription / EECContextPush bodies + notifier.
- **MBS** (mbsmfd): N2 multipart ContextUpdate + NGAP MBS transfer ASN.1 (TS 29.532).
- **Analytics** (nwdafd): real per-NF NF_LOAD ingestion via NRF NFStatusSubscribe (TS 29.520).
- **Slice admission** (nsacfd): slice-quota provisioning from config (TS 29.536 §6.1.3.4).
- **Test infrastructure**: amfd/pcfd/udmd/ausfd/bsfd split into lib+bin so cross-NF tests
  drive the peer's real handler; hand-derived golden byte-vectors for the wire encoders.

### Fixed
- **nsacfd** did not provision its configured slice quotas → 403'd every PDU session
  (5GSM cause #67), taking down the whole data plane. Now provisioned per TS 29.536, with an
  SST-wide quota covering SD-specific requests.
- **amfd** never discovered the NSACF on-demand and dropped NSACF NRF profiles → slice admission
  was silently degrade-open. On-demand NRF discovery added (TS 29.510).
- NAS/NGAP/PFCP wire fixes across the fleet (e.g. amfd T3512 GPRS-timer unit, smfd PFCP PDI
  UE-IP S/D flag, udrd SQN side-effects).
- CI-flaky tests sharing a process-global NF context / env under parallel `cargo test`
  serialized on a per-crate test guard (nsacfd, udmd, ausfd).

### Changed
- Documentation synced with the code (getting-started, docker/E2E, per-component gap docs, NF table).
- Honesty pass: dropped "production-ready" framing; 6G/Rel-20 items are research prototypes.

### Validation
- `cargo test --workspace`: 5170 passed / 0 failed · `clippy`: 0 errors · `fmt`: clean · Docker E2E: 84/84.

## [0.0.1] — 2026-03-08
- Initial public tag.
