# Fix nssfd Nnssf_NSSelection: NSI population, roaming enum, unrouted scenarios, fabricated response IEs

Closes nextgcore #93.

All cites re-located against `main` at `32a091a`; the issue verified them at
`76ea248`.

## 1. The NSI table was never populated — and the configuration to populate it
already existed

The issue frames this as "add an `nsi` section to `NssfSection`". Re-verification
found something more specific: **the `nsi` block is already present in every
shipped config** — `docker/rust/configs/5gc/nssf.yaml`, `nssf-oauth2.yaml`, the
k8s ConfigMap and the Helm ConfigMap all carry

```yaml
nssf:
  sbi:
    client:
      nsi:
        - uri: http://.../
          s_nssai: { sst: 1 }
```

…and `SbiClientYaml` declared only `nrf`, so serde dropped it silently. `nsi_add`
therefore had **no production caller at all** (every call site was `#[cfg(test)]`),
`nsi_find_by_s_nssai` missed on every request, and the handler answered `403`.

So the fix is to READ the configuration the deployments already carry, not to
invent a second top-level `nsi` schema. A new key would have left the shipped one
inert while looking fixed — the same divergent-configuration trap as two NF
profile builders. **Consequence: every shipped deployment starts selecting slices
correctly with no config change.**

`nsi_id` is honoured when the operator assigns one, otherwise the UUID
`NssfNsi::new` already mints is kept. An entry with no `s_nssai` is **skipped with
a warning**, not installed under SST 0: guessing a slice identity would install an
instance answering for a slice nobody configured.

### Startup behaviour when no NSI is configured

An **ERROR log naming the consequence**, not a non-zero exit. The criterion allows
either. Startup failure is right for a *malformed* config, but an **absent
optional section is not malformed**, and refusing to boot would break every
existing deployment on upgrade — for a daemon that still serves the registration
and NSSAI-availability scenarios perfectly well, since neither consults the NSI
table. Because all four shipped configs carry the block, the error fires only for
a deployment that removed it, which is what "cannot ship silently" requires.

## 2. `RoamingIndication` — one correction to the issue

The issue says a conformant `HOME_ROUTED_ROAMING` "is silently dropped rather than
honoured". It was **hard-rejected**: the parser returned `None` and the caller
already answered `400 INVALID_IE_VALUE`. Same defect, sharper symptom — a
conformant consumer got a bad-request for a legal value.

- `HOME_ROUTED_ROAMING` (TS 29.531 §6.1.6.3.3) is now accepted.
- The outbound H-NSSF query emits it instead of the non-normative `HOME_ROUTED`.
- `HOME_ROUTED` is still **accepted inbound** as a documented shim, because this
  NSSF emitted it until now, so a peer on an older build may echo it back. It is
  never emitted.
- Anything else is refused with 400 `INVALID_IE_VALUE` naming the three legal
  tokens. `roaming_indication_from_str -> Option` became
  `roaming_indication_parse -> Result`, so "not understood" and "not sent" stop
  being the same value.

`build_hnssf_query_path` was **extracted** from the async `send_hnssf_query` for
one reason: the emitted token was built inline inside a network call, so no test
could see it. That extraction is why the wire value is now pinned — see
Verification.

## 3. The two unrouted scenarios, and what each is actually allowed to answer

Both query parameters are plain `array(Snssai), minItems: 1` — considerably
simpler than the issue's "backed by a configured mapping table" suggests. The
response IEs are NOT interchangeable:

| Scenario | Clause | Feature | Response IE |
|---|---|---|---|
| `slice-info-request-for-pdn-connection` | §5.2.2.2.5 | RSIPCE (bit 3) | `mappingOfNssai` (VPLMN→HPLMN) |
| `slice-info-request-for-other-purpose` | §5.2.2.2.6 | SIOP (bit 4) | `snssaiInfoRspData` (NSI IDs per S-NSSAI) |

- **other-purpose** is served entirely from the NSI table this PR populates, so it
  became answerable only once part 1 landed.
- **pdn-connection** needs VPLMN→HPLMN mapping data nothing in this core derives:
  the registration path only echoes a mapping the *consumer* supplied, and the
  home store is keyed by (home PLMN, home S-NSSAI) rather than holding a
  serving→home pair. Rather than fabricate one, a new `nssf.nssai_mapping[]`
  config block provides it, and with no entries the scenario answers the spec's
  own **403 `SNSSAI_NOT_SUPPORTED`** (§5.2.2.2.5 step 2b).

Both previously fell through to **400 `MANDATORY_QUERY_PARAM_MISSING`**, which
told a conformant consumer it had omitted a query parameter it had just supplied —
a wrong answer, not merely a missing feature.

`supportedFeatures: "d"` (bit 1 + RSIPCE + SIOP) is advertised on these two
responses only. Widening what the registration / PDU-session / UE-CU responses
advertise would change already-negotiated behaviour on paths #93 does not touch.

## 4. Fabricated response IEs

- **`targetAmfSet` comes only from configuration.** The TAI-derived
  `<mcc>-<mnc>-01-001` fallback is deleted: region 01 / set 001 is an AMF set
  nobody deployed, so the AMF was told to re-select against a set that does not
  exist — and because the value is *well-formed*, the failure surfaced as a
  re-selection finding nothing rather than as a bad response. Absent is checkable
  by the consumer; a plausible wrong value is acted on with full confidence.
- **Suppressed when `candidateAmfList` is present.** TS 29.531 §6.1.6.2.2 makes
  these two alternative ways to steer re-selection; sending both leaves the AMF to
  guess which governs, and the candidate list is the more specific answer.
- **`accessType` reflects the request.** Taken from
  `allowedNssaiCurrentAccess.accessType`, which is where TS 29.531 puts the access
  the consumer is asking about. `allowedNssaiOtherAccess` describes the *other*
  access and is deliberately not read as the current one.
  `SliceInfoForPDUSession` carries **no** `accessType` member at all, so on the
  PDU-session path `3GPP_ACCESS` is the only available answer; it is now a named,
  documented `DEFAULT_ACCESS_TYPE` rather than an inline literal, and the doc
  comment says why deriving one there would mean inventing it.

## Verification

- Workspace: **5913 tests pass, 0 fail** (nssfd 94 → 105); `cargo clippy
  --workspace` clean; `cargo fmt --all --check` clean.
- **17 behavioural claims individually revert-verified**, each fix reverted with
  the named test required to FAIL.
- Three reverts did not bite on the first pass, and all three were real problems
  in my own tests, not defence in depth:
  1. **Nothing tested the outbound H-NSSF token.** Reverting the emission to
     `HOME_ROUTED` left the roaming test green, because that test only asserted
     the *constant*. Fixed by extracting `build_hnssf_query_path` and asserting
     the query string contains `"roamingIndication":"HOME_ROUTED_ROAMING"` and
     does **not** contain the old spelling. This is the criterion that explicitly
     asked for the outbound assertion.
  2. **The slice-less-entry test passed for the wrong reason.** The global NSSF
     context defaults to `max_num_of_nf = 0`, so `nsi_add` refuses *every* insert
     until `init` runs — meaning the test asserting "0 installed" was satisfied by
     a loader that could not install anything at all. It only passed in the full
     suite by ordering accident, i.e. it was latently flaky. All four NSI tests now
     call `nssf_context_init(64)` explicitly, with a comment recording why.
  3. One revert anchor was stale (paired with the wrong test); retargeted.

### Verification ceilings

- The NSI loader is asserted through `load_configured_nsis` against the real YAML
  shape, which covers deserialisation plus installation, but **not** the
  `main()` wiring that calls it — nssfd's startup is not driven by any test
  harness. What is proven is that the shipped YAML shape parses into installed,
  discoverable NSIs.
- The startup ERROR log for an empty NSI table is not asserted (no log-capture
  harness in this crate); the code path is present and the count logic is
  exercised.
- GitNexus impact analysis was **not run** — no GitNexus MCP server is connected,
  so `nextgcore/CLAUDE.md`'s mandate remains unsatisfiable.

## Files

- `src/bins/nextgcore-nssfd/src/main.rs` — `NsiClientYaml`/`SbiClientYaml.nsi`,
  `load_configured_nsis`, startup check, `roaming_indication_parse` +
  `ROAMING_HOME_ROUTED`, `build_hnssf_query_path`, the two scenario handlers +
  dispatcher arms, `nssai_mapping` config, `targetAmfSet`/`accessType` fixes
- `src/bins/nextgcore-nssfd/src/nnssf_handler.rs` —
  `RegistrationSliceInfo.current_access_type`
- `docs-book/src/configuration/nssf.md` — the docs stated the `nsi` block was
  inert and documented the removed TAI fallback
