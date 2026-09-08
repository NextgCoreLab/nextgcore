# nextgcore #205 (amfd): retrieve the GPSI from `am-data` and convey it on N11

Verified against `main` @ `4e5771d`. The issue was written at `d9aea74`; every cite was
re-located and one part of its suggested approach is **stale** — see below.

## Verified against current main

| claim in the issue | site on `4e5771d` | still true? |
|---|---|---|
| the N11 builder documents `gpsi` as deliberately absent | `bins/nextgcore-amfd/src/sbi_path.rs:883` | yes |
| `AmfUe` has no `gpsi` field | `grep -n gpsi bins/nextgcore-amfd/src/context.rs` → nothing | yes |
| the AMF's only SDM retrieval is `GET /nudm-sdm/v2/{supi}/am-data` | `sbi_path.rs:1582` (`call_udm_sdm_get_am_data`) | yes |
| the response parse does not read `gpsis` | it read `subscribedUeAmbr` and `nssai.defaultSingleNssais` only | yes |
| `udrd` populates `gpsis` in `am-data` | `bins/nextgcore-udrd/src/nudr_handler.rs:474` `build_am_data`, `msisdn-{bcd}` | yes |

**Stale in the suggested approach.** It says to "populate the existing (already-wired) `gpsi`
member of the N11 identity struct". There is no such member: `SmContextIdentity`
(`sbi_path.rs:818`) carries `supi`, `pei`, `guami`, `serving_plmn`, `serving_nf_id`, `ue_location`
and stops. The comment at `:883` is the *only* trace of `gpsi` in the crate. So the field had to be
added to the struct as well as to `AmfUe` — a larger diff than the issue implies, though in the
same shape.

## Decision 1: `Gpsi` is accepted only in its two NAMED forms, which is stricter than TS 29.571's own pattern

TS 29.571's `Gpsi` pattern is `^(msisdn-[0-9]{5,15}|extid-[^@]+@[^@]+|.+)$`. **That trailing `.+`
alternative matches any non-empty string**, so validating against the pattern *literally* would
validate nothing — a UDR bug that put a bare SUPI, a stray whitespace or an empty placeholder into
`gpsis` would pass, and the AMF would convey it to the SMF as an external identity.

`validated_gpsi` therefore accepts `msisdn-<5..15 digits>` and `extid-<local>@<domain>` and
rejects everything else. The reasoning: a GPSI exists to be the identifier a CHF or AF correlates
on (TS 23.501 §5.9.8), so a value of unknown form is worth no more than no value at all — and
`None` is the honest one, because every consumer then omits the member instead of conveying
something a billing system cannot join on. This is the same omit-never-placehold rule #73
established for `supi` and `servingNetwork`, applied one step earlier: at ingest rather than at
serialisation.

The deliberate cost, stated because it is a real conformance trade: a subscription carrying a
FUTURE GPSI type added by 3GPP under the `.+` escape is dropped rather than forwarded. The caller
logs that at `warn` with the entry count, so it is diagnosable instead of silent, and the fix is to
add the new form to `validated_gpsi`.

## Decision 2: the first well-formed entry wins, and a malformed leading entry is skipped

`gpsis` is an array; the N11 `gpsi` member is singular. The first entry that validates is taken —
not the first entry outright, so one malformed record does not cost a subscriber their usable
second identity. When nothing in the array validates, nothing is stored.

## Decision 3: the store is unconditional, so a withdrawn GPSI is cleared

`state.amf_ue.gpsi = am_data.gpsi.clone()` assigns even when the response carries none, rather than
`if let Some(..)`. A subscription that STOPS carrying a GPSI must clear the stale one on
re-registration; keeping the old value would have the AMF conveying an identity the subscription no
longer asserts, which is the same class of defect as conveying a derived one.

## Decision 4: two refactors were made to close a false-guard shape, not for tidiness

Neither is asked for by the issue. Both exist because without them the tests would have been
guards that prove nothing:

1. **`parse_am_data` extracted from `call_udm_sdm_get_am_data`.** The decode was inline in an async
   function that needs a live UDM, so the interesting `gpsis` inputs — several entries, a malformed
   leading entry, an empty array, an all-malformed array — were not expressible from a test at all.
2. **`build_sm_context_identity` extracted from the inline block at the CreateSMContext call site**
   (`ngap_path.rs:3600`). `sbi_path`'s serialiser tests build a `SmContextIdentity` **by hand**, so
   they assert that the serialiser emits what it is handed. They would keep passing if the mapping
   from the UE context were `gpsi: None` — the exact shape of false guard recorded from the #210
   session. The new test asserts the mapping itself.

The second extraction is a behaviour-preserving move of ~50 lines; its revert (`gpsi: None`) is one
of the five below.

## Acceptance criteria

- [x] `AmfUe` carries an optional GPSI parsed from the `am-data` response the AMF already retrieves
      — `context.rs` `gpsi: Option<String>`, assigned from `AmDataResponse.gpsi` in the
      registration path.
- [x] A malformed or absent `gpsis` yields no stored GPSI (no blank, no derived value) —
      `am_data_takes_the_first_well_formed_gpsi` covers empty array, empty string, a SUPI, a
      non-string, and an absent member; `validated_gpsi_accepts_only_the_named_forms` covers 13
      malformed spellings including both `msisdn-` digit bounds.
- [x] `build_create_sm_context_request` emits `gpsi` when held; a test asserts both the present and
      absent cases, and that the emitted value matches the `Gpsi` pattern —
      `n11_create_carries_the_gpsi_when_the_subscription_supplies_one` (present, pattern-checked,
      and asserted *not equal* to the SUPI) and `n11_omits_identity_the_amf_does_not_have` (absent,
      `gpsi` added to its omit list).
- [x] Workspace lint and the amfd suite pass.

## Verification

Workspace `5985 passed / 0 failed / 6 ignored` (baseline `5981` on `4e5771d`; +4 tests). `cargo
clippy --workspace --all-targets` and `cargo fmt --all -- --check` clean, zero new warnings.

Five reverts, each run against the named test:

| revert | expected to break | result |
|---|---|---|
| the N11 `gpsi` insert removed | `n11_create_carries_the_gpsi_when_the_subscription_supplies_one` | **1 failed** |
| `gpsi` emitted unconditionally (`null` when absent) | `n11_omits_identity_the_amf_does_not_have` | **1 failed** (`got {"gpsi":null,...}`) |
| `validated_gpsi` accepts any non-empty string (the letter of the TS 29.571 pattern) | `validated_gpsi_accepts_only_the_named_forms`, `am_data_takes_the_first_well_formed_gpsi` | **2 failed** |
| `parse_am_data` stops reading `gpsis` | `am_data_takes_the_first_well_formed_gpsi` | **1 failed** |
| `build_sm_context_identity` returns `gpsi: None` | `sm_context_identity_is_built_from_the_ue_context` | **1 failed** |

No false guards found this time. The fifth revert is the one that would have caught one: it is the
link the hand-built-identity tests cannot see.

## Ceilings

* **One link in the chain is still untested**: the single assignment
  `state.amf_ue.gpsi = am_data.gpsi.clone()` inside `handle_registration_complete`'s SBI sequence.
  The decode either side of it is tested (`parse_am_data`) and so is the mapping after it
  (`build_sm_context_identity`), but that statement sits in a ~400-line async method whose
  preconditions are a live UDM, a live PCF and an authenticated UE state machine. Driving it needs
  a registration-flow harness that does not exist in this crate; noted rather than faked with a
  test that would assert only that a field can be assigned.
* `AmfUe` already carries `msisdn: Vec<String>` / `num_of_msisdn`, populated by nothing in the
  crate. They are the EPS-shaped spelling of the same subscriber datum and are left alone: nothing
  in #205 asks about them, and merging them into `gpsi` would change what `msisdn` means for any
  future reader. Worth an issue if the duplication matters.
* Only the N11 `SmContextCreateData` consumer is wired. The GPSI is also conveyable on
  Namf_EventExposure and in Namf communication contexts (`namf_server.rs:557` already comments that
  a subscription may target a `gpsi`); those are untouched, because #205 scopes to the N11 member
  #73 criterion 1 named.
* `extid-` GPSIs are accepted and conveyed but no in-tree producer emits one: `udrd`'s
  `build_am_data` only ever writes `msisdn-{bcd}`. So the `extid-` half of the validator is
  exercised by unit tests only, never end to end.
* GitNexus impact analysis unrunnable (no MCP server connected — 40th consecutive PR). Blast radius
  by grep: `SmContextIdentity` has one production construction site (now
  `build_sm_context_identity`) and one consumer (`build_create_sm_context_request`);
  `AmDataResponse` has one producer and one consumer; `AmfUe.gpsi` has one writer and one reader.
