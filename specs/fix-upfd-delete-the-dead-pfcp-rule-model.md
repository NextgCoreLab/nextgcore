# fix(upfd): delete the dead PFCP rule model, and close the blind spot that hid it

Closes #335.

## Criteria 1 and 2 — the types go, `UeIp` with them

Every type in #335's table was re-verified unreferenced at `3129aea` before deletion, and the
check has to be spelled carefully because **the names are reused for live types in three other
modules** — which is what #335 warns makes a grep misleading:

| type | live namesake elsewhere | referents of THIS one |
|---|---|---|
| `Pdr`, `Pdi`, `SdfFilter`, `Far`, `OuterHeaderCreation`, `ForwardingParameters` | `n4_handler` (parsed from the N4 wire) | none |
| `FTeid` | `n4_build`, and `pfcp_path` imports `n4_build::FTeid` | none |
| `DuplicatingParameters`, `RedirectInformation`, `HeaderEnrichment`, `RateLimiter` | none anywhere | none |
| `UeIp` | none | only `Pdr.ue_ip` and `Pdr::pdr_match`, so it follows `Pdr` (criterion 2) |

`rg 'use crate::context::' bins/nextgcore-upfd/src` plus `rg 'context::' bins/nextgcore-upfd/src`
together return only `upf_self`, `upf_context_init`, `upf_context_final`, `TsnBridge`,
`TsnPortType` and `UPF_GLOBAL_TEST_LOCK`. No test referenced the rule types either, so they were
unreferenced from **every** target, not just the bin.

**287 lines removed**, no behaviour change: unlike #325's session model — which reached the wire
through `sess_count` → `get_load` → the NRF's `NFProfile.load` — this half had no reader at all.
Deleting it also retired the last uses of `Ipv4Addr`/`Ipv6Addr` and `AtomicU64` in the module, so
those imports went too. `nextgcore-ipfw` stays a dependency: `Pdr::pdr_match` was one of three
callers of `compile_rule`, and `main.rs:718` and `data_plane.rs` are the live ones.

## Criterion 3 — the module doc

`context.rs`'s doc claimed it held "the PFCP rule types" (a line #325 added). It now names what it
holds — the TSN bridge model and the process-global whose only live business is the load gauge —
and records this second deletion beside the first, including the three-modules-one-name hazard.

## Criterion 4 — the `dead_code = "allow"` decision, and why the premise was wrong

**Decision: the workspace-wide `allow` stays. It is not what hid either half of this rot.**

#335 and #325 both name `Cargo.toml:210` as the ambient condition that let the rot survive. That
is measurable, so it was measured rather than asserted — and it is false.

With `dead_code` flipped to `warn` workspace-wide, `cargo check --workspace --all-targets` emits
**277 warnings**, distributed:

| crate | warnings | crate | warnings |
|---|---|---|---|
| smfd | 121 | mbsmfd | 6 |
| lmfd | 37 | amfd | 5 |
| easdfd | 34 | 14 others | 1–3 each |
| seppd | 19 | integration tests | 9 |
| eesd | 17 | **upfd** | **0** |

**upfd emits none of them** — not one warning for the very types this issue is about. Three probes
in the same file, same run, same lint level pin the mechanism:

| probe | result |
|---|---|
| `fn probe(..)` (private), no caller | **warns** |
| `pub fn probe(..)`, no caller | **silent** |
| `pub(crate) fn probe(..)`, no caller | **warns** |

The lint does not fire on a `pub` item, and `pub mod context;` gave every item inside an effective
visibility of `pub` — in a **bin** crate, which has no external consumer to be `pub` *for*. So
narrowing the workspace `allow` would have bought 277 warnings of a *different population*
(private items, 121 of them belonging to smfd's tracked #223) and still not caught #325 or #335.
The thing that finds this class is the importer grep both issues used.

One probe was **invalid and had to be re-run**, which is worth recording because its output looked
like a finding: probe 3 first ran after `Cargo.toml` had already been restored to `allow`, so
`pub(crate)` appeared silent too, "confirming" that visibility made no difference. The instrument
was off, not the hypothesis — the same shape as a revert that does not bite (#326).

### What the decision does instead

Keeping the blanket and writing a note would leave the file exactly as detectable as before. So the
blind spot is closed where the issue lives, in two one-line changes to `main.rs`:

- `pub mod context;` → `mod context;` — drops the module's items to an effective `pub(crate)`,
  which the lint *does* cover. This is what turns detection on; no per-item edit needed.
- `#![deny(dead_code)]` — re-enables the lint over the workspace `allow` for this crate.

`deny`, not `warn`, because CI runs `cargo clippy --workspace` with **no** `-D warnings`
("Gate on errors only", `.github/workflows/ci.yml:88-91`). A `warn` would print into a log nobody
reads and gate nothing — the same mistake as the test retry that hid a 20% flake for months
(#308). At `deny` the crate is at zero today, so the gate costs nothing to adopt.

This is #335's **option 2 enforced rather than requested**: future-use code in upfd now has to
state what it waits for in an `#[allow(dead_code)]` reason, instead of resting on a workspace
blanket that documents nothing. It is deliberately **not** option 3: scoped to one crate, because
the workspace sweep is 277 sites and 121 of them are a different open issue.

### The gate found one immediately

Turning it on failed the build on `UpfContext::is_initialized` — **production-dead, read only by
`the_session_ceiling_reaches_the_global_context`**. That is the same test-only-reader shape as
#325, surfacing within seconds of the gate existing, which is the argument for the gate.

It is now `#[cfg(test)]`, with the distinction stated in the doc: the `initialized` **flag** is
production state (`init` latches double-initialisation on it, `fini` refuses a second teardown on
it); only the *accessor* was test-only. Gating the accessor is honest; gating the flag would not be.

## Revert-verify

The gate is the only new behaviour here, so it is the thing that had to be made to fail — and
against **CI's own command**, not a stricter local one, since the difference between `warn` and
`deny` was the entire point:

- Inject `pub(crate) fn gate_probe_zzz(&self) -> bool` into `context.rs` with no caller →
  `cargo clippy -p nextgcore-upfd` fails: `error: method gate_probe_zzz is never used`. Before this
  change the identical injection was **silent**.
- Injection and restoration were each confirmed by grep count (1, then 0) before and after the
  run, because an edit that never landed reports as a pass (#326's `cd` short-circuit).
- A first attempt injected the probe *after* `mod tests`, which failed with
  `error: items after a test module` instead of the dead-code error — a compile error proves
  nothing about the lint, so it was re-injected before the test module.

The deletion needs no revert-verify: there is no assertion it could falsify, which is precisely
the difference between this half and #325's.

## Ceilings, stated rather than implied

- The gate covers **upfd only**, and within upfd it fully covers `context.rs`. The other 14 modules
  are still `pub mod`, so a dead `pub` item in them remains invisible; making them crate-private is
  mechanical but touches every module and belongs with a decision about the workspace sweep.
- **#223** (smfd's `SmfSess`, the same class, 121 of the 277 warnings) is untouched and
  `decision`-labelled.
- The 277 figure is from `--all-targets` at `warn`; it is a *count of warning lines*, and several
  cover multiple fields, so it is a floor on the item count, not an exact tally.

## Verification

- Workspace **6537 tests, 0 failures** — unchanged from `main`, as expected for a change that
  deletes no test and adds no behaviour. `cargo clippy --workspace` 0 errors, upfd 0 warnings.
  `cargo fmt --all --check` clean.
- `Cargo.toml` was flipped to `warn` twice for measurement and restored both times; the working
  tree was confirmed identical to `HEAD` (`git diff --stat` empty) before the real edits began.

## Files

- `src/bins/nextgcore-upfd/src/context.rs` — 287-line rule model and `UeIp` deleted; imports
  trimmed; module doc corrected; `is_initialized` gated `#[cfg(test)]`.
- `src/bins/nextgcore-upfd/src/main.rs` — `mod context;` and `#![deny(dead_code)]`, with the
  measurement that justifies both.
