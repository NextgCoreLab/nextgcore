# nextgcore #234 + #233: delete two dead registries that read as working NRF integration

Verified against `main` @ `4ec257a`. Both issues' reference tables reproduced exactly; both turned out to
be **more** dead than reported.

`Closes #234`. `Closes #233`.

## Why one PR for two issues

The project convention is one PR per issue *covering all of that issue's parts* — the prohibition is on
**splitting** an umbrella, not on combining. These two are single-scope pure deletions of the same class,
filed in the same backlog sweep, with the same recommendation (`DELETE`) already settled in each issue body
so neither needs re-litigating. Combining them means one lint/test gate instead of two, and both still
close cleanly and auditably. The bodies below are kept separate so a reviewer can compare each diff against
the issue that asked for it.

## #234: `bsfd`'s consumer-side NRF-discovery path

Three functions formed a consumer-side discovery path that could not work and had no caller.
`bsf_sbi_send_request` and `bsf_sbi_discover_and_send` logged at debug, did nothing, and returned a
**fabricated `Ok(1)`** transaction ID; `bsf_nnrf_handle_nf_discover` was reached only from its own two
tests, which passed *because* the stub fabricated success.

### The pre-check the issue asked for, answered

> Check first whether `bsf_sbi_send_response`, `PathSbiRequest` and `SbiXact` have live callers before
> removing them too.

**None of the three does**, so all three went as well:

| symbol | references in `bsfd` |
|---|---|
| `bsf_sbi_send_response` | its definition and one test (`sbi_path.rs:343`) — nothing else |
| `PathSbiRequest` | the deleted functions, one test, and the deleted discovery handler |
| `SbiXact` | **its definition only.** No caller, no test, nothing |
| `PathSbiRequestBuilder` | its own definition, whose return type is `PathSbiRequest` |

`bsf_sbi_send_response` is worth naming separately: it returned `Ok(())` having sent nothing, under a
comment saying "the actual response is sent by the HTTP handler in main.rs". So it was a third stub that
lies to its caller, in the same file, and the issue did not know it was dead.

Also removed with the handler: `SearchResult`, `NfInstanceInfo` and `SbiXactContext`, which only fed it.

### Not re-litigated

The evidence that ruled out "wire it per TS 29.521 / TS 29.510" is copied into the removal note at the
site, so a fourth pass cannot reopen it: `bsfd`'s `nnrf-nfm` obligations are already complete (profile PUT,
heartbeat worker in `lib.rs`, DELETE on close); TS 23.501 §6.2.19 and TS 29.521 define the BSF as a
**producer** of binding management with no originated service request for that role; and the giveaway is
that the handler hardcoded `GET /nbsf-management/v1/pcf-bindings` — it would have had the BSF query **its
own service** on another NF, which is a copy-paste artefact of the C port rather than a defined procedure.

### What was kept, and why

`handle_nf_status_notify` stays. It has no non-test caller either — `bsf_sm.rs:176` mentions the C original
in a comment but does not call it — but it is an *inbound* status-notify observer, not an outbound client
that could not work. Withdrawing an inbound hook is a different decision from deleting a discovery path
TS 29.521 does not give the BSF, and #234 scopes itself to the latter. Recorded in the module doc so it is
not mistaken for live code.

`bsf_sm.rs:343` carried a comment pointing at `bsf_nnrf_handle_nf_discover`. Left dangling it would be a
reference to a deleted symbol, so it now says why the branch has nothing to dispatch to.

`pcfd`'s `tests/strict_peer_bsfd.rs` is the only external consumer of `bsfd`'s public API and uses only
`bsf_sbi_request_handler` and `test_support::init_context` — checked before deleting anything re-exported by
`pub use sbi_path::*`.

## #233: `nwdafd`'s `DataSource` registry

The struct, `add_data_source`, `get_data_sources`, `data_source_count` and the `data_sources` map formed an
inventory API structurally incapable of holding anything.

**Two corrections, both in the direction of more-dead-than-reported:**

1. #233 says the grep hits are "its definitions and its own tests". There were **no tests** — the five
   definitions were the only references in the crate. That is why the deletion needed no test changes, and
   why `cargo check --all-targets` staying green is itself the proof that nothing referenced them.
2. `get_data_sources` ended in `.expect("value expected")` where every sibling reader uses `unwrap_or`. A
   poisoned lock would therefore have **panicked** the NWDAF — on a read of a map that was always empty.

### The pre-check the issue asked for, answered

> Check first whether any `docs-book` page or `build_nf_profile` claims a data-source inventory this was
> meant to feed.

Clean. `build_nf_profile` never mentions data sources. The two `docs-book` pages that say "data source"
(`concepts/ai-stack.md:63`, `configuration/nwdaf.md:73`) describe the **G2-1 NRF collector** — "the only
data source is the NRF's view of NF load" — which is `nrf_collector.rs` and is untouched here. So no page
is left claiming an inventory the code no longer offers, and the alternative the issue names (wire a
producer) remains a feature needing its own issue rather than a silent expansion of this one.

## Verification

Workspace: **5934 passed / 0 failed** over two consecutive runs, against a `main` baseline of **5938 / 0**.
The difference is exactly the four deleted `bsfd` tests — `test_sbi_request` and `test_sbi_send_response`
in `sbi_path.rs`, plus `test_search_result_empty` and `test_search_result_with_instances` in
`nnrf_handler.rs`, the two the issue names as the discovery stub's only callers. Each tested a symbol this
removes. `nwdafd` had no test to delete. `cargo clippy --workspace` and `cargo fmt --all -- --check` clean.

**On revert-verification.** As with #236, this adds no behaviour, so there is no guard to make fail;
inventing one would be the decorative-test failure mode this project records. The compiler is the check
that matters here — every "X had no caller" claim is falsified at build time if it is wrong — and
`cargo check -p nextgcore-bsfd --all-targets`, `cargo check -p nextgcore-nwdafd --all-targets` and the
whole-workspace build are that check. For `nwdafd` specifically it is unusually strong: had the issue been
right that tests exercised the registry, the build would have failed.

## Ceilings

* **`handle_nf_status_notify` in `bsfd` remains uncalled** (see above). It is now documented as a latent
  hook rather than left to read as live code, but it is still ~20 lines with no producer.
* **Nothing was added**, so there is no new behaviour to test and no test added. The claim being made is
  "the removed code could not run", and that is established by reference-counting plus the build, not by a
  test.
