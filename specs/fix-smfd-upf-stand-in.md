# nextgcore #289 (smfd tests): a UPF stand-in, so the post-N4 tail is reachable

Verified against `main` @ `02c39dc`.

#289 is test infrastructure with one production decision inside it, filed by #276's revert pass
after that pass found a call site which had been absent for a month while looking wired.

## Verified against current main

| claim in the issue | site on `02c39dc` | still true? |
|---|---|---|
| `handle_sm_context_create` cannot pass its N4 leg in any test | `main.rs:1709` `select_upf()` → `None`, `main.rs:1714` `is_associated()` | yes |
| everything after the PFCP block is dead to the suite | `main.rs:3093-3223` (EASDF leg, session fill-in, `PolicyBinding` insert) | yes |
| `a_failed_establishment_creates_no_easdf_dns_context` says so in its own doc comment | `main.rs:6298` | yes |
| `a_failed_create_leaves_no_registered_sm_context` predicts this issue | `main.rs:6980` | yes |
| `PFCP_CLIENT` is a `OnceLock`, so an installed client is permanent | `pfcp_path.rs:270` | yes |
| `teardown_association` → `clear_pfcp_sessions` clears a process-global map | `pfcp_path.rs:698`, `:821` | yes |
| `SESSION_MAP_LOCK` guards that map from inside `mod tests` | `pfcp_path.rs:909` | yes |
| removing the `easdf::create_dns_context` call leaves the suite green | re-checked by reverting it | yes — **425 → 456 tests later, still green before this change** |
| the `PolicyBinding` insert is at `main.rs:2998` | it is at **`main.rs:3194`** | numbering only; the site is there |

## Decision 1: `PFCP_CLIENT` becomes settable, and install-and-release happens per test

The issue names this decision and recommends the opposite of what landed:

> Decide deliberately: does the harness **install** the global client (permanent, …), or is
> `PFCP_CLIENT` changed from `OnceLock` to something settable per test? … Installing-and-releasing
> is the smaller change and probably right; say which and why.

Installing permanently was implemented first and **does not work**, for a reason the issue could
not have known from reading the code: a `PfcpClient` owns a `tokio::net::UdpSocket`, and a tokio
socket belongs to the runtime that created it. `#[tokio::test]` gives every test its own runtime, so
a client installed by whichever test touched the harness first is a client whose socket is dead for
every test after it. The failure is not subtle once seen:

```
the stand-in UPF must accept the association:
  Local("send failed: A Tokio 1.x context was found, but it is being shutdown.")
```

So `PFCP_CLIENT` and `PFCP_POOL` are now `std::sync::RwLock`s rather than `OnceLock`s, each test
installs its own stand-in, and the stand-in **un-installs itself on drop** — install-and-release, at
per-test rather than per-process granularity. `clear_global_upf_for_test` is `#[cfg(test)]`: a
running SMF has no reason to un-install its own N4 endpoint, and doing so mid-session would strand
the `SESSION_PEERS` bindings.

What changes for the running daemon: `set_global_client` overwrites instead of being first-wins.
`main` calls it exactly once, through `set_global_pool` at startup (`main.rs:660`, the only external
caller), so today's behaviour is identical. `global_pool()` returns an owned `Vec` instead of a
`&'static [_]` because a lock guard must not be held across the `await`s its callers perform; the
cost is one `Vec<Arc<_>>` clone per session establishment.

This is a production change made for a test reason, which is exactly why the issue asked for it to
be stated rather than done quietly. The alternative — leaving production alone and accepting that
the whole post-N4 tail stays unverifiable — is what the last three issues in this area already paid
for once each.

## Decision 2: one lock, and it lives beside the globals rather than in `mod tests`

`SESSION_MAP_LOCK` is replaced by `pfcp_path::N4_TEST_LOCK`, declared at module level next to the
statics it protects and `pub(crate)` so `main.rs`'s tests take the *same* lock rather than declaring
a second one. Three variables are involved and they cannot be guarded separately: the two globals,
the context's `pfcp_sessions` map that `clear_pfcp_sessions` empties process-wide, and the
association state of the one installed client. The stand-in holds the guard as a field, so a test
gets serialisation and a UPF from one binding and cannot accidentally take one without the other.

A second lock over the same variables is the mistake #276 made with the EASDF context lock, where
the symptom was a **hang** rather than a flaky assertion. The lock order is written into the doc
comment — any module switch lock first, `N4_TEST_LOCK` second — because the two tests that hold
`easdf::SWITCH_LOCK` and this lock together would deadlock against each other if any future call
site reversed it.

## Decision 3: the stand-in hand-encodes its Session Establishment Response

The Association Setup / Heartbeat / Association Release replies use the `nextgcore-pfcp` library
codec (as `pfcp_path`'s existing fake UPF already did). The **Session Establishment Response** is
hand-encoded instead, because the SMF's own establishment parser is what the success path is being
trusted to run: it reads F-SEID with V4 on bit 2 (TS 29.244 §8.2.37) and F-TEID with V4 on bit 1
(§8.2.3), an asymmetry the production parser calls out in a comment and a stand-in sharing an
encoder with it could not catch. The stand-in also answers Session Modification and Session
Deletion, so the update and release paths become reachable for later work (#291, #293).

## Decision 4: the failure-path tests keep their halves, and now fail for the real reason

Both converted tests previously reached `504 UPF_NOT_RESPONDING` because **no UPF existed at all**.
They now use a stand-in whose association is deliberately down, so they exercise the real failure
mode — TS 29.244 §6.2.6.2, no session signalling without an association, which is the first thing
`pfcp_session_establish` checks. Their assertions are unchanged in substance: a create that answers
an error creates no EASDF DNS context and leaves no registered SM context behind.

## Acceptance criteria

- [x] A test drives `handle_sm_context_create` to a `201` against a stand-in UPF —
      `a_successful_create_registers_an_activated_session_and_its_binding` and
      `an_established_session_creates_its_easdf_dns_context`.
- [x] Removing the `easdf::create_dns_context` call makes a NAMED test fail (today: nothing fails).
- [x] Removing the `PolicyBinding` insert makes a named test fail.
- [x] The success path asserts `upCnxState == ACTIVATED` and the stored session AMBR.
- [x] Exactly ONE lock guards `PFCP_CLIENT` + `pfcp_sessions` across `pfcp_path` and `main.rs`
      tests; its doc comment names the variables it is the one agreement about.
- [x] The two tests quoted in the issue are converted per their own instructions, keeping their
      failure-path halves.
- [x] The whole-workspace suite is green over repeated runs (≥5).

## Verification

Workspace **6272 passed / 0 failed** (baseline 6270 on `02c39dc`; +2, the two new create tests —
`nextgcore-smfd` 454 → 456), and `cargo test -p nextgcore-easdfd --features dns-udp` unchanged at
**51 passed / 0 failed**. `cargo clippy -p nextgcore-smfd --all-targets` clean, no new warning in
the workspace lint; `cargo fmt --all` applied.

**Five consecutive whole-workspace runs, all 6272 / 0** — the change touches process-global state,
so a single green run is not evidence about it. The count is identical across runs, which is the
part that matters: a per-test install that leaked would show up as a different number, not as a
failure, in whichever crate ran next.

| revert | expected to break | result |
|---|---|---|
| `easdf::create_dns_context` call removed (i.e. #114's state restored) | `an_established_session_creates_its_easdf_dns_context` | **1 failed** |
| the `PolicyBinding` insert made unreachable | `a_successful_create_registers_an_activated_session_and_its_binding` | **1 failed** |
| the session fill-in of `up_cnx_state` + `session_ambr` removed | same test | **1 failed** (`left: Deactivated`) |

The first row is the whole point of the issue: **that exact revert left all 425 tests green on
`main`**, and it is the row #276's spec had to record as a ceiling rather than as a result.

Each revert was run against the whole crate suite rather than a name filter: "the revert did not
bite" and "my filter did not select the guard" produce identical output, and #117 already lost a
finding that way.

## Ceilings

- **The third inspection-only call site named in #289 is now guarded, but only for the values this
  harness sets.** `upCnxState` and the session AMBR are asserted; the rest of the fill-in (`pti`,
  `ue_ssc_mode`, the S-NSSAI, `establishment_accept_sent`) is written by the same block and is
  therefore *reachable*, not *asserted*. A future test that needs one of them no longer needs a
  harness first.
- **The stand-in answers; it does not enforce.** It returns a fixed F-SEID/F-TEID and accepts every
  request. It cannot catch a malformed Create PDR, because it never decodes the PDRs it is sent —
  `n4_build`'s own tests cover the encoding. A stand-in that validated the request would be a second
  PFCP implementation to keep in step with TS 29.244.
- **`request_ebi` and the UDM legs stay off in these tests**, so #291's and #293's wire assertions
  are not covered here — they are those issues' work, and the harness they need now exists.
- **One consumer of the tail is still unreachable**: `handle_sm_context_update`'s
  `pfcp_session_modify` path needs a session established *and* an N2 setup response, which this
  spec does not build. The stand-in answers Session Modification already, so that is a test away
  rather than a harness away.
