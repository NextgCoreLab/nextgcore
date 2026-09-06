# nextgcore #99 (SEPP N32-f): forward in TLS mode, terminate contexts, and fix the error shape

Verified against `main` @ `2aedbdb`. The issue's cites are from `76ea248`; all three defects
re-verified and all three still hold.

Closes #99. Three defects, five criteria — the whole issue.

## Verified against current main

| # | defect | site |
|---|---|---|
| 1 | TLS-mode N32-f **echoes** the reconstructed request back as a 200 body | `n32_server.rs:463` `.with_json_body(&rec)` |
| 2 | no `n32f-terminate` route; router falls through to 404 | `n32_server.rs:148-160` |
| 3 | `N32fErrorInfo` lists are `Vec<String>`, no `n32fContextId` | `prins.rs:624-635`, `to_error_info` at `:662` |

The PRINS path *does* forward (`forward_and_protect_response` at `:657` → `forward_to_target_nf`
at `:677`), so the SEPP-to-NF hop exists — it is only the TLS branch that never uses it.

## Decision 1: TLS mode relays the NF response verbatim; PRINS does not

The fix is not "call the PRINS helper". `forward_and_protect_response` does two things —
forward, then wrap the NF response in an `N32fReformattedRspMsg` and PRINS-protect it. In TLS
security mode that wrapping would be **wrong**: TS 33.501 §5.9.3 makes the TLS connection
itself the protection, and there is no JOSE envelope on either direction. A PRINS-shaped
response would be undeserialisable by a peer that negotiated TLS.

So the TLS branch calls `forward_to_target_nf` directly and relays the NF's real status,
headers and body. That means the two security modes share the *forwarding* step and diverge on
the *response* step, which is the asymmetry the issue's "no PRINS reformatting/envelope is
applied to the response" note is pointing at.

`forward_to_target_nf` takes a `prins::ReconstructedRequest` (a `HashMap` of headers and a
non-optional `message_id`), while the TLS branch had built a `ReconstructedRequestJson` (a
`Vec` of pairs, optional `message_id`) purely to serialise it back. The TLS branch now builds
the former; the latter is no longer constructed on this path.

## Decision 2: termination clears the N32-f context, not the peer

TS 29.573 §5.2.4 terminates an **`n32fContextId`** — not the peer relationship. The SEPP node
carries `n32f_security: Option<N32fSecurityInfo>`, which is where the context id and its keys
live, so termination is:

1. `node_find_by_n32f_context_id` to locate the node (already exists),
2. set `n32f_security = None` — this is the key deletion the issue asks for, since the keys are
   *inside* that struct,
3. reset `handshake_state` so a later N32-f message cannot ride the dead context,
4. `node_update`, and respond `200` with `N32fContextInfo`.

Deliberately **not** `node_remove`: the peer, its N32-c API root and its negotiated
capabilities are provisioning state that survives an N32-f teardown. Removing the node would
mean a re-handshake could not find its own peer config, turning a routine context termination
into a de-provisioning.

An unknown `n32fContextId` is a `404`, not a `204`: the peer asked us to terminate something
we do not have, and silently succeeding would let it believe keys were destroyed that never
existed here.

## Decision 3: the error report gains two typed objects

`N32fErrorInfo` becomes the TS 29.573 §6.1.5.4 shape:

* `failedModificationList: Vec<FailedModificationInfo>` — `{ipxId, n32fErrorType}`. The existing
  `failed_modifications: Vec<String>` already holds IPX identifiers, so each maps to an
  `ipxId` and carries the report's own `n32fErrorType`.
* `errorDetailsList: Vec<N32fErrorDetail>` — `{attribute, msgReconstructFailReason}`. The
  existing single `detail` string becomes `msgReconstructFailReason`; `attribute` is optional
  and left unset, because the current error path does not know which attribute failed and
  inventing one would be worse than omitting it.
* `n32fContextId` added, optional.

`policyMismatchList` and `riErrorInformation` are **not** added: nothing in the current error
path can populate them, and an always-absent optional field is honest where a fabricated one
is not.

## Verification (actual)

Five new tests (four in `n32_server`, one in `prins`). Workspace **5718 passed / 0 failed**,
`cargo test --workspace` exit 0, no compile errors (checked for `^error`, not only a
`test result:` line). fmt clean; `cargo clippy --workspace --all-targets` exit 0 with no
warning in any file touched.

**Revert-verified:** restoring the echo in the TLS branch fails
`tls_mode_does_not_echo_the_reconstructed_request`; dropping `n32f_security = None` from the
terminate handler fails `n32f_terminate_returns_context_info_and_deletes_the_keys` on
*"the N32-f context and its key material must be deleted"*.

### An existing integration test pinned the defect

`tests/n32_two_sepp.rs` asserted the **echo** — it deserialised the response as
`ReconstructedJson` and checked `rec.method == "GET"` and `rec.url ==
"/nnrf-disc/v1/nf-instances"`. So the behaviour the issue calls critical was the documented
expectation, and the suite stayed green while TLS-mode roaming traffic was never delivered.
Inverted rather than deleted, with a comment recording the flip. Criterion 2 asks for exactly
this regression test.

### My own first version of that guard was vacuous

Worth recording because I nearly shipped it. `tls_mode_does_not_echo_the_reconstructed_request`
first hand-wrote the N32-f envelope as JSON, which was **missing `protocol`** — so
`parse_n32f_message` rejected it at 400 *before* the TLS branch ran, and every assertion
(`status != 200`, body-doesn't-contain-the-url) passed for the wrong reason. Re-running the
revert exposed it: the echo could be restored and the unit test still passed.

Fixed twice over: the envelope is now built with the real sender-side
`build_n32f_tls_message`, and the assertion is **positive** — the body must contain
`"target NF apiRoot could not be resolved"`, a string only reachable from inside
`forward_to_target_nf`. Asserting the forward was *attempted* is what makes the test
non-vacuous; asserting only that the echo is absent is not.

**Not verified:** no real peer SEPP or target NF was involved. The forwarding is asserted
through `forward_to_target_nf`'s own unresolved-target path, not against a live NF, and the
error shape is asserted against the yaml's field names rather than a conformant peer's parser.
CI skips Docker E2E. The `n32_two_sepp` integration test does run two real seppd processes, but
neither has a reachable target NF.

## Definition of done

- [x] TLS mode forwards and relays the NF's real response; no echo
- [x] `n32f-terminate` routed, returns `N32fContextInfo`, deletes context + keys
- [x] A terminated context is unusable afterwards
- [x] `N32fErrorInfo` matches TS 29.573 §6.1.5.4
- [x] `cargo test -p nextgcore-seppd` and workspace clippy clean
- [x] **#99 closes**

## Follow-up

The issue names a companion, still to be filed: sender-PLMN authorisation is enforced only
when `peer_plmn_ids` is non-empty (`prins.rs`), and RI `ModificationPolicy` is not populated
from exchange-params (`sbi_path.rs::build_prins_context`). Explicitly out of scope here per the
issue's own "Out of scope / companion issue" note.
