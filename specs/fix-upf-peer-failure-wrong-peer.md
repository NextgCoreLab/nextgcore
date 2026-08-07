# Fix: UPF peer-failure teardown ignores which peer failed

## Problem

`PfcpServer::declare_peer_failure` (`bins/nextgcore-upfd/src/pfcp_path.rs:574`)
takes a `peer: SocketAddr` but uses it only for the log line. It then
unconditionally drops the single stored association and clears **every**
session:

```rust
async fn declare_peer_failure(&self, peer: SocketAddr, reason: &str) {
    log::warn!("PFCP peer {peer} failure ({reason}): clearing association and sessions");
    *self.association.write().await = None;   // <-- no check of `peer`
    ...
}
```

Both call sites can fire for a peer that does **not** hold the current
association:

- `handle_association_release_request` (line 857) — any host may send an
  Association Release Request; it is acknowledged with `RequestAccepted`
  and then tears down whoever *is* associated.
- `check_peer_recovery` (line 723) — compares an incoming Recovery Time
  Stamp against the stored association without first confirming the
  sender owns it, so a heartbeat from a different address whose RTS
  happens to differ declares failure for the real peer.

### Observed failure

Reproduced on Kind and again on EKS devtest1 during this session. A
rolling `kubectl rollout restart deployment/smf` briefly runs two SMF
pods. The new pod associates; the old pod then sends its Association
Release on shutdown; the UPF wipes the **new** pod's association. Every
subsequent Session Establishment is rejected:

```
PFCP Association established with 10.244.0.60:8805 (peer RTS=...)
PFCP peer 10.244.0.52:8805 failure (association released by peer): clearing association and sessions
Session Establishment from 10.244.0.60:8805 without PFCP association
```

The SMF surfaces this as `cause 72 (No Established PFCP Association)`,
which fails PDU session establishment and black-holes the user plane.
The only workaround was scaling the SMF to 0, restarting the UPF, then
scaling back to 1 — done manually for both E2E runs.

This also means any multi-SMF deployment is broken: one SMF's shutdown
drops every other SMF's sessions.

## Fix

Make the teardown peer-aware. `declare_peer_failure` returns early
unless the failing peer is the one currently associated:

- Compare `peer` against `association.peer_addr` under the read lock.
- If it does not match, log at `warn` and return without touching the
  association, the session table, or emitting `PeerFailure`.
- If there is no association at all, likewise return without clearing.

`check_peer_recovery` additionally gates its RTS comparison on the
sender being the associated peer, so a stray datagram cannot trigger the
path at all.

Non-goal: making the UPF support multiple concurrent associations. The
field stays `Option<PfcpAssociation>`. This change only stops a
non-owning peer from tearing down the owner's state; issue #66 tracks
durable multi-peer state.

TS 29.244 §6.2.6 scopes an association to the CP/UP function pair, and
§7.4.4.2 scopes Association Release to the requesting peer's own
association. TS 23.527 §4.2 scopes stale-session cleanup to the failed
peer's sessions. Clearing another peer's state is non-conformant on all
three counts.

## Verification

Two new tests in `pfcp_path.rs`, each verified to FAIL when the fix is
reverted:

1. `test_association_release_from_other_peer_is_ignored` — peer A
   associates, peer B sends an Association Release. Assert A's
   association survives, no `PeerFailure` event is emitted, and B still
   receives its `ASSOCIATION_RELEASE_RESPONSE`.
2. `test_recovery_timestamp_change_from_other_peer_is_ignored` — peer A
   associates with RTS=100, peer B heartbeats with RTS=200. Assert A's
   association survives and no `PeerFailure` is emitted.

Existing `test_heartbeat_rts_change_drops_association` and
`test_association_release_clears_state` must still pass: the owning
peer's failure path is unchanged.

Full-workspace `cargo test --release --workspace`, `cargo fmt --check`,
and `cargo clippy` must be clean.

Result: 5290 passed / 0 failed (up from 5288 — the two new tests), fmt
clean, clippy clean. Two pre-existing clippy warnings unrelated to this
change were also fixed under "own the whole branch": an unused
`OsStrExt` import in `nextgcore-tun/src/linux.rs` and an
`io::Error::new(ErrorKind::Other, ...)` in `upfd/src/data_plane.rs`.
Both were confirmed present on clean `HEAD` first.

Verified live on Kind with the rebuilt UPF image: a rolling
`kubectl rollout restart deployment/smf` — which previously produced
cause 72 every time — now logs

```
ignoring PFCP peer failure from 10.244.0.82:8805 (association released
by peer): the association belongs to 10.244.0.90:8805 -- not clearing it
```

and the E2E stays at 74 passed / 0 failed / 6 skipped with 0% packet
loss to 8.8.8.8.

The base-manifest, deploy.sh and Helm changes made in the same session are
separate concerns and ship separately; see `specs/fix-k8s-base-deployment.md`
and `specs/fix-helm-chart-control-plane.md`.
