//! Releasing a restarted PCEF's Gx sessions (#365, RFC 6733 §8.16, TS 23.007, TS 29.212).
//!
//! #287 landed the **detection**: `nextgcore_diameter::restart` compares a peer's
//! `Origin-State-Id` across connections and reports `Restarted` from the CER/CEA path.
//! It deliberately stopped short of any teardown, and recorded per NF why. Two of the
//! three were settled for good — hssd has nothing to discard, and mmed's S6a state is
//! request-scoped — leaving pcrfd as the one that was genuinely unfinished.
//!
//! # What a restarted PCEF means for the PCRF
//!
//! The PCEF has lost its Gx sessions. TS 29.212's model has it re-establish with a fresh
//! CCR-I, so the PCRF's copies of the old ones are dead weight: they hold PCC rules, a
//! bound UE IP, and — after #57 — *persisted* state for sessions no peer will ever
//! reference again. Releasing them is the conformant tidy-up.
//!
//! # Persistence (#57) is not in conflict with this
//!
//! #57 chose persistence over restart signalling for this state, and that decision is not
//! overturned. The two answer different questions: persistence survives **our** restart,
//! this cleans up after **theirs**. A Gx session reloaded from the snapshot is exactly the
//! kind of record that should be released when its PCEF comes back with a new
//! `Origin-State-Id` — the snapshot is what makes the stale copy outlive the process that
//! made it.
//!
//! # Only `Restarted`, and why the other four are not "close enough"
//!
//! [`PeerRestartOutcome`] has five variants and exactly one licenses a teardown:
//!
//! - `NotAdvertised` — the peer does not implement §8.16. It has not restarted; nothing is
//!   known either way.
//! - `FirstSighting` — a baseline. Acting here would release on every peer's first
//!   connection, which is every session at startup.
//! - `Unchanged` — it demonstrably has not restarted.
//! - `Regressed` — §8.16 requires the value to increase, so a decrease is evidence the
//!   signal **cannot be trusted**. It is the one change that must not trigger a reaction.
//! - `Restarted` — the value increased. This is the case.
//!
//! The branch is `outcome.is_restart()`, which the library documents as matching exactly
//! that variant, rather than `!= Unchanged` — which would sweep in three of the four above.

use nextgcore_diameter::restart::{set_peer_restart_observer, PeerRestartOutcome};

use crate::gx_path::RxAbortTarget;

/// Serialises every test that reads or writes `PCRF_RELEASE_RESTARTED_PCEF_SESSIONS`.
///
/// Declared beside the switch it guards rather than inside `mod tests`, per this
/// project's one-lock-per-process-global rule, so a future toucher in another module
/// reaches this same static instead of declaring a second one — #276 showed a second
/// lock over shared state *hangs* the suite rather than merely flaking it.
///
/// The environment is single-valued for the whole process: unlike the Gx sessions
/// below (which tests keep apart with distinct Origin-Hosts, this crate's recorded
/// convention) there is no per-test copy of an env var, so whoever sets it last owns
/// every concurrent reader's answer. That is #368's defect class exactly.
#[cfg(test)]
pub(crate) static RELEASE_SWITCH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether a detected PCEF restart may release the Gx sessions held for it.
///
/// A runtime switch rather than a cargo feature, matching this project's convention so CI
/// compiles and exercises the path in both states.
///
/// Defaults **OFF**, and unlike `PCRF_ASR_ON_RULE_FAILURE` next door — which defaults ON
/// — the reason is specific: this **drops traffic on a false positive**. The trigger is a
/// single peer-supplied integer comparison, and if it fires wrongly the PCRF tears down
/// the policy state of live sessions and aborts their AF sessions. That is the same
/// hazard class that made #56 default its subscriber-change watcher off, and the recorded
/// house rule is explicit: a runtime switch defaulting ON *except where the behaviour
/// drops traffic*. This drops traffic.
///
/// #287's detection is always on because it destroys nothing. This is the opposite.
///
/// Set `PCRF_RELEASE_RESTARTED_PCEF_SESSIONS=1` (or `true`/`yes`/`on`) to enable.
pub fn release_on_peer_restart_enabled() -> bool {
    matches!(
        std::env::var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Install pcrfd's reaction to a detected peer restart. Called once at startup.
pub fn install() {
    if set_peer_restart_observer(on_peer_restart) {
        if release_on_peer_restart_enabled() {
            log::info!(
                "PCEF restart handling: a detected restart will RELEASE the Gx sessions held \
                 for that peer and abort their bound Rx sessions \
                 (PCRF_RELEASE_RESTARTED_PCEF_SESSIONS is on)"
            );
        } else {
            log::info!(
                "PCEF restart handling: detection only. A detected restart will NAME the Gx \
                 sessions it would release and release nothing \
                 (PCRF_RELEASE_RESTARTED_PCEF_SESSIONS is off)"
            );
        }
    }
}

/// React to one observed outcome from a Diameter peer's capabilities exchange.
///
/// Runs on the peer's own task, so it must not block for long: the synchronous part is one
/// walk of the Gx session index plus the local removals, and the ASRs — which cross the
/// network — are spawned.
pub(crate) fn on_peer_restart(origin_host: &str, outcome: PeerRestartOutcome) {
    let PeerRestartOutcome::Restarted { previous, current } = outcome else {
        // Every other outcome is either "has not restarted" or "the signal is not
        // trustworthy". The library logs all five; there is nothing for pcrfd to add.
        return;
    };

    // A READ guard on the outer lock: every mutation below goes through `PcrfContext`'s own
    // per-field locks, which is this crate's established shape (see `gx_path::handle_ccr`).
    // Read through the poison rather than bailing -- pcrfd's recorded one-poison-semantics
    // decision, and here bailing would leave the stale sessions in place *silently*, which
    // is the outcome this whole path exists to prevent.
    let ctx = crate::context::pcrf_self();
    let context = ctx.read().unwrap_or_else(|e| e.into_inner());
    let held = context.gx_sessions_for_peer(origin_host);

    if held.is_empty() {
        log::info!(
            "PCEF {origin_host} restarted (Origin-State-Id {previous} -> {current}) and this \
             PCRF holds no Gx session for it; nothing to release"
        );
        return;
    }

    let sids: Vec<&str> = held.iter().map(|(sid, _)| sid.as_str()).collect();

    if !release_on_peer_restart_enabled() {
        // A signal nobody reads is worse than none, so the disabled path names the
        // sessions rather than saying a release was skipped. An operator deciding whether
        // to turn the switch on needs to see what it would have done.
        log::warn!(
            "PCEF {origin_host} restarted (Origin-State-Id {previous} -> {current}) and this \
             PCRF still holds {} Gx session(s) it will never hear about again: {sids:?}. NOT \
             released: PCRF_RELEASE_RESTARTED_PCEF_SESSIONS is off. Their PCC rules, bound UE \
             IPs and persisted records stay until the PCEF's own CCR-I replaces them",
            held.len()
        );
        return;
    }

    log::warn!(
        "PCEF {origin_host} restarted (Origin-State-Id {previous} -> {current}); releasing the \
         {} Gx session(s) held for it: {sids:?} (TS 29.212, TS 23.007)",
        held.len()
    );

    // Criterion 5: an Rx session bound to a released Gx session needs an answer. The
    // bearer its service was authorised over is gone, so the AF is told with an ASR
    // carrying Abort-Cause BEARER_RELEASED -- the same answer, through the same helper,
    // that a CCR-T already produces for the same reason. Sending nothing would leave the
    // AF believing an unenforceable service is live, which is #57's own argument for the
    // rule-report ASR one function away.
    //
    // NOTE the peer_host asymmetry #365 flags: `PcrfRxSession::peer_host` is the
    // **P-CSCF's** host, not the PCEF's. It is the ASR's destination, and is emphatically
    // not the key this release is keyed on -- that is `PcrfGxSession::peer_host`.
    let mut aborts: Vec<RxAbortTarget> = Vec::new();
    for (sid, rx_indexes) in &held {
        // Scoped per Gx session: a single accumulating vector would re-remove the previous
        // session's Rx bindings on every later iteration.
        let mut bound: Vec<RxAbortTarget> = Vec::new();
        for rx_idx in rx_indexes {
            if let Some(rx) = context.rx_session_find_by_idx(*rx_idx) {
                bound.push(RxAbortTarget {
                    rx_sid: rx.sid.clone(),
                    peer_host: rx.peer_host.clone(),
                    // `None`, deliberately. `PcrfRxSession` stores no AF realm, and the
                    // CCR-driven abort paths fill this from the CCR's `Origin-Realm` --
                    // which they can, because the request that triggered them came from the
                    // peer being reported on. There is no such request here, and the realm
                    // that IS to hand is the restarted PCEF's, which would be actively
                    // wrong: the ASR is addressed to the AF. `pcrf_rx_send_asr_for_target`
                    // falls back to our own realm, which is at least true of the sender.
                    peer_realm: None,
                });
            }
        }
        // Remove the Rx bindings and then the Gx session itself, in that order, so a
        // session is never reachable with dangling bindings.
        for target in &bound {
            context.rx_session_remove(&target.rx_sid);
        }
        context.gx_session_remove(sid);
        aborts.extend(bound);
    }

    if aborts.is_empty() {
        return;
    }
    let local = crate::fd_path::pcrf_local_identity();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                for target in &aborts {
                    crate::rx_path::pcrf_rx_send_asr_for_target(target, &local).await;
                }
            });
        }
        Err(_) => log::warn!(
            "PCEF {origin_host} restart: {} bound Rx session(s) were released locally but no \
             async runtime is available to send their ASRs, so their AFs are NOT told",
            aborts.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::pcrf_self;

    /// Seed a Gx session owned by `peer` with `rx_hosts` Rx sessions bound to it, and
    /// return `(gx_idx, rx_sids)`.
    ///
    /// Every test uses Origin-Hosts and Session-Ids unique to it, which is how this crate
    /// keeps the process-global `pcrf_self()` context from making one test's state
    /// another's. That is enough for the sessions; it is NOT enough for the env switch,
    /// which is why [`RELEASE_SWITCH_TEST_LOCK`] exists.
    fn seed(gx_sid: &str, peer: &str, rx_sids: &[&str]) -> usize {
        let ctx = pcrf_self();
        let context = ctx.read().unwrap_or_else(|e| e.into_inner());
        let gx_idx = context.gx_session_add(gx_sid).expect("seed the Gx session");
        context.gx_session_update(gx_sid, |s| s.set_peer_host(peer));
        for rx_sid in rx_sids {
            let rx_idx = context
                .rx_session_add(rx_sid, gx_idx)
                .expect("seed the Rx session");
            context.rx_session_update(rx_sid, |r| {
                r.peer_host = Some(format!("af-for-{rx_sid}.example.com"))
            });
            context.gx_session_update(gx_sid, |s| s.rx_sessions.push(rx_idx));
        }
        gx_idx
    }

    fn gx_alive(sid: &str) -> bool {
        let ctx = pcrf_self();
        let context = ctx.read().unwrap_or_else(|e| e.into_inner());
        context.gx_session_find_by_sid(sid).is_some()
    }

    /// Set the switch for the duration of a test and restore it, so a sibling that reads
    /// it never sees this test's value.
    struct Switch(Option<String>);
    impl Switch {
        fn on() -> Self {
            Self::set("1")
        }
        fn off() -> Self {
            Self::set("0")
        }
        fn set(value: &str) -> Self {
            let previous = std::env::var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS").ok();
            std::env::set_var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS", value);
            Self(previous)
        }
    }
    impl Drop for Switch {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS", v),
                None => std::env::remove_var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS"),
            }
        }
    }

    /// #365 criterion 2: a restart releases the sessions of the peer that restarted, and
    /// **only** those.
    ///
    /// The two-PCEF shape is the point. A single-peer test passes identically against a
    /// release that ignores `Origin-Host` altogether and drops every Gx session in the
    /// context — which is the worst available bug here, and the one a derived lookup with
    /// a wrong predicate would produce.
    #[test]
    fn a_restart_releases_only_the_restarted_peers_sessions() {
        let _guard = RELEASE_SWITCH_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _switch = Switch::on();

        seed("gx-365-a1", "pgw-365-a.example.com", &["rx-365-a1"]);
        seed("gx-365-a2", "pgw-365-a.example.com", &[]);
        seed("gx-365-b1", "pgw-365-b.example.com", &["rx-365-b1"]);

        on_peer_restart(
            "pgw-365-a.example.com",
            PeerRestartOutcome::Restarted {
                previous: 1,
                current: 2,
            },
        );

        assert!(
            !gx_alive("gx-365-a1"),
            "the restarted PCEF's session must be released"
        );
        assert!(
            !gx_alive("gx-365-a2"),
            "ALL of the restarted PCEF's sessions must be released, not just the first"
        );
        assert!(
            gx_alive("gx-365-b1"),
            "another PCEF's session must SURVIVE: this is what a single-peer test cannot \
             distinguish from releasing everything"
        );

        let ctx = pcrf_self();
        let context = ctx.read().unwrap_or_else(|e| e.into_inner());
        assert!(
            context.rx_session_find_by_sid("rx-365-a1").is_none(),
            "an Rx session bound to a released Gx session is released with it"
        );
        assert!(
            context.rx_session_find_by_sid("rx-365-b1").is_some(),
            "the surviving Gx session's Rx binding must survive too"
        );
    }

    /// #365 criterion 2, the other half: `Restarted` is the ONLY variant that releases.
    ///
    /// Written as a loop over the four rejected variants rather than one test each,
    /// because the failure mode being guarded is a branch written as `!= Unchanged` — and
    /// that mistake passes a test that only checks `Unchanged`.
    #[test]
    fn no_other_outcome_releases_anything() {
        let _guard = RELEASE_SWITCH_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _switch = Switch::on();

        let host = "pgw-365-variants.example.com";
        for (i, outcome) in [
            PeerRestartOutcome::NotAdvertised,
            PeerRestartOutcome::FirstSighting { current: 7 },
            PeerRestartOutcome::Unchanged { current: 7 },
            // The important one: §8.16 requires the value to INCREASE, so a decrease means
            // the signal cannot be trusted. Releasing here would let a peer with a broken
            // clock tear down live sessions.
            PeerRestartOutcome::Regressed {
                previous: 9,
                current: 4,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let sid = format!("gx-365-variant-{i}");
            seed(&sid, host, &[]);
            on_peer_restart(host, outcome);
            assert!(
                gx_alive(&sid),
                "{outcome:?} is not a restart and must release nothing"
            );
        }
    }

    /// #365 criterion 3: with the switch OFF nothing is released.
    ///
    /// The log naming what *would* have been released is asserted by reading
    /// `on_peer_restart`, not here: capturing `log` output needs a process-global
    /// subscriber, and installing one from a test is the shared-state hazard #368 was
    /// filed for. What is mechanically checkable — and what an operator actually depends
    /// on — is that the sessions are still there.
    #[test]
    fn the_switch_defaults_off_and_off_releases_nothing() {
        let _guard = RELEASE_SWITCH_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // The default, asserted with the variable ABSENT rather than set to "0": those are
        // different states, and only the absent one is what a deployment that never heard
        // of this switch actually has.
        {
            let previous = std::env::var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS").ok();
            std::env::remove_var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS");
            assert!(
                !release_on_peer_restart_enabled(),
                "an unset switch must mean OFF: this behaviour drops traffic on a false \
                 positive, so it cannot be opt-out"
            );
            if let Some(v) = previous {
                std::env::set_var("PCRF_RELEASE_RESTARTED_PCEF_SESSIONS", v);
            }
        }

        let _switch = Switch::off();
        let host = "pgw-365-off.example.com";
        seed("gx-365-off1", host, &["rx-365-off1"]);

        on_peer_restart(
            host,
            PeerRestartOutcome::Restarted {
                previous: 3,
                current: 4,
            },
        );

        assert!(
            gx_alive("gx-365-off1"),
            "with the switch off the stale session STAYS: the log says what would have gone"
        );
        let ctx = pcrf_self();
        let context = ctx.read().unwrap_or_else(|e| e.into_inner());
        assert!(
            context.rx_session_find_by_sid("rx-365-off1").is_some(),
            "and its Rx binding stays with it"
        );
    }

    /// The switch accepts the same spellings as its siblings, and nothing else.
    #[test]
    fn the_switch_accepts_the_conventional_spellings() {
        let _guard = RELEASE_SWITCH_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for on in ["1", "true", "TRUE", "yes", "on", " on "] {
            let _switch = Switch::set(on);
            assert!(release_on_peer_restart_enabled(), "{on:?} must enable");
        }
        for off in ["0", "false", "no", "off", "", "maybe"] {
            let _switch = Switch::set(off);
            assert!(
                !release_on_peer_restart_enabled(),
                "{off:?} must NOT enable: anything unrecognised has to fail closed for a \
                 switch that drops traffic"
            );
        }
    }

    /// The derived lookup answers by `Origin-Host` and skips already-released sessions.
    ///
    /// `gx_session_remove` leaves the positional `gx_sessions` element in place (the Rx
    /// bindings index into that vector), so a lookup that walked the vector instead of the
    /// index would hand back sessions released long ago — and the release path would then
    /// "release" them again on every subsequent restart.
    #[test]
    fn the_lookup_walks_the_index_not_the_session_vector() {
        let host = "pgw-365-lookup.example.com";
        seed("gx-365-look1", host, &[]);
        seed("gx-365-look2", host, &[]);
        let ctx = pcrf_self();
        let context = ctx.read().unwrap_or_else(|e| e.into_inner());

        let held = context.gx_sessions_for_peer(host);
        assert_eq!(
            held.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
            vec!["gx-365-look1", "gx-365-look2"],
            "both are held, and the order is sorted rather than HashMap order"
        );

        context.gx_session_remove("gx-365-look1");
        let held = context.gx_sessions_for_peer(host);
        assert_eq!(
            held.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
            vec!["gx-365-look2"],
            "a released session must not come back: it is still in the positional vector"
        );

        assert!(
            context
                .gx_sessions_for_peer("pgw-365-nobody.example.com")
                .is_empty(),
            "a peer we hold nothing for yields nothing"
        );
    }
}
