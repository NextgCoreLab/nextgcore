//! Peer-restart detection from `Origin-State-Id` (RFC 6733 §8.16, TS 23.007).
//!
//! # What §8.16 actually specifies, and what it does not
//!
//! `Origin-State-Id` is monotonically increasing, set once per process lifetime, and
//! exchanged in the capabilities exchange. Its whole purpose is that **a peer detects a
//! restart by seeing the value change**. `peer::origin_state_id` implements the sending
//! half; #280 made it conformant and stable, and #287's enumeration of the receiving half
//! came back **empty** — every reference to the AVP in this tree was a send site or a test.
//!
//! So this stack advertised a correct restart signal that no in-tree peer would notice
//! changing. This module is the receiving half.
//!
//! §8.16 defines the **signal**. It does not define the **reaction**: what a node discards
//! when a peer restarts is per-interface, and belongs to TS 23.007. That split is why this
//! module reports and never destroys — see "What no NF does" below.
//!
//! # Why the state lives here and not on `DiameterPeer`
//!
//! A [`crate::peer::DiameterPeer`] is per-**connection**. A restart drops the transport, so
//! the CER/CEA that carries the new value arrives on a *fresh* peer object with nothing to
//! compare against. The comparison is therefore keyed by `Origin-Host` and outlives any one
//! connection, which is what this module holds.
//!
//! # Which messages are acted on: CER and CEA only
//!
//! This answers #287's question 4 ("is the detection allowed to act on a single observation,
//! or must it be corroborated?"). The capabilities exchange is where §8.16 conveys the
//! value, and a *new* CER/CEA is itself evidence that the connection was re-established —
//! the two observations corroborate each other, so one CER is enough.
//!
//! A changed value on a **DWA** over a surviving connection is a different thing: the peer
//! cannot have restarted while this connection lived, so the change is a protocol anomaly (a
//! misconfigured peer, or a message that is not from whom it claims). Those are logged and
//! **not** treated as restarts. Acting on them would let a single malformed watchdog answer
//! trigger whatever reaction is wired downstream.
//!
//! # What no NF does with this, and why that is a decision rather than an omission
//!
//! Detection is always on: it is non-destructive, so the house rule about defaulting a
//! traffic-affecting behaviour OFF does not apply to it. **Nothing in this tree tears
//! subscriber or session state down on a detected restart**, and per NF the reason differs:
//!
//! - **hssd** — nothing to discard. A restarted MME re-registers with a fresh
//!   `Update-Location-Request` on its next attach, and that overwrites `mme_host` /
//!   `mme_realm` idempotently. The aggressive reading (purge the affected subscriber state)
//!   is detach-adjacent, which is the hazard #56 flagged when it defaulted the
//!   subscriber-change watcher OFF.
//! - **pcrfd** — a restarted PCEF has lost its Gx sessions, and releasing the PCRF's copies
//!   would be the conformant tidy-up. #57 chose **persistence over restart signalling** for
//!   this, and that decision is not overturned here. It also cannot be implemented cheaply:
//!   `PcrfContext` indexes Gx sessions by session-id and by UE IP, not by `Origin-Host`, so
//!   there is no way to ask "what do I hold for this peer" without a new index. Filed as
//!   #365 rather than half-built.
//! - **mmed** — nothing to discard. Its S6a state is request-scoped: a request in flight when
//!   the peer went away is already failed by the transport teardown, which fails every
//!   waiter in the pending map.
//!
//! What the detection *does* buy today is a distinguishable diagnosis. A peer that restarted
//! and a peer whose connection merely flapped produce the same reconnect, and until now the
//! logs could not tell them apart.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// What comparing a peer's `Origin-State-Id` against the last one seen says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRestartOutcome {
    /// The peer sent no `Origin-State-Id`. The AVP is optional, so this means the peer does
    /// not implement §8.16 — emphatically **not** that it restarted. Kept distinct from
    /// [`Self::FirstSighting`] so a peer that never advertises cannot be mistaken for one
    /// that has just come up.
    NotAdvertised,
    /// The first value ever seen from this peer. A baseline, not a restart: with nothing to
    /// compare against there is no change to detect, and treating it as a restart would fire
    /// on every peer the first time it connects.
    FirstSighting { current: u32 },
    /// Same value as last time: the peer has not restarted since it was last seen.
    Unchanged { current: u32 },
    /// The value increased. The peer restarted and lost the state it held.
    Restarted { previous: u32, current: u32 },
    /// The value DECREASED. §8.16 requires it to be monotonically increasing, so this is a
    /// protocol violation rather than a restart — a peer whose clock or storage went
    /// backwards, or a message that is not from whom it claims. Reported separately and
    /// never treated as a restart: a decrease is the one change that must not trigger a
    /// reaction, because it is evidence the value cannot be trusted.
    Regressed { previous: u32, current: u32 },
}

impl PeerRestartOutcome {
    /// Whether this outcome means the peer restarted and lost its state.
    ///
    /// Exactly one variant qualifies. Callers should branch on this rather than on
    /// `!= Unchanged`, which would sweep in [`Self::FirstSighting`] and
    /// [`Self::Regressed`].
    pub fn is_restart(self) -> bool {
        matches!(self, Self::Restarted { .. })
    }
}

/// Last `Origin-State-Id` seen per `Origin-Host`.
///
/// Process-global for the same reason [`crate::peer::origin_state_id`] is: it describes the
/// node's view of its peers across every connection this process makes, and a per-connection
/// copy could not detect anything (see the module doc).
fn seen() -> &'static Mutex<HashMap<String, u32>> {
    static SEEN: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record `origin_state_id` for `origin_host` and report what changed.
///
/// `None` means the peer sent no `Origin-State-Id`; the stored value is then left alone, so a
/// peer that advertises intermittently does not lose its baseline and does not read as
/// restarted the next time it does advertise.
///
/// Call this from the CER/CEA path only. See the module doc for why DWA is excluded.
pub fn observe_peer_restart(origin_host: &str, origin_state_id: Option<u32>) -> PeerRestartOutcome {
    let Some(current) = origin_state_id else {
        return PeerRestartOutcome::NotAdvertised;
    };

    // A poisoned lock would mean a panic while holding it, which can only happen in a test
    // here; recovering the map is better than propagating the panic into a peer's CER
    // handling, where it would drop a connection over a bookkeeping failure.
    let mut map = match seen().lock() {
        Ok(map) => map,
        Err(poisoned) => poisoned.into_inner(),
    };

    match map.insert(origin_host.to_string(), current) {
        None => PeerRestartOutcome::FirstSighting { current },
        Some(previous) if previous == current => PeerRestartOutcome::Unchanged { current },
        Some(previous) if previous < current => PeerRestartOutcome::Restarted { previous, current },
        Some(previous) => PeerRestartOutcome::Regressed { previous, current },
    }
}

/// Log an outcome at the level its meaning deserves, once, in one place.
///
/// Centralised so the three CER/CEA sites cannot describe the same event differently. The
/// levels are the point: a restart is `warn` because it means the peer lost state a
/// deployment may care about, and a regression is `warn` because it means the signal itself
/// is untrustworthy — neither is routine, and both used to be invisible.
pub fn log_peer_restart_outcome(origin_host: &str, outcome: PeerRestartOutcome) {
    match outcome {
        PeerRestartOutcome::NotAdvertised => log::debug!(
            "peer {origin_host} advertises no Origin-State-Id, so its restarts cannot be \
             detected (RFC 6733 §8.16)"
        ),
        PeerRestartOutcome::FirstSighting { current } => log::info!(
            "peer {origin_host} Origin-State-Id {current} recorded as the baseline; a change \
             from here means it restarted"
        ),
        PeerRestartOutcome::Unchanged { current } => log::debug!(
            "peer {origin_host} Origin-State-Id unchanged at {current}: it has not restarted"
        ),
        PeerRestartOutcome::Restarted { previous, current } => log::warn!(
            "peer {origin_host} RESTARTED: Origin-State-Id {previous} -> {current}. It has \
             lost the state it held for this node (RFC 6733 §8.16, TS 23.007). No session or \
             subscriber state is discarded here -- see nextgcore-diameter's `restart` module \
             for the per-NF reasoning"
        ),
        PeerRestartOutcome::Regressed { previous, current } => log::warn!(
            "peer {origin_host} sent a DECREASING Origin-State-Id {previous} -> {current}, \
             which §8.16 forbids. Treated as neither a restart nor a steady state: the value \
             cannot be trusted, so nothing is concluded from it"
        ),
    }
}

/// Forget every recorded value.
///
/// Test-only, and it exists because the map is process-global: two tests observing the same
/// `Origin-Host` would otherwise see each other's baseline, and the one that ran second
/// would report `Unchanged` where it expected `FirstSighting`. Tests that use it take
/// [`test_lock`].
#[cfg(test)]
pub(crate) fn reset_for_test() {
    match seen().lock() {
        Ok(mut map) => map.clear(),
        Err(poisoned) => poisoned.into_inner().clear(),
    }
}

/// The lock every test touching the process-global map must take.
///
/// Declared beside the global it guards rather than inside a `mod tests`, so a sibling module
/// that grows a test against this state can reach it. One lock, not one per test file: the
/// hazard is the shared map, and a second lock over the same state is no protection at all.
#[cfg(test)]
pub(crate) fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A first value is a baseline, and an unchanged one is not a restart.
    ///
    /// The most important negative in this module: a detector that reported the first
    /// sighting as a restart would fire on every peer the first time it connected, which is
    /// worse than not detecting anything.
    #[test]
    fn a_first_value_is_a_baseline_and_an_unchanged_one_is_not_a_restart() {
        let _guard = test_lock().lock().unwrap_or_else(|p| p.into_inner());
        reset_for_test();

        assert_eq!(
            observe_peer_restart("mme.example.org", Some(1000)),
            PeerRestartOutcome::FirstSighting { current: 1000 },
            "the first value seen has nothing to be compared against"
        );
        assert_eq!(
            observe_peer_restart("mme.example.org", Some(1000)),
            PeerRestartOutcome::Unchanged { current: 1000 }
        );
        assert!(
            !observe_peer_restart("mme.example.org", Some(1000)).is_restart(),
            "and `is_restart` must agree, since that is what callers branch on"
        );
    }

    /// An INCREASED value is a restart, and only that variant reports as one.
    #[test]
    fn an_increased_value_is_a_restart() {
        let _guard = test_lock().lock().unwrap_or_else(|p| p.into_inner());
        reset_for_test();

        observe_peer_restart("hss.example.org", Some(1000));
        let outcome = observe_peer_restart("hss.example.org", Some(1001));
        assert_eq!(
            outcome,
            PeerRestartOutcome::Restarted {
                previous: 1000,
                current: 1001
            }
        );
        assert!(outcome.is_restart());
    }

    /// A DECREASED value is a §8.16 violation, not a restart.
    ///
    /// The one change that must not trigger a reaction: a decrease is evidence the value
    /// cannot be trusted, so concluding "restarted" from it would act on a signal the peer
    /// has just proved it does not maintain. A detector comparing with `!=` would report a
    /// restart here.
    #[test]
    fn a_decreased_value_is_a_violation_and_not_a_restart() {
        let _guard = test_lock().lock().unwrap_or_else(|p| p.into_inner());
        reset_for_test();

        observe_peer_restart("pcef.example.org", Some(5000));
        let outcome = observe_peer_restart("pcef.example.org", Some(4999));
        assert_eq!(
            outcome,
            PeerRestartOutcome::Regressed {
                previous: 5000,
                current: 4999
            },
            "§8.16 requires the value to increase monotonically"
        );
        assert!(
            !outcome.is_restart(),
            "and it must NOT be reported as a restart: a `!=` comparison would say it was"
        );
    }

    /// An absent AVP is distinct from a first sighting, and does not disturb the baseline.
    ///
    /// The AVP is optional, so a peer that never sends it must not read as restarting; and a
    /// peer that sends it intermittently must not lose its baseline when it omits it, or the
    /// next advertisement would look like a first sighting and a real restart after that
    /// would be missed.
    #[test]
    fn an_absent_avp_is_not_a_restart_and_preserves_the_baseline() {
        let _guard = test_lock().lock().unwrap_or_else(|p| p.into_inner());
        reset_for_test();

        assert_eq!(
            observe_peer_restart("silent.example.org", None),
            PeerRestartOutcome::NotAdvertised
        );

        observe_peer_restart("flaky.example.org", Some(7));
        assert_eq!(
            observe_peer_restart("flaky.example.org", None),
            PeerRestartOutcome::NotAdvertised,
            "an omission says nothing about whether the peer restarted"
        );
        assert_eq!(
            observe_peer_restart("flaky.example.org", Some(7)),
            PeerRestartOutcome::Unchanged { current: 7 },
            "and the baseline survived the omission: without that this would read as a \
             FirstSighting and the NEXT increase would be measured from the wrong value"
        );
    }

    /// Peers are tracked independently.
    ///
    /// One shared map, so a bug keying it wrongly — or not at all — would make one peer's
    /// restart look like every peer's.
    #[test]
    fn each_peer_is_tracked_under_its_own_origin_host() {
        let _guard = test_lock().lock().unwrap_or_else(|p| p.into_inner());
        reset_for_test();

        observe_peer_restart("a.example.org", Some(100));
        observe_peer_restart("b.example.org", Some(200));

        assert_eq!(
            observe_peer_restart("a.example.org", Some(101)),
            PeerRestartOutcome::Restarted {
                previous: 100,
                current: 101
            }
        );
        assert_eq!(
            observe_peer_restart("b.example.org", Some(200)),
            PeerRestartOutcome::Unchanged { current: 200 },
            "b must be unaffected by a's restart"
        );
    }
}
