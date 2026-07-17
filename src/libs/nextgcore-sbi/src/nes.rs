//! Network Energy Saving idle/sleep state machine (issue #22).
//!
//! A small, reusable, PURE state machine an NF drives from its own poll
//! tick: `Active → (idle > threshold) → Draining → (in-flight settled) →
//! Suspended`, and `Suspended → (activity) → Active`. The machine only
//! decides transitions; the NF performs the externally visible actions
//! (PATCH `nfStatus=SUSPENDED` / NRF deregistration on suspend, the reverse
//! on resume) — see `nextgcore_sbi::heartbeat::{patch_nf_status,
//! set_self_nf_status, set_heartbeat_paused}`.
//!
//! Graceful drain: the machine never emits [`NesTransition::Suspend`] while
//! requests are in flight; if the drain window expires with work still
//! pending, it aborts back to `Active` (no request is ever dropped by a
//! sleep transition). Times are plain `u64` milliseconds supplied by the
//! caller, keeping the machine deterministic and unit-testable.
//!
//! Non-normative: TS 23.501/TS 29.510 define the `nfStatus` values used to
//! reflect sleep toward the NRF, but a full "6G NES" sleep/scale policy has
//! no frozen Rel-20 Stage-3 — this is a research prototype.

/// What to do toward the NRF when entering the sleep state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NesAction {
    /// Keep the NF profile but PATCH `nfStatus=SUSPENDED` (heartbeats
    /// continue, advertising the suspended status).
    #[default]
    Suspend,
    /// Deregister from the NRF entirely (heartbeats pause; re-registration
    /// happens on resume).
    Deregister,
}

impl NesAction {
    /// Parse the config string (`suspend` | `deregister`).
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "suspend" => Some(Self::Suspend),
            "deregister" => Some(Self::Deregister),
            _ => None,
        }
    }
}

/// NES sleep-policy configuration (an NF's off-by-default `nes:` block).
#[derive(Debug, Clone, Copy)]
pub struct NesConfig {
    /// Idle time (no inbound activity) before draining starts.
    pub idle_threshold_ms: u64,
    /// Maximum time to wait for in-flight work to settle; expiry aborts the
    /// sleep attempt back to `Active`.
    pub drain_timeout_ms: u64,
    /// Action toward the NRF on suspend.
    pub action: NesAction,
}

/// NES lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NesState {
    Active,
    Draining,
    Suspended,
}

/// Externally visible transition the caller must act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NesTransition {
    /// Idle threshold crossed: stop taking on deferrable work.
    BeginDrain,
    /// Drained: perform the configured [`NesAction`].
    Suspend,
    /// Drain window expired with work still in flight: back to `Active`
    /// (nothing external to do; the sleep attempt is abandoned).
    AbortDrain,
    /// Activity while suspended: undo the [`NesAction`] (PATCH back to
    /// `REGISTERED` / re-register).
    Resume,
}

/// The pure NES state machine. All time is caller-supplied milliseconds.
#[derive(Debug)]
pub struct NesMachine {
    config: NesConfig,
    state: NesState,
    last_activity_ms: u64,
    drain_started_ms: u64,
    last_tick_ms: u64,
    time_awake_ms: u64,
    time_suspended_ms: u64,
}

impl NesMachine {
    pub fn new(config: NesConfig, now_ms: u64) -> Self {
        Self {
            config,
            state: NesState::Active,
            last_activity_ms: now_ms,
            drain_started_ms: 0,
            last_tick_ms: now_ms,
            time_awake_ms: 0,
            time_suspended_ms: 0,
        }
    }

    pub fn state(&self) -> NesState {
        self.state
    }

    pub fn action(&self) -> NesAction {
        self.config.action
    }

    /// Fraction of observed time spent suspended (the `energy_sleep_ratio`
    /// gauge source).
    pub fn sleep_ratio(&self) -> f64 {
        let total = self.time_awake_ms + self.time_suspended_ms;
        if total > 0 {
            self.time_suspended_ms as f64 / total as f64
        } else {
            0.0
        }
    }

    /// Record inbound activity. From `Suspended` this is the wake-up signal
    /// ([`NesTransition::Resume`]); from `Draining` it silently aborts the
    /// drain (new demand cancels the sleep attempt — nothing was suspended
    /// yet, so there is nothing external to undo).
    pub fn on_activity(&mut self, now_ms: u64) -> Option<NesTransition> {
        self.accumulate(now_ms);
        self.last_activity_ms = now_ms;
        match self.state {
            NesState::Suspended => {
                self.state = NesState::Active;
                Some(NesTransition::Resume)
            }
            NesState::Draining => {
                self.state = NesState::Active;
                None
            }
            NesState::Active => None,
        }
    }

    /// Advance the machine from a poll tick. `in_flight` is the number of
    /// requests currently being served; [`NesTransition::Suspend`] is only
    /// emitted once it reaches zero (graceful drain).
    pub fn tick(&mut self, now_ms: u64, in_flight: u64) -> Option<NesTransition> {
        self.accumulate(now_ms);
        match self.state {
            NesState::Active => {
                if now_ms.saturating_sub(self.last_activity_ms) >= self.config.idle_threshold_ms {
                    self.state = NesState::Draining;
                    self.drain_started_ms = now_ms;
                    Some(NesTransition::BeginDrain)
                } else {
                    None
                }
            }
            NesState::Draining => {
                if in_flight == 0 {
                    self.state = NesState::Suspended;
                    Some(NesTransition::Suspend)
                } else if now_ms.saturating_sub(self.drain_started_ms)
                    >= self.config.drain_timeout_ms
                {
                    // In-flight work outlived the drain window: never drop
                    // it — abandon the sleep attempt instead.
                    self.state = NesState::Active;
                    self.last_activity_ms = now_ms;
                    Some(NesTransition::AbortDrain)
                } else {
                    None
                }
            }
            NesState::Suspended => None,
        }
    }

    fn accumulate(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_tick_ms);
        match self.state {
            NesState::Suspended => self.time_suspended_ms += elapsed,
            _ => self.time_awake_ms += elapsed,
        }
        self.last_tick_ms = now_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> NesMachine {
        NesMachine::new(
            NesConfig {
                idle_threshold_ms: 1_000,
                drain_timeout_ms: 500,
                action: NesAction::Suspend,
            },
            0,
        )
    }

    #[test]
    fn idle_drains_then_suspends_when_no_work_in_flight() {
        let mut m = machine();
        assert_eq!(m.tick(999, 0), None, "below idle threshold");
        assert_eq!(m.state(), NesState::Active);

        assert_eq!(m.tick(1_000, 0), Some(NesTransition::BeginDrain));
        assert_eq!(m.state(), NesState::Draining);

        assert_eq!(m.tick(1_100, 0), Some(NesTransition::Suspend));
        assert_eq!(m.state(), NesState::Suspended);
        // Suspended stays put with no activity.
        assert_eq!(m.tick(10_000, 0), None);
        assert_eq!(m.state(), NesState::Suspended);
    }

    /// Acceptance (issue #22): graceful drain — the sleep transition never
    /// fires while requests are in flight.
    #[test]
    fn drain_waits_for_in_flight_and_suspends_only_when_settled() {
        let mut m = machine();
        assert_eq!(m.tick(1_000, 3), Some(NesTransition::BeginDrain));
        assert_eq!(m.tick(1_100, 3), None, "in-flight work blocks suspend");
        assert_eq!(m.tick(1_200, 1), None, "still one in flight");
        assert_eq!(m.state(), NesState::Draining);
        assert_eq!(m.tick(1_300, 0), Some(NesTransition::Suspend));
        assert_eq!(m.state(), NesState::Suspended);
    }

    #[test]
    fn drain_timeout_aborts_back_to_active_without_dropping_work() {
        let mut m = machine();
        assert_eq!(m.tick(1_000, 2), Some(NesTransition::BeginDrain));
        // Drain window (500ms) expires with work still pending.
        assert_eq!(m.tick(1_500, 2), Some(NesTransition::AbortDrain));
        assert_eq!(m.state(), NesState::Active);
        // The abort refreshed the idle clock: no immediate re-drain.
        assert_eq!(m.tick(1_600, 0), None);
        assert_eq!(m.tick(2_500, 0), Some(NesTransition::BeginDrain));
    }

    /// Acceptance (issue #22): activity restores the NF from Suspended
    /// (the caller PATCHes back to REGISTERED / re-registers on Resume).
    #[test]
    fn activity_resumes_from_suspended_and_aborts_draining() {
        let mut m = machine();
        m.tick(1_000, 0);
        m.tick(1_001, 0);
        assert_eq!(m.state(), NesState::Suspended);
        assert_eq!(m.on_activity(2_000), Some(NesTransition::Resume));
        assert_eq!(m.state(), NesState::Active);

        // Draining + activity: silent abort (nothing external happened yet).
        m.tick(3_000, 0);
        assert_eq!(m.state(), NesState::Draining);
        assert_eq!(m.on_activity(3_100), None);
        assert_eq!(m.state(), NesState::Active);

        // Active + activity: no transition.
        assert_eq!(m.on_activity(3_200), None);
    }

    #[test]
    fn sleep_ratio_accumulates_by_state() {
        let mut m = machine();
        m.tick(1_000, 0); // BeginDrain at 1000 (1000ms awake)
        m.tick(1_100, 0); // Suspend at 1100 (+100ms awake)
        m.tick(2_200, 0); // +1100ms suspended
        let ratio = m.sleep_ratio();
        assert!((ratio - 0.5).abs() < 1e-9, "1100/2200 = 0.5, got {ratio}");
    }

    #[test]
    fn action_parse() {
        assert_eq!(NesAction::parse("suspend"), Some(NesAction::Suspend));
        assert_eq!(NesAction::parse("DEREGISTER"), Some(NesAction::Deregister));
        assert_eq!(NesAction::parse("off"), None);
    }
}
