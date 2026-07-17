//! udmd Network Energy Saving runtime (issue #22, feature `nes`, off by
//! default).
//!
//! Drives the reusable `nextgcore_sbi::nes::NesMachine` from a poll ticker:
//! inbound activity comes from the process-global `app::NES_REQUESTS`
//! counter, the graceful-drain gate from `app::NES_IN_FLIGHT`. On
//! `Suspend`, the configured [`nextgcore_sbi::nes::NesAction`] is reflected
//! to the NRF — PATCH `nfStatus=SUSPENDED` (heartbeats continue advertising
//! the suspended status; nrfd honors the self-suspension) or full
//! deregistration (heartbeats pause). On `Resume` the reverse happens.
//!
//! It also feeds the live `/metrics` energy endpoint
//! (`nextgcore_metrics::nes_energy`) using a **SYNTHETIC power model** — no
//! hardware counters exist in this research core:
//!
//! ```text
//! utilization = min(1.0, requests_this_tick / (capacity_rps * dt))
//! power_w     = suspended ? 0.1 * idle_power_w
//!                         : idle_power_w + (max_power_w - idle_power_w) * utilization
//! joules     += power_w * dt
//! ```
//!
//! The whole NES policy is non-normative (no frozen Rel-20 Stage-3); see
//! docs/NES.md.

use nextgcore_metrics::nes_energy::{serve_metrics, EnergyGauges};
use nextgcore_sbi::context::NfStatus;
use nextgcore_sbi::nes::{NesAction, NesConfig, NesMachine, NesTransition};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Resolved NES settings (YAML with defaults applied).
#[derive(Debug, Clone)]
pub struct NesSettings {
    pub enabled: bool,
    pub idle_threshold_secs: u64,
    pub drain_timeout_secs: u64,
    pub poll_interval_secs: u64,
    pub action: NesAction,
    pub metrics_port: u16,
    pub capacity_rps: f64,
    pub idle_power_w: f64,
    pub max_power_w: f64,
}

impl Default for NesSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_threshold_secs: 300,
            drain_timeout_secs: 10,
            poll_interval_secs: 5,
            action: NesAction::Suspend,
            metrics_port: 9090,
            capacity_rps: 100.0,
            idle_power_w: 5.0,
            max_power_w: 25.0,
        }
    }
}

impl NesSettings {
    /// Apply the YAML `nes:` block over the defaults.
    pub(crate) fn from_yaml(yaml: &crate::app::NesYaml) -> Self {
        let defaults = Self::default();
        Self {
            enabled: yaml.enabled.unwrap_or(false),
            idle_threshold_secs: yaml
                .idle_threshold_secs
                .unwrap_or(defaults.idle_threshold_secs),
            drain_timeout_secs: yaml
                .drain_timeout_secs
                .unwrap_or(defaults.drain_timeout_secs),
            poll_interval_secs: yaml
                .poll_interval_secs
                .unwrap_or(defaults.poll_interval_secs)
                .max(1),
            action: yaml
                .action
                .as_deref()
                .and_then(NesAction::parse)
                .unwrap_or(defaults.action),
            metrics_port: yaml.metrics_port.unwrap_or(defaults.metrics_port),
            capacity_rps: yaml.capacity_rps.unwrap_or(defaults.capacity_rps).max(1.0),
            idle_power_w: yaml.idle_power_w.unwrap_or(defaults.idle_power_w).max(0.0),
            max_power_w: yaml.max_power_w.unwrap_or(defaults.max_power_w).max(0.0),
        }
    }
}

/// Externally visible NES actions, injected so unit tests use a recorder
/// while production reflects transitions to the NRF.
pub trait NesActions: Send + Sync {
    fn on_suspend(&self);
    fn on_resume(&self);
}

/// Production actions: reflect sleep state to the NRF.
pub struct NrfNesActions {
    pub action: NesAction,
    pub nf_instance_id: String,
    pub sbi_addr: String,
    pub sbi_port: u16,
}

impl NesActions for NrfNesActions {
    fn on_suspend(&self) {
        let id = self.nf_instance_id.clone();
        match self.action {
            NesAction::Suspend => {
                // Heartbeats keep flowing, now advertising SUSPENDED (nrfd
                // honors the self-suspension without reactivating).
                nextgcore_sbi::heartbeat::set_self_nf_status(NfStatus::Suspended);
                tokio::spawn(async move {
                    if let Err(e) =
                        nextgcore_sbi::heartbeat::patch_nf_status(&id, NfStatus::Suspended, 0).await
                    {
                        log::warn!("NES suspend PATCH failed: {e}");
                    }
                });
            }
            NesAction::Deregister => {
                // A deleted profile must not be PATCHed: pause heartbeats.
                nextgcore_sbi::heartbeat::set_heartbeat_paused(true);
                tokio::spawn(async move {
                    let ctx = nextgcore_sbi::context::global_context();
                    let Some(nrf_uri) = ctx.get_nrf_uri().await else {
                        return;
                    };
                    let Some((host, port)) = crate::app::parse_nrf_host_port(&nrf_uri) else {
                        return;
                    };
                    let client = ctx.get_client(&host, port).await;
                    let path = format!("/nnrf-nfm/v1/nf-instances/{id}");
                    match client
                        .send_request(nextgcore_sbi::message::SbiRequest::delete(&path))
                        .await
                    {
                        Ok(resp) if resp.is_success() => {
                            log::info!("NES: deregistered from NRF (sleep)");
                        }
                        Ok(resp) => log::warn!("NES deregister returned {}", resp.status),
                        Err(e) => log::warn!("NES deregister failed: {e}"),
                    }
                });
            }
        }
    }

    fn on_resume(&self) {
        let id = self.nf_instance_id.clone();
        match self.action {
            NesAction::Suspend => {
                nextgcore_sbi::heartbeat::set_self_nf_status(NfStatus::Registered);
                tokio::spawn(async move {
                    if let Err(e) =
                        nextgcore_sbi::heartbeat::patch_nf_status(&id, NfStatus::Registered, 0)
                            .await
                    {
                        log::warn!("NES resume PATCH failed: {e}");
                    }
                });
            }
            NesAction::Deregister => {
                let sbi_addr = self.sbi_addr.clone();
                let sbi_port = self.sbi_port;
                tokio::spawn(async move {
                    // Review fix (issue #22): a one-shot re-registration
                    // could strand the NF deregistered with paused
                    // heartbeats after a transient NRF outage. Retry with
                    // capped exponential backoff; heartbeats resume only
                    // once the NRF has accepted the profile again.
                    let mut backoff = std::time::Duration::from_secs(1);
                    for attempt in 1u32..=8 {
                        match crate::app::register_with_nrf_id(&id, &sbi_addr, sbi_port).await {
                            Ok(_) => {
                                log::info!(
                                    "NES: re-registered with NRF (resume, attempt {attempt})"
                                );
                                nextgcore_sbi::heartbeat::set_heartbeat_paused(false);
                                return;
                            }
                            Err(e) => {
                                log::warn!("NES re-registration attempt {attempt} failed: {e}");
                            }
                        }
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
                    }
                    log::error!(
                        "NES: giving up re-registration after 8 attempts; NF remains \
                         deregistered with heartbeats paused (restart required)"
                    );
                });
            }
        }
    }
}

/// One NES decision step (pure apart from the injected actions): feed
/// activity into the machine, otherwise advance it; dispatch the external
/// actions on Suspend/Resume. Unit-testable with a recorder.
pub fn drive_tick(
    machine: &mut NesMachine,
    actions: &dyn NesActions,
    now_ms: u64,
    activity_delta: u64,
    in_flight: u64,
) -> Option<NesTransition> {
    if activity_delta > 0 {
        let transition = machine.on_activity(now_ms);
        if transition == Some(NesTransition::Resume) {
            actions.on_resume();
        }
        return transition;
    }
    let transition = machine.tick(now_ms, in_flight);
    if transition == Some(NesTransition::Suspend) {
        actions.on_suspend();
    }
    transition
}

/// Spawn the NES runtime when the config enables it (issue #22 toggle:
/// absent block or `enabled: false` → complete no-op).
pub fn spawn_if_enabled(
    settings: Option<NesSettings>,
    nf_instance_id: String,
    sbi_addr: String,
    sbi_port: u16,
) {
    let Some(settings) = settings else {
        log::debug!("NES: no nes: config block; disabled");
        return;
    };
    if !settings.enabled {
        log::info!("NES: configured but disabled (nes.enabled=false)");
        return;
    }
    log::info!(
        "NES enabled: idle={}s drain={}s action={:?} metrics_port={} (non-normative prototype, synthetic power model)",
        settings.idle_threshold_secs,
        settings.drain_timeout_secs,
        settings.action,
        settings.metrics_port
    );

    let gauges = EnergyGauges::new("UDM", &nf_instance_id);
    gauges.register_specs();

    let actions = NrfNesActions {
        action: settings.action,
        nf_instance_id,
        sbi_addr,
        sbi_port,
    };

    tokio::spawn(run_nes_loop(settings, gauges, actions));
}

async fn run_nes_loop(settings: NesSettings, gauges: Arc<EnergyGauges>, actions: NrfNesActions) {
    // Live /metrics endpoint (real HTTP/1.1; acceptance criterion).
    let render_gauges = gauges.clone();
    let metrics_addr = format!("0.0.0.0:{}", settings.metrics_port);
    match metrics_addr.parse() {
        Ok(addr) => {
            if let Err(e) =
                serve_metrics(addr, Arc::new(move || render_gauges.render_prometheus())).await
            {
                log::warn!("NES metrics endpoint failed to bind {metrics_addr}: {e}");
            }
        }
        Err(e) => log::warn!("NES metrics address invalid ({metrics_addr}): {e}"),
    }

    let config = NesConfig {
        idle_threshold_ms: settings.idle_threshold_secs * 1_000,
        drain_timeout_ms: settings.drain_timeout_secs * 1_000,
        action: settings.action,
    };
    let start = std::time::Instant::now();
    let mut machine = NesMachine::new(config, 0);
    let mut last_requests = crate::app::NES_REQUESTS.load(Ordering::Relaxed);
    let dt_secs = settings.poll_interval_secs as f64;
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(
        settings.poll_interval_secs,
    ));
    ticker.tick().await; // first tick fires immediately; skip the zero-dt round

    loop {
        ticker.tick().await;
        let now_ms = start.elapsed().as_millis() as u64;
        let requests = crate::app::NES_REQUESTS.load(Ordering::Relaxed);
        let delta = requests.saturating_sub(last_requests);
        last_requests = requests;
        let in_flight = crate::app::NES_IN_FLIGHT.load(Ordering::Relaxed);

        if let Some(transition) = drive_tick(&mut machine, &actions, now_ms, delta, in_flight) {
            log::info!(
                "NES transition: {transition:?} (state={:?})",
                machine.state()
            );
        }

        // SYNTHETIC power model (documented in the module doc + docs/NES.md).
        let utilization = (delta as f64 / (settings.capacity_rps * dt_secs)).min(1.0);
        let suspended = machine.state() == nextgcore_sbi::nes::NesState::Suspended;
        let power_w = if suspended {
            0.1 * settings.idle_power_w
        } else {
            settings.idle_power_w + (settings.max_power_w - settings.idle_power_w) * utilization
        };
        gauges.set_utilization(utilization);
        gauges.set_power_watts(power_w);
        gauges.add_joules(power_w * dt_secs);
        gauges.set_sleep_ratio(machine.sleep_ratio());
        // Rough data-volume proxy: count requests as wire bits are not
        // tracked per-NF (1 request ≈ 8 kbit, synthetic like the power).
        gauges.add_data_bits(delta * 8_192);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<&'static str>>,
    }

    impl NesActions for Recorder {
        fn on_suspend(&self) {
            self.events.lock().unwrap().push("suspend");
        }
        fn on_resume(&self) {
            self.events.lock().unwrap().push("resume");
        }
    }

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

    /// Acceptance (issue #22): idle → drain → suspend fires the suspend
    /// action exactly once, and later activity fires resume.
    #[test]
    fn idle_drain_suspend_then_activity_resumes() {
        let recorder = Recorder::default();
        let mut m = machine();

        assert_eq!(drive_tick(&mut m, &recorder, 500, 0, 0), None);
        assert_eq!(
            drive_tick(&mut m, &recorder, 1_000, 0, 0),
            Some(NesTransition::BeginDrain)
        );
        assert_eq!(
            drive_tick(&mut m, &recorder, 1_100, 0, 0),
            Some(NesTransition::Suspend)
        );
        assert_eq!(*recorder.events.lock().unwrap(), vec!["suspend"]);

        // Quiet suspended ticks: no repeat actions.
        assert_eq!(drive_tick(&mut m, &recorder, 5_000, 0, 0), None);
        assert_eq!(*recorder.events.lock().unwrap(), vec!["suspend"]);

        // Inbound activity wakes the NF back up.
        assert_eq!(
            drive_tick(&mut m, &recorder, 6_000, 3, 1),
            Some(NesTransition::Resume)
        );
        assert_eq!(*recorder.events.lock().unwrap(), vec!["suspend", "resume"]);
    }

    /// Acceptance (issue #22): graceful drain — in-flight work blocks the
    /// suspend action; it fires only once the work settles.
    #[test]
    fn drain_gate_blocks_suspend_until_in_flight_settles() {
        let recorder = Recorder::default();
        let mut m = machine();

        assert_eq!(
            drive_tick(&mut m, &recorder, 1_000, 0, 2),
            Some(NesTransition::BeginDrain)
        );
        assert_eq!(drive_tick(&mut m, &recorder, 1_100, 0, 2), None);
        assert!(
            recorder.events.lock().unwrap().is_empty(),
            "no drop, no suspend"
        );
        assert_eq!(
            drive_tick(&mut m, &recorder, 1_200, 0, 0),
            Some(NesTransition::Suspend)
        );
        assert_eq!(*recorder.events.lock().unwrap(), vec!["suspend"]);
    }

    #[test]
    fn drain_timeout_aborts_without_any_action() {
        let recorder = Recorder::default();
        let mut m = machine();
        drive_tick(&mut m, &recorder, 1_000, 0, 1);
        assert_eq!(
            drive_tick(&mut m, &recorder, 1_500, 0, 1),
            Some(NesTransition::AbortDrain)
        );
        assert!(recorder.events.lock().unwrap().is_empty());
    }

    #[test]
    fn settings_defaults_and_yaml_overlay() {
        let defaults = NesSettings::default();
        assert!(!defaults.enabled, "NES must be off by default");
        assert_eq!(defaults.action, NesAction::Suspend);

        let yaml = crate::app::NesYaml {
            enabled: Some(true),
            idle_threshold_secs: Some(60),
            drain_timeout_secs: None,
            poll_interval_secs: Some(0), // clamped to 1
            action: Some("deregister".to_string()),
            metrics_port: Some(9191),
            capacity_rps: None,
            idle_power_w: Some(2.0),
            max_power_w: None,
        };
        let settings = NesSettings::from_yaml(&yaml);
        assert!(settings.enabled);
        assert_eq!(settings.idle_threshold_secs, 60);
        assert_eq!(settings.drain_timeout_secs, defaults.drain_timeout_secs);
        assert_eq!(settings.poll_interval_secs, 1);
        assert_eq!(settings.action, NesAction::Deregister);
        assert_eq!(settings.metrics_port, 9191);
        assert_eq!(settings.idle_power_w, 2.0);
        assert_eq!(settings.max_power_w, defaults.max_power_w);
    }
}
