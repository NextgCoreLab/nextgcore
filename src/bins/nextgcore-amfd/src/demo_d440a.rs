//! Demo `d440a-ai-paging` (nextgsim#462): the demo layer over the base
//! `paging.strategy: recommended-first` (#1442, TS 23.502 §4.2.3.3). Cargo feature
//! `demo-d440a-ai-paging` plus the `demo:` block, both off by default.
//!
//! # What the demo adds
//! - **Modes.** amfd accepts the gNB's five modes (`page-all`, `last-served`,
//!   `ct`, `lsq`, `onnx`), so one `demo:` block, written into every target's
//!   config, names one arm across the RAN and the core. In amfd every mode does the
//!   same thing: it forces the effective strategy to `recommended-first`, which
//!   supersedes `amf.paging.strategy`, and amfd logs the effective strategy at
//!   startup. The prediction is the gNB's. amfd only follows the RAN's
//!   recommendation, and under `page-all` the gNB sends none, so the whole area is
//!   paged from attempt 1.
//! - **Log lines**, `[demo:d440a-ai-paging]`, info level so a release build keeps
//!   them:
//!   - `Paging sent to N/M ue=<supi> scope=<scope> targets=[gNB 0x..,..] attempt K`,
//!     after the base `Paging sent to ...` line, which is unchanged. `<scope>` is
//!     `recommended` or `registration-area`.
//!   - `page answered ue=<supi> via gNB 0x.. attempt K`, when a Service Request
//!     answers the page.
//! - **`amf_paging_attempts_total{scope}`**: one per PAGING attempt, by scope,
//!   rendered only while the demo is active.
//!
//! # Not here
//! `nextg_demo_enabled{demo,mode}` and the `WARN DEMO MODE ACTIVE` banner come
//! from `nextgcore-demo`. Storing the RAN's recommendation and paging it first are
//! the base `recommended-first` strategy, not demo code.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::context::PagingStrategy;

/// The demo key (nextgsim#458 convention), the gNB's key.
pub const DEMO_KEY: &str = "d440a-ai-paging";

/// The gNB's modes. amfd treats them alike (module docs).
pub const MODES: &[&str] = &["page-all", "last-served", "ct", "lsq", "onnx"];

/// What this binary registers in its demo registry under the feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: MODES,
    requires: &[],
};

#[cfg(test)]
thread_local! {
    static MODE_ON_THIS_THREAD: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: run this demo in `mode` on the current thread for the guard's
/// lifetime, without installing the process-wide write-once demo state.
#[cfg(test)]
pub(crate) struct ModeOnThisThread;

#[cfg(test)]
impl ModeOnThisThread {
    pub(crate) fn set(mode: &'static str) -> Self {
        MODE_ON_THIS_THREAD.with(|m| m.set(Some(mode)));
        Self
    }
}

#[cfg(test)]
impl Drop for ModeOnThisThread {
    fn drop(&mut self) {
        MODE_ON_THIS_THREAD.with(|m| m.set(None));
    }
}

/// The demo's mode in this process, or `None` when it is not active.
pub fn mode() -> Option<&'static str> {
    #[cfg(test)]
    if let Some(m) = MODE_ON_THIS_THREAD.with(|m| m.get()) {
        return Some(m);
    }
    nextgcore_demo::active_mode(DEMO_KEY)
}

/// The paging strategy in effect: `recommended-first` whenever the demo is active
/// (any registered mode), otherwise the configured one.
pub fn effective_strategy(configured: PagingStrategy, mode: Option<&str>) -> PagingStrategy {
    match mode {
        Some(m) if MODES.contains(&m) => PagingStrategy::RecommendedFirst,
        _ => configured,
    }
}

/// The scope of one paging attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A first attempt to the RAN's recommended gNBs in the registration area.
    Recommended,
    /// The whole registration area.
    RegistrationArea,
}

impl Scope {
    const ALL: [Scope; 2] = [Scope::Recommended, Scope::RegistrationArea];

    /// The attempt's scope: `recommended` when it went to the RAN's recommended
    /// gNBs, `registration-area` otherwise.
    pub fn of(recommended: bool) -> Self {
        if recommended {
            Scope::Recommended
        } else {
            Scope::RegistrationArea
        }
    }

    /// The `scope=` value and metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Recommended => "recommended",
            Scope::RegistrationArea => "registration-area",
        }
    }
}

static ATTEMPTS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Count one PAGING attempt of `scope`.
pub fn count_attempt(scope: Scope) {
    ATTEMPTS[scope as usize].fetch_add(1, Ordering::Relaxed);
}

/// The attempts of `scope` so far.
pub fn attempt_count(scope: Scope) -> u64 {
    ATTEMPTS[scope as usize].load(Ordering::Relaxed)
}

/// `amf_paging_attempts_total{scope}`, only while the demo is active, so a
/// demo-off `/metrics` is unchanged.
pub fn render_metrics(out: &mut String) {
    if mode().is_none() {
        return;
    }
    render_attempts(out);
}

fn render_attempts(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_header(
        out,
        "amf_paging_attempts_total",
        "counter",
        "PAGING attempts (demo d440a-ai-paging, nextgsim#462), by scope: recommended is a \
         first attempt to the RAN's recommended gNBs, registration-area the whole area",
    );
    for s in Scope::ALL {
        let _ = writeln!(
            out,
            "amf_paging_attempts_total{{scope=\"{}\"}} {}",
            s.as_str(),
            attempt_count(s)
        );
    }
}

/// `Paging sent to N/M ue=<supi> scope=<scope> targets=[gNB 0x..,..] attempt K`.
/// A target whose gNB ID is unknown is `gNB ?`.
pub fn paging_sent_line(
    sent: usize,
    supi: &str,
    scope: Scope,
    gnb_ids: &[Option<u32>],
    attempt: u32,
) -> String {
    let targets: Vec<String> = gnb_ids
        .iter()
        .map(|g| g.map_or_else(|| "gNB ?".to_string(), |g| format!("gNB 0x{g:x}")))
        .collect();
    format!(
        "Paging sent to {sent}/{} ue={supi} scope={} targets=[{}] attempt {attempt}",
        gnb_ids.len(),
        scope.as_str(),
        targets.join(",")
    )
}

/// `page answered ue=<supi> via gNB 0x.. attempt K`.
pub fn page_answered_line(supi: &str, gnb_id: Option<u32>, attempt: u32) -> String {
    let via = gnb_id.map_or_else(|| "an unknown gNB".to_string(), |g| format!("gNB 0x{g:x}"));
    format!("page answered ue={supi} via {via} attempt {attempt}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> nextgcore_demo::DemoRegistry {
        nextgcore_demo::DemoRegistry::new(&[DEMO_SPEC])
    }

    fn validate(
        yaml: &str,
    ) -> Result<nextgcore_demo::ActiveDemos, nextgcore_demo::DemoConfigError> {
        let root: serde_yaml::Value = serde_yaml::from_str(yaml).expect("yaml");
        nextgcore_demo::DemoConfig::from_root(&root)?.validate(&registry())
    }

    fn block(mode: &str) -> String {
        format!("demo:\n  enabled: true\n  d440a-ai-paging:\n    enabled: true\n    mode: {mode}\n")
    }

    /// The gNB's five modes activate, each forcing `recommended-first`. Any other
    /// mode fails startup with `UnknownMode`: there is no fallback.
    #[test]
    fn the_gnb_modes_are_accepted_and_each_forces_recommended_first() {
        for mode in ["page-all", "last-served", "ct", "lsq", "onnx"] {
            let active = validate(&block(mode)).expect("valid");
            assert_eq!(active.mode(DEMO_KEY), Some(mode));
            assert_eq!(
                active.banner().as_deref(),
                Some(format!("DEMO MODE ACTIVE: d440a-ai-paging={mode}").as_str())
            );
            assert_eq!(
                effective_strategy(PagingStrategy::RegistrationArea, active.mode(DEMO_KEY)),
                PagingStrategy::RecommendedFirst,
                "{mode}"
            );
        }
        for mode in ["bogus", "recommended-first", "registration-area"] {
            match validate(&block(mode)) {
                Err(nextgcore_demo::DemoConfigError::UnknownMode { demo, mode: m, .. }) => {
                    assert_eq!(demo, DEMO_KEY);
                    assert_eq!(m, mode);
                }
                other => panic!("{mode}: expected UnknownMode, got {other:?}"),
            }
        }
    }

    /// Demo off: no block, the kill switch off, or the key off leaves nothing
    /// active, so the configured strategy stands.
    #[test]
    fn demo_off_changes_nothing() {
        for yaml in [
            "amf: {}\n",
            "demo:\n  enabled: false\n  d440a-ai-paging:\n    enabled: true\n    mode: ct\n",
            "demo:\n  enabled: true\n  d440a-ai-paging:\n    enabled: false\n    mode: ct\n",
        ] {
            let active = validate(yaml).expect("valid");
            assert!(active.is_empty(), "{yaml}");
            for configured in [
                PagingStrategy::RegistrationArea,
                PagingStrategy::RecommendedFirst,
                PagingStrategy::NwdafMobility,
            ] {
                assert_eq!(
                    effective_strategy(configured, active.mode(DEMO_KEY)),
                    configured
                );
            }
        }
    }

    #[test]
    fn the_scope_follows_the_attempt() {
        assert_eq!(Scope::of(true), Scope::Recommended);
        assert_eq!(Scope::of(false), Scope::RegistrationArea);
    }

    /// The ticket's success-signal shapes.
    #[test]
    fn the_demo_lines_carry_scope_targets_and_attempt() {
        assert_eq!(
            paging_sent_line(2, "imsi-1", Scope::Recommended, &[Some(0x3), Some(0x4)], 1),
            "Paging sent to 2/2 ue=imsi-1 scope=recommended targets=[gNB 0x3,gNB 0x4] attempt 1"
        );
        assert_eq!(
            paging_sent_line(5, "imsi-1", Scope::RegistrationArea, &[Some(0x0), None], 2),
            "Paging sent to 5/2 ue=imsi-1 scope=registration-area targets=[gNB 0x0,gNB ?] attempt 2",
            "gNB ID 0 is a real ID; an unknown one is `?`"
        );
        assert_eq!(
            page_answered_line("imsi-001010000000001", Some(0x4), 1),
            "page answered ue=imsi-001010000000001 via gNB 0x4 attempt 1"
        );
        assert_eq!(
            page_answered_line("imsi-1", None, 2),
            "page answered ue=imsi-1 via an unknown gNB attempt 2"
        );
    }

    /// The counter's exposition, both scopes always listed.
    #[test]
    fn the_attempts_counter_lists_both_scopes() {
        let mut out = String::new();
        render_attempts(&mut out);
        assert!(
            out.contains("# TYPE amf_paging_attempts_total counter"),
            "{out}"
        );
        assert!(
            out.contains("amf_paging_attempts_total{scope=\"recommended\"} "),
            "{out}"
        );
        assert!(
            out.contains("amf_paging_attempts_total{scope=\"registration-area\"} "),
            "{out}"
        );
    }

    /// Demo off renders nothing. (No count here: the counters are
    /// process-global and the pump tests measure deltas under CONTEXT_GUARD.)
    #[test]
    fn demo_off_renders_no_counter() {
        let mut out = String::new();
        render_metrics(&mut out);
        assert!(out.is_empty(), "{out}");
        let _on = ModeOnThisThread::set("ct");
        render_metrics(&mut out);
        assert!(out.contains("amf_paging_attempts_total"), "{out}");
    }
}
