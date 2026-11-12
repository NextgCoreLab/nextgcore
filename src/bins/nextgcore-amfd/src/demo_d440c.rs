//! Demo `d440c-nwdaf-paging` (nextgsim#464): the demo layer over the base
//! `paging.strategy: nwdaf-mobility` (`nwdaf_mobility.rs`). Cargo feature
//! `demo-d440c-nwdaf-paging` plus the `demo:` block, both off by default.
//!
//! # What the demo adds
//! - **Modes** force the effective paging strategy. The block supersedes
//!   `amf.paging.strategy`, and amfd logs the effective strategy at startup:
//!   - `nwdaf-mobility` (the main arm) runs the base `nwdaf-mobility` strategy;
//!   - `registration-area` (the page-all baseline) runs the base default.
//!
//!   `ran-recommendation` (the #462 comparison arm) is **not registered yet**. It
//!   needs #462's amfd demo `d440a-ai-paging`, and until that merges the mode
//!   fails startup with `UnknownMode`, so no mode is accepted before it does what
//!   it names.
//! - **Log lines**, `[demo:d440c-nwdaf-paging]`, info level so a release build
//!   keeps them:
//!   - `Paging sent to N/M scope=<scope> targets=[gNB 0x..,..] attempt K`, after
//!     the base `Paging sent to ...` line, which is unchanged. `<scope>` is one
//!     of `nwdaf-mobility`, `last-known`, `recommended` or `registration-area`.
//!   - `page answered ue=<supi> via gNB 0x.. attempt K`, when a Service Request
//!     answers the page.
//! - **Assistance Data for Recommended Cells, built from the prediction.** On a
//!   first attempt steered by the NWDAF, the PAGING's Assistance Data for Paging
//!   also carries a Recommended Cells for Paging list:
//!   - the UE's last known cell, as the visited cell;
//!   - then the predicted cell, as a non-visited cell after the visited one it
//!     follows (TS 38.413 §9.3.1.71 ordering).
//!
//!   **Non-normative.** §9.3.1.71 says this IE "is transparent to the 5GC", and
//!   TS 23.502 §4.2.3.3 has the AMF convey the RAN's own recommendation. Here the
//!   AMF fills it from NWDAF analytics instead. The base build never sends it.
//!
//! # Not here
//! `nextg_demo_enabled{demo,mode}` and the `WARN DEMO MODE ACTIVE` banner come
//! from `nextgcore-demo`: amfd's `/metrics` renders through
//! `nextgcore_metrics::nf::render_common`, and `install` logs the banner.

use crate::context::{PagingStrategy, PlmnId};

/// The demo key (nextgsim#458 convention).
pub const DEMO_KEY: &str = "d440c-nwdaf-paging";
/// Mode: the base `nwdaf-mobility` strategy plus the demo's assistance data.
pub const MODE_NWDAF_MOBILITY: &str = "nwdaf-mobility";
/// Mode: the page-all baseline, the base `registration-area` strategy.
pub const MODE_REGISTRATION_AREA: &str = "registration-area";

/// What this binary registers in its demo registry under the feature.
/// `ran-recommendation` joins `modes` once #462's amfd demo has merged.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: &[MODE_NWDAF_MOBILITY, MODE_REGISTRATION_AREA],
    requires: &[],
};

#[cfg(test)]
thread_local! {
    static MODE_ON_THIS_THREAD: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: run this demo in `mode` on the current thread for the guard's
/// lifetime, without installing the process-wide write-once demo state.
/// `#[tokio::test]` runs the pump on the test's own thread.
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

/// The paging strategy in effect: the demo mode's, when the demo is active;
/// otherwise the configured one.
pub fn effective_strategy(configured: PagingStrategy, mode: Option<&str>) -> PagingStrategy {
    match mode {
        Some(MODE_NWDAF_MOBILITY) => PagingStrategy::NwdafMobility,
        Some(MODE_REGISTRATION_AREA) => PagingStrategy::RegistrationArea,
        _ => configured,
    }
}

/// The scope label of one attempt's demo line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A first attempt steered by an NWDAF prediction owned by a gNB in the area.
    NwdafMobility,
    /// A first attempt that pages only the last known cell's gNB.
    LastKnown,
    /// A first attempt to the RAN's recommended nodes.
    Recommended,
    /// The whole registration area.
    RegistrationArea,
}

impl Scope {
    /// The `scope=` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::NwdafMobility => "nwdaf-mobility",
            Scope::LastKnown => "last-known",
            Scope::Recommended => "recommended",
            Scope::RegistrationArea => "registration-area",
        }
    }
}

/// `Paging sent to N/M scope=<scope> targets=[gNB 0x..,..] attempt K`.
pub fn paging_sent_line(sent: usize, scope: Scope, gnb_ids: &[u32], attempt: u32) -> String {
    let targets: Vec<String> = gnb_ids.iter().map(|g| format!("gNB 0x{g:x}")).collect();
    format!(
        "Paging sent to {sent}/{} scope={} targets=[{}] attempt {attempt}",
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

/// The Recommended Cells for Paging the demo sends on an NWDAF-steered first
/// attempt: the last known cell (visited) and then the predicted one
/// (non-visited), once each. Empty when there is no prediction.
pub fn recommended_cells(
    last_known: Option<&(PlmnId, u64)>,
    predicted: Option<&crate::context::PredictedCell>,
) -> Vec<(PlmnId, u64)> {
    let Some(p) = predicted else {
        return Vec::new();
    };
    let mut cells: Vec<(PlmnId, u64)> = last_known.cloned().into_iter().collect();
    let predicted = (p.plmn_id.clone(), p.nci);
    if !cells.contains(&predicted) {
        cells.push(predicted);
    }
    cells
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
        format!(
            "demo:\n  enabled: true\n  d440c-nwdaf-paging:\n    enabled: true\n    mode: {mode}\n"
        )
    }

    /// The two registered modes activate. An unknown mode fails, and so does
    /// `ran-recommendation` until #462's amfd demo lands: there is no fallback.
    #[test]
    fn only_the_implemented_modes_are_accepted() {
        for mode in [MODE_NWDAF_MOBILITY, MODE_REGISTRATION_AREA] {
            let active = validate(&block(mode)).expect("valid");
            assert_eq!(active.mode(DEMO_KEY), Some(mode));
            assert_eq!(
                active.banner().as_deref(),
                Some(format!("DEMO MODE ACTIVE: d440c-nwdaf-paging={mode}").as_str())
            );
        }
        for mode in ["bogus", "ran-recommendation"] {
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
        let off = [
            String::new(),
            "demo:\n  enabled: false\n  d440c-nwdaf-paging:\n    enabled: true\n    mode: nwdaf-mobility\n"
                .to_string(),
            "demo:\n  enabled: true\n  d440c-nwdaf-paging:\n    enabled: false\n    mode: nwdaf-mobility\n"
                .to_string(),
        ];
        for yaml in off {
            let root = if yaml.is_empty() {
                "amf: {}\n".to_string()
            } else {
                yaml
            };
            let active = validate(&root).expect("valid");
            assert!(active.is_empty(), "{root}");
            assert_eq!(
                effective_strategy(PagingStrategy::RecommendedFirst, active.mode(DEMO_KEY)),
                PagingStrategy::RecommendedFirst
            );
        }
    }

    #[test]
    fn the_mode_forces_the_effective_strategy() {
        assert_eq!(
            effective_strategy(PagingStrategy::RegistrationArea, Some(MODE_NWDAF_MOBILITY)),
            PagingStrategy::NwdafMobility
        );
        assert_eq!(
            effective_strategy(PagingStrategy::NwdafMobility, Some(MODE_REGISTRATION_AREA)),
            PagingStrategy::RegistrationArea
        );
    }

    /// The ticket's success-signal shapes.
    #[test]
    fn the_demo_lines_carry_scope_targets_and_attempt() {
        assert_eq!(
            paging_sent_line(1, Scope::NwdafMobility, &[0x2], 1),
            "Paging sent to 1/1 scope=nwdaf-mobility targets=[gNB 0x2] attempt 1"
        );
        assert_eq!(
            paging_sent_line(2, Scope::RegistrationArea, &[0x1, 0x3], 2),
            "Paging sent to 2/2 scope=registration-area targets=[gNB 0x1,gNB 0x3] attempt 2"
        );
        assert_eq!(
            page_answered_line("imsi-001010000000001", Some(0x2), 1),
            "page answered ue=imsi-001010000000001 via gNB 0x2 attempt 1"
        );
    }

    #[test]
    fn the_recommended_cells_are_the_last_known_then_the_predicted() {
        let plmn = PlmnId::new("001", "01");
        let p = crate::context::PredictedCell {
            plmn_id: plmn.clone(),
            nci: 0x8001,
            confidence: Some(60),
        };
        assert_eq!(
            recommended_cells(Some(&(plmn.clone(), 0x4001)), Some(&p)),
            vec![(plmn.clone(), 0x4001), (plmn.clone(), 0x8001)]
        );
        assert_eq!(
            recommended_cells(None, Some(&p)),
            vec![(plmn.clone(), 0x8001)]
        );
        assert_eq!(
            recommended_cells(Some(&(plmn.clone(), 0x8001)), Some(&p)),
            vec![(plmn.clone(), 0x8001)],
            "a prediction of the last known cell is listed once"
        );
        assert!(recommended_cells(Some(&(plmn, 0x4001)), None).is_empty());
    }
}
