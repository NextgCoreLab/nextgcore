//! The PCF's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`), then the PCF's own:
//!
//! - the policy association census at scrape time, by kind: AM (TS 29.507), SM
//!   (TS 29.512), UE (TS 29.525) policy associations and policy authorization
//!   application sessions (TS 29.514), and the event exposure subscriptions
//!   (TS 29.523);
//! - `pcf_policy_operations_total{policy,operation,result}`: every create, update and
//!   delete of those resources the PCF answered, success being a 2xx.

use nextgcore_metrics::nf::{write_header, write_metric};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Policy resource kinds.
pub const POLICIES: [&str; 4] = ["am", "sm", "ue", "app_session"];
/// Operations on them.
pub const OPERATIONS: [&str; 3] = ["create", "update", "delete"];

fn counters() -> &'static [AtomicU64] {
    static C: std::sync::OnceLock<Vec<AtomicU64>> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        (0..POLICIES.len() * OPERATIONS.len() * 2)
            .map(|_| AtomicU64::new(0))
            .collect()
    })
}

fn slot(policy: usize, op: usize, ok: bool) -> usize {
    (policy * OPERATIONS.len() + op) * 2 + usize::from(ok)
}

/// Which policy operation a request is: indices into [`POLICIES`] and
/// [`OPERATIONS`], from the path segments after the leading `/` and the method.
pub fn classify(parts: &[&str], method: &str) -> Option<(usize, usize)> {
    let (service, resource) = (*parts.first()?, *parts.get(2)?);
    let sub = parts.get(4).copied();
    let item = parts.len() >= 4;
    let policy = match (service, resource) {
        ("npcf-am-policy-control", "policies") => 0,
        ("npcf-smpolicycontrol", "sm-policies") => 1,
        ("npcf-ue-policy-control", "policies") => 2,
        ("npcf-policyauthorization", "app-sessions") => 3,
        _ => return None,
    };
    let op = match (method, item, sub) {
        ("POST", false, _) => 0,
        ("POST", true, Some("update")) | ("PATCH", true, _) => 1,
        ("POST", true, Some("delete")) | ("DELETE", true, _) => 2,
        _ => return None,
    };
    Some((policy, op))
}

/// Count a policy operation answered with `status`.
pub fn observe(policy: usize, op: usize, status: u16) {
    counters()[slot(policy, op, (200..300).contains(&status))].fetch_add(1, Ordering::Relaxed);
}

/// The PCF's live state at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct PcfCensus {
    pub am: usize,
    pub sm: usize,
    pub ue: usize,
    pub app_sessions: usize,
    pub event_subscriptions: usize,
}

/// Render the PCF families for `census`.
pub fn render_pcf_families(out: &mut String, census: &PcfCensus) {
    write_header(out, "pcf_policy_associations", "gauge",
        "Policy associations the PCF holds, by kind (am TS 29.507, sm TS 29.512, ue TS 29.525, app_session TS 29.514)");
    for (kind, n) in [
        ("am", census.am),
        ("sm", census.sm),
        ("ue", census.ue),
        ("app_session", census.app_sessions),
    ] {
        let _ = writeln!(out, "pcf_policy_associations{{policy=\"{kind}\"}} {n}");
    }
    write_metric(
        out,
        "pcf_event_subscriptions",
        "gauge",
        "Npcf_EventExposure subscriptions the PCF holds (TS 29.523)",
        census.event_subscriptions,
    );
    write_header(out, "pcf_policy_operations_total", "counter",
        "Policy association creates, updates and deletes the PCF answered, by result (success = 2xx)");
    for (p, policy) in POLICIES.iter().enumerate() {
        for (o, op) in OPERATIONS.iter().enumerate() {
            for (ok, result) in [(true, "success"), (false, "failure")] {
                let n = counters()[slot(p, o, ok)].load(Ordering::Relaxed);
                let _ = writeln!(out,
                    "pcf_policy_operations_total{{policy=\"{policy}\",operation=\"{op}\",result=\"{result}\"}} {n}");
            }
        }
    }
}

fn census() -> PcfCensus {
    let ctx = crate::context::pcf_self();
    let Ok(ctx) = ctx.read() else {
        return PcfCensus::default();
    };
    PcfCensus {
        am: ctx.ue_am_count(),
        sm: ctx.sess_count(),
        ue: crate::ue_policy::ue_policy_count(),
        app_sessions: ctx.app_count(),
        event_subscriptions: ctx.event_sub_count(),
    }
}

/// The whole PCF `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "pcf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    render_pcf_families(&mut out, &census());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_classified_by_policy_kind_and_operation() {
        let c = |p: &str, m: &str| {
            let parts: Vec<&str> = p.trim_start_matches('/').split('/').collect();
            classify(&parts, m)
        };
        assert_eq!(
            c("/npcf-am-policy-control/v1/policies", "POST"),
            Some((0, 0))
        );
        assert_eq!(
            c("/npcf-am-policy-control/v1/policies/x/update", "POST"),
            Some((0, 1))
        );
        assert_eq!(
            c("/npcf-am-policy-control/v1/policies/x", "DELETE"),
            Some((0, 2))
        );
        assert_eq!(c("/npcf-am-policy-control/v1/policies/x", "GET"), None);
        assert_eq!(
            c("/npcf-smpolicycontrol/v1/sm-policies", "POST"),
            Some((1, 0))
        );
        assert_eq!(
            c("/npcf-smpolicycontrol/v1/sm-policies/1/update", "POST"),
            Some((1, 1))
        );
        assert_eq!(
            c("/npcf-smpolicycontrol/v1/sm-policies/1/delete", "POST"),
            Some((1, 2))
        );
        assert_eq!(
            c("/npcf-ue-policy-control/v1/policies", "POST"),
            Some((2, 0))
        );
        assert_eq!(
            c(
                "/npcf-ue-policy-control/v1/notify/x/n1-message-notify",
                "POST"
            ),
            None
        );
        assert_eq!(
            c("/npcf-policyauthorization/v1/app-sessions", "POST"),
            Some((3, 0))
        );
        assert_eq!(
            c("/npcf-policyauthorization/v1/app-sessions/a", "PATCH"),
            Some((3, 1))
        );
        assert_eq!(
            c("/npcf-policyauthorization/v1/app-sessions/a/delete", "POST"),
            Some((3, 2))
        );
    }

    #[test]
    fn the_census_renders_by_kind() {
        let mut out = String::new();
        render_pcf_families(
            &mut out,
            &PcfCensus {
                am: 1,
                sm: 2,
                ue: 3,
                app_sessions: 4,
                event_subscriptions: 5,
            },
        );
        let v = |s| nextgcore_metrics::nf::sample_value(&out, s);
        assert_eq!(v(r#"pcf_policy_associations{policy="am"}"#), Some(1.0));
        assert_eq!(v(r#"pcf_policy_associations{policy="sm"}"#), Some(2.0));
        assert_eq!(v(r#"pcf_policy_associations{policy="ue"}"#), Some(3.0));
        assert_eq!(
            v(r#"pcf_policy_associations{policy="app_session"}"#),
            Some(4.0)
        );
        assert_eq!(v("pcf_event_subscriptions"), Some(5.0));
    }
}
