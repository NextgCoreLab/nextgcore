//! The BSF's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`), then the BSF's own:
//! the binding census at scrape time (PDU session, UE and MBS session bindings,
//! TS 29.521 §4.2.2-§4.2.5, and event subscriptions §4.2.6), and every
//! Nbsf_Management operation the BSF answered, by result (success = 2xx).

use nextgcore_metrics::nf::{result_of, write_header, write_metric, CounterFamily};
use std::fmt::Write as _;

static BINDING_OPERATIONS: CounterFamily = CounterFamily::new(
    "bsf_binding_operations_total",
    "Nbsf_Management binding operations answered, by binding kind, operation and result (success = 2xx)",
    &["binding", "operation", "result"],
);

static SUBSCRIPTION_OPERATIONS: CounterFamily = CounterFamily::new(
    "bsf_subscription_operations_total",
    "Nbsf_Management event subscription operations answered, by operation and result",
    &["operation", "result"],
);

/// A request the BSF counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsfOperation {
    /// `(binding kind, operation)` on `pcfBindings` / `pcf-ue-bindings` / `pcf-mbs-bindings`.
    Binding(&'static str, &'static str),
    /// An operation on `subscriptions`.
    Subscription(&'static str),
}

/// Which Nbsf_Management operation `method` on `uri` is (TS 29.521 §5.3).
pub fn classify(method: &str, uri: &str) -> Option<BsfOperation> {
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.first() != Some(&"nbsf-management") || parts.len() < 3 {
        return None;
    }
    let item = parts.len() >= 4;
    let binding = match parts[2] {
        "pcfBindings" => "pdu",
        "pcf-ue-bindings" => "ue",
        "pcf-mbs-bindings" => "mbs",
        "subscriptions" => {
            return match (method, item) {
                ("POST", false) => Some(BsfOperation::Subscription("subscribe")),
                ("PUT", true) => Some(BsfOperation::Subscription("modify")),
                ("DELETE", true) => Some(BsfOperation::Subscription("unsubscribe")),
                _ => None,
            }
        }
        _ => return None,
    };
    let operation = match (method, item) {
        ("POST", false) => "register",
        ("GET", false) => "discovery",
        ("GET", true) => "retrieve",
        ("PATCH", true) => "update",
        ("DELETE", true) => "deregister",
        _ => return None,
    };
    Some(BsfOperation::Binding(binding, operation))
}

/// Count `op`, answered with `status`.
pub fn observe(op: BsfOperation, status: u16) {
    match op {
        BsfOperation::Binding(b, o) => BINDING_OPERATIONS.inc(&[b, o, result_of(status)]),
        BsfOperation::Subscription(o) => SUBSCRIPTION_OPERATIONS.inc(&[o, result_of(status)]),
    }
}

/// The BSF's live state at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct BsfCensus {
    pub pdu_bindings: usize,
    pub ue_bindings: usize,
    pub mbs_bindings: usize,
    pub subscriptions: usize,
}

/// Render the BSF families for `census`.
pub fn render_bsf_families(out: &mut String, census: &BsfCensus) {
    write_header(
        out,
        "bsf_pcf_bindings",
        "gauge",
        "PCF bindings the BSF holds, by kind (pdu, ue, mbs; TS 29.521)",
    );
    for (kind, n) in [
        ("pdu", census.pdu_bindings),
        ("ue", census.ue_bindings),
        ("mbs", census.mbs_bindings),
    ] {
        let _ = writeln!(out, "bsf_pcf_bindings{{binding=\"{kind}\"}} {n}");
    }
    write_metric(
        out,
        "bsf_subscriptions",
        "gauge",
        "Nbsf_Management event subscriptions the BSF holds",
        census.subscriptions,
    );
    BINDING_OPERATIONS.render(out);
    SUBSCRIPTION_OPERATIONS.render(out);
}

fn census() -> BsfCensus {
    let ctx = crate::context::bsf_self();
    let Ok(ctx) = ctx.read() else {
        return BsfCensus::default();
    };
    BsfCensus {
        pdu_bindings: ctx.sess_count(),
        ue_bindings: ctx.ue_binding_count(),
        mbs_bindings: ctx.mbs_binding_count(),
        subscriptions: ctx.subscription_count(),
    }
}

/// The whole BSF `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "bsf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    render_bsf_families(&mut out, &census());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbsf_management_requests_are_classified() {
        use BsfOperation::*;
        assert_eq!(
            classify("POST", "/nbsf-management/v1/pcfBindings"),
            Some(Binding("pdu", "register"))
        );
        assert_eq!(
            classify("GET", "/nbsf-management/v1/pcfBindings?ipv4Addr=10.45.0.2"),
            Some(Binding("pdu", "discovery"))
        );
        assert_eq!(
            classify("DELETE", "/nbsf-management/v1/pcfBindings/1"),
            Some(Binding("pdu", "deregister"))
        );
        assert_eq!(
            classify("PATCH", "/nbsf-management/v1/pcf-ue-bindings/a"),
            Some(Binding("ue", "update"))
        );
        assert_eq!(
            classify("GET", "/nbsf-management/v1/pcf-mbs-bindings/a"),
            Some(Binding("mbs", "retrieve"))
        );
        assert_eq!(
            classify("POST", "/nbsf-management/v1/subscriptions"),
            Some(Subscription("subscribe"))
        );
        assert_eq!(
            classify("DELETE", "/nbsf-management/v1/subscriptions/s"),
            Some(Subscription("unsubscribe"))
        );
        assert_eq!(classify("GET", "/nbsf-management/v1/subscriptions"), None);
        assert_eq!(classify("GET", "/nnrf-disc/v1/nf-instances"), None);
    }
}
