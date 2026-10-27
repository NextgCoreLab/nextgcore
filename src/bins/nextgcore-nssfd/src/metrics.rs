//! The NSSF's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`), then the NSSF's own:
//! Nnssf_NSSelection (TS 29.531 §5.2) and Nnssf_NSSAIAvailability (§5.3) operations by
//! result (success = 2xx), and the stored state at scrape time.

use nextgcore_metrics::nf::{result_of, write_metric, CounterFamily};

static SELECTIONS: CounterFamily = CounterFamily::new(
    "nssf_selections_total",
    "Nnssf_NSSelection_Get requests answered (TS 29.531 §5.2.2.2), by result (success = 2xx)",
    &["result"],
);

static AVAILABILITY_OPERATIONS: CounterFamily = CounterFamily::new(
    "nssf_availability_operations_total",
    "Nnssf_NSSAIAvailability operations answered (TS 29.531 §5.3), by operation and result",
    &["operation", "result"],
);

/// A request the NSSF counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssfOperation {
    /// `GET /nnssf-nsselection/v2/network-slice-information`.
    Selection,
    /// An Nnssf_NSSAIAvailability operation.
    Availability(&'static str),
}

/// Which NSSF operation `method` on `uri` is.
pub fn classify(method: &str, uri: &str) -> Option<NssfOperation> {
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    match (parts.first().copied(), parts.get(2).copied()) {
        (Some("nnssf-nsselection"), Some("network-slice-information"))
            if method == "GET" && parts.len() == 3 =>
        {
            Some(NssfOperation::Selection)
        }
        (Some("nnssf-nssaiavailability"), Some("nssai-availability")) => {
            let op = match (parts.len(), parts.get(3).copied(), method) {
                (4, Some("subscriptions"), "POST") => "subscribe",
                (5, Some("subscriptions"), "DELETE") => "unsubscribe",
                (5, Some("subscriptions"), "PATCH") => "modify_subscription",
                (4, Some(_), "PUT") => "update",
                (4, Some(_), "PATCH") => "patch",
                (4, Some(_), "DELETE") => "delete",
                _ => return None,
            };
            Some(NssfOperation::Availability(op))
        }
        _ => None,
    }
}

/// Count `op`, answered with `status`.
pub fn observe(op: NssfOperation, status: u16) {
    match op {
        NssfOperation::Selection => SELECTIONS.inc(&[result_of(status)]),
        NssfOperation::Availability(o) => AVAILABILITY_OPERATIONS.inc(&[o, result_of(status)]),
    }
}

/// The NSSF's state at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct NssfCensus {
    pub availability_nfs: usize,
    pub subscriptions: usize,
    pub slice_instances: usize,
}

/// Render the NSSF families for `census`.
pub fn render_nssf_families(out: &mut String, census: &NssfCensus) {
    write_metric(
        out,
        "nssf_nssai_availability_nfs",
        "gauge",
        "NFs whose NSSAI availability the NSSF stores (TS 29.531 §5.3.2.2)",
        census.availability_nfs,
    );
    write_metric(
        out,
        "nssf_subscriptions",
        "gauge",
        "NSSAI availability subscriptions the NSSF holds",
        census.subscriptions,
    );
    write_metric(
        out,
        "nssf_network_slice_instances",
        "gauge",
        "Network slice instances configured",
        census.slice_instances,
    );
    SELECTIONS.render(out);
    AVAILABILITY_OPERATIONS.render(out);
}

fn census() -> NssfCensus {
    let ctx = crate::context::nssf_self();
    let Ok(ctx) = ctx.read() else {
        return NssfCensus::default();
    };
    NssfCensus {
        availability_nfs: ctx.nssai_availability_count(),
        subscriptions: ctx.subscription_count(),
        slice_instances: ctx.nsi_count(),
    }
}

/// The whole NSSF `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "nssf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    render_nssf_families(&mut out, &census());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nssf_requests_are_classified() {
        use NssfOperation::*;
        assert_eq!(
            classify(
                "GET",
                "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF"
            ),
            Some(Selection)
        );
        assert_eq!(
            classify("POST", "/nnssf-nsselection/v2/network-slice-information"),
            None
        );
        assert_eq!(
            classify("PUT", "/nnssf-nssaiavailability/v1/nssai-availability/nf-1"),
            Some(Availability("update"))
        );
        assert_eq!(
            classify(
                "POST",
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions"
            ),
            Some(Availability("subscribe"))
        );
        assert_eq!(
            classify(
                "DELETE",
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/s"
            ),
            Some(Availability("unsubscribe"))
        );
        assert_eq!(
            classify("OPTIONS", "/nnssf-nssaiavailability/v1/nssai-availability"),
            None
        );
    }
}
