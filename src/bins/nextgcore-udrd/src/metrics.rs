//! The UDR's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`), then the UDR's own:
//! `udr_operations_total{data,operation,result}`, every Nudr_DataRepository
//! (TS 29.504) and Nudr_GroupIDmap (TS 29.598) operation answered by data set
//! (subscription, policy, application, exposure data, data change subscriptions,
//! group id map) and method-level operation, success being a 2xx; and the UE
//! contexts at scrape time.

use nextgcore_metrics::nf::{result_of, write_metric, CounterFamily};

static OPERATIONS: CounterFamily = CounterFamily::new(
    "udr_operations_total",
    "Nudr operations answered (TS 29.504, TS 29.598), by data set, operation and result (success = 2xx)",
    &["data", "operation", "result"],
);

/// Which Nudr operation `method` on `uri` is: `(data set, operation)`.
pub fn classify(method: &str, uri: &str) -> Option<(&'static str, &'static str)> {
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let data = match (parts.first().copied()?, parts.get(2).copied().unwrap_or("")) {
        ("nudr-group-id-map", _) => "group_id_map",
        ("nudr-dr", _) if parts.contains(&"subs-to-notify") => "data_change_subscription",
        ("nudr-dr", "subscription-data") => "subscription_data",
        ("nudr-dr", "policy-data") => "policy_data",
        ("nudr-dr", "application-data") => "application_data",
        ("nudr-dr", "exposure-data") => "exposure_data",
        ("nudr-dr", _) => "other",
        _ => return None,
    };
    let operation = match method {
        "GET" => "query",
        "PUT" => "create_or_replace",
        "POST" => "create",
        "PATCH" => "update",
        "DELETE" => "delete",
        _ => "other",
    };
    Some((data, operation))
}

/// Count `op`, answered with `status`.
pub fn observe((data, op): (&'static str, &'static str), status: u16) {
    OPERATIONS.inc(&[data, op, result_of(status)]);
}

/// Render the UDR families for `ue_contexts`.
pub fn render_udr_families(out: &mut String, ue_contexts: usize) {
    write_metric(
        out,
        "udr_ue_contexts",
        "gauge",
        "UE contexts the UDR holds",
        ue_contexts,
    );
    OPERATIONS.render(out);
}

/// The whole UDR `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "udr",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    let ues = crate::context::udr_self()
        .read()
        .map(|c| c.ue_count())
        .unwrap_or(0);
    render_udr_families(&mut out, ues);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nudr_requests_are_classified() {
        let s = "imsi-001010000000001";
        assert_eq!(classify("GET", &format!("/nudr-dr/v2/subscription-data/{s}/authentication-data/authentication-subscription")), Some(("subscription_data", "query")));
        assert_eq!(classify("PATCH", &format!("/nudr-dr/v2/subscription-data/{s}/authentication-data/authentication-subscription")), Some(("subscription_data", "update")));
        assert_eq!(
            classify("POST", "/nudr-dr/v2/subscription-data/subs-to-notify"),
            Some(("data_change_subscription", "create"))
        );
        assert_eq!(
            classify("GET", &format!("/nudr-dr/v2/policy-data/ues/{s}/am-data")),
            Some(("policy_data", "query"))
        );
        assert_eq!(
            classify("GET", "/nudr-group-id-map/v1/nf-group-ids"),
            Some(("group_id_map", "query"))
        );
        assert_eq!(classify("GET", "/nudm-sdm/v2/x"), None);
    }
}
