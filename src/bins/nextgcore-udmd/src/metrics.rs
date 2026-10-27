//! The UDM's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`), then the UDM's own:
//!
//! - `udm_operations_total{service,operation,result}`: every Nudm operation answered
//!   (TS 29.503), success being a 2xx. `operation` names the TS 29.503 service
//!   operation for the ones that matter operationally (authentication vector
//!   generation, AMF/SMF registration, SDM data retrieval and subscription) and is
//!   `other` for the rest of each service;
//! - the UE context census at scrape time (UEs, those with an AMF registered for
//!   3GPP access, PDU sessions, SDM subscriptions);
//! - with the `nes` feature, the NES energy gauges (#22).

use nextgcore_metrics::nf::{result_of, write_metric, CounterFamily};

/// The environment variable naming the UDM's `/metrics` port.
pub const METRICS_PORT_ENV: &str = "UDM_METRICS_PORT";

static OPERATIONS: CounterFamily = CounterFamily::new(
    "udm_operations_total",
    "Nudm operations answered (TS 29.503), by service, operation and result (success = 2xx)",
    &["service", "operation", "result"],
);

/// Which Nudm operation `method` on `uri` is: `(service, operation)`.
pub fn classify(method: &str, uri: &str) -> Option<(&'static str, &'static str)> {
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let service = crate::app::NUDM_SERVICE_NAMES
        .iter()
        .copied()
        .find(|s| Some(*s) == parts.first().copied())?;
    // parts: [service, version, ueId, resource, ...]
    let res = parts.get(3).copied().unwrap_or("");
    let sub = parts.get(4).copied().unwrap_or("");
    let op = match (service, method, res, sub) {
        ("nudm-ueau", "POST", "security-information", "generate-auth-data") => "generate_auth_data",
        ("nudm-ueau", "POST", "auth-events", "") => "auth_event",
        ("nudm-ueau", "PUT", "auth-events", _) => "auth_event_cancel",
        ("nudm-uecm", "PUT", "registrations", "amf-3gpp-access") => "amf_registration",
        ("nudm-uecm", "PATCH", "registrations", "amf-3gpp-access") => "amf_registration_update",
        ("nudm-uecm", "POST", "registrations", "amf-3gpp-access") => "amf_deregistration",
        ("nudm-uecm", "PUT", "registrations", "smf-registrations") => "smf_registration",
        ("nudm-uecm", "DELETE", "registrations", "smf-registrations") => "smf_deregistration",
        ("nudm-uecm", "GET", "registrations", _) => "get_registrations",
        ("nudm-sdm", "POST", "sdm-subscriptions", "") => "subscribe",
        ("nudm-sdm", "DELETE", "sdm-subscriptions", _) => "unsubscribe",
        ("nudm-sdm", "PATCH", "sdm-subscriptions", _) => "modify_subscription",
        ("nudm-sdm", "GET", _, _) => "get",
        _ => "other",
    };
    Some((service, op))
}

/// Count `op`, answered with `status`.
pub fn observe((service, op): (&'static str, &'static str), status: u16) {
    OPERATIONS.inc(&[service, op, result_of(status)]);
}

#[cfg(feature = "nes")]
static NES_GAUGES: std::sync::OnceLock<
    std::sync::Arc<nextgcore_metrics::nes_energy::EnergyGauges>,
> = std::sync::OnceLock::new();

/// Serve the NES energy gauges on the UDM's `/metrics` (#22, #1334).
#[cfg(feature = "nes")]
pub fn set_nes_gauges(gauges: std::sync::Arc<nextgcore_metrics::nes_energy::EnergyGauges>) {
    let _ = NES_GAUGES.set(gauges);
}

/// The UDM's state at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct UdmCensus {
    pub ues: usize,
    pub amf_registered_ues: usize,
    pub pdu_sessions: usize,
    pub sdm_subscriptions: usize,
}

/// Render the UDM families for `census`.
pub fn render_udm_families(out: &mut String, census: &UdmCensus) {
    write_metric(
        out,
        "udm_ue_contexts",
        "gauge",
        "UE contexts the UDM holds",
        census.ues,
    );
    write_metric(
        out,
        "udm_amf_registered_ues",
        "gauge",
        "UEs with an AMF registered for 3GPP access (Nudm_UECM, TS 29.503 §5.3.2.2)",
        census.amf_registered_ues,
    );
    write_metric(
        out,
        "udm_pdu_sessions",
        "gauge",
        "PDU sessions with an SMF registered (Nudm_UECM)",
        census.pdu_sessions,
    );
    write_metric(
        out,
        "udm_sdm_subscriptions",
        "gauge",
        "Nudm_SDM subscriptions the UDM holds (TS 29.503 §5.2.2.3)",
        census.sdm_subscriptions,
    );
    OPERATIONS.render(out);
}

fn census() -> UdmCensus {
    let ctx = crate::context::udm_self();
    let Ok(ctx) = ctx.read() else {
        return UdmCensus::default();
    };
    UdmCensus {
        ues: ctx.ue_count(),
        amf_registered_ues: ctx.amf_registered_ue_count(),
        pdu_sessions: ctx.sess_count(),
        sdm_subscriptions: ctx.sdm_subscription_count(),
    }
}

/// The whole UDM `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "udm",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    render_udm_families(&mut out, &census());
    #[cfg(feature = "nes")]
    if let Some(g) = NES_GAUGES.get() {
        out.push_str(&g.render_prometheus());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nudm_requests_are_classified() {
        let supi = "imsi-001010000000001";
        let c = |m, p: String| classify(m, &p);
        assert_eq!(
            c(
                "POST",
                format!("/nudm-ueau/v1/{supi}/security-information/generate-auth-data")
            ),
            Some(("nudm-ueau", "generate_auth_data"))
        );
        assert_eq!(
            c("POST", format!("/nudm-ueau/v1/{supi}/auth-events")),
            Some(("nudm-ueau", "auth_event"))
        );
        assert_eq!(
            c(
                "PUT",
                format!("/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access")
            ),
            Some(("nudm-uecm", "amf_registration"))
        );
        assert_eq!(
            c(
                "PUT",
                format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/5")
            ),
            Some(("nudm-uecm", "smf_registration"))
        );
        assert_eq!(
            c("GET", format!("/nudm-sdm/v2/{supi}/am-data")),
            Some(("nudm-sdm", "get"))
        );
        assert_eq!(
            c("POST", format!("/nudm-sdm/v2/{supi}/sdm-subscriptions")),
            Some(("nudm-sdm", "subscribe"))
        );
        assert_eq!(
            c("POST", format!("/nudm-ee/v1/{supi}/ee-subscriptions")),
            Some(("nudm-ee", "other"))
        );
        assert_eq!(c("GET", "/nausf-auth/v1/x".to_string()), None);
    }
}
