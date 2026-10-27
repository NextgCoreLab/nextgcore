//! The AUSF's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`), then the AUSF's own:
//!
//! - `ausf_operations_total{operation,result}`: every Nausf_UEAuthentication
//!   (TS 29.509 §5.2), Nausf_SoRProtection (§5.3) and Nausf_UPUProtection (§5.4)
//!   operation answered, success being a 2xx;
//! - `ausf_authentication_results_total{method,result}`: the authentication verdicts
//!   the AUSF returned, read from the `authResult` of a 5G-AKA confirmation
//!   (ConfirmationDataResponse) or a final EAP session answer (EapSession) — a
//!   verdict of AUTHENTICATION_FAILURE is still a 200, so the HTTP status alone
//!   cannot tell it;
//! - the UE authentication contexts and stored KAUSF anchors at scrape time.

use nextgcore_metrics::nf::{result_of, write_metric, CounterFamily};
use nextgcore_sbi::message::SbiResponse;

static OPERATIONS: CounterFamily = CounterFamily::new(
    "ausf_operations_total",
    "Nausf operations answered (TS 29.509), by operation and result (success = 2xx)",
    &["operation", "result"],
);

static RESULTS: CounterFamily = CounterFamily::new(
    "ausf_authentication_results_total",
    "Authentication verdicts returned (authResult, TS 29.509 §6.1.6.3.3), by method",
    &["method", "result"],
);

/// Which Nausf operation `method` on `uri` is (TS 29.509 §6.1.3, §6.2, §6.3).
pub fn classify(method: &str, uri: &str) -> Option<&'static str> {
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let sub = parts.get(4).copied();
    match (parts.first().copied()?, parts.get(2).copied(), method) {
        ("nausf-auth", Some("ue-authentications"), "POST") if sub == Some("eap-session") => {
            Some("eap_session")
        }
        ("nausf-auth", Some("ue-authentications"), "POST")
            if parts.get(3) == Some(&"deregister") =>
        {
            Some("deregister")
        }
        ("nausf-auth", Some("ue-authentications"), "POST") if parts.len() == 3 => {
            Some("authenticate")
        }
        ("nausf-auth", Some("ue-authentications"), "PUT") if sub == Some("5g-aka-confirmation") => {
            Some("5g_aka_confirmation")
        }
        ("nausf-auth", Some("ue-authentications"), "DELETE") if parts.len() >= 4 => Some("delete"),
        ("nausf-sorprotection", _, "POST") if parts.get(3) == Some(&"ue-sor") => {
            Some("sor_protection")
        }
        ("nausf-upuprotection", _, "POST") if parts.get(3) == Some(&"ue-upu") => {
            Some("upu_protection")
        }
        _ => None,
    }
}

/// Count `operation` answered with `response`, and the verdict it carries.
pub fn observe(operation: &'static str, response: &SbiResponse) {
    OPERATIONS.inc(&[operation, result_of(response.status)]);
    let method = match operation {
        "5g_aka_confirmation" => "5g_aka",
        "eap_session" => "eap_aka_prime",
        _ => return,
    };
    let verdict = response
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
        .and_then(|v| {
            v.get("authResult")
                .and_then(|r| r.as_str())
                .map(str::to_string)
        });
    let result = match verdict.as_deref() {
        Some("AUTHENTICATION_SUCCESS") => "success",
        Some("AUTHENTICATION_FAILURE") => "failure",
        // An EAP exchange still ongoing carries AUTHENTICATION_ONGOING or nothing.
        _ => return,
    };
    RESULTS.inc(&[method, result]);
}

/// The AUSF's state at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct AusfCensus {
    pub ue_contexts: usize,
    pub anchors: usize,
}

/// Render the AUSF families for `census`.
pub fn render_ausf_families(out: &mut String, census: &AusfCensus) {
    write_metric(
        out,
        "ausf_ue_authentication_contexts",
        "gauge",
        "UE authentication contexts the AUSF holds",
        census.ue_contexts,
    );
    write_metric(
        out,
        "ausf_kausf_anchors",
        "gauge",
        "KAUSF anchors stored for SoR/UPU protection (TS 33.501 §6.1.3)",
        census.anchors,
    );
    OPERATIONS.render(out);
    RESULTS.render(out);
}

fn census() -> AusfCensus {
    let ctx = crate::context::ausf_self();
    let Ok(ctx) = ctx.read() else {
        return AusfCensus::default();
    };
    AusfCensus {
        ue_contexts: ctx.ue_count(),
        anchors: ctx.anchor_count(),
    }
}

/// The whole AUSF `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "ausf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    render_ausf_families(&mut out, &census());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nausf_requests_are_classified() {
        assert_eq!(
            classify("POST", "/nausf-auth/v1/ue-authentications"),
            Some("authenticate")
        );
        assert_eq!(
            classify(
                "PUT",
                "/nausf-auth/v1/ue-authentications/c1/5g-aka-confirmation"
            ),
            Some("5g_aka_confirmation")
        );
        assert_eq!(
            classify("POST", "/nausf-auth/v1/ue-authentications/c1/eap-session"),
            Some("eap_session")
        );
        assert_eq!(
            classify("POST", "/nausf-auth/v1/ue-authentications/deregister"),
            Some("deregister")
        );
        assert_eq!(
            classify("DELETE", "/nausf-auth/v1/ue-authentications/c1"),
            Some("delete")
        );
        assert_eq!(
            classify(
                "POST",
                "/nausf-sorprotection/v1/imsi-001010000000001/ue-sor"
            ),
            Some("sor_protection")
        );
        assert_eq!(classify("GET", "/nausf-auth/v1/ue-authentications"), None);
    }

    #[test]
    fn the_verdict_is_read_from_auth_result() {
        let resp = |body: &str| {
            SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
        };
        let get = |m, r| RESULTS.get(&[m, r]);
        let (s0, f0) = (get("5g_aka", "success"), get("5g_aka", "failure"));
        observe(
            "5g_aka_confirmation",
            &resp(r#"{"authResult":"AUTHENTICATION_SUCCESS"}"#),
        );
        observe(
            "5g_aka_confirmation",
            &resp(r#"{"authResult":"AUTHENTICATION_FAILURE"}"#),
        );
        observe("5g_aka_confirmation", &resp("{}"));
        assert!(get("5g_aka", "success") > s0);
        assert!(get("5g_aka", "failure") > f0);
    }
}
