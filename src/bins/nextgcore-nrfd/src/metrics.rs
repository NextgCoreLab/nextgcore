//! The NRF's Prometheus exposition (#1334).
//!
//! The families every NF shares (`nextgcore_metrics::nf`; the NRF is no NRF client,
//! so without the `nextgcore_nrf_*` client families), then the NRF's own:
//!
//! - the registry census at scrape time: `nrf_registered_nf_count` (every profile the
//!   NRF holds, the series the shipped `NrfLowRegisteredNfs` alert reads),
//!   `nrf_registered_nf_instances{nf_type,nf_status}` and `nrf_subscriptions`;
//! - NFManagement outcomes (TS 29.510 §5.2.2): registrations, updates (heartbeats),
//!   deregistrations, subscriptions created;
//! - NFDiscovery outcomes (§5.3.2): a SearchResult (200) is a success, a rejected
//!   query (any other status) a failure, the pair the shipped
//!   `NrfDiscoveryFailureRate` alert divides. An empty SearchResult is a success of
//!   the NRF (nothing of that type is registered, routine for an optional NF such as
//!   a UCMF or an NSACF) and is also counted on its own;
//! - AccessToken outcomes (§5.4.2): granted / denied.
//!
//! `nf_type` comes from the registrant's profile, so it is kept only when it is a
//! TS 29.510 `NFType` value this tree knows; anything else is `other`.

use nextgcore_metrics::nf::{labels, write_header, write_metric};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

static REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static UPDATES: AtomicU64 = AtomicU64::new(0);
static DEREGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static SUBSCRIPTIONS_CREATED: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_SUCCESS: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_FAILURE: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_EMPTY: AtomicU64 = AtomicU64::new(0);
static TOKENS_GRANTED: AtomicU64 = AtomicU64::new(0);
static TOKENS_DENIED: AtomicU64 = AtomicU64::new(0);

/// What an NRF request was, for the outcome counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrfOperation {
    /// `PUT /nnrf-nfm/v1/nf-instances/{id}` (NFRegister, or a complete replacement).
    Register,
    /// `PATCH /nnrf-nfm/v1/nf-instances/{id}` (NFUpdate, the heartbeat).
    Update,
    /// `DELETE /nnrf-nfm/v1/nf-instances/{id}` (NFDeregister).
    Deregister,
    /// `POST /nnrf-nfm/v1/subscriptions` (NFStatusSubscribe).
    Subscribe,
    /// `POST /nnrf-oauth2/v1/access-token`.
    AccessToken,
}

/// Count the outcome of `op`, answered with `status`.
pub fn observe(op: NrfOperation, status: u16) {
    let ok = (200..300).contains(&status);
    let counter = match (op, ok) {
        (NrfOperation::Register, true) => &REGISTRATIONS,
        (NrfOperation::Update, true) => &UPDATES,
        (NrfOperation::Deregister, true) => &DEREGISTRATIONS,
        (NrfOperation::Subscribe, true) => &SUBSCRIPTIONS_CREATED,
        (NrfOperation::AccessToken, true) => &TOKENS_GRANTED,
        (NrfOperation::AccessToken, false) => &TOKENS_DENIED,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Count one NFDiscovery: answered with `found` matching instances, or `None` when
/// the query was rejected.
pub fn observe_discovery(found: Option<usize>) {
    match found {
        Some(n) => {
            DISCOVERY_SUCCESS.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                DISCOVERY_EMPTY.fetch_add(1, Ordering::Relaxed);
            }
        }
        None => {
            DISCOVERY_FAILURE.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// TS 29.510 §6.1.6.3.3 `NFType` values kept as label values.
const KNOWN_NF_TYPES: [&str; 40] = [
    "NRF", "UDM", "AMF", "SMF", "AUSF", "NEF", "PCF", "SMSF", "NSSF", "UDR", "LMF", "GMLC",
    "5G_EIR", "SEPP", "UPF", "N3IWF", "AF", "UDSF", "BSF", "CHF", "NWDAF", "PCSCF", "CBCF", "HSS",
    "UCMF", "SOR_AF", "SPAF", "MME", "SCSAS", "SCEF", "SCP", "NSSAAF", "ICSCF", "SCSCF", "DRA",
    "IMS_AS", "AANF", "5G_DDNMF", "NSACF", "MFAF",
];

/// Further `NFType` values (Rel-17/18) this tree registers.
const MORE_NF_TYPES: [&str; 10] = [
    "EASDF", "DCCF", "MB_SMF", "TSCTSF", "ADRF", "GBA_BSF", "CEF", "MB_UPF", "NSWOF", "PKMF",
];

fn nf_type_label(t: &str) -> &str {
    if KNOWN_NF_TYPES.contains(&t) || MORE_NF_TYPES.contains(&t) || t == "EES" || t == "PIN" {
        t
    } else {
        "other"
    }
}

fn nf_status_label(s: &str) -> &str {
    match s {
        "REGISTERED" | "SUSPENDED" | "UNDISCOVERABLE" | "CANARY_RELEASE" => s,
        _ => "other",
    }
}

/// Render the NRF families for the registry `census` (`(nfType, nfStatus, count)`)
/// and `subscriptions`.
pub fn render_nrf_families(
    out: &mut String,
    census: &[(String, String, usize)],
    subscriptions: usize,
) {
    let total: usize = census.iter().map(|(_, _, n)| n).sum();
    write_metric(
        out,
        "nrf_registered_nf_count",
        "gauge",
        "NF profiles the NRF holds (TS 29.510 §5.2.2.2)",
        total,
    );
    let mut by_label: std::collections::BTreeMap<(&str, &str), usize> = Default::default();
    for (t, s, n) in census {
        *by_label
            .entry((nf_type_label(t), nf_status_label(s)))
            .or_insert(0) += n;
    }
    write_header(
        out,
        "nrf_registered_nf_instances",
        "gauge",
        "NF profiles the NRF holds, by nfType and nfStatus",
    );
    for ((t, s), n) in by_label {
        let _ = writeln!(
            out,
            "nrf_registered_nf_instances{} {n}",
            labels(&[("nf_type", t), ("nf_status", s)])
        );
    }
    write_metric(
        out,
        "nrf_subscriptions",
        "gauge",
        "NF status subscriptions the NRF holds (TS 29.510 §5.2.2.5)",
        subscriptions,
    );
    let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
    write_metric(
        out,
        "nrf_nf_registrations_total",
        "counter",
        "NFRegister requests accepted (PUT nf-instances, 2xx)",
        get(&REGISTRATIONS),
    );
    write_metric(
        out,
        "nrf_nf_updates_total",
        "counter",
        "NFUpdate requests accepted (PATCH nf-instances, 2xx), heartbeats included",
        get(&UPDATES),
    );
    write_metric(
        out,
        "nrf_nf_deregistrations_total",
        "counter",
        "NFDeregister requests accepted (DELETE nf-instances, 2xx)",
        get(&DEREGISTRATIONS),
    );
    write_metric(
        out,
        "nrf_subscriptions_created_total",
        "counter",
        "NFStatusSubscribe requests accepted",
        get(&SUBSCRIPTIONS_CREATED),
    );
    write_metric(
        out,
        "nrf_discovery_success_total",
        "counter",
        "NFDiscover requests answered with a SearchResult (200), empty ones included",
        get(&DISCOVERY_SUCCESS),
    );
    write_metric(
        out,
        "nrf_discovery_failure_total",
        "counter",
        "NFDiscover requests rejected (any status other than 200)",
        get(&DISCOVERY_FAILURE),
    );
    write_metric(
        out,
        "nrf_discovery_empty_total",
        "counter",
        "NFDiscover SearchResults that matched no NF instance",
        get(&DISCOVERY_EMPTY),
    );
    write_header(
        out,
        "nrf_access_tokens_total",
        "counter",
        "Access token requests (TS 29.510 §5.4.2), by result",
    );
    let _ = writeln!(
        out,
        "nrf_access_tokens_total{{result=\"granted\"}} {}",
        get(&TOKENS_GRANTED)
    );
    let _ = writeln!(
        out,
        "nrf_access_tokens_total{{result=\"denied\"}} {}",
        get(&TOKENS_DENIED)
    );
}

/// The whole NRF `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "nrf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: false,
    });
    let manager = crate::nnrf_handler::nf_manager();
    render_nrf_families(
        &mut out,
        &manager.profile_census(),
        manager.subscription_count(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_census_is_labelled_by_known_types_only() {
        let mut out = String::new();
        render_nrf_families(
            &mut out,
            &[
                ("AMF".into(), "REGISTERED".into(), 2),
                ("SMF".into(), "SUSPENDED".into(), 1),
                ("imsi-001010000000001".into(), "x".into(), 1),
            ],
            3,
        );
        let v = |s| nextgcore_metrics::nf::sample_value(&out, s);
        assert_eq!(v("nrf_registered_nf_count"), Some(4.0));
        assert_eq!(
            v(r#"nrf_registered_nf_instances{nf_type="AMF",nf_status="REGISTERED"}"#),
            Some(2.0)
        );
        assert_eq!(
            v(r#"nrf_registered_nf_instances{nf_type="other",nf_status="other"}"#),
            Some(1.0)
        );
        assert_eq!(v("nrf_subscriptions"), Some(3.0));
        assert!(!out.contains("imsi"), "{out}");
    }
}
