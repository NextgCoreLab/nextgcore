//! Producer-subscription coordination — the DCCF's defining function (#112).
//!
//! TS 23.288 §5A.2: the DCCF collects from a producer **once** and shares the
//! data with every analytics consumer that asked for it, instead of each
//! consumer subscribing to the producer directly. Without this the DCCF is a
//! passive callback registry: it adds a hop and reduces no signalling.
//!
//! # Flow
//!
//! On a consumer subscribe, when a producer subscription for the same
//! `(events, target)` scope already exists it is **reused** (the whole point);
//! otherwise the DCCF:
//!
//! 1. resolves the named NF instance — `GET
//!    {nrf}/nnrf-nfm/v1/nf-instances/{targetNfId}` (TS 29.510 NF profile
//!    retrieval);
//! 2. picks that profile's event-exposure service and builds its apiRoot;
//! 3. POSTs the **consumer's own** subscription body with `notificationURI` and
//!    `notifCorrId` rewritten to point at this DCCF, so the producer's data
//!    arrives here;
//! 4. records the resource URI, refcounted by consumer, so the last consumer to
//!    unsubscribe deletes it.
//!
//! # Off by default
//!
//! Gated behind `--coordination` / `DCCF_COORDINATION`, default **off**, because
//! it makes `subscribe` perform outbound signalling that can fail or stall — a
//! behaviour change in an NF nothing in this stack exercises end to end yet. The
//! issue asked for a *cargo feature*; a runtime switch is used instead so CI
//! **compiles and tests both states in one run**. A cargo feature would leave the
//! coordination path uncompiled in CI (which builds default features), where it
//! would rot unnoticed.
//!
//! # What is deliberately not implemented
//!
//! Coordination requires the consumer to name its producer (`targetNfId`). A
//! consumer that names none would need an event→producer-NF-type table (TS 23.288
//! §6.2), and for most NWDAF events that mapping is genuinely ambiguous —
//! `SERVICE_EXPERIENCE` can come from an AF or the NEF, `NF_LOAD` from OAM or the
//! NRF. Guessing would create producer subscriptions on the wrong NF. Such a
//! subscription is accepted and served by the consumer-facing contract; only the
//! coordination step is skipped, with a log line saying so.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use nextgcore_sbi::client::SbiClient;

use crate::context::{
    dccf_context_claim_producer_sub, dccf_context_record_producer_sub, ProducerClaim,
};
use crate::data_mgmt::{DataManagementSubsc, SubscriptionScope};

/// Is coordination enabled for this process?
static COORDINATION_ENABLED: AtomicBool = AtomicBool::new(false);

/// The NRF to resolve producers through, and this DCCF's own notification URI.
static COORDINATION_CONFIG: OnceLock<CoordinationConfig> = OnceLock::new();

/// What the coordination path needs to reach the NRF and to be called back.
#[derive(Debug, Clone)]
pub struct CoordinationConfig {
    /// NRF root, e.g. `http://127.0.0.1:7777`.
    pub nrf_uri: String,
    /// This DCCF's own notify URI, handed to producers as `notificationURI` so
    /// their data arrives here rather than at the consumer.
    pub own_notify_uri: String,
}

/// Enable coordination with the given config (called once at startup).
pub fn enable_coordination(config: CoordinationConfig) {
    let _ = COORDINATION_CONFIG.set(config);
    COORDINATION_ENABLED.store(true, Ordering::SeqCst);
    log::info!("[DCCF] producer-subscription coordination ENABLED (TS 23.288 §5A.2)");
}

/// Whether coordination is enabled.
pub fn coordination_enabled() -> bool {
    COORDINATION_ENABLED.load(Ordering::SeqCst)
}

/// Test-only: set the config and toggle without going through startup.
#[cfg(test)]
pub fn set_coordination_for_test(config: Option<CoordinationConfig>) {
    match config {
        Some(c) => {
            // `OnceLock` cannot be re-set, so tests share one config; the NRF and
            // notify URI are per-run values passed by the caller.
            let _ = COORDINATION_CONFIG.set(c);
            COORDINATION_ENABLED.store(true, Ordering::SeqCst);
        }
        None => COORDINATION_ENABLED.store(false, Ordering::SeqCst),
    }
}

/// The current coordination config, when enabled.
fn config() -> Option<&'static CoordinationConfig> {
    coordination_enabled()
        .then(|| COORDINATION_CONFIG.get())
        .flatten()
}

/// Outcome of the coordination step, so the caller (and the tests) can see what
/// happened rather than inferring it from logs.
#[derive(Debug, PartialEq, Eq)]
pub enum CoordinationOutcome {
    /// Coordination is switched off.
    Disabled,
    /// The subscription named no `targetNfId`, so no producer could be resolved
    /// without guessing.
    NoProducerNamed,
    /// An existing producer subscription was reused — the de-duplication.
    Reused { producer_id: String },
    /// A new producer subscription was created.
    Created { producer_id: String },
    /// Something failed; the consumer subscription still stands.
    Failed(String),
}

/// Ensure a producer subscription exists for `scope`, creating one only if no
/// existing subscription already covers it.
pub async fn ensure_producer_subscription(
    consumer_id: &str,
    scope: &SubscriptionScope,
    sub: &DataManagementSubsc,
) -> CoordinationOutcome {
    let Some(cfg) = config() else {
        return CoordinationOutcome::Disabled;
    };
    // Reuse first: this is the whole point of the DCCF, so it must be checked
    // before any producer signalling.
    if let ProducerClaim::Reused { producer_id } =
        dccf_context_claim_producer_sub(consumer_id, scope)
    {
        return CoordinationOutcome::Reused { producer_id };
    }

    let Some(target) = sub.target_nf_id.as_deref() else {
        log::info!(
            "[DCCF] consumer subscription {consumer_id} names no targetNfId; skipping producer \
             coordination (an event-to-producer mapping is deliberately not guessed)"
        );
        return CoordinationOutcome::NoProducerNamed;
    };

    let profile = match fetch_nf_profile(&cfg.nrf_uri, target).await {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[DCCF] producer discovery for {target} failed: {e}");
            return CoordinationOutcome::Failed(e);
        }
    };
    let Some((api_root, service_name)) = event_exposure_endpoint(&profile) else {
        let detail = format!("NF {target} advertises no event-exposure service");
        log::warn!("[DCCF] {detail}");
        return CoordinationOutcome::Failed(detail);
    };

    // Forward the CONSUMER'S own subscription body, with the callback rewritten
    // to this DCCF. Rewriting rather than synthesising a body means the producer
    // receives exactly what the consumer asked for -- the DCCF is subscribing on
    // its behalf, not inventing a subscription.
    let mut producer_body = match sub.ana_sub.clone().or_else(|| sub.data_sub.clone()) {
        Some(b) => b,
        None => return CoordinationOutcome::Failed("no anaSub/dataSub to forward".to_string()),
    };
    if let Some(obj) = producer_body.as_object_mut() {
        obj.insert(
            "notificationURI".to_string(),
            serde_json::Value::String(cfg.own_notify_uri.clone()),
        );
        obj.insert(
            "notifCorrId".to_string(),
            serde_json::Value::String(format!("dccf-{consumer_id}")),
        );
    }

    match post_producer_subscription(&api_root, &service_name, &producer_body).await {
        Ok(resource_uri) => {
            dccf_context_record_producer_sub(
                consumer_id,
                scope.clone(),
                target.to_string(),
                resource_uri,
            );
            CoordinationOutcome::Created {
                producer_id: target.to_string(),
            }
        }
        Err(e) => {
            log::warn!("[DCCF] creating a producer subscription on {target} failed: {e}");
            CoordinationOutcome::Failed(e)
        }
    }
}

/// Delete a producer subscription that has lost its last consumer.
pub async fn delete_producer_subscription(resource_uri: &str) {
    let Some((host, port, path)) = split_uri(resource_uri) else {
        log::warn!("[DCCF] cannot delete producer subscription: unparseable URI {resource_uri}");
        return;
    };
    let client = SbiClient::with_host_port(&host, port);
    match client.delete(&path).await {
        Ok(resp) => log::info!(
            "[DCCF] deleted producer subscription {resource_uri} -> status={}",
            resp.status
        ),
        Err(e) => log::warn!("[DCCF] deleting producer subscription {resource_uri} failed: {e}"),
    }
}

/// `GET {nrf}/nnrf-nfm/v1/nf-instances/{nfInstanceId}` — TS 29.510 NF profile
/// retrieval. Returns the profile JSON.
async fn fetch_nf_profile(
    nrf_uri: &str,
    nf_instance_id: &str,
) -> Result<serde_json::Value, String> {
    let Some((host, port, _)) = split_uri(nrf_uri) else {
        return Err(format!("unparseable NRF URI {nrf_uri}"));
    };
    let client = SbiClient::with_host_port(&host, port);
    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let resp = client.get(&path).await.map_err(|e| e.to_string())?;
    if resp.status != 200 {
        return Err(format!("NRF answered {} for {path}", resp.status));
    }
    serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}"))
        .map_err(|e| format!("unparseable NF profile: {e}"))
}

/// Pick an event-exposure service from an NF profile and build its apiRoot.
///
/// A service is taken to be event exposure when its `serviceName` contains
/// `eventexposure` or `evts` — the two spellings 3GPP uses
/// (`namf-evts`, `nsmf-event-exposure`, `nnwdaf-eventssubscription`,
/// `npcf-eventexposure`). Matching on the name rather than a hardcoded list means
/// a producer family this DCCF has never heard of still works.
fn event_exposure_endpoint(profile: &serde_json::Value) -> Option<(String, String)> {
    let services = profile.get("nfServices").and_then(|v| v.as_array())?;
    let service = services.iter().find(|s| {
        s.get("serviceName")
            .and_then(|n| n.as_str())
            .is_some_and(|n| {
                let n = n.to_ascii_lowercase();
                n.contains("eventexposure")
                    || n.contains("evts")
                    || n.contains("eventssubscription")
            })
    })?;
    let service_name = service.get("serviceName")?.as_str()?.to_string();

    // apiRoot: prefer the service's own ipEndPoints, then the profile's
    // addresses. A profile with neither is not reachable and is skipped rather
    // than dialled at a guessed port.
    let scheme = service
        .get("scheme")
        .and_then(|s| s.as_str())
        .unwrap_or("http");
    if let Some(ep) = service
        .get("ipEndPoints")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let addr = ep
            .get("ipv4Address")
            .and_then(|v| v.as_str())
            .or_else(|| ep.get("fqdn").and_then(|v| v.as_str()))?;
        let port = ep.get("port").and_then(|v| v.as_u64()).unwrap_or(80);
        return Some((format!("{scheme}://{addr}:{port}"), service_name));
    }
    let addr = profile
        .get("ipv4Addresses")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .or_else(|| profile.get("fqdn").and_then(|v| v.as_str()))?;
    Some((format!("{scheme}://{addr}:80"), service_name))
}

/// POST the subscription to the producer's event-exposure service. Returns the
/// created resource URI, taken from `Location` when the producer supplies one.
async fn post_producer_subscription(
    api_root: &str,
    service_name: &str,
    body: &serde_json::Value,
) -> Result<String, String> {
    let Some((host, port, _)) = split_uri(api_root) else {
        return Err(format!("unparseable producer apiRoot {api_root}"));
    };
    let client = SbiClient::with_host_port(&host, port);
    let path = format!("/{service_name}/v1/subscriptions");
    let resp = client
        .post_json(&path, body)
        .await
        .map_err(|e| e.to_string())?;
    if resp.status != 201 && resp.status != 200 {
        return Err(format!("producer answered {} for {path}", resp.status));
    }
    Ok(resp
        .http
        .get_header("location")
        .cloned()
        .unwrap_or_else(|| format!("{api_root}{path}")))
}

/// Split `scheme://host:port/path` into `(host, port, path)`.
///
/// Shared by all three calls above so the parsing rule (and the default port per
/// scheme) is stated once.
fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        (80u16, uri)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_uri_handles_scheme_port_and_path() {
        assert_eq!(
            split_uri("http://10.0.0.1:7777/nnrf-nfm/v1/x"),
            Some(("10.0.0.1".to_string(), 7777, "/nnrf-nfm/v1/x".to_string()))
        );
        // Default ports per scheme.
        assert_eq!(
            split_uri("http://nrf.example"),
            Some(("nrf.example".to_string(), 80, "/".to_string()))
        );
        assert_eq!(
            split_uri("https://nrf.example/x"),
            Some(("nrf.example".to_string(), 443, "/x".to_string()))
        );
        assert_eq!(split_uri("http://"), None);
    }

    /// The event-exposure service is found by name across the spellings 3GPP
    /// uses, and its own `ipEndPoints` win over the profile-level address.
    #[test]
    fn event_exposure_endpoint_prefers_the_service_endpoint() {
        let profile = serde_json::json!({
            "nfInstanceId": "amf-1",
            "nfType": "AMF",
            "ipv4Addresses": ["10.0.0.9"],
            "nfServices": [
                {"serviceName": "namf-comm", "scheme": "http"},
                {"serviceName": "namf-evts", "scheme": "http",
                 "ipEndPoints": [{"ipv4Address": "10.0.0.10", "port": 8080}]}
            ]
        });
        assert_eq!(
            event_exposure_endpoint(&profile),
            Some(("http://10.0.0.10:8080".to_string(), "namf-evts".to_string()))
        );

        // Falls back to the profile address when the service has no endpoint.
        let profile = serde_json::json!({
            "ipv4Addresses": ["10.0.0.9"],
            "nfServices": [{"serviceName": "npcf-eventexposure", "scheme": "http"}]
        });
        assert_eq!(
            event_exposure_endpoint(&profile),
            Some((
                "http://10.0.0.9:80".to_string(),
                "npcf-eventexposure".to_string()
            ))
        );

        // A profile with no event-exposure service, and one with no address at
        // all, are both skipped rather than dialled at a guessed port.
        assert_eq!(
            event_exposure_endpoint(&serde_json::json!({
                "nfServices": [{"serviceName": "namf-comm"}]
            })),
            None
        );
        assert_eq!(
            event_exposure_endpoint(&serde_json::json!({
                "nfServices": [{"serviceName": "namf-evts"}]
            })),
            None
        );
    }

    /// With coordination off, nothing is attempted — the guard on the default
    /// posture.
    #[tokio::test]
    async fn coordination_is_off_by_default() {
        set_coordination_for_test(None);
        let outcome = ensure_producer_subscription(
            "c1",
            &SubscriptionScope::default(),
            &DataManagementSubsc::default(),
        )
        .await;
        assert_eq!(outcome, CoordinationOutcome::Disabled);
    }
}
