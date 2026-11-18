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

use nextgcore_sbi::client::SbiClient;

use nextgcore_sbi::callback_auth::CallbackToken;

use crate::context::{
    dccf_context_abandon_producer_sub, dccf_context_claim_producer_sub,
    dccf_context_record_producer_sub, ProducerClaim,
};
use crate::data_mgmt::{DataManagementSubsc, SubscriptionScope};

/// Is coordination enabled for this process?
static COORDINATION_ENABLED: AtomicBool = AtomicBool::new(false);

/// The path prefix of the `notificationURI` this DCCF hands a producer (#1518):
/// `{apiRoot}{PRODUCER_NOTIFY_PREFIX}/{token}`. Its last segment is in
/// `nextgcore_sbi::log_redact::CALLBACK_TOKEN_SEGMENTS`.
pub const PRODUCER_NOTIFY_PREFIX: &str = "/ndccf-datamanagement/v1/notify/dccf-data-notify";

/// The `notificationURI` for the producer subscription holding `token` (#1518).
pub fn producer_notify_uri(own_api_root: &str, token: &CallbackToken) -> String {
    format!(
        "{}{PRODUCER_NOTIFY_PREFIX}/{}",
        own_api_root.trim_end_matches('/'),
        token.as_str()
    )
}

/// The NRF to resolve producers through, and this DCCF's own apiRoot.
static COORDINATION_CONFIG: std::sync::RwLock<Option<CoordinationConfig>> =
    std::sync::RwLock::new(None);

/// What the coordination path needs to reach the NRF and to be called back.
#[derive(Debug, Clone)]
pub struct CoordinationConfig {
    /// NRF root, e.g. `http://127.0.0.1:7777`.
    pub nrf_uri: String,
    /// This DCCF's own apiRoot, e.g. `http://10.0.0.9:7777`. Producers are handed
    /// `notificationURI`s under it, each with its subscription's token (#1518), so
    /// their data arrives here rather than at the consumer.
    pub own_api_root: String,
}

/// Enable coordination with the given config (called once at startup).
pub fn enable_coordination(config: CoordinationConfig) {
    *COORDINATION_CONFIG
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(config);
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
            // Replaced per test: each runs its own loopback NRF.
            *COORDINATION_CONFIG
                .write()
                .unwrap_or_else(|e| e.into_inner()) = Some(c);
            COORDINATION_ENABLED.store(true, Ordering::SeqCst);
        }
        None => COORDINATION_ENABLED.store(false, Ordering::SeqCst),
    }
}

/// The current coordination config, when enabled.
fn config() -> Option<CoordinationConfig> {
    coordination_enabled()
        .then(|| {
            COORDINATION_CONFIG
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        })
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
    // before any producer signalling. A claim that needs a create holds the
    // subscription in flight, so a concurrent consumer of the same scope reuses it.
    let target = sub.target_nf_id.as_deref();
    let (notify_token, claim_seq) =
        match dccf_context_claim_producer_sub(consumer_id, scope, target) {
            ProducerClaim::Reused { producer_id } => {
                return CoordinationOutcome::Reused { producer_id }
            }
            ProducerClaim::NoProducer => {
                log::info!(
                    "[DCCF] consumer subscription {consumer_id} names no targetNfId; skipping \
                 producer coordination (an event-to-producer mapping is deliberately not guessed)"
                );
                return CoordinationOutcome::NoProducerNamed;
            }
            ProducerClaim::NeedsCreate {
                notify_token,
                claim_seq,
            } => (notify_token, claim_seq),
        };
    let target = target.unwrap_or_default();
    // From here every exit, an await cancelled included (the consumer's subscribe
    // request this runs in is dropped when its client goes away), records or
    // abandons this claim.
    let claim = InFlightClaim {
        scope: scope.clone(),
        claim_seq,
        armed: true,
    };
    let failed = CoordinationOutcome::Failed;

    let profile = match fetch_nf_profile(&cfg.nrf_uri, target).await {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[DCCF] producer discovery for {target} failed: {e}");
            return failed(e);
        }
    };
    let Some((api_root, service_name)) = event_exposure_endpoint(&profile) else {
        let detail = format!("NF {target} advertises no event-exposure service");
        log::warn!("[DCCF] {detail}");
        return failed(detail);
    };

    // Forward the CONSUMER'S own subscription body, with the callback rewritten
    // to this DCCF. Rewriting rather than synthesising a body means the producer
    // receives exactly what the consumer asked for -- the DCCF is subscribing on
    // its behalf, not inventing a subscription.
    let mut producer_body = match sub.ana_sub.clone().or_else(|| sub.data_sub.clone()) {
        Some(b) => b,
        None => return failed("no anaSub/dataSub to forward".to_string()),
    };
    if let Some(obj) = producer_body.as_object_mut() {
        obj.insert(
            "notificationURI".to_string(),
            serde_json::Value::String(producer_notify_uri(&cfg.own_api_root, &notify_token)),
        );
        obj.insert(
            "notifCorrId".to_string(),
            serde_json::Value::String(format!("dccf-{consumer_id}")),
        );
    }

    match post_producer_subscription(&api_root, &service_name, &producer_body).await {
        Ok(resource_uri) => {
            claim.committed(resource_uri);
            CoordinationOutcome::Created {
                producer_id: target.to_string(),
            }
        }
        Err(e) => {
            log::warn!("[DCCF] creating a producer subscription on {target} failed: {e}");
            failed(e)
        }
    }
}

/// A producer-subscription claim held in flight (#1747 review). Dropped without
/// [`InFlightClaim::committed`] (the create failed, or the future running it was
/// cancelled) it abandons the claim, so the scope can be claimed again rather than
/// being reused forever by consumers no producer subscription serves.
struct InFlightClaim {
    scope: SubscriptionScope,
    claim_seq: u64,
    /// Cleared once committed: drop then leaves the entry alone.
    armed: bool,
}

impl InFlightClaim {
    /// The producer created it at `resource_uri`: record it. When the claim went
    /// while the create was in flight (every consumer left, or the scope was
    /// claimed anew), delete it at the producer instead, on its own task so that
    /// cancelling this future cannot leak it.
    fn committed(mut self, resource_uri: String) {
        self.armed = false;
        if !dccf_context_record_producer_sub(&self.scope, self.claim_seq, resource_uri.clone()) {
            log::info!(
                "[DCCF] producer subscription {resource_uri} created for a claim no longer \
                 held; deleting it"
            );
            tokio::spawn(async move { delete_producer_subscription(&resource_uri).await });
        }
    }
}

impl Drop for InFlightClaim {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let left = dccf_context_abandon_producer_sub(&self.scope, self.claim_seq);
        if !left.is_empty() {
            log::warn!(
                "[DCCF] producer subscription for {} consumer(s) {left:?} not created; no \
                 producer data reaches them until a later subscription of the same scope \
                 creates one",
                left.len()
            );
        }
    }
}

/// Delete a producer subscription that has lost its last consumer.
pub async fn delete_producer_subscription(resource_uri: &str) {
    let Some((host, port, path)) = split_uri(resource_uri) else {
        log::warn!("[DCCF] cannot delete producer subscription: unparseable URI {resource_uri}");
        return;
    };
    let client = producer_client(&host, port, path.trim_start_matches('/'));
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
    // #1617: the NRF client TLS (https + this NF's certificate) for an https
    // NRF URI or the production profile.
    let Some(client) = SbiClient::for_nrf_uri(nrf_uri) else {
        return Err(format!("unparseable NRF URI {nrf_uri}"));
    };
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
    // #1324: the endpoint's IPv4 or IPv6 address, else the service's or the NF's
    // (IPv4, IPv6, FQDN); an IPv6 host is bracketed in the URI.
    let addr = nextgcore_sbi::nf_addressing::service_host(profile, Some(service))?;
    let port = nextgcore_sbi::nf_addressing::service_port(Some(service)).unwrap_or(80);
    Some((
        format!(
            "{scheme}://{}",
            nextgcore_sbi::uri_encode::uri_authority(&addr, port)
        ),
        service_name,
    ))
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
    let client = producer_client(&host, port, service_name);
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

/// The client for a service request to the producer at `host:port` (#1663):
/// the SBI profile applies (`for_peer`), and the installed OAuth2 client is
/// attached for the producer's NF type, read from the service name `service`
/// starts with: API names follow `n<nftype>-<service>` (TS 29.501 §4.4.1's
/// example is `nsmf-pdusession`), so `nnwdaf-...` is the NWDAF. A service name
/// that names no known NF type gets no token rather than one for a guessed
/// audience.
fn producer_client(host: &str, port: u16, service: &str) -> SbiClient {
    let client = SbiClient::for_peer(host, port);
    match producer_nf_type(service) {
        Some(target) => crate::attach_oauth2(client, target),
        None => {
            log::warn!(
                "[DCCF] service {service:?} names no known producer NF type; sending without \
                 an access token"
            );
            client
        }
    }
}

/// The producer NF type a TS 29.501 service name (or a path starting with one)
/// names: `namf-evts` is AMF, `nnwdaf-eventssubscription` NWDAF.
fn producer_nf_type(service: &str) -> Option<nextgcore_sbi::types::NfType> {
    let api_name = service.split('/').next()?;
    let nf = api_name.split('-').next()?.strip_prefix('n')?;
    nextgcore_sbi::types::NfType::from_name(&nf.to_ascii_uppercase())
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

    /// #1663: the producer NF type comes from the service name, and an unknown
    /// one yields none rather than a guess.
    #[test]
    fn the_producer_type_is_read_from_the_service_name() {
        use nextgcore_sbi::types::NfType;
        assert_eq!(producer_nf_type("namf-evts"), Some(NfType::Amf));
        assert_eq!(producer_nf_type("nsmf-event-exposure"), Some(NfType::Smf));
        assert_eq!(
            producer_nf_type("nnwdaf-eventssubscription"),
            Some(NfType::Nwdaf)
        );
        assert_eq!(producer_nf_type("npcf-eventexposure"), Some(NfType::Pcf));
        assert_eq!(
            producer_nf_type("namf-evts/v1/subscriptions/s1"),
            Some(NfType::Amf)
        );
        assert_eq!(producer_nf_type("xyz-evts"), None);
        assert_eq!(producer_nf_type("nfoo-evts"), None);
    }

    /// #1663, failure-path property 1 (a failed request applies nothing): when
    /// the token cannot be obtained, neither the producer subscription's create
    /// nor its delete is sent, not even bare. The recorder here is UNGATED, so it
    /// would see a bare send. The create's error means `ensure_producer_subscription`
    /// records no producer subscription.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_token_fetch_sends_nothing_1663() {
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        use nextgcore_sbi::types::NfType;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = std::sync::Arc::clone(&seen);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let recorder = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
            listener,
        );
        recorder
            .start(move |_req| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    nextgcore_sbi::message::SbiResponse::with_status(201)
                        .with_header("location", "/x/v1/subscriptions/s-1")
                }
            })
            .await
            .expect("recorder starts");
        let api_root = format!("http://127.0.0.1:{}", addr.port());
        // Port 1 on loopback: nothing listens, so the token request fails.
        let no_nrf = stand_in::oauth2_client_for(1, NfType::Dccf);
        let create = crate::TEST_OAUTH2_CLIENT
            .scope(
                std::sync::Arc::clone(&no_nrf),
                post_producer_subscription(&api_root, "namf-evts", &serde_json::json!({})),
            )
            .await;
        crate::TEST_OAUTH2_CLIENT
            .scope(
                no_nrf,
                delete_producer_subscription(&format!("{api_root}/namf-evts/v1/subscriptions/s-1")),
            )
            .await;

        assert!(
            create.as_ref().is_err_and(|e| e.contains("access token")),
            "the token error, not a producer answer: {create:?}"
        );
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no token: nothing is sent, not even bare"
        );
    }

    /// #1663: the producer subscription's create and delete pass an
    /// OAuth2-required producer with the installed client, and the create is
    /// refused 401 without one. The stand-in AMF is gated by nextgcore-sbi's own
    /// check (JWKS, audience AMF), so a recorded request passed it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn producer_subscription_create_and_delete_pass_an_oauth2_required_amf_1663() {
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        use nextgcore_sbi::types::NfType;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (_nrf, nrf_port) = stand_in::token_nrf(sk.clone()).await;
        let (_amf, amf_port, seen) = stand_in::oauth2_producer(&sk, NfType::Amf, |req| {
            if req.header.method == "DELETE" {
                nextgcore_sbi::message::SbiResponse::with_status(204)
            } else {
                nextgcore_sbi::message::SbiResponse::with_status(201)
                    .with_header("location", "/namf-evts/v1/subscriptions/s-1663")
            }
        })
        .await;
        let api_root = format!("http://127.0.0.1:{amf_port}");
        let body = serde_json::json!({ "eventList": [] });

        let without = post_producer_subscription(&api_root, "namf-evts", &body).await;
        let oauth2 = stand_in::oauth2_client_for(nrf_port, NfType::Dccf);
        let with = crate::TEST_OAUTH2_CLIENT
            .scope(
                std::sync::Arc::clone(&oauth2),
                post_producer_subscription(&api_root, "namf-evts", &body),
            )
            .await;
        crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2,
                delete_producer_subscription(&format!(
                    "{api_root}/namf-evts/v1/subscriptions/s-1663"
                )),
            )
            .await;

        assert!(
            without.as_ref().is_err_and(|e| e.contains("401")),
            "refused without a token: {without:?}"
        );
        assert_eq!(with, Ok("/namf-evts/v1/subscriptions/s-1663".to_string()));
        assert_eq!(
            stand_in::bearer_requests(&seen, "POST", "/namf-evts/v1/subscriptions"),
            1
        );
        assert_eq!(
            stand_in::bearer_requests(&seen, "DELETE", "/namf-evts/v1/subscriptions/s-1663"),
            1
        );
    }

    /// With coordination off, nothing is attempted — the guard on the default
    /// posture.
    #[test]
    fn coordination_is_off_by_default() {
        // #1785: the coordination switch is process-global, and the
        // data-management tests switch it on under this lock; flipping it off
        // without the lock disabled their coordination mid-test.
        let _g = crate::context::GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_coordination_for_test(None);
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(ensure_producer_subscription(
                "c1",
                &SubscriptionScope::default(),
                &DataManagementSubsc::default(),
            ));
        assert_eq!(outcome, CoordinationOutcome::Disabled);
    }
}

/// #1324 review: producer to consumer. A peer profile built with an IPv4, IPv6 or
/// FQDN host (as this codebase's producers build them) resolves to that host.
#[cfg(test)]
mod tests_peer_host_kind_1324 {
    use super::*;
    use nextgcore_sbi::nf_addressing::{dialled_host, sample_search_result, SAMPLE_HOSTS};

    #[test]
    fn a_peer_at_any_host_type_is_resolved() {
        for host in SAMPLE_HOSTS {
            let r = sample_search_result("NWDAF", "nnwdaf-eventssubscription", host, 7799);
            let (uri, _) = event_exposure_endpoint(&r["nfInstances"][0]).expect("an endpoint");
            let want = format!(
                "http://{}",
                nextgcore_sbi::uri_encode::uri_authority(&dialled_host(host), 7799)
            );
            assert_eq!(uri, want);
        }
    }
}
