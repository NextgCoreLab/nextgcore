//! NRF SBI Path Implementation
//!
//! Port of src/nrf/sbi-path.c - SBI server open/close and notification sending

use crate::nnrf_build::{
    nrf_nnrf_nfm_build_nf_profile_changed_notify, nrf_nnrf_nfm_build_nf_status_notify, ChangeItem,
    NotificationEventType,
};
use crate::nnrf_handler::{nf_manager, NfProfile, SubscrCond, SubscrCondKind, SubscriptionData};
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::message::SbiRequest;
use nextgcore_sbi::oauth::OAuth2Client;
use nextgcore_sbi::types::{NfType, UriScheme};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on the
/// NRF's outbound SBI calls. Installed from `main` when
/// `nrf.sbi.oauth2.require` is true; absent (None) otherwise, preserving the
/// default token-free path.
static OAUTH2_CLIENT: OnceLock<Arc<OAuth2Client>> = OnceLock::new();

/// Install the process-wide OAuth2 client (T1.1). Idempotent; the first call
/// wins. Called by `main` only when SBI OAuth2 is enabled.
pub fn set_oauth2_client(client: Arc<OAuth2Client>) {
    let _ = OAUTH2_CLIENT.set(client);
}

/// The installed OAuth2 client, if any.
fn oauth2_client() -> Option<Arc<OAuth2Client>> {
    OAUTH2_CLIENT.get().cloned()
}

/// Attach the process-wide OAuth2 client (when installed) so the outbound
/// request carries an NRF-issued Bearer token scoped to `target`. A no-op
/// when SBI OAuth2 is disabled, preserving the default path.
fn attach_oauth2(client: SbiClient, target: NfType) -> SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

/// Map an NF type string (TS 29.510 NFType) to [`NfType`] for OAuth2 token
/// scoping.
///
/// Delegates to [`NfType::from_nf_type_str`], which covers all 41 spec variants.
/// This used to be a local 11-entry table, so the 30 unlisted NF types — SEPP,
/// UPF, NWDAF, CHF, EASDF, TSCTSF and the rest — all returned `None` and were
/// then silently coerced to `AMF` by the caller.
fn nf_type_from_str(s: &str) -> Option<NfType> {
    NfType::from_nf_type_str(s)
}

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    /// Server address
    pub addr: String,
    /// Server port
    pub port: u16,
    /// TLS enabled
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// NF service information
#[derive(Debug, Clone)]
pub struct NfServiceInfo {
    /// Service name
    pub name: String,
    /// API version
    pub version: String,
    /// API full version
    pub full_version: String,
}

/// SBI server handle
pub struct SbiServer {
    /// Server configuration
    config: SbiServerConfig,
    /// NF services
    services: Vec<NfServiceInfo>,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self {
            config,
            services: Vec::new(),
        }
    }

    /// Add an NF service
    pub fn add_service(&mut self, service: NfServiceInfo) {
        self.services.push(service);
    }

    /// Get server URI
    pub fn uri(&self) -> String {
        let scheme = if self.config.tls_enabled {
            "https"
        } else {
            "http"
        };
        format!("{}://{}:{}", scheme, self.config.addr, self.config.port)
    }
}

/// Open SBI server
///
/// Initializes the NRF SBI server with NFM and DISC services
pub fn nrf_sbi_open(config: Option<SbiServerConfig>) -> Result<SbiServer, String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();
    let mut server = SbiServer::new(config);

    // Add nnrf-nfm service (NF Management)
    server.add_service(NfServiceInfo {
        name: "nnrf-nfm".to_string(),
        version: "v1".to_string(),
        full_version: "1.0.0".to_string(),
    });

    // Add nnrf-disc service (NF Discovery)
    server.add_service(NfServiceInfo {
        name: "nnrf-disc".to_string(),
        version: "v1".to_string(),
        full_version: "1.0.0".to_string(),
    });

    log::info!("NRF SBI server opened at {}", server.uri());

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    Ok(server)
}

/// Close SBI server
pub fn nrf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        log::warn!("SBI server not running");
        return;
    }

    log::info!("NRF SBI server closed");
    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);
}

/// Check if SBI server is running
pub fn nrf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}

/// Notification send result
#[derive(Debug)]
pub enum NotifySendResult {
    /// Successfully sent
    Success,
    /// Failed to send
    Failed(String),
    /// No client available
    NoClient,
}

/// Send a pre-built notify request over HTTP/2 to the subscriber URI.
/// Shared by all async single-subscriber send functions.
async fn dispatch_notify_request_async(
    notify_request: &crate::nnrf_build::SbiNotifyRequest,
    nf_instance_id: &str,
    notification_uri: &str,
    req_nf_type: Option<&str>,
    event_str: &str,
) -> NotifySendResult {
    log::debug!(
        "Sending NF status notify to {} (event={}, nf_instance={})",
        notify_request.uri,
        event_str,
        nf_instance_id
    );

    let (host, port, path, scheme) = match parse_notification_uri(&notify_request.uri) {
        Some(parts) => parts,
        None => {
            log::error!("Failed to parse notification URI: {}", notify_request.uri);
            return NotifySendResult::Failed(format!(
                "Invalid notification URI: {}",
                notify_request.uri
            ));
        }
    };

    let client_config = SbiClientConfig::new(&host, port).with_scheme(scheme);
    let client = SbiClient::new(client_config);

    // OAuth2 audience must be the ACTUAL subscriber NF type (TS 33.501 §13.4.1:
    // the access token's `audience` claim identifies the NF service producer the
    // token is valid for).
    //
    // This previously did `.unwrap_or(NfType::Amf)`, so any NF type the local
    // table did not recognise — every one of SEPP, UPF, NWDAF, CHF, EASDF,
    // TSCTSF, ... — silently received a token minted for an AMF audience. Two
    // consequences, both bad: a conformant consumer rejects the token on an
    // audience mismatch (so the notification is lost for a reason the log does
    // not explain), and an AMF-audience token is handed to a party that never
    // asked for one.
    //
    // Now: send the notification WITHOUT a token rather than with a wrong one.
    // The subscriber rejects an unauthenticated notify with 401, which is a
    // truthful and debuggable failure, unlike a plausible token for the wrong
    // audience.
    let client = match req_nf_type {
        Some(raw) => match nf_type_from_str(raw) {
            Some(target) => attach_oauth2(client, target),
            None => {
                log::warn!(
                    "NF status notify to {notification_uri}: unrecognised subscriber NFType \
                     '{raw}' (TS 29.510 NFType); sending WITHOUT an OAuth2 token rather than \
                     minting one for the wrong audience"
                );
                client
            }
        },
        None => {
            // No reqNfType on the subscription: nothing identifies the audience,
            // so there is no correct token to mint.
            log::debug!(
                "NF status notify to {notification_uri}: subscription carries no reqNfType; \
                 sending without an OAuth2 token"
            );
            client
        }
    };

    let sbi_request = SbiRequest::post(&path)
        .with_header("Content-Type", &notify_request.content_type)
        .with_header("Accept", &notify_request.accept)
        .with_body(notify_request.body.clone(), &notify_request.content_type);

    match client.send_request(sbi_request).await {
        Ok(response) => {
            let status = response.status;
            if status == 204 || (200..300).contains(&status) {
                log::info!(
                    "NF status notify delivered: {} -> {} ({}) [HTTP {}]",
                    nf_instance_id,
                    notification_uri,
                    event_str,
                    status
                );
                NotifySendResult::Success
            } else {
                log::warn!(
                    "NF status notify rejected: {} -> {} ({}) [HTTP {}]",
                    nf_instance_id,
                    notification_uri,
                    event_str,
                    status
                );
                NotifySendResult::Failed(format!("HTTP {status}"))
            }
        }
        Err(e) => {
            log::error!(
                "Failed to deliver NF status notify to {}: {}",
                notification_uri,
                e
            );
            NotifySendResult::Failed(e.to_string())
        }
    }
}

/// Send NF status notify to a single subscriber (async version)
///
/// Builds and sends an NF status notification to the subscriber's callback URI
/// using the nextgcore-sbi HTTP/2 client.
pub async fn nrf_nnrf_nfm_send_nf_status_notify_async(
    subscription_data: &SubscriptionData,
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
) -> NotifySendResult {
    let notify_request = match nrf_nnrf_nfm_build_nf_status_notify(
        subscription_data,
        event,
        nf_instance,
        server_uri,
    ) {
        Some(req) => req,
        None => {
            log::error!("nrf_nnrf_nfm_build_nf_status_notify() failed");
            return NotifySendResult::Failed("Failed to build notification".to_string());
        }
    };

    dispatch_notify_request_async(
        &notify_request,
        &nf_instance.nf_instance_id,
        &subscription_data.notification_uri,
        subscription_data.req_nf_type.as_deref(),
        event.as_str(),
    )
    .await
}

/// Send an NF_PROFILE_CHANGED notification carrying `profile_changes` to a
/// single subscriber (async version, TS 29.510 §5.2.2.6).
pub async fn nrf_nnrf_nfm_send_nf_profile_changed_notify_async(
    subscription_data: &SubscriptionData,
    nf_instance: &NfProfile,
    server_uri: &str,
    profile_changes: Vec<ChangeItem>,
) -> NotifySendResult {
    let notify_request = match nrf_nnrf_nfm_build_nf_profile_changed_notify(
        subscription_data,
        nf_instance,
        server_uri,
        profile_changes,
    ) {
        Some(req) => req,
        None => {
            log::error!("nrf_nnrf_nfm_build_nf_profile_changed_notify() failed");
            return NotifySendResult::Failed(
                "Failed to build profile-changed notification".to_string(),
            );
        }
    };

    dispatch_notify_request_async(
        &notify_request,
        &nf_instance.nf_instance_id,
        &subscription_data.notification_uri,
        subscription_data.req_nf_type.as_deref(),
        NotificationEventType::NfProfileChanged.as_str(),
    )
    .await
}

/// Send NF status notify to a single subscriber (sync stub for backward compat)
///
/// Builds and sends an NF status notification to the subscriber's callback URI
pub fn nrf_nnrf_nfm_send_nf_status_notify(
    subscription_data: &SubscriptionData,
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
) -> NotifySendResult {
    // Build the notification request
    let request = match nrf_nnrf_nfm_build_nf_status_notify(
        subscription_data,
        event,
        nf_instance,
        server_uri,
    ) {
        Some(req) => req,
        None => {
            log::error!("nrf_nnrf_nfm_build_nf_status_notify() failed");
            return NotifySendResult::Failed("Failed to build notification".to_string());
        }
    };

    log::debug!(
        "Sending NF status notify to {} (event={:?}, nf_instance={})",
        request.uri,
        event,
        nf_instance.nf_instance_id
    );

    log::info!(
        "NF status notify queued: {} -> {} ({})",
        nf_instance.nf_instance_id,
        subscription_data.notification_uri,
        event.as_str()
    );

    NotifySendResult::Success
}

/// Parse a notification URI into (host, port, path, scheme) components.
fn parse_notification_uri(uri: &str) -> Option<(String, u16, String, UriScheme)> {
    let (scheme, rest) = if let Some(rest) = uri.strip_prefix("https://") {
        (UriScheme::Https, rest)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        (UriScheme::Http, rest)
    } else {
        return None;
    };

    let (authority, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rfind(':') {
        Some(pos) => {
            let h = &authority[..pos];
            let p = authority[pos + 1..].parse::<u16>().ok()?;
            (h.to_string(), p)
        }
        None => {
            let default_port = scheme.default_port();
            (authority.to_string(), default_port)
        }
    };

    Some((host, port, path.to_string(), scheme))
}

/// Send NF status notify to all matching subscribers (async version)
///
/// Iterates through all subscriptions and sends notifications to those
/// that match the NF instance based on subscription conditions.
/// Delivers notifications concurrently using tokio tasks.
pub async fn nrf_nnrf_nfm_send_nf_status_notify_all_async(
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
) -> Result<u32, String> {
    let manager = nf_manager();
    let subscriptions = manager.list_subscriptions();

    let mut sent_count = 0u32;

    for subscription in &subscriptions {
        if !subscription_matches(subscription, nf_instance) {
            continue;
        }
        if !subscription_accepts_event(subscription, event) {
            continue;
        }

        // Send notification asynchronously
        match nrf_nnrf_nfm_send_nf_status_notify_async(subscription, event, nf_instance, server_uri)
            .await
        {
            NotifySendResult::Success => {
                sent_count += 1;
            }
            NotifySendResult::Failed(err) => {
                log::error!(
                    "Failed to send NF status notify to {}: {}",
                    subscription.notification_uri,
                    err
                );
                // Continue sending to other subscribers rather than aborting
            }
            NotifySendResult::NoClient => {
                log::warn!("No client for subscription {}", subscription.id);
            }
        }
    }

    log::info!(
        "Sent {} NF status notifications for {} (event={:?})",
        sent_count,
        nf_instance.nf_instance_id,
        event
    );

    Ok(sent_count)
}

/// Send NF_PROFILE_CHANGED notifications to all matching subscribers (async).
///
/// Mirrors `nrf_nnrf_nfm_send_nf_status_notify_all_async` but carries the
/// RFC 6902-style `profileChanges` list in the body (TS 29.510 §5.2.2.6).
pub async fn nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
    nf_instance: &NfProfile,
    server_uri: &str,
    profile_changes: Vec<ChangeItem>,
) -> Result<u32, String> {
    let manager = nf_manager();
    let subscriptions = manager.list_subscriptions();
    let mut sent_count = 0u32;

    let changed_attributes = changed_attribute_names(&profile_changes);

    for subscription in &subscriptions {
        if !subscription_matches(subscription, nf_instance) {
            continue;
        }
        if !subscription_accepts_event(subscription, NotificationEventType::NfProfileChanged) {
            continue;
        }
        if !subscription_accepts_profile_changes(subscription, &changed_attributes) {
            continue;
        }

        match nrf_nnrf_nfm_send_nf_profile_changed_notify_async(
            subscription,
            nf_instance,
            server_uri,
            profile_changes.clone(),
        )
        .await
        {
            NotifySendResult::Success => {
                sent_count += 1;
            }
            NotifySendResult::Failed(err) => {
                log::error!(
                    "Failed to send NF_PROFILE_CHANGED notify to {}: {}",
                    subscription.notification_uri,
                    err
                );
                // Continue to remaining subscribers.
            }
            NotifySendResult::NoClient => {
                log::warn!("No client for subscription {}", subscription.id);
            }
        }
    }

    log::info!(
        "Sent {} NF_PROFILE_CHANGED notifications for {}",
        sent_count,
        nf_instance.nf_instance_id
    );

    Ok(sent_count)
}

/// Send NF_PROFILE_CHANGED notifications to a provided subscriber list (sync
/// stub, used in unit tests — mirrors the existing sync all function).
pub fn nrf_nnrf_nfm_send_nf_profile_changed_notify_all(
    nf_instance: &NfProfile,
    server_uri: &str,
    subscriptions: &[SubscriptionData],
    profile_changes: Vec<ChangeItem>,
) -> Result<u32, String> {
    let mut sent_count = 0u32;
    let changed_attributes = changed_attribute_names(&profile_changes);

    for subscription in subscriptions {
        if !subscription_matches(subscription, nf_instance) {
            continue;
        }
        if !subscription_accepts_event(subscription, NotificationEventType::NfProfileChanged) {
            continue;
        }
        if !subscription_accepts_profile_changes(subscription, &changed_attributes) {
            continue;
        }

        let notify_request = nrf_nnrf_nfm_build_nf_profile_changed_notify(
            subscription,
            nf_instance,
            server_uri,
            profile_changes.clone(),
        );
        match notify_request {
            Some(_) => {
                log::info!(
                    "NF_PROFILE_CHANGED notify queued: {} -> {}",
                    nf_instance.nf_instance_id,
                    subscription.notification_uri
                );
                sent_count += 1;
            }
            None => {
                return Err("Failed to build NF_PROFILE_CHANGED notification".to_string());
            }
        }
    }

    log::info!(
        "Sent {} NF_PROFILE_CHANGED notifications for {}",
        sent_count,
        nf_instance.nf_instance_id
    );

    Ok(sent_count)
}

/// Send NF status notify to all matching subscribers (sync version)
///
/// Iterates through all subscriptions and sends notifications to those
/// that match the NF instance based on subscription conditions
pub fn nrf_nnrf_nfm_send_nf_status_notify_all(
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
    subscriptions: &[SubscriptionData],
) -> Result<u32, String> {
    let mut sent_count = 0u32;

    for subscription in subscriptions {
        if !subscription_matches(subscription, nf_instance) {
            continue;
        }
        if !subscription_accepts_event(subscription, event) {
            continue;
        }

        // Send notification
        match nrf_nnrf_nfm_send_nf_status_notify(subscription, event, nf_instance, server_uri) {
            NotifySendResult::Success => {
                sent_count += 1;
            }
            NotifySendResult::Failed(err) => {
                log::error!(
                    "Failed to send NF status notify to {}: {}",
                    subscription.notification_uri,
                    err
                );
                return Err(err);
            }
            NotifySendResult::NoClient => {
                log::warn!("No client for subscription {}", subscription.id);
            }
        }
    }

    log::info!(
        "Sent {} NF status notifications for {} (event={:?})",
        sent_count,
        nf_instance.nf_instance_id,
        event
    );

    Ok(sent_count)
}

/// Check if a subscription matches an NF instance for notification delivery.
fn subscription_matches(subscription: &SubscriptionData, nf_instance: &NfProfile) -> bool {
    // Skip if the requester is the same as the NF instance
    if let Some(ref req_nf_instance_id) = subscription.req_nf_instance_id {
        if req_nf_instance_id == &nf_instance.nf_instance_id {
            return false;
        }
    }

    // An absent condition means "every NF", which is the spec's reading of an
    // omitted filter and the one nwdafd's NF-status feed relies on.
    match subscription.subscr_cond {
        Some(ref cond) => subscr_cond_matches(cond, nf_instance),
        None => true,
    }
}

/// Does `event` fall inside the subscriber's requested event set?
///
/// TS 29.510 §5.2.2.5.2: `reqNotifEvents` is the list of `NotificationEventType`
/// the subscriber asked for. An absent list is "no restriction" — the filter's
/// absence conventionally means unconstrained, per the project's recorded
/// fail-open rule for filters (as distinct from credentials).
pub fn subscription_accepts_event(
    subscription: &SubscriptionData,
    event: NotificationEventType,
) -> bool {
    match subscription.req_notif_events {
        Some(ref events) => events.iter().any(|e| e == event.as_str()),
        None => true,
    }
}

/// Does at least one of `changed_attributes` warrant an `NF_PROFILE_CHANGED`
/// notification under the subscriber's `notifCondition`?
///
/// TS 29.510 §5.2.2.5.2. An absent condition, or an empty change list (a
/// complete-replacement notification carries the profile rather than a change
/// list), is "no restriction".
pub fn subscription_accepts_profile_changes(
    subscription: &SubscriptionData,
    changed_attributes: &[String],
) -> bool {
    let Some(ref cond) = subscription.notif_condition else {
        return true;
    };
    if changed_attributes.is_empty() {
        return true;
    }
    changed_attributes
        .iter()
        .any(|attr| cond.notifies_attribute(attr))
}

/// The top-level NFProfile attribute each `ChangeItem` touches, e.g. `/load` and
/// `/nfServices/0/priority` both reduce to the first path segment (`load`,
/// `nfServices`), which is the granularity `notifCondition` is expressed at.
fn changed_attribute_names(changes: &[ChangeItem]) -> Vec<String> {
    changes
        .iter()
        .filter_map(|c| {
            c.path
                .trim_start_matches('/')
                .split('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .collect()
}

/// Evaluate a recognised `SubscrCond` against an NF profile.
///
/// Every arm reads its criteria from the condition as received and compares them
/// against the profile document the NRF stored verbatim on registration, so a
/// criterion is either compared against real profile data or the condition was
/// refused at subscribe time (see `SubscrCond::unsupported_criterion`). There is
/// deliberately **no** catch-all `=> true` arm: a variant that reached here
/// without criteria to compare would silently become match-all, which is the
/// defect this replaces.
fn subscr_cond_matches(cond: &SubscrCond, nf: &NfProfile) -> bool {
    // A conditionType-tagged condition names its produced NF type; a UPF
    // condition must not match an AMF just because the AMF has no upfInfo.
    if let Some(implied) = cond.kind.implied_nf_type() {
        if nf.nf_type != implied {
            return false;
        }
    }

    let doc = &nf.attributes;
    let info = cond
        .kind
        .info_container()
        .and_then(|name| doc.get(name))
        .unwrap_or(&serde_json::Value::Null);

    match cond.kind {
        SubscrCondKind::NfInstanceId => cond.str_at("nfInstanceId") == Some(&nf.nf_instance_id),

        SubscrCondKind::NfInstanceIdList => cond
            .str_list_at("nfInstanceIdList")
            .is_some_and(|ids| ids.iter().any(|id| *id == nf.nf_instance_id)),

        SubscrCondKind::NfType => cond.str_at("nfType") == Some(&nf.nf_type),

        SubscrCondKind::ServiceName => cond
            .str_at("serviceName")
            .is_some_and(|name| nf.nf_services.iter().any(|s| s.service_name == name)),

        SubscrCondKind::ServiceNameList => {
            cond.str_list_at("serviceNameList").is_some_and(|names| {
                nf.nf_services
                    .iter()
                    .any(|s| names.iter().any(|n| *n == s.service_name))
            })
        }

        // AmfCond: anyOf [amfSetId, amfRegionId]. Both present => both must
        // match ("Set Id and/or Region Id" in the schema description).
        SubscrCondKind::Amf => {
            let amf_info = doc.get("amfInfo").unwrap_or(&serde_json::Value::Null);
            let matches_member = |key: &str| match cond.str_at(key) {
                Some(want) => amf_info.get(key).and_then(|v| v.as_str()) == Some(want),
                None => true,
            };
            matches_member("amfSetId") && matches_member("amfRegionId")
        }

        SubscrCondKind::GuamiList => {
            let profile_guamis = doc
                .get("amfInfo")
                .and_then(|i| i.get("guamiList"))
                .and_then(|v| v.as_array());
            match (cond.obj_list_at("guamiList"), profile_guamis) {
                (Some(wanted), Some(held)) => {
                    wanted.iter().any(|w| held.iter().any(|h| guami_eq(w, h)))
                }
                _ => false,
            }
        }

        // NetworkSliceCond: snssaiList is mandatory; nsiList, when present, is
        // an additional constraint rather than an alternative.
        SubscrCondKind::NetworkSlice => {
            let snssai_ok = match (
                cond.obj_list_at("snssaiList"),
                doc.get("sNssais").and_then(|v| v.as_array()),
            ) {
                (Some(wanted), Some(held)) => {
                    wanted.iter().any(|w| held.iter().any(|h| snssai_eq(w, h)))
                }
                _ => false,
            };
            if !snssai_ok {
                return false;
            }
            match cond.str_list_at("nsiList") {
                Some(wanted) if !wanted.is_empty() => {
                    let held = doc
                        .get("nsiList")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                        .unwrap_or_default();
                    wanted.iter().any(|w| held.contains(w))
                }
                _ => true,
            }
        }

        SubscrCondKind::NfGroup => {
            if cond.str_at("nfType") != Some(&nf.nf_type) {
                return false;
            }
            match cond.str_at("nfGroupId") {
                Some(want) => profile_group_ids(doc).iter().any(|g| g == want),
                None => false,
            }
        }

        SubscrCondKind::NfGroupList => {
            if cond.str_at("nfType") != Some(&nf.nf_type) {
                return false;
            }
            let held = profile_group_ids(doc);
            cond.str_list_at("nfGroupIdList")
                .is_some_and(|wanted| wanted.iter().any(|w| held.iter().any(|g| g == w)))
        }

        SubscrCondKind::NfSet => cond
            .str_at("nfSetId")
            .is_some_and(|want| profile_nf_set_ids(doc).iter().any(|s| s == want)),

        // NfServiceSetCond: nfServiceSetId is mandatory, nfSetId an optional
        // additional constraint.
        SubscrCondKind::NfServiceSet => {
            let service_set_ok = cond.str_at("nfServiceSetId").is_some_and(|want| {
                doc.get("nfServices")
                    .and_then(|v| v.as_array())
                    .is_some_and(|services| {
                        services.iter().any(|s| {
                            s.get("nfServiceSetIdList")
                                .and_then(|v| v.as_array())
                                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(want)))
                        })
                    })
            });
            if !service_set_ok {
                return false;
            }
            match cond.str_at("nfSetId") {
                Some(want) => profile_nf_set_ids(doc).iter().any(|s| s == want),
                None => true,
            }
        }

        SubscrCondKind::ScpDomain => {
            let held = doc
                .get("scpDomains")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            let domain_ok = cond
                .str_list_at("scpDomains")
                .is_some_and(|wanted| wanted.iter().any(|w| held.contains(w)));
            if !domain_ok {
                return false;
            }
            match cond.str_list_at("nfTypeList") {
                Some(wanted) if !wanted.is_empty() => wanted.iter().any(|t| *t == nf.nf_type),
                _ => true,
            }
        }

        // UpfCond: conditionType is the only mandatory member, so a bare
        // {conditionType: UPF_COND} legitimately means "every UPF" — the NF-type
        // narrowing above has already been applied. taiList is refused at
        // subscribe time (UpfInfo carries no TAI list).
        SubscrCondKind::Upf => match cond.str_list_at("smfServingArea") {
            Some(wanted) if !wanted.is_empty() => {
                let held = info
                    .get("smfServingArea")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                wanted.iter().any(|w| held.contains(w))
            }
            _ => true,
        },

        SubscrCondKind::Nwdaf => {
            // analyticsIds are carried by NwdafInfo as eventIds / nwdafEvents.
            if let Some(wanted) = cond.str_list_at("analyticsIds") {
                if !wanted.is_empty() {
                    let mut held: Vec<&str> = Vec::new();
                    for key in ["eventIds", "nwdafEvents", "analyticsIds"] {
                        if let Some(a) = info.get(key).and_then(|v| v.as_array()) {
                            held.extend(a.iter().filter_map(|v| v.as_str()));
                        }
                    }
                    if !wanted.iter().any(|w| held.contains(w)) {
                        return false;
                    }
                }
            }
            if let Some(wanted) = cond.obj_list_at("snssaiList") {
                if !wanted.is_empty() {
                    let held = doc
                        .get("sNssais")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if !wanted.iter().any(|w| held.iter().any(|h| snssai_eq(w, h))) {
                        return false;
                    }
                }
            }
            serving_area_matches(cond, info)
        }

        // NefCond: the AF/identifier-range criteria are refused at subscribe
        // time, so only snssaiList and the serving area reach here.
        SubscrCondKind::Nef => {
            if let Some(wanted) = cond.obj_list_at("snssaiList") {
                if !wanted.is_empty() {
                    let held = doc
                        .get("sNssais")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if !wanted.iter().any(|w| held.iter().any(|h| snssai_eq(w, h))) {
                        return false;
                    }
                }
            }
            serving_area_matches(cond, info)
        }

        SubscrCondKind::Dccf => {
            for (cond_key, info_key) in [
                ("nfTypeList", "servingNfTypeList"),
                ("nfSetIdList", "servingNfSetIdList"),
            ] {
                if let Some(wanted) = cond.str_list_at(cond_key) {
                    if !wanted.is_empty() {
                        let held = info
                            .get(info_key)
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                            .unwrap_or_default();
                        if !wanted.iter().any(|w| held.contains(w)) {
                            return false;
                        }
                    }
                }
            }
            serving_area_matches(cond, info)
        }
    }
}

/// `taiList` / `taiRangeList` narrowing against an `*Info` container's own
/// `taiList` / `taiRangeList` (TS 29.510 NwdafInfo / NefInfo / DccfInfo).
///
/// Absent criteria do not narrow. A present criterion must find a counterpart:
/// a wanted TAI matches when the profile lists it explicitly **or** when it
/// falls inside one of the profile's TAI ranges, which is how a serving area is
/// expressed for a large deployment.
fn serving_area_matches(cond: &SubscrCond, info: &serde_json::Value) -> bool {
    if let Some(wanted) = cond.obj_list_at("taiList") {
        if !wanted.is_empty() {
            let held = info
                .get("taiList")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let held_ranges = info
                .get("taiRangeList")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let hit = wanted.iter().any(|w| {
                held.iter().any(|h| tai_eq(w, h))
                    || held_ranges.iter().any(|r| tai_range_contains(r, w))
            });
            if !hit {
                return false;
            }
        }
    }
    if let Some(wanted) = cond.obj_list_at("taiRangeList") {
        if !wanted.is_empty() {
            let held_ranges = info
                .get("taiRangeList")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let hit = wanted
                .iter()
                .any(|w| held_ranges.iter().any(|h| tai_range_overlaps(w, h)));
            if !hit {
                return false;
            }
        }
    }
    true
}

/// Every `groupId` the profile carries, across its `*Info` containers.
///
/// TS 29.510 puts the NF Group Id inside the per-type info container
/// (`udrInfo.groupId`, `udmInfo.groupId`, `ausfInfo.groupId`, ...), and the
/// `*InfoList` forms hold a map of the same objects. Collecting from every
/// container rather than switching on `nfType` keeps `NfGroupCond` working for
/// any group-bearing NF type without enumerating them, and the condition's own
/// mandatory `nfType` already restricts which profiles get here.
fn profile_group_ids(doc: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    let Some(obj) = doc.as_object() else {
        return ids;
    };
    let mut push = |v: &serde_json::Value| {
        if let Some(id) = v.get("groupId").and_then(|g| g.as_str()) {
            ids.push(id.to_string());
        }
    };
    for (key, value) in obj {
        if !key.ends_with("Info") && !key.ends_with("InfoList") {
            continue;
        }
        if key.ends_with("InfoList") {
            // Map of info objects keyed by an operator-chosen id.
            if let Some(map) = value.as_object() {
                for entry in map.values() {
                    push(entry);
                }
            }
        } else {
            push(value);
        }
    }
    ids
}

/// The profile's `nfSetIdList`, as owned strings.
fn profile_nf_set_ids(doc: &serde_json::Value) -> Vec<String> {
    doc.get("nfSetIdList")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// PLMN equality on the significant members (TS 29.571 `PlmnId`: mcc + mnc).
///
/// Compared member-by-member rather than by whole-value equality so an
/// insignificant difference — a `nid` on one side, a differing key order, an
/// explicit `null` — cannot make two identical PLMNs compare unequal.
fn plmn_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let member = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    !member(a, "mcc").is_empty()
        && member(a, "mcc") == member(b, "mcc")
        && member(a, "mnc") == member(b, "mnc")
}

/// GUAMI equality (TS 29.571 `Guami`: plmnId + amfId).
fn guami_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    fn amf_id(v: &serde_json::Value) -> &str {
        v.get("amfId").and_then(|x| x.as_str()).unwrap_or_default()
    }
    match (a.get("plmnId"), b.get("plmnId")) {
        (Some(pa), Some(pb)) => {
            plmn_eq(pa, pb) && !amf_id(a).is_empty() && amf_id(a).eq_ignore_ascii_case(amf_id(b))
        }
        _ => false,
    }
}

/// S-NSSAI equality (TS 29.571 `Snssai`: sst + optional sd).
///
/// An absent `sd` and an `sd` of `"ffffff"` both mean "no slice differentiator"
/// per TS 23.003, so they compare equal — otherwise a conformant subscriber
/// spelling the default explicitly would never match a profile that omits it.
fn snssai_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let sst = |v: &serde_json::Value| v.get("sst").and_then(|x| x.as_u64());
    let sd = |v: &serde_json::Value| match v.get("sd").and_then(|x| x.as_str()) {
        Some(s) if !s.eq_ignore_ascii_case("ffffff") => Some(s.to_ascii_lowercase()),
        _ => None,
    };
    match (sst(a), sst(b)) {
        (Some(x), Some(y)) => x == y && sd(a) == sd(b),
        _ => false,
    }
}

/// TAI equality (TS 29.571 `Tai`: plmnId + tac, optional nid).
///
/// TAC is compared as a parsed number where both sides parse as hex, so `"0001"`
/// and `"1"` are the same TAC — the schema's pattern permits 3 or 4 hex digits.
fn tai_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let plmn_ok = match (a.get("plmnId"), b.get("plmnId")) {
        (Some(pa), Some(pb)) => plmn_eq(pa, pb),
        _ => false,
    };
    if !plmn_ok {
        return false;
    }
    fn tac(v: &serde_json::Value) -> Option<&str> {
        v.get("tac").and_then(|x| x.as_str())
    }
    match (tac(a), tac(b)) {
        (Some(x), Some(y)) => match (tac_to_u32(x), tac_to_u32(y)) {
            (Some(nx), Some(ny)) => nx == ny,
            _ => x.eq_ignore_ascii_case(y),
        },
        _ => false,
    }
}

/// Parse a TAC (3 or 4 hex digits per TS 29.571 `Tac`) to its numeric value.
fn tac_to_u32(tac: &str) -> Option<u32> {
    u32::from_str_radix(tac.trim(), 16).ok()
}

/// Does `tai` fall inside `range` (TS 29.510 `TaiRange`: plmnId + tacRangeList)?
///
/// A `TacRange` carries either a `start`/`end` pair or a `pattern`. Only the
/// explicit range is evaluated; a pattern-only range does not match, because
/// treating an unevaluated pattern as a hit would widen the serving area to
/// everything, which is the failure mode this whole change removes.
fn tai_range_contains(range: &serde_json::Value, tai: &serde_json::Value) -> bool {
    let plmn_ok = match (range.get("plmnId"), tai.get("plmnId")) {
        (Some(pr), Some(pt)) => plmn_eq(pr, pt),
        _ => false,
    };
    if !plmn_ok {
        return false;
    }
    let Some(tac) = tai.get("tac").and_then(|v| v.as_str()).and_then(tac_to_u32) else {
        return false;
    };
    range
        .get("tacRangeList")
        .and_then(|v| v.as_array())
        .is_some_and(|ranges| {
            ranges.iter().any(|r| match tac_range_bounds(r) {
                Some((start, end)) => tac >= start && tac <= end,
                None => false,
            })
        })
}

/// Do two `TaiRange`s overlap? Same PLMN and at least one overlapping TAC range.
fn tai_range_overlaps(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let plmn_ok = match (a.get("plmnId"), b.get("plmnId")) {
        (Some(pa), Some(pb)) => plmn_eq(pa, pb),
        _ => false,
    };
    if !plmn_ok {
        return false;
    }
    let bounds = |v: &serde_json::Value| {
        v.get("tacRangeList")
            .and_then(|x| x.as_array())
            .map(|ranges| {
                ranges
                    .iter()
                    .filter_map(tac_range_bounds)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let (ra, rb) = (bounds(a), bounds(b));
    ra.iter()
        .any(|(sa, ea)| rb.iter().any(|(sb, eb)| sa <= eb && sb <= ea))
}

/// The numeric `start`..=`end` bounds of a `TacRange`, or `None` for the
/// pattern-only form.
fn tac_range_bounds(range: &serde_json::Value) -> Option<(u32, u32)> {
    let start = range
        .get("start")
        .and_then(|v| v.as_str())
        .and_then(tac_to_u32)?;
    let end = range
        .get("end")
        .and_then(|v| v.as_str())
        .and_then(tac_to_u32)?;
    if start <= end {
        Some((start, end))
    } else {
        Some((end, start))
    }
}

/// Client notification callback result
#[derive(Debug)]
pub enum ClientNotifyResult {
    /// Success
    Ok,
    /// Done (connection closed normally)
    Done,
    /// Error
    Error(String),
}

/// Handle client notification callback
///
/// Called when a notification response is received from a subscriber
pub fn client_notify_cb(status: i32, response_status: Option<u16>) -> ClientNotifyResult {
    if status != 0 {
        let level = if status == 1 { "DEBUG" } else { "WARN" };
        log::log!(
            if level == "DEBUG" {
                log::Level::Debug
            } else {
                log::Level::Warn
            },
            "client_notify_cb() failed [{status}]"
        );
        return if status == 1 {
            ClientNotifyResult::Done
        } else {
            ClientNotifyResult::Error(format!("Status: {status}"))
        };
    }

    if let Some(res_status) = response_status {
        if res_status != 204 {
            // HTTP 204 No Content is expected
            log::warn!("Subscription notification failed [{res_status}]");
        }
    }

    ClientNotifyResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nnrf_handler::{PlmnId, SubscrCond};

    fn create_test_profile() -> NfProfile {
        NfProfile {
            nf_instance_id: "test-nf-123".to_string(),
            nf_type: "AMF".to_string(),
            nf_status: "REGISTERED".to_string(),
            heartbeat_timer: Some(10),
            plmn_list: vec![PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            }],
            ipv4_addresses: vec!["192.168.1.1".to_string()],
            fqdn: Some("amf.example.com".to_string()),
            ..Default::default()
        }
    }

    fn create_test_subscription(nf_type_cond: Option<&str>) -> SubscriptionData {
        SubscriptionData {
            id: "sub-123".to_string(),
            req_nf_type: Some("SMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://smf.example.com/notify".to_string(),
            subscr_cond: nf_type_cond.map(SubscrCond::nf_type),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
        }
    }

    /// A profile built from a full NFProfile document, so the conditions that
    /// match against `attributes` (nfSetIdList, amfInfo, sNssais, ...) have real
    /// data to read.
    fn profile_from(doc: serde_json::Value) -> NfProfile {
        NfProfile::from_json(&doc).expect("valid NFProfile")
    }

    fn cond(raw: serde_json::Value) -> SubscrCond {
        SubscrCond::from_json(&raw).expect("recognised subscrCond")
    }

    fn sub_with_cond(raw: serde_json::Value) -> SubscriptionData {
        SubscriptionData {
            id: "cond-sub".to_string(),
            req_nf_type: None,
            req_nf_instance_id: None,
            notification_uri: "http://consumer.example.com/notify".to_string(),
            subscr_cond: Some(cond(raw)),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
        }
    }

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 7777);
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_sbi_server_uri() {
        let config = SbiServerConfig {
            addr: "10.0.0.1".to_string(),
            port: 8080,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "http://10.0.0.1:8080");
    }

    #[test]
    fn test_sbi_server_uri_tls() {
        let config = SbiServerConfig {
            addr: "10.0.0.1".to_string(),
            port: 443,
            tls_enabled: true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key: Some("/path/to/key".to_string()),
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "https://10.0.0.1:443");
    }

    #[test]
    fn test_sbi_server_add_service() {
        let config = SbiServerConfig::default();
        let mut server = SbiServer::new(config);

        server.add_service(NfServiceInfo {
            name: "nnrf-nfm".to_string(),
            version: "v1".to_string(),
            full_version: "1.0.0".to_string(),
        });

        assert_eq!(server.services.len(), 1);
        assert_eq!(server.services[0].name, "nnrf-nfm");
    }

    #[test]
    fn test_send_nf_status_notify() {
        let subscription = create_test_subscription(Some("AMF"));
        let profile = create_test_profile();

        let result = nrf_nnrf_nfm_send_nf_status_notify(
            &subscription,
            NotificationEventType::NfRegistered,
            &profile,
            "http://nrf.example.com",
        );

        match result {
            NotifySendResult::Success => {}
            _ => panic!("Expected success"),
        }
    }

    #[test]
    fn test_send_nf_status_notify_all_matching() {
        let profile = create_test_profile();
        let subscriptions = vec![
            create_test_subscription(Some("AMF")), // Should match
            create_test_subscription(Some("SMF")), // Should not match
        ];

        let result = nrf_nnrf_nfm_send_nf_status_notify_all(
            NotificationEventType::NfRegistered,
            &profile,
            "http://nrf.example.com",
            &subscriptions,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Only one subscription matches
    }

    #[test]
    fn test_send_nf_status_notify_all_skip_self() {
        let profile = create_test_profile();
        let mut subscription = create_test_subscription(Some("AMF"));
        subscription.req_nf_instance_id = Some("test-nf-123".to_string()); // Same as profile

        let subscriptions = vec![subscription];

        let result = nrf_nnrf_nfm_send_nf_status_notify_all(
            NotificationEventType::NfRegistered,
            &profile,
            "http://nrf.example.com",
            &subscriptions,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // Should skip self
    }

    #[test]
    fn test_client_notify_cb_success() {
        let result = client_notify_cb(0, Some(204));
        match result {
            ClientNotifyResult::Ok => {}
            _ => panic!("Expected Ok"),
        }
    }

    #[test]
    fn test_client_notify_cb_done() {
        let result = client_notify_cb(1, None);
        match result {
            ClientNotifyResult::Done => {}
            _ => panic!("Expected Done"),
        }
    }

    #[test]
    fn test_client_notify_cb_error() {
        let result = client_notify_cb(2, None);
        match result {
            ClientNotifyResult::Error(_) => {}
            _ => panic!("Expected Error"),
        }
    }

    #[test]
    fn test_client_notify_cb_wrong_status() {
        // Should still return Ok but log a warning
        let result = client_notify_cb(0, Some(500));
        match result {
            ClientNotifyResult::Ok => {}
            _ => panic!("Expected Ok even with wrong status"),
        }
    }

    #[test]
    fn test_nf_type_from_str() {
        // Common NRF-notification consumers map correctly, case-insensitively.
        assert_eq!(nf_type_from_str("AMF"), Some(NfType::Amf));
        assert_eq!(nf_type_from_str("smf"), Some(NfType::Smf));
        assert_eq!(nf_type_from_str("Pcf"), Some(NfType::Pcf));
        assert_eq!(nf_type_from_str("UDR"), Some(NfType::Udr));
        // Genuinely unknown values stay None. The caller must NOT substitute a
        // default: for OAuth2 scoping a default means a token minted for the
        // wrong audience.
        assert_eq!(nf_type_from_str("WHATEVER"), None);
        assert_eq!(nf_type_from_str(""), None);
    }

    #[test]
    fn test_nf_type_from_str_covers_types_beyond_the_old_local_table() {
        // Regression: this mapping used to be a local 11-entry table, so every
        // other TS 29.510 NFType returned None and was then coerced to
        // NfType::Amf by dispatch_notify_request_async's `.unwrap_or`. Those
        // subscribers got an AMF-audience OAuth2 token.
        //
        // Each of these is a legitimate NRF subscriber that the old table missed.
        assert_eq!(nf_type_from_str("SEPP"), Some(NfType::Sepp));
        assert_eq!(nf_type_from_str("UPF"), Some(NfType::Upf));
        assert_eq!(nf_type_from_str("NWDAF"), Some(NfType::Nwdaf));
        assert_eq!(nf_type_from_str("CHF"), Some(NfType::Chf));
        assert_eq!(nf_type_from_str("EASDF"), Some(NfType::Easdf));
        assert_eq!(nf_type_from_str("TSCTSF"), Some(NfType::Tsctsf));
        assert_eq!(nf_type_from_str("NSACF"), Some(NfType::Nsacf));
        assert_eq!(nf_type_from_str("MBSMF"), Some(NfType::Mbsmf));
        // Underscored spellings from TS 29.510 must parse too.
        assert_eq!(nf_type_from_str("5G_EIR"), Some(NfType::FiveGEir));
        assert_eq!(nf_type_from_str("SMSF_5G"), Some(NfType::Smsf5G));
        // None of them may resolve to AMF.
        for raw in [
            "SEPP", "UPF", "NWDAF", "CHF", "EASDF", "TSCTSF", "NSACF", "MBSMF", "5G_EIR", "SMSF_5G",
        ] {
            assert_ne!(
                nf_type_from_str(raw),
                Some(NfType::Amf),
                "{raw} must not be scoped as AMF"
            );
        }
    }

    // ------------------------------------------------------------------
    // #68 criterion 5: SubscrCond matching honours the discriminator
    // variants instead of collapsing to match-all.
    // ------------------------------------------------------------------

    /// The defect this replaces, stated as a test.
    ///
    /// The old model read `nfType`/`serviceName`/`nfInstanceId` out of whatever
    /// object arrived. A conformant `NfSetCond`, `AmfCond`, `NfGroupCond` or
    /// `NetworkSliceCond` carries none of those three, so it parsed to a
    /// condition with all three fields `None` — and `subscription_matches` then
    /// fell through every `if let` and returned `true`. Every such subscriber
    /// received a notification for every NF in the registry.
    #[test]
    fn narrow_conditions_do_not_match_an_unrelated_nf() {
        // A plain AMF: no nfSetIdList, no amfInfo, no sNssais, no group id.
        let amf = profile_from(serde_json::json!({
            "nfInstanceId": "amf-unrelated",
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
        }));

        for raw in [
            serde_json::json!({ "nfSetId": "set-1" }),
            serde_json::json!({ "amfSetId": "set-1" }),
            serde_json::json!({ "amfRegionId": "01" }),
            serde_json::json!({ "guamiList": [{ "plmnId": {"mcc": "001", "mnc": "01"},
                                                "amfId": "cafe00" }] }),
            serde_json::json!({ "snssaiList": [{ "sst": 1 }] }),
            serde_json::json!({ "nfType": "UDM", "nfGroupId": "group-1" }),
            serde_json::json!({ "nfServiceSetId": "svcset-1" }),
            serde_json::json!({ "scpDomains": ["dom-1"] }),
            serde_json::json!({ "nfInstanceIdList": ["someone-else"] }),
            serde_json::json!({ "conditionType": "SERVICE_NAME_LIST_COND",
                                "serviceNameList": ["nsmf-pdusession"] }),
            serde_json::json!({ "conditionType": "UPF_COND" }),
            serde_json::json!({ "conditionType": "NWDAF_COND" }),
            serde_json::json!({ "conditionType": "NEF_COND" }),
            serde_json::json!({ "conditionType": "DCCF_COND" }),
        ] {
            let sub = sub_with_cond(raw.clone());
            assert!(
                !subscription_matches(&sub, &amf),
                "condition {raw} must not match an unrelated AMF; matching it is \
                 the match-all defect"
            );
        }
    }

    /// The positive half: each variant matches the profile it names. Asserting
    /// only the negative above would pass for an implementation that matches
    /// nothing at all.
    #[test]
    fn each_condition_variant_matches_its_own_profile() {
        let amf = profile_from(serde_json::json!({
            "nfInstanceId": "amf-1",
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
            "nfSetIdList": ["set-1", "set-2"],
            "sNssais": [{"sst": 1, "sd": "0000ab"}, {"sst": 2}],
            "nsiList": ["nsi-7"],
            "scpDomains": ["dom-1"],
            "amfInfo": {
                "amfSetId": "set-a",
                "amfRegionId": "01",
                "guamiList": [{"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe00"}],
            },
            "nfServices": [{
                "serviceInstanceId": "s1",
                "serviceName": "namf-comm",
                "versions": [],
                "scheme": "http",
                "nfServiceSetIdList": ["svcset-1"],
            }],
        }));

        let cases = [
            (
                "NfInstanceIdCond",
                serde_json::json!({ "nfInstanceId": "amf-1" }),
            ),
            (
                "NfInstanceIdListCond",
                serde_json::json!({ "nfInstanceIdList": ["other", "amf-1"] }),
            ),
            ("NfTypeCond", serde_json::json!({ "nfType": "AMF" })),
            (
                "ServiceNameCond",
                serde_json::json!({ "serviceName": "namf-comm" }),
            ),
            (
                "ServiceNameListCond",
                serde_json::json!({ "conditionType": "SERVICE_NAME_LIST_COND",
                                 "serviceNameList": ["nsmf-pdusession", "namf-comm"] }),
            ),
            (
                "AmfCond (set only)",
                serde_json::json!({ "amfSetId": "set-a" }),
            ),
            (
                "AmfCond (set + region)",
                serde_json::json!({ "amfSetId": "set-a", "amfRegionId": "01" }),
            ),
            (
                "GuamiListCond",
                serde_json::json!({ "guamiList": [{"plmnId": {"mcc": "001", "mnc": "01"},
                                                "amfId": "cafe00"}] }),
            ),
            (
                "NetworkSliceCond",
                serde_json::json!({ "snssaiList": [{"sst": 2}] }),
            ),
            (
                "NetworkSliceCond + nsiList",
                serde_json::json!({ "snssaiList": [{"sst": 2}], "nsiList": ["nsi-7"] }),
            ),
            ("NfSetCond", serde_json::json!({ "nfSetId": "set-2" })),
            (
                "NfServiceSetCond",
                serde_json::json!({ "nfServiceSetId": "svcset-1" }),
            ),
            (
                "NfServiceSetCond + nfSetId",
                serde_json::json!({ "nfServiceSetId": "svcset-1", "nfSetId": "set-1" }),
            ),
            (
                "ScpDomainCond",
                serde_json::json!({ "scpDomains": ["dom-0", "dom-1"] }),
            ),
            (
                "ScpDomainCond + nfTypeList",
                serde_json::json!({ "scpDomains": ["dom-1"], "nfTypeList": ["AMF"] }),
            ),
        ];
        for (name, raw) in cases {
            let sub = sub_with_cond(raw.clone());
            assert!(
                subscription_matches(&sub, &amf),
                "{name} ({raw}) must match the profile it names"
            );
        }

        // And each optional extra criterion genuinely narrows: flip only the
        // extra and the same condition must stop matching.
        for raw in [
            serde_json::json!({ "amfSetId": "set-a", "amfRegionId": "02" }),
            serde_json::json!({ "snssaiList": [{"sst": 2}], "nsiList": ["nsi-other"] }),
            serde_json::json!({ "nfServiceSetId": "svcset-1", "nfSetId": "set-absent" }),
            serde_json::json!({ "scpDomains": ["dom-1"], "nfTypeList": ["SMF"] }),
        ] {
            let sub = sub_with_cond(raw.clone());
            assert!(
                !subscription_matches(&sub, &amf),
                "the extra criterion in {raw} must narrow the match"
            );
        }
    }

    /// A group id lives inside the per-type `*Info` container, and the
    /// `*InfoList` map form holds the same objects.
    #[test]
    fn nf_group_conditions_read_the_group_id_out_of_the_info_container() {
        let udm = profile_from(serde_json::json!({
            "nfInstanceId": "udm-1",
            "nfType": "UDM",
            "nfStatus": "REGISTERED",
            "udmInfo": { "groupId": "udm-group-7" },
        }));
        let udr = profile_from(serde_json::json!({
            "nfInstanceId": "udr-1",
            "nfType": "UDR",
            "nfStatus": "REGISTERED",
            "udrInfoList": { "a": { "groupId": "udr-group-9" } },
        }));

        assert!(subscription_matches(
            &sub_with_cond(serde_json::json!({"nfType": "UDM", "nfGroupId": "udm-group-7"})),
            &udm
        ));
        assert!(subscription_matches(
            &sub_with_cond(serde_json::json!({
                "conditionType": "NF_GROUP_LIST_COND",
                "nfType": "UDR",
                "nfGroupIdList": ["udr-group-0", "udr-group-9"],
            })),
            &udr
        ));

        // The condition's mandatory nfType still restricts: the right group id
        // on the wrong NF type must not match.
        assert!(!subscription_matches(
            &sub_with_cond(serde_json::json!({"nfType": "UDR", "nfGroupId": "udm-group-7"})),
            &udm
        ));
        // ... and so does the group id: right type, wrong group.
        assert!(!subscription_matches(
            &sub_with_cond(serde_json::json!({"nfType": "UDM", "nfGroupId": "udm-group-other"})),
            &udm
        ));
    }

    /// A `conditionType`-tagged condition names the NF type it is about, so it
    /// must not match another type's profile even when that profile happens to
    /// carry nothing to compare against.
    #[test]
    fn conditiontype_conditions_are_restricted_to_their_own_nf_type() {
        let upf = profile_from(serde_json::json!({
            "nfInstanceId": "upf-1",
            "nfType": "UPF",
            "nfStatus": "REGISTERED",
            "upfInfo": { "smfServingArea": ["area-1"] },
        }));
        let smf = profile_from(serde_json::json!({
            "nfInstanceId": "smf-1",
            "nfType": "SMF",
            "nfStatus": "REGISTERED",
        }));

        let bare_upf_cond = sub_with_cond(serde_json::json!({"conditionType": "UPF_COND"}));
        assert!(
            subscription_matches(&bare_upf_cond, &upf),
            "conditionType alone is the only mandatory member, so a bare \
             UPF_COND legitimately means every UPF"
        );
        assert!(
            !subscription_matches(&bare_upf_cond, &smf),
            "a UPF condition must never match an SMF"
        );

        // smfServingArea narrows within the type.
        assert!(subscription_matches(
            &sub_with_cond(serde_json::json!({
                "conditionType": "UPF_COND", "smfServingArea": ["area-1"]
            })),
            &upf
        ));
        assert!(!subscription_matches(
            &sub_with_cond(serde_json::json!({
                "conditionType": "UPF_COND", "smfServingArea": ["area-absent"]
            })),
            &upf
        ));
    }

    /// Serving-area narrowing for the NWDAF/NEF/DCCF conditions: an explicit TAI
    /// list and a TAI range both count as a hit, and a TAI outside both does not.
    #[test]
    fn serving_area_conditions_match_a_tai_list_or_a_tai_range() {
        let nwdaf = profile_from(serde_json::json!({
            "nfInstanceId": "nwdaf-1",
            "nfType": "NWDAF",
            "nfStatus": "REGISTERED",
            "sNssais": [{"sst": 1}],
            "nwdafInfo": {
                "eventIds": ["NF_LOAD"],
                "taiList": [{"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "0001"}],
                "taiRangeList": [{
                    "plmnId": {"mcc": "001", "mnc": "01"},
                    "tacRangeList": [{"start": "0100", "end": "0200"}],
                }],
            },
        }));

        let tai = |tac: &str| {
            serde_json::json!({"taiList": [{"plmnId": {"mcc": "001", "mnc": "01"}, "tac": tac}],
                               "conditionType": "NWDAF_COND"})
        };
        assert!(
            subscription_matches(&sub_with_cond(tai("0001")), &nwdaf),
            "an explicitly listed TAI must match"
        );
        assert!(
            subscription_matches(&sub_with_cond(tai("0150")), &nwdaf),
            "a TAI inside the profile's TAC range must match"
        );
        assert!(
            !subscription_matches(&sub_with_cond(tai("0300")), &nwdaf),
            "a TAI outside both the list and the range must not match"
        );

        // analyticsIds narrow against NwdafInfo eventIds / nwdafEvents.
        assert!(subscription_matches(
            &sub_with_cond(serde_json::json!({
                "conditionType": "NWDAF_COND", "analyticsIds": ["NF_LOAD"]
            })),
            &nwdaf
        ));
        assert!(!subscription_matches(
            &sub_with_cond(serde_json::json!({
                "conditionType": "NWDAF_COND", "analyticsIds": ["UE_MOBILITY"]
            })),
            &nwdaf
        ));

        // A pattern-only TacRange is not evaluated, and must therefore NOT be
        // read as a match — treating it as one would widen the serving area to
        // everything, which is the failure mode being removed.
        let pattern_only = profile_from(serde_json::json!({
            "nfInstanceId": "nwdaf-2",
            "nfType": "NWDAF",
            "nfStatus": "REGISTERED",
            "nwdafInfo": {
                "taiRangeList": [{
                    "plmnId": {"mcc": "001", "mnc": "01"},
                    "tacRangeList": [{"pattern": "^01.*$"}],
                }],
            },
        }));
        assert!(!subscription_matches(
            &sub_with_cond(tai("0150")),
            &pattern_only
        ));
    }

    /// The identity comparators compare significant members only, so an
    /// insignificant spelling difference cannot make two identical values differ.
    #[test]
    fn identity_comparators_ignore_insignificant_differences() {
        // sd absent == sd "ffffff" (TS 23.003: no slice differentiator).
        assert!(snssai_eq(
            &serde_json::json!({"sst": 1}),
            &serde_json::json!({"sst": 1, "sd": "FFFFFF"})
        ));
        assert!(!snssai_eq(
            &serde_json::json!({"sst": 1, "sd": "0000ab"}),
            &serde_json::json!({"sst": 1})
        ));
        // sd is hex, so case must not distinguish two identical S-NSSAIs.
        assert!(snssai_eq(
            &serde_json::json!({"sst": 1, "sd": "0000AB"}),
            &serde_json::json!({"sst": 1, "sd": "0000ab"})
        ));
        // A differing sst is a different slice even with the same sd.
        assert!(!snssai_eq(
            &serde_json::json!({"sst": 1, "sd": "0000ab"}),
            &serde_json::json!({"sst": 2, "sd": "0000ab"})
        ));

        // TAC is hex, so "0001" and "1" are the same TAC.
        let tai =
            |tac: &str| serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01"}, "tac": tac});
        assert!(tai_eq(&tai("0001"), &tai("1")));
        assert!(!tai_eq(&tai("0001"), &tai("0002")));
        // A different PLMN is a different TAI even with the same TAC.
        assert!(!tai_eq(
            &tai("0001"),
            &serde_json::json!({"plmnId": {"mcc": "002", "mnc": "01"}, "tac": "0001"})
        ));

        // A GUAMI needs both PLMN and amfId; amfId is hex, so case must not
        // distinguish. An extra nid on one side must not either.
        let guami = serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "CAFE00"});
        assert!(guami_eq(
            &guami,
            &serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01", "nid": "00000000000"},
                                "amfId": "cafe00"})
        ));
        assert!(!guami_eq(
            &guami,
            &serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "cafe01"})
        ));
        // A GUAMI with no amfId at all must not match anything.
        assert!(!guami_eq(
            &serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01"}}),
            &guami
        ));
    }

    // ------------------------------------------------------------------
    // #68 criterion 4: reqNotifEvents and notifCondition are honoured.
    // ------------------------------------------------------------------

    /// `reqNotifEvents` was dropped on parse, so a subscriber asking only for
    /// NF_DEREGISTERED still received every registration and profile change.
    #[test]
    fn req_notif_events_gates_the_delivered_event() {
        let mut sub = create_test_subscription(None);

        // Absent list == no restriction (an omitted filter is unconstrained).
        for event in [
            NotificationEventType::NfRegistered,
            NotificationEventType::NfDeregistered,
            NotificationEventType::NfProfileChanged,
        ] {
            assert!(subscription_accepts_event(&sub, event));
        }

        sub.req_notif_events = Some(vec!["NF_DEREGISTERED".to_string()]);
        assert!(subscription_accepts_event(
            &sub,
            NotificationEventType::NfDeregistered
        ));
        assert!(
            !subscription_accepts_event(&sub, NotificationEventType::NfRegistered),
            "a subscriber that asked only for NF_DEREGISTERED must not be sent \
             NF_REGISTERED"
        );
        assert!(!subscription_accepts_event(
            &sub,
            NotificationEventType::NfProfileChanged
        ));

        // Multiple requested events are all honoured.
        sub.req_notif_events = Some(vec![
            "NF_REGISTERED".to_string(),
            "NF_PROFILE_CHANGED".to_string(),
        ]);
        assert!(subscription_accepts_event(
            &sub,
            NotificationEventType::NfRegistered
        ));
        assert!(subscription_accepts_event(
            &sub,
            NotificationEventType::NfProfileChanged
        ));
        assert!(!subscription_accepts_event(
            &sub,
            NotificationEventType::NfDeregistered
        ));
    }

    /// `notifCondition` narrows NF_PROFILE_CHANGED to the attributes the
    /// subscriber actually cares about.
    #[test]
    fn notif_condition_gates_profile_changes_by_attribute() {
        use crate::nnrf_handler::NotifCondition;

        let mut sub = create_test_subscription(None);
        let load_change = vec!["load".to_string()];
        let capacity_change = vec!["capacity".to_string()];

        // Absent condition == no restriction.
        assert!(subscription_accepts_profile_changes(&sub, &load_change));

        sub.notif_condition = Some(NotifCondition {
            monitored_attributes: Some(vec!["load".to_string()]),
            unmonitored_attributes: None,
        });
        assert!(subscription_accepts_profile_changes(&sub, &load_change));
        assert!(
            !subscription_accepts_profile_changes(&sub, &capacity_change),
            "monitoredAttributes is an allowlist: an unlisted attribute must not \
             be notified"
        );

        sub.notif_condition = Some(NotifCondition {
            monitored_attributes: None,
            unmonitored_attributes: Some(vec!["load".to_string()]),
        });
        assert!(
            !subscription_accepts_profile_changes(&sub, &load_change),
            "unmonitoredAttributes is a denylist"
        );
        assert!(subscription_accepts_profile_changes(&sub, &capacity_change));

        // A change touching several attributes is notified when ANY of them is
        // monitored — dropping it would lose a change the subscriber asked for.
        sub.notif_condition = Some(NotifCondition {
            monitored_attributes: Some(vec!["load".to_string()]),
            unmonitored_attributes: None,
        });
        assert!(subscription_accepts_profile_changes(
            &sub,
            &["capacity".to_string(), "load".to_string()]
        ));

        // An empty change list is a complete-replacement notification (the
        // profile is carried instead of a change list), so it is not narrowed.
        assert!(subscription_accepts_profile_changes(&sub, &[]));
    }

    /// `notifCondition` is expressed over top-level NFProfile attributes, so a
    /// nested RFC 6902 path must reduce to its first segment.
    #[test]
    fn changed_attribute_names_reduce_a_json_pointer_to_its_first_segment() {
        let changes = vec![
            ChangeItem {
                op: "replace".to_string(),
                path: "/load".to_string(),
                value: None,
                orig_value: None,
            },
            ChangeItem {
                op: "replace".to_string(),
                path: "/nfServices/0/priority".to_string(),
                value: None,
                orig_value: None,
            },
            // A path with no leading slash, and the whole-document path, must
            // not produce an empty attribute name that matches nothing.
            ChangeItem {
                op: "replace".to_string(),
                path: "capacity".to_string(),
                value: None,
                orig_value: None,
            },
            ChangeItem {
                op: "replace".to_string(),
                path: "/".to_string(),
                value: None,
                orig_value: None,
            },
        ];
        assert_eq!(
            changed_attribute_names(&changes),
            vec![
                "load".to_string(),
                "nfServices".to_string(),
                "capacity".to_string()
            ]
        );
    }
}
