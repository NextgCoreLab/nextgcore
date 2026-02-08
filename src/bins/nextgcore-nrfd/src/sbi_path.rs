//! NRF SBI Path Implementation
//!
//! Port of src/nrf/sbi-path.c - SBI server open/close and notification sending

use crate::nnrf_build::{nrf_nnrf_nfm_build_nf_status_notify, NotificationEventType};
use crate::nnrf_handler::{nf_manager, NfProfile, SubscriptionData};
use ogs_sbi::client::{SbiClient, SbiClientConfig};
use ogs_sbi::message::SbiRequest;
use ogs_sbi::types::UriScheme;
use std::sync::atomic::{AtomicBool, Ordering};

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

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
        let scheme = if self.config.tls_enabled { "https" } else { "http" };
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

    log::info!(
        "NRF SBI server opened at {}",
        server.uri()
    );

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

/// Send NF status notify to a single subscriber (async version)
///
/// Builds and sends an NF status notification to the subscriber's callback URI
/// using the ogs-sbi HTTP/2 client.
pub async fn nrf_nnrf_nfm_send_nf_status_notify_async(
    subscription_data: &SubscriptionData,
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
) -> NotifySendResult {
    // Build the notification request
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

    log::debug!(
        "Sending NF status notify to {} (event={:?}, nf_instance={})",
        notify_request.uri,
        event,
        nf_instance.nf_instance_id
    );

    // Parse the notification URI to extract host and port
    let (host, port, path, scheme) = match parse_notification_uri(&notify_request.uri) {
        Some(parts) => parts,
        None => {
            log::error!(
                "Failed to parse notification URI: {}",
                notify_request.uri
            );
            return NotifySendResult::Failed(format!(
                "Invalid notification URI: {}",
                notify_request.uri
            ));
        }
    };

    // Build an SBI client for the subscriber endpoint
    let client_config = SbiClientConfig::new(&host, port).with_scheme(scheme);
    let client = SbiClient::new(client_config);

    // Build the SBI request
    let sbi_request = SbiRequest::post(&path)
        .with_header("Content-Type", &notify_request.content_type)
        .with_header("Accept", &notify_request.accept)
        .with_body(notify_request.body.clone(), &notify_request.content_type);

    // Send the notification
    match client.send_request(sbi_request).await {
        Ok(response) => {
            let status = response.status;
            if status == 204 || (200..300).contains(&status) {
                log::info!(
                    "NF status notify delivered: {} -> {} ({}) [HTTP {}]",
                    nf_instance.nf_instance_id,
                    subscription_data.notification_uri,
                    event.as_str(),
                    status
                );
                NotifySendResult::Success
            } else {
                log::warn!(
                    "NF status notify rejected: {} -> {} ({}) [HTTP {}]",
                    nf_instance.nf_instance_id,
                    subscription_data.notification_uri,
                    event.as_str(),
                    status
                );
                NotifySendResult::Failed(format!("HTTP {status}"))
            }
        }
        Err(e) => {
            log::error!(
                "Failed to deliver NF status notify to {}: {}",
                subscription_data.notification_uri,
                e
            );
            NotifySendResult::Failed(e.to_string())
        }
    }
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

        // Send notification asynchronously
        match nrf_nnrf_nfm_send_nf_status_notify_async(
            subscription,
            event,
            nf_instance,
            server_uri,
        )
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
                log::warn!(
                    "No client for subscription {}",
                    subscription.id
                );
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
                log::warn!(
                    "No client for subscription {}",
                    subscription.id
                );
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

    // Check subscription condition
    if let Some(ref subscr_cond) = subscription.subscr_cond {
        // Check NF type condition
        if let Some(ref cond_nf_type) = subscr_cond.nf_type {
            if cond_nf_type != &nf_instance.nf_type {
                return false;
            }
        }
        // Check service name condition
        else if let Some(ref cond_service_name) = subscr_cond.service_name {
            let has_service = nf_instance
                .nf_services
                .iter()
                .any(|s| &s.service_name == cond_service_name);
            if !has_service {
                return false;
            }
        }
        // Check NF instance ID condition
        else if let Some(ref cond_nf_instance_id) = subscr_cond.nf_instance_id {
            if cond_nf_instance_id != &nf_instance.nf_instance_id {
                return false;
            }
        }
    }

    true
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
            ipv6_addresses: vec![],
            fqdn: Some("amf.example.com".to_string()),
            nf_services: vec![],
        }
    }

    fn create_test_subscription(nf_type_cond: Option<&str>) -> SubscriptionData {
        SubscriptionData {
            id: "sub-123".to_string(),
            req_nf_type: Some("SMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://smf.example.com/notify".to_string(),
            subscr_cond: nf_type_cond.map(|t| SubscrCond {
                nf_type: Some(t.to_string()),
                service_name: None,
                nf_instance_id: None,
            }),
            validity_duration: 3600,
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
}
