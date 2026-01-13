//! NextGCore SMF (Session Management Function)
//!
//! The SMF handles PDU session management in 5G Core and EPC networks.
//!
//! # Architecture
//!
//! The SMF consists of several key components:
//! - Context management (UE, Session, Bearer contexts)
//! - State machines (SMF, GSM, PFCP)
//! - Protocol handlers (N4/PFCP, GTP-C, SBI)
//! - Policy binding (PCC rules to bearers/QoS flows)
//!
//! # Supported Interfaces
//!
//! - N4: PFCP interface to UPF
//! - N7: Policy control interface to PCF
//! - N10: UE context management interface to UDM
//! - N11: PDU session management interface from AMF
//! - S5/S8: GTP-C interface to SGW (EPC mode)

use anyhow::{Context, Result};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod binding;
mod context;
mod event;
mod gsm_build;
mod gsm_handler;
mod gsm_sm;
mod gtp_build;
mod gtp_handler;
mod gtp_path;
mod gn_build;
mod gn_handler;
mod n4_build;
mod n4_handler;
mod pfcp_path;
mod pfcp_sm;
#[cfg(test)]
mod property_tests;
mod smf_sm;
mod timer;

use context::{smf_context_init, smf_context_final, smf_self};
use smf_sm::SmfFsm;

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Configuration loaded from YAML
struct SmfConfig {
    sbi_addr: String,
    sbi_port: u16,
    max_ue: usize,
    max_sess: usize,
    max_bearer: usize,
}

impl Default for SmfConfig {
    fn default() -> Self {
        Self {
            sbi_addr: "0.0.0.0".to_string(),
            sbi_port: 7777,
            max_ue: 1024,
            max_sess: 4096,
            max_bearer: 8192,
        }
    }
}

fn load_config(path: &str) -> SmfConfig {
    let mut config = SmfConfig::default();

    if let Ok(content) = std::fs::read_to_string(path) {
        // Parse YAML configuration - look for sbi.server section
        let mut in_smf_section = false;
        let mut in_sbi_section = false;
        let mut in_sbi_server_section = false;
        let mut found_sbi_addr = false;
        let mut found_sbi_port = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Track which section we're in based on indentation
            if line.starts_with("smf:") {
                in_smf_section = true;
                in_sbi_section = false;
                in_sbi_server_section = false;
            } else if in_smf_section && line.starts_with("  sbi:") {
                in_sbi_section = true;
                in_sbi_server_section = false;
            } else if in_smf_section && in_sbi_section && line.starts_with("    server:") {
                in_sbi_server_section = true;
            } else if in_smf_section && in_sbi_section && in_sbi_server_section {
                // Check if we've exited the server section
                // Server entries start with 6 spaces (for "- address:") or more
                if !trimmed.is_empty() && !line.starts_with("      ") {
                    in_sbi_server_section = false;
                }
            } else if in_smf_section && in_sbi_section {
                // Check if we've exited the sbi section
                // sbi subsections start with 4 spaces
                if !trimmed.is_empty() && !line.starts_with("    ") && !line.starts_with("  sbi:") {
                    in_sbi_section = false;
                }
            } else if in_smf_section {
                // Check if we've exited the smf section
                if !trimmed.is_empty() && !line.starts_with("  ") && !line.starts_with("smf:") {
                    in_smf_section = false;
                }
            }

            // Extract values only from smf.sbi.server section
            if in_smf_section && in_sbi_section && in_sbi_server_section {
                if !found_sbi_addr && (trimmed.starts_with("- address:") || trimmed.starts_with("address:")) {
                    if let Some(addr) = trimmed.split(':').nth(1) {
                        let addr = addr.trim();
                        // Skip IPv4/IPv6 addresses with port suffix
                        if !addr.contains(':') {
                            config.sbi_addr = addr.to_string();
                            found_sbi_addr = true;
                        }
                    }
                } else if !found_sbi_port && trimmed.starts_with("port:") {
                    if let Some(port) = trimmed.split(':').nth(1) {
                        if let Ok(p) = port.trim().parse() {
                            config.sbi_port = p;
                            found_sbi_port = true;
                        }
                    }
                }
            }
        }
    }

    config
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    log::info!("NextGCore SMF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    // Load configuration
    let config_path = std::env::var("SMF_CONFIG")
        .unwrap_or_else(|_| "/etc/nextgcore/nextgcore-smfd.yaml".to_string());
    let config = load_config(&config_path);
    log::info!("Loading configuration from {}", config_path);
    log::info!("SBI config: address={}, port={}", config.sbi_addr, config.sbi_port);

    // Initialize SMF context
    smf_context_init(config.max_ue, config.max_sess, config.max_bearer);
    log::info!("SMF context initialized (max_ue={}, max_sess={}, max_bearer={})",
        config.max_ue, config.max_sess, config.max_bearer);

    // Initialize SMF state machine
    let mut smf_sm = SmfFsm::new();
    smf_sm.init();
    log::info!("SMF state machine initialized");

    // Start SBI HTTP/2 server
    let sbi_addr: SocketAddr = format!("{}:{}", config.sbi_addr, config.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(smf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore SMF ready");

    // Main async event loop
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));

    loop {
        interval.tick().await;

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }

        // Process timer expirations and state machine updates
        // In a full implementation, this would check the timer manager
    }

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Cleanup state machine
    smf_sm.fini();
    log::info!("SMF state machine finalized");
    drop(smf_sm);

    // Cleanup context
    smf_context_final();
    log::info!("SMF context finalized");

    log::info!("NextGCore SMF stopped");
    Ok(())
}

/// SBI request handler for SMF
async fn smf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("SMF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];
    let resource_id = parts.get(3).copied();

    match (service, resource, method) {
        // =====================================================================
        // PDU Session Management Service (nsmf-pdusession)
        // =====================================================================

        // Create SM Context (N11)
        // POST /nsmf-pdusession/v1/sm-contexts
        ("nsmf-pdusession", "sm-contexts", "POST") if resource_id.is_none() => {
            handle_sm_context_create(&request).await
        }

        // Update SM Context
        // POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
        ("nsmf-pdusession", "sm-contexts", "POST") if parts.len() >= 5 && parts[4] == "modify" => {
            let sm_context_ref = parts[3];
            handle_sm_context_update(sm_context_ref, &request).await
        }

        // Release SM Context
        // POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/release
        ("nsmf-pdusession", "sm-contexts", "POST") if parts.len() >= 5 && parts[4] == "release" => {
            let sm_context_ref = parts[3];
            handle_sm_context_release(sm_context_ref).await
        }

        // Retrieve SM Context
        // POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/retrieve
        ("nsmf-pdusession", "sm-contexts", "POST") if parts.len() >= 5 && parts[4] == "retrieve" => {
            let sm_context_ref = parts[3];
            handle_sm_context_retrieve(sm_context_ref).await
        }

        // Create PDU Session
        // POST /nsmf-pdusession/v1/pdu-sessions
        ("nsmf-pdusession", "pdu-sessions", "POST") if resource_id.is_none() => {
            handle_pdu_session_create(&request).await
        }

        // Update PDU Session
        // POST /nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/modify
        ("nsmf-pdusession", "pdu-sessions", "POST") if parts.len() >= 5 && parts[4] == "modify" => {
            let pdu_session_ref = parts[3];
            handle_pdu_session_update(pdu_session_ref).await
        }

        // Release PDU Session
        // POST /nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/release
        ("nsmf-pdusession", "pdu-sessions", "POST") if parts.len() >= 5 && parts[4] == "release" => {
            let pdu_session_ref = parts[3];
            handle_pdu_session_release(pdu_session_ref).await
        }

        // =====================================================================
        // Event Exposure Service (nsmf-event-exposure)
        // =====================================================================

        // Subscribe to events
        // POST /nsmf-event-exposure/v1/subscriptions
        ("nsmf-event-exposure", "subscriptions", "POST") => {
            handle_event_subscribe().await
        }

        // Unsubscribe from events
        // DELETE /nsmf-event-exposure/v1/subscriptions/{subscriptionId}
        ("nsmf-event-exposure", "subscriptions", "DELETE") => {
            if let Some(sub_id) = resource_id {
                handle_event_unsubscribe(sub_id).await
            } else {
                send_bad_request("Missing subscription ID", None)
            }
        }

        // =====================================================================
        // Callback handlers (from other NFs)
        // =====================================================================

        // SM Policy Update Notification (from PCF)
        ("nsmf-callback", "sm-policy-notify", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                handle_sm_policy_notify(sm_context_ref).await
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // N1N2 Transfer Failure Notification (from AMF)
        ("nsmf-callback", "n1-n2-failure", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                handle_n1n2_transfer_failure(sm_context_ref).await
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // AMF Status Change Notification
        ("nsmf-callback", "amf-status", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                handle_amf_status_change(sm_context_ref).await
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // Default: unknown endpoint
        _ => {
            log::warn!("Unknown SBI endpoint: {} {}", method, path);
            send_not_found("Unknown endpoint", None)
        }
    }
}

// =============================================================================
// SM Context Handlers
// =============================================================================

/// Handle SM Context Create (from AMF via N11)
async fn handle_sm_context_create(_request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Create request received");

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        let sm_context_ref = format!("{}", context.sess_count() + 1);

        let response_body = serde_json::json!({
            "smContextRef": sm_context_ref,
            "pduSessionId": 1,
            "upCnxState": "ACTIVATING"
        });

        let location = format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context_ref);

        return SbiResponse::with_status(201)
            .with_header("Location", location)
            .with_body(response_body.to_string(), "application/json");
    }

    SbiResponse::with_status(500)
}

/// Handle SM Context Update
async fn handle_sm_context_update(sm_context_ref: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Update request for ref={}", sm_context_ref);

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if context.sess_find_by_sm_context_ref(sm_context_ref).is_some() {
            let response_body = serde_json::json!({
                "upCnxState": "ACTIVATED"
            });

            return SbiResponse::with_status(200)
                .with_body(response_body.to_string(), "application/json");
        }
    }

    let error = serde_json::json!({
        "status": 404,
        "cause": "CONTEXT_NOT_FOUND"
    });
    SbiResponse::with_status(404)
        .with_body(error.to_string(), "application/json")
}

/// Handle SM Context Release
async fn handle_sm_context_release(sm_context_ref: &str) -> SbiResponse {
    log::info!("SM Context Release request for ref={}", sm_context_ref);

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if let Some(sess) = context.sess_find_by_sm_context_ref(sm_context_ref) {
            context.sess_remove(sess.id);
        }
    }

    SbiResponse::with_status(204)
}

/// Handle SM Context Retrieve
async fn handle_sm_context_retrieve(sm_context_ref: &str) -> SbiResponse {
    log::info!("SM Context Retrieve request for ref={}", sm_context_ref);

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if let Some(sess) = context.sess_find_by_sm_context_ref(sm_context_ref) {
            let up_cnx_state = match sess.up_cnx_state {
                context::UpCnxState::Activated => "ACTIVATED",
                context::UpCnxState::Activating => "ACTIVATING",
                context::UpCnxState::Deactivated => "DEACTIVATED",
            };

            let response_body = serde_json::json!({
                "smContextRef": sm_context_ref,
                "pduSessionId": sess.psi,
                "dnn": sess.session_name,
                "sNssai": {
                    "sst": sess.s_nssai.sst,
                    "sd": sess.s_nssai.sd
                },
                "upCnxState": up_cnx_state
            });

            return SbiResponse::with_status(200)
                .with_body(response_body.to_string(), "application/json");
        }
    }

    let error = serde_json::json!({
        "status": 404,
        "cause": "CONTEXT_NOT_FOUND"
    });
    SbiResponse::with_status(404)
        .with_body(error.to_string(), "application/json")
}

// =============================================================================
// PDU Session Handlers
// =============================================================================

/// Handle PDU Session Create
async fn handle_pdu_session_create(_request: &SbiRequest) -> SbiResponse {
    log::info!("PDU Session Create request received");

    let pdu_session_ref = "1";
    let response_body = serde_json::json!({
        "pduSessionRef": pdu_session_ref,
        "cause": "REL_DUE_TO_HO"
    });

    let location = format!("/nsmf-pdusession/v1/pdu-sessions/{}", pdu_session_ref);

    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_body(response_body.to_string(), "application/json")
}

/// Handle PDU Session Update
async fn handle_pdu_session_update(pdu_session_ref: &str) -> SbiResponse {
    log::info!("PDU Session Update request for ref={}", pdu_session_ref);

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if context.sess_find_by_pdu_session_ref(pdu_session_ref).is_some() {
            return SbiResponse::with_status(200);
        }
    }

    SbiResponse::with_status(404)
}

/// Handle PDU Session Release
async fn handle_pdu_session_release(pdu_session_ref: &str) -> SbiResponse {
    log::info!("PDU Session Release request for ref={}", pdu_session_ref);

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if let Some(sess) = context.sess_find_by_pdu_session_ref(pdu_session_ref) {
            context.sess_remove(sess.id);
        }
    }

    SbiResponse::with_status(204)
}

// =============================================================================
// Event Exposure Handlers
// =============================================================================

/// Handle Event Subscribe
async fn handle_event_subscribe() -> SbiResponse {
    log::info!("Event subscription request received");

    let subscription_id = uuid::Uuid::new_v4().to_string();
    let response_body = serde_json::json!({
        "subscriptionId": subscription_id
    });

    let location = format!("/nsmf-event-exposure/v1/subscriptions/{}", subscription_id);

    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_body(response_body.to_string(), "application/json")
}

/// Handle Event Unsubscribe
async fn handle_event_unsubscribe(subscription_id: &str) -> SbiResponse {
    log::info!("Event unsubscription request for id={}", subscription_id);
    SbiResponse::with_status(204)
}

// =============================================================================
// Callback Handlers
// =============================================================================

/// Handle SM Policy Notification (from PCF)
async fn handle_sm_policy_notify(sm_context_ref: &str) -> SbiResponse {
    log::info!("SM Policy notification for ref={}", sm_context_ref);
    SbiResponse::with_status(204)
}

/// Handle N1N2 Transfer Failure (from AMF)
async fn handle_n1n2_transfer_failure(sm_context_ref: &str) -> SbiResponse {
    log::info!("N1N2 transfer failure notification for ref={}", sm_context_ref);
    SbiResponse::with_status(204)
}

/// Handle AMF Status Change Notification
async fn handle_amf_status_change(sm_context_ref: &str) -> SbiResponse {
    log::info!("AMF status change notification for ref={}", sm_context_ref);
    SbiResponse::with_status(204)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smf_config_default() {
        let config = SmfConfig::default();
        assert_eq!(config.sbi_port, 7777);
        assert_eq!(config.max_ue, 1024);
    }
}
