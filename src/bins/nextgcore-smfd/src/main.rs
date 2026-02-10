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

/// Session state: stores UPF SEID per sm_context_ref for PFCP modifications
static PFCP_SESSIONS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

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
// PFCP Client (N4 to UPF)
// =============================================================================

/// PFCP Session Establishment result from UPF
struct PfcpSessionResult {
    upf_seid: u64,
    upf_teid: u32,
    upf_addr: [u8; 4],
}

/// Send PFCP Session Establishment Request to UPF and return UPF TEID
async fn pfcp_session_establish(
    smf_n4_seid: u64,
    ue_ip: [u8; 4],
    dnn: &str,
    sst: u8,
    upf_addr: &str,
    upf_port: u16,
) -> Result<PfcpSessionResult> {
    use n4_build::{PfcpMessageBuilder, PdrParams, FarParams, pfcp_ie};
    use tokio::net::UdpSocket;
    use std::time::Duration;

    log::info!("PFCP Session Establishment: UPF={}:{}, UE IP={}.{}.{}.{}",
        upf_addr, upf_port, ue_ip[0], ue_ip[1], ue_ip[2], ue_ip[3]);

    // Build PFCP payload: F-SEID + Node ID + Create PDR (uplink) + Create FAR (uplink) + Create PDR (downlink) + Create FAR (downlink)
    let smf_ip: [u8; 4] = {
        let s = std::env::var("SMF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() == 4 { [parts[0], parts[1], parts[2], parts[3]] } else { [127, 0, 0, 1] }
    };
    let mut builder = PfcpMessageBuilder::new();

    // Node ID (IPv4)
    builder.add_node_id(&smf_ip);

    // F-SEID (SMF's SEID)
    builder.add_f_seid(smf_n4_seid, Some(smf_ip), None);

    // APN/DNN
    builder.add_apn_dnn(dnn);

    // S-NSSAI
    builder.add_s_nssai(sst, None);

    // Create PDR 1 (Uplink): UE -> UPF -> DN
    let ul_pdr = PdrParams {
        pdr_id: 1,
        precedence: 100,
        source_interface: 0, // Access
        f_teid: Some((0, None, None)), // teid=0: UPF allocates
        ue_ip_address: Some((Some(ue_ip), None, true)), // source
        outer_header_removal: Some(0), // GTP-U/UDP/IPv4
        far_id: Some(1),
        qfi: Some(9),
        ..Default::default()
    };
    let ul_pdr_bytes = n4_build::build_create_pdr(&ul_pdr);
    builder.add_tlv(pfcp_ie::CREATE_PDR, &ul_pdr_bytes);

    // Create FAR 1 (Uplink): Forward to DN
    let ul_far = FarParams {
        far_id: 1,
        apply_action: 0x02, // FORW (forward)
        destination_interface: Some(6), // Core/SGi-LAN
        ..Default::default()
    };
    let ul_far_bytes = n4_build::build_create_far(&ul_far);
    builder.add_tlv(pfcp_ie::CREATE_FAR, &ul_far_bytes);

    // Create PDR 2 (Downlink): DN -> UPF -> UE (initially buffered, FAR updated after gNB responds)
    let dl_pdr = PdrParams {
        pdr_id: 2,
        precedence: 100,
        source_interface: 6, // Core
        ue_ip_address: Some((Some(ue_ip), None, false)), // destination
        far_id: Some(2),
        qfi: Some(9),
        ..Default::default()
    };
    let dl_pdr_bytes = n4_build::build_create_pdr(&dl_pdr);
    builder.add_tlv(pfcp_ie::CREATE_PDR, &dl_pdr_bytes);

    // Create FAR 2 (Downlink): Buffer initially (will be updated with gNB TEID)
    let dl_far = FarParams {
        far_id: 2,
        apply_action: 0x04, // BUFF (buffer)
        destination_interface: Some(0), // Access
        ..Default::default()
    };
    let dl_far_bytes = n4_build::build_create_far(&dl_far);
    builder.add_tlv(pfcp_ie::CREATE_FAR, &dl_far_bytes);

    let payload = builder.build();

    // Build PFCP header
    // Flags: version=1 (0x20) + SEID present (0x01) = 0x21
    let mut packet = Vec::with_capacity(16 + payload.len());
    packet.push(0x21); // flags
    packet.push(50); // Session Establishment Request
    let total_len = (12 + payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&0u64.to_be_bytes()); // SEID=0 for new session
    let seq: u32 = 1;
    packet.extend_from_slice(&seq.to_be_bytes()[1..4]); // 3 bytes
    packet.push(0); // spare
    packet.extend_from_slice(&payload);

    // Send via UDP
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to bind PFCP client socket")?;
    let upf_endpoint: SocketAddr = format!("{}:{}", upf_addr, upf_port).parse()
        .context("Invalid UPF address")?;

    socket.send_to(&packet, upf_endpoint).await
        .context("Failed to send PFCP to UPF")?;
    log::info!("PFCP Session Establishment Request sent ({} bytes)", packet.len());

    // Receive response with timeout
    let mut resp_buf = vec![0u8; 4096];
    let (resp_len, _) = tokio::time::timeout(
        Duration::from_secs(5),
        socket.recv_from(&mut resp_buf),
    ).await
        .context("PFCP response timeout")?
        .context("PFCP recv error")?;

    log::info!("PFCP response received ({} bytes)", resp_len);

    // Parse response header (16 bytes for SEID-present header)
    if resp_len < 16 {
        anyhow::bail!("PFCP response too short");
    }

    let resp_seid = u64::from_be_bytes(resp_buf[4..12].try_into().unwrap());
    let resp_payload = &resp_buf[16..resp_len];

    // Parse response IEs to find UP F-SEID and Created PDR with F-TEID
    let mut upf_seid: u64 = 0;
    let mut upf_teid: u32 = 0;
    let mut upf_ip: [u8; 4] = [127, 0, 0, 1];

    let mut offset = 0;
    while offset + 4 <= resp_payload.len() {
        let ie_type = u16::from_be_bytes([resp_payload[offset], resp_payload[offset + 1]]);
        let ie_len = u16::from_be_bytes([resp_payload[offset + 2], resp_payload[offset + 3]]) as usize;
        let ie_start = offset + 4;
        let ie_end = ie_start + ie_len;
        if ie_end > resp_payload.len() { break; }

        let ie_value = &resp_payload[ie_start..ie_end];

        match ie_type {
            57 => { // F-SEID (0x0039)
                if ie_value.len() >= 9 {
                    let flags = ie_value[0];
                    upf_seid = u64::from_be_bytes(ie_value[1..9].try_into().unwrap());
                    if flags & 0x02 != 0 && ie_value.len() >= 13 {
                        upf_ip = [ie_value[9], ie_value[10], ie_value[11], ie_value[12]];
                    }
                    log::info!("UPF F-SEID: seid=0x{:016x}, ip={}.{}.{}.{}",
                        upf_seid, upf_ip[0], upf_ip[1], upf_ip[2], upf_ip[3]);
                }
            }
            8 => { // Created PDR (0x0008)
                // Parse inner IEs of Created PDR group
                let mut inner_off = 0;
                while inner_off + 4 <= ie_value.len() {
                    let inner_type = u16::from_be_bytes([ie_value[inner_off], ie_value[inner_off + 1]]);
                    let inner_len = u16::from_be_bytes([ie_value[inner_off + 2], ie_value[inner_off + 3]]) as usize;
                    let inner_start = inner_off + 4;
                    let inner_end = inner_start + inner_len;
                    if inner_end > ie_value.len() { break; }

                    if inner_type == 21 { // F-TEID (0x0015)
                        let fteid_val = &ie_value[inner_start..inner_end];
                        if fteid_val.len() >= 5 {
                            let fteid_flags = fteid_val[0];
                            let teid = u32::from_be_bytes(fteid_val[1..5].try_into().unwrap());
                            if fteid_flags & 0x02 != 0 && fteid_val.len() >= 9 {
                                upf_ip = [fteid_val[5], fteid_val[6], fteid_val[7], fteid_val[8]];
                            }
                            if teid != 0 {
                                upf_teid = teid;
                                log::info!("UPF F-TEID: teid=0x{:08x}", upf_teid);
                            }
                        }
                    }
                    inner_off = inner_end;
                }
            }
            _ => {}
        }
        offset = ie_end;
    }

    if upf_teid == 0 {
        log::warn!("No UPF F-TEID in response, using SEID-based TEID");
        upf_teid = (upf_seid & 0xFFFFFFFF) as u32;
    }

    log::info!("PFCP Session Established: UPF SEID=0x{:016x}, UPF TEID=0x{:08x}", upf_seid, upf_teid);

    Ok(PfcpSessionResult {
        upf_seid,
        upf_teid,
        upf_addr: upf_ip,
    })
}

/// Send PFCP Session Modification Request to UPF to activate DL FAR with gNB TEID
async fn pfcp_session_modify(
    upf_seid: u64,
    gnb_teid: u32,
    gnb_addr: [u8; 4],
    upf_addr: &str,
    upf_port: u16,
) -> Result<()> {
    use n4_build::{SessionModificationParams, build_session_modification_request};
    use tokio::net::UdpSocket;
    use std::time::Duration;

    log::info!(
        "PFCP Session Modification: UPF SEID=0x{:016x}, gNB TEID=0x{:08x}, gNB addr={}.{}.{}.{}",
        upf_seid, gnb_teid, gnb_addr[0], gnb_addr[1], gnb_addr[2], gnb_addr[3]
    );

    // Build modification: update FAR 2 (downlink) from BUFF to FORW with outer header creation (GTP-U to gNB)
    // outer_header_creation: (description, teid, ipv4, ipv6)
    // description 0x0100 = GTP-U/UDP/IPv4
    let params = SessionModificationParams {
        update_fars_activate: vec![(
            2,                              // FAR ID 2 (downlink)
            0,                              // destination_interface: Access
            Some((0x0100, gnb_teid, Some(gnb_addr), None)), // outer header creation: GTP-U to gNB
            true,                           // send end marker
        )],
        ..Default::default()
    };

    let payload = build_session_modification_request(&params);

    // Build PFCP header with UPF SEID
    let mut packet = Vec::with_capacity(16 + payload.len());
    packet.push(0x21); // flags: version=1 + SEID present
    packet.push(52);   // Session Modification Request
    let total_len = (12 + payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&upf_seid.to_be_bytes());
    let seq: u32 = 2;
    packet.extend_from_slice(&seq.to_be_bytes()[1..4]);
    packet.push(0); // spare
    packet.extend_from_slice(&payload);

    // Send via UDP
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to bind PFCP client socket")?;
    let upf_endpoint: SocketAddr = format!("{}:{}", upf_addr, upf_port).parse()
        .context("Invalid UPF address")?;

    socket.send_to(&packet, upf_endpoint).await
        .context("Failed to send PFCP modification to UPF")?;
    log::info!("PFCP Session Modification Request sent ({} bytes)", packet.len());

    // Receive response with timeout
    let mut resp_buf = vec![0u8; 4096];
    let (resp_len, _) = tokio::time::timeout(
        Duration::from_secs(5),
        socket.recv_from(&mut resp_buf),
    ).await
        .context("PFCP modification response timeout")?
        .context("PFCP modification recv error")?;

    log::info!("PFCP Session Modification Response received ({} bytes)", resp_len);

    // Check response header: verify it's a Session Modification Response (53)
    if resp_len >= 16 {
        let msg_type = resp_buf[1];
        if msg_type == 53 {
            log::info!("PFCP Session Modification successful");
        } else {
            log::warn!("Unexpected PFCP response type: {}", msg_type);
        }
    }

    Ok(())
}

/// Send PFCP Session Deletion Request to UPF
async fn pfcp_session_delete(
    upf_seid: u64,
    upf_addr: &str,
    upf_port: u16,
) -> Result<()> {
    use tokio::net::UdpSocket;
    use std::time::Duration;

    log::info!("PFCP Session Deletion: UPF SEID=0x{:016x}", upf_seid);

    // PFCP Session Deletion Request has no IEs beyond the header
    let payload: Vec<u8> = Vec::new();

    // Build PFCP header with UPF SEID
    let mut packet = Vec::with_capacity(16 + payload.len());
    packet.push(0x21); // flags: version=1 + SEID present
    packet.push(54);   // Session Deletion Request (message type 54)
    let total_len = (12 + payload.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&upf_seid.to_be_bytes());
    let seq: u32 = 3;
    packet.extend_from_slice(&seq.to_be_bytes()[1..4]);
    packet.push(0); // spare
    packet.extend_from_slice(&payload);

    // Send via UDP
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .context("Failed to bind PFCP client socket")?;
    let upf_endpoint: SocketAddr = format!("{}:{}", upf_addr, upf_port).parse()
        .context("Invalid UPF address")?;

    socket.send_to(&packet, upf_endpoint).await
        .context("Failed to send PFCP deletion to UPF")?;
    log::info!("PFCP Session Deletion Request sent ({} bytes)", packet.len());

    // Receive response with timeout
    let mut resp_buf = vec![0u8; 4096];
    let (resp_len, _) = tokio::time::timeout(
        Duration::from_secs(5),
        socket.recv_from(&mut resp_buf),
    ).await
        .context("PFCP deletion response timeout")?
        .context("PFCP deletion recv error")?;

    log::info!("PFCP Session Deletion Response received ({} bytes)", resp_len);

    // Check response header: verify it's a Session Deletion Response (55)
    if resp_len >= 16 {
        let msg_type = resp_buf[1];
        if msg_type == 55 {
            log::info!("PFCP Session Deletion successful");
        } else {
            log::warn!("Unexpected PFCP deletion response type: {}", msg_type);
        }
    }

    Ok(())
}

// =============================================================================
// SM Context Handlers
// =============================================================================

/// Handle SM Context Create (from AMF via N11)
async fn handle_sm_context_create(request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Create request received");

    // Parse request body
    let req_body: serde_json::Value = match &request.http.content {
        Some(content) => match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to parse SM Context Create request: {}", e);
                return send_bad_request("Invalid JSON", None);
            }
        },
        None => serde_json::json!({}),
    };

    let pdu_session_id = req_body["pduSessionId"].as_u64().unwrap_or(1) as u8;
    let sst = req_body["sNssai"]["sst"].as_u64().unwrap_or(1) as u8;
    let dnn = req_body["dnn"].as_str().unwrap_or("internet");

    log::info!("SM Context Create: PSI={}, SST={}, DNN={}", pdu_session_id, sst, dnn);

    let ctx = smf_self();
    let sm_context_ref;
    let ue_ip_octets: [u8; 4];

    if let Ok(context) = ctx.read() {
        let sess_idx = context.sess_count() + 1;
        sm_context_ref = format!("{}", sess_idx);
        // Allocate UE IP: 10.45.0.{1+idx}
        let ip_suffix = (sess_idx as u8).wrapping_add(1);
        ue_ip_octets = [10, 45, 0, ip_suffix];
    } else {
        return SbiResponse::with_status(500);
    }

    log::info!(
        "SMF allocated: ref={}, UE IP={}.{}.{}.{}",
        sm_context_ref, ue_ip_octets[0], ue_ip_octets[1], ue_ip_octets[2], ue_ip_octets[3]
    );

    // Build N1 SM message: NAS PDU Session Establishment Accept
    let mut n1_sm_msg = Vec::new();
    n1_sm_msg.push(0x2E); // EPD: 5GSM
    n1_sm_msg.push(pdu_session_id);
    n1_sm_msg.push(0x00); // PTI
    n1_sm_msg.push(0xC2); // Message Type: PDU Session Establishment Accept
    n1_sm_msg.push(0x01); // PDU session type: IPv4
    n1_sm_msg.push(0x01); // SSC mode 1
    n1_sm_msg.extend_from_slice(&[0x06, 0x01, 0x03, 0x01, 0x01, 0x09]); // QoS rules (QFI=9)
    n1_sm_msg.extend_from_slice(&[0x06, 0x06, 0x00, 0x64, 0x06, 0x00, 0x64]); // Session AMBR 100Mbps
    // PDU address (IEI 0x29)
    n1_sm_msg.push(0x29); n1_sm_msg.push(0x05); n1_sm_msg.push(0x01);
    n1_sm_msg.extend_from_slice(&ue_ip_octets);
    // DNN (IEI 0x25)
    let dnn_bytes = dnn.as_bytes();
    n1_sm_msg.push(0x25);
    n1_sm_msg.push((dnn_bytes.len() + 1) as u8);
    n1_sm_msg.push(dnn_bytes.len() as u8);
    n1_sm_msg.extend_from_slice(dnn_bytes);

    // Establish PFCP session with UPF to get real UPF TEID
    let smf_n4_seid = (sm_context_ref.parse::<u64>().unwrap_or(1)) | 0x1000;
    let upf_addr_str = std::env::var("UPF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let upf_n4_port: u16 = std::env::var("UPF_PFCP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8805);

    let (upf_teid, upf_addr) = match pfcp_session_establish(
        smf_n4_seid, ue_ip_octets, dnn, sst, &upf_addr_str, upf_n4_port,
    ).await {
        Ok(result) => {
            log::info!(
                "PFCP session established: UPF SEID=0x{:016x}, TEID=0x{:08x}, addr={}.{}.{}.{}",
                result.upf_seid, result.upf_teid,
                result.upf_addr[0], result.upf_addr[1], result.upf_addr[2], result.upf_addr[3]
            );
            // Store UPF SEID for later PFCP modifications
            if let Ok(mut sessions) = PFCP_SESSIONS.lock() {
                sessions.insert(sm_context_ref.to_string(), result.upf_seid);
                log::debug!("Stored UPF SEID=0x{:016x} for sm_context_ref={}", result.upf_seid, sm_context_ref);
            }
            (result.upf_teid, result.upf_addr)
        }
        Err(e) => {
            log::warn!("PFCP session establishment failed ({}), using fallback TEID", e);
            let fallback_teid = sm_context_ref.parse::<u32>().unwrap_or(1);
            (fallback_teid, [127u8, 0, 0, 1])
        }
    };

    // Build N2 SM Information: UPF tunnel endpoint
    // Format: QFI(1) + UPF TEID(4,BE) + addr_type(1) + IPv4(4) + 5QI(1) + priority(1)
    let mut n2_sm_info = Vec::with_capacity(12);
    n2_sm_info.push(9u8); // QFI
    n2_sm_info.extend_from_slice(&upf_teid.to_be_bytes());
    n2_sm_info.push(1); // IPv4
    n2_sm_info.extend_from_slice(&upf_addr);
    n2_sm_info.push(9); // 5QI
    n2_sm_info.push(1); // Priority

    use base64::Engine;
    let n1_b64 = base64::engine::general_purpose::STANDARD.encode(&n1_sm_msg);
    let n2_b64 = base64::engine::general_purpose::STANDARD.encode(&n2_sm_info);

    let response_body = serde_json::json!({
        "smContextRef": sm_context_ref,
        "pduSessionId": pdu_session_id,
        "upCnxState": "ACTIVATING",
        "n1SmMsg": n1_b64,
        "n2SmInfo": n2_b64
    });

    let location = format!("/nsmf-pdusession/v1/sm-contexts/{}", sm_context_ref);

    log::info!(
        "SM Context Created: ref={}, n1_len={}, n2_len={}, UPF TEID=0x{:08x}",
        sm_context_ref, n1_sm_msg.len(), n2_sm_info.len(), upf_teid
    );

    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_body(response_body.to_string(), "application/json")
}

/// Handle SM Context Update (gNB TEID from AMF after PDU Session Resource Setup Response)
async fn handle_sm_context_update(sm_context_ref: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Update request for ref={}", sm_context_ref);

    // Parse request body for N2 SM Info (gNB TEID)
    let req_body: serde_json::Value = match &request.http.content {
        Some(content) => serde_json::from_str(content).unwrap_or(serde_json::json!({})),
        None => serde_json::json!({}),
    };

    let n2_sm_info_type = req_body["n2SmInfoType"].as_str().unwrap_or("");

    if n2_sm_info_type == "PDU_RES_SETUP_RSP" {
        // Decode N2 SM Info to extract gNB TEID and address
        use base64::Engine;
        if let Some(n2_b64) = req_body["n2SmInfo"].as_str() {
            if let Ok(n2_bytes) = base64::engine::general_purpose::STANDARD.decode(n2_b64) {
                if n2_bytes.len() >= 6 {
                    let qfi = n2_bytes[0];
                    let gnb_teid = u32::from_be_bytes([n2_bytes[1], n2_bytes[2], n2_bytes[3], n2_bytes[4]]);
                    let addr_type = n2_bytes[5];

                    let gnb_addr = if addr_type == 1 && n2_bytes.len() >= 10 {
                        [n2_bytes[6], n2_bytes[7], n2_bytes[8], n2_bytes[9]]
                    } else {
                        [127, 0, 0, 1]
                    };

                    log::info!(
                        "SM Context Update: gNB TEID=0x{:08x}, addr={}.{}.{}.{}, QFI={}",
                        gnb_teid, gnb_addr[0], gnb_addr[1], gnb_addr[2], gnb_addr[3], qfi
                    );

                    // Send PFCP Session Modification to UPF: activate DL FAR with gNB TEID
                    // Retrieve the real UPF SEID stored during establishment
                    let upf_seid = PFCP_SESSIONS.lock().ok()
                        .and_then(|sessions| sessions.get(sm_context_ref).copied())
                        .unwrap_or_else(|| {
                            log::warn!("No stored UPF SEID for ref={}, using fallback", sm_context_ref);
                            sm_context_ref.parse::<u64>().unwrap_or(1)
                        });
                    log::info!("PFCP Session Modification: UPF SEID=0x{:016x} for ref={}", upf_seid, sm_context_ref);
                    let upf_mod_addr = std::env::var("UPF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
                    let upf_mod_port: u16 = std::env::var("UPF_PFCP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8805);
                    match pfcp_session_modify(
                        upf_seid, gnb_teid, gnb_addr, &upf_mod_addr, upf_mod_port,
                    ).await {
                        Ok(()) => {
                            log::info!("PFCP Session Modified: DL FAR activated with gNB TEID=0x{:08x}", gnb_teid);
                        }
                        Err(e) => {
                            log::warn!("PFCP Session Modification failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    let response_body = serde_json::json!({
        "upCnxState": "ACTIVATED"
    });

    SbiResponse::with_status(200)
        .with_body(response_body.to_string(), "application/json")
}

/// Handle SM Context Release
///
/// Sends PFCP Session Deletion Request to UPF to release the N4 session,
/// then removes session state.
async fn handle_sm_context_release(sm_context_ref: &str) -> SbiResponse {
    log::info!("SM Context Release request for ref={}", sm_context_ref);

    // Look up UPF SEID for this session
    let upf_seid = PFCP_SESSIONS.lock().ok()
        .and_then(|sessions| sessions.get(sm_context_ref).copied());

    if let Some(seid) = upf_seid {
        // Send PFCP Session Deletion Request to UPF
        let upf_addr = std::env::var("UPF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let upf_port: u16 = std::env::var("UPF_PFCP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8805);

        match pfcp_session_delete(seid, &upf_addr, upf_port).await {
            Ok(()) => {
                log::info!("PFCP Session Deleted: UPF SEID=0x{:016x} for ref={}", seid, sm_context_ref);
            }
            Err(e) => {
                log::warn!("PFCP Session Deletion failed: {} (continuing with release)", e);
            }
        }

        // Remove from PFCP sessions map
        if let Ok(mut sessions) = PFCP_SESSIONS.lock() {
            sessions.remove(sm_context_ref);
        }
    } else {
        log::warn!("No PFCP session found for sm_context_ref={}", sm_context_ref);
    }

    // Remove from SMF context
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
