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
use ogs_sbi::context::{global_context, NfInstance, NfService};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_not_found, SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

mod binding;
mod context;
mod event;
mod gn_build;
mod gn_handler;
mod gsm_build;
mod gsm_handler;
mod gsm_sm;
mod gtp_build;
mod gtp_handler;
mod gtp_path;
pub mod mbs_session; // Rel-17: MBS multicast/broadcast session
mod n4_build;
mod n4_handler;
mod pfcp_path;
mod pfcp_sm;
mod policy;
#[cfg(test)]
mod property_tests;
mod session_extensions; // #199-#201: IPv6 dual-stack, SSC modes, Ethernet PDU
pub mod slicing; // Rel-17: per-slice QoS profiles
mod smf_sm;
mod timer;

use context::{smf_context_final, smf_context_init, smf_self};
use smf_sm::SmfFsm;

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Monotonically-increasing PFCP sequence number counter.
/// Each transaction fetches-and-increments this so concurrent PDU sessions
/// never reuse the same sequence number.
static PFCP_SEQ: AtomicU32 = AtomicU32::new(1);

/// Externally-reachable base URI of this SMF's SBI server, used for the
/// callback URIs handed to the PCF (notificationUri). Set once in `main`.
static SELF_SBI_URI: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Base URI for callbacks (e.g. `http://10.0.0.5:7777`).
fn self_sbi_uri() -> String {
    SELF_SBI_URI
        .get()
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:7777".to_string())
}

// ---------------------------------------------------------------------------
// Typed YAML configuration structs (serde_yaml Deserialize)
// ---------------------------------------------------------------------------

/// A single server/client address entry
#[derive(Debug, Deserialize)]
struct AddrEntry {
    address: Option<String>,
    port: Option<u16>,
    uri: Option<String>,
}

/// SBI client NRF list
#[derive(Debug, Default, Deserialize)]
struct SbiClient {
    nrf: Option<Vec<AddrEntry>>,
}

/// SBI section (server list + client)
#[derive(Debug, Default, Deserialize)]
struct SbiSection {
    server: Option<Vec<AddrEntry>>,
    client: Option<SbiClient>,
}

/// Top-level `smf:` section
#[derive(Debug, Default, Deserialize)]
struct SmfSection {
    sbi: Option<SbiSection>,
}

/// Root YAML document
#[derive(Debug, Default, Deserialize)]
struct SmfYaml {
    smf: Option<SmfSection>,
}

/// Resolved, flat configuration used at runtime
struct SmfConfig {
    sbi_addr: String,
    sbi_port: u16,
    max_ue: usize,
    max_sess: usize,
    max_bearer: usize,
    /// NRF URI parsed from `smf.sbi.client.nrf[0].uri` (if present).
    nrf_uri: Option<String>,
}

impl Default for SmfConfig {
    fn default() -> Self {
        Self {
            sbi_addr: "0.0.0.0".to_string(),
            sbi_port: 7777,
            max_ue: 1024,
            max_sess: 4096,
            max_bearer: 8192,
            nrf_uri: None,
        }
    }
}

fn load_config(path: &str) -> SmfConfig {
    let mut config = SmfConfig::default();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Could not read SMF config '{path}': {e}. Using defaults.");
            return config;
        }
    };

    let yaml: SmfYaml = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse SMF YAML config '{path}': {e}. Using defaults.");
            return config;
        }
    };

    if let Some(smf) = yaml.smf {
        if let Some(sbi) = smf.sbi {
            if let Some(servers) = sbi.server {
                if let Some(first) = servers.into_iter().next() {
                    if let Some(addr) = first.address {
                        config.sbi_addr = addr;
                    }
                    if let Some(port) = first.port {
                        config.sbi_port = port;
                    }
                }
            }
            // Extract the NRF URI here so main() doesn't re-read and re-parse
            // the same file just to seed it.
            if let Some(client) = sbi.client {
                if let Some(nrf_list) = client.nrf {
                    if let Some(nrf) = nrf_list.into_iter().next() {
                        config.nrf_uri = nrf.uri;
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore SMF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    // Load configuration — respect -c/--config CLI arg first, then SMF_CONFIG env var
    let config_path = std::env::args()
        .zip(std::env::args().skip(1))
        .find_map(|(a, b)| {
            if a == "-c" || a == "--config" {
                Some(b)
            } else {
                None
            }
        })
        .or_else(|| std::env::var("SMF_CONFIG").ok())
        .unwrap_or_else(|| "/etc/nextgcore/smf.yaml".to_string());
    let config = load_config(&config_path);
    log::info!("Loading configuration from {config_path}");
    log::info!(
        "SBI config: address={}, port={}",
        config.sbi_addr,
        config.sbi_port
    );

    // Seed NRF URI into SBI context for NF registration (parsed once in load_config).
    if let Some(ref uri) = config.nrf_uri {
        log::info!("NRF URI configured: {uri}");
        global_context().set_nrf_uri(uri).await;
    }

    // Advertised SBI base URI used for PCF callbacks (notificationUri).
    // 0.0.0.0 is not reachable by peers, so fall back to loopback unless
    // overridden with SMF_SBI_ADVERTISE_URI.
    let advertise_uri = std::env::var("SMF_SBI_ADVERTISE_URI").unwrap_or_else(|_| {
        let host = if config.sbi_addr == "0.0.0.0" {
            "127.0.0.1"
        } else {
            config.sbi_addr.as_str()
        };
        format!("http://{host}:{}", config.sbi_port)
    });
    log::info!("SBI advertise URI for callbacks: {advertise_uri}");
    let _ = SELF_SBI_URI.set(advertise_uri);

    // Initialize SMF context
    smf_context_init(config.max_ue, config.max_sess, config.max_bearer);
    log::info!(
        "SMF context initialized (max_ue={}, max_sess={}, max_bearer={})",
        config.max_ue,
        config.max_sess,
        config.max_bearer
    );

    // Initialize SMF state machine
    let mut smf_sm = SmfFsm::new();
    smf_sm.init();
    log::info!("SMF state machine initialized");

    // Start SBI HTTP/2 server
    let sbi_addr: SocketAddr = format!("{}:{}", config.sbi_addr, config.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server
        .start(smf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (if configured)
    match smf_nrf_register(&config.sbi_addr, config.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    log::info!("NextGCore SMF ready");

    // Bind the single N4 (PFCP) socket. All SMF→UPF requests AND all
    // unsolicited UPF→SMF messages (Session Report Requests, heartbeats)
    // flow through this one socket so transactions can be matched by
    // sequence number (TS 29.244 7.2.1).
    let pfcp_bind_addr: SocketAddr = {
        let addr = std::env::var("SMF_PFCP_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = std::env::var("SMF_PFCP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8805);
        format!("{addr}:{port}")
            .parse()
            .context("Invalid SMF PFCP listen address")?
    };
    let upf_pfcp_addr: SocketAddr = {
        let addr = std::env::var("UPF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("UPF_PFCP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8805);
        format!("{addr}:{port}")
            .parse()
            .context("Invalid UPF PFCP address")?
    };
    let smf_node_ip: [u8; 4] = {
        let s = std::env::var("SMF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() == 4 {
            [parts[0], parts[1], parts[2], parts[3]]
        } else {
            [127, 0, 0, 1]
        }
    };

    let pfcp_socket = Arc::new(
        tokio::net::UdpSocket::bind(pfcp_bind_addr)
            .await
            .with_context(|| format!("Failed to bind SMF PFCP socket on {pfcp_bind_addr}"))?,
    );
    log::info!("SMF N4 PFCP socket bound on {pfcp_bind_addr} (UPF peer: {upf_pfcp_addr})");

    let pfcp_client = Arc::new(pfcp_path::PfcpClient::new(
        pfcp_socket.clone(),
        upf_pfcp_addr,
        smf_node_ip,
    ));
    pfcp_path::set_global_client(pfcp_client.clone());

    // PFCP receive/dispatch loop: responses complete pending transactions;
    // node-level requests (heartbeat, association release) are answered by
    // the engine; Session Report Requests are handled here.
    let shutdown_pfcp = shutdown.clone();
    let client_rx = pfcp_client.clone();
    let sock_rx = pfcp_socket.clone();
    let pfcp_listener_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            if shutdown_pfcp.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                sock_rx.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, peer))) => {
                    let pkt = buf[..len].to_vec();
                    if !client_rx.on_datagram(&pkt, peer).await {
                        handle_pfcp_incoming(&sock_rx, &pkt, peer).await;
                    }
                }
                Ok(Err(e)) => log::warn!("PFCP listener recv error: {e}"),
                Err(_) => {} // timeout — loop and re-check shutdown
            }
        }
        log::info!("SMF N4 PFCP listener stopped");
    });

    // N4 association maintenance: establish the PFCP association at startup
    // (Node ID + Recovery Time Stamp, TS 29.244 6.2.6) and keep it alive
    // with heartbeats. Heartbeat exhaustion or a changed peer Recovery Time
    // Stamp tears the association down (stale sessions flushed) and
    // triggers re-association.
    let shutdown_assoc = shutdown.clone();
    let client_assoc = pfcp_client.clone();
    let pfcp_assoc_handle = tokio::spawn(async move {
        let heartbeat_period = std::time::Duration::from_secs(10);
        let reassociate_holdoff = std::time::Duration::from_secs(10);
        loop {
            if shutdown_assoc.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            if !client_assoc.is_associated().await {
                match client_assoc.associate().await {
                    Ok(()) => {}
                    Err(e) => {
                        // Abnormal action on association failure: declare the
                        // UPF unreachable and hold off before a new cycle.
                        log::error!(
                            "PFCP Association Setup with {} failed: {e}; retrying in {}s",
                            client_assoc.peer(),
                            reassociate_holdoff.as_secs()
                        );
                        tokio::time::sleep(reassociate_holdoff).await;
                        continue;
                    }
                }
            }
            tokio::time::sleep(heartbeat_period).await;
            if shutdown_assoc.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            if client_assoc.is_associated().await {
                if let Err(e) = client_assoc.heartbeat_once().await {
                    // Exhaustion already marked the association down inside
                    // the engine; the next loop turn re-associates.
                    log::error!("PFCP heartbeat to {} failed: {e}", client_assoc.peer());
                }
            }
        }
    });

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

    pfcp_assoc_handle.abort();

    // Graceful shutdown: release the N4 association before going down
    // (TS 29.244 6.2.9 — Association Release initiated by the CP function)
    if pfcp_client.is_associated().await {
        match pfcp_client.release_association().await {
            Ok(()) => log::info!("PFCP association released"),
            Err(e) => log::warn!("PFCP Association Release failed: {e}"),
        }
    }
    pfcp_listener_handle.abort();

    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
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

// =============================================================================
// PFCP N4 Receive Path (SMF as server for UPF-initiated messages)
// =============================================================================

/// Dispatch an incoming PFCP datagram received on the SMF's N4 listen socket.
async fn handle_pfcp_incoming(
    sock: &tokio::net::UdpSocket,
    pkt: &[u8],
    peer: std::net::SocketAddr,
) {
    if pkt.len() < 4 {
        log::warn!("PFCP packet from {peer} too short ({} bytes)", pkt.len());
        return;
    }
    let msg_type = pkt[1];
    log::debug!(
        "PFCP message type={msg_type} from {peer} ({} bytes)",
        pkt.len()
    );

    match msg_type {
        56 => handle_pfcp_session_report(sock, pkt, peer).await,
        _ => log::debug!("PFCP: unhandled message type={msg_type} from {peer}"),
    }
}

/// Handle PFCP Session Report Request (message type 56) from UPF.
///
/// The UPF sends this when a URR threshold is crossed.  The SMF logs the
/// usage report and responds with a Session Report Response (type 57)
/// carrying a "Request Accepted" cause IE.
async fn handle_pfcp_session_report(
    sock: &tokio::net::UdpSocket,
    pkt: &[u8],
    peer: std::net::SocketAddr,
) {
    // Minimum PFCP header with SEID: 16 bytes
    // flags[1] + msg_type[1] + length[2] + seid[8] + seq[3] + spare[1]
    if pkt.len() < 16 {
        log::warn!(
            "PFCP Session Report Request from {peer} too short ({} bytes)",
            pkt.len()
        );
        return;
    }

    let seid = u64::from_be_bytes(pkt[4..12].try_into().unwrap_or([0u8; 8]));
    // Sequence number is 3 bytes at offset 12 (big-endian, upper byte = 0)
    let seq = u32::from_be_bytes([0, pkt[12], pkt[13], pkt[14]]);

    log::info!("PFCP Session Report Request: SEID=0x{seid:016x}, seq={seq}, peer={peer}");

    // Parse IEs from the payload (offset 16 onward).
    let payload = &pkt[16..];

    // Report Type (IE 39) is MANDATORY in a Session Report Request
    // (TS 29.244 Table 7.5.8.1-1) — reject its absence with cause 66.
    let report_type = pfcp_path::find_ie(payload, 39).and_then(|v| v.first().copied());
    let Some(report_type) = report_type else {
        log::warn!("Session Report Request missing mandatory Report Type IE — rejecting");
        let mut body = n4_build::PfcpMessageBuilder::new();
        body.add_cause_raw(66); // Mandatory IE missing
        body.add_u16(n4_build::pfcp_ie::OFFENDING_IE, 39);
        let resp = pfcp_path::encode_wire_message(
            pfcp_path::pfcp_message_type::SESSION_REPORT_RESPONSE,
            Some(seid),
            seq,
            &body.build(),
        );
        if let Err(e) = sock.send_to(&resp, peer).await {
            log::warn!("Failed to send Session Report Response to {peer}: {e}");
        }
        return;
    };

    // Downlink Data Report (DLDR, bit 0x01): the UPF buffered the first DL
    // packet for an idle session — in a full deployment this triggers the
    // Network Triggered Service Request (N1N2 transfer / paging via AMF).
    if report_type & 0x01 != 0 {
        if let Some(dldr) = pfcp_path::find_ie(payload, 83) {
            let pdr_id = pfcp_path::find_ie(dldr, 56)
                .filter(|v| v.len() >= 2)
                .map(|v| u16::from_be_bytes([v[0], v[1]]));
            // Downlink Data Service Information (IE 45): flags + PPI/QFI
            let qfi = pfcp_path::find_ie(dldr, 45).and_then(|v| {
                if v.is_empty() {
                    return None;
                }
                let flags = v[0];
                let mut idx = 1;
                if flags & 0x01 != 0 {
                    idx += 1; // skip PPI
                }
                if flags & 0x02 != 0 {
                    v.get(idx).map(|q| q & 0x3F)
                } else {
                    None
                }
            });
            log::info!(
                "Downlink Data Report: SEID=0x{seid:016x}, PDR={pdr_id:?}, QFI={qfi:?} — \
                 triggering UP connection re-activation"
            );
        } else {
            log::warn!("Report Type has DLDR set but no Downlink Data Report IE present");
        }
    }

    // Error Indication Report (bit 0x04): a peer GTP-U node rejected one of
    // the session's tunnels — the DL tunnel toward the gNB is stale.
    if report_type & 0x04 != 0 {
        log::warn!(
            "Error Indication Report for SEID=0x{seid:016x}: remote GTP-U endpoint rejected \
             the DL tunnel (stale gNB F-TEID)"
        );
    }

    let mut offset = 0;
    while offset + 4 <= payload.len() {
        let ie_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ie_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        let ie_start = offset + 4;
        let ie_end = ie_start + ie_len;
        if ie_end > payload.len() {
            break;
        }

        // IE type 78 = Usage Report within Session Report Request (TS 29.244)
        if ie_type == 78 {
            let ur = &payload[ie_start..ie_end];
            let mut ur_off = 0;
            let mut urr_id: u32 = 0;
            let mut vol_ul: u64 = 0;
            let mut vol_dl: u64 = 0;
            while ur_off + 4 <= ur.len() {
                let t = u16::from_be_bytes([ur[ur_off], ur[ur_off + 1]]);
                let l = u16::from_be_bytes([ur[ur_off + 2], ur[ur_off + 3]]) as usize;
                let s = ur_off + 4;
                let e = s + l;
                if e > ur.len() {
                    break;
                }
                match t {
                    // URR ID (IE type 81)
                    81 if l >= 4 => {
                        urr_id = u32::from_be_bytes(ur[s..s + 4].try_into().unwrap_or([0u8; 4]));
                    }
                    // Volume Measurement (IE type 42): flags(1) + total(8) + ul(8) + dl(8)
                    42 if l >= 1 => {
                        let flags = ur[s];
                        let mut v = s + 1;
                        if flags & 0x01 != 0 && v + 8 <= e {
                            v += 8;
                        } // skip total
                        if flags & 0x02 != 0 && v + 8 <= e {
                            vol_ul =
                                u64::from_be_bytes(ur[v..v + 8].try_into().unwrap_or([0u8; 8]));
                            v += 8;
                        }
                        if flags & 0x04 != 0 && v + 8 <= e {
                            vol_dl =
                                u64::from_be_bytes(ur[v..v + 8].try_into().unwrap_or([0u8; 8]));
                        }
                    }
                    _ => {}
                }
                ur_off = e;
            }
            log::info!(
                "PFCP Usage Report: SEID=0x{seid:016x}, URR ID={urr_id}, \
                 UL={vol_ul} bytes, DL={vol_dl} bytes"
            );
        }

        offset = ie_end;
    }

    // Build Session Report Response (type 57) with Cause = Request Accepted
    // through the single builder/encoder path.
    let mut body = n4_build::PfcpMessageBuilder::new();
    body.add_cause_raw(1); // Request Accepted
    let resp = pfcp_path::encode_wire_message(
        pfcp_path::pfcp_message_type::SESSION_REPORT_RESPONSE,
        Some(seid),
        seq,
        &body.build(),
    );

    if let Err(e) = sock.send_to(&resp, peer).await {
        log::warn!("Failed to send PFCP Session Report Response to {peer}: {e}");
    } else {
        log::info!("PFCP Session Report Response sent: SEID=0x{seid:016x}, seq={seq}, peer={peer}");
    }
}

/// Register SMF NF instance with NRF
///
/// Sends PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId} to NRF
async fn smf_nrf_register(sbi_addr: &str, sbi_port: u16) -> std::result::Result<String, String> {
    let sbi_ctx = global_context();

    // Prefer the URI seeded from YAML config; fall back to NRF_URI env var
    let nrf_uri = match sbi_ctx.get_nrf_uri().await {
        Some(uri) => uri,
        None => match std::env::var("NRF_URI").ok() {
            Some(uri) => uri,
            None => {
                log::debug!("No NRF URI configured, skipping NRF registration");
                return Ok(String::new());
            }
        },
    };

    log::info!("Registering SMF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "SMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{nf_instance_id}-nsmf-pdusession"),
            "serviceName": "nsmf-pdusession",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }],
        "allowedNfTypes": ["AMF"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("SMF registered with NRF (id={nf_instance_id})");

            // Store self instance in SBI context
            let mut self_instance = NfInstance::new(&nf_instance_id, ogs_sbi::types::NfType::Smf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = NfService::new(
                "nsmf-pdusession",
                ogs_sbi::types::SbiServiceType::NsmfPdusession,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777")
fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
}

/// SBI request handler for SMF
async fn smf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("SMF SBI request: {method} {uri}");

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
        ("nsmf-pdusession", "sm-contexts", "POST")
            if parts.len() >= 5 && parts[4] == "retrieve" =>
        {
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
        ("nsmf-pdusession", "pdu-sessions", "POST")
            if parts.len() >= 5 && parts[4] == "release" =>
        {
            let pdu_session_ref = parts[3];
            handle_pdu_session_release(pdu_session_ref).await
        }

        // =====================================================================
        // Event Exposure Service (nsmf-event-exposure)
        // =====================================================================

        // Subscribe to events
        // POST /nsmf-event-exposure/v1/subscriptions
        ("nsmf-event-exposure", "subscriptions", "POST") => handle_event_subscribe().await,

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

        // SM Policy Update/Terminate Notification (from PCF, TS 29.512
        // §4.2.3/§4.2.4: POST {notificationUri}/update | /terminate)
        ("nsmf-callback", "sm-policy-notify", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                let action = parts.get(4).copied().unwrap_or("update");
                match action {
                    "update" => handle_sm_policy_notify(sm_context_ref, &request).await,
                    "terminate" => handle_sm_policy_terminate(sm_context_ref).await,
                    other => send_bad_request(&format!("Unknown notify action '{other}'"), None),
                }
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
            log::warn!("Unknown SBI endpoint: {method} {path}");
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

/// QoS applied to the N4 session, derived from the PCF SM policy decision
/// (or the documented config-default when no PCF is configured).
struct SessionQos {
    qfi: u8,
    ambr_ul_bps: u64,
    ambr_dl_bps: u64,
    /// When the authorized flow is an XR delay-critical GBR 5QI (82-85), the
    /// XR flow parameters that drive a dedicated XR QER in the PFCP session.
    xr_flow: Option<XrSessionFlow>,
}

/// XR delay-critical GBR flow carried into the PFCP QER/PDR setup.
struct XrSessionFlow {
    five_qi: u8,
    gbr_ul_bps: u64,
    gbr_dl_bps: u64,
}

/// Build a `binding::SessionPolicy` from a parsed `PolicyDecision` so the
/// XR-aware QoS-flow binding can inspect the authorized 5QI/GBR.
///
/// The decision's PCC rules carry per-rule 5QI + GBR; when none are present
/// (config-default), a synthetic rule from the default 5QI is emitted so an XR
/// default 5QI still produces an XR flow.
fn decision_to_session_policy(decision: &policy::PolicyDecision) -> binding::SessionPolicy {
    let mut sp = binding::SessionPolicy::new();
    let mk_rule =
        |id: &str, five_qi: u8, arp: u8, gbr_ul: u64, gbr_dl: u64, mbr_ul: u64, mbr_dl: u64| {
            let mut rule = binding::PccRule::new_5gc_install(id);
            rule.set_qos(binding::PccQos {
                qci: five_qi,
                arp: binding::ArpParams {
                    priority_level: arp,
                    pre_emption_capability: binding::is_xr_5qi(five_qi),
                    pre_emption_vulnerability: false,
                },
                mbr: binding::BitRate {
                    uplink: mbr_ul,
                    downlink: mbr_dl,
                },
                gbr: binding::BitRate {
                    uplink: gbr_ul,
                    downlink: gbr_dl,
                },
            });
            rule
        };

    if decision.pcc_rules.is_empty() {
        sp.add_rule(mk_rule(
            "default",
            decision.def_five_qi,
            decision.arp_priority_level,
            0,
            0,
            decision.sess_ambr_ul_bps,
            decision.sess_ambr_dl_bps,
        ));
    } else {
        for r in &decision.pcc_rules {
            sp.add_rule(mk_rule(
                &r.id,
                r.five_qi,
                decision.arp_priority_level,
                r.gbr_ul_bps.unwrap_or(0),
                r.gbr_dl_bps.unwrap_or(0),
                r.mbr_ul_bps.unwrap_or(decision.sess_ambr_ul_bps),
                r.mbr_dl_bps.unwrap_or(decision.sess_ambr_dl_bps),
            ));
        }
    }
    sp
}

/// Send PFCP Session Establishment Request to UPF and return UPF TEID.
///
/// The QER enforcing the authorized Session-AMBR (TS 29.512 authSessAmbr →
/// TS 29.244 MBR) and the QFI come from `qos` — no hardcoded values.
async fn pfcp_session_establish(
    smf_n4_seid: u64,
    ue_ip: [u8; 4],
    dnn: &str,
    sst: u8,
    qos: &SessionQos,
) -> Result<PfcpSessionResult> {
    use n4_build::{pfcp_ie, FarParams, PdrParams, PfcpMessageBuilder, QerParams};

    let client =
        pfcp_path::global_client().ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;

    // TS 29.244 6.2.6.2: no session signalling without an association
    if !client.is_associated().await {
        anyhow::bail!("no established PFCP association with {}", client.peer());
    }

    log::info!(
        "PFCP Session Establishment: UPF={}, UE IP={}.{}.{}.{}",
        client.peer(),
        ue_ip[0],
        ue_ip[1],
        ue_ip[2],
        ue_ip[3]
    );

    // Build PFCP payload: Node ID + F-SEID + Create PDR (uplink) + Create FAR
    // (uplink) + Create PDR (downlink) + Create FAR (downlink)
    let smf_ip = client.node_ip();
    let mut builder = PfcpMessageBuilder::new();

    // Node ID (IPv4, with the mandatory Node ID Type octet — TS 29.244 8.2.38)
    builder.add_node_id_ipv4(smf_ip);

    // F-SEID (SMF's SEID)
    builder.add_f_seid(smf_n4_seid, Some(smf_ip), None);

    // APN/DNN
    builder.add_apn_dnn(dnn);

    // S-NSSAI
    builder.add_s_nssai(sst, None);

    // Create QER 1: enforce the authorized Session-AMBR (MBR UL/DL) on the
    // default QoS flow. Gates open in both directions.
    let session_qer = QerParams {
        qer_id: 1,
        gate_status: (0, 0),
        mbr: Some((qos.ambr_ul_bps, qos.ambr_dl_bps)),
        gbr: None,
        qfi: Some(qos.qfi),
    };
    let qer_bytes = n4_build::build_create_qer(&session_qer);
    builder.add_tlv(pfcp_ie::CREATE_QER, &qer_bytes);

    // Create QER 2 (XR delay-critical GBR, TS 23.501 §5.7.4 / TS 29.244 5.4.1):
    // when the authorized flow is an XR 5QI (82-85), install a dedicated QER
    // carrying the guaranteed bit rate so the UPF arms guaranteed-rate buckets
    // and never starves the XR flow. The XR QFI tags the GTP-U packets for
    // DSCP marking (EF/AF41) at the UPF. Gates open in both directions.
    let xr_qer_id: u32 = 2;
    if let Some(ref xr) = qos.xr_flow {
        let xr_qer = QerParams {
            qer_id: xr_qer_id,
            gate_status: (0, 0),
            mbr: Some((qos.ambr_ul_bps, qos.ambr_dl_bps)),
            // GBR set marks this as a delay-critical guaranteed-rate (XR) flow;
            // the UPF recognizes XR from the GBR (the XR 5QI 82-85 cannot
            // survive the 6-bit PFCP QFI, so GBR is the wire-stable signal).
            gbr: Some((xr.gbr_ul_bps, xr.gbr_dl_bps)),
            qfi: Some(xr.five_qi & 0x3F),
        };
        let xr_qer_bytes = n4_build::build_create_qer(&xr_qer);
        builder.add_tlv(pfcp_ie::CREATE_QER, &xr_qer_bytes);
        log::info!(
            "PFCP: installing XR QER {} (5QI={}, GBR UL/DL={}/{} bps)",
            xr_qer_id,
            xr.five_qi,
            xr.gbr_ul_bps,
            xr.gbr_dl_bps
        );
    }
    // PDRs bind to the XR QER when present, otherwise the Session-AMBR QER.
    let flow_qer_id = if qos.xr_flow.is_some() { xr_qer_id } else { 1 };
    let flow_qfi = qos
        .xr_flow
        .as_ref()
        .map(|x| x.five_qi & 0x3F)
        .unwrap_or(qos.qfi);

    // Create PDR 1 (Uplink): UE -> UPF -> DN
    let ul_pdr = PdrParams {
        pdr_id: 1,
        precedence: 100,
        source_interface: 0,                            // Access
        f_teid: Some((0, None, None)),                  // teid=0: UPF allocates
        ue_ip_address: Some((Some(ue_ip), None, true)), // source
        outer_header_removal: Some(0),                  // GTP-U/UDP/IPv4
        far_id: Some(1),
        qer_id: Some(flow_qer_id),
        qfi: Some(flow_qfi),
        ..Default::default()
    };
    let ul_pdr_bytes = n4_build::build_create_pdr(&ul_pdr);
    builder.add_tlv(pfcp_ie::CREATE_PDR, &ul_pdr_bytes);

    // Create FAR 1 (Uplink): Forward to DN
    let ul_far = FarParams {
        far_id: 1,
        apply_action: 0x02,             // FORW (forward)
        destination_interface: Some(2), // SGi-LAN/N6 (TS 29.244 8.2.25)
        ..Default::default()
    };
    let ul_far_bytes = n4_build::build_create_far(&ul_far);
    builder.add_tlv(pfcp_ie::CREATE_FAR, &ul_far_bytes);

    // Create PDR 2 (Downlink): DN -> UPF -> UE (initially buffered, FAR updated after gNB responds)
    let dl_pdr = PdrParams {
        pdr_id: 2,
        precedence: 100,
        source_interface: 1, // Core (TS 29.244 8.2.24)
        ue_ip_address: Some((Some(ue_ip), None, false)), // destination
        far_id: Some(2),
        qer_id: Some(flow_qer_id),
        qfi: Some(flow_qfi),
        ..Default::default()
    };
    let dl_pdr_bytes = n4_build::build_create_pdr(&dl_pdr);
    builder.add_tlv(pfcp_ie::CREATE_PDR, &dl_pdr_bytes);

    // Create FAR 2 (Downlink): Buffer initially (will be updated with gNB TEID)
    let dl_far = FarParams {
        far_id: 2,
        apply_action: 0x04,             // BUFF (buffer)
        destination_interface: Some(0), // Access
        ..Default::default()
    };
    let dl_far_bytes = n4_build::build_create_far(&dl_far);
    builder.add_tlv(pfcp_ie::CREATE_FAR, &dl_far_bytes);

    let payload = builder.build();

    // Send through the transaction engine: T1 retransmission up to N1
    // attempts, exhaustion = error (TS 29.244 7.2.1). SEID=0 for a new
    // session (TS 29.244 7.2.2.4.2).
    let (resp_type, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST,
            Some(0),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Establishment failed: {e}"))?;

    if resp_type != pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE {
        anyhow::bail!("unexpected PFCP response type {resp_type} to Session Establishment");
    }

    // Cause check: any non-accepted cause is a hard failure with the real
    // cause value surfaced (no silent fallback)
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => {}
        Some(cause) => anyhow::bail!(
            "PFCP Session Establishment rejected: cause {cause} ({})",
            pfcp_path::cause_name(cause)
        ),
        None => anyhow::bail!("PFCP Session Establishment Response missing mandatory Cause IE"),
    }

    let resp_payload = &resp_body[..];

    // Parse response IEs to find UP F-SEID and Created PDR with F-TEID
    let mut upf_seid: u64 = 0;
    let mut upf_teid: u32 = 0;
    let mut upf_ip: [u8; 4] = [127, 0, 0, 1];

    let mut offset = 0;
    while offset + 4 <= resp_payload.len() {
        let ie_type = u16::from_be_bytes([resp_payload[offset], resp_payload[offset + 1]]);
        let ie_len =
            u16::from_be_bytes([resp_payload[offset + 2], resp_payload[offset + 3]]) as usize;
        let ie_start = offset + 4;
        let ie_end = ie_start + ie_len;
        if ie_end > resp_payload.len() {
            break;
        }

        let ie_value = &resp_payload[ie_start..ie_end];

        match ie_type {
            57 => {
                // F-SEID (0x0039)
                if ie_value.len() >= 9 {
                    let flags = ie_value[0];
                    upf_seid = u64::from_be_bytes(ie_value[1..9].try_into().unwrap());
                    if flags & 0x02 != 0 && ie_value.len() >= 13 {
                        upf_ip = [ie_value[9], ie_value[10], ie_value[11], ie_value[12]];
                    }
                    log::info!(
                        "UPF F-SEID: seid=0x{:016x}, ip={}.{}.{}.{}",
                        upf_seid,
                        upf_ip[0],
                        upf_ip[1],
                        upf_ip[2],
                        upf_ip[3]
                    );
                }
            }
            8 => {
                // Created PDR (0x0008)
                // Parse inner IEs of Created PDR group
                let mut inner_off = 0;
                while inner_off + 4 <= ie_value.len() {
                    let inner_type =
                        u16::from_be_bytes([ie_value[inner_off], ie_value[inner_off + 1]]);
                    let inner_len =
                        u16::from_be_bytes([ie_value[inner_off + 2], ie_value[inner_off + 3]])
                            as usize;
                    let inner_start = inner_off + 4;
                    let inner_end = inner_start + inner_len;
                    if inner_end > ie_value.len() {
                        break;
                    }

                    if inner_type == 21 {
                        // F-TEID (0x0015)
                        let fteid_val = &ie_value[inner_start..inner_end];
                        if fteid_val.len() >= 5 {
                            let fteid_flags = fteid_val[0];
                            let teid = u32::from_be_bytes(fteid_val[1..5].try_into().unwrap());
                            if fteid_flags & 0x02 != 0 && fteid_val.len() >= 9 {
                                upf_ip = [fteid_val[5], fteid_val[6], fteid_val[7], fteid_val[8]];
                            }
                            if teid != 0 {
                                upf_teid = teid;
                                log::info!("UPF F-TEID: teid=0x{upf_teid:08x}");
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

    if upf_seid == 0 {
        anyhow::bail!("PFCP Session Establishment Response missing UP F-SEID (mandatory IE)");
    }
    if upf_teid == 0 {
        // Conditional IE failure: with FTUP the UPF must return the
        // allocated F-TEID in a Created PDR (TS 29.244 7.5.3.2)
        anyhow::bail!("PFCP Session Establishment Response missing Created PDR F-TEID");
    }

    log::info!("PFCP Session Established: UPF SEID=0x{upf_seid:016x}, UPF TEID=0x{upf_teid:08x}");

    Ok(PfcpSessionResult {
        upf_seid,
        upf_teid,
        upf_addr: upf_ip,
    })
}

/// Send PFCP Session Modification Request to UPF to activate DL FAR with gNB TEID
async fn pfcp_session_modify(upf_seid: u64, gnb_teid: u32, gnb_addr: [u8; 4]) -> Result<()> {
    use n4_build::{build_session_modification_request, SessionModificationParams};

    let client =
        pfcp_path::global_client().ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    if !client.is_associated().await {
        anyhow::bail!("no established PFCP association with {}", client.peer());
    }

    log::info!(
        "PFCP Session Modification: UPF SEID=0x{:016x}, gNB TEID=0x{:08x}, gNB addr={}.{}.{}.{}",
        upf_seid,
        gnb_teid,
        gnb_addr[0],
        gnb_addr[1],
        gnb_addr[2],
        gnb_addr[3]
    );

    // Build modification: update FAR 2 (downlink) from BUFF to FORW with outer header creation (GTP-U to gNB)
    // outer_header_creation: (description, teid, ipv4, ipv6)
    // description 0x0100 = GTP-U/UDP/IPv4
    let params = SessionModificationParams {
        update_fars_activate: vec![(
            2,                                              // FAR ID 2 (downlink)
            0,                                              // destination_interface: Access
            Some((0x0100, gnb_teid, Some(gnb_addr), None)), // outer header creation: GTP-U to gNB
            true, // SNDEM: End Marker packets on the old tunnel
        )],
        ..Default::default()
    };

    let payload = build_session_modification_request(&params);

    let (resp_type, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_MODIFICATION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Modification failed: {e}"))?;

    if resp_type != pfcp_path::pfcp_message_type::SESSION_MODIFICATION_RESPONSE {
        anyhow::bail!("unexpected PFCP response type {resp_type} to Session Modification");
    }
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => {
            log::info!("PFCP Session Modification successful");
            Ok(())
        }
        Some(cause) => anyhow::bail!(
            "PFCP Session Modification rejected: cause {cause} ({})",
            pfcp_path::cause_name(cause)
        ),
        None => anyhow::bail!("PFCP Session Modification Response missing mandatory Cause IE"),
    }
}

/// Send PFCP Session Deletion Request to UPF
async fn pfcp_session_delete(upf_seid: u64) -> Result<()> {
    let client =
        pfcp_path::global_client().ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    if !client.is_associated().await {
        anyhow::bail!("no established PFCP association with {}", client.peer());
    }

    log::info!("PFCP Session Deletion: UPF SEID=0x{upf_seid:016x}");

    // Session Deletion Request has no message-body IEs (TS 29.244 7.5.6)
    let payload = n4_build::build_session_deletion_request();

    let (resp_type, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Deletion failed: {e}"))?;

    if resp_type != pfcp_path::pfcp_message_type::SESSION_DELETION_RESPONSE {
        anyhow::bail!("unexpected PFCP response type {resp_type} to Session Deletion");
    }
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => {
            log::info!("PFCP Session Deletion successful");
            Ok(())
        }
        Some(cause) => anyhow::bail!(
            "PFCP Session Deletion rejected: cause {cause} ({})",
            pfcp_path::cause_name(cause)
        ),
        None => anyhow::bail!("PFCP Session Deletion Response missing mandatory Cause IE"),
    }
}

// =============================================================================
// SM Context Handlers
// =============================================================================

/// Build a ProblemDetails 400 response (TS 29.500 §5.2.7).
fn problem_400(cause: &str, detail: &str) -> SbiResponse {
    let body = serde_json::json!({
        "status": 400,
        "cause": cause,
        "detail": detail,
    });
    SbiResponse::with_status(400).with_body(body.to_string(), "application/problem+json")
}

/// Build the N2 SM `PDUSessionResourceSetupRequestTransfer` (TS 38.413
/// §9.3.4.1) carrying the UPF N3 GTP-U F-TEID and the QoS flow setup list,
/// using the real-APER `ogs-ngap` transfer codec (not bespoke bytes).
fn build_setup_request_transfer(
    upf_teid: u32,
    upf_addr: [u8; 4],
    qfi: u8,
    five_qi: u16,
    arp_priority_level: u8,
) -> ogs_ngap::NgapResult<Vec<u8>> {
    use ogs_ngap::transfer::{
        AllocationAndRetentionPriority, GtpTunnel, NonDynamic5qiDescriptor,
        PduSessionResourceSetupRequestTransfer, PduSessionType, PreEmptionCapability,
        PreEmptionVulnerability, QosCharacteristics, QosFlowLevelQosParameters,
        QosFlowSetupRequestItem, TransportLayerAddress, UpTransportLayerInformation,
    };

    let transfer = PduSessionResourceSetupRequestTransfer {
        pdu_session_aggregate_maximum_bit_rate: None,
        ul_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress::from_ipv4(upf_addr),
            gtp_teid: upf_teid.to_be_bytes(),
        }),
        data_forwarding_not_possible: false,
        pdu_session_type: PduSessionType::Ipv4,
        security_indication: None,
        network_instance: None,
        qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
            qos_flow_identifier: qfi,
            qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(
                    NonDynamic5qiDescriptor::new(five_qi),
                ),
                allocation_and_retention_priority: AllocationAndRetentionPriority {
                    priority_level_arp: arp_priority_level,
                    pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                },
                gbr_qos_information: None,
                reflective_qos_attribute: false,
                additional_qos_flow_information: false,
            },
            e_rab_id: None,
        }],
    };
    transfer.encode()
}

/// Extract the gNB DL GTP-U endpoint (TEID, IPv4 address, first QFI) from a
/// real-APER `PDUSessionResourceSetupResponseTransfer` (TS 38.413 §9.3.4.2).
fn decode_setup_response_dl_endpoint(data: &[u8]) -> Option<(u32, [u8; 4], u8)> {
    use ogs_ngap::transfer::{
        PduSessionResourceSetupResponseTransfer, UpTransportLayerInformation,
    };

    let transfer = match PduSessionResourceSetupResponseTransfer::decode(data) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to decode PDUSessionResourceSetupResponseTransfer: {e:?}");
            return None;
        }
    };
    let UpTransportLayerInformation::GtpTunnel(tunnel) = &transfer
        .dl_qos_flow_per_tnl_information
        .up_transport_layer_information;
    let teid = u32::from_be_bytes(tunnel.gtp_teid);
    let addr = ipv4_from_octets(&tunnel.transport_layer_address.octets)?;
    let qfi = transfer
        .dl_qos_flow_per_tnl_information
        .associated_qos_flow_list
        .first()
        .map(|f| f.qos_flow_identifier)
        .unwrap_or(0);
    Some((teid, addr, qfi))
}

/// Extract the target-gNB DL GTP-U endpoint from a real-APER
/// `PathSwitchRequestTransfer` (TS 38.413 §9.3.4.8) during an Xn handover.
fn decode_path_switch_dl_endpoint(data: &[u8]) -> Option<(u32, [u8; 4], u8)> {
    use ogs_ngap::transfer::{PathSwitchRequestTransfer, UpTransportLayerInformation};

    let transfer = match PathSwitchRequestTransfer::decode(data) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to decode PathSwitchRequestTransfer: {e:?}");
            return None;
        }
    };
    let UpTransportLayerInformation::GtpTunnel(tunnel) = &transfer.dl_ngu_up_tnl_information;
    let teid = u32::from_be_bytes(tunnel.gtp_teid);
    let addr = ipv4_from_octets(&tunnel.transport_layer_address.octets)?;
    let qfi = transfer
        .qos_flow_accepted_list
        .first()
        .copied()
        .unwrap_or(0);
    Some((teid, addr, qfi))
}

/// Coerce a TransportLayerAddress octet vector to an IPv4 quad (None if not 4).
fn ipv4_from_octets(octets: &[u8]) -> Option<[u8; 4]> {
    if octets.len() == 4 {
        Some([octets[0], octets[1], octets[2], octets[3]])
    } else {
        // IPv6 (16) or other widths are not supported for the GTP-U DL path here
        log::warn!(
            "gNB transport address is not IPv4 ({} octets)",
            octets.len()
        );
        None
    }
}

/// Build an SmContextCreateError (TS 29.502 §6.1.6.2.4) carrying a
/// PDU Session Establishment Reject N1 SM container with a 5GSM cause.
fn sm_context_create_error(
    status: u16,
    cause: &str,
    psi: u8,
    pti: u8,
    gsm_cause_5gsm: u8,
) -> SbiResponse {
    use base64::Engine;
    let n1 = policy::build_establishment_reject(psi, pti, gsm_cause_5gsm);
    let body = serde_json::json!({
        "error": { "status": status, "cause": cause },
        "n1SmMsg": base64::engine::general_purpose::STANDARD.encode(&n1),
    });
    SbiResponse::with_status(status).with_body(body.to_string(), "application/json")
}

/// Dispatch an Npcf_SMPolicyControl client response into a session's GSM FSM
/// (drives Wait5gcSmPolicyAssociation → WaitPfcpEstablishment / N1N2Reject5gc).
fn fsm_dispatch_policy_response(fsm: &mut gsm_sm::GsmFsm, status: u16) {
    let mut ev = event::SmfEvent::sbi_client(event::SbiResponse { status, body: None }, 0);
    if let Some(ref mut sbi) = ev.sbi {
        sbi.message = Some(event::SbiMessage {
            service_name: "npcf-smpolicycontrol".to_string(),
            res_status: Some(status),
            ..Default::default()
        });
    }
    fsm.dispatch(&ev);
}

/// Handle SM Context Create (from AMF via N11, TS 29.502 §5.2.2.2)
async fn handle_sm_context_create(request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Create request received");

    // Parse request body
    let req_body: serde_json::Value = match &request.http.content {
        Some(content) => match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to parse SM Context Create request: {e}");
                return problem_400("INVALID_MSG_FORMAT", "request body is not valid JSON");
            }
        },
        None => return problem_400("MANDATORY_IE_MISSING", "SmContextCreateData body required"),
    };

    // ---- SmContextCreateData attributes (TS 29.502 Table 6.1.6.2.2-1) ----
    let Some(pdu_session_id) = req_body["pduSessionId"]
        .as_u64()
        .filter(|p| (1..=15).contains(p))
        .map(|p| p as u8)
    else {
        return problem_400("MANDATORY_IE_INCORRECT", "pduSessionId (1..15) is required");
    };
    let Some(dnn) = req_body["dnn"].as_str().map(str::to_string) else {
        return problem_400("MANDATORY_IE_MISSING", "dnn is required");
    };
    let Some(sst) = req_body["sNssai"]["sst"].as_u64().map(|v| v as u8) else {
        return problem_400("MANDATORY_IE_MISSING", "sNssai.sst is required");
    };
    let snssai_sd = req_body["sNssai"]["sd"].as_str().map(str::to_string);
    // supi is conditional-mandatory (non-emergency registration); the current
    // AMF does not send it yet (Wave 3.1), so warn instead of rejecting.
    let supi = match req_body["supi"].as_str() {
        Some(s) => s.to_string(),
        None => {
            log::warn!("SmContextCreateData without supi (lenient: AMF Wave 3.1 pending)");
            "imsi-unknown".to_string()
        }
    };
    let an_type = req_body["anType"].as_str().unwrap_or_else(|| {
        log::warn!("SmContextCreateData without anType — assuming 3GPP_ACCESS");
        "3GPP_ACCESS"
    });
    let sm_context_status_uri = req_body["smContextStatusUri"].as_str().map(str::to_string);
    if sm_context_status_uri.is_none() {
        log::warn!(
            "SmContextCreateData without smContextStatusUri (status notifications disabled)"
        );
    }
    let serving_nf_id = req_body["servingNfId"].as_str().unwrap_or("");
    let rat_type = req_body["ratType"].as_str().unwrap_or("NR");
    // RedCap (Reduced Capability) UE indication (Rel-17, TS 29.502): drives a
    // reduced session-AMBR cap below so a RedCap device's data path is policed
    // to its narrowband capability.
    let redcap_indication = req_body["redcapIndication"].as_bool().unwrap_or(false);
    let guami = &req_body["guami"];
    let serving_network = &req_body["servingNetwork"];
    log::info!(
        "SM Context Create: SUPI={supi}, PSI={pdu_session_id}, SST={sst}, DNN={dnn}, \
         anType={an_type}, ratType={rat_type}, servingNfId={serving_nf_id}, \
         guami={guami}, servingNetwork={serving_network}"
    );

    // ---- N1 SM container: PDU Session Establishment Request (TS 24.501) ----
    let (pti, requested_type, requested_ssc) = match req_body["n1SmMsg"].as_str() {
        Some(b64) => {
            use base64::Engine;
            let Ok(n1_bytes) = base64::engine::general_purpose::STANDARD.decode(b64) else {
                return problem_400("N1_SM_ERROR", "n1SmMsg is not valid base64");
            };
            match policy::parse_establishment_request(&n1_bytes) {
                Some(req) => {
                    if req.psi != pdu_session_id {
                        log::warn!(
                            "N1 PSI {} differs from SmContextCreateData pduSessionId {}",
                            req.psi,
                            pdu_session_id
                        );
                    }
                    log::info!(
                        "N1 SM decoded: PTI={}, requested PDU type={:?}, SSC mode={:?}, \
                         integrity max rate={:?}",
                        req.pti,
                        req.requested_pdu_session_type,
                        req.requested_ssc_mode,
                        req.integrity_max_rate
                    );
                    (
                        req.pti,
                        req.requested_pdu_session_type
                            .unwrap_or(policy::pdu_session_type::IPV4),
                        req.requested_ssc_mode.unwrap_or(1),
                    )
                }
                None => {
                    return problem_400(
                        "N1_SM_ERROR",
                        "n1SmMsg is not a PDU Session Establishment Request",
                    )
                }
            }
        }
        None => {
            log::warn!("SmContextCreateData without n1SmMsg — using defaults (PTI=0)");
            (0u8, policy::pdu_session_type::IPV4, 1u8)
        }
    };

    // Selected PDU session type: this SMF serves IPv4 (and the IPv4 leg of
    // IPv4v6). IPv6-only/Ethernet/Unstructured → reject, 5GSM cause #50.
    let selected_type = match requested_type {
        policy::pdu_session_type::IPV4 | policy::pdu_session_type::IPV4V6 => {
            policy::pdu_session_type::IPV4
        }
        other => {
            log::warn!("Unsupported requested PDU session type {other} — rejecting (cause 50)");
            return sm_context_create_error(
                403,
                "PDU_SESSION_TYPE_NOT_SUPPORTED",
                pdu_session_id,
                pti,
                policy::gsm_cause::PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED,
            );
        }
    };
    let selected_ssc = if requested_ssc == 0 { 1 } else { requested_ssc };

    // ---- Allocate session resources ----
    let ctx = smf_self();
    let sm_context_ref;
    let ue_ip_octets: [u8; 4];

    if let Ok(context) = ctx.read() {
        let sess_idx = context.next_sess_index();
        sm_context_ref = format!("{sess_idx}");
        // Allocate UE IP from bitmap pool
        match context.ipv4_pool.allocate() {
            Some(addr) => {
                ue_ip_octets = addr.octets();
            }
            None => {
                log::error!("IPv4 address pool exhausted");
                return sm_context_create_error(
                    500,
                    "INSUFFICIENT_RESOURCES",
                    pdu_session_id,
                    pti,
                    policy::gsm_cause::INSUFFICIENT_RESOURCES,
                );
            }
        }
    } else {
        return SbiResponse::with_status(500);
    }

    log::info!(
        "SMF allocated: ref={}, UE IP={}.{}.{}.{}",
        sm_context_ref,
        ue_ip_octets[0],
        ue_ip_octets[1],
        ue_ip_octets[2],
        ue_ip_octets[3]
    );

    let release_ip = || {
        if let Ok(ctx) = smf_self().read() {
            ctx.ipv4_pool
                .release(std::net::Ipv4Addr::from(ue_ip_octets));
        }
    };

    // ---- GSM FSM: Initial → Wait5gcSmPolicyAssociation ----
    let sess_idx_u64 = sm_context_ref.parse::<u64>().unwrap_or(0);
    let mut fsm = gsm_sm::GsmFsm::new(sess_idx_u64);
    fsm.init();
    fsm.dispatch(&event::SmfEvent::gsm_message(
        sess_idx_u64,
        policy::gsm_message_type::ESTABLISHMENT_REQUEST,
        Vec::new(),
    ));

    // ---- Npcf_SMPolicyControl_Create (TS 29.512 §4.2.2) ----
    let notification_uri = format!(
        "{}/nsmf-callback/v1/sm-policy-notify/{}",
        self_sbi_uri(),
        sm_context_ref
    );
    let mut decision = match policy::resolve_pcf_endpoint().await {
        None => {
            // Documented config-default fallback: no PCF configured.
            log::warn!(
                "No PCF configured (PCF_URI / NRF) — applying config-default policy \
                 (DNN-derived 5QI, AMBR 100/100 Mbps)"
            );
            fsm.transition_to(gsm_sm::GsmState::WaitPfcpEstablishment);
            // DNN-aware default: an XR DNN (e.g. "xr") yields a delay-critical
            // GBR XR 5QI (82-85) with a populated PCC rule, exercising the
            // XR-aware QoS-flow binding + PFCP QER setup below even without a PCF.
            policy::PolicyDecision::config_default_for_dnn(&dnn)
        }
        Some(pcf) => {
            let create_ctx = policy::SmPolicyCreateContext {
                supi: &supi,
                psi: pdu_session_id,
                pdu_session_type: selected_type,
                dnn: &dnn,
                sst,
                sd: snssai_sd.as_deref(),
                ue_ipv4: ue_ip_octets,
                notification_uri: &notification_uri,
            };
            match policy::sm_policy_create(&pcf, &create_ctx).await {
                Ok(decision) => {
                    log::info!(
                        "SM policy created: id={}, 5QI={}, AMBR UL/DL={}/{} bps, {} PCC rule(s)",
                        decision.sm_policy_id,
                        decision.def_five_qi,
                        decision.sess_ambr_ul_bps,
                        decision.sess_ambr_dl_bps,
                        decision.pcc_rules.len()
                    );
                    fsm_dispatch_policy_response(&mut fsm, 201);
                    decision
                }
                Err(policy::PolicyError::Rejected { status, detail }) => {
                    // Abnormal path: PCF policy rejection → session reject
                    // with 5GSM cause #29 (TS 24.501).
                    log::error!("PCF rejected SM policy (status={status}): {detail}");
                    fsm_dispatch_policy_response(&mut fsm, status);
                    release_ip();
                    return sm_context_create_error(
                        403,
                        "POLICY_REJECTED",
                        pdu_session_id,
                        pti,
                        policy::gsm_cause::USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED,
                    );
                }
                Err(e) => {
                    // PCF configured but unreachable: hard failure (no
                    // silent fallback) → 5GSM cause #38 network failure.
                    log::error!("SM policy create failed: {e}");
                    fsm.transition_to(gsm_sm::GsmState::Exception);
                    release_ip();
                    return sm_context_create_error(
                        504,
                        "PCF_NOT_RESPONDING",
                        pdu_session_id,
                        pti,
                        policy::gsm_cause::NETWORK_FAILURE,
                    );
                }
            }
        }
    };

    // ---- XR DNN → XR 5QI upgrade (Rel-18, TS 23.501 §5.7.4) ----
    // The DNN is the only XR signal a standard UE conveys at establishment, so
    // apply the XR delay-critical GBR 5QI here for an XR DNN regardless of the
    // policy source. Idempotent for the config-default path (already XR) and a
    // no-op for non-XR DNNs; it upgrades a PCF decision that doesn't model XR.
    decision.ensure_xr_for_dnn(&dnn);

    // ---- RedCap session-AMBR reduction (Rel-17, TS 23.501 §5.7.1) ----
    // A RedCap UE's narrowband RF cannot sustain a normal-UE session-AMBR, so
    // cap the authorized Session-AMBR to the configured RedCap ceiling. This
    // single reduction propagates to the N1 PDU Session Establishment Accept,
    // the PFCP QER MBR (and thus the UPF data-plane policing), and the stored
    // policy binding below — no separate enforcement site needed.
    if redcap_indication {
        // RedCap session-AMBR ceiling (TS 38.101-1 RedCap peak-rate envelope):
        // 150 Mbps DL / 50 Mbps UL. Configurable via REDCAP_SESS_AMBR_*_BPS.
        let redcap_dl_cap = std::env::var("REDCAP_SESS_AMBR_DL_BPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(150_000_000);
        let redcap_ul_cap = std::env::var("REDCAP_SESS_AMBR_UL_BPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50_000_000);

        let orig_dl = decision.sess_ambr_dl_bps;
        let orig_ul = decision.sess_ambr_ul_bps;
        // A zero AMBR means "unset/unlimited" in the authorized policy; treat
        // it as exceeding the cap so the RedCap ceiling still applies.
        decision.sess_ambr_dl_bps = if orig_dl == 0 {
            redcap_dl_cap
        } else {
            orig_dl.min(redcap_dl_cap)
        };
        decision.sess_ambr_ul_bps = if orig_ul == 0 {
            redcap_ul_cap
        } else {
            orig_ul.min(redcap_ul_cap)
        };

        log::info!(
            "RedCap UE: session-AMBR reduced from UL/DL {}/{} to {}/{} bps \
             (RedCap cap UL/DL {}/{} bps)",
            orig_ul,
            orig_dl,
            decision.sess_ambr_ul_bps,
            decision.sess_ambr_dl_bps,
            redcap_ul_cap,
            redcap_dl_cap,
        );
    }

    let qfi = decision.default_qfi();

    // ---- XR-aware QoS flow binding (TS 23.501 §5.7.4, Rel-18) ----
    // Run the XR-aware binding over the authorized policy. When the authorized
    // default 5QI or any installed PCC rule is an XR delay-critical GBR 5QI
    // (82-85), this yields XR flow metadata (delay budget, GBR) that drives a
    // dedicated XR QER in the PFCP session below. For non-XR sessions the
    // metadata is empty and the default Session-AMBR QER is used unchanged.
    let xr_policy = decision_to_session_policy(&decision);
    let (_xr_results, _xr_flags, xr_meta) = binding::process_xr_qos_flow_binding(&xr_policy, &[]);
    let xr_flow = xr_meta.into_iter().next();
    if let Some(ref xr) = xr_flow {
        log::info!(
            "XR QoS flow bound: 5QI={}, PDB={}ms, GBR UL/DL={}/{} bps, PDB-enforcement={}",
            xr.five_qi,
            xr.delay_budget_ms,
            xr.gbr_ul_bps,
            xr.gbr_dl_bps,
            xr.requires_pdb_enforcement
        );
    }

    let session_qos = SessionQos {
        qfi,
        ambr_ul_bps: decision.sess_ambr_ul_bps,
        ambr_dl_bps: decision.sess_ambr_dl_bps,
        xr_flow: xr_flow.map(|xr| XrSessionFlow {
            five_qi: xr.five_qi,
            gbr_ul_bps: xr.gbr_ul_bps,
            gbr_dl_bps: xr.gbr_dl_bps,
        }),
    };

    // ---- N4: PFCP Session Establishment with policy-derived QoS ----
    // A failed N4 establishment is a hard failure for the PDU session — no
    // fabricated TEID fallback (the data path would be a black hole).
    let smf_n4_seid = (sm_context_ref.parse::<u64>().unwrap_or(1)) | 0x1000;

    let (upf_teid, upf_addr) =
        match pfcp_session_establish(smf_n4_seid, ue_ip_octets, &dnn, sst, &session_qos).await {
            Ok(result) => {
                log::info!(
                    "PFCP session established: UPF SEID=0x{:016x}, TEID=0x{:08x}, addr={}.{}.{}.{}",
                    result.upf_seid,
                    result.upf_teid,
                    result.upf_addr[0],
                    result.upf_addr[1],
                    result.upf_addr[2],
                    result.upf_addr[3]
                );
                // Store UPF SEID for later PFCP modifications (in SmfContext, not a global)
                if let Ok(ctx) = smf_self().read() {
                    if let Ok(mut sessions) = ctx.pfcp_sessions.write() {
                        sessions.insert(sm_context_ref.to_string(), result.upf_seid);
                    }
                }
                // FSM: WaitPfcpEstablishment → Operational
                fsm.dispatch(&event::SmfEvent::n4_message(0, 0, Vec::new()));
                (result.upf_teid, result.upf_addr)
            }
            Err(e) => {
                log::error!("PFCP session establishment failed: {e} — rejecting SM context");
                fsm.transition_to(gsm_sm::GsmState::Exception);
                // Roll back the PCF SM policy association (TS 29.512 §4.2.5)
                if let Some(ref pol_id) =
                    (!decision.is_config_default).then_some(decision.sm_policy_id.clone())
                {
                    if let Some(pcf) = policy::resolve_pcf_endpoint().await {
                        if let Err(e) = policy::sm_policy_delete(&pcf, pol_id).await {
                            log::warn!("SM policy rollback delete failed: {e}");
                        }
                    }
                }
                release_ip();
                return sm_context_create_error(
                    504,
                    "UPF_NOT_RESPONDING",
                    pdu_session_id,
                    pti,
                    policy::gsm_cause::INSUFFICIENT_RESOURCES,
                );
            }
        };

    // ---- Store the policy binding (drives later update/release/notify) ----
    if let Ok(context) = ctx.read() {
        if let Ok(mut bindings) = context.policy_bindings.write() {
            bindings.insert(
                sm_context_ref.clone(),
                context::PolicyBinding {
                    sm_policy_id: (!decision.is_config_default)
                        .then_some(decision.sm_policy_id.clone()),
                    supi: supi.clone(),
                    psi: pdu_session_id,
                    pti,
                    pdu_session_type: selected_type,
                    ssc_mode: selected_ssc,
                    ue_ip: ue_ip_octets,
                    dnn: dnn.clone(),
                    qfi,
                    five_qi: decision.def_five_qi,
                    ambr_ul_bps: decision.sess_ambr_ul_bps,
                    ambr_dl_bps: decision.sess_ambr_dl_bps,
                    sm_context_status_uri: sm_context_status_uri.clone(),
                    fsm: fsm.clone(),
                },
            );
        }
    }

    // ---- N1: PDU Session Establishment Accept with authorized QoS ----
    let n1_sm_msg = policy::build_establishment_accept(
        pdu_session_id,
        pti,
        selected_type,
        selected_ssc,
        qfi,
        decision.sess_ambr_dl_bps,
        decision.sess_ambr_ul_bps,
        ue_ip_octets,
        &dnn,
    );

    // ---- N2 SM Information: real-APER PDUSessionResourceSetupRequestTransfer ----
    // TS 38.413 §9.3.4.1, carrying the UPF N3 GTP-U F-TEID + QoS flow setup list.
    // The AMF relays this opaquely to the gNB; the gNB's strict APER decoder
    // rejects the legacy hand-rolled byte layout, so it must be real APER.
    let n2_sm_info = match build_setup_request_transfer(
        upf_teid,
        upf_addr,
        qfi,
        decision.def_five_qi as u16,
        decision.arp_priority_level,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to encode PDUSessionResourceSetupRequestTransfer: {e:?}");
            release_ip();
            return sm_context_create_error(
                500,
                "SYSTEM_FAILURE",
                pdu_session_id,
                pti,
                policy::gsm_cause::NETWORK_FAILURE,
            );
        }
    };

    use base64::Engine;
    let n1_b64 = base64::engine::general_purpose::STANDARD.encode(&n1_sm_msg);
    let n2_b64 = base64::engine::general_purpose::STANDARD.encode(&n2_sm_info);

    let response_body = serde_json::json!({
        "smContextRef": sm_context_ref,
        "pduSessionId": pdu_session_id,
        "upCnxState": "ACTIVATING",
        "n1SmMsg": n1_b64,
        "n2SmInfo": n2_b64,
        "n2SmInfoType": "PDU_RES_SETUP_REQ"
    });

    let location = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}");

    log::info!(
        "SM Context Created: ref={}, 5QI={}, QFI={}, AMBR UL/DL={}/{} bps, UPF TEID=0x{:08x}",
        sm_context_ref,
        decision.def_five_qi,
        qfi,
        decision.sess_ambr_ul_bps,
        decision.sess_ambr_dl_bps,
        upf_teid
    );

    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_body(response_body.to_string(), "application/json")
}

/// Look up the stored UPF SEID for an SM context (copy-then-drop the guards
/// per the lock-order rule).
fn lookup_upf_seid(sm_context_ref: &str) -> Option<u64> {
    smf_self().read().ok().and_then(|ctx| {
        ctx.pfcp_sessions
            .read()
            .ok()
            .and_then(|sessions| sessions.get(sm_context_ref).copied())
    })
}

/// Look up a clone of the policy binding for an SM context.
fn lookup_policy_binding(sm_context_ref: &str) -> Option<context::PolicyBinding> {
    smf_self().read().ok().and_then(|ctx| {
        ctx.policy_bindings
            .read()
            .ok()
            .and_then(|bindings| bindings.get(sm_context_ref).cloned())
    })
}

/// Send a PFCP QER modification carrying an authorized Session-AMBR.
async fn pfcp_update_session_qer(upf_seid: u64, qfi: u8, ambr_ul: u64, ambr_dl: u64) -> Result<()> {
    let client =
        pfcp_path::global_client().ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    let params = n4_build::SessionModificationParams {
        update_qers: vec![n4_build::QerParams {
            qer_id: 1,
            gate_status: (0, 0), // Both gates open
            mbr: Some((ambr_ul, ambr_dl)),
            gbr: None,
            qfi: Some(qfi),
        }],
        ..Default::default()
    };
    let payload = n4_build::build_session_modification_request(&params);
    let (_, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_MODIFICATION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Modification (QoS) failed: {e}"))?;
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => Ok(()),
        cause => anyhow::bail!("PFCP Session Modification (QoS) rejected: cause={cause:?}"),
    }
}

/// Deactivate the downlink FAR (back to BUFF) — used when the AN-side
/// resources failed or the UP connection is deactivated.
async fn pfcp_deactivate_dl_far(upf_seid: u64) -> Result<()> {
    let client =
        pfcp_path::global_client().ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    let params = n4_build::SessionModificationParams {
        update_fars_deactivate: vec![2],
        ..Default::default()
    };
    let payload = n4_build::build_session_modification_request(&params);
    let (_, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_MODIFICATION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP DL FAR deactivation failed: {e}"))?;
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => Ok(()),
        cause => anyhow::bail!("PFCP DL FAR deactivation rejected: cause={cause:?}"),
    }
}

/// Handle SM Context Update (TS 29.502 §5.2.2.3) — dispatches on
/// n2SmInfoType (all inbound values of TS 29.502 Table 6.1.6.3.3-1 that can
/// arrive on /modify) and on upCnxState.
async fn handle_sm_context_update(sm_context_ref: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Update request for ref={sm_context_ref}");

    // Parse request body for N2 SM Info (gNB TEID)
    let req_body: serde_json::Value = match &request.http.content {
        Some(content) => match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                return problem_400("INVALID_MSG_FORMAT", &format!("invalid JSON: {e}"));
            }
        },
        None => serde_json::json!({}),
    };

    let n2_sm_info_type = req_body["n2SmInfoType"].as_str().unwrap_or("");

    match n2_sm_info_type {
        // gNB accepted the PDU session resources (initial setup) — or the UE
        // moved and the target gNB took over (Xn path switch). Both carry the
        // new DL F-TEID that the UPF must forward to, but in different APER
        // transfer containers (TS 38.413 §9.3.4.2 vs §9.3.4.8).
        "PDU_RES_SETUP_RSP" | "PATH_SWITCH_REQ" => {
            use base64::Engine;
            let Some(n2_bytes) = req_body["n2SmInfo"]
                .as_str()
                .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            else {
                return problem_400("N2_SM_ERROR", "n2SmInfo missing or not valid base64");
            };

            // Real-APER decode of the gNB DL N3 endpoint via the ogs-ngap
            // transfer codec (the gNB now emits real APER, not legacy bytes).
            let endpoint = if n2_sm_info_type == "PATH_SWITCH_REQ" {
                decode_path_switch_dl_endpoint(&n2_bytes)
            } else {
                decode_setup_response_dl_endpoint(&n2_bytes)
            };
            let Some((gnb_teid, gnb_addr, qfi)) = endpoint else {
                return problem_400(
                    "N2_SM_ERROR",
                    "could not decode gNB DL F-TEID from N2 SM transfer",
                );
            };

            log::info!(
                "SM Context Update ({n2_sm_info_type}): gNB TEID=0x{:08x}, \
                 addr={}.{}.{}.{}, QFI={}",
                gnb_teid,
                gnb_addr[0],
                gnb_addr[1],
                gnb_addr[2],
                gnb_addr[3],
                qfi
            );

            let Some(upf_seid) = lookup_upf_seid(sm_context_ref) else {
                // No N4 session exists for this context — fabricating a SEID
                // would target an unrelated session
                log::error!("No stored UPF SEID for ref={sm_context_ref}");
                return SbiResponse::with_status(404);
            };
            match pfcp_session_modify(upf_seid, gnb_teid, gnb_addr).await {
                Ok(()) => {
                    log::info!(
                        "PFCP Session Modified: DL FAR activated with gNB TEID=0x{gnb_teid:08x}"
                    );
                }
                Err(e) => {
                    log::error!("PFCP Session Modification failed: {e}");
                    return SbiResponse::with_status(504);
                }
            }

            let mut response_body = serde_json::json!({ "upCnxState": "ACTIVATED" });
            if n2_sm_info_type == "PATH_SWITCH_REQ" {
                // Echo the (unchanged) UL tunnel back to the target gNB
                response_body["n2SmInfoType"] = serde_json::json!("PATH_SWITCH_REQ_ACK");
            }
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        // AN failed to set up (or path-switch / handover resource allocation
        // failed): the DL tunnel is invalid — buffer downlink again.
        "PDU_RES_SETUP_FAIL" | "PATH_SWITCH_SETUP_FAIL" | "HANDOVER_RES_ALLOC_FAIL" => {
            log::warn!("SM Context Update ({n2_sm_info_type}): AN resource failure for ref={sm_context_ref}");
            if let Some(upf_seid) = lookup_upf_seid(sm_context_ref) {
                if let Err(e) = pfcp_deactivate_dl_far(upf_seid).await {
                    log::warn!("DL FAR deactivation after AN failure failed: {e}");
                }
            }
            let response_body = serde_json::json!({ "upCnxState": "DEACTIVATED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        // UE-initiated PDU Session Modification: AMF forwards the N1 SM
        // container; QoS comes from an Npcf_SMPolicyControl_Update — not
        // hardcoded values.
        "PDU_RES_MOD_REQ" => {
            use base64::Engine;
            let Some(n1_sm_msg) = req_body["n1SmMsg"]
                .as_str()
                .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            else {
                return problem_400("N1_SM_ERROR", "n1SmMsg missing or not valid base64");
            };
            let Some(hdr) = policy::parse_n1_sm_header(&n1_sm_msg) else {
                return problem_400("N1_SM_ERROR", "n1SmMsg is not a 5GSM message");
            };
            let binding = lookup_policy_binding(sm_context_ref);
            let psi = binding
                .as_ref()
                .map(|b| b.psi)
                .unwrap_or_else(|| sm_context_ref.parse().unwrap_or(1));
            let pti = hdr.pti;
            log::info!(
                "SM Context Update (UE modification): PSI={psi}, PTI={pti}, msg=0x{:02x}",
                hdr.message_type
            );

            // Re-authorize via PCF (trigger RES_MO_RE, TS 29.512 §4.2.4)
            let (qfi, ambr_ul, ambr_dl) = match binding.as_ref() {
                Some(b) => {
                    let mut authorized = (b.qfi, b.ambr_ul_bps, b.ambr_dl_bps);
                    if let Some(ref pol_id) = b.sm_policy_id {
                        match policy::resolve_pcf_endpoint().await {
                            Some(pcf) => {
                                match policy::sm_policy_update(&pcf, pol_id, &["RES_MO_RE"], None)
                                    .await
                                {
                                    Ok(dec) => {
                                        authorized =
                                            (b.qfi, dec.sess_ambr_ul_bps, dec.sess_ambr_dl_bps);
                                    }
                                    Err(policy::PolicyError::Rejected { status, detail }) => {
                                        // Abnormal path: PCF rejects the
                                        // modification → 403 + 5GSM cause 29
                                        log::error!(
                                            "PCF rejected SM policy update (status={status}): {detail}"
                                        );
                                        return sm_context_create_error(
                                            403,
                                            "POLICY_REJECTED",
                                            psi,
                                            pti,
                                            policy::gsm_cause::USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED,
                                        );
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "SM policy update failed ({e}) — keeping current QoS"
                                        );
                                    }
                                }
                            }
                            None => log::warn!("PCF unresolved — keeping current QoS"),
                        }
                    }
                    authorized
                }
                None => {
                    log::warn!(
                        "No policy binding for ref={sm_context_ref} — applying config-default QoS"
                    );
                    let d = policy::PolicyDecision::config_default();
                    (d.default_qfi(), d.sess_ambr_ul_bps, d.sess_ambr_dl_bps)
                }
            };

            // Apply the authorized QoS to the N4 session QER
            if let Some(seid) = lookup_upf_seid(sm_context_ref) {
                if let Err(e) = pfcp_update_session_qer(seid, qfi, ambr_ul, ambr_dl).await {
                    log::error!("{e}");
                    return SbiResponse::with_status(504);
                }
                // Persist the new authorized AMBR in the binding
                if let Ok(ctx) = smf_self().read() {
                    if let Ok(mut bindings) = ctx.policy_bindings.write() {
                        if let Some(b) = bindings.get_mut(sm_context_ref) {
                            b.ambr_ul_bps = ambr_ul;
                            b.ambr_dl_bps = ambr_dl;
                        }
                    }
                }
            } else {
                log::warn!("No PFCP session found for modification: ref={sm_context_ref}");
            }

            // N1: PDU Session Modification Command (PTI echoed, authorized AMBR)
            let n1_mod_cmd = policy::build_modification_command(psi, pti, ambr_dl, ambr_ul);

            // N2 SM Info: QoS flow modification for gNB (QFI + confirm)
            let n2_sm_info = vec![qfi, 0x01];

            let response_body = serde_json::json!({
                "n1SmMsg": base64::engine::general_purpose::STANDARD.encode(&n1_mod_cmd),
                "n2SmInfo": base64::engine::general_purpose::STANDARD.encode(&n2_sm_info),
                "n2SmInfoType": "PDU_RES_MOD_REQ"
            });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        // gNB confirmed a modification / released resources / reported
        // secondary-RAT usage — acknowledge.
        "PDU_RES_MOD_RSP" | "PDU_RES_REL_RSP" | "SECONDARY_RAT_USAGE" => {
            log::info!(
                "SM Context Update ({n2_sm_info_type}) acknowledged for ref={sm_context_ref}"
            );
            SbiResponse::with_status(200)
                .with_body(serde_json::json!({}).to_string(), "application/json")
        }

        // No N2 payload: UP connection-state change request
        "" => {
            let up_cnx_state = req_body["upCnxState"].as_str().unwrap_or("");
            if up_cnx_state == "DEACTIVATED" {
                // UE went idle: buffer downlink traffic at the UPF
                if let Some(upf_seid) = lookup_upf_seid(sm_context_ref) {
                    if let Err(e) = pfcp_deactivate_dl_far(upf_seid).await {
                        log::warn!("DL FAR deactivation failed: {e}");
                        return SbiResponse::with_status(504);
                    }
                }
                let response_body = serde_json::json!({ "upCnxState": "DEACTIVATED" });
                return SbiResponse::with_status(200)
                    .with_body(response_body.to_string(), "application/json");
            }
            // Default: treat as activation confirmation
            let response_body = serde_json::json!({ "upCnxState": "ACTIVATED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        other => {
            log::warn!("SM Context Update: unsupported n2SmInfoType '{other}'");
            problem_400("N2_SM_ERROR", &format!("unsupported n2SmInfoType {other}"))
        }
    }
}

/// Handle SM Context Release (TS 29.502 §5.2.2.4)
///
/// Deletes the PCF SM policy association (Npcf_SMPolicyControl_Delete,
/// TS 29.512 §4.2.5), sends PFCP Session Deletion to the UPF, releases the
/// UE IP and removes session state. The GSM FSM is driven through
/// WaitPfcpDeletion to release.
async fn handle_sm_context_release(sm_context_ref: &str) -> SbiResponse {
    log::info!("SM Context Release request for ref={sm_context_ref}");

    // Take the policy binding (copy out, drop guards before any await)
    let binding = smf_self().read().ok().and_then(|ctx| {
        ctx.policy_bindings
            .write()
            .ok()
            .and_then(|mut bindings| bindings.remove(sm_context_ref))
    });

    // Drive the GSM FSM: Operational → WaitPfcpDeletion
    let mut fsm = binding.as_ref().map(|b| b.fsm.clone());
    if let Some(ref mut f) = fsm {
        let mut ev = event::SmfEvent::sbi_server(
            0,
            event::SbiRequest {
                method: "POST".to_string(),
                uri: format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/release"),
                body: None,
            },
        );
        if let Some(ref mut sbi) = ev.sbi {
            sbi.message = Some(event::SbiMessage {
                service_name: "nsmf-pdusession".to_string(),
                resource_components: vec![
                    "sm-contexts".to_string(),
                    sm_context_ref.to_string(),
                    "release".to_string(),
                ],
                ..Default::default()
            });
        }
        f.dispatch(&ev);
    }

    // N7: delete the SM policy association at the PCF
    if let Some(ref b) = binding {
        if let Some(ref pol_id) = b.sm_policy_id {
            match policy::resolve_pcf_endpoint().await {
                Some(pcf) => match policy::sm_policy_delete(&pcf, pol_id).await {
                    Ok(()) => log::info!("SM policy association {pol_id} deleted at PCF"),
                    Err(e) => log::warn!("SM policy delete failed: {e} (continuing release)"),
                },
                None => log::warn!("PCF unresolved — skipping SM policy delete"),
            }
        }
    }

    // Look up UPF SEID for this session (from SmfContext, not a global)
    let upf_seid = lookup_upf_seid(sm_context_ref);

    if let Some(seid) = upf_seid {
        // Send PFCP Session Deletion Request to UPF (with retransmission)
        match pfcp_session_delete(seid).await {
            Ok(()) => {
                log::info!("PFCP Session Deleted: UPF SEID=0x{seid:016x} for ref={sm_context_ref}");
                if let Some(ref mut f) = fsm {
                    // WaitPfcpDeletion → release path
                    f.dispatch(&event::SmfEvent::n4_message(0, 0, Vec::new()));
                }
            }
            Err(e) => {
                // The local context is removed anyway: keeping it would leak
                // resources for a session the peer may no longer have
                log::warn!("PFCP Session Deletion failed: {e} (continuing with release)");
            }
        }

        // Remove from PFCP sessions map
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut sessions) = ctx.pfcp_sessions.write() {
                sessions.remove(sm_context_ref);
            }
        }
    } else {
        log::warn!("No PFCP session found for sm_context_ref={sm_context_ref}");
    }

    // Release the UE IP allocated for this session
    if let Some(ref b) = binding {
        if let Ok(ctx) = smf_self().read() {
            ctx.ipv4_pool.release(std::net::Ipv4Addr::from(b.ue_ip));
        }
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
    log::info!("SM Context Retrieve request for ref={sm_context_ref}");

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
    SbiResponse::with_status(404).with_body(error.to_string(), "application/json")
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

    let location = format!("/nsmf-pdusession/v1/pdu-sessions/{pdu_session_ref}");

    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_body(response_body.to_string(), "application/json")
}

/// Handle PDU Session Update
async fn handle_pdu_session_update(pdu_session_ref: &str) -> SbiResponse {
    log::info!("PDU Session Update request for ref={pdu_session_ref}");

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if context
            .sess_find_by_pdu_session_ref(pdu_session_ref)
            .is_some()
        {
            return SbiResponse::with_status(200);
        }
    }

    SbiResponse::with_status(404)
}

/// Handle PDU Session Release
async fn handle_pdu_session_release(pdu_session_ref: &str) -> SbiResponse {
    log::info!("PDU Session Release request for ref={pdu_session_ref}");

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

    let location = format!("/nsmf-event-exposure/v1/subscriptions/{subscription_id}");

    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_body(response_body.to_string(), "application/json")
}

/// Handle Event Unsubscribe
async fn handle_event_unsubscribe(subscription_id: &str) -> SbiResponse {
    log::info!("Event unsubscription request for id={subscription_id}");
    SbiResponse::with_status(204)
}

// =============================================================================
// Callback Handlers
// =============================================================================

/// Handle SM Policy Update Notification (from PCF, TS 29.512 §4.2.3.2):
/// the SmPolicyNotification carries an SmPolicyDecision whose authorized
/// session AMBR / default QoS is applied to the session's N4 QER.
async fn handle_sm_policy_notify(sm_context_ref: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SM Policy update notification for ref={sm_context_ref}");

    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
    else {
        return problem_400("INVALID_MSG_FORMAT", "SmPolicyNotification body required");
    };

    let Some(binding) = lookup_policy_binding(sm_context_ref) else {
        return send_not_found(
            &format!("No SM context for ref={sm_context_ref}"),
            Some("CONTEXT_NOT_FOUND"),
        );
    };

    // The decision may be nested (smPolicyDecision) or top-level
    let decision_json = body.get("smPolicyDecision").unwrap_or(&body);
    let pol_id = binding.sm_policy_id.clone().unwrap_or_default();
    let dec = policy::parse_sm_policy_decision(&pol_id, decision_json);

    log::info!(
        "Applying PCF-updated policy to ref={sm_context_ref}: AMBR UL/DL={}/{} bps, 5QI={}",
        dec.sess_ambr_ul_bps,
        dec.sess_ambr_dl_bps,
        dec.def_five_qi
    );

    // Apply to the N4 session QER (copy SEID out, no guards across await)
    if let Some(seid) = lookup_upf_seid(sm_context_ref) {
        if let Err(e) = pfcp_update_session_qer(
            seid,
            binding.qfi,
            dec.sess_ambr_ul_bps,
            dec.sess_ambr_dl_bps,
        )
        .await
        {
            log::error!("Failed to apply PCF-updated QoS: {e}");
            return SbiResponse::with_status(504);
        }
    }

    // Persist the updated AMBR in the binding
    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut bindings) = ctx.policy_bindings.write() {
            if let Some(b) = bindings.get_mut(sm_context_ref) {
                b.ambr_ul_bps = dec.sess_ambr_ul_bps;
                b.ambr_dl_bps = dec.sess_ambr_dl_bps;
                b.five_qi = dec.def_five_qi;
            }
        }
    }

    SbiResponse::with_status(204)
}

/// Handle SM Policy Termination Notification (from PCF, TS 29.512 §4.2.3.3):
/// the PCF requests release of the policy association — the SMF tears the
/// PDU session down (PFCP delete + resource release).
async fn handle_sm_policy_terminate(sm_context_ref: &str) -> SbiResponse {
    log::warn!("SM Policy termination requested by PCF for ref={sm_context_ref}");
    if lookup_policy_binding(sm_context_ref).is_none() {
        return send_not_found(
            &format!("No SM context for ref={sm_context_ref}"),
            Some("CONTEXT_NOT_FOUND"),
        );
    }
    // Re-use the release path (PFCP deletion, IP release, FSM, binding drop).
    // The SM policy delete inside is a no-op risk-wise: the PCF asked for it.
    handle_sm_context_release(sm_context_ref).await;
    SbiResponse::with_status(204)
}

/// Handle N1N2 Transfer Failure (from AMF)
async fn handle_n1n2_transfer_failure(sm_context_ref: &str) -> SbiResponse {
    log::info!("N1N2 transfer failure notification for ref={sm_context_ref}");
    SbiResponse::with_status(204)
}

/// Handle AMF Status Change Notification
async fn handle_amf_status_change(sm_context_ref: &str) -> SbiResponse {
    log::info!("AMF status change notification for ref={sm_context_ref}");
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
        assert!(config.nrf_uri.is_none());
    }

    #[test]
    fn test_load_config_extracts_sbi_and_nrf_in_one_parse() {
        use std::io::Write;
        let yaml = "smf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        \
                    port: 8888\n    client:\n      nrf:\n        - uri: http://nrf.example:7777\n";
        let path = std::env::temp_dir().join(format!("smf-cfg-test-{}.yaml", std::process::id()));
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(yaml.as_bytes()))
            .expect("write temp config");

        let config = load_config(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);

        assert_eq!(config.sbi_addr, "127.0.0.1");
        assert_eq!(config.sbi_port, 8888);
        // NRF URI now comes from the single load_config parse (no second read).
        assert_eq!(config.nrf_uri.as_deref(), Some("http://nrf.example:7777"));
    }

    // ------------------------------------------------------------------
    // N2 SM transfer cross-codec guards (W5 PDU-session data-plane)
    // ------------------------------------------------------------------
    //
    // The smfd builds the N2 SM PDUSessionResourceSetupRequestTransfer with the
    // real-APER ogs-ngap codec and decodes the gNB's SetupResponseTransfer with
    // it. These pin the wire bytes against the independent nextgsim-ngap codec
    // (the gNB), mirroring the W5 NG-Setup/ICS reconciliation: the request
    // bytes are byte-identical to the gNB's decoder vector, and the gNB's
    // response bytes decode here.

    /// smfd's emitted SetupRequestTransfer for UPF F-TEID 0x00010001 /
    /// 10.45.0.1 / QFI 1 / 5QI 9 / ARP 8 — must equal the vector the gNB
    /// (nextgsim-ngap) decodes (capture_tests.rs::SMFD_SETUP_REQUEST_TRANSFER).
    const GNB_EXPECTED_SETUP_REQUEST: [u8; 32] = [
        0x00, 0x03, 0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x0a, 0x2d, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x86, 0x00, 0x01, 0x00, 0x00, 0x88, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x09,
        0x1c, 0x00,
    ];

    #[test]
    fn setup_request_transfer_matches_gnb_wire_bytes() {
        let bytes = build_setup_request_transfer(0x0001_0001, [10, 45, 0, 1], 1, 9, 8).unwrap();
        assert_eq!(
            bytes,
            GNB_EXPECTED_SETUP_REQUEST.to_vec(),
            "smfd SetupRequestTransfer must be byte-identical to the gNB decoder vector"
        );
    }

    #[test]
    fn setup_request_transfer_self_roundtrips() {
        use ogs_ngap::transfer::{
            PduSessionResourceSetupRequestTransfer, UpTransportLayerInformation,
        };
        let bytes = build_setup_request_transfer(0x0001_0001, [10, 45, 0, 1], 1, 9, 8).unwrap();
        let t = PduSessionResourceSetupRequestTransfer::decode(&bytes).expect("decode");
        let UpTransportLayerInformation::GtpTunnel(tun) = &t.ul_ngu_up_tnl_information;
        assert_eq!(u32::from_be_bytes(tun.gtp_teid), 0x0001_0001);
        assert_eq!(tun.transport_layer_address.octets, vec![10, 45, 0, 1]);
        assert_eq!(t.qos_flow_setup_request_list.len(), 1);
        assert_eq!(t.qos_flow_setup_request_list[0].qos_flow_identifier, 1);
    }

    /// The gNB (nextgsim-ngap) produces this SetupResponseTransfer for gNB DL
    /// F-TEID 0x00020002 / 10.46.0.1 / QFI 1 (pinned in the gNB test
    /// capture_tests.rs::gnb_setup_response_transfer_roundtrips). smfd must
    /// decode it to extract the gNB DL F-TEID for the PFCP DL FAR.
    const GNB_SETUP_RESPONSE_TRANSFER: [u8; 13] = [
        0x00, 0x03, 0xe0, 0x0a, 0x2e, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01,
    ];

    #[test]
    fn gnb_setup_response_transfer_decodes_in_smfd() {
        let (teid, addr, qfi) =
            decode_setup_response_dl_endpoint(&GNB_SETUP_RESPONSE_TRANSFER).expect("smfd decodes");
        assert_eq!(teid, 0x0002_0002);
        assert_eq!(addr, [10, 46, 0, 1]);
        assert_eq!(qfi, 1);
    }
}
