//! NextGCore UPF (User Plane Function)
//!
//! Port of src/upf/ - User Plane Function for 5G/LTE core network
//!
//! The UPF is responsible for:
//! - User plane packet routing and forwarding
//! - QoS handling
//! - Traffic usage reporting
//! - Uplink/downlink traffic detection

pub mod arp_nd;
pub mod context;
pub mod data_plane;
pub mod event;
pub mod gtp_path;
pub mod n4_build;
pub mod n4_handler;
pub mod pfcp_path;
pub mod pfcp_sm;
pub mod rule_match;
pub mod timer;
pub mod upf_sm;

#[cfg(test)]
mod property_tests;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use context::{upf_context_final, upf_context_init, upf_self};
use data_plane::DataPlane;
use event::UpfEvent;
use gtp_path::{upf_gtp_close, upf_gtp_final, upf_gtp_init, upf_gtp_open};
use pfcp_path::{pfcp_close, pfcp_open, PfcpPathContext, PfcpServer, PfcpSessionEvent};
use upf_sm::UpfSmContext;

/// NextGCore UPF - User Plane Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-upfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core User Plane Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/upf.yaml")]
    config: String,

    /// Log file path
    #[arg(short = 'l', long)]
    log_file: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// Kill running instance
    #[arg(short = 'k', long)]
    kill: bool,

    /// PFCP server address
    #[arg(long, default_value = "127.0.0.4")]
    pfcp_addr: String,

    /// PFCP server port
    #[arg(long, default_value = "8805")]
    pfcp_port: u16,

    /// GTP-U address
    #[arg(long, default_value = "127.0.0.4")]
    gtpu_addr: String,

    /// GTP-U port
    #[arg(long, default_value = "2152")]
    gtpu_port: u16,

    /// TUN interface name
    #[arg(long, default_value = "ogstun")]
    tun_ifname: String,

    /// TUN interface IP address
    #[arg(long, default_value = "10.45.0.1")]
    tun_ip: String,

    /// TUN interface prefix length
    #[arg(long, default_value = "16")]
    tun_prefix: u8,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sessions: usize,

    /// Disable data plane (TUN device) - useful for control plane testing
    #[arg(long, default_value = "false")]
    no_dataplane: bool,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore UPF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UPF context
    upf_context_init(args.max_sessions);
    log::info!("UPF context initialized (max_sessions={})", args.max_sessions);

    // Initialize GTP-U path
    upf_gtp_init().map_err(|e| anyhow::anyhow!("Failed to initialize GTP path: {}", e))?;
    log::info!("GTP-U path initialized");

    // Initialize UPF state machine
    let mut upf_sm = UpfSmContext::new();
    upf_sm.init();
    log::info!("UPF state machine initialized");

    // Initialize PFCP path context
    let mut pfcp_ctx = PfcpPathContext::new();

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {}", e);
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Parse PFCP and GTP-U addresses
    let pfcp_addr: SocketAddr = format!("{}:{}", args.pfcp_addr, args.pfcp_port)
        .parse()
        .context("Invalid PFCP address")?;
    let gtpu_addr: SocketAddr = format!("{}:{}", args.gtpu_addr, args.gtpu_port)
        .parse()
        .context("Invalid GTP-U address")?;
    let tun_ip: Ipv4Addr = args.tun_ip.parse()
        .context("Invalid TUN IP address")?;

    // Initialize legacy PFCP path context (for compatibility)
    pfcp_open(&mut pfcp_ctx, pfcp_addr)
        .map_err(|e| anyhow::anyhow!("Failed to open PFCP path: {}", e))?;
    log::info!("PFCP path context initialized on {}", pfcp_addr);

    // Open GTP-U path (control plane)
    upf_gtp_open().map_err(|e| anyhow::anyhow!("Failed to open GTP path: {}", e))?;
    log::info!("GTP-U path opened on {}", gtpu_addr);

    // Initialize data plane (optional based on --no-dataplane flag)
    let mut data_plane = DataPlane::new(shutdown.clone());
    let data_plane_enabled = !args.no_dataplane;

    if data_plane_enabled {
        // Initialize data plane (TUN + GTP-U socket)
        data_plane.init(
            &args.tun_ifname,
            tun_ip,
            args.tun_prefix,
            gtpu_addr,
        ).await.context("Failed to initialize data plane")?;
    } else {
        log::warn!("Data plane disabled (--no-dataplane flag set)");
        log::warn!("UPF running in control plane only mode - no user traffic forwarding");
    }

    // Transition to operational state
    let entry_event = UpfEvent::entry();
    upf_sm.dispatch(&entry_event);

    log::info!("NextGCore UPF ready");

    // Create PFCP session event channel
    let (pfcp_session_tx, mut pfcp_session_rx) = tokio::sync::mpsc::channel::<PfcpSessionEvent>(100);

    // Create async PFCP server
    let pfcp_server = PfcpServer::new(pfcp_addr, shutdown.clone(), pfcp_session_tx)
        .await
        .context("Failed to create PFCP server")?;
    let pfcp_server = Arc::new(pfcp_server);

    // Run data plane (if enabled)
    let data_plane = Arc::new(data_plane);
    let data_plane_handle = if data_plane_enabled {
        log::info!("Starting data plane task...");
        let dp_clone = data_plane.clone();
        Some(tokio::spawn(async move {
            log::info!("Data plane task spawned, calling run()");
            if let Err(e) = dp_clone.run().await {
                log::error!("Data plane error: {}", e);
            }
            log::info!("Data plane task finished");
        }))
    } else {
        None
    };

    // Run PFCP server
    log::info!("Starting PFCP server task...");
    let pfcp_server_clone = pfcp_server.clone();
    let pfcp_server_handle = tokio::spawn(async move {
        log::info!("PFCP server task spawned");
        if let Err(e) = pfcp_server_clone.run().await {
            log::error!("PFCP server error: {}", e);
        }
        log::info!("PFCP server task finished");
    });

    // Run PFCP session event handler (connects PFCP to data plane)
    log::info!("Starting PFCP session event handler...");
    let dp_for_pfcp = data_plane.clone();
    let shutdown_events = shutdown.clone();
    let pfcp_event_handle = tokio::spawn(async move {
        log::info!("PFCP session event handler started");
        while let Some(event) = pfcp_session_rx.recv().await {
            if shutdown_events.load(Ordering::SeqCst) {
                break;
            }
            handle_pfcp_session_event(&dp_for_pfcp, event);
        }
        log::info!("PFCP session event handler finished");
    });

    // Run URR threshold check task (periodic usage report generation)
    log::info!("Starting URR threshold check task...");
    let dp_for_urr = data_plane.clone();
    let shutdown_urr = shutdown.clone();
    let urr_check_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            if shutdown_urr.load(Ordering::SeqCst) {
                break;
            }
            let reports = dp_for_urr.collect_urr_reports();
            for report in &reports {
                log::info!(
                    "URR threshold report: SEID={:#x}, URR_ID={}, total={} bytes ({} UL, {} DL), {} pkts",
                    report.upf_seid, report.urr_id,
                    report.total_bytes, report.ul_bytes, report.dl_bytes, report.total_pkts
                );
                // Note: In production, this would call pfcp_path::send_session_report_request()
                // to send a PFCP Session Report Request to the SMF with the usage report.
                // The PfcpServer would need access to the session's SMF address to send it.
            }
        }
    });

    // Main async event loop (control plane)
    run_async_event_loop(&mut upf_sm, &mut pfcp_ctx, shutdown.clone()).await?;

    // Stop all tasks
    pfcp_server_handle.abort();
    pfcp_event_handle.abort();
    urr_check_handle.abort();

    // Stop data plane (if enabled)
    if let Some(handle) = data_plane_handle {
        handle.abort();
    }

    // Graceful shutdown
    log::info!("Shutting down...");

    // Close GTP-U path
    upf_gtp_close().map_err(|e| anyhow::anyhow!("Failed to close GTP path: {}", e))?;
    log::info!("GTP-U path closed");

    // Close PFCP path
    pfcp_close(&mut pfcp_ctx);
    log::info!("PFCP path closed");

    // Finalize GTP-U
    upf_gtp_final().map_err(|e| anyhow::anyhow!("Failed to finalize GTP path: {}", e))?;
    log::info!("GTP-U path finalized");

    // Cleanup state machine
    upf_sm.fini();
    log::info!("UPF state machine finalized");

    // Cleanup context
    upf_context_final();
    log::info!("UPF context finalized");

    log::info!("NextGCore UPF stopped");
    Ok(())
}

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    let mut builder = env_logger::Builder::new();

    // Set log level
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    builder.filter_level(level);

    // Configure format
    builder.format_timestamp_millis();

    if args.no_color {
        builder.write_style(env_logger::WriteStyle::Never);
    }

    builder.init();

    Ok(())
}

/// Set up signal handlers for graceful shutdown
fn setup_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<()> {
    // Set up Ctrl+C handler
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    Ok(())
}

/// Main async event loop using tokio
async fn run_async_event_loop(
    upf_sm: &mut UpfSmContext,
    pfcp_ctx: &mut PfcpPathContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async event loop");

    // Heartbeat tracking
    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    let mut last_heartbeat_check = std::time::Instant::now();
    let heartbeat_timeout = std::time::Duration::from_secs(60);

    loop {
        tokio::select! {
            // Periodic heartbeat and transaction maintenance
            _ = heartbeat_interval.tick() => {
                if shutdown.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                    break;
                }

                // Check if state machine is still operational
                if !upf_sm.is_operational() && !upf_sm.is_final() {
                    let entry_event = UpfEvent::entry();
                    upf_sm.dispatch(&entry_event);
                }

                // Check for PFCP heartbeat timeout on associated peers
                if last_heartbeat_check.elapsed() > heartbeat_timeout {
                    for (_, node) in pfcp_ctx.peer_nodes.iter() {
                        if node.associated {
                            let addr_bytes = match node.addr.ip() {
                                std::net::IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()) as u64,
                                std::net::IpAddr::V6(_) => 0,
                            };
                            log::warn!("PFCP heartbeat timeout for peer {}", node.addr);
                            let no_hb_event = UpfEvent::n4_no_heartbeat(addr_bytes);
                            upf_sm.dispatch(&no_hb_event);
                        }
                    }
                    last_heartbeat_check = std::time::Instant::now();
                }

                // Process pending PFCP transactions (check for timeouts)
                let stale_seqs: Vec<u32> = pfcp_ctx
                    .transactions
                    .iter()
                    .filter(|(_, xact)| xact.state == pfcp_path::XactState::Pending)
                    .map(|(seq, _)| *seq)
                    .collect();
                for seq in stale_seqs {
                    if let Some(xact) = pfcp_ctx.find_xact(seq) {
                        if xact.state == pfcp_path::XactState::Pending {
                            log::debug!("Cleaning up stale PFCP transaction seq={}", seq);
                            xact.state = pfcp_path::XactState::Timeout;
                        }
                    }
                }
            }

            // Periodic stats reporting and URR threshold checks
            _ = stats_interval.tick() => {
                if shutdown.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                    break;
                }
                update_session_stats().await;
            }
        }
    }

    log::debug!("Exiting async event loop");
    Ok(())
}

/// Update session statistics, check URR thresholds, and trigger usage reports
async fn update_session_stats() {
    let ctx = upf_self();
    let sess_count = ctx.sess_count();
    if sess_count > 0 {
        log::debug!("Active sessions: {}", sess_count);
    }

    // Note: URR threshold reporting is handled in the data plane via
    // DataPlane::collect_urr_reports(). When the PFCP session event handler
    // detects exceeded URR thresholds, it generates Session Report Requests
    // via pfcp_path::send_session_report_request() to notify the SMF.
    // The data plane's 30-second stats interval provides periodic measurement
    // period checks as well.
}

/// Handle PFCP session events (connect PFCP to data plane)
fn handle_pfcp_session_event(data_plane: &DataPlane, event: PfcpSessionEvent) {
    use std::net::IpAddr;
    use data_plane::GTPU_PORT;

    match event {
        PfcpSessionEvent::SessionEstablished {
            upf_seid,
            smf_seid,
            ue_ipv4,
            ul_teid,
            dl_teid,
            gnb_addr,
        } => {
            log::info!(
                "PFCP Session Established: UPF_SEID={:#x}, SMF_SEID={:#x}, UE={:?}, UL_TEID={:#x}, DL_TEID={:#x}",
                upf_seid, smf_seid, ue_ipv4, ul_teid, dl_teid
            );

            if let Some(ue_ip) = ue_ipv4 {
                // Convert gNB IP to SocketAddr
                let gnb_socket = if let Some(addr) = gnb_addr {
                    SocketAddr::new(IpAddr::V4(addr), GTPU_PORT)
                } else {
                    // Default gNB address if not provided
                    log::warn!("No gNB address provided, using default");
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), GTPU_PORT)
                };

                // Add session to data plane with SEID info
                data_plane.add_session_from_pfcp(
                    upf_seid,
                    smf_seid,
                    ue_ip,
                    ul_teid,
                    dl_teid,
                    gnb_socket,
                    None, // PDU session ID (could be extracted from PFCP if available)
                    None, // QFI (could be extracted from PFCP if available)
                );
            } else {
                log::warn!("Session established without UE IP address");
            }
        }

        PfcpSessionEvent::SessionModified {
            upf_seid,
            dl_teid,
            gnb_addr,
        } => {
            log::info!("PFCP Session Modified: UPF_SEID={:#x}", upf_seid);

            // Convert gNB IP to SocketAddr if present
            let gnb_socket = gnb_addr.map(|addr| {
                SocketAddr::new(IpAddr::V4(addr), GTPU_PORT)
            });

            // Update session in data plane by SEID
            if dl_teid.is_some() || gnb_socket.is_some() {
                data_plane.update_session_from_pfcp(upf_seid, dl_teid, gnb_socket);
            }
        }

        PfcpSessionEvent::SessionDeleted { upf_seid, ue_ipv4: _ } => {
            log::info!("PFCP Session Deleted: UPF_SEID={:#x}", upf_seid);
            // Remove session from data plane by SEID
            data_plane.remove_session_from_pfcp(upf_seid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-upfd"]);
        assert_eq!(args.config, "/etc/nextgcore/upf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.pfcp_addr, "127.0.0.4");
        assert_eq!(args.pfcp_port, 8805);
        assert_eq!(args.gtpu_addr, "127.0.0.4");
        assert_eq!(args.gtpu_port, 2152);
        assert_eq!(args.tun_ifname, "ogstun");
        assert_eq!(args.max_sessions, 1024);
        assert!(!args.kill);
        assert!(!args.no_color);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-upfd",
            "-c",
            "/custom/upf.yaml",
            "-e",
            "debug",
            "--pfcp-addr",
            "10.0.0.1",
            "--pfcp-port",
            "8806",
            "--gtpu-addr",
            "10.0.0.2",
            "--gtpu-port",
            "2153",
            "--tun-ifname",
            "mytun",
            "--max-sessions",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/upf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.pfcp_addr, "10.0.0.1");
        assert_eq!(args.pfcp_port, 8806);
        assert_eq!(args.gtpu_addr, "10.0.0.2");
        assert_eq!(args.gtpu_port, 2153);
        assert_eq!(args.tun_ifname, "mytun");
        assert_eq!(args.max_sessions, 2048);
    }

    #[test]
    fn test_args_kill_flag() {
        let args = Args::parse_from(["nextgcore-upfd", "-k"]);
        assert!(args.kill);
    }

    #[test]
    fn test_args_no_color() {
        let args = Args::parse_from(["nextgcore-upfd", "-m"]);
        assert!(args.no_color);
    }

    #[test]
    fn test_args_log_file() {
        let args = Args::parse_from(["nextgcore-upfd", "-l", "/var/log/upf.log"]);
        assert_eq!(args.log_file, Some("/var/log/upf.log".to_string()));
    }
}
