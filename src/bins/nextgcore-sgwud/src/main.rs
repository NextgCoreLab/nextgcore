//! NextGCore SGWU (Serving Gateway User Plane)
//!
//! Port of src/sgwu - SGWU context, state machines, and event handling

pub mod context;
pub mod event;
pub mod gtp_path;
pub mod pfcp_path;
pub mod pfcp_sm;
pub mod sm;
pub mod sxa_build;
pub mod sxa_handler;
pub mod timer;

use anyhow::Result;

/// Where the Prometheus endpoint listens (`SGWU_METRICS_PORT`, default 9090 — the
/// port every other daemon in this tree uses for it).
fn metrics_addr() -> std::net::SocketAddr {
    let port: u16 = std::env::var("SGWU_METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9090);
    std::net::SocketAddr::from(([0, 0, 0, 0], port))
}

/// Render the SGW-U's runtime state in Prometheus text format (issue #59).
///
/// Deliberately small and honest: the session count and the associated-peer count are
/// the two numbers that distinguish a working SGW-U from a broken one, and both come
/// from live state rather than from a counter this function increments.
fn render_metrics() -> String {
    let sessions = context::sgwu_self().sess_count();
    let associated = pfcp_path::sxa_node()
        .map(|n| n.associated_peer_count())
        .unwrap_or(0);
    format!(
        "# HELP sgwu_pfcp_sessions Number of PFCP sessions held on Sxa\n\
         # TYPE sgwu_pfcp_sessions gauge\n\
         sgwu_pfcp_sessions {sessions}\n\
         # HELP sgwu_pfcp_associations Number of associated SGW-C peers\n\
         # TYPE sgwu_pfcp_associations gauge\n\
         sgwu_pfcp_associations {associated}\n\
         # HELP sgwu_up 1 when the SGW-U runtime is serving\n\
         # TYPE sgwu_up gauge\n\
         sgwu_up 1\n"
    )
}

/// Resolve when the process is asked to stop: SIGTERM (how a container stops one) or
/// Ctrl-C. Before #59 neither existed, because `main` had already returned.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Cannot listen for SIGTERM ({e}); Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => log::info!("SIGTERM received"),
            _ = tokio::signal::ctrl_c() => log::info!("SIGINT received"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();
    log::info!("NextGCore SGWU starting...");

    // Initialize context
    context::sgwu_context_init(1024);

    // Initialize GTP-U subsystem
    if let Err(e) = gtp_path::gtp_init() {
        log::error!("Failed to initialize GTP-U: {e}");
        return Err(anyhow::anyhow!("GTP-U init failed"));
    }

    // Create and initialize state machine
    let mut sgwu_sm = sm::SgwuStateMachine::new();
    sgwu_sm.init();

    // Dispatch entry event to transition to operational state
    let entry_event = event::SgwuEvent::entry();
    let result = sgwu_sm.dispatch(&entry_event);
    log::info!("SGWU state machine result: {result:?}");

    // Open the Sxa PFCP socket (issue #59: this used to bind nothing)
    let pfcp = match pfcp_path::pfcp_open().await {
        Ok(node) => node,
        Err(e) => {
            log::error!("Failed to open PFCP socket: {e}");
            return Err(anyhow::anyhow!("PFCP open failed: {e}"));
        }
    };

    // Open GTP-U server sockets
    if let Err(e) = gtp_path::gtp_open() {
        log::error!("Failed to open GTP-U sockets: {e}");
        return Err(anyhow::anyhow!("GTP-U open failed"));
    }

    // The runtime (issue #59). `main` used to fall straight through from here to the
    // cleanup block and return Ok(()), so the process exited 0 on startup -- and
    // because docker-compose-epc.yml probed it with `kill -0 1` and restarted only
    // `on-failure`, a clean exit was reported as healthy. Everything below is what
    // makes the daemon a daemon: a receive loop, heartbeat-driven peer-failure
    // detection, a metrics endpoint, and a shutdown that waits to be asked.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(pfcp.clone().run(shutdown_rx.clone()));
    let heartbeats = tokio::spawn(pfcp.clone().heartbeat_monitor(shutdown_rx));
    match nextgcore_metrics::nes_energy::serve_metrics(
        metrics_addr(),
        std::sync::Arc::new(render_metrics),
    )
    .await
    {
        Ok((bound, _handle)) => log::info!("SGWU metrics endpoint on http://{bound}/metrics"),
        // Non-fatal: an SGW-U that cannot expose metrics still carries traffic, and
        // refusing to start would turn a busy port into a user-plane outage.
        Err(e) => log::warn!("SGWU metrics endpoint not available: {e}"),
    }

    log::info!(
        "NextGCore SGWU initialized successfully (PFCP/Sxa on {})",
        pfcp.local_addr()
    );

    shutdown_signal().await;
    log::info!("NextGCore SGWU shutting down...");
    let _ = shutdown_tx.send(true);
    // Await the tasks so a session removed during teardown is not raced by a
    // datagram still being processed.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), heartbeats).await;

    // Cleanup
    gtp_path::gtp_close();
    pfcp_path::pfcp_close().await;
    gtp_path::gtp_final();
    context::sgwu_context_final();
    sgwu_sm.fini();

    log::info!("NextGCore SGWU shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgwu_initialization() {
        // Test context initialization
        let ctx = context::SgwuContext::new();
        assert!(!ctx.is_initialized());

        // Test state machine initialization
        let mut sm = sm::SgwuStateMachine::new();
        assert!(sm.is_initial());

        sm.dispatch(&event::SgwuEvent::entry());
        assert!(sm.is_operational());
    }

    #[test]
    fn test_sgwu_session_lifecycle() {
        let ctx = context::SgwuContext::new();

        // Add session
        let f_seid = context::FSeid::with_ipv4(0x1234, std::net::Ipv4Addr::new(10, 0, 0, 1));
        let sess = ctx.sess_add(&f_seid).unwrap();
        assert_eq!(ctx.sess_count(), 1);

        // Find session
        let found = ctx.sess_find_by_sgwc_sxa_seid(0x1234).unwrap();
        assert_eq!(found.id, sess.id);

        // Remove session
        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_pfcp_state_machine() {
        let mut pfcp_sm = pfcp_sm::PfcpStateMachine::new(1);
        assert!(pfcp_sm.is_initial());

        // Transition to will_associate
        pfcp_sm.dispatch(&event::SgwuEvent::entry());
        assert!(pfcp_sm.is_will_associate());

        // Simulate association
        let assoc_event = event::SgwuEvent::sxa_message(
            1,
            1,
            vec![pfcp_sm::pfcp_message_type::ASSOCIATION_SETUP_RESPONSE],
        );
        pfcp_sm.dispatch(&assoc_event);
        assert!(pfcp_sm.is_associated());
    }

    #[test]
    fn test_sxa_build_session_establishment_response() {
        let sess = context::SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: context::FSeid::with_ipv4(
                0x2000,
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            ),
            ..Default::default()
        };

        let msg = sxa_build::build_session_establishment_response(&sess, &[]).unwrap();
        assert_eq!(
            msg.msg_type,
            sxa_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE
        );
        assert_eq!(msg.seid, 0x2000);
    }

    #[test]
    fn test_sxa_handler_session_establishment() {
        let sess = context::SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: context::FSeid::with_ipv4(
                0x2000,
                std::net::Ipv4Addr::new(10, 0, 0, 1),
            ),
            ..Default::default()
        };

        let req = sxa_handler::SessionEstablishmentRequest::default();
        let (result, _) = sxa_handler::handle_session_establishment_request(Some(&sess), 1, &req);
        assert!(matches!(result, sxa_handler::HandlerResult::Ok));
    }

    #[test]
    fn test_gtp_path_init() {
        assert!(gtp_path::gtp_init().is_ok());
        gtp_path::gtp_final();
    }

    /// #59: `pfcp_open` binds a real socket, so the test asks for an ephemeral one
    /// rather than fighting a live SGW-U for UDP/8805.
    #[tokio::test]
    async fn test_pfcp_path_open_close() {
        std::env::set_var("PFCP_BIND_ADDR", "127.0.0.1:0");
        let node = pfcp_path::pfcp_open().await.expect("bind");
        assert_ne!(node.local_addr().port(), 0, "a real socket was bound");
        pfcp_path::pfcp_close().await;
        std::env::remove_var("PFCP_BIND_ADDR");
    }

    /// #59 criterion 6: the metrics endpoint renders live state, in Prometheus text
    /// format. Asserted on the rendered body rather than on the endpoint binding,
    /// because a body that reports nothing is the failure worth catching.
    #[test]
    fn the_metrics_render_reports_sessions_and_associations() {
        context::sgwu_context_init(1024);
        let body = render_metrics();
        for expected in [
            "# TYPE sgwu_pfcp_sessions gauge",
            "sgwu_pfcp_sessions ",
            "sgwu_pfcp_associations ",
            "sgwu_up 1",
        ] {
            assert!(body.contains(expected), "missing {expected} in:\n{body}");
        }
    }

    #[test]
    fn test_gtpu_server_open_close() {
        // Bind to an ephemeral loopback port so tests never collide with a
        // live GTP-U endpoint on 2152
        let server = gtp_path::GtpuServer::open("127.0.0.1:0", 2152).unwrap();
        assert_ne!(server.local_addr().port(), 0);
        server.close();
    }
}
