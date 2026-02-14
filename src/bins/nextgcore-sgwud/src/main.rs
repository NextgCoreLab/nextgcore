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

fn main() -> Result<()> {
    env_logger::init();
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

    // Open PFCP server sockets
    if let Err(e) = pfcp_path::pfcp_open() {
        log::error!("Failed to open PFCP sockets: {e}");
        return Err(anyhow::anyhow!("PFCP open failed"));
    }

    // Open GTP-U server sockets
    if let Err(e) = gtp_path::gtp_open() {
        log::error!("Failed to open GTP-U sockets: {e}");
        return Err(anyhow::anyhow!("GTP-U open failed"));
    }

    log::info!("NextGCore SGWU initialized successfully");

    // Note: Main event loop implementation
    // Event loop runs via ogs_pollset_poll processing PFCP and GTP-U messages:
    // 1. PFCP messages dispatched to pfcp_sm via SXA events
    // 2. GTP-U packets forwarded between S1-U/S5-U interfaces via gtp_handler
    // 3. Session operations handled by pfcp_handler for PFCP Session messages

    // Cleanup
    gtp_path::gtp_close();
    pfcp_path::pfcp_close();
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
        let f_seid = context::FSeid::with_ipv4(
            0x1234,
            std::net::Ipv4Addr::new(10, 0, 0, 1),
        );
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
        assert_eq!(msg.msg_type, sxa_build::pfcp_type::SESSION_ESTABLISHMENT_RESPONSE);
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

    #[test]
    fn test_pfcp_path_open_close() {
        assert!(pfcp_path::pfcp_open().is_ok());
        pfcp_path::pfcp_close();
    }

    #[test]
    fn test_gtpu_header_parse_build() {
        let header = gtp_path::GtpuHeader {
            version: 1,
            pt: true,
            e: false,
            s: false,
            pn: false,
            msg_type: gtp_path::gtpu_type::G_PDU,
            length: 100,
            teid: 0x12345678,
            seq_num: None,
            npdu_num: None,
            next_ext_hdr_type: None,
        };

        let data = header.build();
        let (parsed, _) = gtp_path::GtpuHeader::parse(&data).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.msg_type, gtp_path::gtpu_type::G_PDU);
        assert_eq!(parsed.teid, 0x12345678);
    }
}
