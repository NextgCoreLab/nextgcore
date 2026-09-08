//! BSF NRF Handler
//!
//! Port of src/bsf/nnrf-handler.c - Handler for NRF status notifications.
//!
//! ## Removed in #234: the consumer-side NF-discovery path
//!
//! `bsf_nnrf_handle_nf_discover` and the three types that only fed it
//! (`SearchResult`, `NfInstanceInfo`, `SbiXactContext`) are gone, together with
//! the two tests that were its only callers — and which passed *because* the stub
//! they reached fabricated `Ok(1)`. See the removal note in
//! [`crate::sbi_path`] for the evidence that ruled out wiring it instead: bsfd's
//! `nnrf-nfm` obligations are already complete, TS 29.521 gives the BSF no
//! originated service request for binding management, and the handler hardcoded
//! `GET /nbsf-management/v1/pcf-bindings` — it would have had the BSF query its
//! own service on another NF.
//!
//! What remains is [`handle_nf_status_notify`], which is a different thing: an
//! inbound status-notify observer, not an outbound discovery client. It has no
//! non-test caller either — `bsf_sm.rs:176` mentions the C original in a comment
//! but does not call it — so it is a latent hook rather than live code. It was
//! left in place because #234 scopes itself to the discovery path, and because
//! withdrawing an inbound observer is a different decision from deleting an
//! outbound client that could not work.

/// Handle NF status notify
pub fn handle_nf_status_notify(nf_instance_id: &str, nf_status: &str) -> Result<(), String> {
    log::debug!("NF status notify: nf_instance_id={nf_instance_id}, status={nf_status}");

    match nf_status {
        "REGISTERED" => {
            log::info!("NF instance [{nf_instance_id}] registered");
        }
        "DEREGISTERED" => {
            log::info!("NF instance [{nf_instance_id}] deregistered");
        }
        "SUSPENDED" => {
            log::warn!("NF instance [{nf_instance_id}] suspended");
        }
        _ => {
            log::warn!("Unknown NF status [{nf_status}] for instance [{nf_instance_id}]");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_nf_status_notify() {
        let result = handle_nf_status_notify("nf-001", "REGISTERED");
        assert!(result.is_ok());

        let result = handle_nf_status_notify("nf-001", "DEREGISTERED");
        assert!(result.is_ok());

        let result = handle_nf_status_notify("nf-001", "SUSPENDED");
        assert!(result.is_ok());
    }
}
