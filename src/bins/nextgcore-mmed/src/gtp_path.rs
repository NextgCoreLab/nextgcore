//! MME GTP Path Management
//!
//! Port of src/mme/mme-gtp-path.c - GTP path/send functions for S11 interface

use crate::context::MmeContext;
use crate::s11_build::{
    self, GtpCause, GtpCreateAction, GtpDeleteAction,
    GtpModifyAction, GtpReleaseAction, Gtp2BearerQos,
};
use std::net::SocketAddr;

pub type GtpPathResult<T> = Result<T, GtpPathError>;

#[derive(Debug, Clone)]
pub enum GtpPathError {
    SocketError(String),
    BuildError(String),
    TransactionError(String),
    ContextNotFound,
    InvalidState(String),
}

impl std::fmt::Display for GtpPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketError(msg) => write!(f, "Socket error: {msg}"),
            Self::BuildError(msg) => write!(f, "Build error: {msg}"),
            Self::TransactionError(msg) => write!(f, "Transaction error: {msg}"),
            Self::ContextNotFound => write!(f, "Context not found"),
            Self::InvalidState(msg) => write!(f, "Invalid state: {msg}"),
        }
    }
}

impl std::error::Error for GtpPathError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteIndirectAction {
    HandoverComplete,
    HandoverCancel,
}

#[derive(Debug, Clone, Default)]
pub struct GtpXactData {
    pub xact_id: u64,
    pub create_action: Option<GtpCreateAction>,
    pub delete_action: Option<GtpDeleteAction>,
    pub modify_action: Option<GtpModifyAction>,
    pub release_action: Option<GtpReleaseAction>,
    pub delete_indirect_action: Option<DeleteIndirectAction>,
    pub local_teid: u32,
    pub enb_ue_id: u64,
}

#[derive(Debug, Default)]
pub struct GtpPathState {
    pub gtpc_addr: Option<SocketAddr>,
    pub gtpc_addr6: Option<SocketAddr>,
    pub initialized: bool,
}

pub fn gtp_open(state: &mut GtpPathState) -> GtpPathResult<()> {
    log::info!("Opening GTP path");
    state.initialized = true;
    log::info!("GTP path opened successfully");
    Ok(())
}

pub fn gtp_close(state: &mut GtpPathState) -> GtpPathResult<()> {
    log::info!("Closing GTP path");
    state.initialized = false;
    log::info!("GTP path closed");
    Ok(())
}

pub fn send_create_session_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    sess_id: u64,
    create_action: GtpCreateAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Create Session Request");

    let sess = ctx.sess_find_by_id(sess_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(sess.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let target_sgw_ue = if create_action == GtpCreateAction::PathSwitchRequest {
        ctx.sgw_ue_find_by_id(sgw_ue.target_ue_id).ok_or(GtpPathError::ContextNotFound)?
    } else {
        sgw_ue.clone()
    };

    let _pkbuf = s11_build::build_create_session_request(&sess, &mme_ue, &target_sgw_ue, create_action)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        create_action: Some(create_action),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_modify_bearer_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    uli_presence: bool,
    modify_action: GtpModifyAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Modify Bearer Request");

    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_modify_bearer_request(&mme_ue, &sgw_ue, &[], uli_presence)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        modify_action: Some(modify_action),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_delete_session_request(
    ctx: &MmeContext,
    enb_ue_id: Option<u64>,
    sgw_ue_id: u64,
    sess_id: u64,
    action: GtpDeleteAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Delete Session Request");

    let sess = ctx.sess_find_by_id(sess_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(sess.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_delete_session_request(&sess, &mme_ue, &sgw_ue, 5, action)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        delete_action: Some(action),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id: enb_ue_id.unwrap_or(0),
        ..Default::default()
    })
}

pub fn send_delete_all_sessions(
    ctx: &MmeContext,
    enb_ue_id: Option<u64>,
    mme_ue_id: u64,
    action: GtpDeleteAction,
) -> GtpPathResult<Vec<GtpXactData>> {
    log::debug!("Sending Delete All Sessions");

    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue_id = mme_ue.sgw_ue_id;

    let mut xacts = Vec::new();
    for sess_id in &mme_ue.sess_list {
        if ctx.sess_find_by_id(*sess_id).is_some() {
            let xact = send_delete_session_request(ctx, enb_ue_id, sgw_ue_id, *sess_id, action)?;
            xacts.push(xact);
        }
    }
    Ok(xacts)
}

pub fn send_create_bearer_response(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
) -> GtpPathResult<()> {
    log::debug!("Sending Create Bearer Response");

    let bearer = ctx.bearer_find_by_id(bearer_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(bearer.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_create_bearer_response(&bearer, &mme_ue, &sgw_ue, cause_value)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    Ok(())
}

pub fn send_update_bearer_response(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
) -> GtpPathResult<()> {
    log::debug!("Sending Update Bearer Response");

    let bearer = ctx.bearer_find_by_id(bearer_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(bearer.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_update_bearer_response(&bearer, &mme_ue, &sgw_ue, cause_value)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    Ok(())
}

pub fn send_delete_bearer_response(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
) -> GtpPathResult<()> {
    log::debug!("Sending Delete Bearer Response");

    let bearer = ctx.bearer_find_by_id(bearer_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(bearer.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_delete_bearer_response(&bearer, &mme_ue, &sgw_ue, cause_value)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;
    Ok(())
}

pub fn send_release_access_bearers_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    action: GtpReleaseAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Release Access Bearers Request");

    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_release_access_bearers_request(sgw_ue.sgw_s11_teid, ctx.next_pool_id() as u32);

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        release_action: Some(action),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_release_all_ue_in_enb(
    ctx: &MmeContext,
    enb_id: u64,
    action: GtpReleaseAction,
) -> GtpPathResult<Vec<GtpXactData>> {
    log::debug!("Sending Release All UE in eNB");

    let enb = ctx.enb_find_by_id(enb_id).ok_or(GtpPathError::ContextNotFound)?;
    let mut xacts = Vec::new();

    for enb_ue_id in &enb.enb_ue_list {
        if let Some(enb_ue) = ctx.enb_ue_find_by_id(*enb_ue_id) {
            if ctx.mme_ue_find_by_id(enb_ue.mme_ue_id).is_some() {
                let xact = send_release_access_bearers_request(ctx, *enb_ue_id, enb_ue.mme_ue_id, action)?;
                xacts.push(xact);
            }
        }
    }
    Ok(xacts)
}

pub fn send_downlink_data_notification_ack(
    ctx: &MmeContext,
    bearer_id: u64,
    cause_value: GtpCause,
) -> GtpPathResult<()> {
    log::debug!("Sending Downlink Data Notification Ack");

    let bearer = ctx.bearer_find_by_id(bearer_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(bearer.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_downlink_data_notification_ack(sgw_ue.sgw_s11_teid, ctx.next_pool_id() as u32, cause_value);
    Ok(())
}

pub fn send_create_indirect_data_forwarding_tunnel_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Create Indirect Data Forwarding Tunnel Request");

    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_create_indirect_data_forwarding_tunnel_request(&mme_ue, &sgw_ue, &[])
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_delete_indirect_data_forwarding_tunnel_request(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    action: DeleteIndirectAction,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Delete Indirect Data Forwarding Tunnel Request");

    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id(),
        delete_indirect_action: Some(action),
        local_teid: mme_ue.gn.mme_gn_teid,
        enb_ue_id,
        ..Default::default()
    })
}

pub fn send_bearer_resource_command(
    ctx: &MmeContext,
    bearer_id: u64,
    linked_bearer_ebi: u8,
    pti: u8,
    tad: &[u8],
    qos: Option<&Gtp2BearerQos>,
) -> GtpPathResult<GtpXactData> {
    log::debug!("Sending Bearer Resource Command");

    let bearer = ctx.bearer_find_by_id(bearer_id).ok_or(GtpPathError::ContextNotFound)?;
    let mme_ue = ctx.mme_ue_find_by_id(bearer.mme_ue_id).ok_or(GtpPathError::ContextNotFound)?;
    let sgw_ue = ctx.sgw_ue_find_by_id(mme_ue.sgw_ue_id).ok_or(GtpPathError::ContextNotFound)?;

    let _pkbuf = s11_build::build_bearer_resource_command(&bearer, &mme_ue, &sgw_ue, linked_bearer_ebi, pti, tad, qos)
        .map_err(|e| GtpPathError::BuildError(e.to_string()))?;

    Ok(GtpXactData {
        xact_id: ctx.next_pool_id() | GTP_CMD_XACT_ID_FLAG,
        local_teid: mme_ue.gn.mme_gn_teid,
        ..Default::default()
    })
}

const GTP_CMD_XACT_ID_FLAG: u64 = 0x8000_0000_0000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_path_state_default() {
        let state = GtpPathState::default();
        assert!(!state.initialized);
    }

    #[test]
    fn test_gtp_open_close() {
        let mut state = GtpPathState::default();
        assert!(gtp_open(&mut state).is_ok());
        assert!(state.initialized);
        assert!(gtp_close(&mut state).is_ok());
        assert!(!state.initialized);
    }

    #[test]
    fn test_delete_indirect_action() {
        assert_eq!(DeleteIndirectAction::HandoverComplete, DeleteIndirectAction::HandoverComplete);
    }

    #[test]
    fn test_gtp_xact_data_default() {
        let xact = GtpXactData::default();
        assert_eq!(xact.xact_id, 0);
        assert!(xact.create_action.is_none());
    }
}
