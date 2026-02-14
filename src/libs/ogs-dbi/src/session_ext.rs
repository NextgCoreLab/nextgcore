//! Extended session management functions

use crate::mongoc::DbiResult;

/// Enumerate active PDU sessions for a subscriber
pub fn ogs_dbi_active_sessions(supi: &str) -> DbiResult<Vec<crate::types::OgsSession>> {
    let subscription_data = crate::subscription::ogs_dbi_subscription_data(supi)?;
    let mut sessions = Vec::new();
    for slice in &subscription_data.slice {
        for session in &slice.session {
            sessions.push(session.clone());
        }
    }
    Ok(sessions)
}

/// Modify QoS for a session
pub fn ogs_dbi_session_modify(_supi: &str, _session_name: &str, _new_qos: &crate::types::OgsQos) -> DbiResult<()> {
    // Stub: would update MongoDB session QoS parameters
    Ok(())
}
