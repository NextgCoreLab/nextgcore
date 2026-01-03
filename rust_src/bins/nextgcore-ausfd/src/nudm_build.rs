//! NUDM UEAU Request Builders
//!
//! Port of src/ausf/nudm-build.c - NUDM UEAU request builders

use crate::context::{ausf_self, AuthResult, AuthType};

/// Resynchronization info for authentication
#[derive(Debug, Clone)]
pub struct ResynchronizationInfo {
    pub rand: String,
    pub auts: String,
}

/// Authentication info request
#[derive(Debug, Clone)]
pub struct AuthenticationInfoRequest {
    pub serving_network_name: String,
    pub ausf_instance_id: String,
    pub resynchronization_info: Option<ResynchronizationInfo>,
}

/// Auth event for result confirmation
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub time_stamp: String,
    pub nf_instance_id: String,
    pub success: bool,
    pub auth_type: AuthType,
    pub serving_network_name: String,
    pub auth_removal_ind: Option<bool>,
}

/// SBI request representation
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub service_name: String,
    pub api_version: String,
    pub resource_components: Vec<String>,
    pub body: Option<String>,
}

/// Build NUDM UEAU get request (POST /{suci}/security-information/generate-auth-data)
///
/// Port of ausf_nudm_ueau_build_get()
pub fn ausf_nudm_ueau_build_get(
    ausf_ue_id: u64,
    resync_info: Option<&ResynchronizationInfo>,
) -> Option<SbiRequest> {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = context.ue_find_by_id(ausf_ue_id)?;

    let serving_network_name = ausf_ue.serving_network_name.as_ref()?;

    // Build AuthenticationInfoRequest
    let auth_info_request = AuthenticationInfoRequest {
        serving_network_name: serving_network_name.clone(),
        ausf_instance_id: get_nf_instance_id(),
        resynchronization_info: resync_info.cloned(),
    };

    // Serialize to JSON
    let body = serde_json::to_string(&auth_info_request_to_json(&auth_info_request)).ok();

    Some(SbiRequest {
        method: "POST".to_string(),
        service_name: "nudm-ueau".to_string(),
        api_version: "v1".to_string(),
        resource_components: vec![
            ausf_ue.suci.clone(),
            "security-information".to_string(),
            "generate-auth-data".to_string(),
        ],
        body,
    })
}

/// Build NUDM UEAU result confirmation inform request (POST /{supi}/auth-events)
///
/// Port of ausf_nudm_ueau_build_result_confirmation_inform()
pub fn ausf_nudm_ueau_build_result_confirmation_inform(ausf_ue_id: u64) -> Option<SbiRequest> {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = context.ue_find_by_id(ausf_ue_id)?;
    let supi = ausf_ue.supi.as_ref()?;
    let serving_network_name = ausf_ue.serving_network_name.as_ref()?;

    // Build AuthEvent
    let auth_event = AuthEvent {
        time_stamp: get_current_timestamp(),
        nf_instance_id: get_nf_instance_id(),
        success: ausf_ue.auth_result == AuthResult::AuthenticationSuccess,
        auth_type: ausf_ue.auth_type,
        serving_network_name: serving_network_name.clone(),
        auth_removal_ind: None,
    };

    // Serialize to JSON
    let body = serde_json::to_string(&auth_event_to_json(&auth_event)).ok();

    Some(SbiRequest {
        method: "POST".to_string(),
        service_name: "nudm-ueau".to_string(),
        api_version: "v1".to_string(),
        resource_components: vec![supi.clone(), "auth-events".to_string()],
        body,
    })
}

/// Build NUDM UEAU auth removal indication request (PUT /{supi}/auth-events)
///
/// Port of ausf_nudm_ueau_build_auth_removal_ind()
pub fn ausf_nudm_ueau_build_auth_removal_ind(ausf_ue_id: u64) -> Option<SbiRequest> {
    let ctx = ausf_self();
    let context = ctx.read().unwrap();

    let ausf_ue = context.ue_find_by_id(ausf_ue_id)?;
    let supi = ausf_ue.supi.as_ref()?;
    let serving_network_name = ausf_ue.serving_network_name.as_ref()?;

    // Build AuthEvent with auth_removal_ind = true
    let auth_event = AuthEvent {
        time_stamp: get_current_timestamp(),
        nf_instance_id: get_nf_instance_id(),
        success: true,
        auth_type: ausf_ue.auth_type,
        serving_network_name: serving_network_name.clone(),
        auth_removal_ind: Some(true),
    };

    // Serialize to JSON
    let body = serde_json::to_string(&auth_event_to_json(&auth_event)).ok();

    Some(SbiRequest {
        method: "PUT".to_string(),
        service_name: "nudm-ueau".to_string(),
        api_version: "v1".to_string(),
        resource_components: vec![supi.clone(), "auth-events".to_string()],
        body,
    })
}

/// Get current timestamp in ISO 8601 format
fn get_current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Format as ISO 8601
    let secs = duration.as_secs();
    let datetime = chrono_lite_format(secs);
    datetime
}

/// Simple ISO 8601 timestamp formatter (without chrono dependency)
fn chrono_lite_format(secs: u64) -> String {
    // Calculate date/time components from Unix timestamp
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Calculate year, month, day (simplified - doesn't handle leap years perfectly)
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get NF instance ID (placeholder)
fn get_nf_instance_id() -> String {
    // TODO: Get from SBI context
    "ausf-instance-id".to_string()
}

/// Convert AuthenticationInfoRequest to JSON value
fn auth_info_request_to_json(
    req: &AuthenticationInfoRequest,
) -> serde_json::Value {
    let mut json = serde_json::json!({
        "servingNetworkName": req.serving_network_name,
        "ausfInstanceId": req.ausf_instance_id,
    });

    if let Some(ref resync) = req.resynchronization_info {
        json["resynchronizationInfo"] = serde_json::json!({
            "rand": resync.rand,
            "auts": resync.auts,
        });
    }

    json
}

/// Convert AuthEvent to JSON value
fn auth_event_to_json(event: &AuthEvent) -> serde_json::Value {
    let auth_type_str = match event.auth_type {
        AuthType::FiveGAka => "5G_AKA",
        AuthType::EapAkaPrime => "EAP_AKA_PRIME",
        AuthType::EapTls => "EAP_TLS",
    };

    let mut json = serde_json::json!({
        "timeStamp": event.time_stamp,
        "nfInstanceId": event.nf_instance_id,
        "success": event.success,
        "authType": auth_type_str,
        "servingNetworkName": event.serving_network_name,
    });

    if let Some(auth_removal_ind) = event.auth_removal_ind {
        json["authRemovalInd"] = serde_json::json!(auth_removal_ind);
    }

    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_timestamp() {
        let ts = get_current_timestamp();
        // Should be in ISO 8601 format
        assert!(ts.contains("T"));
        assert!(ts.ends_with("Z"));
    }

    #[test]
    fn test_chrono_lite_format() {
        // Test Unix epoch
        assert_eq!(chrono_lite_format(0), "1970-01-01T00:00:00Z");

        // Test a known timestamp (2024-01-01 00:00:00 UTC)
        let ts_2024 = 1704067200;
        assert_eq!(chrono_lite_format(ts_2024), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(!is_leap_year(1970));
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2024));
    }

    #[test]
    fn test_auth_info_request_to_json() {
        let req = AuthenticationInfoRequest {
            serving_network_name: "5G:mnc001.mcc001.3gppnetwork.org".to_string(),
            ausf_instance_id: "test-ausf".to_string(),
            resynchronization_info: None,
        };

        let json = auth_info_request_to_json(&req);
        assert_eq!(
            json["servingNetworkName"],
            "5G:mnc001.mcc001.3gppnetwork.org"
        );
        assert_eq!(json["ausfInstanceId"], "test-ausf");
    }

    #[test]
    fn test_auth_info_request_with_resync() {
        let req = AuthenticationInfoRequest {
            serving_network_name: "5G:mnc001.mcc001.3gppnetwork.org".to_string(),
            ausf_instance_id: "test-ausf".to_string(),
            resynchronization_info: Some(ResynchronizationInfo {
                rand: "0123456789abcdef0123456789abcdef".to_string(),
                auts: "fedcba9876543210fedcba9876543210".to_string(),
            }),
        };

        let json = auth_info_request_to_json(&req);
        assert!(json["resynchronizationInfo"].is_object());
        assert_eq!(
            json["resynchronizationInfo"]["rand"],
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_auth_event_to_json() {
        let event = AuthEvent {
            time_stamp: "2024-01-01T00:00:00Z".to_string(),
            nf_instance_id: "test-ausf".to_string(),
            success: true,
            auth_type: AuthType::FiveGAka,
            serving_network_name: "5G:mnc001.mcc001.3gppnetwork.org".to_string(),
            auth_removal_ind: None,
        };

        let json = auth_event_to_json(&event);
        assert_eq!(json["success"], true);
        assert_eq!(json["authType"], "5G_AKA");
    }

    #[test]
    fn test_auth_event_with_removal_ind() {
        let event = AuthEvent {
            time_stamp: "2024-01-01T00:00:00Z".to_string(),
            nf_instance_id: "test-ausf".to_string(),
            success: true,
            auth_type: AuthType::FiveGAka,
            serving_network_name: "5G:mnc001.mcc001.3gppnetwork.org".to_string(),
            auth_removal_ind: Some(true),
        };

        let json = auth_event_to_json(&event);
        assert_eq!(json["authRemovalInd"], true);
    }
}
