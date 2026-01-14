//! NRF Message Building
//!
//! Port of src/nrf/nnrf-build.c - Build NF status notify messages

use crate::nnrf_handler::{NfProfile, SubscriptionData};

/// Notification event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationEventType {
    /// NF registered
    NfRegistered,
    /// NF deregistered
    NfDeregistered,
    /// NF profile changed
    NfProfileChanged,
}

impl NotificationEventType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationEventType::NfRegistered => "NF_REGISTERED",
            NotificationEventType::NfDeregistered => "NF_DEREGISTERED",
            NotificationEventType::NfProfileChanged => "NF_PROFILE_CHANGED",
        }
    }
}

/// Notification data for NF status notify
#[derive(Debug, Clone)]
pub struct NotificationData {
    /// Event type
    pub event: NotificationEventType,
    /// NF instance URI
    pub nf_instance_uri: String,
    /// NF profile (optional, not included for deregistration)
    pub nf_profile: Option<NfProfile>,
}

/// SBI request for notification
#[derive(Debug, Clone)]
pub struct SbiNotifyRequest {
    /// HTTP method
    pub method: String,
    /// URI
    pub uri: String,
    /// Content type
    pub content_type: String,
    /// Accept header
    pub accept: String,
    /// Callback header
    pub callback: String,
    /// Body (JSON)
    pub body: String,
}

/// Build NF status notify request
pub fn nrf_nnrf_nfm_build_nf_status_notify(
    subscription_data: &SubscriptionData,
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
) -> Option<SbiNotifyRequest> {
    // Build NF instance URI
    let nf_instance_uri = format!(
        "{}/nnrf-nfm/v1/nf-instances/{}",
        server_uri, nf_instance.nf_instance_id
    );

    // Build notification data
    let notification_data = NotificationData {
        event,
        nf_instance_uri: nf_instance_uri.clone(),
        nf_profile: if event != NotificationEventType::NfDeregistered {
            Some(nf_instance.clone())
        } else {
            None
        },
    };

    // Serialize to JSON
    let body = build_notification_json(&notification_data)?;

    Some(SbiNotifyRequest {
        method: "POST".to_string(),
        uri: subscription_data.notification_uri.clone(),
        content_type: "application/json".to_string(),
        accept: "application/problem+json".to_string(),
        callback: "Nnrf_NFManagement_NFStatusNotify".to_string(),
        body,
    })
}

/// Build notification JSON body
fn build_notification_json(data: &NotificationData) -> Option<String> {
    let mut json = String::from("{");

    // Event
    json.push_str(&format!("\"event\":\"{}\",", data.event.as_str()));

    // NF instance URI
    json.push_str(&format!("\"nfInstanceUri\":\"{}\"", data.nf_instance_uri));

    // NF profile (if present)
    if let Some(ref profile) = data.nf_profile {
        json.push_str(",\"nfProfile\":");
        json.push_str(&build_nf_profile_json(profile)?);
    }

    json.push('}');

    Some(json)
}

/// Build NF profile JSON
fn build_nf_profile_json(profile: &NfProfile) -> Option<String> {
    let mut json = String::from("{");

    // Required fields
    json.push_str(&format!(
        "\"nfInstanceId\":\"{}\",",
        profile.nf_instance_id
    ));
    json.push_str(&format!("\"nfType\":\"{}\",", profile.nf_type));
    json.push_str(&format!("\"nfStatus\":\"{}\"", profile.nf_status));

    // Optional heartbeat timer
    if let Some(heartbeat) = profile.heartbeat_timer {
        json.push_str(&format!(",\"heartBeatTimer\":{}", heartbeat));
    }

    // PLMN list
    if !profile.plmn_list.is_empty() {
        json.push_str(",\"plmnList\":[");
        let plmns: Vec<String> = profile
            .plmn_list
            .iter()
            .map(|p| format!("{{\"mcc\":\"{}\",\"mnc\":\"{}\"}}", p.mcc, p.mnc))
            .collect();
        json.push_str(&plmns.join(","));
        json.push(']');
    }

    // IPv4 addresses
    if !profile.ipv4_addresses.is_empty() {
        json.push_str(",\"ipv4Addresses\":[");
        let addrs: Vec<String> = profile
            .ipv4_addresses
            .iter()
            .map(|a| format!("\"{}\"", a))
            .collect();
        json.push_str(&addrs.join(","));
        json.push(']');
    }

    // IPv6 addresses
    if !profile.ipv6_addresses.is_empty() {
        json.push_str(",\"ipv6Addresses\":[");
        let addrs: Vec<String> = profile
            .ipv6_addresses
            .iter()
            .map(|a| format!("\"{}\"", a))
            .collect();
        json.push_str(&addrs.join(","));
        json.push(']');
    }

    // FQDN
    if let Some(ref fqdn) = profile.fqdn {
        json.push_str(&format!(",\"fqdn\":\"{}\"", fqdn));
    }

    json.push('}');

    Some(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nnrf_handler::PlmnId;

    fn create_test_profile() -> NfProfile {
        NfProfile {
            nf_instance_id: "test-nf-123".to_string(),
            nf_type: "AMF".to_string(),
            nf_status: "REGISTERED".to_string(),
            heartbeat_timer: Some(10),
            plmn_list: vec![PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            }],
            ipv4_addresses: vec!["192.168.1.1".to_string()],
            ipv6_addresses: vec![],
            fqdn: Some("amf.example.com".to_string()),
            nf_services: vec![],
        }
    }

    fn create_test_subscription() -> SubscriptionData {
        SubscriptionData {
            id: "sub-123".to_string(),
            req_nf_type: Some("SMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://smf.example.com/notify".to_string(),
            subscr_cond: None,
            validity_duration: 3600,
        }
    }

    #[test]
    fn test_notification_event_type_as_str() {
        assert_eq!(
            NotificationEventType::NfRegistered.as_str(),
            "NF_REGISTERED"
        );
        assert_eq!(
            NotificationEventType::NfDeregistered.as_str(),
            "NF_DEREGISTERED"
        );
        assert_eq!(
            NotificationEventType::NfProfileChanged.as_str(),
            "NF_PROFILE_CHANGED"
        );
    }

    #[test]
    fn test_build_nf_status_notify_registered() {
        let subscription = create_test_subscription();
        let profile = create_test_profile();

        let request = nrf_nnrf_nfm_build_nf_status_notify(
            &subscription,
            NotificationEventType::NfRegistered,
            &profile,
            "http://nrf.example.com",
        );

        assert!(request.is_some());
        let request = request.unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "http://smf.example.com/notify");
        assert_eq!(request.content_type, "application/json");
        assert!(request.body.contains("NF_REGISTERED"));
        assert!(request.body.contains("test-nf-123"));
        assert!(request.body.contains("nfProfile"));
    }

    #[test]
    fn test_build_nf_status_notify_deregistered() {
        let subscription = create_test_subscription();
        let profile = create_test_profile();

        let request = nrf_nnrf_nfm_build_nf_status_notify(
            &subscription,
            NotificationEventType::NfDeregistered,
            &profile,
            "http://nrf.example.com",
        );

        assert!(request.is_some());
        let request = request.unwrap();

        assert!(request.body.contains("NF_DEREGISTERED"));
        // Deregistered should not include nfProfile
        assert!(!request.body.contains("nfProfile"));
    }

    #[test]
    fn test_build_nf_profile_json() {
        let profile = create_test_profile();
        let json = build_nf_profile_json(&profile);

        assert!(json.is_some());
        let json = json.unwrap();

        assert!(json.contains("\"nfInstanceId\":\"test-nf-123\""));
        assert!(json.contains("\"nfType\":\"AMF\""));
        assert!(json.contains("\"nfStatus\":\"REGISTERED\""));
        assert!(json.contains("\"heartBeatTimer\":10"));
        assert!(json.contains("\"mcc\":\"001\""));
        assert!(json.contains("\"mnc\":\"01\""));
        assert!(json.contains("\"192.168.1.1\""));
        assert!(json.contains("\"fqdn\":\"amf.example.com\""));
    }

    #[test]
    fn test_build_notification_json() {
        let profile = create_test_profile();
        let data = NotificationData {
            event: NotificationEventType::NfRegistered,
            nf_instance_uri: "http://nrf.example.com/nf-instances/test-nf-123".to_string(),
            nf_profile: Some(profile),
        };

        let json = build_notification_json(&data);
        assert!(json.is_some());
        let json = json.unwrap();

        assert!(json.contains("\"event\":\"NF_REGISTERED\""));
        assert!(json.contains("\"nfInstanceUri\":\"http://nrf.example.com/nf-instances/test-nf-123\""));
        assert!(json.contains("\"nfProfile\":{"));
    }
}
