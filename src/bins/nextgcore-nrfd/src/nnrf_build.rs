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

/// RFC 6902-style change item for NF_PROFILE_CHANGED notifications
/// (TS 29.510 §5.2.2.6 — each applied PatchItem is relayed to subscribers)
#[derive(Debug, Clone)]
pub struct ChangeItem {
    /// Operation: "add", "remove", "replace", "move", "copy"
    pub op: String,
    /// JSON Pointer path (RFC 6901)
    pub path: String,
    /// New value (for "add" / "replace")
    pub value: Option<serde_json::Value>,
    /// Original value before the operation (for "replace" / "remove" —
    /// TS 29.510 extension on top of RFC 6902)
    pub orig_value: Option<serde_json::Value>,
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
    /// RFC 6902-style change items (NF_PROFILE_CHANGED only, TS 29.510 §5.2.2.6)
    pub profile_changes: Option<Vec<ChangeItem>>,
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
    build_nf_status_notify_inner(subscription_data, event, nf_instance, server_uri, None)
}

/// Build an NF_PROFILE_CHANGED notification carrying the RFC 6902-style
/// `profileChanges` list derived from the applied PATCH (TS 29.510 §5.2.2.6).
pub fn nrf_nnrf_nfm_build_nf_profile_changed_notify(
    subscription_data: &SubscriptionData,
    nf_instance: &NfProfile,
    server_uri: &str,
    profile_changes: Vec<ChangeItem>,
) -> Option<SbiNotifyRequest> {
    build_nf_status_notify_inner(
        subscription_data,
        NotificationEventType::NfProfileChanged,
        nf_instance,
        server_uri,
        Some(profile_changes),
    )
}

/// Internal builder shared by the public notify-build functions.
fn build_nf_status_notify_inner(
    subscription_data: &SubscriptionData,
    event: NotificationEventType,
    nf_instance: &NfProfile,
    server_uri: &str,
    profile_changes: Option<Vec<ChangeItem>>,
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
        profile_changes,
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

    // RFC 6902-style profileChanges (NF_PROFILE_CHANGED, TS 29.510 §5.2.2.6)
    if let Some(ref changes) = data.profile_changes {
        if !changes.is_empty() {
            json.push_str(",\"profileChanges\":");
            json.push_str(&build_profile_changes_json(changes));
        }
    }

    json.push('}');

    Some(json)
}

/// Serialize a slice of `ChangeItem` to the `profileChanges` JSON array.
fn build_profile_changes_json(changes: &[ChangeItem]) -> String {
    let items: Vec<String> = changes
        .iter()
        .map(|c| {
            let mut obj = format!("{{\"op\":\"{}\",\"path\":\"{}\"", c.op, c.path);
            if let Some(ref v) = c.value {
                if let Ok(s) = serde_json::to_string(v) {
                    obj.push_str(&format!(",\"newValue\":{s}"));
                }
            }
            if let Some(ref v) = c.orig_value {
                if let Ok(s) = serde_json::to_string(v) {
                    obj.push_str(&format!(",\"origValue\":{s}"));
                }
            }
            obj.push('}');
            obj
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build NF profile JSON
fn build_nf_profile_json(profile: &NfProfile) -> Option<String> {
    // Profiles registered through the SBI path carry the full NFProfile
    // document — notify subscribers with every attribute, not a summary.
    if profile.attributes.is_object() {
        return Some(profile.to_json().to_string());
    }

    let mut json = String::from("{");

    // Required fields
    json.push_str(&format!("\"nfInstanceId\":\"{}\",", profile.nf_instance_id));
    json.push_str(&format!("\"nfType\":\"{}\",", profile.nf_type));
    json.push_str(&format!("\"nfStatus\":\"{}\"", profile.nf_status));

    // Optional heartbeat timer
    if let Some(heartbeat) = profile.heartbeat_timer {
        json.push_str(&format!(",\"heartBeatTimer\":{heartbeat}"));
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
            .map(|a| format!("\"{a}\""))
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
            .map(|a| format!("\"{a}\""))
            .collect();
        json.push_str(&addrs.join(","));
        json.push(']');
    }

    // FQDN
    if let Some(ref fqdn) = profile.fqdn {
        json.push_str(&format!(",\"fqdn\":\"{fqdn}\""));
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
            fqdn: Some("amf.example.com".to_string()),
            ..Default::default()
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
            profile_changes: None,
        };

        let json = build_notification_json(&data);
        assert!(json.is_some());
        let json = json.unwrap();

        assert!(json.contains("\"event\":\"NF_REGISTERED\""));
        assert!(
            json.contains("\"nfInstanceUri\":\"http://nrf.example.com/nf-instances/test-nf-123\"")
        );
        assert!(json.contains("\"nfProfile\":{"));
    }

    // ------------------------------------------------------------------
    // nrfd-02: NF_PROFILE_CHANGED notification builder
    // ------------------------------------------------------------------

    #[test]
    fn test_build_profile_changes_json_replace() {
        let changes = vec![ChangeItem {
            op: "replace".to_string(),
            path: "/load".to_string(),
            value: Some(serde_json::json!(75)),
            orig_value: Some(serde_json::json!(50)),
        }];
        let json = build_profile_changes_json(&changes);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let item = &parsed[0];
        assert_eq!(item["op"], "replace");
        assert_eq!(item["path"], "/load");
        assert_eq!(item["newValue"], 75);
        assert_eq!(item["origValue"], 50);
    }

    #[test]
    fn test_build_profile_changes_json_add_remove() {
        let changes = vec![
            ChangeItem {
                op: "add".to_string(),
                path: "/priority".to_string(),
                value: Some(serde_json::json!(1)),
                orig_value: None,
            },
            ChangeItem {
                op: "remove".to_string(),
                path: "/fqdn".to_string(),
                value: None,
                orig_value: Some(serde_json::json!("amf.example.com")),
            },
        ];
        let json = build_profile_changes_json(&changes);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["op"], "add");
        assert_eq!(parsed[0]["newValue"], 1);
        assert!(parsed[0].get("origValue").is_none());
        assert_eq!(parsed[1]["op"], "remove");
        assert_eq!(parsed[1]["origValue"], "amf.example.com");
        assert!(parsed[1].get("newValue").is_none());
    }

    #[test]
    fn test_build_nf_profile_changed_notify_includes_profile_changes() {
        let subscription = create_test_subscription();
        let profile = create_test_profile();
        let changes = vec![ChangeItem {
            op: "replace".to_string(),
            path: "/load".to_string(),
            value: Some(serde_json::json!(80)),
            orig_value: Some(serde_json::json!(40)),
        }];

        let request = nrf_nnrf_nfm_build_nf_profile_changed_notify(
            &subscription,
            &profile,
            "http://nrf.example.com",
            changes,
        );

        assert!(request.is_some());
        let request = request.unwrap();
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();

        assert_eq!(body["event"], "NF_PROFILE_CHANGED");
        assert!(body["nfProfile"].is_object(), "nfProfile must be present");
        let pc = body["profileChanges"]
            .as_array()
            .expect("profileChanges array");
        assert_eq!(pc.len(), 1);
        assert_eq!(pc[0]["op"], "replace");
        assert_eq!(pc[0]["path"], "/load");
        assert_eq!(pc[0]["newValue"], 80);
        assert_eq!(pc[0]["origValue"], 40);
    }

    #[test]
    fn test_build_nf_profile_changed_notify_empty_changes_omits_field() {
        // profileChanges omitted (not serialized as empty array) when none exist.
        let subscription = create_test_subscription();
        let profile = create_test_profile();

        let request = nrf_nnrf_nfm_build_nf_profile_changed_notify(
            &subscription,
            &profile,
            "http://nrf.example.com",
            vec![],
        );

        let body: serde_json::Value = serde_json::from_str(&request.unwrap().body).unwrap();
        assert_eq!(body["event"], "NF_PROFILE_CHANGED");
        assert!(
            body.get("profileChanges").is_none(),
            "empty changes must not serialize profileChanges"
        );
    }

    #[test]
    fn test_build_notification_json_with_profile_changes() {
        let profile = create_test_profile();
        let data = NotificationData {
            event: NotificationEventType::NfProfileChanged,
            nf_instance_uri: "http://nrf.example.com/nf-instances/test-nf-123".to_string(),
            nf_profile: Some(profile),
            profile_changes: Some(vec![ChangeItem {
                op: "replace".to_string(),
                path: "/nfStatus".to_string(),
                value: Some(serde_json::json!("REGISTERED")),
                orig_value: Some(serde_json::json!("SUSPENDED")),
            }]),
        };

        let json = build_notification_json(&data).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["event"], "NF_PROFILE_CHANGED");
        let pc = parsed["profileChanges"].as_array().unwrap();
        assert_eq!(pc[0]["newValue"], "REGISTERED");
        assert_eq!(pc[0]["origValue"], "SUSPENDED");
    }
}
