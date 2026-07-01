//! Remaining EES service API data models — eesd-13.
//!
//! Implements five `eees-*` service APIs that have no 5GC NEF/PCF-AF
//! dependency and can be validated entirely with unit tests:
//!
//! * `eees-cea` (TS 29.558 §5.14): Common EAS Announcement — EAS announces
//!   its capability/availability to EECs via the EES broker.
//! * `eees-appclientinformation` (TS 29.558 §5.5): Application Client
//!   Information — EAS provides information about its app clients.
//! * `eees-acrmgntevent` (TS 29.558 §5.8): ACR Management Event subscriptions
//!   — EECs subscribe to be notified about ACR lifecycle events.
//! * `eees-eeccontextreloc` (TS 29.558 §5.10): EEC Context Relocation —
//!   request to relocate an EEC's context between EES instances.
//! * `eees-acr-param` (TS 29.558 §5.13): ACR Parameter Information — EAS
//!   requests the ACR parameters the EES holds for a given EEC/EAS pair.
//!
//! DEFERRED (eesd-13 subset requiring 5GC NEF/PCF-AF exposure path):
//! * `eees-session-with-qos` (TS 29.558 §5.6) — needs Nnef_TrafficInfluence
//!   to a live NEF; no NEF exposure path exists in this repo.
//! * `eees-tie` (TS 29.558 §5.15) — Traffic Influence EAS; same NEF/PCF-AF
//!   dependency; blocked until Nnef/Npcf AF exposure is wired.

use serde::{Deserialize, Serialize};

// ============================================================================
// eees-cea — Common EAS Announcement (TS 29.558 §5.14)
// ============================================================================

/// `CeaAnnouncement` — body of `CreateCeaAnnouncement`
/// (`POST .../eees-cea/v1/announcements`) and stored resource.
///
/// Mandatory IE: `easId`. The server mints an `announcementId` on creation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CeaAnnouncement {
    /// EAS identifier (mandatory; consumer-provided).
    pub eas_id: String,
    /// Server-minted announcement resource identifier (read-only on creation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_id: Option<String>,
    /// EAS profile embedded in the announcement (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_prof: Option<crate::types::EasProfile>,
    /// Announcement expiration time (RFC 3339; absent ⇒ never expires).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional, TS 29.558 §7.8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ============================================================================
// eees-appclientinformation — Application Client Information (TS 29.558 §5.5)
// ============================================================================

/// `AppClientInfo` — body of `ProvideAppClientInfo`
/// (`POST .../eees-appclientinformation/v1/app-client-infos`) and stored
/// resource.
///
/// Mandatory IE: `acId`. The server mints an `acInfoId` on creation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppClientInfo {
    /// Application Client identifier (mandatory; consumer-provided, immutable).
    pub ac_id: String,
    /// Server-minted resource identifier (read-only; populated on creation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_info_id: Option<String>,
    /// EAS application identifiers this AC connects to (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ids: Option<Vec<String>>,
    /// AC type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_type: Option<String>,
    /// Resource expiration time (RFC 3339; absent ⇒ never expires).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ============================================================================
// eees-acrmgntevent — ACR Management Event subscriptions (TS 29.558 §5.8)
// ============================================================================

/// ACR management event types (TS 29.558 §5.8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcrMgntEvent {
    /// ACR procedure completed successfully.
    AcrCompleted,
    /// ACR procedure failed.
    AcrFailed,
    /// ACR procedure initiated.
    AcrInitiated,
    /// EAS relocated to a new serving area.
    EasRelocated,
}

/// `AcrMgntEventSubsc` — body of `CreateAcrMgntEventSubsc`
/// (`POST .../eees-acrmgntevent/v1/subscriptions`) and stored resource.
///
/// Mandatory IE: `notificationUri`. The server mints a `subscriptionId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrMgntEventSubsc {
    /// Callback URI for ACR management event notifications (mandatory).
    pub notification_uri: String,
    /// Server-minted subscription resource identifier (read-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// EEC identifier filter (optional; absent ⇒ all EECs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_id: Option<String>,
    /// EAS identifier filter (optional; absent ⇒ all EASes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_id: Option<String>,
    /// Event types to subscribe to (optional; absent ⇒ all events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_events: Option<Vec<AcrMgntEvent>>,
    /// Subscription expiration time (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ============================================================================
// eees-eeccontextreloc — EEC Context Relocation (TS 29.558 §5.10)
// ============================================================================

/// Outcome of an EEC context relocation operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelocResult {
    /// Context relocation completed successfully.
    Success,
    /// Context relocation failed.
    Failure,
}

/// `EecCtxtRelReq` — body of `RequestEECContextRelocation`
/// (`POST .../eees-eeccontextreloc/v1/request-relocation`).
///
/// Mandatory IEs: `eecId`, `srcEesId`, `tgtEesId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EecCtxtRelReq {
    /// EEC identifier (mandatory).
    pub eec_id: String,
    /// Source EES identifier (mandatory; current EES serving the EEC).
    pub src_ees_id: String,
    /// Target EES identifier (mandatory; EES the EEC is relocating to).
    pub tgt_ees_id: String,
    /// UE identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `EecCtxtRelResp` — response to `RequestEECContextRelocation`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EecCtxtRelResp {
    /// EEC identifier (echoed).
    pub eec_id: String,
    /// Relocation outcome.
    pub reloc_result: RelocResult,
    /// Supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ============================================================================
// eees-acr-param — ACR Parameter Information (TS 29.558 §5.13)
// ============================================================================

/// `AcrParamInfoReq` — body of `RequestAcrParamInfo`
/// (`POST .../eees-acr-param/v1/request-acr-params`).
///
/// Mandatory IEs: `eecId`, `sEasId`. The EES looks up any stored ACR state
/// for the `(eecId, sEasId)` pair and returns the parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrParamInfoReq {
    /// EEC identifier (mandatory).
    pub eec_id: String,
    /// Source EAS identifier (mandatory).
    pub s_eas_id: String,
    /// UE identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `AcrParamInfoResp` — response to `RequestAcrParamInfo`.
///
/// `acrParams` is absent when no prior ACR state exists for the given pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrParamInfoResp {
    /// ACR relocation identity from a prior Determine/Initiate (absent if none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_params: Option<crate::acr::AcrRelocationInfo>,
    /// Supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CeaAnnouncement ----------------------------------------------------

    /// Minimal body (mandatory `easId`) round-trips with camelCase fields.
    #[test]
    fn test_cea_announcement_roundtrip_minimal() {
        let body = r#"{"easId":"eas1.example.com"}"#;
        let ann: CeaAnnouncement = serde_json::from_str(body).expect("deserializes");
        assert_eq!(ann.eas_id, "eas1.example.com");
        assert!(ann.announcement_id.is_none());
        let back = serde_json::to_string(&ann).unwrap();
        assert!(back.contains(r#""easId":"eas1.example.com""#));
        assert!(!back.contains("announcementId"));
    }

    /// Missing mandatory `easId` fails to deserialize → handler maps to 400.
    #[test]
    fn test_cea_announcement_missing_eas_id_fails() {
        assert!(
            serde_json::from_str::<CeaAnnouncement>(r#"{"expTime":"2030-01-01T00:00:00Z"}"#)
                .is_err()
        );
    }

    /// Full round-trip including `announcementId` (server-populated in response).
    #[test]
    fn test_cea_announcement_with_id_roundtrip() {
        let ann = CeaAnnouncement {
            eas_id: "eas-cea.example.com".into(),
            announcement_id: Some("ann-uuid-1".into()),
            eas_prof: None,
            exp_time: Some("2030-01-01T00:00:00Z".into()),
            supp_feat: Some("1".into()),
        };
        let json = serde_json::to_string(&ann).unwrap();
        assert!(json.contains(r#""announcementId":"ann-uuid-1""#));
        assert!(json.contains(r#""expTime""#));
        let back: CeaAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ann);
    }

    // ---- AppClientInfo ------------------------------------------------------

    /// Minimal body (mandatory `acId`) round-trips.
    #[test]
    fn test_app_client_info_roundtrip_minimal() {
        let body = r#"{"acId":"ac1"}"#;
        let info: AppClientInfo = serde_json::from_str(body).expect("deserializes");
        assert_eq!(info.ac_id, "ac1");
        assert!(info.ac_info_id.is_none());
        let back = serde_json::to_string(&info).unwrap();
        assert!(back.contains(r#""acId":"ac1""#));
    }

    /// Missing mandatory `acId` fails to deserialize.
    #[test]
    fn test_app_client_info_missing_ac_id_fails() {
        assert!(serde_json::from_str::<AppClientInfo>(r#"{"easIds":["eas1"]}"#).is_err());
    }

    /// Full round-trip with `acInfoId` and optional fields.
    #[test]
    fn test_app_client_info_full_roundtrip() {
        let info = AppClientInfo {
            ac_id: "ac1".into(),
            ac_info_id: Some("acinfo-uuid-1".into()),
            eas_ids: Some(vec!["eas1".into(), "eas2".into()]),
            ac_type: Some("V2X".into()),
            exp_time: None,
            supp_feat: Some("1".into()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains(r#""acInfoId":"acinfo-uuid-1""#));
        assert!(json.contains(r#""easIds""#));
        assert!(json.contains(r#""acType":"V2X""#));
        let back: AppClientInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
    }

    // ---- AcrMgntEventSubsc --------------------------------------------------

    /// Mandatory `notificationUri` round-trips; missing it fails.
    #[test]
    fn test_acr_mgnt_event_subsc_roundtrip() {
        let body =
            r#"{"notificationUri":"http://eec/cb","acrEvents":["ACR_COMPLETED","EAS_RELOCATED"]}"#;
        let sub: AcrMgntEventSubsc = serde_json::from_str(body).expect("deserializes");
        assert_eq!(sub.notification_uri, "http://eec/cb");
        let events = sub.acr_events.unwrap();
        assert!(events.contains(&AcrMgntEvent::AcrCompleted));
        assert!(events.contains(&AcrMgntEvent::EasRelocated));
        assert!(sub.subscription_id.is_none());
    }

    #[test]
    fn test_acr_mgnt_event_subsc_missing_uri_fails() {
        assert!(serde_json::from_str::<AcrMgntEventSubsc>(r#"{"eecId":"eec1"}"#).is_err());
    }

    /// `AcrMgntEvent` enum serializes as SCREAMING_SNAKE_CASE.
    #[test]
    fn test_acr_mgnt_event_serialization() {
        assert_eq!(
            serde_json::to_string(&AcrMgntEvent::AcrCompleted).unwrap(),
            r#""ACR_COMPLETED""#
        );
        assert_eq!(
            serde_json::to_string(&AcrMgntEvent::AcrFailed).unwrap(),
            r#""ACR_FAILED""#
        );
        assert_eq!(
            serde_json::to_string(&AcrMgntEvent::AcrInitiated).unwrap(),
            r#""ACR_INITIATED""#
        );
        assert_eq!(
            serde_json::to_string(&AcrMgntEvent::EasRelocated).unwrap(),
            r#""EAS_RELOCATED""#
        );
    }

    // ---- EecCtxtRelReq / EecCtxtRelResp -------------------------------------

    /// Mandatory three-ID body round-trips.
    #[test]
    fn test_eec_ctxt_rel_req_roundtrip() {
        let body = r#"{"eecId":"eec1","srcEesId":"ees-src","tgtEesId":"ees-tgt"}"#;
        let req: EecCtxtRelReq = serde_json::from_str(body).expect("deserializes");
        assert_eq!(req.eec_id, "eec1");
        assert_eq!(req.src_ees_id, "ees-src");
        assert_eq!(req.tgt_ees_id, "ees-tgt");
        assert!(req.ue_id.is_none());
    }

    /// Missing `srcEesId` fails.
    #[test]
    fn test_eec_ctxt_rel_req_missing_src_ees_id_fails() {
        assert!(
            serde_json::from_str::<EecCtxtRelReq>(r#"{"eecId":"eec1","tgtEesId":"ees-tgt"}"#)
                .is_err()
        );
    }

    /// `EecCtxtRelResp` serializes `relocResult` as SCREAMING_SNAKE_CASE.
    #[test]
    fn test_eec_ctxt_rel_resp_roundtrip() {
        let resp = EecCtxtRelResp {
            eec_id: "eec1".into(),
            reloc_result: RelocResult::Success,
            supp_feat: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""relocResult":"SUCCESS""#));
        assert!(json.contains(r#""eecId":"eec1""#));
        let back: EecCtxtRelResp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }

    /// `RelocResult` enum round-trips.
    #[test]
    fn test_reloc_result_serialization() {
        assert_eq!(
            serde_json::to_string(&RelocResult::Success).unwrap(),
            r#""SUCCESS""#
        );
        assert_eq!(
            serde_json::to_string(&RelocResult::Failure).unwrap(),
            r#""FAILURE""#
        );
        let s: RelocResult = serde_json::from_str(r#""SUCCESS""#).unwrap();
        assert_eq!(s, RelocResult::Success);
    }

    // ---- AcrParamInfoReq / AcrParamInfoResp ---------------------------------

    /// Mandatory `eecId` + `sEasId` round-trips.
    #[test]
    fn test_acr_param_info_req_roundtrip() {
        let body = r#"{"eecId":"eec1","sEasId":"eas-s.example.com"}"#;
        let req: AcrParamInfoReq = serde_json::from_str(body).expect("deserializes");
        assert_eq!(req.eec_id, "eec1");
        assert_eq!(req.s_eas_id, "eas-s.example.com");
        assert!(req.ue_id.is_none());
    }

    /// Missing `sEasId` fails to deserialize.
    #[test]
    fn test_acr_param_info_req_missing_s_eas_id_fails() {
        assert!(serde_json::from_str::<AcrParamInfoReq>(r#"{"eecId":"eec1"}"#).is_err());
    }

    /// `AcrParamInfoResp` with absent `acrParams` serializes without the field.
    #[test]
    fn test_acr_param_info_resp_absent_params() {
        let resp = AcrParamInfoResp::default();
        let json = serde_json::to_string(&resp).unwrap();
        // When both fields are absent the body is just `{}`
        assert!(!json.contains("acrParams"));
        let back: AcrParamInfoResp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }

    /// `AcrParamInfoResp` with an `acrParams` value round-trips.
    #[test]
    fn test_acr_param_info_resp_with_params() {
        let resp = AcrParamInfoResp {
            acr_params: Some(crate::acr::AcrRelocationInfo {
                s_eas_id: Some("eas-s".into()),
                t_eas_id: Some("eas-t".into()),
                s_eas_endpoint: None,
                t_eas_endpoint: None,
            }),
            supp_feat: Some("1".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""acrParams""#));
        assert!(json.contains(r#""sEasId":"eas-s""#));
        let back: AcrParamInfoResp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }
}
