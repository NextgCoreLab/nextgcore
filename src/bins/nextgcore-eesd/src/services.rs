//! Remaining EES service API data models — eesd-13.
//!
//! Implements five `eees-*` service APIs that have no 5GC NEF/PCF-AF
//! dependency and can be validated entirely with unit tests:
//!
//! * `eees-cea` (TS 29.558 §5.14): Common EAS Announcement — EAS announces
//!   its capability/availability to EECs via the EES broker.
//! * `eees-appclientinformation` (TS 29.558 §8.4): AC Information
//!   subscriptions — an EAS subscribes for reports about Application Clients.
//!   Models are spec-exact per `TS29558_Eees_AppClientInformation.yaml`
//!   ([`ACInfoSubscription`], [`ACFilters`], [`ACInfoNotification`]).
//! * `eees-acrmgntevent` (TS 29.558 §5.8): ACR Management Event subscriptions
//!   — EECs subscribe to be notified about ACR lifecycle events.
//! * `eees-eeccontextreloc` (TS 29.558 §8.7.2): EEC Contexts — an EES pushes
//!   ([`EECContextPush`]) / pulls ([`EECContext`]) EEC context information.
//!   Models are spec-exact per `TS29558_Eees_EECContextRelocation.yaml`.
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
// eees-appclientinformation — AC Information subscriptions (TS 29.558 §8.4,
// TS29558_Eees_AppClientInformation.yaml)
// ============================================================================

/// `ACInfoSubscription` (TS29558_Eees_AppClientInformation.yaml:317-353) —
/// body of `CreateAppClientInfoSubscription`
/// (`POST .../eees-appclientinformation/v1/subscriptions`), of the PUT
/// full-replace, and of every 200/201 response.
///
/// The ONLY mandatory field is `easId` (yaml:352-353). The spec body carries
/// no resource identifier: the server-minted `subscriptionId` is the store key
/// and is returned via the `Location` header only, never in the wire body.
///
/// Cross-spec leaf types (`ReportingInformation` from TS 29.523,
/// `WebsockNotifConfig` from TS 29.122) are carried as passthrough JSON
/// values, per the established `acr.rs` convention (preserve wire bytes
/// without fabricating a local model).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACInfoSubscription {
    /// Identifier of the EAS subscribing for AC information report
    /// (yaml:321-323; the sole REQUIRED field).
    pub eas_id: String,
    /// Filters to retrieve the information about specific ACs
    /// (yaml:324-329, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_fltrs: Option<Vec<ACFilters>>,
    /// Subscription expiration time (`DateTime`, yaml:330-331).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// TS 29.523 `ReportingInformation` (yaml:332-333; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_req: Option<serde_json::Value>,
    /// Callback URI for AC information notifications (`Uri`, yaml:334-335;
    /// optional in the schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_destination: Option<String>,
    /// Set to true to request a test notification (yaml:336-340).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_test_notification: Option<bool>,
    /// TS 29.122 `WebsockNotifConfig` (yaml:341-342; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websock_notif_config: Option<serde_json::Value>,
    /// Supported features (yaml:343-344).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
    /// Notification triggering conditions (yaml:345-351, minItems 1;
    /// `TrigCondParams` anyOf-enum modelled as an open string, yaml:485-507).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trig_cond_params: Option<Vec<String>>,
}

/// Top-level members of `ACInfoSubscriptionPatch`
/// (TS29558_Eees_AppClientInformation.yaml:355-377) — the ONLY fields a
/// `PATCH` (`application/merge-patch+json`) may modify. The RFC 7396 merge is
/// restricted to these keys; anything else in the patch document (including
/// the immutable `easId`) is ignored.
pub const ACINFO_PATCHABLE_FIELDS: [&str; 5] = [
    "acFltrs",
    "expTime",
    "eventReq",
    "notificationDestination",
    "trigCondParams",
];

/// `ACFilters` (TS29558_Eees_AppClientInformation.yaml:379-419) — filters for
/// an AC Information Subscription. Cross-spec leaves (`ServiceArea`,
/// `ACServiceKPIs`, `ScheduledCommunicationTime`, `LocationArea5G`,
/// `EASBdlInd`) are passthrough JSON values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ACFilters {
    /// AC types (yaml:383-387).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_types_list: Option<Vec<String>>,
    /// Edge computing service provider identifiers (yaml:388-392).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecsp_ids_list: Option<Vec<String>>,
    /// AC identifiers (yaml:393-397).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_ids_list: Option<Vec<String>>,
    /// TS 29.558 `ServiceArea` (yaml:398-399; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svc_area: Option<serde_json::Value>,
    /// Maximum `ACServiceKPIs` (yaml:400-401; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ac_kpi: Option<serde_json::Value>,
    /// Minimum `ACServiceKPIs` (yaml:402-403; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ac_kpi: Option<serde_json::Value>,
    /// EAS operation schedules (`ScheduledCommunicationTime`, yaml:404-409).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_schds: Option<Vec<serde_json::Value>>,
    /// UE identifiers (Gpsi) hosting the AC (yaml:410-415).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_ids: Option<Vec<String>>,
    /// `LocationArea5G` (yaml:416-417; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loc_infs: Option<serde_json::Value>,
    /// `EASBdlInd` (yaml:418-419; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_bund_ind: Option<serde_json::Value>,
}

/// `ACInfoNotification` (TS29558_Eees_AppClientInformation.yaml:421-437) —
/// the callback body POSTed to `notificationDestination`. Required: `subId`,
/// `acInfs` (minItems 1). Consumed by the shared notification sender (D6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACInfoNotification {
    /// Identifier of the AC information subscription (yaml:425-428; REQUIRED).
    pub sub_id: String,
    /// ACs information matching the filter criteria (yaml:429-434; REQUIRED).
    pub ac_infs: Vec<ACInformation>,
}

/// `ACInformation` (TS29558_Eees_AppClientInformation.yaml:439-458) — AC
/// information matching the filter criteria. Required: `acProfs` (minItems 1;
/// TS 24.558 `ACProfile` passthrough).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACInformation {
    /// List of profile information of ACs (yaml:443-448; REQUIRED).
    pub ac_profs: Vec<serde_json::Value>,
    /// List of UE identifiers (Gpsi) hosting the AC (yaml:449-454).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_ids: Option<Vec<String>>,
    /// `LocationArea5G` (yaml:455-456; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_loc_infs: Option<serde_json::Value>,
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
// eees-eeccontextreloc — EEC Contexts (TS 29.558 §8.7.2,
// TS29558_Eees_EECContextRelocation.yaml)
// ============================================================================

/// `EECContextPush` (TS29558_Eees_EECContextRelocation.yaml:179-203) — body
/// of `PushEecContexts` (`POST .../eees-eeccontextreloc/v1/eec-contexts`).
///
/// Required: `eesId` and `eecCntx` (yaml:201-203). Success is 200
/// ([`EECContextPushRes`]) or 204 — there is NO created sub-resource and NO
/// `Location` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EECContextPush {
    /// Identifier of the entity pushing the EEC context (yaml:183-185; REQUIRED).
    pub ees_id: String,
    /// The EEC context being pushed (yaml:186-187; REQUIRED).
    pub eec_cntx: EECContext,
    /// Target EAS endpoint (`EndPoint`, yaml:188-189).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgt_eas: Option<crate::types::EndPoint>,
    /// True when the EEC requests ACR-scenario selection (yaml:190-195).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_scenarios_sel_req: Option<bool>,
    /// Additional EEC contexts (yaml:196-200, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_cntxs: Option<Vec<EECContext>>,
}

/// `EECContextPushRes` (TS29558_Eees_EECContextRelocation.yaml:205-215) —
/// 200-response body of `PushEecContexts`. Emitted ONLY when there is real
/// content (a minted implicit registration or a selected ACR-scenario list);
/// an empty object is never sent (the EES answers 204 instead).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EECContextPushRes {
    /// EEC implicit registration details (yaml:209-210).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impl_reg: Option<ImplicitRegDetails>,
    /// Selected ACR scenarios (`ACRScenario` open-enum strings, yaml:211-215).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sel_acr_scenarios_list: Option<Vec<String>>,
}

/// `ImplicitRegDetails` (TS29558_Eees_EECContextRelocation.yaml:217-227).
/// Required: `regId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImplicitRegDetails {
    /// Identifier of the EEC registration (yaml:221-223; REQUIRED).
    pub reg_id: String,
    /// Registration expiration time (`DateTime`, yaml:224-225).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
}

/// `EECContext` (TS29558_Eees_EECContextRelocation.yaml:229-267) — the EEC
/// context information, keyed by `cntxId` (the `eec-cntx-id` pull query key).
///
/// Required: `eecId` AND `cntxId` (yaml:265-267). Cross-spec leaves
/// (`LocationArea5G`, `ACProfile`) are passthrough JSON values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EECContext {
    /// Unique identifier of the EEC (yaml:233-235; REQUIRED).
    pub eec_id: String,
    /// Unique identifier assigned to the EEC context (yaml:236-238; REQUIRED).
    pub cntx_id: String,
    /// UE identifier (Gpsi, yaml:239-240).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Capability-exposure subscription IDs for the EEC ID (yaml:241-246).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e1_subs: Option<Vec<String>>,
    /// UE location (`LocationArea5G`, yaml:247-248; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_loc: Option<serde_json::Value>,
    /// AC profiles (TS 24.558 `ACProfile`, yaml:249-254; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_profs: Option<Vec<serde_json::Value>>,
    /// Service session contexts (yaml:255-256).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sess_cntxs: Option<SessionContexts>,
    /// EEC service continuity support details (yaml:257-258).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_srv_cont_supp: Option<EECSrvContinuitySupport>,
    /// True when UE mobility support is required (yaml:259-264).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_mob_supp_ind: Option<bool>,
}

/// `SessionContexts` (TS29558_Eees_EECContextRelocation.yaml:140-151).
/// Required: `sessCntxs` (minItems 1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionContexts {
    /// List of service session contexts information (yaml:144-149; REQUIRED).
    pub sess_cntxs: Vec<IndividualSessionContext>,
}

/// `IndividualSessionContext` (TS29558_Eees_EECContextRelocation.yaml:153-177).
/// Required: `easId`, `endPt`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IndividualSessionContext {
    /// Identifier of the Application Server (yaml:157-159; REQUIRED).
    pub eas_id: String,
    /// EAS endpoint (`EndPoint`, yaml:160-161; REQUIRED).
    pub end_pt: crate::types::EndPoint,
    /// Identifier of the AC (yaml:162-164).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Selected ACR scenarios (`ACRScenario` open-enum strings, yaml:165-170).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_list: Option<Vec<String>>,
    /// EEC identifier (yaml:171-172).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_id: Option<String>,
    /// Application group identifier (yaml:173-174).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_grp_id: Option<String>,
}

/// `EECSrvContinuitySupport` (TS29558_Eees_EECContextRelocation.yaml:269-285).
/// Required: `srvContSupp`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EECSrvContinuitySupport {
    /// True when the EEC supports service continuity (yaml:273-277; REQUIRED).
    pub srv_cont_supp: bool,
    /// ACR scenarios supported by the EEC (`ACRScenario` open-enum strings,
    /// yaml:278-283, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_scenarios: Option<Vec<String>>,
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

    // ---- ACInfoSubscription (TS29558_Eees_AppClientInformation.yaml) --------

    /// Spec-exact hand-built JSON literal carrying ALL 9 schema fields
    /// (yaml:317-353) deserializes; camelCase names are exact
    /// (`notificationDestination`, `trigCondParams`, `acFltrs`).
    #[test]
    fn test_acinfo_subscription_spec_literal_all_fields() {
        // Hand-derived from ACInfoSubscription (yaml:317-353) + ACFilters
        // (yaml:379-419); NOT built via our own structs.
        let body = r#"{
            "easId":"eas1.example.com",
            "acFltrs":[{
                "acTypesList":["V2X"],
                "ecspIdsList":["ecsp-1"],
                "acIdsList":["ac1","ac2"],
                "svcArea":{"tais":[{"plmnId":{"mcc":"999","mnc":"70"},"tac":"000001"}]},
                "maxAcKpi":{"connBand":"100 Mbps"},
                "minAcKpi":{"connBand":"1 Mbps"},
                "opSchds":[{"daysOfWeek":[1]}],
                "ueIds":["msisdn-14155550001"],
                "locInfs":{"geographicAreas":[]},
                "easBundInd":{"bdlId":"bundle-7"}
            }],
            "expTime":"2030-01-01T00:00:00Z",
            "eventReq":{"notifMethod":"ON_EVENT_DETECTION"},
            "notificationDestination":"http://eas1.example.com/acinfo-cb",
            "requestTestNotification":true,
            "websockNotifConfig":{"requestWebsocketUri":true},
            "suppFeat":"1",
            "trigCondParams":["EAS_DISCOVERY","EEC_REGISTRATION"]
        }"#;
        let sub: ACInfoSubscription = serde_json::from_str(body).expect("deserializes");
        assert_eq!(sub.eas_id, "eas1.example.com");
        let fltr = &sub.ac_fltrs.as_ref().unwrap()[0];
        assert_eq!(fltr.ac_types_list.as_deref(), Some(&["V2X".to_string()][..]));
        assert_eq!(fltr.ue_ids.as_deref().unwrap().len(), 1);
        assert_eq!(sub.exp_time.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert!(sub.event_req.is_some());
        assert_eq!(
            sub.notification_destination.as_deref(),
            Some("http://eas1.example.com/acinfo-cb")
        );
        assert_eq!(sub.request_test_notification, Some(true));
        assert!(sub.websock_notif_config.is_some());
        assert_eq!(sub.supp_feat.as_deref(), Some("1"));
        assert_eq!(
            sub.trig_cond_params.as_deref(),
            Some(&["EAS_DISCOVERY".to_string(), "EEC_REGISTRATION".to_string()][..])
        );
    }

    /// Golden byte-vector: serializing a fully-populated subscription emits
    /// EXACTLY the spec camelCase wire form (hand-derived, not roundtrip-only).
    #[test]
    fn test_acinfo_subscription_golden_serialization() {
        let sub = ACInfoSubscription {
            eas_id: "eas1.example.com".into(),
            ac_fltrs: Some(vec![ACFilters {
                ac_ids_list: Some(vec!["ac1".into()]),
                ..Default::default()
            }]),
            exp_time: Some("2030-01-01T00:00:00Z".into()),
            event_req: None,
            notification_destination: Some("http://eas1.example.com/cb".into()),
            request_test_notification: None,
            websock_notif_config: None,
            supp_feat: Some("1".into()),
            trig_cond_params: Some(vec!["EAS_DISCOVERY".into()]),
        };
        // Hand-derived from ACInfoSubscription yaml:317-353 field names.
        let expected = concat!(
            r#"{"easId":"eas1.example.com","#,
            r#""acFltrs":[{"acIdsList":["ac1"]}],"#,
            r#""expTime":"2030-01-01T00:00:00Z","#,
            r#""notificationDestination":"http://eas1.example.com/cb","#,
            r#""suppFeat":"1","#,
            r#""trigCondParams":["EAS_DISCOVERY"]}"#
        );
        assert_eq!(serde_json::to_string(&sub).unwrap(), expected);
    }

    /// Unknown fields are tolerated (3GPP forward compatibility).
    #[test]
    fn test_acinfo_subscription_unknown_field_tolerance() {
        let body = r#"{"easId":"eas1","futureRel21Field":{"x":1}}"#;
        let sub: ACInfoSubscription = serde_json::from_str(body).expect("deserializes");
        assert_eq!(sub.eas_id, "eas1");
    }

    /// Missing the sole mandatory `easId` (yaml:352-353) fails to deserialize
    /// → handler maps to 400 MANDATORY_IE_MISSING. The OLD bespoke shape
    /// (`acId`-keyed) is exactly such a body.
    #[test]
    fn test_acinfo_subscription_missing_eas_id_fails() {
        assert!(serde_json::from_str::<ACInfoSubscription>(
            r#"{"acFltrs":[{"acIdsList":["ac1"]}]}"#
        )
        .is_err());
        // Old bespoke AppClientInfo shape → rejected.
        assert!(serde_json::from_str::<ACInfoSubscription>(r#"{"acId":"ac1"}"#).is_err());
    }

    /// `ACInfoNotification` requires `subId` + `acInfs`, and `ACInformation`
    /// requires `acProfs` (yaml:421-458); golden serialization asserted.
    #[test]
    fn test_acinfo_notification_model() {
        let notif = ACInfoNotification {
            sub_id: "sub-1".into(),
            ac_infs: vec![ACInformation {
                ac_profs: vec![serde_json::json!({"acId":"ac1","acType":"V2X"})],
                ue_ids: Some(vec!["msisdn-14155550001".into()]),
                ue_loc_infs: None,
            }],
        };
        let expected = concat!(
            r#"{"subId":"sub-1","acInfs":[{"acProfs":[{"acId":"ac1","acType":"V2X"}],"#,
            r#""ueIds":["msisdn-14155550001"]}]}"#
        );
        assert_eq!(serde_json::to_string(&notif).unwrap(), expected);
        // Missing required members fail to deserialize.
        assert!(serde_json::from_str::<ACInfoNotification>(r#"{"subId":"sub-1"}"#).is_err());
        assert!(serde_json::from_str::<ACInformation>(r#"{"ueIds":["u1"]}"#).is_err());
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

    // ---- EECContextPush / EECContext (TS29558_Eees_EECContextRelocation) ----

    /// Spec-exact hand-built `EECContextPush` JSON literal (envelope +
    /// required nested `eecId`/`cntxId`, yaml:179-203/229-267) deserializes.
    #[test]
    fn test_eec_context_push_spec_literal() {
        // Hand-derived from EECContextPush (yaml:179-203), EECContext
        // (yaml:229-267), SessionContexts (yaml:140-151),
        // IndividualSessionContext (yaml:153-177) and
        // EECSrvContinuitySupport (yaml:269-285).
        let body = r#"{
            "eesId":"ees-src.example.com",
            "eecCntx":{
                "eecId":"eec1",
                "cntxId":"cntx-1",
                "ueId":"msisdn-14155550001",
                "e1Subs":["e1-sub-1"],
                "ueLoc":{"geographicAreas":[]},
                "acProfs":[{"acId":"ac1"}],
                "sessCntxs":{"sessCntxs":[{
                    "easId":"eas1.example.com",
                    "endPt":{"fqdn":"eas1.example.com"},
                    "acId":"ac1",
                    "acrList":["EEC_INITIATED"],
                    "eecId":"eec1",
                    "appGrpId":"grp-1"
                }]},
                "eecSrvContSupp":{"srvContSupp":true,"acrScenarios":["EEC_INITIATED"]},
                "ueMobSuppInd":true
            },
            "tgtEas":{"fqdn":"t-eas.example.com"},
            "acrScenariosSelReq":true,
            "eecCntxs":[{"eecId":"eec2","cntxId":"cntx-2"}]
        }"#;
        let push: EECContextPush = serde_json::from_str(body).expect("deserializes");
        assert_eq!(push.ees_id, "ees-src.example.com");
        assert_eq!(push.eec_cntx.eec_id, "eec1");
        assert_eq!(push.eec_cntx.cntx_id, "cntx-1");
        let sess = push.eec_cntx.sess_cntxs.as_ref().unwrap();
        assert_eq!(sess.sess_cntxs[0].eas_id, "eas1.example.com");
        assert_eq!(
            sess.sess_cntxs[0].end_pt.fqdn.as_deref(),
            Some("eas1.example.com")
        );
        let cont = push.eec_cntx.eec_srv_cont_supp.as_ref().unwrap();
        assert!(cont.srv_cont_supp);
        assert_eq!(
            cont.acr_scenarios.as_deref(),
            Some(&["EEC_INITIATED".to_string()][..])
        );
        assert_eq!(push.acr_scenarios_sel_req, Some(true));
        assert_eq!(push.eec_cntxs.as_ref().unwrap()[0].cntx_id, "cntx-2");
    }

    /// Golden byte-vector: the minimal spec push envelope serializes to
    /// EXACTLY the hand-derived camelCase wire form.
    #[test]
    fn test_eec_context_push_golden_serialization() {
        let push = EECContextPush {
            ees_id: "ees-src".into(),
            eec_cntx: EECContext {
                eec_id: "eec1".into(),
                cntx_id: "c-1".into(),
                ue_id: None,
                e1_subs: None,
                ue_loc: None,
                ac_profs: None,
                sess_cntxs: None,
                eec_srv_cont_supp: None,
                ue_mob_supp_ind: None,
            },
            tgt_eas: None,
            acr_scenarios_sel_req: None,
            eec_cntxs: None,
        };
        // Hand-derived from EECContextPush yaml:179-203 field names.
        assert_eq!(
            serde_json::to_string(&push).unwrap(),
            r#"{"eesId":"ees-src","eecCntx":{"eecId":"eec1","cntxId":"c-1"}}"#
        );
    }

    /// The OLD flat bespoke shape (top-level `eecId`, no `cntxId`/envelope)
    /// fails to deserialize; missing nested `cntxId` also fails.
    #[test]
    fn test_eec_context_push_old_flat_shape_fails() {
        assert!(serde_json::from_str::<EECContextPush>(r#"{"eecId":"eec1","ueId":"ue-1"}"#)
            .is_err());
        // Envelope present but nested EECContext missing cntxId (yaml:265-267).
        assert!(serde_json::from_str::<EECContextPush>(
            r#"{"eesId":"ees-src","eecCntx":{"eecId":"eec1"}}"#
        )
        .is_err());
        // Missing eesId (yaml:201-203).
        assert!(serde_json::from_str::<EECContextPush>(
            r#"{"eecCntx":{"eecId":"eec1","cntxId":"c-1"}}"#
        )
        .is_err());
    }

    /// `EECContextPushRes` golden serialization (yaml:205-215) and
    /// `ImplicitRegDetails.regId` requiredness (yaml:217-227).
    #[test]
    fn test_eec_context_push_res_golden() {
        let res = EECContextPushRes {
            impl_reg: None,
            sel_acr_scenarios_list: Some(vec!["EEC_INITIATED".into()]),
        };
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            r#"{"selAcrScenariosList":["EEC_INITIATED"]}"#
        );
        let res = EECContextPushRes {
            impl_reg: Some(ImplicitRegDetails {
                reg_id: "reg-1".into(),
                exp_time: Some("2030-01-01T00:00:00Z".into()),
            }),
            sel_acr_scenarios_list: None,
        };
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            r#"{"implReg":{"regId":"reg-1","expTime":"2030-01-01T00:00:00Z"}}"#
        );
        assert!(serde_json::from_str::<ImplicitRegDetails>(
            r#"{"expTime":"2030-01-01T00:00:00Z"}"#
        )
        .is_err());
    }

    /// `SessionContexts`/`IndividualSessionContext` requiredness
    /// (yaml:150-151 sessCntxs; yaml:175-177 easId+endPt).
    #[test]
    fn test_session_contexts_required_members() {
        assert!(serde_json::from_str::<SessionContexts>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<IndividualSessionContext>(
            r#"{"easId":"eas1.example.com"}"#
        )
        .is_err());
        let ok: IndividualSessionContext = serde_json::from_str(
            r#"{"easId":"eas1.example.com","endPt":{"fqdn":"eas1.example.com"}}"#,
        )
        .unwrap();
        assert_eq!(ok.eas_id, "eas1.example.com");
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
