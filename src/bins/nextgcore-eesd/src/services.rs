//! Remaining EES service API data models — eesd-13.
//!
//! Implements five `eees-*` service APIs that have no 5GC NEF/PCF-AF
//! dependency and can be validated entirely with unit tests:
//!
//! * `eees-cea` (TS 29.558 Eees_CommonEASAnnouncement): Common EAS
//!   Announcement — an announcing EES pushes the selected common-EAS
//!   information ([`CommonEASInfo`]) to the receiving EES via the custom
//!   operation `POST /declare` (→ 204, or 200 [`CommonEASInfoDecResp`]).
//! * `eees-appclientinformation` (TS 29.558 §8.4): AC Information
//!   subscriptions — an EAS subscribes for reports about Application Clients.
//!   Models are spec-exact per `TS29558_Eees_AppClientInformation.yaml`
//!   ([`ACInfoSubscription`], [`ACFilters`], [`ACInfoNotification`]).
//! * `eees-acrmgntevent` (TS 29.558 §5.8): ACR Management Event subscriptions
//!   — EECs subscribe to be notified about ACR lifecycle events.
//! * `eees-eeccontextreloc` (TS 29.558 §8.7.2): EEC Contexts — an EES pushes
//!   ([`EECContextPush`]) / pulls ([`EECContext`]) EEC context information.
//!   Models are spec-exact per `TS29558_Eees_EECContextRelocation.yaml`.
//! * `eees-acr-param` (TS 29.558 Eees_ACRParameterInformation): ACR Parameter
//!   Information — the consumer (S-EAS via EEL) pushes ACR parameter
//!   information ([`ACRParamsInfo`]) TO the EES via the custom operation
//!   `POST /send-acrparamsinfo` (→ 204, no response body).
//!
//! DEFERRED (eesd-13 subset requiring 5GC NEF/PCF-AF exposure path):
//! * `eees-session-with-qos` (TS 29.558 §5.6) — needs Nnef_TrafficInfluence
//!   to a live NEF; no NEF exposure path exists in this repo.
//! * `eees-tie` (TS 29.558 §5.15) — Traffic Influence EAS; same NEF/PCF-AF
//!   dependency; blocked until Nnef/Npcf AF exposure is wired.

use serde::{Deserialize, Serialize};

// ============================================================================
// eees-cea — Common EAS Announcement (TS 29.558 Eees_CommonEASAnnouncement,
// TS29558_Eees_CommonEASAnnouncement.yaml)
// ============================================================================

/// `CommonEASInfo` (TS29558_Eees_CommonEASAnnouncement.yaml:92-120) — body of
/// the custom operation `Declare`
/// (`POST {apiRoot}/eees-cea/v1/declare`). The API has NO resources: the
/// announcing EES pushes the common-EAS information and the receiving EES
/// answers 204 (or 200 [`CommonEASInfoDecResp`] when it has real group
/// connection information to return).
///
/// Required IEs (yaml:116-120): `requestorId`, `easId`, `easEndPt`, `appGrpId`.
/// Cross-spec leaves (`EASServiceKPI` from TS 29.558, `EDNInfo` from
/// TS 29.558 Eecs_EESRegistration) are carried as passthrough JSON values, per
/// the established `acr.rs` convention (preserve wire bytes without fabricating
/// a local model).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CommonEASInfo {
    /// Identifier of the announcing EES sending the request (yaml:97-99; REQUIRED).
    pub requestor_id: String,
    /// EAS ID of the selected common EAS (yaml:102-104; REQUIRED).
    pub eas_id: String,
    /// Endpoint of the selected common EAS (`EndPoint`, yaml:105-106; REQUIRED).
    pub eas_end_pt: crate::types::EndPoint,
    /// Application group identifier (yaml:111-113; REQUIRED).
    pub app_grp_id: String,
    /// Endpoint of the announcing EES (`EndPoint`, yaml:100-101).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requestor_end_pt: Option<crate::types::EndPoint>,
    /// `EASServiceKPI` of the common EAS (yaml:107-108; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_kpis_list: Option<serde_json::Value>,
    /// `EDNInfo` of the EDN hosting the common EAS (yaml:109-110; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edn_info: Option<serde_json::Value>,
    /// Supported features (yaml:114-115).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `CommonEASInfoDecResp` (TS29558_Eees_CommonEASAnnouncement.yaml:122-135) —
/// the 200-response body of `Declare`. The `anyOf: [required grpConnInfo]`
/// constraint (yaml:134-135) means a valid response MUST carry a non-empty
/// `grpConnInfo` list; the EES answers 204 instead of an empty 200 body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct CommonEASInfoDecResp {
    /// Group connection information (yaml:127-131, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grp_conn_info: Option<Vec<GrpConnInfo>>,
    /// Supported features (yaml:132-133).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `GrpConnInfo` (TS29558_Eees_CommonEASAnnouncement.yaml:137-154). Required:
/// `ueId`, `connInd` (yaml:152-154).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GrpConnInfo {
    /// UE identifier (`Gpsi`, yaml:142-143; REQUIRED).
    pub ue_id: String,
    /// Whether the UE identified by `ueId` should connect to the selected
    /// common EAS (yaml:144-151; REQUIRED).
    pub conn_ind: bool,
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
// eees-acrmgntevent — ACR Management Event subscriptions (TS 29.558,
// TS29558_Eees_ACRManagementEvent.yaml)
// ============================================================================

/// The six `AcrMgntEvent` enumeration values defined by TS 29.558
/// (TS29558_Eees_ACRManagementEvent.yaml:778-800). The schema is
/// `anyOf: [enum, string]` (forward-compatible), so the wire type is an open
/// `String`; these constants pin the spec values for matching/tests. The old
/// fabricated four-value enum — whose values did not exist anywhere in the spec
/// — was deleted (D7).
pub const ACR_MGNT_EVENTS: [&str; 6] = [
    "UP_PATH_CHG",
    "ACR_MONITORING",
    "ACR_FACILITATION",
    "ACT_START_STOP",
    "ACR_SELECTION",
    "OUT_OF_SERVICE_AREA",
];

/// `AcrMgntEventsSubscription` (TS29558_Eees_ACRManagementEvent.yaml:424-469) —
/// body of `CreateACRMngEventSubscr`
/// (`POST .../eees-acrmgntevent/v1/subscriptions`), of the PUT full-replace, and
/// of every 200/201 response.
///
/// Required IEs (yaml:466-469): `easId`, `eventSubscs` (minItems 1),
/// `notificationDestination`. The read-only `self` link is the resource URI set
/// by the server on create (the store key is the last path segment).
///
/// Cross-spec leaves (`ReportingInformation` from TS 29.523, `AvailabilityNotif`
/// / `FailureAcrMgntEventInfo` sub-trees, `WebsockNotifConfig` from TS 29.122)
/// are carried as passthrough JSON values, per the established `acr.rs`
/// convention (preserve wire bytes without fabricating a local model).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrMgntEventsSubscription {
    /// Resource self-link (`Uri`, yaml:428-429; server-set, read-only).
    #[serde(rename = "self", skip_serializing_if = "Option::is_none")]
    pub self_: Option<String>,
    /// Identifier of the service consumer (yaml:430-432; REQUIRED).
    pub eas_id: String,
    /// The subscribed ACR management events (yaml:433-438, minItems 1;
    /// REQUIRED).
    pub event_subscs: Vec<AcrMgntEventSubsc>,
    /// TS 29.523 `ReportingInformation` (yaml:439-440; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evt_req: Option<serde_json::Value>,
    /// Callback URI for ACR management event notifications (`Uri`,
    /// yaml:441-442; REQUIRED).
    pub notification_destination: String,
    /// The ACR management event report(s) (yaml:443-448, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_reports: Option<Vec<AcrMgntEventReport>>,
    /// UP path-change monitoring availability (`AvailabilityNotif`,
    /// yaml:449-450; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_info: Option<serde_json::Value>,
    /// Failure event reports (`FailureAcrMgntEventInfo`, yaml:451-456,
    /// minItems 1; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_event_reports: Option<Vec<serde_json::Value>>,
    /// Set to true to request a test notification (yaml:457-461).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_test_notification: Option<bool>,
    /// TS 29.122 `WebsockNotifConfig` (yaml:462-463; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websock_notif_config: Option<serde_json::Value>,
    /// Supported features (yaml:464-465).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `AcrMgntEventSubsc` (TS29558_Eees_ACRManagementEvent.yaml:471-519) — one
/// subscribed ACR management event with its optional filters. The sole REQUIRED
/// member is `event` (yaml:518-519), an [`ACR_MGNT_EVENTS`] open-enum string.
///
/// Cross-spec leaves (`AcrMgntEventFilter`, `ReportingInformation`,
/// `TargetUeIdentification`, `DnaiChangeType`, `EasCharacteristics`,
/// `TrafficFilterInfo`) are carried as passthrough JSON values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrMgntEventSubsc {
    /// The subscribed ACR management event (`AcrMgntEvent` open-enum string,
    /// yaml:475-476/778-800; REQUIRED).
    pub event: String,
    /// Event filter (`AcrMgntEventFilter`, yaml:477-478; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_filter: Option<serde_json::Value>,
    /// TS 29.523 `ReportingInformation` (yaml:479-480; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evt_req: Option<serde_json::Value>,
    /// Target UE identification (`TargetUeIdentification`, yaml:481-482;
    /// passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgt_ue_id: Option<serde_json::Value>,
    /// Application group identifier (yaml:483-484).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_grp_id: Option<String>,
    /// DNAI change type (`DnaiChangeType`, yaml:485-486; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnai_chg_type: Option<serde_json::Value>,
    /// Whether EAS acknowledgement of UP path change is expected (yaml:487-493).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ack_ind: Option<bool>,
    /// A list of EAS characteristics (`EasCharacteristics`, yaml:494-499,
    /// minItems 1; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_chars: Option<Vec<serde_json::Value>>,
    /// Traffic filter information (`TrafficFilterInfo`, yaml:500-501;
    /// passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traf_filter_info: Option<serde_json::Value>,
    /// Service continuity planning indication (yaml:502-509).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serv_cont_plan_ind: Option<bool>,
    /// Whether the EAS will acknowledge service-continuity notifications
    /// (yaml:510-517).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ack_svc_cont: Option<bool>,
}

/// Top-level members of `AcrMgntEventsSubscriptionPatch`
/// (TS29558_Eees_ACRManagementEvent.yaml:521-535) — the ONLY fields a `PATCH`
/// (`application/merge-patch+json`) may modify. The RFC 7396 merge is restricted
/// to these keys; anything else in the patch document (including the immutable
/// `easId`) is ignored.
pub const ACRMGNT_PATCHABLE_FIELDS: [&str; 3] =
    ["eventSubscs", "evtReq", "notificationDestination"];

/// `AcrMgntEventsNotification` (TS29558_Eees_ACRManagementEvent.yaml:537-554) —
/// the callback body POSTed to `notificationDestination`. Required
/// (yaml:552-554): `subpId`, `eventReports` (minItems 1). Consumed by the shared
/// notification sender (D6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrMgntEventsNotification {
    /// Identifier of the Individual ACR Management Events Subscription for which
    /// the notification is delivered (yaml:541-545; REQUIRED).
    pub subp_id: String,
    /// A list of ACR management event reports (yaml:546-551, minItems 1;
    /// REQUIRED).
    pub event_reports: Vec<AcrMgntEventReport>,
}

/// `AcrMgntEventReport` (TS29558_Eees_ACRManagementEvent.yaml:556-603) — one ACR
/// management event report. The sole REQUIRED member is `event` (yaml:602-603).
/// Cross-spec leaf sub-trees (`UpPathChangeInfo`, `ActStatus`,
/// `TargetUeIdentification`, `SelectedACRScenarios`, `EasInBundleInfo`,
/// `InOutArea`) are passthrough JSON values; `easEndPoint` reuses
/// [`crate::types::EndPoint`] and `acrParams` reuses the spec-exact
/// [`crate::acr::AcrParameters`] (`ACRParameters`, yaml:605-610).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrMgntEventReport {
    /// The ACR management event (`AcrMgntEvent` open-enum string,
    /// yaml:560-561; REQUIRED).
    pub event: String,
    /// Event time stamp (`DateTime`, yaml:562-563).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_stamp: Option<String>,
    /// UP path-change information (`UpPathChangeInfo`, yaml:564-565;
    /// passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_path_chg_info: Option<serde_json::Value>,
    /// EAS endpoint (`EndPoint`, yaml:566-567).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_end_point: Option<crate::types::EndPoint>,
    /// ACT status (`ActStatus`, yaml:568-569; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act_status: Option<serde_json::Value>,
    /// ACR parameters (`ACRParameters`, yaml:570-571) — reuses the spec-exact
    /// [`crate::acr::AcrParameters`] (`predictExpTime`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_params: Option<crate::acr::AcrParameters>,
    /// AC identifier (yaml:572-573).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Target UE identification (`TargetUeIdentification`, yaml:574-575;
    /// passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<serde_json::Value>,
    /// Selected ACR scenarios (`SelectedACRScenarios`, yaml:576-580, minItems 1;
    /// passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sel_acr_scen: Option<Vec<serde_json::Value>>,
    /// EAS-in-bundle information (`EasInBundleInfo`, yaml:581-586, minItems 1;
    /// passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_in_bdl_info_list: Option<Vec<serde_json::Value>>,
    /// Service continuity planning indication (yaml:587-594).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serv_cont_plan_ind: Option<bool>,
    /// In/out of service area (`InOutArea`, yaml:595-596; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_out_of_serv_area: Option<serde_json::Value>,
    /// A list of target UE identifications (`TargetUeIdentification`,
    /// yaml:597-601, minItems 1; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_ids: Option<Vec<serde_json::Value>>,
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
// eees-acr-param — ACR Parameter Information (TS 29.558
// Eees_ACRParameterInformation, TS29558_Eees_ACRParameterInformation.yaml)
// ============================================================================

/// `ACRParamsInfo` (TS29558_Eees_ACRParameterInformation.yaml:83-106) — body
/// of the custom operation `Request`
/// (`POST {apiRoot}/eees-acr-param/v1/send-acrparamsinfo`).
///
/// The spec REVERSES the legacy bespoke direction: the consumer (S-EAS via EEL)
/// PUSHES ACR parameter information TO the EES; success is 204 with no response
/// body (yaml:41-44). All six properties are REQUIRED (yaml:100-106).
///
/// NOTE the odd yaml attribute casing `sAsEndPoint`/`tAsEndPoint` (yaml:94-97;
/// NOT `sEas…`/`tEas…`) — pinned by the byte-level serialization tests below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACRParamsInfo {
    /// Identifier of the entity sending the request (yaml:88-89; REQUIRED).
    pub requestor_id: String,
    /// EEC identifier (yaml:90-91; REQUIRED).
    pub eec_id: String,
    /// AC identifier (yaml:92-93; REQUIRED).
    pub ac_id: String,
    /// Source AS endpoint (`EndPoint`, yaml:94-95; REQUIRED). Serializes as
    /// `sAsEndPoint`.
    pub s_as_end_point: crate::types::EndPoint,
    /// Target AS endpoint (`EndPoint`, yaml:96-97; REQUIRED). Serializes as
    /// `tAsEndPoint`.
    pub t_as_end_point: crate::types::EndPoint,
    /// ACR parameters (`ACRParameters` = TS 24.558 `AcrParameters`, yaml:98-99;
    /// REQUIRED) — reuses the existing spec-exact [`crate::acr::AcrParameters`]
    /// (`predictExpTime`).
    pub acr_params: crate::acr::AcrParameters,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CommonEASInfo (TS29558_Eees_CommonEASAnnouncement.yaml) ------------

    /// Spec-exact hand-built JSON literal carrying ALL 8 schema fields
    /// (yaml:92-120) deserializes; camelCase names are exact (`requestorId`,
    /// `easEndPt`, `appGrpId`, `serviceKpisList`, `requestorEndPt`).
    #[test]
    fn test_common_eas_info_spec_literal_all_fields() {
        // Hand-derived from CommonEASInfo (yaml:92-120); NOT built via our
        // own structs.
        let body = r#"{
            "requestorId":"ees-src.example.com",
            "requestorEndPt":{"fqdn":"ees-src.example.com"},
            "easId":"common-eas.example.com",
            "easEndPt":{"fqdn":"common-eas.edge.example.com","port":443},
            "serviceKpisList":{"conBdwth":"100 Mbps"},
            "ednInfo":{"ednServiceArea":{"tais":[]}},
            "appGrpId":"grp-1",
            "suppFeat":"1"
        }"#;
        let info: CommonEASInfo = serde_json::from_str(body).expect("deserializes");
        assert_eq!(info.requestor_id, "ees-src.example.com");
        assert_eq!(info.eas_id, "common-eas.example.com");
        assert_eq!(
            info.eas_end_pt.fqdn.as_deref(),
            Some("common-eas.edge.example.com")
        );
        assert_eq!(info.eas_end_pt.port, Some(443));
        assert_eq!(info.app_grp_id, "grp-1");
        assert!(info.requestor_end_pt.is_some());
        assert!(info.service_kpis_list.is_some());
        assert!(info.edn_info.is_some());
        assert_eq!(info.supp_feat.as_deref(), Some("1"));
    }

    /// Golden byte-vector: the minimal declaration (4 required IEs only)
    /// serializes to EXACTLY the hand-derived camelCase wire form.
    #[test]
    fn test_common_eas_info_golden_serialization() {
        let info = CommonEASInfo {
            requestor_id: "ees-src.example.com".into(),
            eas_id: "eas1.example.com".into(),
            eas_end_pt: crate::types::EndPoint {
                fqdn: Some("eas1.example.com".into()),
                ..Default::default()
            },
            app_grp_id: "grp-1".into(),
            requestor_end_pt: None,
            service_kpis_list: None,
            edn_info: None,
            supp_feat: None,
        };
        // Hand-derived from CommonEASInfo yaml:92-120 field names.
        let expected = concat!(
            r#"{"requestorId":"ees-src.example.com","#,
            r#""easId":"eas1.example.com","#,
            r#""easEndPt":{"fqdn":"eas1.example.com"},"#,
            r#""appGrpId":"grp-1"}"#
        );
        assert_eq!(serde_json::to_string(&info).unwrap(), expected);
    }

    /// Each of the 4 required IEs (yaml:116-120) individually missing fails to
    /// deserialize → handler maps to 400 MANDATORY_IE_MISSING. The OLD bespoke
    /// CeaAnnouncement shape (`easId` only) is exactly such a body.
    #[test]
    fn test_common_eas_info_missing_required_fails() {
        // Missing requestorId.
        assert!(serde_json::from_str::<CommonEASInfo>(
            r#"{"easId":"e","easEndPt":{"fqdn":"e"},"appGrpId":"g"}"#
        )
        .is_err());
        // Missing easId.
        assert!(serde_json::from_str::<CommonEASInfo>(
            r#"{"requestorId":"r","easEndPt":{"fqdn":"e"},"appGrpId":"g"}"#
        )
        .is_err());
        // Missing easEndPt.
        assert!(serde_json::from_str::<CommonEASInfo>(
            r#"{"requestorId":"r","easId":"e","appGrpId":"g"}"#
        )
        .is_err());
        // Missing appGrpId.
        assert!(serde_json::from_str::<CommonEASInfo>(
            r#"{"requestorId":"r","easId":"e","easEndPt":{"fqdn":"e"}}"#
        )
        .is_err());
        // Old bespoke CeaAnnouncement shape (`easId` only) → rejected.
        assert!(serde_json::from_str::<CommonEASInfo>(r#"{"easId":"eas1"}"#).is_err());
    }

    /// `CommonEASInfoDecResp` + `GrpConnInfo` golden serialization
    /// (yaml:122-154) and `GrpConnInfo` requiredness (yaml:152-154).
    #[test]
    fn test_common_eas_info_dec_resp_golden() {
        let resp = CommonEASInfoDecResp {
            grp_conn_info: Some(vec![GrpConnInfo {
                ue_id: "msisdn-14155550001".into(),
                conn_ind: true,
            }]),
            supp_feat: None,
        };
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"grpConnInfo":[{"ueId":"msisdn-14155550001","connInd":true}]}"#
        );
        // An all-absent response body is `{}` (the EES answers 204 instead).
        assert_eq!(
            serde_json::to_string(&CommonEASInfoDecResp::default()).unwrap(),
            "{}"
        );
        // GrpConnInfo requires both ueId and connInd.
        assert!(serde_json::from_str::<GrpConnInfo>(r#"{"ueId":"u1"}"#).is_err());
        assert!(serde_json::from_str::<GrpConnInfo>(r#"{"connInd":true}"#).is_err());
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

    // ---- AcrMgntEventsSubscription (TS29558_Eees_ACRManagementEvent.yaml) ----

    /// Spec-exact hand-built JSON literal carrying every top-level field
    /// (yaml:424-469) + a fully-populated `AcrMgntEventSubsc` (yaml:471-519)
    /// deserializes; camelCase names are exact (`notificationDestination`,
    /// `eventSubscs`, `requestTestNotification`, `easAckSvcCont`).
    #[test]
    fn test_acrmgnt_subscription_spec_literal_all_fields() {
        // Hand-derived from AcrMgntEventsSubscription (yaml:424-469) +
        // AcrMgntEventSubsc (yaml:471-519); NOT built via our own structs.
        let body = r#"{
            "self":"https://ees.example.com/eees-acrmgntevent/v1/subscriptions/sub-1",
            "easId":"eas1.example.com",
            "eventSubscs":[{
                "event":"UP_PATH_CHG",
                "eventFilter":"INTRA_EDN_MOBILITY",
                "evtReq":{"immRep":true},
                "tgtUeId":{"gpsi":"msisdn-14155550001"},
                "appGrpId":"grp-1",
                "dnaiChgType":"EARLY",
                "easAckInd":true,
                "easChars":[{"easId":"eas1.example.com"}],
                "trafFilterInfo":{"uris":["https://eas1.example.com/"]},
                "servContPlanInd":true,
                "easAckSvcCont":false
            }],
            "evtReq":{"notifMethod":"ON_EVENT_DETECTION"},
            "notificationDestination":"http://eas1.example.com/acrmgnt-cb",
            "eventReports":[{"event":"ACR_MONITORING"}],
            "availabilityInfo":{"availabilityStatus":"AVAILABLE"},
            "failEventReports":[{"event":"UP_PATH_CHG","failureCode":"OTHER_REASONS"}],
            "requestTestNotification":true,
            "websockNotifConfig":{"requestWebsocketUri":true},
            "suppFeat":"1"
        }"#;
        let sub: AcrMgntEventsSubscription = serde_json::from_str(body).expect("deserializes");
        assert_eq!(
            sub.self_.as_deref(),
            Some("https://ees.example.com/eees-acrmgntevent/v1/subscriptions/sub-1")
        );
        assert_eq!(sub.eas_id, "eas1.example.com");
        assert_eq!(sub.event_subscs.len(), 1);
        let es = &sub.event_subscs[0];
        assert_eq!(es.event, "UP_PATH_CHG");
        assert_eq!(es.app_grp_id.as_deref(), Some("grp-1"));
        assert_eq!(es.eas_ack_ind, Some(true));
        assert_eq!(es.serv_cont_plan_ind, Some(true));
        assert_eq!(es.eas_ack_svc_cont, Some(false));
        assert!(es.tgt_ue_id.is_some());
        assert!(es.event_filter.is_some());
        assert_eq!(
            sub.notification_destination,
            "http://eas1.example.com/acrmgnt-cb"
        );
        assert!(sub.event_reports.is_some());
        assert!(sub.availability_info.is_some());
        assert!(sub.fail_event_reports.is_some());
        assert_eq!(sub.request_test_notification, Some(true));
        assert!(sub.websock_notif_config.is_some());
        assert_eq!(sub.supp_feat.as_deref(), Some("1"));
    }

    /// Golden byte-vector: the minimal spec subscription (3 required IEs only)
    /// serializes to EXACTLY the hand-derived camelCase wire form — pinning the
    /// `self`→"self" rename and the `eventSubscs`/`notificationDestination`
    /// casing at the byte level.
    #[test]
    fn test_acrmgnt_subscription_golden_serialization() {
        let sub = AcrMgntEventsSubscription {
            self_: Some("/eees-acrmgntevent/v1/subscriptions/s-1".into()),
            eas_id: "eas1.example.com".into(),
            event_subscs: vec![AcrMgntEventSubsc {
                event: "ACR_MONITORING".into(),
                event_filter: None,
                evt_req: None,
                tgt_ue_id: None,
                app_grp_id: None,
                dnai_chg_type: None,
                eas_ack_ind: None,
                eas_chars: None,
                traf_filter_info: None,
                serv_cont_plan_ind: None,
                eas_ack_svc_cont: None,
            }],
            evt_req: None,
            notification_destination: "http://eas1.example.com/cb".into(),
            event_reports: None,
            availability_info: None,
            fail_event_reports: None,
            request_test_notification: None,
            websock_notif_config: None,
            supp_feat: None,
        };
        // Hand-derived from AcrMgntEventsSubscription yaml:424-469 field names.
        let expected = concat!(
            r#"{"self":"/eees-acrmgntevent/v1/subscriptions/s-1","#,
            r#""easId":"eas1.example.com","#,
            r#""eventSubscs":[{"event":"ACR_MONITORING"}],"#,
            r#""notificationDestination":"http://eas1.example.com/cb"}"#
        );
        assert_eq!(serde_json::to_string(&sub).unwrap(), expected);
    }

    /// Each of the 3 required IEs (yaml:466-469) individually missing fails to
    /// deserialize → handler maps to 400 MANDATORY_IE_MISSING. The OLD bespoke
    /// body (`notificationUri` + `acrEvents`) is exactly such a body: it lacks
    /// `easId`, `eventSubscs`, and `notificationDestination`.
    #[test]
    fn test_acrmgnt_subscription_missing_required_fails() {
        // Missing easId.
        assert!(serde_json::from_str::<AcrMgntEventsSubscription>(
            r#"{"eventSubscs":[{"event":"UP_PATH_CHG"}],"notificationDestination":"http://cb"}"#
        )
        .is_err());
        // Missing eventSubscs.
        assert!(serde_json::from_str::<AcrMgntEventsSubscription>(
            r#"{"easId":"eas1","notificationDestination":"http://cb"}"#
        )
        .is_err());
        // Missing notificationDestination.
        assert!(serde_json::from_str::<AcrMgntEventsSubscription>(
            r#"{"easId":"eas1","eventSubscs":[{"event":"UP_PATH_CHG"}]}"#
        )
        .is_err());
        // Nested AcrMgntEventSubsc missing its required `event` (yaml:518-519).
        assert!(serde_json::from_str::<AcrMgntEventsSubscription>(
            r#"{"easId":"eas1","eventSubscs":[{"appGrpId":"g"}],"notificationDestination":"http://cb"}"#
        )
        .is_err());
        // Old bespoke shape (notificationUri + acrEvents, none of the spec
        // required IEs) → rejected.
        assert!(serde_json::from_str::<AcrMgntEventsSubscription>(
            r#"{"notificationUri":"http://eec/cb","acrEvents":["LEGACY_VALUE"]}"#
        )
        .is_err());
    }

    /// The `AcrMgntEvent` open-enum accepts all 6 spec values (yaml:778-800) as
    /// plain strings AND tolerates a forward-compat unknown string.
    #[test]
    fn test_acrmgnt_event_open_enum_values() {
        for ev in ACR_MGNT_EVENTS {
            let body = format!(r#"{{"event":"{ev}"}}"#);
            let es: AcrMgntEventSubsc = serde_json::from_str(&body).expect("deserializes");
            assert_eq!(es.event, ev);
        }
        // Forward-compatible unknown value (open enum) is tolerated.
        let es: AcrMgntEventSubsc =
            serde_json::from_str(r#"{"event":"REL21_FUTURE_EVENT"}"#).expect("deserializes");
        assert_eq!(es.event, "REL21_FUTURE_EVENT");
    }

    /// `AcrMgntEventsNotification` requires `subpId` + `eventReports`, and
    /// `AcrMgntEventReport` requires `event` (yaml:537-603); golden
    /// serialization asserted (incl. reused `acrParams`/`easEndPoint`).
    #[test]
    fn test_acrmgnt_notification_model() {
        let notif = AcrMgntEventsNotification {
            subp_id: "sub-1".into(),
            event_reports: vec![AcrMgntEventReport {
                event: "ACR_MONITORING".into(),
                eas_end_point: Some(crate::types::EndPoint {
                    fqdn: Some("t-eas.example.com".into()),
                    ..Default::default()
                }),
                acr_params: Some(crate::acr::AcrParameters {
                    predict_exp_time: Some("2030-01-01T00:00:00Z".into()),
                }),
                ..Default::default()
            }],
        };
        // Hand-derived from AcrMgntEventsNotification yaml:537-554 +
        // AcrMgntEventReport yaml:556-603 field names.
        let expected = concat!(
            r#"{"subpId":"sub-1","eventReports":[{"event":"ACR_MONITORING","#,
            r#""easEndPoint":{"fqdn":"t-eas.example.com"},"#,
            r#""acrParams":{"predictExpTime":"2030-01-01T00:00:00Z"}}]}"#
        );
        assert_eq!(serde_json::to_string(&notif).unwrap(), expected);
        // Missing required members fail to deserialize.
        assert!(
            serde_json::from_str::<AcrMgntEventsNotification>(r#"{"subpId":"sub-1"}"#).is_err()
        );
        assert!(serde_json::from_str::<AcrMgntEventReport>(r#"{"acId":"ac1"}"#).is_err());
    }

    /// `AcrMgntEventsSubscriptionPatch` patchable-field allow-list (yaml:521-535)
    /// excludes the immutable `easId`.
    #[test]
    fn test_acrmgnt_patchable_fields() {
        assert!(ACRMGNT_PATCHABLE_FIELDS.contains(&"eventSubscs"));
        assert!(ACRMGNT_PATCHABLE_FIELDS.contains(&"notificationDestination"));
        assert!(ACRMGNT_PATCHABLE_FIELDS.contains(&"evtReq"));
        assert!(!ACRMGNT_PATCHABLE_FIELDS.contains(&"easId"));
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

    // ---- ACRParamsInfo (TS29558_Eees_ACRParameterInformation.yaml) ----------

    /// Spec-exact hand-built JSON literal carrying ALL 6 REQUIRED fields
    /// (yaml:83-106) deserializes; the odd casing `sAsEndPoint`/`tAsEndPoint`
    /// (yaml:94-97) is exact.
    #[test]
    fn test_acr_params_info_spec_literal_all_fields() {
        // Hand-derived from ACRParamsInfo (yaml:83-106); NOT built via our own
        // structs.
        let body = r#"{
            "requestorId":"eas-s.example.com",
            "eecId":"eec1",
            "acId":"ac1",
            "sAsEndPoint":{"fqdn":"s-as.edge.example.com"},
            "tAsEndPoint":{"fqdn":"t-as.edge.example.com","port":8443},
            "acrParams":{"predictExpTime":"2030-01-01T00:00:00Z"}
        }"#;
        let info: ACRParamsInfo = serde_json::from_str(body).expect("deserializes");
        assert_eq!(info.requestor_id, "eas-s.example.com");
        assert_eq!(info.eec_id, "eec1");
        assert_eq!(info.ac_id, "ac1");
        assert_eq!(
            info.s_as_end_point.fqdn.as_deref(),
            Some("s-as.edge.example.com")
        );
        assert_eq!(
            info.t_as_end_point.fqdn.as_deref(),
            Some("t-as.edge.example.com")
        );
        assert_eq!(info.t_as_end_point.port, Some(8443));
        assert_eq!(
            info.acr_params.predict_exp_time.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
    }

    /// Golden byte-vector: serializing a fully-populated `ACRParamsInfo` emits
    /// EXACTLY the spec wire form, pinning the `sAsEndPoint`/`tAsEndPoint`
    /// casing (an easy silent-400 trap) at the byte level.
    #[test]
    fn test_acr_params_info_golden_serialization() {
        let info = ACRParamsInfo {
            requestor_id: "eas-s.example.com".into(),
            eec_id: "eec1".into(),
            ac_id: "ac1".into(),
            s_as_end_point: crate::types::EndPoint {
                fqdn: Some("s-as.edge.example.com".into()),
                ..Default::default()
            },
            t_as_end_point: crate::types::EndPoint {
                fqdn: Some("t-as.edge.example.com".into()),
                ..Default::default()
            },
            acr_params: crate::acr::AcrParameters {
                predict_exp_time: Some("2030-01-01T00:00:00Z".into()),
            },
        };
        // Hand-derived from ACRParamsInfo yaml:83-106 field names.
        let expected = concat!(
            r#"{"requestorId":"eas-s.example.com","#,
            r#""eecId":"eec1","#,
            r#""acId":"ac1","#,
            r#""sAsEndPoint":{"fqdn":"s-as.edge.example.com"},"#,
            r#""tAsEndPoint":{"fqdn":"t-as.edge.example.com"},"#,
            r#""acrParams":{"predictExpTime":"2030-01-01T00:00:00Z"}}"#
        );
        assert_eq!(serde_json::to_string(&info).unwrap(), expected);
    }

    /// Each REQUIRED field missing fails to deserialize, and the WRONG casing
    /// `sEasEndpoint`/`tEasEndpoint` (not `sAsEndPoint`/`tAsEndPoint`) is a
    /// silent-400 trap: it leaves `sAsEndPoint` absent → error.
    #[test]
    fn test_acr_params_info_missing_required_fails() {
        let full = r#"{"requestorId":"r","eecId":"e","acId":"a","#.to_string()
            + r#""sAsEndPoint":{"fqdn":"s"},"tAsEndPoint":{"fqdn":"t"},"acrParams":{}}"#;
        // Sanity: the complete body deserializes.
        assert!(serde_json::from_str::<ACRParamsInfo>(&full).is_ok());
        // Each required field individually removed → error.
        for missing in [
            r#"{"eecId":"e","acId":"a","sAsEndPoint":{"fqdn":"s"},"tAsEndPoint":{"fqdn":"t"},"acrParams":{}}"#,
            r#"{"requestorId":"r","acId":"a","sAsEndPoint":{"fqdn":"s"},"tAsEndPoint":{"fqdn":"t"},"acrParams":{}}"#,
            r#"{"requestorId":"r","eecId":"e","sAsEndPoint":{"fqdn":"s"},"tAsEndPoint":{"fqdn":"t"},"acrParams":{}}"#,
            r#"{"requestorId":"r","eecId":"e","acId":"a","tAsEndPoint":{"fqdn":"t"},"acrParams":{}}"#,
            r#"{"requestorId":"r","eecId":"e","acId":"a","sAsEndPoint":{"fqdn":"s"},"acrParams":{}}"#,
            r#"{"requestorId":"r","eecId":"e","acId":"a","sAsEndPoint":{"fqdn":"s"},"tAsEndPoint":{"fqdn":"t"}}"#,
        ] {
            assert!(
                serde_json::from_str::<ACRParamsInfo>(missing).is_err(),
                "expected error for body missing a required IE: {missing}"
            );
        }
        // Wrong casing sEasEndpoint/tEasEndpoint → sAsEndPoint absent → error.
        assert!(serde_json::from_str::<ACRParamsInfo>(
            r#"{"requestorId":"r","eecId":"e","acId":"a","sEasEndpoint":{"fqdn":"s"},"tEasEndpoint":{"fqdn":"t"},"acrParams":{}}"#
        )
        .is_err());
    }
}
