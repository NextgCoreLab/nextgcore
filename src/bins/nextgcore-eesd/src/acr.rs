//! Application Context Relocation (ACR) data model — eesd-07.
//!
//! Data types modelled from the 3GPP tables (attribute names, mandatory /
//! optional presence, JSON casing) rather than a bespoke shape:
//!
//! * `eees-appctxtreloc` (**TS 24.558 §6.5.5**): the EEC/EAS-triggered
//!   Determine / Initiate / Declare flow. Request bodies are
//!   [`AcrDetermReq`] (§6.5.5.2.2), [`AcrInitReq`] (§6.5.5.2.3) and
//!   [`AcrDecReq`] (§6.5.5.2.4). Success is **204 No Content** (no response
//!   body) per the API tables (§8.x), so there are no `*Resp` body types.
//! * `eees-eelmanagedacr` (**TS 29.558 §8.8**): [`EELACRReq`] (§8.8.6.2.2) /
//!   [`EELACRResp`] (§8.8.6.2.3).
//! * `eees-acrstatus-update` (**TS 29.558 §8.9**): [`ACRUpdateData`]
//!   (§8.9.6.2.2), with [`ACRDataStatus`] (§8.9.6.2.3) as the optional
//!   response body.
//!
//! Rarely-used attributes whose data types live in other specs (e.g.
//! `ExpectedLocationArea`, `TunnelInfo`, `RouteToLocation`, `EasCharacteristics`,
//! `ACTResultInfo`) are carried as passthrough JSON ([`serde_json::Value`]) so
//! the wire representation is preserved without fabricating a local structure;
//! full local models for those are a follow-up.
//!
//! The EES maintains a per-UE ACR state machine (see [`AcrStatus`]) whose
//! transitions are `DETERMINED` → `INITIATED` → `COMPLETED` (or `FAILED`),
//! held in `EesContext::acr_states`. Notifications to EAS/EEC endpoints are
//! STUB (logged, no live peer).

use serde::{Deserialize, Serialize};

use crate::types::EndPoint;

// ---------------------------------------------------------------------------
// Shared sub-types (TS 24.558 §6.5.5)
// ---------------------------------------------------------------------------

/// `AcrParameters` (TS 24.558 §6.5.5.2.7) — ACR parameters specific to an ACR
/// request initiated for service-continuity planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrParameters {
    /// Predicted expiration time of the current EAS's usefulness (DateTime,
    /// optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predict_exp_time: Option<String>,
}

/// `AcrModificationParams` (TS 24.558 §6.5.5.2.8) — parameters for an ACR
/// modification request. Per the spec the endpoints and `acrParams` "shall be
/// present although they are not specified as mandatory due to backward
/// compatibility reasons".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrModificationParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_eas_endpoint: Option<EndPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_endpoint: Option<EndPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_params: Option<AcrParameters>,
}

/// `EecCtxtReloc` (TS 24.558 §6.5.5.2.5) — EEC context relocation information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EecCtxtReloc {
    /// EEC context identifier (mandatory).
    pub eec_ctxt_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_ees_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_eec_endpoint: Option<EndPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_ees_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eec_endpoint: Option<EndPoint>,
}

/// ACR status — the progression through the relocation state machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcrStatus {
    /// T-EAS selected; ACR not yet initiated.
    Determined,
    /// ACR in progress (Initiate accepted by the EES).
    Initiated,
    /// ACR successfully completed; T-EAS is now the serving EAS.
    Completed,
    /// ACR aborted or rolled back.
    Failed,
}

// ---------------------------------------------------------------------------
// eees-appctxtreloc: Determine / Initiate / Declare (TS 24.558 §6.5.5)
// ---------------------------------------------------------------------------

/// `AcrDetermReq` (TS 24.558 §6.5.5.2.2) — body of `Determine`
/// (`POST .../eees-appctxtreloc/v1/determine`).
///
/// Required IEs (OpenAPI): `requestorId`, `sEasEndpoint`. `ueId` "shall be
/// present although it is not specified as mandatory due to backward
/// compatibility reasons", hence modelled as optional.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrDetermReq {
    /// Identifier of the EEC or EAS sending the request (mandatory).
    pub requestor_id: String,
    /// Endpoint of the selected S-EAS (mandatory).
    pub s_eas_endpoint: EndPoint,
    /// UE identifier (GPSI); SHALL be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Application identifier of the EAS (e.g. FQDN/URI), optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_id: Option<String>,
    /// Identifier of the AC, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Predicted/expected UE location or service area (ExpectedLocationArea);
    /// passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_loc_area: Option<serde_json::Value>,
    /// Target tunnel information (TunnelInfo); passthrough.
    #[serde(rename = "tunnel_Info", skip_serializing_if = "Option::is_none")]
    pub tunnel_info: Option<serde_json::Value>,
}

/// `AcrInitReq` (TS 24.558 §6.5.5.2.3) — body of `Initiate`
/// (`POST .../eees-appctxtreloc/v1/initiate`).
///
/// Required IEs (OpenAPI): `requestorId`, `tEasEndpoint`, `easNotifInd`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrInitReq {
    /// Identifier of the EEC sending the request (mandatory).
    pub requestor_id: String,
    /// Endpoint of the T-EAS (mandatory).
    pub t_eas_endpoint: EndPoint,
    /// Whether the EAS should be notified about the need for ACR
    /// (mandatory; default false).
    #[serde(default)]
    pub eas_notif_ind: bool,
    /// UE identifier (GPSI); SHALL be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Application identifier of the EAS, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_id: Option<String>,
    /// Identifier of the AC, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Endpoint of the S-EAS; conditional (present when `easNotifInd` or
    /// `prevEasNotifInd` is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_eas_endpoint: Option<EndPoint>,
    /// Endpoint of the previous T-EAS; conditional (present when re-sending to
    /// cancel a previous ACR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_t_eas_endpoint: Option<EndPoint>,
    /// Whether the EAS should be notified about ACR cancellation; conditional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_eas_notif_ind: Option<bool>,
    /// T-EAS DNAI / N6 routing (RouteToLocation); passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_req: Option<serde_json::Value>,
    /// Simultaneous-connectivity inactivity time guidance (DurationSec).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sim_inact_time: Option<i64>,
    /// EEC context relocation information, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_ctxt_reloc: Option<EecCtxtReloc>,
    /// Predicted/expected UE location or service area; passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_loc_area: Option<serde_json::Value>,
    /// Service-continuity ACR parameters, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_params: Option<AcrParameters>,
    /// ACR modification parameters, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_modification_params: Option<AcrModificationParams>,
    /// EAS bundle information (EASBundleInfo); passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_bundle_info: Option<serde_json::Value>,
    /// T-EAS endpoints for the EAS bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_end_point_bundle_list: Option<Vec<EndPoint>>,
    /// List of UE identifiers (EdgeApp_3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_ids: Option<Vec<String>>,
    /// List of predicted/expected location areas (EdgeApp_3); passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_loc_areas: Option<Vec<serde_json::Value>>,
}

/// `AcrDecReq` (TS 24.558 §6.5.5.2.4) — body of `Declare`
/// (`POST .../eees-appctxtreloc/v1/declare`).
///
/// Required IEs (OpenAPI): `ueId`, `tEasId`, `tEasEndpoint`. `requestorId`
/// SHALL be included but is not mandatory for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrDecReq {
    /// UE identifier (GPSI) (mandatory).
    pub ue_id: String,
    /// Target EAS identifier — the new serving EAS (mandatory).
    pub t_eas_id: String,
    /// Endpoint of the T-EAS (mandatory).
    pub t_eas_endpoint: EndPoint,
    /// Identifier of the AC, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Identifier of the EAS sending the request; SHALL be included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requestor_id: Option<String>,
    /// Predicted/expected UE location or service area; passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_loc_area: Option<serde_json::Value>,
    /// EAS bundle information (EASBundleInfo); passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_bundle_info: Option<serde_json::Value>,
    /// T-EAS endpoints for the EAS bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_end_point_bundle_list: Option<Vec<EndPoint>>,
    /// List of UE identifiers in the application group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_grp_ue_ids: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// eees-eelmanagedacr: EEL-managed ACR request (TS 29.558 §8.8)
// ---------------------------------------------------------------------------

/// `EELACRReq` (TS 29.558 §8.8.6.2.2) — body of `Eees_EELManagedACR_Request`
/// (`POST .../eees-eelmanagedacr/v1/eel-managed-acr`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EELACRReq {
    /// UE identifier in the form of a GPSI (mandatory).
    pub ue_id: String,
    /// Set of EAS characteristics used to determine the required EASs
    /// (mandatory, 1..N; EasCharacteristics passthrough).
    pub eas_characs: Vec<serde_json::Value>,
    /// URI via which the Application Context can be accessed for ACT, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_ctxt_store_addr: Option<String>,
    /// Supported features, conditional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `EELACRResp` (TS 29.558 §8.8.6.2.3) — response body of
/// `Eees_EELManagedACR_Request`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EELACRResp {
    /// URI via which the Application Context can be accessed for ACT
    /// (included if not received in the request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_ctxt_store_addr: Option<String>,
    /// Negotiated supported features.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ---------------------------------------------------------------------------
// eees-acrstatus-update: ACR status update (TS 29.558 §8.9)
// ---------------------------------------------------------------------------

/// `ACRUpdateData` (TS 29.558 §8.9.6.2.2) — body of
/// `Eees_ACRStatusUpdate_Request`
/// (`POST .../eees-acrstatus-update/v1/update`).
///
/// At least one of `actResultInfo`, `e3SubscIds` or `e3NotificationUri` shall
/// be present (NOTE).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACRUpdateData {
    /// Application identifier of the service consumer (EAS/EES) sending the
    /// request (mandatory).
    pub eas_id: String,
    /// Identifier of the concerned AC, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Status of ACT (success/failure and related info); conditional
    /// (ACTResultInfo passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act_result_info: Option<serde_json::Value>,
    /// List of EDGE-3 subscription identifiers; conditional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e3_subsc_ids: Option<Vec<String>>,
    /// Updated notification URI for EDGE-3 subscriptions; conditional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e3_notification_uri: Option<String>,
}

/// `ACRDataStatus` (TS 29.558 §8.9.6.2.3) — optional response body of
/// `Eees_ACRStatusUpdate_Request`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACRDataStatus {
    /// Status of the initialization of EDGE-3 subscriptions (E3SubscsStatus:
    /// `SUCCESSFUL`/`FAILED`).
    pub e3_subscs_status: String,
    /// Updated list of EDGE-3 subscription identifiers, optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e3_subsc_ids: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// ACR state machine (stored in EesContext::acr_states)
// ---------------------------------------------------------------------------

/// Relocation identity reported by the bespoke `eees-acr-param` query helper
/// (a non-3GPP convenience API): the S-EAS/T-EAS identifiers and endpoints of a
/// tracked ACR. Distinct from the spec [`AcrParameters`] (§6.5.5.2.7), which
/// carries only `predictExpTime` and cannot hold relocation identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrRelocationInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_eas_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_eas_endpoint: Option<EndPoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_endpoint: Option<EndPoint>,
}

/// Per-UE ACR relocation state maintained by the EES.
///
/// Keyed (in `acr_states`) by the UE identity where available (see
/// [`super::context`]); the `eees-acrstatus-update` path, which carries no
/// `ueId`, keys its record by `easId`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AcrState {
    pub requestor_id: Option<String>,
    pub ue_id: Option<String>,
    pub eas_id: Option<String>,
    pub s_eas_endpoint: Option<EndPoint>,
    pub t_eas_id: Option<String>,
    pub t_eas_endpoint: Option<EndPoint>,
    pub status: Option<AcrStatus>,
}

/// Error outcomes from ACR context operations.
#[derive(Debug, PartialEq, Eq)]
pub enum AcrContextError {
    /// S-EAS is not registered with the EES → 404.
    SEasNotFound,
    /// No eligible T-EAS found in the registered pool → 503.
    NoTEasAvailable,
    /// Internal lock failure → 500.
    Internal,
}

/// Build the `acr_states` map key for a UE-scoped ACR record: the GPSI when
/// present, otherwise the requestor identity.
pub fn acr_ue_key(ue_id: Option<&str>, requestor_id: Option<&str>) -> String {
    match (ue_id, requestor_id) {
        (Some(u), _) if !u.trim().is_empty() => format!("ue:{u}"),
        (_, Some(r)) if !r.trim().is_empty() => format!("req:{r}"),
        _ => "acr:unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AcrDetermReq (TS 24.558 §6.5.5.2.2) --------------------------------

    /// Spec-minimal body round-trips: required `requestorId` + `sEasEndpoint`.
    #[test]
    fn test_acr_determ_req_roundtrip() {
        let body = r#"{
            "requestorId":"eec1.example.com",
            "sEasEndpoint":{"fqdn":"eas-s.edge.example.com"},
            "ueId":"imsi-999700000000001",
            "easId":"eas-s.example.com"
        }"#;
        let req: AcrDetermReq = serde_json::from_str(body).expect("deserializes");
        assert_eq!(req.requestor_id, "eec1.example.com");
        assert_eq!(req.s_eas_endpoint.fqdn.as_deref(), Some("eas-s.edge.example.com"));
        assert_eq!(req.ue_id.as_deref(), Some("imsi-999700000000001"));
        let back = serde_json::to_string(&req).unwrap();
        assert!(back.contains(r#""requestorId":"eec1.example.com""#));
        assert!(back.contains(r#""sEasEndpoint""#));
    }

    /// Missing mandatory `requestorId` fails to deserialize → handler maps 400.
    #[test]
    fn test_acr_determ_req_missing_requestor_id_fails() {
        let body = r#"{"sEasEndpoint":{"fqdn":"eas-s"}}"#;
        assert!(serde_json::from_str::<AcrDetermReq>(body).is_err());
    }

    /// Missing mandatory `sEasEndpoint` fails to deserialize.
    #[test]
    fn test_acr_determ_req_missing_s_eas_endpoint_fails() {
        let body = r#"{"requestorId":"eec1"}"#;
        assert!(serde_json::from_str::<AcrDetermReq>(body).is_err());
    }

    /// `tunnel_Info` keeps its exact (non-camelCase) spec attribute name.
    #[test]
    fn test_acr_determ_req_tunnel_info_name() {
        let req = AcrDetermReq {
            requestor_id: "eec1".into(),
            s_eas_endpoint: EndPoint { fqdn: Some("eas-s".into()), ..Default::default() },
            ue_id: None,
            eas_id: None,
            ac_id: None,
            expected_loc_area: None,
            tunnel_info: Some(serde_json::json!({"anchor":"upf1"})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""tunnel_Info""#), "must serialize as tunnel_Info: {json}");
        assert!(!json.contains("tunnelInfo"));
    }

    // ---- AcrInitReq (TS 24.558 §6.5.5.2.3) ----------------------------------

    /// Required `requestorId` + `tEasEndpoint` + `easNotifInd` round-trip.
    #[test]
    fn test_acr_init_req_roundtrip() {
        let body = r#"{
            "requestorId":"eec1",
            "tEasEndpoint":{"fqdn":"eas-t.edge.example.com"},
            "easNotifInd":true,
            "ueId":"imsi-999700000000001"
        }"#;
        let req: AcrInitReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.requestor_id, "eec1");
        assert_eq!(req.t_eas_endpoint.fqdn.as_deref(), Some("eas-t.edge.example.com"));
        assert!(req.eas_notif_ind);
    }

    /// Missing mandatory `tEasEndpoint` fails to deserialize.
    #[test]
    fn test_acr_init_req_missing_t_eas_endpoint_fails() {
        let body = r#"{"requestorId":"eec1","easNotifInd":false}"#;
        assert!(serde_json::from_str::<AcrInitReq>(body).is_err());
    }

    /// `easNotifInd` defaults to false when omitted (documented default).
    #[test]
    fn test_acr_init_req_eas_notif_ind_defaults_false() {
        let body = r#"{"requestorId":"eec1","tEasEndpoint":{"fqdn":"eas-t"}}"#;
        let req: AcrInitReq = serde_json::from_str(body).unwrap();
        assert!(!req.eas_notif_ind);
    }

    // ---- AcrDecReq (TS 24.558 §6.5.5.2.4) -----------------------------------

    /// Required `ueId` + `tEasId` + `tEasEndpoint` round-trip.
    #[test]
    fn test_acr_dec_req_roundtrip() {
        let body = r#"{
            "ueId":"imsi-999700000000001",
            "tEasId":"eas-t.example.com",
            "tEasEndpoint":{"fqdn":"eas-t.edge.example.com"},
            "requestorId":"eas-s.example.com"
        }"#;
        let req: AcrDecReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.ue_id, "imsi-999700000000001");
        assert_eq!(req.t_eas_id, "eas-t.example.com");
        assert_eq!(req.t_eas_endpoint.fqdn.as_deref(), Some("eas-t.edge.example.com"));
        assert_eq!(req.requestor_id.as_deref(), Some("eas-s.example.com"));
    }

    /// Missing mandatory `tEasId` fails to deserialize.
    #[test]
    fn test_acr_dec_req_missing_t_eas_id_fails() {
        let body = r#"{"ueId":"imsi-1","tEasEndpoint":{"fqdn":"eas-t"}}"#;
        assert!(serde_json::from_str::<AcrDecReq>(body).is_err());
    }

    // ---- AcrParameters (TS 24.558 §6.5.5.2.7) -------------------------------

    /// `AcrParameters` carries only `predictExpTime`.
    #[test]
    fn test_acr_parameters_predict_exp_time() {
        let p = AcrParameters { predict_exp_time: Some("2026-07-01T12:00:00Z".into()) };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""predictExpTime":"2026-07-01T12:00:00Z""#));
        let back: AcrParameters = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        // Empty object is valid (all-optional).
        assert_eq!(serde_json::to_string(&AcrParameters::default()).unwrap(), "{}");
    }

    // ---- EELACRReq (TS 29.558 §8.8.6.2.2) -----------------------------------

    /// Required `ueId` + `easCharacs` round-trip.
    #[test]
    fn test_eel_acr_req_roundtrip() {
        let body = r#"{
            "ueId":"imsi-999700000000001",
            "easCharacs":[{"easId":"eas-t"}],
            "appCtxtStoreAddr":"https://store.example.com/ctx/1"
        }"#;
        let req: EELACRReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.ue_id, "imsi-999700000000001");
        assert_eq!(req.eas_characs.len(), 1);
        assert_eq!(req.app_ctxt_store_addr.as_deref(), Some("https://store.example.com/ctx/1"));
    }

    /// Missing mandatory `easCharacs` fails to deserialize.
    #[test]
    fn test_eel_acr_req_missing_eas_characs_fails() {
        assert!(serde_json::from_str::<EELACRReq>(r#"{"ueId":"imsi-1"}"#).is_err());
    }

    // ---- ACRUpdateData (TS 29.558 §8.9.6.2.2) -------------------------------

    /// Required `easId` + `actResultInfo` round-trip.
    #[test]
    fn test_acr_update_data_roundtrip() {
        let body = r#"{
            "easId":"eas-t.example.com",
            "actResultInfo":{"actResult":"ACT_SUCCESSFUL"}
        }"#;
        let req: ACRUpdateData = serde_json::from_str(body).unwrap();
        assert_eq!(req.eas_id, "eas-t.example.com");
        assert!(req.act_result_info.is_some());
    }

    /// Missing mandatory `easId` fails to deserialize.
    #[test]
    fn test_acr_update_data_missing_eas_id_fails() {
        let body = r#"{"actResultInfo":{"actResult":"ACT_SUCCESSFUL"}}"#;
        assert!(serde_json::from_str::<ACRUpdateData>(body).is_err());
    }

    // ---- AcrStatus ----------------------------------------------------------

    /// `AcrStatus` serializes as SCREAMING_SNAKE_CASE.
    #[test]
    fn test_acr_status_serialization() {
        assert_eq!(serde_json::to_string(&AcrStatus::Determined).unwrap(), r#""DETERMINED""#);
        assert_eq!(serde_json::to_string(&AcrStatus::Initiated).unwrap(), r#""INITIATED""#);
        assert_eq!(serde_json::to_string(&AcrStatus::Completed).unwrap(), r#""COMPLETED""#);
        assert_eq!(serde_json::to_string(&AcrStatus::Failed).unwrap(), r#""FAILED""#);
    }

    /// The UE-scoped state key prefers the GPSI, then the requestor identity.
    #[test]
    fn test_acr_ue_key() {
        assert_eq!(acr_ue_key(Some("imsi-1"), Some("eec1")), "ue:imsi-1");
        assert_eq!(acr_ue_key(None, Some("eec1")), "req:eec1");
        assert_eq!(acr_ue_key(Some("  "), Some("eec1")), "req:eec1");
        assert_eq!(acr_ue_key(None, None), "acr:unknown");
    }
}
