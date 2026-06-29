//! Application Context Relocation (ACR) data model — eesd-07.
//!
//! Implements the three ACR service APIs per TS 24.558 / TS 29.558:
//!
//! * `eees-appctxtreloc` (TS 24.558 §5.5): EEC-triggered Determine /
//!   Initiate / Declare flow (S-EAS → T-EAS coordination, TS 23.558 §8.8
//!   Scenario A).
//! * `eees-eel-acr` (TS 29.558 §5.11): EEL-managed ACR request
//!   (`RequestEELManagedACR`, Scenario C) — the EEL requests the EES to
//!   orchestrate the relocation internally.
//! * `eees-acrstatus-update` (TS 29.558 §5.12): ACR status update
//!   (`RequestACRUpdate`) from an EAS or the EEL.
//!
//! The EES maintains a per-(eecId, sEasId) state machine (see [`AcrStatus`])
//! whose transitions are: `None` → `DETERMINED` → `INITIATED` → `COMPLETED`
//! (or `FAILED`). State is held in `EesContext::acr_states`. ACR status
//! notifications to EAS/EEC endpoints are STUB (logged, no live peer).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared sub-types
// ---------------------------------------------------------------------------

/// S-EAS / T-EAS endpoint pair (TS 24.558 / TS 29.558 `AcrParameters`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrParameters {
    /// Source EAS identifier (mandatory; the current serving EAS).
    pub s_eas_id: String,
    /// Target EAS identifier (mandatory once Determine has run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_id: Option<String>,
    /// Source EAS reachability (optional; echoed from EASProfile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_eas_endpoint: Option<crate::types::EndPoint>,
    /// Target EAS reachability (optional; filled from T-EAS registration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_endpoint: Option<crate::types::EndPoint>,
}

/// `AcrModificationParams` — application context state to migrate from
/// S-EAS to T-EAS (TS 24.558). Carried as passthrough JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrModificationParams {
    /// Application-specific context data (passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_ctx: Option<serde_json::Value>,
    /// EAS relocation metadata (passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_reloc_info: Option<serde_json::Value>,
}

/// ACR status — the progression through the relocation state machine
/// (TS 29.558 §5.12 / TS 24.558 §5.5).
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

/// TS 23.558 §8.8 ACR scenario identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AcrScenario {
    /// Scenario A: EEC-triggered (Determine → Initiate → Declare).
    EecTriggered,
    /// Scenario B: EES-triggered.
    EesTriggered,
    /// Scenario C: EEL-managed (via `eees-eel-acr`).
    EelManaged,
    /// Scenario D: 5GC-triggered.
    FiveGcTriggered,
}

// ---------------------------------------------------------------------------
// eees-appctxtreloc: Determine / Initiate / Declare (TS 24.558 §5.5)
// ---------------------------------------------------------------------------

/// `AcrDetermReq` — body of `Determine`
/// (`POST .../eees-appctxtreloc/v1/determine`).
///
/// Mandatory IEs: `eecId`, `sEasId`. The EES selects a T-EAS from the
/// registered pool (first registered EAS ≠ S-EAS) and records the
/// relocation state as `DETERMINED`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrDetermReq {
    /// EEC identifier (mandatory).
    pub eec_id: String,
    /// Source EAS identifier — current serving EAS (mandatory).
    pub s_eas_id: String,
    /// UE identifier (GPSI/SUPI; optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Requested ACR scenario (optional; defaults to EEC-triggered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_scenario: Option<AcrScenario>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Response to `AcrDetermReq` — carries the determined T-EAS and ACR
/// parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrDetermResp {
    /// ACR parameters (S-EAS + selected T-EAS with endpoints).
    pub acr_params: AcrParameters,
    /// Negotiated supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `AcrInitReq` — body of `Initiate`
/// (`POST .../eees-appctxtreloc/v1/initiate`).
///
/// Mandatory IEs: `eecId`, `acrParams.sEasId`. `acrParams.tEasId` MUST be
/// present (set during Determine, or supplied by the EEC directly). The EES
/// transitions the relocation state to `INITIATED`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrInitReq {
    /// EEC identifier (mandatory).
    pub eec_id: String,
    /// ACR parameters (sEasId mandatory; tEasId must be present).
    pub acr_params: AcrParameters,
    /// ACR scenario (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_scenario: Option<AcrScenario>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Response to `AcrInitReq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrInitResp {
    /// Updated ACR parameters.
    pub acr_params: AcrParameters,
    /// Negotiated supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `AcrDeclareReq` — body of `Declare`
/// (`POST .../eees-appctxtreloc/v1/declare`).
///
/// Mandatory IEs: `eecId`, `sEasId`, `tEasId`. Marks the relocation
/// `COMPLETED`; the EES (stub) notifies the T-EAS and any ACR-status
/// subscribers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrDeclareReq {
    /// EEC identifier (mandatory).
    pub eec_id: String,
    /// Source EAS identifier (mandatory).
    pub s_eas_id: String,
    /// Target EAS identifier — the new serving EAS (mandatory).
    pub t_eas_id: String,
    /// Application context modification parameters (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_mod_params: Option<AcrModificationParams>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Response to `AcrDeclareReq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrDeclareResp {
    /// Final ACR parameters (completed relocation).
    pub acr_params: AcrParameters,
    /// Negotiated supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ---------------------------------------------------------------------------
// eees-eel-acr: EEL-managed ACR request (TS 29.558 §5.11)
// ---------------------------------------------------------------------------

/// `EelManagedAcrReq` — body of `RequestEELManagedACR`
/// (`POST .../eees-eel-acr/v1/request-eelacr`).
///
/// The EEL requests the EES to orchestrate an ACR (Scenario C): the EES
/// performs Determine + Initiate internally and returns the resulting T-EAS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EelManagedAcrReq {
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

/// Response to `EelManagedAcrReq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EelManagedAcrResp {
    /// ACR parameters with the selected and initiated T-EAS.
    pub acr_params: AcrParameters,
    /// Negotiated supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ---------------------------------------------------------------------------
// eees-acrstatus-update: ACR status notification (TS 29.558 §5.12)
// ---------------------------------------------------------------------------

/// `AcrStatusUpdateReq` — body of `RequestACRUpdate`
/// (`POST .../eees-acrstatus-update/v1/request-acrupdate`).
///
/// An EAS (S-EAS or T-EAS) or the EEL reports an ACR status change to the
/// EES. The EES updates its internal relocation state and (stub) notifies
/// interested parties.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcrStatusUpdateReq {
    /// EEC identifier (mandatory).
    pub eec_id: String,
    /// ACR parameters identifying the relocation (sEasId mandatory;
    /// tEasId expected when status ≠ DETERMINED).
    pub acr_params: AcrParameters,
    /// Updated ACR status (mandatory).
    pub acr_status: AcrStatus,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Response to `AcrStatusUpdateReq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcrStatusUpdateResp {
    /// Negotiated supported features (echoed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

// ---------------------------------------------------------------------------
// ACR state machine (stored in EesContext::acr_states)
// ---------------------------------------------------------------------------

/// Per-(eecId, sEasId) ACR relocation state maintained by the EES.
#[derive(Debug, Clone, PartialEq)]
pub struct AcrState {
    pub eec_id: String,
    pub s_eas_id: String,
    pub t_eas_id: Option<String>,
    pub status: AcrStatus,
}

/// Error outcomes from ACR context operations.
#[derive(Debug, PartialEq, Eq)]
pub enum AcrContextError {
    /// S-EAS `easId` is not registered with the EES → 404.
    SEasNotFound,
    /// No eligible T-EAS found in the registered pool → 503.
    NoTEasAvailable,
    /// Internal lock failure → 500.
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AcrDetermReq -------------------------------------------------------

    /// Spec-minimal body round-trips (camelCase: `eecId`, `sEasId`).
    #[test]
    fn test_acr_determ_req_roundtrip() {
        let body = r#"{"eecId":"eec1.example.com","sEasId":"eas-s.example.com"}"#;
        let req: AcrDetermReq = serde_json::from_str(body).expect("deserializes");
        assert_eq!(req.eec_id, "eec1.example.com");
        assert_eq!(req.s_eas_id, "eas-s.example.com");
        assert!(req.ue_id.is_none());
        assert!(req.acr_scenario.is_none());
        let back = serde_json::to_string(&req).unwrap();
        assert!(back.contains(r#""eecId":"eec1.example.com""#));
        assert!(back.contains(r#""sEasId":"eas-s.example.com""#));
    }

    /// Missing mandatory `sEasId` fails to deserialize → handler maps to 400.
    #[test]
    fn test_acr_determ_req_missing_s_eas_id_fails() {
        let body = r#"{"eecId":"eec1.example.com"}"#;
        assert!(serde_json::from_str::<AcrDetermReq>(body).is_err());
    }

    /// Missing mandatory `eecId` fails to deserialize.
    #[test]
    fn test_acr_determ_req_missing_eec_id_fails() {
        let body = r#"{"sEasId":"eas-s.example.com"}"#;
        assert!(serde_json::from_str::<AcrDetermReq>(body).is_err());
    }

    /// `AcrDetermResp` round-trips with nested `acrParams.tEasId`.
    #[test]
    fn test_acr_determ_resp_roundtrip() {
        let resp = AcrDetermResp {
            acr_params: AcrParameters {
                s_eas_id: "eas-s".into(),
                t_eas_id: Some("eas-t".into()),
                s_eas_endpoint: None,
                t_eas_endpoint: None,
            },
            supp_feat: Some("1".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""sEasId":"eas-s""#));
        assert!(json.contains(r#""tEasId":"eas-t""#));
        assert!(json.contains(r#""suppFeat":"1""#));
        let back: AcrDetermResp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }

    // ---- AcrInitReq ---------------------------------------------------------

    /// Body with nested `acrParams` (sEasId + tEasId) round-trips.
    #[test]
    fn test_acr_init_req_roundtrip() {
        let body = r#"{
            "eecId":"eec1",
            "acrParams":{"sEasId":"eas-s.example.com","tEasId":"eas-t.example.com"}
        }"#;
        let req: AcrInitReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.eec_id, "eec1");
        assert_eq!(req.acr_params.s_eas_id, "eas-s.example.com");
        assert_eq!(req.acr_params.t_eas_id.as_deref(), Some("eas-t.example.com"));
    }

    /// Missing `acrParams` fails to deserialize.
    #[test]
    fn test_acr_init_req_missing_acr_params_fails() {
        let body = r#"{"eecId":"eec1"}"#;
        assert!(serde_json::from_str::<AcrInitReq>(body).is_err());
    }

    // ---- AcrDeclareReq ------------------------------------------------------

    /// Minimal body (eecId, sEasId, tEasId) round-trips.
    #[test]
    fn test_acr_declare_req_roundtrip() {
        let body =
            r#"{"eecId":"eec1","sEasId":"eas-s.example.com","tEasId":"eas-t.example.com"}"#;
        let req: AcrDeclareReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.eec_id, "eec1");
        assert_eq!(req.s_eas_id, "eas-s.example.com");
        assert_eq!(req.t_eas_id, "eas-t.example.com");
        assert!(req.acr_mod_params.is_none());
    }

    /// Optional `acrModParams.appCtx` passthrough JSON is preserved.
    #[test]
    fn test_acr_declare_req_with_mod_params() {
        let body = r#"{
            "eecId":"eec1","sEasId":"s","tEasId":"t",
            "acrModParams":{"appCtx":{"sessionKey":"abc123"}}
        }"#;
        let req: AcrDeclareReq = serde_json::from_str(body).unwrap();
        let params = req.acr_mod_params.unwrap();
        let ctx = params.app_ctx.unwrap();
        assert_eq!(ctx["sessionKey"], "abc123");
    }

    // ---- EelManagedAcrReq ---------------------------------------------------

    /// Mandatory `eecId` + `sEasId` round-trips.
    #[test]
    fn test_eel_managed_acr_req_roundtrip() {
        let body = r#"{"eecId":"eec-eel","sEasId":"eas-src.example.com"}"#;
        let req: EelManagedAcrReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.eec_id, "eec-eel");
        assert_eq!(req.s_eas_id, "eas-src.example.com");
        assert!(req.ue_id.is_none());
    }

    /// Missing `sEasId` fails to deserialize.
    #[test]
    fn test_eel_managed_acr_req_missing_s_eas_id_fails() {
        assert!(serde_json::from_str::<EelManagedAcrReq>(r#"{"eecId":"eec"}"#).is_err());
    }

    // ---- AcrStatusUpdateReq -------------------------------------------------

    /// Full body with `COMPLETED` status round-trips.
    #[test]
    fn test_acr_status_update_req_roundtrip() {
        let body = r#"{
            "eecId":"eec1",
            "acrParams":{"sEasId":"eas-s.example.com","tEasId":"eas-t.example.com"},
            "acrStatus":"COMPLETED"
        }"#;
        let req: AcrStatusUpdateReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.eec_id, "eec1");
        assert_eq!(req.acr_status, AcrStatus::Completed);
        assert_eq!(req.acr_params.t_eas_id.as_deref(), Some("eas-t.example.com"));
    }

    /// Missing `acrStatus` fails to deserialize.
    #[test]
    fn test_acr_status_update_req_missing_status_fails() {
        let body = r#"{"eecId":"eec1","acrParams":{"sEasId":"s","tEasId":"t"}}"#;
        assert!(serde_json::from_str::<AcrStatusUpdateReq>(body).is_err());
    }

    // ---- Enum serialization -------------------------------------------------

    /// `AcrStatus` serializes as SCREAMING_SNAKE_CASE.
    #[test]
    fn test_acr_status_serialization() {
        assert_eq!(serde_json::to_string(&AcrStatus::Determined).unwrap(), r#""DETERMINED""#);
        assert_eq!(serde_json::to_string(&AcrStatus::Initiated).unwrap(), r#""INITIATED""#);
        assert_eq!(serde_json::to_string(&AcrStatus::Completed).unwrap(), r#""COMPLETED""#);
        assert_eq!(serde_json::to_string(&AcrStatus::Failed).unwrap(), r#""FAILED""#);
    }

    /// `AcrStatus` deserializes from SCREAMING_SNAKE_CASE.
    #[test]
    fn test_acr_status_deserialization() {
        let s: AcrStatus = serde_json::from_str(r#""DETERMINED""#).unwrap();
        assert_eq!(s, AcrStatus::Determined);
        let s: AcrStatus = serde_json::from_str(r#""FAILED""#).unwrap();
        assert_eq!(s, AcrStatus::Failed);
    }

    /// `AcrScenario` serializes as SCREAMING_SNAKE_CASE.
    #[test]
    fn test_acr_scenario_serialization() {
        assert_eq!(
            serde_json::to_string(&AcrScenario::EecTriggered).unwrap(),
            r#""EEC_TRIGGERED""#
        );
        assert_eq!(
            serde_json::to_string(&AcrScenario::EelManaged).unwrap(),
            r#""EEL_MANAGED""#
        );
        assert_eq!(
            serde_json::to_string(&AcrScenario::FiveGcTriggered).unwrap(),
            r#""FIVE_GC_TRIGGERED""#
        );
    }

    /// `AcrParameters` with all optional fields round-trips.
    #[test]
    fn test_acr_parameters_roundtrip() {
        use crate::types::EndPoint;
        let params = AcrParameters {
            s_eas_id: "eas-s".into(),
            t_eas_id: Some("eas-t".into()),
            s_eas_endpoint: Some(EndPoint {
                fqdn: Some("eas-s.edge".into()),
                ..Default::default()
            }),
            t_eas_endpoint: Some(EndPoint {
                fqdn: Some("eas-t.edge".into()),
                ..Default::default()
            }),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""sEasId":"eas-s""#));
        assert!(json.contains(r#""tEasId":"eas-t""#));
        assert!(json.contains(r#""sEasEndpoint""#));
        assert!(json.contains(r#""tEasEndpoint""#));
        let back: AcrParameters = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
    }
}
