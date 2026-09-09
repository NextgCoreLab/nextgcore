//! EES capability-exposure service APIs (issue #106).
//!
//! Five service APIs defined by their TS 29.558 / TS 24.558 YAMLs had **no
//! dispatch arm at all**, so every request against them fell through to
//! `send_not_found`:
//!
//! | API | root | this module |
//! |---|---|---|
//! | EAS Information Provisioning | `eees-easinfoprov/v1` | **served locally** |
//! | UE Identifier | `eees-ueidentifier/v1` | served where the EES owns the answer, `501` where the CN is required |
//! | UE Location | `eees-uelocation/v1` | `501` — no location source in this build |
//! | Session with QoS | `eees-session-with-qos/v1` | `501` — no NEF `AsSessionWithQoS` leg |
//! | Traffic Influence (EAS) | `eees-tie/v1` | `501` — no NEF/PCF-AF traffic-influence leg |
//!
//! # Why some of these answer 501 rather than a 2xx
//!
//! A 404 says "this resource does not exist", which is false: the resource is
//! defined by the API this EES claims to serve, and a conformant EAS/EEC cannot
//! tell a missing route from a mistyped one. A `501 NOT_IMPLEMENTED` with a
//! ProblemDetails naming the missing dependency says the true thing.
//!
//! **501, not 503.** 503 invites a retry, and for these three a retry can never
//! succeed: the capability is structurally absent from the build, not
//! temporarily unavailable. TS 29.500 §5.2.7.2 gives `NOT_IMPLEMENTED` for
//! exactly this. If a NEF leg is added later, the honest answer changes to a
//! 2xx (or to 503 when a *configured* NEF is unreachable), and the tests here
//! are what will need inverting.
//!
//! **Why not accept and store instead.** Answering 201 to
//! `CreateIndSessionWithQoS` while actuating no QoS anywhere would be
//! fabricated success — the caller would believe a QoS flow exists. The same
//! argument rules out creating `eees-uelocation` subscriptions: a subscription
//! that can never fire is worse than a refusal, because the failure is silent.
//! That is the same trap #106 itself reports for AppClientInformation, whose
//! notification is implemented in this change.

use serde::{Deserialize, Serialize};

use crate::context::ees_self;
use crate::types::{EasProfile, EndPoint};

/// ACR scenarios (`ACRScenario`, `TS29558_Eecs_EESRegistration.yaml`) that this
/// EES can actually take part in — the basis for
/// `ACR_SCENARIO_SELECTION_REQUEST`.
///
/// Derived from what is implemented, not from the enumeration:
///
/// * `EEC_INITIATED` — `eees-appctxtreloc` determine / initiate / declare.
/// * `EEC_EXECUTED_VIA_TARGET_EES` — this EES can act as the **target** EES: the
///   TS 29.558 §5.10 EEC-context pull landed in #105.
/// * `SOURCE_EAS_DECIDED` — `eees-acr-param` and `eees-acrstatus-update` accept
///   the S-EAS's decision and its outcome.
/// * `EEL_MANAGED_ACR` — `eees-eel-acr/request-eelacr`.
///
/// Deliberately **absent**: `EEC_EXECUTED_VIA_SOURCE_EES` and
/// `SOURCE_EES_EXECUTED`. Both require this EES to act as the *source* and push
/// an EEC context to a target EES, and only the pull half exists — the push
/// counterpart is a known open gap. Advertising them would make an EES claim a
/// scenario it would then fail to execute, which is worse than advertising
/// fewer.
pub const EES_SUPPORTED_ACR_SCENARIOS: &[&str] = &[
    "EEC_INITIATED",
    "EEC_EXECUTED_VIA_TARGET_EES",
    "SOURCE_EAS_DECIDED",
    "EEL_MANAGED_ACR",
];

/// `EasInfoProvReqType` value: the EEC announces the ACR scenarios it selected.
pub const REQ_TYPE_ACR_ANNOUNCEMENT: &str = "ACR_SCENARIO_SELECTION_ANNOUNCEMENT";
/// `EasInfoProvReqType` value: the EEC asks the EES to select ACR scenarios.
pub const REQ_TYPE_ACR_REQUEST: &str = "ACR_SCENARIO_SELECTION_REQUEST";
/// `EasInfoProvReqType` value: the EEC asks the EES to select an EAS.
pub const REQ_TYPE_EAS_SELECTION: &str = "EAS_SELECTION";

/// `EASInfoProvReq` (`TS24558_Eees_EASInformationProvisioning.yaml`) — the
/// request body of `POST {apiRoot}/eees-easinfoprov/v1/declare`.
///
/// Every member is optional in the schema, including `reqType`. Only the members
/// this EES acts on are modelled; the rest of the (large) schema is not declared
/// at all, because declaring a member nothing reads is the shape of defect this
/// issue is about. Unknown members in an incoming body are ignored by serde, so
/// a conformant sender is never rejected for sending more.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasInfoProvReq {
    /// Identifier of the EEC making the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_id: Option<String>,
    /// Identifier of the AC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Identifier(s) of the selected EAS(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sel_eas_ids: Option<Vec<String>>,
    /// Application group identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_grp_id: Option<String>,
    /// Identifier of the EES.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ees_id: Option<String>,
    /// Type of provisioning request (`EasInfoProvReqType`; open enumeration, so
    /// carried as a `String` for forward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_type: Option<String>,
    /// ACR scenarios selected by the EEC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sel_acr_scenarios: Option<Vec<String>>,
    /// Supported features.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// `InstantiatedEASInfo` (`TS24558_Eees_EASInformationProvisioning.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InstantiatedEasInfo {
    /// The EAS profile of the instantiated EAS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas: Option<EasProfile>,
    /// Lifetime of the instantiated EAS (`DurationSec`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub life_time: Option<u64>,
}

/// `EASInfoProvResp` (`TS24558_Eees_EASInformationProvisioning.yaml`) — the 200
/// response body.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasInfoProvResp {
    /// ACR scenarios selected **by the EES**.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sel_acr_scenario_list: Option<Vec<String>>,
    /// Instantiated EAS information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inst_eas_info: Option<InstantiatedEasInfo>,
    /// Endpoint of the common EAS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub com_eas_endpoint: Option<EndPoint>,
    /// Endpoint of the common EES.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub com_ees_endpoint: Option<EndPoint>,
}

/// `UserInfo` (`TS29558_Eees_UEIdentifier.yaml`) — the request body of both
/// `POST .../eees-ueidentifier/v1/fetch` and `.../get`.
///
/// The schema's constraint is `anyOf: [required: [ueId], required: [ipAddr]]` —
/// at least one of the two must identify the UE. That is enforced by
/// [`Self::validate`] rather than by serde, which cannot express `anyOf`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    /// Identifier of the requestor (EAS/EEC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requestor_id: Option<String>,
    /// EAS identifiers the UE IDs are requested for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ids: Option<Vec<String>>,
    /// Identifier of the ASP providing the EAS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_provider_id: Option<String>,
    /// UE identifier as a GPSI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// UE IP address (`IpAddr`; passthrough — only its presence is acted on).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addr: Option<serde_json::Value>,
    /// Application port identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_port_id: Option<u16>,
    /// Port number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_number: Option<u16>,
    /// Supported features.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

impl UserInfo {
    /// Enforce the schema's `anyOf`: at least one of `ueId` / `ipAddr`.
    pub fn validate(&self) -> Result<(), String> {
        if self.ue_id.is_none() && self.ip_addr.is_none() {
            return Err(
                "At least one of ueId / ipAddr must be present (TS29558_Eees_UEIdentifier.yaml \
                 UserInfo anyOf)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// `UeId` (`TS29558_Eees_UEIdentifier.yaml`). The schema is
/// `oneOf: [required: [edgeUeId], required: [afSpecUeId]]` — **exactly one**.
///
/// This EES returns the `edgeUeId` form. `afSpecUeId` is a GPSI obtained from
/// the core network; echoing back the GPSI the requestor supplied would dress a
/// value it already had as a CN resolution it never performed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UeId {
    /// EDGE UE identifier assigned by the edge enabler layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_ue_id: Option<String>,
    /// AF-specific UE identifier (a GPSI from the CN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub af_spec_ue_id: Option<String>,
    /// The EAS this identifier is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_id: Option<String>,
}

/// `UeIdInfo` (`TS29558_Eees_UEIdentifier.yaml`) — the 200 response body.
/// Required: `ueIds` (minItems 1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UeIdInfo {
    /// One entry per requested EAS.
    pub ue_ids: Vec<UeId>,
    /// Supported features.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Derive the EDGE UE identifier for `(gpsi, eas_id)`.
///
/// The EDGE UE ID is an edge-enabler-layer identifier, so the EES is entitled to
/// assign it — unlike `afSpecUeId`, which would have to come from the CN.
///
/// Requirements this satisfies, and why each matters:
///
/// * **Stable** — a repeat request returns the same value, so an EAS can use it
///   as a key. A random UUID per call would be useless for that.
/// * **Per-EAS** — the same UE is a different `edgeUeId` to a different EAS, so
///   two EASes cannot correlate their users by comparing identifiers.
/// * **Opaque** — the GPSI is not recoverable from it by an EAS, which is the
///   point of not just handing out the MSISDN.
///
/// SHA-256 over a domain-separated input, truncated to 32 hex characters.
/// Truncation is fine here: this is an identifier, not a MAC — an attacker
/// gains nothing from a collision they cannot steer, and 128 bits leaves no
/// accidental ones.
pub fn edge_ue_id(gpsi: &str, eas_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Domain separation, and a length-prefixed join so ("ab","c") and ("a","bc")
    // cannot hash to the same value.
    hasher.update(b"nextgcore/eesd/edge-ue-id/v1\x00");
    hasher.update((gpsi.len() as u64).to_be_bytes());
    hasher.update(gpsi.as_bytes());
    hasher.update((eas_id.len() as u64).to_be_bytes());
    hasher.update(eas_id.as_bytes());
    let digest = hasher.finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Is `gpsi` a UE this EES knows about, i.e. one an EEC has registered for?
///
/// The EES answers `eees-ueidentifier` only for UEs it serves. Minting an
/// identifier for an arbitrary GPSI would turn the API into an oracle that
/// answers for any input, telling the caller nothing about whether the UE exists.
pub fn is_known_ue(gpsi: &str) -> bool {
    ees_self()
        .read()
        .map(|c| {
            c.eec_list()
                .iter()
                .any(|r| r.ue_id.as_deref() == Some(gpsi))
        })
        .unwrap_or(false)
}

/// Resolve the EDGE UE identifiers for a `UserInfo` request.
///
/// `Ok(UeIdInfo)` when the UE is identified by a GPSI this EES serves.
/// `Err(reason)` names why it cannot be answered, which the handler turns into
/// the right status: an unknown GPSI is a 404, an IP-only request is a 501.
pub fn resolve_ue_ids(req: &UserInfo) -> Result<UeIdInfo, UeIdError> {
    let Some(gpsi) = req.ue_id.as_deref() else {
        // Only `ipAddr` was given. Mapping a UE IP address to a subscriber needs
        // the core network (Nnef_UEId / the T8 UE-ID API): the EES has no
        // IP-to-UE binding of its own, and guessing one would be an invention.
        return Err(UeIdError::CoreNetworkRequired);
    };
    if !is_known_ue(gpsi) {
        return Err(UeIdError::UnknownUe);
    }
    // One identifier per requested EAS; with none named, a single EAS-agnostic
    // identifier keyed on the requestor.
    let eas_ids: Vec<String> = match req.eas_ids.as_ref().filter(|v| !v.is_empty()) {
        Some(ids) => ids.clone(),
        None => vec![req.requestor_id.clone().unwrap_or_default()],
    };
    Ok(UeIdInfo {
        ue_ids: eas_ids
            .into_iter()
            .map(|eas_id| UeId {
                edge_ue_id: Some(edge_ue_id(gpsi, &eas_id)),
                af_spec_ue_id: None,
                eas_id: (!eas_id.is_empty()).then_some(eas_id),
            })
            .collect(),
        supp_feat: None,
    })
}

/// Why `eees-ueidentifier` could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeIdError {
    /// The request identified the UE only by IP address, which needs the CN.
    CoreNetworkRequired,
    /// The GPSI is not a UE this EES serves.
    UnknownUe,
}

/// Select the ACR scenarios this EES will use, given what the EEC asked for.
///
/// The intersection, in the **EEC's** order so its preference is honoured. An
/// EEC that named nothing gets this EES's full supported set, since the request
/// type asks the EES to choose.
pub fn select_acr_scenarios(requested: Option<&[String]>) -> Vec<String> {
    match requested.filter(|r| !r.is_empty()) {
        Some(req) => req
            .iter()
            .filter(|s| EES_SUPPORTED_ACR_SCENARIOS.contains(&s.as_str()))
            .cloned()
            .collect(),
        None => EES_SUPPORTED_ACR_SCENARIOS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

/// Look up the EAS profiles for the `selEasIds` an EEC named, from this EES's
/// own registrations. Unknown identifiers are simply absent from the result —
/// the response reports what is instantiated, and an EAS that never registered
/// is not.
pub fn instantiated_eas(sel_eas_ids: Option<&[String]>) -> Option<InstantiatedEasInfo> {
    let ids = sel_eas_ids?;
    let ctx = ees_self();
    let guard = ctx.read().ok()?;
    let eas = ids
        .iter()
        .find_map(|id| guard.eas_discover(Some(id), None).into_iter().next())?;
    Some(InstantiatedEasInfo {
        eas: Some(eas),
        life_time: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EDGE UE ID is stable for the same pair, differs per EAS, and does not
    /// leak the GPSI. Each property is asserted separately because they fail
    /// independently: a random id breaks stability, a GPSI-only hash breaks
    /// per-EAS separation, and a plain echo breaks opacity.
    #[test]
    fn edge_ue_id_is_stable_per_eas_and_opaque() {
        let a = edge_ue_id("msisdn-491701234567", "eas1.example.com");
        assert_eq!(
            a,
            edge_ue_id("msisdn-491701234567", "eas1.example.com"),
            "the same (UE, EAS) pair must always give the same identifier"
        );
        assert_ne!(
            a,
            edge_ue_id("msisdn-491701234567", "eas2.example.com"),
            "two EASes must not be able to correlate a UE by identifier"
        );
        assert_ne!(
            a,
            edge_ue_id("msisdn-491709999999", "eas1.example.com"),
            "two UEs must not share an identifier at one EAS"
        );
        assert!(
            !a.contains("491701234567"),
            "the GPSI must not be recoverable from the identifier: {a}"
        );
        assert_eq!(a.len(), 32, "128 bits as hex");
        // The length-prefixed hash input: these two must not collide.
        assert_ne!(edge_ue_id("ab", "c"), edge_ue_id("a", "bc"));
    }

    /// `UserInfo` must carry at least one UE identifier (the schema's `anyOf`).
    #[test]
    fn user_info_requires_a_ue_identifier() {
        assert!(UserInfo::default().validate().is_err());
        assert!(UserInfo {
            ue_id: Some("msisdn-1".into()),
            ..Default::default()
        }
        .validate()
        .is_ok());
        assert!(UserInfo {
            ip_addr: Some(serde_json::json!({"ipv4Addr": "10.0.0.1"})),
            ..Default::default()
        }
        .validate()
        .is_ok());
    }

    /// An IP-only request cannot be answered by the EES alone, and says so with
    /// a distinct error rather than an empty success.
    #[test]
    fn an_ip_only_request_reports_that_the_core_network_is_required() {
        let req = UserInfo {
            ip_addr: Some(serde_json::json!({"ipv4Addr": "10.0.0.1"})),
            ..Default::default()
        };
        assert_eq!(resolve_ue_ids(&req), Err(UeIdError::CoreNetworkRequired));
    }

    /// Scenario selection is the intersection, in the EEC's order, and never
    /// advertises a scenario this EES cannot execute.
    #[test]
    fn acr_scenario_selection_is_the_intersection() {
        // The EEC's order is preserved.
        assert_eq!(
            select_acr_scenarios(Some(&[
                "EEL_MANAGED_ACR".to_string(),
                "EEC_INITIATED".to_string()
            ])),
            vec!["EEL_MANAGED_ACR".to_string(), "EEC_INITIATED".to_string()]
        );
        // A scenario needing the source-side context push is dropped.
        assert_eq!(
            select_acr_scenarios(Some(&[
                "SOURCE_EES_EXECUTED".to_string(),
                "EEC_INITIATED".to_string()
            ])),
            vec!["EEC_INITIATED".to_string()]
        );
        // Nothing in common: an empty list, which the handler must not dress up
        // as a selection.
        assert!(select_acr_scenarios(Some(&["SOURCE_EES_EXECUTED".to_string()])).is_empty());
        // Nothing asked for: the EES's full supported set.
        assert_eq!(
            select_acr_scenarios(None).len(),
            EES_SUPPORTED_ACR_SCENARIOS.len()
        );
    }

    /// The advertised set must not include a scenario whose execution path is
    /// missing. Pinned as a test because the tempting "complete" list is the
    /// whole enumeration.
    #[test]
    fn unsupported_acr_scenarios_are_not_advertised() {
        for never in ["EEC_EXECUTED_VIA_SOURCE_EES", "SOURCE_EES_EXECUTED"] {
            assert!(
                !EES_SUPPORTED_ACR_SCENARIOS.contains(&never),
                "{never} needs a source-side EEC-context push, which this EES does not have"
            );
        }
        assert!(EES_SUPPORTED_ACR_SCENARIOS.contains(&"EEL_MANAGED_ACR"));
    }

    /// The request body parses from the spec spelling, including members this
    /// EES does not model (which must be ignored, not rejected).
    #[test]
    fn eas_info_prov_req_parses_the_spec_spelling() {
        let body = r#"{
            "eecId": "eec-1",
            "acId": "ac-1",
            "selEasIds": ["eas1.example.com"],
            "reqType": "ACR_SCENARIO_SELECTION_REQUEST",
            "selAcrScenarios": ["EEC_INITIATED"],
            "appGrpId": "grp-1",
            "dnais": ["dnai-1"],
            "svcArea": [{"geographicAreas": []}]
        }"#;
        let req: EasInfoProvReq = serde_json::from_str(body).expect("parses");
        assert_eq!(req.eec_id.as_deref(), Some("eec-1"));
        assert_eq!(req.req_type.as_deref(), Some(REQ_TYPE_ACR_REQUEST));
        assert_eq!(
            req.sel_acr_scenarios.as_deref(),
            Some(&["EEC_INITIATED".to_string()][..])
        );
    }

    /// The response serialises under the camelCase names the yaml uses. Asserted
    /// on the TEXT: a round trip of our own struct passes even when every field
    /// name is wrong.
    #[test]
    fn eas_info_prov_resp_uses_the_yaml_member_names() {
        let resp = EasInfoProvResp {
            sel_acr_scenario_list: Some(vec!["EEC_INITIATED".to_string()]),
            ..Default::default()
        };
        let json = serde_json::to_string(&resp).expect("json");
        assert!(
            json.contains("\"selAcrScenarioList\""),
            "expected the yaml spelling, got {json}"
        );
        // Absent members are omitted, not sent as null.
        assert!(!json.contains("instEasInfo"), "got {json}");
        assert!(!json.contains("null"), "got {json}");
    }

    /// `UeIdInfo` serialises `ueIds` / `edgeUeId` per the yaml, and omits the
    /// `afSpecUeId` this EES does not resolve.
    #[test]
    fn ue_id_info_uses_the_yaml_member_names() {
        let info = UeIdInfo {
            ue_ids: vec![UeId {
                edge_ue_id: Some("deadbeef".into()),
                af_spec_ue_id: None,
                eas_id: Some("eas1".into()),
            }],
            supp_feat: None,
        };
        let json = serde_json::to_string(&info).expect("json");
        assert!(json.contains("\"ueIds\""), "got {json}");
        assert!(json.contains("\"edgeUeId\""), "got {json}");
        assert!(
            !json.contains("afSpecUeId"),
            "a GPSI this EES never resolved must not be echoed as one: {json}"
        );
    }
}
