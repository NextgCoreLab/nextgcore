//! MB-SMF SBI data model (TS 29.532 Nmbsmf_MBSSession / TS 29.571)
//!
//! Spec-shaped serde models for the Nmbsmf_MBSSession service, replacing the
//! previous ad-hoc top-level JSON reads:
//!
//! - [`MbsSessionId`] — TMGI and/or SSM choice (TS 29.571 `MbsSessionId`,
//!   TS 29.532 §6.2.3.3). [mbsmfd-07]
//! - [`CreateReqData`] / [`CreateRspData`] wrapping [`ExtMbsSession`] and reading
//!   `mbsSession.serviceType` (TS 29.532 §6.2.6.2.2/3, §6.2.6.4.1). [mbsmfd-06]
//! - [`PatchItem`] / [`PatchData`] for the MBS session PATCH operation
//!   (TS 29.532 §5.3.2.3). [mbsmfd-08]

use serde::{Deserialize, Serialize};

/// MBS Service Type (TS 29.571 `MbsServiceType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MbsServiceType {
    #[serde(rename = "MULTICAST")]
    Multicast,
    #[serde(rename = "BROADCAST")]
    Broadcast,
}

/// PLMN Id (TS 29.571 `PlmnId`): MCC + MNC as decimal-digit strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// TMGI — Temporary Mobile Group Identity (TS 29.571 `Tmgi`).
///
/// `mbsServiceId` is a 6 hex-digit string (3 octets); `plmnId` is the owning
/// PLMN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tmgi {
    /// MBS Service ID — 6 hex digits per TS 29.571 (pattern `^[0-9A-Fa-f]{6}$`).
    pub mbs_service_id: String,
    pub plmn_id: PlmnId,
}

impl Tmgi {
    /// Decode the 6 hex-digit `mbsServiceId` into its 3-octet binary form.
    ///
    /// Invalid / short input is zero-padded and truncated to 3 octets so a
    /// malformed service id can never panic the resolver.
    pub fn service_id_bytes(&self) -> [u8; 3] {
        let mut out = [0u8; 3];
        if let Ok(bytes) = hex::decode(&self.mbs_service_id) {
            for (i, b) in bytes.iter().take(3).enumerate() {
                out[i] = *b;
            }
        }
        out
    }
}

/// IP address (TS 29.571 `IpAddr`): a choice of IPv4 or IPv6 textual form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IpAddr {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_addr: Option<String>,
}

/// Source-specific multicast address (TS 29.571 `Ssm`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ssm {
    pub source_ip_addr: IpAddr,
    pub dest_ip_addr: IpAddr,
}

/// MBS Session Id (TS 29.571 `MbsSessionId`): a TMGI and/or SSM.
///
/// At least one of `tmgi` / `ssm` is present per spec; both forms round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MbsSessionId {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmgi: Option<Tmgi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssm: Option<Ssm>,
}

/// Extended MBS Session (TS 29.532 §6.2.6.4.1 `ExtMbsSession`), the
/// `MbsSession` (TS 29.571) plus MB-SMF extensions.
///
/// Only the fields this bounded chunk reads/echoes are modelled; unknown
/// fields are ignored on decode (no `deny_unknown_fields`).
/// A TS 29.571 `TunnelAddress`: `portNumber` plus one of `ipv4Addr`/`ipv6Addr`
/// (#76).
///
/// `ingressTunAddr` is an ARRAY of these, `readOnly`, `minItems: 1` — not a
/// scalar. The create response used to emit `format!("{:#010x}", gtp_teid)`, i.e. a
/// hex TEID string where a structured address is required, so a conformant consumer
/// could not parse the one member of the response it actually needs to send traffic
/// to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TunnelAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_addr: Option<String>,
    /// `required` in TS 29.571, so never skipped.
    pub port_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExtMbsSession {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbs_session_id: Option<MbsSessionId>,
    /// `serviceType` of type `MbsServiceType` (the spec field name — the audit
    /// text's `mbsServiceType` was wrong).
    ///
    /// **`required` in TS 29.571's `MbsSession`.** It used to be defaulted to
    /// `Multicast` when absent (`_ => Multicast`), so a request that omitted a
    /// mandatory IE was accepted and silently became a multicast session (#76).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<MbsServiceType>,
    /// `tmgiAllocReq`: the consumer asks the MB-SMF to allocate a TMGI. TS 29.571
    /// makes `MbsSession` `anyOf [mbsSessionId, tmgiAllocReq]`, so this is the other
    /// legal way to identify a create (#76).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmgi_alloc_req: Option<bool>,
    /// `ingressTunAddrReq`: the consumer asks for ingress tunnel information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_tun_addr_req: Option<bool>,
    /// `ingressTunAddr`: an ARRAY of structured tunnel addresses, `readOnly` (#76).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_tun_addr: Option<Vec<TunnelAddress>>,
    /// `ssm`: source-specific multicast identification, `writeOnly` (#76). Stored so
    /// an SSM-identified session round-trips.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssm: Option<Ssm>,
    /// `mbsServiceArea`, `writeOnly` (#76). Kept as the raw value: the shape is a
    /// union of NCGI and TAI lists, and re-modelling it here without a consumer for
    /// every member would be a model that reads as enforced and is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbs_service_area: Option<serde_json::Value>,
    /// `mbsServInfo` — MBS service information carrying the QoS request (#76).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbs_serv_info: Option<serde_json::Value>,
    /// `activityStatus`, from `MbsSession` (#76). Driven by PATCH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_status: Option<String>,
    /// `mbsSecurityContext` from `MbsSessionExtension`
    /// (TS29532_Nmbsmf_MBSSession.yaml:809-828), #76.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbs_security_context: Option<serde_json::Value>,
    /// `contactPcfInd` from `MbsSessionExtension`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_pcf_ind: Option<bool>,
    /// `areaSessionPolicyId` from `MbsSessionExtension`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub area_session_policy_id: Option<u32>,
}

/// CreateReqData (TS 29.532 §6.2.6.2.2): MBS session creation request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateReqData {
    pub mbs_session: ExtMbsSession,
}

/// CreateRspData (TS 29.532 §6.2.6.2.3): MBS session creation response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateRspData {
    pub mbs_session: ExtMbsSession,
}

/// JSON Patch operation (RFC 6902) used by the MBS session PATCH
/// (TS 29.532 §5.3.2.3 `PatchItem`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchItem {
    pub op: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// PatchData — the PATCH body is an array of [`PatchItem`] (TS 29.532
/// §5.3.2.3).
pub type PatchData = Vec<PatchItem>;

/// Outcome of applying a [`PatchData`] to a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOutcome {
    /// Patch applied; respond 204 No Content (TS 29.532 §5.3.2.3).
    NoContent,
    /// MBS service area reduced; respond 200 + `redMbsServArea` carrying the
    /// resulting (reduced) area value.
    ReducedArea(serde_json::Value),
}

/// What a [`PatchData`] changed, beyond the service area (#76).
///
/// Returned alongside the outcome so the caller persists exactly what the patch
/// touched. An `Option` per member rather than a bool: "the patch did not mention
/// activityStatus" and "the patch set it to something" are different, and collapsing
/// them would have an unrelated patch reset a session's activity status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchChanges {
    /// New `activityStatus`, when the patch set one.
    pub activity_status: Option<String>,
    /// New `mbsServInfo` (the QoS request), when the patch set one.
    pub mbs_serv_info: Option<serde_json::Value>,
    /// New `mbsSecurityContext`, when the patch set one.
    pub mbs_security_context: Option<serde_json::Value>,
}

impl PatchChanges {
    /// Whether the patch changed anything this MB-SMF models.
    pub fn is_empty(&self) -> bool {
        self.activity_status.is_none()
            && self.mbs_serv_info.is_none()
            && self.mbs_security_context.is_none()
    }
}

/// Apply a [`PatchData`] to the session's modifiable attributes.
///
/// # What #76 changed
///
/// This used to inspect **only** paths beginning `/mbsServiceArea` and return
/// `ReducedArea` for *any* operation on one — including an `add`. TS 29.532 §5.3.2.3
/// gives the `200` + `redMbsServArea` body to a service-area **reduction**: it is
/// the MB-SMF telling the consumer which part of the requested area it could not
/// serve. Returning it for an addition tells the consumer its enlarged area was cut
/// back to exactly what it asked for, which is a different and confusing statement.
/// So the outcome now depends on the RFC 6902 `op`: `remove` and `replace` can
/// reduce, `add` cannot.
///
/// `activityStatus`, `mbsServInfo` (QoS) and `mbsSecurityContext` are now applied
/// too; they were silently ignored, so a PATCH activating a session answered `204`
/// and changed nothing.
pub fn apply_patch_data(
    patch: &PatchData,
    tacs: &mut Vec<u32>,
    changes: &mut PatchChanges,
) -> PatchOutcome {
    let mut reduced: Option<serde_json::Value> = None;
    for item in patch {
        // RFC 6902 ops this MB-SMF acts on. `move`/`copy`/`test` are accepted and
        // ignored rather than refused: refusing a legal op would reject a conformant
        // patch, and acting on one whose semantics need a source document we do not
        // keep would be inventing behaviour.
        let is_removal = item.op == "remove";
        let is_set = item.op == "add" || item.op == "replace";

        if item.path.starts_with("/mbsServiceArea") {
            if let Some(value) = &item.value {
                // Persist any TAC list carried in the new service area so a
                // subsequent GET reflects the change.
                if let Some(arr) = value.as_array() {
                    *tacs = arr
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u32))
                        .collect();
                }
                // Only a reduction gets the 200 + redMbsServArea body.
                if item.op == "replace" || is_removal {
                    reduced = Some(value.clone());
                }
            } else if is_removal {
                // `remove` with no value: the whole area went away, which is the
                // maximal reduction.
                tacs.clear();
                reduced = Some(serde_json::Value::Array(Vec::new()));
            }
            continue;
        }

        if !is_set {
            continue;
        }
        let Some(value) = &item.value else { continue };
        match item.path.as_str() {
            "/activityStatus" => {
                if let Some(status) = value.as_str() {
                    changes.activity_status = Some(status.to_string());
                }
            }
            "/mbsServInfo" => changes.mbs_serv_info = Some(value.clone()),
            "/mbsSecurityContext" => changes.mbs_security_context = Some(value.clone()),
            other => log::debug!("MBS session PATCH: path '{other}' is not modelled; ignored"),
        }
    }
    match reduced {
        Some(value) => PatchOutcome::ReducedArea(value),
        None => PatchOutcome::NoContent,
    }
}

// ---------------------------------------------------------------------------
// mbsmfd-03: ContextUpdate service operation (TS 29.532 §5.3.2.5, §6.2.6.2.5/6)
// ---------------------------------------------------------------------------

/// ContextUpdateAction (TS 29.532 §6.2.6.3.3) — START or TERMINATE MBS data
/// reception. Modelled `anyOf` (the spec allows an open string), so any
/// unrecognized value decodes to [`ContextUpdateAction::Unknown`] rather than
/// failing the request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ContextUpdateAction {
    #[serde(rename = "START")]
    Start,
    #[serde(rename = "TERMINATE")]
    Terminate,
    #[serde(other)]
    Unknown,
}

/// RefToBinaryData (TS 29.571) — a `contentId` referencing a multipart binary
/// part (e.g. the NGAP container of an [`N2MbsSmInfo`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RefToBinaryData {
    pub content_id: String,
}

/// NgapIeType (TS29532_Nmbsmf_MBSSession.yaml:1172-1181) — the type of NGAP
/// IE carried in an [`N2MbsSmInfo`] binary part.
///
/// Direction matters (TS 29.532 §5.3.2.5): the AMF *request* carries
/// `MBS_DIS_SETUP_REQ` / `MBS_DIS_REL_REQ` (TS 38.413 §9.3.5.7/§9.3.5.10);
/// the MB-SMF *response* carries `MBS_DIS_SETUP_RSP` or `MBS_DIS_SETUP_FAIL`
/// (§9.3.5.8/§9.3.5.9). Modelled `anyOf` per the yaml: unknown strings decode
/// to [`NgapIeType::Unknown`] (tolerant deserialize) and are rejected
/// fail-closed with 400 on the AMF handling path. [G1-2]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NgapIeType {
    #[serde(rename = "MBS_DIS_SETUP_REQ")]
    MbsDisSetupReq,
    #[serde(rename = "MBS_DIS_SETUP_RSP")]
    MbsDisSetupRsp,
    #[serde(rename = "MBS_DIS_SETUP_FAIL")]
    MbsDisSetupFail,
    #[serde(rename = "MBS_DIS_REL_REQ")]
    MbsDisRelReq,
    /// Any other string (the yaml `anyOf` open extension): tolerated on
    /// decode, never emitted, rejected when handled.
    #[serde(other, rename = "UNKNOWN")]
    Unknown,
}

/// N2MbsSmInfo (TS 29.532 §6.2.6.2.9) — the N2 (NGAP) MBS session-management
/// container exchanged with the AMF for shared MBS distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2MbsSmInfo {
    /// Typed [`NgapIeType`]; request vs response direction is enforced by the
    /// ContextUpdate handler. [G1-2]
    pub ngap_ie_type: NgapIeType,
    pub ngap_data: RefToBinaryData,
}

/// ContextUpdateReqData (TS 29.532 §6.2.6.2.5) — the ContextUpdate request body.
///
/// `nfcInstanceId` + `mbsSessionId` are mandatory. The SMF path carries
/// `requestedAction` (and optionally `dlTunnelInfo` for unicast individual
/// delivery); the AMF path carries `ranNodeId` + `n2MbsSmInfo`. Unknown fields
/// are ignored on decode.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextUpdateReqData {
    pub nfc_instance_id: String,
    #[serde(default)]
    pub mbs_session_id: MbsSessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area_session_id: Option<serde_json::Value>,
    #[serde(default)]
    pub requested_action: Option<ContextUpdateAction>,
    /// `dlTunnelInfo` (`Bytes`, base64): a SMF DL GTP-U F-TEID for unicast
    /// individual MBS delivery; absent ⇒ multicast (the MB-SMF allocates a
    /// `cTeid` + `llSsm`).
    #[serde(default)]
    pub dl_tunnel_info: Option<String>,
    #[serde(default)]
    pub n2_mbs_sm_info: Option<N2MbsSmInfo>,
    #[serde(default)]
    pub ran_node_id: Option<serde_json::Value>,
    #[serde(default)]
    pub leave_ind: Option<bool>,
}

/// ContextUpdateRspData (TS 29.532 §6.2.6.2.6) — the ContextUpdate response body.
///
/// On a multicast Start the MB-SMF returns the allocated `cTeid` (GTP-U common
/// TEID, `Uint32`) + `llSsm` (lower-layer source-specific multicast address); on
/// the AMF path it returns the `n2MbsSmInfo` container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ContextUpdateRspData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ll_ssm: Option<Ssm>,
    /// `cTeid` is a `Uint32` per TS 29.532 (an integer, not a hex string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_teid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n2_mbs_sm_info: Option<N2MbsSmInfo>,
}

// ---------------------------------------------------------------------------
// mbsmfd-04: Nmbsmf_TMGI service (TS 29.532 §5.2, TS29532_Nmbsmf_TMGI.yaml)
// ---------------------------------------------------------------------------

/// TmgiAllocate (TS 29.532 §6.x, `TS29532_Nmbsmf_TMGI.yaml`) — the Allocate
/// request body: `tmgiNumber` new TMGIs to allocate and/or a `tmgiList` to
/// refresh.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TmgiAllocate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmgi_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmgi_list: Option<Vec<Tmgi>>,
}

/// TmgiAllocated (TS 29.532) — the Allocate 200 response: the allocated/refreshed
/// `tmgiList` plus one common `expirationTime`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TmgiAllocated {
    pub tmgi_list: Vec<Tmgi>,
    pub expiration_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nid: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- mbsmfd-07: MbsSessionId TMGI/SSM serde ----

    #[test]
    fn test_mbs_session_id_tmgi_roundtrip() {
        let id = MbsSessionId {
            tmgi: Some(Tmgi {
                mbs_service_id: "010203".to_string(),
                plmn_id: PlmnId {
                    mcc: "001".to_string(),
                    mnc: "01".to_string(),
                },
            }),
            ssm: None,
        };
        let json = serde_json::to_string(&id).unwrap();
        // TMGI nested under mbsSessionId.tmgi, camelCase field names.
        assert!(json.contains("\"tmgi\""));
        assert!(json.contains("\"mbsServiceId\":\"010203\""));
        assert!(json.contains("\"plmnId\""));
        assert!(!json.contains("ssm"));
        let back: MbsSessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
        assert_eq!(back.tmgi.unwrap().service_id_bytes(), [0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_mbs_session_id_ssm_roundtrip() {
        let json = r#"{"ssm":{"sourceIpAddr":{"ipv4Addr":"10.1.1.1"},"destIpAddr":{"ipv4Addr":"232.0.0.1"}}}"#;
        let id: MbsSessionId = serde_json::from_str(json).unwrap();
        assert!(id.tmgi.is_none());
        let ssm = id.ssm.clone().unwrap();
        assert_eq!(ssm.source_ip_addr.ipv4_addr.as_deref(), Some("10.1.1.1"));
        assert_eq!(ssm.dest_ip_addr.ipv4_addr.as_deref(), Some("232.0.0.1"));
        // Round-trip back.
        let reser = serde_json::to_string(&id).unwrap();
        let back: MbsSessionId = serde_json::from_str(&reser).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn test_mbs_session_id_both_roundtrip() {
        let json = r#"{
            "tmgi":{"mbsServiceId":"0a0b0c","plmnId":{"mcc":"001","mnc":"01"}},
            "ssm":{"sourceIpAddr":{"ipv4Addr":"10.1.1.1"},"destIpAddr":{"ipv4Addr":"232.0.0.1"}}
        }"#;
        let id: MbsSessionId = serde_json::from_str(json).unwrap();
        assert!(id.tmgi.is_some());
        assert!(id.ssm.is_some());
        let back: MbsSessionId =
            serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap();
        assert_eq!(back, id);
    }

    // ---- mbsmfd-06: CreateReqData / CreateRspData + serviceType ----

    #[test]
    fn test_create_req_data_service_type_multicast() {
        let json = r#"{
            "mbsSession":{
                "serviceType":"MULTICAST",
                "mbsSessionId":{"tmgi":{"mbsServiceId":"010203","plmnId":{"mcc":"001","mnc":"01"}}}
            }
        }"#;
        let req: CreateReqData = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.mbs_session.service_type,
            Some(MbsServiceType::Multicast)
        );
        assert_eq!(
            req.mbs_session
                .mbs_session_id
                .as_ref()
                .and_then(|i| i.tmgi.as_ref())
                .map(|t| t.service_id_bytes()),
            Some([0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn test_create_req_data_service_type_broadcast() {
        let json = r#"{"mbsSession":{"serviceType":"BROADCAST"}}"#;
        let req: CreateReqData = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.mbs_session.service_type,
            Some(MbsServiceType::Broadcast)
        );
    }

    #[test]
    fn test_create_rsp_data_roundtrip() {
        let rsp = CreateRspData {
            mbs_session: ExtMbsSession {
                mbs_session_id: Some(MbsSessionId {
                    tmgi: Some(Tmgi {
                        mbs_service_id: "010203".to_string(),
                        plmn_id: PlmnId {
                            mcc: "001".to_string(),
                            mnc: "01".to_string(),
                        },
                    }),
                    ssm: None,
                }),
                service_type: Some(MbsServiceType::Multicast),
                // #76: an ARRAY of structured TunnelAddress, not a hex TEID string.
                ingress_tun_addr: Some(vec![TunnelAddress {
                    ipv4_addr: Some("10.0.0.1".to_string()),
                    ipv6_addr: None,
                    port_number: 2152,
                }]),
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&rsp).unwrap();
        assert!(json.contains("\"mbsSession\""));
        assert!(json.contains("\"serviceType\":\"MULTICAST\""));
        // The structured address must serialise as TS 29.571 declares it: an object
        // with `portNumber` (required) and one of the address members.
        assert!(
            json.contains("\"ingressTunAddr\":[{\"ipv4Addr\":\"10.0.0.1\",\"portNumber\":2152}]"),
            "got {json}"
        );
        // The 201 body deserializes back as CreateRspData.
        let back: CreateRspData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rsp);
    }

    // ---- mbsmfd-08: PatchData 204 / reduced-area 200 ----

    fn patch_of(json: &str) -> (PatchOutcome, Vec<u32>, PatchChanges) {
        let patch: PatchData = serde_json::from_str(json).unwrap();
        let mut tacs = vec![];
        let mut changes = PatchChanges::default();
        let outcome = apply_patch_data(&patch, &mut tacs, &mut changes);
        (outcome, tacs, changes)
    }

    #[test]
    fn test_patch_data_no_content() {
        let (outcome, tacs, changes) =
            patch_of(r#"[{"op":"replace","path":"/mbsServiceInfo","value":{"5qi":9}}]"#);
        assert_eq!(outcome, PatchOutcome::NoContent);
        assert!(tacs.is_empty());
        // `/mbsServiceInfo` is not the spec's `/mbsServInfo`, so nothing is applied.
        assert!(changes.is_empty());
    }

    #[test]
    fn test_patch_data_reduced_area() {
        let (outcome, tacs, _) =
            patch_of(r#"[{"op":"replace","path":"/mbsServiceArea","value":[1,2,3]}]"#);
        match outcome {
            PatchOutcome::ReducedArea(v) => {
                assert_eq!(v, serde_json::json!([1, 2, 3]));
            }
            other => panic!("expected ReducedArea, got {other:?}"),
        }
        assert_eq!(tacs, vec![1, 2, 3]);
    }

    /// #76 criterion 8, the half that was wrong in a way a consumer would act on: an
    /// `add` to the service area is NOT a reduction.
    ///
    /// TS 29.532 §5.3.2.3 gives the `200` + `redMbsServArea` body to a reduction — it
    /// is the MB-SMF saying which part of the requested area it could not serve.
    /// Returning it for an addition tells the consumer its enlarged area was cut back
    /// to exactly what it asked for, which is a different statement and one it may
    /// act on by re-requesting.
    #[test]
    fn an_added_service_area_is_not_reported_as_a_reduction() {
        let (outcome, tacs, _) =
            patch_of(r#"[{"op":"add","path":"/mbsServiceArea","value":[7,8]}]"#);
        assert_eq!(
            outcome,
            PatchOutcome::NoContent,
            "an addition answers 204, not 200 + redMbsServArea"
        );
        assert_eq!(tacs, vec![7, 8], "but the new area is still persisted");

        // `replace` and `remove` can reduce, and both do report it.
        let (outcome, _, _) =
            patch_of(r#"[{"op":"replace","path":"/mbsServiceArea","value":[7]}]"#);
        assert!(matches!(outcome, PatchOutcome::ReducedArea(_)));
        let (outcome, tacs, _) = patch_of(r#"[{"op":"remove","path":"/mbsServiceArea"}]"#);
        assert_eq!(outcome, PatchOutcome::ReducedArea(serde_json::json!([])));
        assert!(tacs.is_empty(), "removing the area clears the TAC list");
    }

    /// #76 criterion 8: `activityStatus`, QoS and security are APPLIED, not ignored.
    #[test]
    fn activity_status_qos_and_security_are_applied_rather_than_acknowledged() {
        let (outcome, _, changes) = patch_of(
            r#"[{"op":"replace","path":"/activityStatus","value":"ACTIVE"},
                 {"op":"replace","path":"/mbsServInfo","value":{"mbsQoSReq":{"5qi":7}}},
                 {"op":"add","path":"/mbsSecurityContext","value":{"keyList":["k1"]}}]"#,
        );
        assert_eq!(
            outcome,
            PatchOutcome::NoContent,
            "none of these is a service-area reduction"
        );
        assert_eq!(changes.activity_status.as_deref(), Some("ACTIVE"));
        assert_eq!(
            changes
                .mbs_serv_info
                .as_ref()
                .and_then(|v| v.pointer("/mbsQoSReq/5qi"))
                .and_then(serde_json::Value::as_u64),
            Some(7)
        );
        assert!(changes.mbs_security_context.is_some());
        assert!(!changes.is_empty());

        // An unmodelled path changes nothing rather than being refused: refusing a
        // legal RFC 6902 op would reject a conformant patch.
        let (_, _, changes) = patch_of(r#"[{"op":"replace","path":"/somethingElse","value":1}]"#);
        assert!(changes.is_empty());

        // A `test` op is accepted and applies nothing.
        let (_, _, changes) =
            patch_of(r#"[{"op":"test","path":"/activityStatus","value":"ACTIVE"}]"#);
        assert!(
            changes.is_empty(),
            "a `test` op must not be treated as a set"
        );
    }

    // ---- mbsmfd-03: ContextUpdate serde ----

    #[test]
    fn test_context_update_req_smf_start() {
        // SMF Start with no dlTunnelInfo => multicast (MB-SMF allocates).
        let json = r#"{
            "nfcInstanceId":"smf-1",
            "mbsSessionId":{"tmgi":{"mbsServiceId":"010203","plmnId":{"mcc":"001","mnc":"01"}}},
            "requestedAction":"START"
        }"#;
        let req: ContextUpdateReqData = serde_json::from_str(json).unwrap();
        assert_eq!(req.nfc_instance_id, "smf-1");
        assert_eq!(req.requested_action, Some(ContextUpdateAction::Start));
        assert!(req.dl_tunnel_info.is_none());
        assert!(req.ran_node_id.is_none());
        assert_eq!(
            req.mbs_session_id
                .tmgi
                .as_ref()
                .map(|t| t.service_id_bytes()),
            Some([0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn test_context_update_req_amf_n2() {
        // AMF request carries ranNodeId + n2MbsSmInfo.
        let json = r#"{
            "nfcInstanceId":"amf-1",
            "mbsSessionId":{"tmgi":{"mbsServiceId":"0a0b0c","plmnId":{"mcc":"001","mnc":"01"}}},
            "ranNodeId":{"gNbId":{"bitLength":24,"gNBValue":"000001"}},
            "n2MbsSmInfo":{"ngapIeType":"MBS_DIS_SETUP_REQ","ngapData":{"contentId":"n2"}}
        }"#;
        let req: ContextUpdateReqData = serde_json::from_str(json).unwrap();
        assert!(req.ran_node_id.is_some());
        let n2 = req.n2_mbs_sm_info.unwrap();
        assert_eq!(n2.ngap_ie_type, NgapIeType::MbsDisSetupReq);
        assert_eq!(n2.ngap_data.content_id, "n2");
    }

    // ---- G1-2: NgapIeType serde matches TS29532_Nmbsmf_MBSSession.yaml:1177-1180 ----

    #[test]
    fn test_ngap_ie_type_serde_matches_yaml() {
        // Serialized tokens are exactly the yaml enum values.
        for (variant, token) in [
            (NgapIeType::MbsDisSetupReq, "\"MBS_DIS_SETUP_REQ\""),
            (NgapIeType::MbsDisSetupRsp, "\"MBS_DIS_SETUP_RSP\""),
            (NgapIeType::MbsDisSetupFail, "\"MBS_DIS_SETUP_FAIL\""),
            (NgapIeType::MbsDisRelReq, "\"MBS_DIS_REL_REQ\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), token);
            let back: NgapIeType = serde_json::from_str(token).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn test_ngap_ie_type_unknown_tolerated_on_decode() {
        // yaml models NgapIeType as anyOf { enum, string }: an unrecognized
        // string must decode (to Unknown), not fail the whole request parse.
        let back: NgapIeType = serde_json::from_str("\"FUTURE_IE_TYPE\"").unwrap();
        assert_eq!(back, NgapIeType::Unknown);
    }

    #[test]
    fn test_context_update_action_unknown_is_lenient() {
        let json = r#"{"nfcInstanceId":"x","mbsSessionId":{},"requestedAction":"FUTURE_OP"}"#;
        let req: ContextUpdateReqData = serde_json::from_str(json).unwrap();
        assert_eq!(req.requested_action, Some(ContextUpdateAction::Unknown));
    }

    #[test]
    fn test_context_update_rsp_roundtrip() {
        let rsp = ContextUpdateRspData {
            ll_ssm: Some(Ssm {
                source_ip_addr: IpAddr {
                    ipv4_addr: Some("10.0.0.7".to_string()),
                    ipv6_addr: None,
                },
                dest_ip_addr: IpAddr {
                    ipv4_addr: Some("239.1.0.1".to_string()),
                    ipv6_addr: None,
                },
            }),
            c_teid: Some(0x0BCA_0001),
            n2_mbs_sm_info: None,
        };
        let json = serde_json::to_string(&rsp).unwrap();
        // cTeid serializes as an integer (Uint32), not a string.
        assert!(json.contains(&format!("\"cTeid\":{}", 0x0BCA_0001u32)));
        assert!(
            !json.contains("\"cTeid\":\""),
            "cTeid is an integer, not a string"
        );
        assert!(json.contains("\"llSsm\""));
        let back: ContextUpdateRspData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rsp);
    }

    // ---- mbsmfd-04: Nmbsmf_TMGI serde ----

    #[test]
    fn test_tmgi_allocate_request_parse() {
        let json = r#"{"tmgiNumber":3}"#;
        let req: TmgiAllocate = serde_json::from_str(json).unwrap();
        assert_eq!(req.tmgi_number, Some(3));
        assert!(req.tmgi_list.is_none());
    }

    #[test]
    fn test_tmgi_allocated_roundtrip() {
        let rsp = TmgiAllocated {
            tmgi_list: vec![Tmgi {
                mbs_service_id: "000001".to_string(),
                plmn_id: PlmnId {
                    mcc: "001".to_string(),
                    mnc: "01".to_string(),
                },
            }],
            expiration_time: "2026-06-28T00:00:00Z".to_string(),
            nid: None,
        };
        let json = serde_json::to_string(&rsp).unwrap();
        assert!(json.contains("\"tmgiList\""));
        assert!(json.contains("\"expirationTime\":\"2026-06-28T00:00:00Z\""));
        let back: TmgiAllocated = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rsp);
    }
}
