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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExtMbsSession {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbs_session_id: Option<MbsSessionId>,
    /// `serviceType` of type `MbsServiceType` (the spec field name — the audit
    /// text's `mbsServiceType` was wrong).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<MbsServiceType>,
    /// GTP-U TEID for the multicast ingress, echoed in the create response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_tun_addr: Option<String>,
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

/// Apply a [`PatchData`] to the session's modifiable attributes.
///
/// Returns [`PatchOutcome::ReducedArea`] when the patch touches the MBS service
/// area (path beginning `/mbsServiceArea`), echoing the new area as
/// `redMbsServArea`; otherwise [`PatchOutcome::NoContent`]. The `tacs` sink
/// receives any service-area-derived TAC list so the caller can persist it.
pub fn apply_patch_data(patch: &PatchData, tacs: &mut Vec<u32>) -> PatchOutcome {
    let mut reduced: Option<serde_json::Value> = None;
    for item in patch {
        if item.path.starts_with("/mbsServiceArea") {
            if let Some(value) = &item.value {
                // Persist any TAC list carried in the new service area so a
                // subsequent GET reflects the change.
                if let Some(arr) = value.as_array() {
                    *tacs = arr.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect();
                }
                reduced = Some(value.clone());
            }
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

/// N2MbsSmInfo (TS 29.532 §6.2.6.4) — the N2 (NGAP) MBS session-management
/// container exchanged with the AMF for shared MBS distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct N2MbsSmInfo {
    /// `NgapIeType` (e.g. `MBS_DIS_SETUP_REQ`).
    pub ngap_ie_type: String,
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
        let back: MbsSessionId = serde_json::from_str(&serde_json::to_string(&id).unwrap()).unwrap();
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
        assert_eq!(req.mbs_session.service_type, Some(MbsServiceType::Multicast));
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
        assert_eq!(req.mbs_session.service_type, Some(MbsServiceType::Broadcast));
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
                ingress_tun_addr: Some("0x0bca0001".to_string()),
            },
        };
        let json = serde_json::to_string(&rsp).unwrap();
        assert!(json.contains("\"mbsSession\""));
        assert!(json.contains("\"serviceType\":\"MULTICAST\""));
        // The 201 body deserializes back as CreateRspData.
        let back: CreateRspData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rsp);
    }

    // ---- mbsmfd-08: PatchData 204 / reduced-area 200 ----

    #[test]
    fn test_patch_data_no_content() {
        let json = r#"[{"op":"replace","path":"/mbsServiceInfo","value":{"5qi":9}}]"#;
        let patch: PatchData = serde_json::from_str(json).unwrap();
        let mut tacs = vec![];
        assert_eq!(apply_patch_data(&patch, &mut tacs), PatchOutcome::NoContent);
        assert!(tacs.is_empty());
    }

    #[test]
    fn test_patch_data_reduced_area() {
        let json = r#"[{"op":"replace","path":"/mbsServiceArea","value":[1,2,3]}]"#;
        let patch: PatchData = serde_json::from_str(json).unwrap();
        let mut tacs = vec![];
        match apply_patch_data(&patch, &mut tacs) {
            PatchOutcome::ReducedArea(v) => {
                assert_eq!(v, serde_json::json!([1, 2, 3]));
            }
            other => panic!("expected ReducedArea, got {other:?}"),
        }
        assert_eq!(tacs, vec![1, 2, 3]);
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
            req.mbs_session_id.tmgi.as_ref().map(|t| t.service_id_bytes()),
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
        assert_eq!(n2.ngap_ie_type, "MBS_DIS_SETUP_REQ");
        assert_eq!(n2.ngap_data.content_id, "n2");
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
        assert!(!json.contains("\"cTeid\":\""), "cTeid is an integer, not a string");
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
