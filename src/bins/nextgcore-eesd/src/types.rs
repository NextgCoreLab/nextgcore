//! EES Edge Enabler Layer data model (TS 29.558 / TS 24.558).
//!
//! camelCase serde structs for the `eees-easregistration` service API. These
//! replace the bespoke flat JSON shape the EES previously parsed. Field naming
//! follows `TS29558_Eees_EASRegistration.yaml`.
//!
//! Scope note (bounded chunk eesd-02/03): the EAS Registration data model is
//! implemented here. The full fidelity of `ServiceArea` (TS 29.558
//! GeographicalServiceArea) and the discovery request/response model
//! (`EasDiscoveryReq`/`EasDiscoveryResp`, eesd-05) are intentionally DEFERRED;
//! nested geo/cell structures are carried as passthrough `serde_json::Value`.

use serde::{Deserialize, Serialize};

/// TS 29.558 §8.1.5.2.2 `EASRegistration`.
///
/// `easProf` is mandatory; `expTime` and `suppFeat` are optional/conditional.
/// `registrationId` is a server-assigned, read-only resource identifier
/// (TS 29.558 §5.2.2.2) carried in the response body and `Location` header — it
/// is distinct from the consumer-provided immutable `easProf.easId` (eesd-03).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasRegistration {
    /// EAS profile (mandatory).
    pub eas_prof: EasProfile,
    /// Registration expiration time (optional; absent ⇒ never expires).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features bitmask string (conditional, TS 29.558 §7.8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
    /// Server-minted resource identifier (read-only; never supplied by the
    /// consumer). Populated on registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
}

/// TS 29.558 §8.1.5.2.3 `EASProfile`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasProfile {
    /// EAS application identifier (URI/FQDN). Mandatory, consumer-provided,
    /// immutable (TS 29.558 §8.1.5.2.3, lines 6953-6956).
    pub eas_id: String,
    /// EAS endpoint (mandatory).
    pub end_pt: EndPoint,
    /// EAS provider identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov_id: Option<String>,
    /// EAS category/type (optional). Wire field name is `type`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub eas_type: Option<String>,
    /// Vendor-specific flexible EAS type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flex_eas_type: Option<String>,
    /// Application client identifiers served by this EAS (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_ids: Option<Vec<String>>,
    /// Service area the EAS serves (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svc_area: Option<ServiceArea>,
    /// Service KPIs (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svc_kpi: Option<EasServiceKpi>,
}

/// Common `EndPoint` type (TS 29.558). One of `uri`/`fqdn`/`ipv4Addrs`/
/// `ipv6Addrs` must be present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EndPoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
}

impl EndPoint {
    /// True when no address form (uri/fqdn/ipv4/ipv6) is set — an `EndPoint`
    /// that carries no reachable address is not a valid mandatory IE.
    pub fn is_empty(&self) -> bool {
        self.uri.is_none()
            && self.fqdn.is_none()
            && self.ipv4_addrs.as_ref().is_none_or(|v| v.is_empty())
            && self.ipv6_addrs.as_ref().is_none_or(|v| v.is_empty())
    }
}

/// `EASServiceKPI` (TS 29.558 §8.1.5.x) — a representative subset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EasServiceKpi {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_req_rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_resp_time: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<u32>,
    /// Available compute (TS 29.558 `avlComp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_comp: Option<u32>,
    /// Available graphical compute (`avlGraComp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_gra_comp: Option<u32>,
    /// Available memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_mem: Option<u32>,
    /// Available storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_stor: Option<u32>,
    /// Connection bandwidth (`BitRate` string, e.g. "100 Mbps").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub con_bdwth: Option<String>,
}

/// `ServiceArea` (TS 29.558) — simplified subset. The full GeographicalService
/// Area / Ncgi / Tai models are DEFERRED (eesd-05/13); nested entries are
/// carried as passthrough JSON values to preserve the wire body losslessly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServiceArea {
    /// Tracking Area Identities (passthrough; full `Tai` model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tais: Option<Vec<serde_json::Value>>,
    /// NR Cell Global Identities (passthrough; full `Ncgi` model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ncgis: Option<Vec<serde_json::Value>>,
    /// Geographic area (passthrough; full `GeographicArea` model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_area: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OpenAPI example body (eesd-02 acceptance) round-trips and exposes
    /// the mandatory `easProf.easId` / `easProf.endPt`.
    #[test]
    fn test_eas_registration_deserialize_example() {
        let body = r#"{"easProf":{"easId":"eas1.example.com","endPt":{"fqdn":"eas1.example.com"}}}"#;
        let reg: EasRegistration = serde_json::from_str(body).expect("example deserializes");
        assert_eq!(reg.eas_prof.eas_id, "eas1.example.com");
        assert_eq!(reg.eas_prof.end_pt.fqdn.as_deref(), Some("eas1.example.com"));
        assert!(reg.registration_id.is_none());
    }

    /// A body missing the mandatory `endPt` fails to deserialize (mapped to a
    /// 400 MANDATORY_IE_MISSING by the handler).
    #[test]
    fn test_eas_registration_missing_endpt_fails() {
        let body = r#"{"easProf":{"easId":"eas1.example.com"}}"#;
        assert!(serde_json::from_str::<EasRegistration>(body).is_err());
    }

    /// A body missing the mandatory `easProf` fails to deserialize.
    #[test]
    fn test_eas_registration_missing_easprof_fails() {
        let body = r#"{"expTime":"2026-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<EasRegistration>(body).is_err());
    }

    /// Serialization emits the spec camelCase field names (`easId`, `endPt`,
    /// `type`, `svcKpi`, `registrationId`).
    #[test]
    fn test_eas_registration_roundtrip_camelcase() {
        let reg = EasRegistration {
            eas_prof: EasProfile {
                eas_id: "eas1.example.com".into(),
                end_pt: EndPoint {
                    fqdn: Some("eas1.example.com".into()),
                    ..Default::default()
                },
                prov_id: Some("prov-7".into()),
                eas_type: Some("V2X".into()),
                flex_eas_type: None,
                ac_ids: Some(vec!["ac1".into()]),
                svc_area: None,
                svc_kpi: Some(EasServiceKpi {
                    availability: Some(99),
                    ..Default::default()
                }),
            },
            exp_time: None,
            supp_feat: Some("1".into()),
            registration_id: Some("11111111-2222-3333-4444-555555555555".into()),
        };
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"easId\":\"eas1.example.com\""));
        assert!(json.contains("\"endPt\""));
        assert!(json.contains("\"type\":\"V2X\""));
        assert!(json.contains("\"svcKpi\""));
        assert!(json.contains("\"registrationId\""));
        // Round-trips back to an equal value.
        let back: EasRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }

    #[test]
    fn test_endpoint_is_empty() {
        assert!(EndPoint::default().is_empty());
        assert!(!EndPoint {
            fqdn: Some("x".into()),
            ..Default::default()
        }
        .is_empty());
        assert!(EndPoint {
            ipv4_addrs: Some(vec![]),
            ..Default::default()
        }
        .is_empty());
    }
}
