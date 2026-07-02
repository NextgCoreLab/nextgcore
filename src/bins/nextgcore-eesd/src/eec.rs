//! EEC Registration data model (EDGE-1, TS 24.558 §5.2 / `Eees_EECRegistration`).
//!
//! eesd-06: the EES exposes the `eees-eecregistration` service API so an Edge
//! Enabler Client can register, update and deregister itself before consuming
//! discovery / ACR services. The resource is identified by a server-minted
//! `registrationId` (distinct from the consumer's immutable `eecId`) and is
//! subject to an `expTime` lifecycle (eesd-12): when the consumer supplies no
//! `expTime`, the EES mints one; lapsed registrations are dropped by the
//! periodic sweep.

use serde::{Deserialize, Serialize};

/// Default validity (seconds) the EES assigns to an EEC registration that
/// arrives without a consumer-supplied `expTime`.
pub const DEFAULT_EEC_REG_LIFETIME_SECS: i64 = 3600;

/// TS 24.558 `EECRegistration` (subset) — body of `CreateEECReg` /
/// `UpdateIndEECReg`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EecRegistration {
    /// Edge Enabler Client identifier (mandatory, consumer-provided, immutable).
    pub eec_id: String,
    /// UE identifier (GPSI, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Application Client profiles served by this EEC (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_profs: Option<Vec<AcProfile>>,
    /// Registration expiration time (RFC 3339). Server-managed: minted when the
    /// consumer omits it (eesd-12).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional, TS 29.558 §7.8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
    /// Server-minted resource identifier (read-only; never supplied by the
    /// consumer). Populated on registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
}

impl EecRegistration {
    /// Validate the mandatory IEs (TS 24.558 §5.2.x). Returns `Err(detail)` when
    /// `eecId` (or any `acProfs[].acId`) is missing/empty.
    pub fn validate(&self) -> Result<(), String> {
        if self.eec_id.trim().is_empty() {
            return Err("Mandatory IE eecId is empty".to_string());
        }
        if let Some(profs) = &self.ac_profs {
            for p in profs {
                if p.ac_id.trim().is_empty() {
                    return Err("Mandatory IE acProfs[].acId is empty".to_string());
                }
            }
        }
        Ok(())
    }
}

/// TS 24.558 `ACProfile` (subset) — an Application Client profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcProfile {
    /// Application Client identifier (mandatory).
    pub ac_id: String,
    /// AC type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_type: Option<String>,
    /// EAS application identifiers the AC connects to (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ids: Option<Vec<String>>,
    /// Expected AC geographical service area (passthrough; full model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expsac_info: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eec_registration_deserialize_example() {
        let body = r#"{"eecId":"eec1.example.com","acProfs":[{"acId":"ac1","acType":"V2X"}]}"#;
        let reg: EecRegistration = serde_json::from_str(body).expect("deserializes");
        assert_eq!(reg.eec_id, "eec1.example.com");
        assert_eq!(reg.ac_profs.as_ref().unwrap()[0].ac_id, "ac1");
        assert!(reg.registration_id.is_none());
        assert!(reg.validate().is_ok());
    }

    #[test]
    fn test_eec_registration_missing_eec_id_fails() {
        // eecId absent → deserialization fails (handler maps to 400).
        let body = r#"{"acProfs":[{"acId":"ac1"}]}"#;
        assert!(serde_json::from_str::<EecRegistration>(body).is_err());
    }

    #[test]
    fn test_eec_registration_empty_eec_id_invalid() {
        let reg = EecRegistration {
            eec_id: "".into(),
            ue_id: None,
            ac_profs: None,
            exp_time: None,
            supp_feat: None,
            registration_id: None,
        };
        assert!(reg.validate().is_err());
    }

    #[test]
    fn test_eec_registration_roundtrip_camelcase() {
        let reg = EecRegistration {
            eec_id: "eec1".into(),
            ue_id: Some("gpsi-12345".into()),
            ac_profs: Some(vec![AcProfile {
                ac_id: "ac1".into(),
                ac_type: Some("V2X".into()),
                eas_ids: Some(vec!["eas1".into()]),
                expsac_info: None,
            }]),
            exp_time: Some("2026-01-01T00:00:00Z".into()),
            supp_feat: Some("1".into()),
            registration_id: Some("reg-1".into()),
        };
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"eecId\":\"eec1\""));
        assert!(json.contains("\"ueId\":\"gpsi-12345\""));
        assert!(json.contains("\"acProfs\""));
        assert!(json.contains("\"registrationId\""));
        let back: EecRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }
}
