//! `Nlmf_Broadcast` and `Nlmf_DataExposure` — the LMF's other two service
//! surfaces (issue #104).
//!
//! TS 23.501 Table 7.2.25-1 lists three LMF services. This NF exposed exactly
//! one (`nlmf-loc`): `grep -rn 'broadcast\|cipher\|exposure' src/bins/nextgcore-lmfd/src`
//! was empty, and `register_with_nrf` advertised a single `serviceName`. Both
//! missing surfaces are vendored in the specs folder, so neither is guesswork:
//!
//! | service | apiRoot | operations |
//! |---|---|---|
//! | `Nlmf_Broadcast` (TS 29.572 §5.3) | `nlmf-broadcast/v1` | `POST /cipher-key-data` |
//! | `Nlmf_DataExposure` (§5.4) | `nlmf-dataexposure/v1` | `POST /subscriptions`, `PATCH`/`DELETE /subscriptions/{id}` |
//!
//! # Not feature-gated
//!
//! #104 suggests putting each behind an off-by-default cargo feature "so partial
//! work does not affect the default build". They are routed unconditionally
//! instead, for two reasons. They are **pure additions**: two new apiRoots that no
//! existing path can reach, so no current behaviour changes. And a cargo feature
//! would leave them **uncompiled in CI** (which builds default features), where
//! they would rot — the same trade taken for the #112 and #114 switches. What
//! *is* deliberately conditional is the honesty of the answers below.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Nlmf_Broadcast (TS29572_Nlmf_Broadcast.yaml)
// ---------------------------------------------------------------------------

/// `CipherRequestData` — the `POST /cipher-key-data` request body.
/// Required: `amfCallBackURI`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CipherRequestData {
    /// Where the LMF delivers `CipheringKeyInfo` notifications (REQUIRED).
    #[serde(rename = "amfCallBackURI", default)]
    pub amf_call_back_uri: String,
    #[serde(rename = "supportedFeatures", skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

/// `CipherResponseData` — the `200` response. Required: `dataAvailability`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CipherResponseData {
    #[serde(rename = "dataAvailability")]
    pub data_availability: String,
}

/// `DataAvailability` values (`TS29572_Nlmf_Broadcast.yaml`).
pub mod data_availability {
    /// The LMF holds ciphering key data and will notify the AMF.
    pub const AVAILABLE: &str = "CIPHERING_KEY_DATA_AVAILABLE";
    /// The LMF holds none.
    pub const NOT_AVAILABLE: &str = "CIPHERING_KEY_DATA_NOT_AVAILABLE";
}

/// `CipheringDataSet` — one ciphering key set (`CipheringKeyInfo.cipheringData[]`).
///
/// Required by the yaml: `cipheringSetID`, `cipheringKey`, `c0`,
/// `validityStartTime`, `validityDuration`. Modelled in full because this is what
/// the LMF would notify to the AMF, and a partial model would silently drop a
/// mandatory member if the store ever gains a real source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CipheringDataSet {
    #[serde(rename = "cipheringSetID")]
    pub ciphering_set_id: u16,
    /// Base64 (`format: byte`) ciphering key.
    #[serde(rename = "cipheringKey")]
    pub ciphering_key: String,
    /// Base64 first component of the initial ciphering counter.
    pub c0: String,
    #[serde(rename = "ltePosSibTypes", skip_serializing_if = "Option::is_none")]
    pub lte_pos_sib_types: Option<String>,
    #[serde(rename = "nrPosSibTypes", skip_serializing_if = "Option::is_none")]
    pub nr_pos_sib_types: Option<String>,
    /// RFC 3339 validity start.
    #[serde(rename = "validityStartTime")]
    pub validity_start_time: String,
    /// Validity duration, 1..65535.
    #[serde(rename = "validityDuration")]
    pub validity_duration: u16,
    #[serde(rename = "taiList", skip_serializing_if = "Option::is_none")]
    pub tai_list: Option<String>,
}

/// `CipheringKeyInfo` — the notification body POSTed to `amfCallBackURI`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CipheringKeyInfo {
    #[serde(rename = "cipheringData")]
    pub ciphering_data: Vec<CipheringDataSet>,
    #[serde(rename = "supportedFeatures", skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

// ---------------------------------------------------------------------------
// Nlmf_DataExposure (TS29572_Nlmf_DataExposure.yaml)
// ---------------------------------------------------------------------------

/// `LmfDataExposureSubscription` — the `POST /subscriptions` body and the `201`
/// echo. Required: `notificationUri`, `notifyCorrelationId`, `aoi`.
///
/// `aoi` (a TS 29.571 `PresenceInfo`) and `qualityThreshold` (a `LocationQoS`)
/// are passthrough `serde_json::Value`s: the first is a large cross-spec leaf, and
/// the second duplicates a type that already exists in `nlmf.rs` — carrying it
/// verbatim avoids two divergent models of one schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LmfDataExposureSubscription {
    #[serde(rename = "notificationUri", default)]
    pub notification_uri: String,
    #[serde(rename = "notifyCorrelationId", default)]
    pub notify_correlation_id: String,
    /// Area of interest (`PresenceInfo`; REQUIRED).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aoi: Option<serde_json::Value>,
    #[serde(rename = "recurTime", skip_serializing_if = "Option::is_none")]
    pub recur_time: Option<serde_json::Value>,
    #[serde(rename = "numOfSamples", skip_serializing_if = "Option::is_none")]
    pub num_of_samples: Option<u32>,
    #[serde(rename = "dataSources", skip_serializing_if = "Option::is_none")]
    pub data_sources: Option<Vec<String>>,
    #[serde(rename = "qualityThreshold", skip_serializing_if = "Option::is_none")]
    pub quality_threshold: Option<serde_json::Value>,
    #[serde(rename = "mlModelId", skip_serializing_if = "Option::is_none")]
    pub ml_model_id: Option<u32>,
    #[serde(rename = "expiryTime", skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<String>,
    #[serde(rename = "pruIndication", skip_serializing_if = "Option::is_none")]
    pub pru_indication: Option<bool>,
}

impl LmfDataExposureSubscription {
    /// Enforce the yaml's `required: [notificationUri, notifyCorrelationId, aoi]`.
    ///
    /// `serde(default)` on the two strings so an absent member is a *missing IE*
    /// rather than a parse error — the same reasoning as elsewhere in this tree:
    /// the two produce different ProblemDetails causes and a consumer needs to
    /// know which of the two it hit.
    pub fn validate(&self) -> Option<&'static str> {
        if self.notification_uri.trim().is_empty() {
            return Some("notificationUri");
        }
        if self.notify_correlation_id.trim().is_empty() {
            return Some("notifyCorrelationId");
        }
        if self.aoi.is_none() {
            return Some("aoi");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Broadcast bodies use the yaml member names — asserted on the serialized
    /// TEXT, since a round trip of our own struct passes even when every name is
    /// wrong (both directions share the mistake).
    #[test]
    fn broadcast_bodies_use_the_yaml_member_names() {
        let json = serde_json::to_string(&CipherResponseData {
            data_availability: data_availability::NOT_AVAILABLE.to_string(),
        })
        .expect("json");
        assert_eq!(
            json,
            r#"{"dataAvailability":"CIPHERING_KEY_DATA_NOT_AVAILABLE"}"#
        );

        // `amfCallBackURI` — note the capitalisation, which no rename_all rule
        // produces.
        let parsed: CipherRequestData =
            serde_json::from_str(r#"{"amfCallBackURI":"http://amf/cipher-notify"}"#)
                .expect("parses");
        assert_eq!(parsed.amf_call_back_uri, "http://amf/cipher-notify");
        let out = serde_json::to_string(&parsed).expect("json");
        assert!(out.contains(r#""amfCallBackURI""#), "got {out}");
        assert!(!out.contains("amfCallBackUri"), "got {out}");

        // A ciphering data set round-trips through the spec spelling.
        let set: CipheringDataSet = serde_json::from_str(
            r#"{"cipheringSetID":7,"cipheringKey":"a2V5","c0":"YzA=",
                "validityStartTime":"2026-01-01T00:00:00Z","validityDuration":600}"#,
        )
        .expect("parses");
        assert_eq!(set.ciphering_set_id, 7);
        assert_eq!(set.validity_duration, 600);
        let info = CipheringKeyInfo {
            ciphering_data: vec![set],
            supported_features: None,
        };
        let json = serde_json::to_string(&info).expect("json");
        assert!(json.contains(r#""cipheringData""#), "got {json}");
        assert!(json.contains(r#""cipheringSetID":7"#), "got {json}");
    }

    /// The DataExposure subscription enforces its three required members, each
    /// named individually so the 400 can say which one is missing.
    #[test]
    fn data_exposure_subscription_requires_its_three_members() {
        let full: LmfDataExposureSubscription = serde_json::from_str(
            r#"{"notificationUri":"http://nwdaf/cb","notifyCorrelationId":"c1",
                "aoi":{"praId":"pra-1"},"dataSources":["NG_RAN"],"numOfSamples":10}"#,
        )
        .expect("parses");
        assert_eq!(full.validate(), None);
        assert_eq!(
            full.data_sources.as_deref(),
            Some(&["NG_RAN".to_string()][..])
        );

        let mut missing = full.clone();
        missing.notification_uri = String::new();
        assert_eq!(missing.validate(), Some("notificationUri"));

        let mut missing = full.clone();
        missing.notify_correlation_id = "   ".to_string();
        assert_eq!(
            missing.validate(),
            Some("notifyCorrelationId"),
            "whitespace is not a value"
        );

        let mut missing = full.clone();
        missing.aoi = None;
        assert_eq!(missing.validate(), Some("aoi"));

        // The echo uses the yaml spellings.
        let json = serde_json::to_string(&full).expect("json");
        assert!(json.contains(r#""notificationUri""#), "got {json}");
        assert!(json.contains(r#""notifyCorrelationId""#), "got {json}");
        assert!(json.contains(r#""dataSources""#), "got {json}");
        // Absent optionals are omitted, not null.
        assert!(!json.contains("null"), "got {json}");
    }
}
