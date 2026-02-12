//! NSSF NS Selection Message Builder
//!
//! Port of src/nssf/nnssf-build.c - Build NS selection request messages

use crate::context::{NssfHome, RoamingIndication, SNssai, Tai};
use crate::sbi_path::PathSbiRequest;

/// Parameters for NS selection request to H-NSSF
#[derive(Debug, Clone)]
pub struct NssfNsselectionParam {
    pub slice_info_for_pdu_session: SliceInfoParam,
    pub tai: Option<Tai>,
}

/// Slice info parameters
#[derive(Debug, Clone)]
pub struct SliceInfoParam {
    pub presence: bool,
    pub snssai: Option<SNssai>,
    pub roaming_indication: RoamingIndication,
}

impl Default for SliceInfoParam {
    fn default() -> Self {
        Self {
            presence: false,
            snssai: None,
            roaming_indication: RoamingIndication::NonRoaming,
        }
    }
}

/// Build NS selection GET request to H-NSSF
/// Port of nssf_nnssf_nsselection_build_get
pub fn nssf_nnssf_nsselection_build_get(
    _home: &NssfHome,
    param: &NssfNsselectionParam,
    nf_instance_id: &str,
    nf_type: &str,
) -> Option<PathSbiRequest> {
    // Validate parameters
    if !param.slice_info_for_pdu_session.presence {
        log::error!("No sliceInfoForPDUSession");
        return None;
    }

    let snssai = match &param.slice_info_for_pdu_session.snssai {
        Some(s) => s,
        None => {
            log::error!("No sNssai");
            return None;
        }
    };

    if param.slice_info_for_pdu_session.roaming_indication == RoamingIndication::NonRoaming {
        // This is fine, just log for debugging
        log::debug!("Roaming indication: NonRoaming");
    }

    // Build query parameters
    let mut query_params = vec![
        format!("nf-id={}", nf_instance_id),
        format!("nf-type={}", nf_type),
        format!("slice-info-request-for-pdu-session.sNssai.sst={}", snssai.sst),
    ];

    if let Some(sd) = snssai.sd {
        query_params.push(format!("slice-info-request-for-pdu-session.sNssai.sd={sd:06x}"));
    }

    query_params.push(format!(
        "slice-info-request-for-pdu-session.roamingIndication={}",
        roaming_indication_to_string(param.slice_info_for_pdu_session.roaming_indication)
    ));

    if let Some(ref tai) = param.tai {
        query_params.push(format!(
            "tai.plmnId.mcc={}&tai.plmnId.mnc={}&tai.tac={}",
            tai.plmn_id.mcc, tai.plmn_id.mnc, tai.tac
        ));
    }

    let query_string = query_params.join("&");
    let uri = format!(
        "/nnssf-nsselection/v2/network-slice-information?{query_string}"
    );

    log::debug!("Built NS selection request: GET {uri}");

    Some(PathSbiRequest {
        method: "GET".to_string(),
        uri,
        headers: vec![
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: None,
    })
}

/// Convert roaming indication to string
fn roaming_indication_to_string(indication: RoamingIndication) -> &'static str {
    match indication {
        RoamingIndication::NonRoaming => "NON_ROAMING",
        RoamingIndication::LocalBreakout => "LOCAL_BREAKOUT",
        RoamingIndication::HomeRouted => "HOME_ROUTED",
    }
}

/// Build authorized network slice info response
pub fn build_authorized_network_slice_info_response(
    nrf_id: &str,
    nsi_id: &str,
) -> String {
    // Build JSON response
    serde_json_minimal(nrf_id, nsi_id)
}

/// Minimal JSON serialization without serde dependency
fn serde_json_minimal(nrf_id: &str, nsi_id: &str) -> String {
    format!(
        r#"{{"nsiInformation":{{"nrfId":"{}","nsiId":"{}"}}}}"#,
        escape_json_string(nrf_id),
        escape_json_string(nsi_id)
    )
}

/// Escape special characters in JSON string
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;

    #[test]
    fn test_build_ns_selection_request() {
        let home = NssfHome::new(
            1,
            PlmnId::new("001", "01"),
            SNssai::new(1, Some(0x010203)),
        );

        let param = NssfNsselectionParam {
            slice_info_for_pdu_session: SliceInfoParam {
                presence: true,
                snssai: Some(SNssai::new(1, Some(0x010203))),
                roaming_indication: RoamingIndication::HomeRouted,
            },
            tai: None,
        };

        let request = nssf_nnssf_nsselection_build_get(&home, &param, "test-nf-id", "AMF");
        assert!(request.is_some());

        let request = request.unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.uri.contains("nnssf-nsselection"));
        assert!(request.uri.contains("nf-id=test-nf-id"));
        assert!(request.uri.contains("sst=1"));
    }

    #[test]
    fn test_build_ns_selection_request_missing_slice_info() {
        let home = NssfHome::new(
            1,
            PlmnId::new("001", "01"),
            SNssai::new(1, None),
        );

        let param = NssfNsselectionParam {
            slice_info_for_pdu_session: SliceInfoParam::default(),
            tai: None,
        };

        let request = nssf_nnssf_nsselection_build_get(&home, &param, "test-nf-id", "AMF");
        assert!(request.is_none());
    }

    #[test]
    fn test_build_authorized_response() {
        let response = build_authorized_network_slice_info_response(
            "http://nrf.example.com",
            "nsi-123",
        );
        assert!(response.contains("nrfId"));
        assert!(response.contains("nsiId"));
        assert!(response.contains("http://nrf.example.com"));
    }

    #[test]
    fn test_roaming_indication_to_string() {
        assert_eq!(roaming_indication_to_string(RoamingIndication::NonRoaming), "NON_ROAMING");
        assert_eq!(roaming_indication_to_string(RoamingIndication::LocalBreakout), "LOCAL_BREAKOUT");
        assert_eq!(roaming_indication_to_string(RoamingIndication::HomeRouted), "HOME_ROUTED");
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json_string("line1\nline2"), "line1\\nline2");
    }
}
