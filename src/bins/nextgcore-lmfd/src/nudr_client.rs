//! #2260: the Application Layer IDs the 5GC has authorised for a UE.
//!
//! TS 23.586 §4.3.5 and §4.3.10: an AF provisions, or the operator
//! pre-provisions, the mapping between a Ranging/Sidelink Positioning
//! Application Layer ID and a GPSI. The UDR stores it as application data.
//! TS 29.519 §6.2.26 serves it: `GET /nudr-dr/v2/application-data/ueid-mappings`,
//! filtered by `gpsis` and answered with `UeIdMappingInfo` entries
//! (`rsUeIdMappingInfo.appLayerId`, `.gpsi`, TS 29.522 `RangSlUeIdMappInfo`).
//!
//! lmfd reads the mapping for the GPSI of the UE it ranges, so it holds an
//! SL-RTT half only under an ID the network maps to that UE. It no longer
//! trusts the first UE to claim the ID.
//!
//! Deviation, stated: TS 23.586 names the NEF (Nnef_UEId) and the GMLC as the
//! functions that resolve the mapping. lmfd reads the same UDR data directly
//! (Nudr_DataRepository, application data) because this tree has no Nnef_UEId
//! mapping retrieval. The data and its API are the specified ones.

use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::global_context;
use serde_json::Value;
use std::time::Duration;

/// The UDR's `nudr-dr` endpoint (scheme, host, port) in an NRF search result.
pub fn parse_udr_search_result(json: &Value) -> Option<(String, String, u16)> {
    json.get("nfInstances")?.as_array()?.iter().find_map(|nf| {
        let svc = nf
            .get("nfServices")?
            .as_array()?
            .iter()
            .find(|s| s.get("serviceName").and_then(Value::as_str) == Some("nudr-dr"))?;
        let host = nextgcore_sbi::nf_addressing::service_host(nf, Some(svc))?;
        let port = nextgcore_sbi::nf_addressing::service_port(Some(svc)).unwrap_or(80);
        let scheme = svc
            .get("scheme")
            .and_then(Value::as_str)
            .unwrap_or("http")
            .to_string();
        Some((scheme, host, port))
    })
}

/// The Application Layer IDs in a TS 29.519 `array(UeIdMappingInfo)` that
/// map to `gpsi`, as the SLPP octets they stand for (UTF-8, the #557 mapping
/// of a JSON `ApplicationlayerId`).
pub fn app_layer_ids_for(body: &Value, gpsi: &str) -> Vec<Vec<u8>> {
    body.as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("rsUeIdMappingInfo"))
        .filter(|m| m.get("gpsi").and_then(Value::as_str) == Some(gpsi))
        .filter_map(|m| m.get("appLayerId").and_then(Value::as_str))
        .map(|id| id.as_bytes().to_vec())
        .collect()
}

/// The Application Layer IDs the UDR maps to `gpsi`. `None` when the UDR
/// cannot be reached or answers anything but a 200 array, so the caller fails
/// closed; `Some(empty)` when no ID is mapped to the GPSI.
pub async fn authorised_app_layer_ids(gpsi: &str) -> Option<Vec<Vec<u8>>> {
    let ctx = global_context();
    let Some(nrf_uri) = ctx.get_nrf_uri().await else {
        log::warn!("#2260: no NRF URI configured; cannot discover the UDR");
        return None;
    };
    let (nrf_host, nrf_port) = crate::parse_host_port(&nrf_uri)?;
    let nrf = ctx.get_client(&nrf_host, nrf_port).await;
    let search = match nrf
        .get("/nnrf-disc/v1/nf-instances?target-nf-type=UDR&requester-nf-type=LMF&service-names=nudr-dr")
        .await
    {
        Ok(r) if r.status == 200 => r,
        Ok(r) => {
            log::warn!("#2260: UDR discovery answered {}", r.status);
            return None;
        }
        Err(e) => {
            log::warn!("#2260: UDR discovery failed: {e}");
            return None;
        }
    };
    let json: Value = serde_json::from_str(search.http.content.as_deref()?).ok()?;
    let Some((_scheme, host, port)) = parse_udr_search_result(&json) else {
        log::warn!("#2260: the NRF knows no UDR with nudr-dr");
        return None;
    };
    let client = crate::attach_oauth2(
        SbiClient::new(
            nextgcore_sbi::security::sbi_peer_client_config(&host, port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        ),
        nextgcore_sbi::types::NfType::Udr,
    );
    let path = format!(
        "/nudr-dr/v2/application-data/ueid-mappings?gpsis={}",
        urlencoding_component(gpsi)
    );
    match client.get(&path).await {
        Ok(r) if r.status == 200 => {
            let body: Value = serde_json::from_str(r.http.content.as_deref()?).ok()?;
            body.is_array().then(|| app_layer_ids_for(&body, gpsi))
        }
        Ok(r) => {
            log::warn!(
                "#2260: the UDR answered {} to the UE ID mapping read",
                r.status
            );
            None
        }
        Err(e) => {
            log::warn!("#2260: the UE ID mapping read failed: {e}");
            None
        }
    }
}

/// Percent-encode a query value (RFC 3986 unreserved characters kept).
fn urlencoding_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// TS 29.519 Table 6.2.26.3.1-3: only the IDs mapped to this GPSI count,
    /// and an entry without a mapping is skipped.
    #[test]
    fn only_the_ids_mapped_to_the_gpsi_are_taken_2260() {
        let body = json!([
            {"rsUeIdMappingInfo": {"appLayerId": "ue-a", "gpsi": "msisdn-1"}},
            {"rsUeIdMappingInfo": {"appLayerId": "ue-x", "gpsi": "msisdn-2"}},
            {"suppFeat": "0"}
        ]);
        assert_eq!(app_layer_ids_for(&body, "msisdn-1"), vec![b"ue-a".to_vec()]);
        assert!(app_layer_ids_for(&json!([]), "msisdn-1").is_empty());
        assert_eq!(urlencoding_component("msisdn-1+2"), "msisdn-1%2B2");
    }

    #[test]
    fn the_udr_endpoint_is_its_nudr_dr_service_2260() {
        let search = json!({"nfInstances": [{
            "nfInstanceId": "udr-1",
            "nfServices": [
                {"serviceName": "nudr-group-id-map", "ipEndPoints": [{"ipv4Address": "10.0.0.9", "port": 1}]},
                {"serviceName": "nudr-dr", "scheme": "http", "ipEndPoints": [{"ipv4Address": "10.0.0.8", "port": 7777}]}
            ]
        }]});
        assert_eq!(
            parse_udr_search_result(&search),
            Some(("http".to_string(), "10.0.0.8".to_string(), 7777))
        );
    }
}
