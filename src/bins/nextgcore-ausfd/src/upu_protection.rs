//! Nausf_UPUProtection producer service (Wave-6 F-03).
//!
//! `POST /nausf-upuprotection/v1/{supi}/ue-upu`
//! (specs/TS29509_Nausf_UPUProtection.yaml:26).
//!
//! TS 33.501 §14.1.4: the AUSF computes UPU-MAC-I_AUSF (Annex A.19, FC 0x7B)
//! over the UE Parameters Update Data + Counter_UPU using the latest KAUSF
//! from the per-SUPI anchor store (§6.14.1/F-02), and — when the UE
//! acknowledgement is requested — UPU-XMAC-I_UE (Annex A.20, FC 0x7C) with
//! the SAME counter.
//!
//! Wire encoding: Annex A.19 P0 is "UE Parameters Update Data, i.e. UE
//! parameters update list as given in clause 9.11.3.53A of TS 24.501
//! (starting from octet 23)" — a sequence of data sets, each coded as
//! 1 octet data-set type (high nibble spare) + 2-octet length + data
//! (figure 9.11.3.53A.2). NOTE: unlike SoR, the UPU header (octet 4) is NOT
//! part of the MAC input.
//!
//! Fail-closed invariants mirror `sor_protection`: 404 CONTEXT_NOT_FOUND
//! without an anchor, 503 COUNTER_WRAP on wrap (counter not consumed), and
//! 400 for any UpuData this module cannot encode byte-exactly.

use crate::context::{ausf_self, AnchorCounterError};
use crate::nudm_handler::bytes_to_hex;
use crate::sor_protection::{encoding_error, problem};
use nextgcore_crypt::kdf::{nextgcore_kdf_upu_mac_iausf, nextgcore_kdf_upu_mac_iue};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};

/// TS 24.501 table 9.11.3.53A.1 data set types (low nibble of the type
/// octet; high nibble spare).
const UPU_SET_ROUTING_ID_SECURED_PACKET: u8 = 0x01; // "Routing indicator update data"
const UPU_SET_DEFAULT_CONF_NSSAI: u8 = 0x02; // "Default configured NSSAI update data"
const UPU_SET_DISASTER_ROAMING_INFO: u8 = 0x03; // "Disaster roaming information update data"
const UPU_SET_ME_ROUTING_ID: u8 = 0x04; // "ME routing indicator update data"

/// Encode the TS 24.501 §9.11.3.4 routing indicator field (2 octets BCD):
/// octet 1 = digit 2 | digit 1, octet 2 = digit 4 | digit 3; 1..4 decimal
/// digits, unused digits coded 0b1111 (0xF).
pub fn encode_routing_indicator(routing_id: &str) -> Result<[u8; 2], String> {
    if routing_id.is_empty()
        || routing_id.len() > 4
        || !routing_id.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "routingId '{routing_id}' is not 1..4 decimal digits (TS 29.544 RoutingId, \
             TS 24.501 §9.11.3.4)"
        ));
    }
    let digits: Vec<u8> = routing_id.bytes().map(|b| b - b'0').collect();
    let digit = |i: usize| -> u8 { digits.get(i).copied().unwrap_or(0x0F) };
    Ok([(digit(1) << 4) | digit(0), (digit(3) << 4) | digit(2)])
}

/// Encode a TS 29.571 `Snssai` array as the value part of the NSSAI IE
/// (TS 24.501 §9.11.3.37, referenced by table 9.11.3.53A.1 for the default
/// configured NSSAI): each S-NSSAI is length octet + contents, where the
/// contents are SST (1 octet) or SST + SD (1 + 3 octets, §9.11.2.8).
pub fn encode_default_conf_nssai(snssais: &[serde_json::Value]) -> Result<Vec<u8>, String> {
    if snssais.is_empty() {
        return Err("defaultConfNssai needs at least 1 S-NSSAI (TS 29.509 minItems 1)".into());
    }
    let mut out = Vec::new();
    for snssai in snssais {
        let sst = snssai
            .get("sst")
            .and_then(|v| v.as_u64())
            .ok_or("Snssai.sst is mandatory (TS 29.571 Snssai)")?;
        if sst > 255 {
            return Err(format!("Snssai.sst {sst} exceeds 255 (TS 29.571 Sst)"));
        }
        match snssai.get("sd") {
            None => {
                out.push(0x01); // length: SST only
                out.push(sst as u8);
            }
            Some(sd) => {
                let sd = sd
                    .as_str()
                    .ok_or("Snssai.sd must be a string of 6 hexadecimal digits")?;
                if sd.len() != 6 || !sd.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!(
                        "Snssai.sd '{sd}' is not 6 hexadecimal digits (TS 29.571 Sd)"
                    ));
                }
                out.push(0x04); // length: SST + 3-octet SD
                out.push(sst as u8);
                for i in (0..6).step_by(2) {
                    out.push(
                        u8::from_str_radix(&sd[i..i + 2], 16)
                            .map_err(|_| format!("Snssai.sd '{sd}' is not valid hex"))?,
                    );
                }
            }
        }
    }
    Ok(out)
}

/// Append one "UE parameters update data set" (figure 9.11.3.53A.2):
/// type octet (spare high nibble) + 2-octet big-endian length + data.
fn push_data_set(out: &mut Vec<u8>, set_type: u8, data: &[u8]) -> Result<(), String> {
    if data.len() > u16::MAX as usize {
        return Err("UE parameters update data set exceeds the 2-octet length field".into());
    }
    out.push(set_type & 0x0F);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// Encode a TS 29.509 `UpuData[]` as the TS 24.501 §9.11.3.53A "UE
/// parameters update list" (octets from octet 23) — exactly the Annex A.19
/// P0 input.
///
/// Field → data set mapping (table 9.11.3.53A.1):
/// - `secPacket` (base64 secured packet, TS 31.115) → type 0001 "Routing
///   indicator update data" (figure 9.11.3.53A.3: content is the secured
///   packet)
/// - `defaultConfNssai` → type 0010 (NSSAI IE value part, §9.11.3.37)
/// - `drei`/`aol`/`dreiEps` → type 0011 (one flags octet, figure
///   9.11.3.53A.4A: b1 DREI, b2 AOL, b3 DREIEPS)
/// - `routingId` → type 0100 "ME routing indicator update data" (2-octet
///   BCD, figure 9.11.3.53A.4B)
///
/// When one UpuData object carries several parameters, the data sets are
/// emitted in the fixed order above (deterministic wire bytes). Fail-closed:
/// `disasterCondPlmnIds` has no §9.11.3.53A data-set encoding and any entry
/// carrying it — or carrying nothing encodable — is rejected; the AUSF must
/// never MAC bytes it cannot produce exactly.
pub fn encode_upu_data_list(upu_data_list: &[serde_json::Value]) -> Result<Vec<u8>, String> {
    if upu_data_list.is_empty() {
        return Err("upuDataList needs at least 1 UpuData (TS 29.509 minItems 1)".into());
    }
    let mut out = Vec::new();
    for item in upu_data_list {
        if item.get("disasterCondPlmnIds").is_some() {
            return Err(
                "UpuData.disasterCondPlmnIds has no TS 24.501 §9.11.3.53A data-set encoding \
                 — refusing to MAC bytes that cannot be produced exactly"
                    .into(),
            );
        }
        let mut encoded_any = false;

        if let Some(packet) = item.get("secPacket") {
            let encoded = packet
                .as_str()
                .ok_or("UpuData.secPacket must be a base64 string (TS 29.509 SecuredPacket)")?;
            let octets = nextgcore_crypt::base64::decode(encoded)
                .filter(|o| !o.is_empty())
                .ok_or("UpuData.secPacket is not valid non-empty base64")?;
            push_data_set(&mut out, UPU_SET_ROUTING_ID_SECURED_PACKET, &octets)?;
            encoded_any = true;
        }

        if let Some(nssai) = item.get("defaultConfNssai") {
            let snssais = nssai
                .as_array()
                .ok_or("UpuData.defaultConfNssai must be an array of Snssai")?;
            let data = encode_default_conf_nssai(snssais)?;
            push_data_set(&mut out, UPU_SET_DEFAULT_CONF_NSSAI, &data)?;
            encoded_any = true;
        }

        if item.get("drei").is_some() || item.get("aol").is_some() || item.get("dreiEps").is_some()
        {
            let mut flags = 0u8;
            if item.get("drei").and_then(|v| v.as_bool()).unwrap_or(false) {
                flags |= 0x01;
            }
            if item.get("aol").and_then(|v| v.as_bool()).unwrap_or(false) {
                flags |= 0x02;
            }
            if item
                .get("dreiEps")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                flags |= 0x04;
            }
            push_data_set(&mut out, UPU_SET_DISASTER_ROAMING_INFO, &[flags])?;
            encoded_any = true;
        }

        if let Some(routing_id) = item.get("routingId") {
            let ri = routing_id
                .as_str()
                .ok_or("UpuData.routingId must be a string (TS 29.544 RoutingId)")?;
            push_data_set(
                &mut out,
                UPU_SET_ME_ROUTING_ID,
                &encode_routing_indicator(ri)?,
            )?;
            encoded_any = true;
        }

        if !encoded_any {
            return Err(
                "UpuData entry carries no encodable parameter (expected secPacket, \
                 defaultConfNssai, routingId or disaster roaming flags)"
                    .into(),
            );
        }
    }
    Ok(out)
}

/// `POST /nausf-upuprotection/v1/{supi}/ue-upu` — Nausf_UPUProtection Protect
/// (TS 29.509, TS 33.501 §14.1.4).
pub fn handle_upu_protect(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Nausf_UPUProtection Protect: supi={supi}");

    let Some(body) = request.http.content.as_deref() else {
        return problem(400, "MANDATORY_IE_MISSING", "Missing UpuInfo request body");
    };
    let upu_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return problem(
                400,
                "INVALID_MSG_FORMAT",
                &format!("Invalid UpuInfo JSON: {e}"),
            )
        }
    };

    // TS 29.509 UpuInfo required: upuDataList (minItems 1) + upuAckInd.
    let Some(upu_ack_ind) = upu_info.get("upuAckInd").and_then(|v| v.as_bool()) else {
        return problem(
            400,
            "MANDATORY_IE_MISSING",
            "UpuInfo.upuAckInd is mandatory (TS 29.509 UpuInfo required: upuAckInd)",
        );
    };
    let Some(upu_data_list) = upu_info.get("upuDataList").and_then(|v| v.as_array()) else {
        return problem(
            400,
            "MANDATORY_IE_MISSING",
            "UpuInfo.upuDataList is mandatory (TS 29.509 UpuInfo required: upuDataList)",
        );
    };

    // Optional upuHeader (octet 4 as 2 hex chars) is validated but NOT part
    // of the MAC input — Annex A.19 P0 starts at octet 23.
    if let Some(header) = upu_info.get("upuHeader") {
        let valid = header
            .as_str()
            .is_some_and(|h| h.len() == 2 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if !valid {
            return problem(
                400,
                "INVALID_MSG_FORMAT",
                "UpuInfo.upuHeader must be 2 hexadecimal characters (TS 29.509 UpuHeader)",
            );
        }
    }

    // P0: verbatim opaque octets when provided, else the encoded list.
    let upu_data: Vec<u8> = if let Some(transparent) = upu_info.get("upuTransparentInfo") {
        let Some(encoded) = transparent.as_str() else {
            return encoding_error("upuTransparentInfo must be a base64 string (TS 29.571 Bytes)");
        };
        match nextgcore_crypt::base64::decode(encoded).filter(|o| !o.is_empty()) {
            Some(octets) => octets,
            None => return encoding_error("upuTransparentInfo is not valid non-empty base64"),
        }
    } else {
        match encode_upu_data_list(upu_data_list) {
            Ok(octets) => octets,
            Err(e) => return encoding_error(&e),
        }
    };

    let ctx = ausf_self();
    let Ok(context) = ctx.read() else {
        return problem(500, "SYSTEM_FAILURE", "AUSF context lock poisoned");
    };

    // TS 33.501 §6.14.1 anchor: absent → 404, never a MAC with a zero key.
    let Some(kausf) = context.anchor_lookup_kausf(supi) else {
        return problem(
            404,
            "CONTEXT_NOT_FOUND",
            &format!(
                "No SoR/UPU anchor for {supi}: no completed primary authentication \
                 in this AUSF (TS 33.501 §6.14.1)"
            ),
        );
    };

    // §6.15.2.2 Counter_UPU lifecycle (allocator = only read path; wrap
    // suspends without consuming).
    let counter_upu = match context.anchor_next_upu_counter(supi) {
        Ok(counter) => counter,
        Err(AnchorCounterError::NoAnchor) => {
            return problem(
                404,
                "CONTEXT_NOT_FOUND",
                &format!("No SoR/UPU anchor for {supi} (TS 33.501 §6.14.1)"),
            );
        }
        Err(AnchorCounterError::CounterWrap) => {
            return problem(
                503,
                "COUNTER_WRAP",
                "Counter_UPU is about to wrap: UPU protection suspended until a fresh \
                 KAUSF (TS 33.501 §6.15.2.2, §14.1.4 'or error (counter_wrap)')",
            );
        }
    };

    // Annex A.19 (FC 0x7B): UPU-MAC-I_AUSF over the UPU data + counter.
    let upu_mac_iausf = nextgcore_kdf_upu_mac_iausf(&kausf, &upu_data, counter_upu);

    // TS 29.509 UpuSecurityInfo: upuMacIausf + counterUpu required;
    // upuXmacIue iff the acknowledgement is requested (§14.1.4 Output
    // Optional, Annex A.20 with the SAME counter).
    let mut security_info = serde_json::json!({
        "upuMacIausf": bytes_to_hex(&upu_mac_iausf),
        "counterUpu": format!("{counter_upu:04x}"),
    });
    if upu_ack_ind {
        let upu_xmac_iue = nextgcore_kdf_upu_mac_iue(&kausf, counter_upu);
        security_info["upuXmacIue"] = serde_json::Value::String(bytes_to_hex(&upu_xmac_iue));
    }

    SbiResponse::with_status(200)
        .with_json_body(&security_info)
        .unwrap_or_else(|_| SbiResponse::with_status(500))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ausf_context_init;
    use crate::nudm_handler::hex_to_bytes;

    fn post_upu(supi: &str, body: &serde_json::Value) -> SbiResponse {
        let request = SbiRequest::post(format!("/nausf-upuprotection/v1/{supi}/ue-upu"))
            .with_json_body(body)
            .expect("build request");
        handle_upu_protect(supi, &request)
    }

    fn body_json(response: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(response.http.content.as_deref().unwrap_or("{}")).expect("JSON body")
    }

    fn test_kausf(tag: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = tag.wrapping_add(i as u8);
        }
        k
    }

    /// The golden UpuData list used across the handler tests.
    fn golden_upu_data_list() -> serde_json::Value {
        serde_json::json!([
            {"routingId": "1234"},
            {"defaultConfNssai": [{"sst": 1}, {"sst": 2, "sd": "00007B"}]}
        ])
    }

    /// Hand-derived wire bytes for `golden_upu_data_list()` (TS 24.501
    /// §9.11.3.53A figure 9.11.3.53A.2):
    ///
    /// set 1: ME routing indicator (type 0100), length 0x0002,
    ///        "1234" → BCD 21 43 (digit2|digit1, digit4|digit3)
    /// set 2: default configured NSSAI (type 0010), length 0x0007,
    ///        NSSAI value part: {sst:1} → 01 01; {sst:2, sd:00007B} →
    ///        04 02 00 00 7B
    const GOLDEN_UPU_LIST: [u8; 15] = [
        0x04, 0x00, 0x02, 0x21, 0x43, // ME routing indicator data set
        0x02, 0x00, 0x07, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x7B, // NSSAI data set
    ];

    // ------------------------------------------------------------------
    // Golden byte-vectors (hand-derived, never roundtrip-only)
    // ------------------------------------------------------------------

    #[test]
    fn golden_upu_data_list_wire_vector() {
        let list = golden_upu_data_list();
        let encoded = encode_upu_data_list(list.as_array().unwrap()).expect("encode");
        assert_eq!(encoded, GOLDEN_UPU_LIST);
    }

    #[test]
    fn golden_secured_packet_and_disaster_flags_vector() {
        // secPacket DE AD BE EF → type 0001, len 0x0004, packet octets;
        // {drei, dreiEps} → type 0011, len 0x0001, flags 0x05 (b1|b3).
        let list = serde_json::json!([
            {"secPacket": nextgcore_crypt::base64::encode(&[0xDE, 0xAD, 0xBE, 0xEF])},
            {"drei": true, "dreiEps": true}
        ]);
        let encoded = encode_upu_data_list(list.as_array().unwrap()).expect("encode");
        assert_eq!(
            encoded,
            [0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x03, 0x00, 0x01, 0x05]
        );
    }

    #[test]
    fn golden_routing_indicator_bcd() {
        // TS 24.501 §9.11.3.4: digit2|digit1, digit4|digit3, F-filled.
        assert_eq!(encode_routing_indicator("1234").unwrap(), [0x21, 0x43]);
        assert_eq!(encode_routing_indicator("123").unwrap(), [0x21, 0xF3]);
        assert_eq!(encode_routing_indicator("12").unwrap(), [0x21, 0xFF]);
        assert_eq!(encode_routing_indicator("1").unwrap(), [0xF1, 0xFF]);
        assert!(encode_routing_indicator("").is_err());
        assert!(encode_routing_indicator("12345").is_err());
        assert!(encode_routing_indicator("12a4").is_err());
    }

    #[test]
    fn upu_encoding_rejections() {
        // disasterCondPlmnIds is not encodable → fail-closed.
        let list = serde_json::json!([
            {"disasterCondPlmnIds": [{"mcc": "001", "mnc": "01"}]}
        ]);
        assert!(encode_upu_data_list(list.as_array().unwrap()).is_err());
        // Entry with nothing encodable.
        let list = serde_json::json!([{"unknownField": true}]);
        assert!(encode_upu_data_list(list.as_array().unwrap()).is_err());
        // Empty list violates minItems 1.
        assert!(encode_upu_data_list(&[]).is_err());
        // Bad SD.
        assert!(
            encode_default_conf_nssai(&[serde_json::json!({"sst": 1, "sd": "12345"})]).is_err()
        );
        // Missing SST (mandatory).
        assert!(
            encode_default_conf_nssai(&[serde_json::json!({"sd": "00007B"})])
                .unwrap_err()
                .contains("mandatory")
        );
    }

    // ------------------------------------------------------------------
    // Handler behaviour (real handler fn, real anchor store)
    // ------------------------------------------------------------------

    #[test]
    fn upu_happy_path_with_ack_returns_all_three_fields_and_mac_is_reproducible() {
        ausf_context_init(64);
        let supi = "imsi-999700000000201";
        let kausf = test_kausf(0xB1);
        ausf_self().read().unwrap().anchor_refresh(supi, &kausf);

        let response = post_upu(
            supi,
            &serde_json::json!({
                "upuAckInd": true,
                "upuDataList": golden_upu_data_list(),
            }),
        );
        assert_eq!(response.status, 200, "body: {:?}", response.http.content);
        let json = body_json(&response);

        assert_eq!(json["counterUpu"], "0001");

        // Reproduce from the documented S-string inputs: P0 = the
        // hand-derived golden list bytes, counter 0x0001 (the UPU header is
        // NOT part of the MAC input — Annex A.19).
        let expected_mac = nextgcore_kdf_upu_mac_iausf(&kausf, &GOLDEN_UPU_LIST, 0x0001);
        assert_eq!(
            hex_to_bytes(json["upuMacIausf"].as_str().unwrap()),
            expected_mac.to_vec()
        );
        let expected_xmac = nextgcore_kdf_upu_mac_iue(&kausf, 0x0001);
        assert_eq!(
            hex_to_bytes(json["upuXmacIue"].as_str().unwrap()),
            expected_xmac.to_vec()
        );
    }

    #[test]
    fn upu_without_ack_omits_xmac() {
        ausf_context_init(64);
        let supi = "imsi-999700000000202";
        ausf_self()
            .read()
            .unwrap()
            .anchor_refresh(supi, &test_kausf(0xB2));

        let response = post_upu(
            supi,
            &serde_json::json!({
                "upuAckInd": false,
                "upuDataList": golden_upu_data_list(),
            }),
        );
        assert_eq!(response.status, 200);
        let json = body_json(&response);
        assert!(json.get("upuMacIausf").is_some());
        assert!(
            json.get("upuXmacIue").is_none(),
            "no XMAC when ack not requested"
        );
    }

    #[test]
    fn upu_transparent_info_is_maced_verbatim() {
        ausf_context_init(64);
        let supi = "imsi-999700000000203";
        let kausf = test_kausf(0xB3);
        ausf_self().read().unwrap().anchor_refresh(supi, &kausf);

        let opaque = [0x04u8, 0x00, 0x02, 0x21, 0x43];
        let response = post_upu(
            supi,
            &serde_json::json!({
                "upuAckInd": false,
                // upuDataList still mandatory per the yaml even when the
                // transparent form carries the octets.
                "upuDataList": [{"routingId": "9999"}],
                "upuTransparentInfo": nextgcore_crypt::base64::encode(&opaque),
            }),
        );
        assert_eq!(response.status, 200);
        let json = body_json(&response);
        let expected_mac = nextgcore_kdf_upu_mac_iausf(&kausf, &opaque, 0x0001);
        assert_eq!(
            hex_to_bytes(json["upuMacIausf"].as_str().unwrap()),
            expected_mac.to_vec(),
            "upuTransparentInfo octets must be MACed verbatim, not the re-encoded list"
        );
    }

    #[test]
    fn upu_missing_mandatory_ies_are_400() {
        ausf_context_init(64);
        let supi = "imsi-999700000000204";
        ausf_self()
            .read()
            .unwrap()
            .anchor_refresh(supi, &test_kausf(0xB4));

        // Missing upuAckInd.
        let response = post_upu(
            supi,
            &serde_json::json!({
                "upuDataList": golden_upu_data_list(),
            }),
        );
        assert_eq!(response.status, 400);
        assert_eq!(body_json(&response)["cause"], "MANDATORY_IE_MISSING");

        // Missing upuDataList.
        let response = post_upu(supi, &serde_json::json!({"upuAckInd": true}));
        assert_eq!(response.status, 400);
        assert_eq!(body_json(&response)["cause"], "MANDATORY_IE_MISSING");

        // Empty upuDataList (minItems 1).
        let response = post_upu(
            supi,
            &serde_json::json!({
                "upuAckInd": true,
                "upuDataList": [],
            }),
        );
        assert_eq!(response.status, 400);

        // disasterCondPlmnIds → fail-closed 400.
        let response = post_upu(
            supi,
            &serde_json::json!({
                "upuAckInd": true,
                "upuDataList": [{"disasterCondPlmnIds": [{"mcc": "001", "mnc": "01"}]}],
            }),
        );
        assert_eq!(response.status, 400);
    }

    #[test]
    fn upu_unknown_supi_is_404_never_a_mac() {
        ausf_context_init(64);
        let response = post_upu(
            "imsi-999700000000299",
            &serde_json::json!({
                "upuAckInd": true,
                "upuDataList": golden_upu_data_list(),
            }),
        );
        assert_eq!(response.status, 404);
        let json = body_json(&response);
        assert_eq!(json["cause"], "CONTEXT_NOT_FOUND");
        assert!(
            json.get("upuMacIausf").is_none(),
            "404 must never carry a MAC"
        );
    }

    #[test]
    fn upu_counter_freshness_and_independence_from_sor_counter() {
        ausf_context_init(64);
        let supi = "imsi-999700000000205";
        let kausf = test_kausf(0xB5);
        let ctx = ausf_self();
        ctx.read().unwrap().anchor_refresh(supi, &kausf);

        let body = serde_json::json!({
            "upuAckInd": true,
            "upuDataList": golden_upu_data_list(),
        });
        let first = body_json(&post_upu(supi, &body));
        let second = body_json(&post_upu(supi, &body));
        assert_eq!(first["counterUpu"], "0001");
        assert_eq!(second["counterUpu"], "0002");
        assert_ne!(
            first["upuMacIausf"], second["upuMacIausf"],
            "identical input must yield different MACs across counters (freshness)"
        );

        // Counter_SoR is a separate counter (§6.14.2.3 vs §6.15.2.2): the
        // two UPU allocations above must not have advanced it.
        assert_eq!(
            ctx.read().unwrap().anchor_next_sor_counter(supi),
            Ok(0x0001)
        );
    }

    #[test]
    fn upu_counter_wrap_is_503_and_not_consumed() {
        ausf_context_init(64);
        let supi = "imsi-999700000000206";
        let ctx = ausf_self();
        ctx.read().unwrap().anchor_refresh(supi, &test_kausf(0xB6));
        assert!(ctx
            .read()
            .unwrap()
            .anchor_force_counters(supi, 0xFFFF, 0xFFFF));

        let body = serde_json::json!({
            "upuAckInd": true,
            "upuDataList": golden_upu_data_list(),
        });
        let response = post_upu(supi, &body);
        assert_eq!(response.status, 503);
        assert_eq!(body_json(&response)["cause"], "COUNTER_WRAP");

        let response = post_upu(supi, &body);
        assert_eq!(response.status, 503, "counter must not be consumed on wrap");

        // Fresh KAUSF lifts the suspension (§6.15.2.2 reset).
        ctx.read().unwrap().anchor_refresh(supi, &test_kausf(0xB7));
        let response = post_upu(supi, &body);
        assert_eq!(response.status, 200);
        assert_eq!(body_json(&response)["counterUpu"], "0001");
    }
}
