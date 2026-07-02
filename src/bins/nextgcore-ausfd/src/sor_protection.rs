//! Nausf_SoRProtection producer service (Wave-6 F-03).
//!
//! `POST /nausf-sorprotection/v1/{supi}/ue-sor`
//! (specs/TS29509_Nausf_SoRProtection.yaml:27).
//!
//! TS 33.501 §14.1.3: the AUSF computes SoR-MAC-I_AUSF (Annex A.17) over the
//! SOR header + Counter_SoR + steering-list octets using the latest KAUSF
//! from the per-SUPI anchor store (TS 33.501 §6.14.1, F-02), and — when the
//! UE acknowledgement is requested (`ackInd == true`) — also SoR-XMAC-I_UE
//! (Annex A.18) with the SAME counter.
//!
//! Wire encoding: TS 24.501 §9.11.3.51 — the MAC input P2 is "octets included
//! in SoR transparent container beyond (and not including) octet 22", i.e.
//! either the "PLMN ID and access technology list" (entries coded per
//! TS 31.102 §4.2.5 EF_PLMNwAcT: 3-octet BCD PLMN + 2-octet access-technology
//! identifier) or a secured packet (TS 31.115).
//!
//! Fail-closed invariants:
//! - no anchor (no completed primary authentication) → 404 CONTEXT_NOT_FOUND,
//!   never a MAC over a zero/unknown key;
//! - counter about to wrap → 503 COUNTER_WRAP (TS 33.501 §14.1.3 "or error
//!   (counter_wrap)", §6.14.2.3 suspension) and the counter is NOT consumed;
//! - anything this module cannot encode byte-exactly is rejected with 400 —
//!   a MAC over guessed bytes would fail UE-side verification.

use crate::context::{ausf_self, AnchorCounterError};
use crate::nudm_handler::bytes_to_hex;
use nextgcore_crypt::kdf::{nextgcore_kdf_sor_mac_iausf, nextgcore_kdf_sor_mac_iue};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};

/// Build an RFC 7807 / TS 29.500 ProblemDetails response.
pub(crate) fn problem(status: u16, cause: &str, detail: &str) -> SbiResponse {
    SbiResponse::with_status(status)
        .with_json_body(&serde_json::json!({
            "status": status,
            "cause": cause,
            "detail": detail,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status))
}

/// Map a wire-encoding error message to a 400 ProblemDetails with the
/// appropriate TS 29.500 protocol cause.
pub(crate) fn encoding_error(detail: &str) -> SbiResponse {
    let cause = if detail.contains("mandatory") {
        "MANDATORY_IE_MISSING"
    } else {
        "INVALID_MSG_FORMAT"
    };
    problem(400, cause, detail)
}

/// TS 24.501 §9.11.3.51 figure 9.11.3.51.5 — SOR header (octet 4) for SOR
/// data type "0" (steering of roaming information, network → UE):
///
/// - bit 1 (0x01): SOR data type = 0 (steering information)
/// - bit 2 (0x02): list indication — 1 = list of preferred PLMN/access
///   technology combinations (or secured packet) provided; 0 = HPLMN "no
///   change" indication
/// - bit 3 (0x04): list type — 0 = secured packet, 1 = "PLMN ID and access
///   technology list"
/// - bit 4 (0x08): ACK — 1 = acknowledgement requested
/// - bit 5 (0x10): AP (additional parameters) — not produced by this AUSF
/// - bits 6-8: spare (0)
pub fn build_sor_header(ack_requested: bool, list_provided: bool, list_type_plmn: bool) -> u8 {
    let mut header = 0u8;
    if list_provided {
        header |= 0x02;
    }
    if list_type_plmn {
        header |= 0x04;
    }
    if ack_requested {
        header |= 0x08;
    }
    header
}

/// Encode one PLMN identity as the 3-octet BCD format of TS 31.102 §4.2.5
/// (EF_PLMNwAcT, "coded as in EF_PLMNsel" = TS 24.008 §10.5.1.13):
///
/// - octet 1: MCC digit 2 (bits 8-5) | MCC digit 1 (bits 4-1)
/// - octet 2: MNC digit 3 (bits 8-5) | MCC digit 3 (bits 4-1)
///   (MNC digit 3 coded 0xF for a 2-digit MNC)
/// - octet 3: MNC digit 2 (bits 8-5) | MNC digit 1 (bits 4-1)
pub fn encode_plmn_id(mcc: &str, mnc: &str) -> Result<[u8; 3], String> {
    let digits = |s: &str, what: &str, min: usize, max: usize| -> Result<Vec<u8>, String> {
        if s.len() < min || s.len() > max || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "plmnId.{what} '{s}' is not {min}..{max} decimal digits (TS 29.571 PlmnId)"
            ));
        }
        Ok(s.bytes().map(|b| b - b'0').collect())
    };
    let mcc_d = digits(mcc, "mcc", 3, 3)?;
    let mnc_d = digits(mnc, "mnc", 2, 3)?;
    let mnc3 = if mnc_d.len() == 3 { mnc_d[2] } else { 0x0F };
    Ok([
        (mcc_d[1] << 4) | mcc_d[0],
        (mnc3 << 4) | mcc_d[2],
        (mnc_d[1] << 4) | mnc_d[0],
    ])
}

/// TS 31.102 §4.2.5 EF_PLMNwAcT access technology identifier (2 octets).
///
/// Octet 1: b8 UTRAN, b7 E-UTRAN, b6 E-UTRAN in NB-S1 mode only, b5 E-UTRAN
/// in WB-S1 mode only, b4 NG-RAN, b3 satellite NG-RAN, b2-b1 RFU.
/// Octet 2: b8 GSM, b7 GSM COMPACT, b6 cdma2000 HRPD, b5 cdma2000 1xRTT,
/// b4 EC-GSM-IoT, b3-b1 RFU.
///
/// The TS 29.509 `AccessTech` enum values name exactly these bit
/// combinations (e.g. EUTRAN_IN_NBS1_MODE_ONLY = b7+b6). Unknown values are
/// rejected (fail-closed): silently dropping one would make the AUSF MAC a
/// different byte string than the one the UDM intends to steer with.
fn access_tech_bits(tech: &str) -> Result<(u8, u8), String> {
    Ok(match tech {
        "NR" => (0x08, 0x00),
        "SATELLITE_NG_RAN" => (0x04, 0x00),
        "UTRAN" => (0x80, 0x00),
        "EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE" => (0x40, 0x00),
        "EUTRAN_IN_NBS1_MODE_ONLY" => (0x60, 0x00),
        "EUTRAN_IN_WBS1_MODE_ONLY" => (0x50, 0x00),
        "GSM_AND_ECGSM_IoT" => (0x00, 0x88),
        "GSM_WITHOUT_ECGSM_IoT" => (0x00, 0x80),
        "ECGSM_IoT_ONLY" => (0x00, 0x08),
        "GSM_COMPACT" => (0x00, 0x40),
        "CDMA_HRPD" => (0x00, 0x20),
        "CDMA_1xRTT" => (0x00, 0x10),
        other => {
            return Err(format!(
                "unsupported AccessTech '{other}' (TS 29.509 AccessTech / TS 31.102 §4.2.5)"
            ))
        }
    })
}

/// Encode a TS 29.509 `SteeringContainer` array form (`SteeringInfo[]`) as
/// the TS 24.501 §9.11.3.51 figure 9.11.3.51.3 "PLMN ID and access
/// technology list": n entries of 5 octets each (3-octet BCD PLMN + 2-octet
/// access technology identifier), in decreasing priority order (input order
/// preserved), at most 16 entries (table 9.11.3.51.1).
///
/// These are exactly the "octets beyond octet 22" that Annex A.17 uses as P2.
pub fn encode_steering_list(entries: &[serde_json::Value]) -> Result<Vec<u8>, String> {
    if entries.is_empty() {
        return Err(
            "steeringContainer array needs at least 1 SteeringInfo (TS 29.509 minItems 1)".into(),
        );
    }
    if entries.len() > 16 {
        return Err(
            "PLMN ID and access technology list carries at most 16 entries \
             (TS 24.501 table 9.11.3.51.1)"
                .into(),
        );
    }
    let mut out = Vec::with_capacity(entries.len() * 5);
    for entry in entries {
        let plmn = entry
            .get("plmnId")
            .ok_or("SteeringInfo.plmnId is mandatory (TS 29.509 SteeringInfo)")?;
        let mcc = plmn
            .get("mcc")
            .and_then(|v| v.as_str())
            .ok_or("SteeringInfo.plmnId.mcc is mandatory")?;
        let mnc = plmn
            .get("mnc")
            .and_then(|v| v.as_str())
            .ok_or("SteeringInfo.plmnId.mnc is mandatory")?;
        out.extend_from_slice(&encode_plmn_id(mcc, mnc)?);

        // accessTechList is optional (only plmnId is required); when present
        // it must carry >= 1 technology. The identifiers OR together — one
        // 2-octet field per PLMN entry (TS 31.102 §4.2.5).
        let (mut act1, mut act2) = (0u8, 0u8);
        if let Some(list) = entry.get("accessTechList") {
            let arr = list
                .as_array()
                .ok_or("SteeringInfo.accessTechList must be an array")?;
            if arr.is_empty() {
                return Err(
                    "SteeringInfo.accessTechList needs at least 1 entry (minItems 1)".into(),
                );
            }
            for tech in arr {
                let name = tech
                    .as_str()
                    .ok_or("SteeringInfo.accessTechList entries must be strings")?;
                let (b1, b2) = access_tech_bits(name)?;
                act1 |= b1;
                act2 |= b2;
            }
        }
        out.push(act1);
        out.push(act2);
    }
    Ok(out)
}

/// The resolved MAC inputs for one Protect invocation.
struct SorMacInputs {
    /// SOR header octet(s) — P0 of Annex A.17.
    header: Vec<u8>,
    /// Steering-list octets beyond octet 22 — P2 of Annex A.17 (`None` =
    /// P2/L2 omitted entirely: HPLMN "no change" indication).
    p2: Option<Vec<u8>>,
}

/// Resolve the SOR header and P2 octets from the SorInfo body.
///
/// Precedence (TS 33.501 A.17: header "is either received from the requester
/// NF, or constructed by the AUSF"):
/// - `sorTransparentInfo` (opaque container octets beyond octet 22) is used
///   verbatim as P2; the requester MUST then also supply `sorHeader`, since
///   the AUSF cannot infer the list indication/type bits from opaque octets.
/// - else `steeringContainer`: array → TS 24.501 PLMN/access-tech list
///   (list type 1), string → base64 SecuredPacket octets (list type 0).
/// - else: HPLMN "no change" indication — P2/L2 omitted (A.17).
/// - a provided `sorHeader` (single octet, base64) always wins over the
///   constructed one.
fn resolve_sor_mac_inputs(
    sor_info: &serde_json::Value,
    ack_ind: bool,
) -> Result<SorMacInputs, Box<SbiResponse>> {
    let (p2, list_provided, list_type_plmn): (Option<Vec<u8>>, bool, bool) =
        if let Some(transparent) = sor_info.get("sorTransparentInfo") {
            let encoded = transparent.as_str().ok_or_else(|| {
                Box::new(encoding_error(
                    "sorTransparentInfo must be a base64 string (TS 29.571 Bytes)",
                ))
            })?;
            let octets = nextgcore_crypt::base64::decode(encoded)
                .filter(|o| !o.is_empty())
                .ok_or_else(|| {
                    Box::new(encoding_error(
                        "sorTransparentInfo is not valid non-empty base64",
                    ))
                })?;
            if sor_info.get("sorHeader").is_none() {
                // Fail-closed: guessing the header bits over opaque octets
                // would produce a MAC the UE rejects.
                return Err(Box::new(problem(
                    400,
                    "MANDATORY_IE_MISSING",
                    "sorHeader is required when sorTransparentInfo is provided: the AUSF \
                     cannot construct the SOR header from opaque container octets \
                     (TS 33.501 Annex A.17, TS 24.501 §9.11.3.51)",
                )));
            }
            (Some(octets), true, false)
        } else {
            match sor_info.get("steeringContainer") {
                None => (None, false, false),
                Some(serde_json::Value::Array(entries)) => {
                    let list =
                        encode_steering_list(entries).map_err(|e| Box::new(encoding_error(&e)))?;
                    (Some(list), true, true)
                }
                Some(serde_json::Value::String(secured)) => {
                    let octets = nextgcore_crypt::base64::decode(secured)
                        .filter(|o| !o.is_empty())
                        .ok_or_else(|| {
                            Box::new(encoding_error(
                                "steeringContainer SecuredPacket is not valid non-empty base64",
                            ))
                        })?;
                    (Some(octets), true, false)
                }
                Some(_) => {
                    return Err(Box::new(encoding_error(
                        "steeringContainer must be a SteeringInfo array or a base64 \
                         SecuredPacket string (TS 29.509 SteeringContainer)",
                    )))
                }
            }
        };

    let header = match sor_info.get("sorHeader") {
        Some(h) => {
            let encoded = h.as_str().ok_or_else(|| {
                Box::new(encoding_error(
                    "sorHeader must be a base64 string (TS 29.571 Bytes)",
                ))
            })?;
            let octets = nextgcore_crypt::base64::decode(encoded)
                .ok_or_else(|| Box::new(encoding_error("sorHeader is not valid base64")))?;
            if octets.len() != 1 {
                return Err(Box::new(encoding_error(
                    "sorHeader must decode to exactly one octet (TS 24.501 §9.11.3.51 octet 4)",
                )));
            }
            octets
        }
        None => vec![build_sor_header(ack_ind, list_provided, list_type_plmn)],
    };

    Ok(SorMacInputs { header, p2 })
}

/// `POST /nausf-sorprotection/v1/{supi}/ue-sor` — Nausf_SoRProtection Protect
/// (TS 29.509, TS 33.501 §14.1.3).
pub fn handle_sor_protect(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Nausf_SoRProtection Protect: supi={supi}");

    let Some(body) = request.http.content.as_deref() else {
        return problem(400, "MANDATORY_IE_MISSING", "Missing SorInfo request body");
    };
    let sor_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return problem(
                400,
                "INVALID_MSG_FORMAT",
                &format!("Invalid SorInfo JSON: {e}"),
            )
        }
    };

    // TS 29.509 SorInfo: ackInd is the only mandatory IE — fail-closed reject.
    let Some(ack_ind) = sor_info.get("ackInd").and_then(|v| v.as_bool()) else {
        return problem(
            400,
            "MANDATORY_IE_MISSING",
            "SorInfo.ackInd is mandatory (TS 29.509 SorInfo required: ackInd)",
        );
    };

    let inputs = match resolve_sor_mac_inputs(&sor_info, ack_ind) {
        Ok(inputs) => inputs,
        Err(response) => return *response,
    };

    let ctx = ausf_self();
    let Ok(context) = ctx.read() else {
        return problem(500, "SYSTEM_FAILURE", "AUSF context lock poisoned");
    };

    // TS 33.501 §6.14.1: the MAC key is the latest KAUSF from the anchor
    // store. Absent anchor → 404, never a MAC with a zero key (fail-closed).
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

    // §6.14.2.3 counter lifecycle: this allocator is the ONLY counter read
    // path; on wrap the counter is NOT consumed and the service is suspended.
    let counter_sor = match context.anchor_next_sor_counter(supi) {
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
                "Counter_SoR is about to wrap: SoR protection suspended until a fresh \
                 KAUSF (TS 33.501 §6.14.2.3, §14.1.3 'or error (counter_wrap)')",
            );
        }
    };

    // Annex A.17 (FC 0x77): SoR-MAC-I_AUSF over header || counter || P2.
    let sor_mac_iausf =
        nextgcore_kdf_sor_mac_iausf(&kausf, &inputs.header, counter_sor, inputs.p2.as_deref());

    // TS 29.509 SorSecurityInfo: sorMacIausf + counterSor required (SorMac =
    // 32 hex chars, CounterSor = 4 hex chars); sorXmacIue iff ack requested
    // (§14.1.3 Output Optional, Annex A.18 with the SAME counter).
    let mut security_info = serde_json::json!({
        "sorMacIausf": bytes_to_hex(&sor_mac_iausf),
        "counterSor": format!("{counter_sor:04x}"),
    });
    if ack_ind {
        let sor_xmac_iue = nextgcore_kdf_sor_mac_iue(&kausf, counter_sor);
        security_info["sorXmacIue"] = serde_json::Value::String(bytes_to_hex(&sor_xmac_iue));
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

    fn post_sor(supi: &str, body: &serde_json::Value) -> SbiResponse {
        let request = SbiRequest::post(format!("/nausf-sorprotection/v1/{supi}/ue-sor"))
            .with_json_body(body)
            .expect("build request");
        handle_sor_protect(supi, &request)
    }

    fn body_json(response: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(response.http.content.as_deref().unwrap_or("{}")).expect("JSON body")
    }

    fn test_kausf(tag: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = tag ^ (i as u8);
        }
        k
    }

    /// The golden two-entry container used across the handler tests.
    fn golden_container() -> serde_json::Value {
        serde_json::json!([
            {"plmnId": {"mcc": "001", "mnc": "01"}, "accessTechList": ["NR"]},
            {"plmnId": {"mcc": "310", "mnc": "410"},
             "accessTechList": ["NR", "EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE"]}
        ])
    }

    /// Hand-derived wire bytes for `golden_container()` (TS 24.501
    /// §9.11.3.51 fig. 9.11.3.51.3 + TS 31.102 §4.2.5):
    ///
    /// entry 1: mcc=001 mnc=01 → BCD 00 F1 10 (MNC digit 3 = 0xF for the
    ///          2-digit MNC); AcT NR → NG-RAN bit b4 of octet 1 = 08 00
    /// entry 2: mcc=310 mnc=410 → BCD 13 00 14; AcT NR|E-UTRAN → 48 00
    const GOLDEN_LIST: [u8; 10] = [0x00, 0xF1, 0x10, 0x08, 0x00, 0x13, 0x00, 0x14, 0x48, 0x00];

    // ------------------------------------------------------------------
    // Golden byte-vectors (hand-derived, never roundtrip-only)
    // ------------------------------------------------------------------

    #[test]
    fn golden_steering_list_wire_vector() {
        let entries = golden_container();
        let encoded = encode_steering_list(entries.as_array().unwrap()).expect("encode");
        assert_eq!(encoded, GOLDEN_LIST);
    }

    #[test]
    fn golden_steering_list_gsm_family_vector() {
        // mcc=262 mnc=02 → BCD 62 F2 20; UTRAN → octet1 b8 = 0x80,
        // GSM_AND_ECGSM_IoT → octet2 b8|b4 = 0x88 (TS 31.102 §4.2.5).
        let entries = serde_json::json!([
            {"plmnId": {"mcc": "262", "mnc": "02"},
             "accessTechList": ["UTRAN", "GSM_AND_ECGSM_IoT"]}
        ]);
        let encoded = encode_steering_list(entries.as_array().unwrap()).expect("encode");
        assert_eq!(encoded, [0x62, 0xF2, 0x20, 0x80, 0x88]);
    }

    #[test]
    fn golden_plmn_without_access_tech_has_zero_act_octets() {
        // accessTechList is optional — the 2 AcT octets are still emitted
        // (every EF_PLMNwAcT entry is exactly 5 octets), just all-zero.
        let entries = serde_json::json!([{"plmnId": {"mcc": "001", "mnc": "01"}}]);
        let encoded = encode_steering_list(entries.as_array().unwrap()).expect("encode");
        assert_eq!(encoded, [0x00, 0xF1, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn sor_header_octet4_bit_rules() {
        // TS 24.501 fig. 9.11.3.51.5: b1 data type, b2 list ind, b3 list
        // type, b4 ACK.
        assert_eq!(build_sor_header(true, true, true), 0x0E, "ack + PLMN list");
        assert_eq!(
            build_sor_header(false, true, false),
            0x02,
            "secured packet, no ack"
        );
        assert_eq!(
            build_sor_header(true, false, false),
            0x08,
            "HPLMN no-change + ack"
        );
        assert_eq!(
            build_sor_header(false, false, false),
            0x00,
            "no-change, no ack"
        );
    }

    #[test]
    fn steering_list_rejections() {
        // > 16 entries (TS 24.501 table 9.11.3.51.1).
        let big: Vec<serde_json::Value> = (0..17)
            .map(|_| serde_json::json!({"plmnId": {"mcc": "001", "mnc": "01"}}))
            .collect();
        assert!(encode_steering_list(&big).is_err());
        // missing plmnId (mandatory).
        assert!(
            encode_steering_list(&[serde_json::json!({"accessTechList": ["NR"]})])
                .unwrap_err()
                .contains("mandatory")
        );
        // unknown access technology (fail-closed).
        let bad = serde_json::json!([
            {"plmnId": {"mcc": "001", "mnc": "01"}, "accessTechList": ["6G_RAN"]}
        ]);
        assert!(encode_steering_list(bad.as_array().unwrap()).is_err());
        // malformed mcc/mnc.
        assert!(encode_plmn_id("01", "01").is_err());
        assert!(encode_plmn_id("001", "0x1").is_err());
        // empty accessTechList violates minItems 1.
        let empty_act = serde_json::json!([
            {"plmnId": {"mcc": "001", "mnc": "01"}, "accessTechList": []}
        ]);
        assert!(encode_steering_list(empty_act.as_array().unwrap()).is_err());
    }

    // ------------------------------------------------------------------
    // Handler behaviour (real handler fn, real anchor store)
    // ------------------------------------------------------------------

    #[test]
    fn sor_happy_path_with_ack_returns_all_three_fields_and_mac_is_reproducible() {
        ausf_context_init(64);
        let supi = "imsi-999700000000101";
        let kausf = test_kausf(0xA1);
        ausf_self().read().unwrap().anchor_refresh(supi, &kausf);

        let response = post_sor(
            supi,
            &serde_json::json!({
                "ackInd": true,
                "steeringContainer": golden_container(),
            }),
        );
        assert_eq!(response.status, 200, "body: {:?}", response.http.content);
        let json = body_json(&response);

        // counterSor: first MAC after a fresh KAUSF uses 0x0001 (§6.14.2.3).
        assert_eq!(json["counterSor"], "0001");

        // Reproduce the MAC from the documented S-string inputs: header 0x0E
        // (ack + list ind + PLMN list type), counter 0x0001, P2 = the
        // hand-derived golden list bytes. The handler's MAC must match a
        // recompute that does NOT reuse any handler intermediates.
        let expected_mac = nextgcore_kdf_sor_mac_iausf(&kausf, &[0x0E], 0x0001, Some(&GOLDEN_LIST));
        assert_eq!(
            hex_to_bytes(json["sorMacIausf"].as_str().unwrap()),
            expected_mac.to_vec()
        );

        // ackInd=true → sorXmacIue present, Annex A.18 with the SAME counter.
        let expected_xmac = nextgcore_kdf_sor_mac_iue(&kausf, 0x0001);
        assert_eq!(
            hex_to_bytes(json["sorXmacIue"].as_str().unwrap()),
            expected_xmac.to_vec()
        );
    }

    #[test]
    fn sor_without_ack_omits_xmac() {
        ausf_context_init(64);
        let supi = "imsi-999700000000102";
        ausf_self()
            .read()
            .unwrap()
            .anchor_refresh(supi, &test_kausf(0xA2));

        let response = post_sor(
            supi,
            &serde_json::json!({
                "ackInd": false,
                "steeringContainer": golden_container(),
            }),
        );
        assert_eq!(response.status, 200);
        let json = body_json(&response);
        assert!(json.get("sorMacIausf").is_some());
        assert!(
            json.get("sorXmacIue").is_none(),
            "no XMAC when ack not requested"
        );
    }

    #[test]
    fn sor_no_steering_container_is_hplmn_no_change_with_p2_omitted() {
        ausf_context_init(64);
        let supi = "imsi-999700000000103";
        let kausf = test_kausf(0xA3);
        ausf_self().read().unwrap().anchor_refresh(supi, &kausf);

        let response = post_sor(supi, &serde_json::json!({"ackInd": true}));
        assert_eq!(response.status, 200);
        let json = body_json(&response);

        // Header 0x08 (ack, list indication 0), P2/L2 omitted (A.17).
        let expected_mac = nextgcore_kdf_sor_mac_iausf(&kausf, &[0x08], 0x0001, None);
        assert_eq!(
            hex_to_bytes(json["sorMacIausf"].as_str().unwrap()),
            expected_mac.to_vec()
        );
    }

    #[test]
    fn sor_secured_packet_container_uses_decoded_octets_as_p2() {
        ausf_context_init(64);
        let supi = "imsi-999700000000104";
        let kausf = test_kausf(0xA4);
        ausf_self().read().unwrap().anchor_refresh(supi, &kausf);

        let packet = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let response = post_sor(
            supi,
            &serde_json::json!({
                "ackInd": false,
                "steeringContainer": nextgcore_crypt::base64::encode(&packet),
            }),
        );
        assert_eq!(response.status, 200);
        let json = body_json(&response);

        // Header 0x02 (list ind 1, list type 0 = secured packet, no ack).
        let expected_mac = nextgcore_kdf_sor_mac_iausf(&kausf, &[0x02], 0x0001, Some(&packet));
        assert_eq!(
            hex_to_bytes(json["sorMacIausf"].as_str().unwrap()),
            expected_mac.to_vec()
        );
    }

    #[test]
    fn sor_provided_header_wins_and_transparent_info_requires_header() {
        ausf_context_init(64);
        let supi = "imsi-999700000000105";
        let kausf = test_kausf(0xA5);
        ausf_self().read().unwrap().anchor_refresh(supi, &kausf);

        // sorTransparentInfo without sorHeader → 400 (fail-closed).
        let opaque = [0x11u8, 0x22, 0x33];
        let response = post_sor(
            supi,
            &serde_json::json!({
                "ackInd": true,
                "sorTransparentInfo": nextgcore_crypt::base64::encode(&opaque),
            }),
        );
        assert_eq!(response.status, 400);
        assert_eq!(body_json(&response)["cause"], "MANDATORY_IE_MISSING");

        // With sorHeader: the provided header + verbatim octets are MACed.
        let response = post_sor(
            supi,
            &serde_json::json!({
                "ackInd": true,
                "sorHeader": nextgcore_crypt::base64::encode(&[0x0A]),
                "sorTransparentInfo": nextgcore_crypt::base64::encode(&opaque),
            }),
        );
        assert_eq!(response.status, 200);
        let json = body_json(&response);
        let expected_mac = nextgcore_kdf_sor_mac_iausf(&kausf, &[0x0A], 0x0001, Some(&opaque));
        assert_eq!(
            hex_to_bytes(json["sorMacIausf"].as_str().unwrap()),
            expected_mac.to_vec()
        );

        // Multi-octet sorHeader → 400 (octet 4 is exactly one octet).
        let response = post_sor(
            supi,
            &serde_json::json!({
                "ackInd": true,
                "sorHeader": nextgcore_crypt::base64::encode(&[0x0A, 0x0B]),
            }),
        );
        assert_eq!(response.status, 400);
    }

    #[test]
    fn sor_missing_ack_ind_is_400_mandatory_ie_missing() {
        ausf_context_init(64);
        let supi = "imsi-999700000000106";
        ausf_self()
            .read()
            .unwrap()
            .anchor_refresh(supi, &test_kausf(0xA6));

        let response = post_sor(
            supi,
            &serde_json::json!({
                "steeringContainer": golden_container(),
            }),
        );
        assert_eq!(response.status, 400);
        assert_eq!(body_json(&response)["cause"], "MANDATORY_IE_MISSING");

        // Missing body entirely.
        let request = SbiRequest::post("/nausf-sorprotection/v1/x/ue-sor");
        let response = handle_sor_protect(supi, &request);
        assert_eq!(response.status, 400);
        assert_eq!(body_json(&response)["cause"], "MANDATORY_IE_MISSING");
    }

    #[test]
    fn sor_unknown_supi_is_404_context_not_found_never_a_mac() {
        ausf_context_init(64);
        let response = post_sor(
            "imsi-999700000000199",
            &serde_json::json!({
                "ackInd": true,
                "steeringContainer": golden_container(),
            }),
        );
        assert_eq!(response.status, 404);
        let json = body_json(&response);
        assert_eq!(json["cause"], "CONTEXT_NOT_FOUND");
        assert!(
            json.get("sorMacIausf").is_none(),
            "404 must never carry a MAC"
        );
    }

    #[test]
    fn sor_counter_freshness_two_calls_two_counters_two_macs() {
        ausf_context_init(64);
        let supi = "imsi-999700000000107";
        ausf_self()
            .read()
            .unwrap()
            .anchor_refresh(supi, &test_kausf(0xA7));

        let body = serde_json::json!({"ackInd": true, "steeringContainer": golden_container()});
        let first = body_json(&post_sor(supi, &body));
        let second = body_json(&post_sor(supi, &body));
        assert_eq!(first["counterSor"], "0001");
        assert_eq!(second["counterSor"], "0002");
        assert_ne!(
            first["sorMacIausf"], second["sorMacIausf"],
            "identical input must yield different MACs across counters (freshness)"
        );
        assert_ne!(first["sorXmacIue"], second["sorXmacIue"]);
    }

    #[test]
    fn sor_counter_wrap_is_503_and_not_consumed() {
        ausf_context_init(64);
        let supi = "imsi-999700000000108";
        let ctx = ausf_self();
        ctx.read().unwrap().anchor_refresh(supi, &test_kausf(0xA8));
        assert!(ctx
            .read()
            .unwrap()
            .anchor_force_counters(supi, 0xFFFF, 0xFFFF));

        let body = serde_json::json!({"ackInd": true, "steeringContainer": golden_container()});
        let response = post_sor(supi, &body);
        assert_eq!(response.status, 503);
        assert_eq!(body_json(&response)["cause"], "COUNTER_WRAP");

        // NOT consumed: the wrap answer must repeat, not roll over.
        let response = post_sor(supi, &body);
        assert_eq!(response.status, 503, "counter must not be consumed on wrap");

        // Fresh KAUSF lifts the suspension (§6.14.2.3 reset).
        ctx.read().unwrap().anchor_refresh(supi, &test_kausf(0xA9));
        let response = post_sor(supi, &body);
        assert_eq!(response.status, 200);
        assert_eq!(body_json(&response)["counterSor"], "0001");
    }
}
