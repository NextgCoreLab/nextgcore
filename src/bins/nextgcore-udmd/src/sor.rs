//! Steering-of-Roaming (SoR) injection into Nudm_SDM am-data (Wave-6 F-04).
//!
//! TS 33.501 §6.14.2.1 steps 7-10: when the UDM decides to send Steering of
//! Roaming information it **shall** invoke Nausf_SoRProtection (there is NO
//! unprotected delivery path in 33.501) and include the returned protected
//! `SorInfo` in the AccessAndMobilitySubscriptionData (TS 29.503 §6.1.6.3.2,
//! specs/TS29503_Nudm_SDM.yaml:4418).
//!
//! Fail-closed (spec choice, cited at the call site): on any AUSF
//! error/timeout/counter_wrap the UDM OMITS `sorInfo` entirely and returns the
//! rest of am-data — it never emits a `steeringContainer` without a matching
//! `sorMacIausf`. Absence of a steering source (no UDR-provisioned `sorInfo`
//! and no `sor` config) leaves the am-data body byte-identical to the UDR
//! response (the matched-sim default-safety mechanism).

use crate::context::{udm_self, SorSteeringConfig};
use crate::sbi_path::udm_ausf_send_sor_protect;

/// Format the current wall-clock time as an RFC 3339 / ISO-8601 UTC string
/// (the `DateTime` shape TS 29.571 expects for `SorInfo.provisioningTime`).
/// Dependency-free civil-date conversion (Howard Hinnant's algorithm), matching
/// the helper already used by mbsmfd.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Resolve the Steering-of-Roaming source for an am-data body (TS 33.501
/// §6.14.2.1 / F-04 step 1). Precedence:
/// - (a) a UDR-provisioned `sorInfo.steeringContainer` (operator provisioned in
///   the UDR) wins;
/// - (b) else the udmd `sor` config section;
/// - else `None` → byte-identical passthrough.
///
/// Returns `(steeringContainer, ackInd)`. For the UDR-provisioned form the
/// `ackInd` defaults to `true` (request the UE acknowledgement) unless the
/// provisioned `sorInfo` states otherwise.
pub(crate) fn resolve_steering_source(
    am_data: &serde_json::Value,
    config: Option<SorSteeringConfig>,
) -> Option<(serde_json::Value, bool)> {
    if let Some(sor) = am_data.get("sorInfo") {
        if let Some(container) = sor.get("steeringContainer") {
            let ack_ind = sor.get("ackInd").and_then(|v| v.as_bool()).unwrap_or(true);
            return Some((container.clone(), ack_ind));
        }
    }
    config.map(|c| (c.steering_container, c.ack_ind))
}

/// Build the TS 29.503 `SorInfo` object from the AUSF's `SorSecurityInfo`
/// (F-04 step 3). Returns `None` when the security info lacks either mandatory
/// TS 29.509 field (`sorMacIausf`/`counterSor`) — the caller then withholds
/// `sorInfo` (fail-closed): a `steeringContainer` never ships without a MAC.
///
/// Field names are asserted verbatim against TS29503_Nudm_SDM.yaml:4418 —
/// note `countersor` is lowercase-s (a genuine spec quirk) while the TS 29.509
/// wire field is `counterSor`.
pub(crate) fn build_sor_info(
    steering_container: &serde_json::Value,
    ack_ind: bool,
    security_info: &serde_json::Value,
    provisioning_time: &str,
) -> Option<serde_json::Value> {
    let sor_mac_iausf = security_info.get("sorMacIausf")?.as_str()?;
    let counter_sor = security_info.get("counterSor")?.as_str()?;
    Some(serde_json::json!({
        "steeringContainer": steering_container,
        "ackInd": ack_ind,
        "sorMacIausf": sor_mac_iausf,
        "countersor": counter_sor,
        "provisioningTime": provisioning_time,
    }))
}

/// Serialize an am-data body from which `sorInfo` has been removed — the
/// fail-closed / withhold path. Guaranteed to carry no `sorInfo` (and hence no
/// `steeringContainer`, which only ever nests inside it per TS 29.503).
fn withhold(mut am_data: serde_json::Value) -> String {
    if let Some(obj) = am_data.as_object_mut() {
        obj.remove("sorInfo");
    }
    // Serializing a `serde_json::Value` cannot fail in practice.
    serde_json::to_string(&am_data).unwrap_or_else(|_| "{}".to_string())
}

/// Temporarily store the expected SoR-XMAC-I_UE for `supi` (TS 33.501
/// §6.14.2.1 step 10), so the SoR ack verify (F-06) can compare it constant-time
/// against the UE-supplied SoR-MAC-I_UE. Pins the Counter_SoR alongside for
/// replay defence. Best-effort: a malformed XMAC just skips the pin.
fn store_expected_xmac(supi: &str, security_info: &serde_json::Value) {
    let Some(xmac_hex) = security_info.get("sorXmacIue").and_then(|v| v.as_str()) else {
        return;
    };
    let bytes = crate::nudm_handler::hex_to_bytes(xmac_hex);
    let Ok(xmac) = <[u8; 16]>::try_from(bytes.as_slice()) else {
        log::warn!("[{supi}] sorXmacIue is not 16 bytes — not pinning expected XMAC");
        return;
    };
    let counter = security_info
        .get("counterSor")
        .and_then(|v| v.as_str())
        .and_then(|s| u16::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let ctx = udm_self();
    let stored = match ctx.read() {
        Ok(guard) => guard.sor_store_expected_xmac(supi, xmac, counter),
        Err(_) => false,
    };
    if !stored {
        log::warn!("[{supi}] could not pin expected SoR-XMAC-I_UE");
    }
}

/// Inject a protected `sorInfo` into the UDR am-data body when a steering
/// source is configured, calling the real Nausf_SoRProtection producer.
///
/// This is the parameterised core (config + authenticating AUSF supplied by
/// the caller) so it is deterministically testable; [`maybe_inject_sor_info`]
/// wraps it with the process-global UDM context reads.
pub(crate) async fn inject_sor_info(
    supi: &str,
    raw: String,
    config: Option<SorSteeringConfig>,
    ausf_instance_id: Option<String>,
) -> String {
    // Only a JSON object can carry sorInfo; anything else forwards verbatim.
    let mut am_data = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) if v.is_object() => v,
        _ => return raw,
    };

    // No steering source anywhere → byte-identical passthrough (default-safe).
    let (steering_container, ack_ind) = match resolve_steering_source(&am_data, config) {
        Some(source) => source,
        None => return raw,
    };

    // Fail-closed: from here a `steeringContainer` must never leave without a
    // matching `sorMacIausf`. Drop any UDR-provisioned (unprotected) sorInfo up
    // front; it is re-added only after the AUSF returns the MAC.
    if let Some(obj) = am_data.as_object_mut() {
        obj.remove("sorInfo");
    }

    let sor_info_request = serde_json::json!({
        "steeringContainer": steering_container,
        "ackInd": ack_ind,
    });

    // TS 33.501 §6.14.2.1 step 9: the UDM SHALL invoke Nausf_SoRProtection.
    // 33.501 defines NO unprotected delivery path, so any AUSF failure means
    // WITHHOLD (fail-closed) — never emit an unprotected steering list.
    let ausf_response =
        match udm_ausf_send_sor_protect(supi, ausf_instance_id.as_deref(), &sor_info_request).await
        {
            Ok(resp) if resp.is_success() => resp,
            Ok(resp) => {
                log::warn!(
                    "[{supi}] Nausf_SoRProtection returned {} — withholding sorInfo \
                     (fail-closed, TS 33.501 §6.14.2.1)",
                    resp.status
                );
                return withhold(am_data);
            }
            Err(e) => {
                log::warn!(
                    "[{supi}] Nausf_SoRProtection call failed: {e} — withholding sorInfo \
                     (fail-closed, TS 33.501 §6.14.2.1)"
                );
                return withhold(am_data);
            }
        };

    let security_info: serde_json::Value = match ausf_response
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str(b).ok())
    {
        Some(value) => value,
        None => {
            log::warn!(
                "[{supi}] SoRProtection response had no parseable SorSecurityInfo — withholding"
            );
            return withhold(am_data);
        }
    };

    let Some(sor_info) =
        build_sor_info(&steering_container, ack_ind, &security_info, &now_rfc3339())
    else {
        log::warn!("[{supi}] SorSecurityInfo missing sorMacIausf/counterSor — withholding");
        return withhold(am_data);
    };

    // §6.14.2.1 step 10: pin the expected SoR-XMAC-I_UE for the F-06 ack verify.
    if ack_ind {
        store_expected_xmac(supi, &security_info);
    }

    if let Some(obj) = am_data.as_object_mut() {
        obj.insert("sorInfo".to_string(), sor_info);
    }
    serde_json::to_string(&am_data).unwrap_or_else(|_| withhold(am_data.clone()))
}

/// F-04 entry point called from `handle_get_am_data`: reads the udmd `sor`
/// config + this UE's authenticating AUSF from the process-global context (in a
/// short guard scope, never held across the AUSF await — the
/// nf-context-lock-deadlocks learning), then delegates to [`inject_sor_info`].
pub async fn maybe_inject_sor_info(supi: &str, raw: String) -> String {
    let (config, ausf_instance_id) = {
        let ctx = udm_self();
        let guard = match ctx.read() {
            Ok(guard) => guard,
            Err(_) => return raw,
        };
        (
            guard.sor_steering(),
            guard.ue_find_by_supi(supi).and_then(|ue| ue.ausf_instance_id),
        )
    };
    inject_sor_info(supi, raw, config, ausf_instance_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical two-entry steering container (mirrors the ausfd F-03 golden
    /// vector so the strict-peer recompute below lines up).
    fn golden_container() -> serde_json::Value {
        serde_json::json!([
            {"plmnId": {"mcc": "001", "mnc": "01"}, "accessTechList": ["NR"]},
            {"plmnId": {"mcc": "310", "mnc": "410"},
             "accessTechList": ["NR", "EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE"]}
        ])
    }

    /// The hand-derived TS 24.501 §9.11.3.51 wire bytes for `golden_container()`
    /// (identical derivation to ausfd's GOLDEN_LIST — used for the independent
    /// MAC recompute, NOT taken from any handler intermediate).
    const GOLDEN_LIST: [u8; 10] = [0x00, 0xF1, 0x10, 0x08, 0x00, 0x13, 0x00, 0x14, 0x48, 0x00];

    fn config(ack: bool) -> SorSteeringConfig {
        SorSteeringConfig {
            steering_container: golden_container(),
            ack_ind: ack,
        }
    }

    // ---- pure helpers --------------------------------------------------------

    #[test]
    fn now_rfc3339_has_datetime_shape() {
        let ts = now_rfc3339();
        // YYYY-MM-DDThh:mm:ssZ = 20 chars, ends with Z, has the T separator.
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn resolve_prefers_udr_provisioned_sor_then_config() {
        // (a) UDR-provisioned sorInfo.steeringContainer wins over config.
        let am_data = serde_json::json!({
            "sorInfo": {"steeringContainer": [{"plmnId": {"mcc": "262", "mnc": "02"}}],
                        "ackInd": false}
        });
        let resolved = resolve_steering_source(&am_data, Some(config(true)));
        let (container, ack) = resolved.expect("UDR-provisioned source");
        assert_eq!(container[0]["plmnId"]["mcc"], "262");
        assert!(!ack, "UDR-provisioned ackInd=false honoured");

        // (b) no UDR sorInfo → config source.
        let am_data = serde_json::json!({"gpsis": ["msisdn-1"]});
        let (container, ack) = resolve_steering_source(&am_data, Some(config(true)))
            .expect("config source");
        assert_eq!(container, golden_container());
        assert!(ack);

        // none → passthrough.
        assert!(resolve_steering_source(&am_data, None).is_none());
    }

    #[test]
    fn build_sor_info_emits_exactly_the_five_ts29503_fields() {
        // Stand-in SorSecurityInfo (shape identical to the real AUSF 200 body).
        let security = serde_json::json!({
            "sorMacIausf": "0123456789abcdef0123456789abcdef",
            "counterSor": "0001",
            "sorXmacIue": "fedcba9876543210fedcba9876543210",
        });
        let sor = build_sor_info(&golden_container(), true, &security, "2026-07-01T00:00:00Z")
            .expect("all mandatory fields present");
        let obj = sor.as_object().unwrap();

        // Exactly the 5 TS29503 SorInfo fields, correct names/types.
        assert_eq!(obj.len(), 5);
        assert!(obj.contains_key("steeringContainer"));
        assert_eq!(sor["ackInd"], serde_json::Value::Bool(true));
        assert_eq!(sor["sorMacIausf"], "0123456789abcdef0123456789abcdef");
        // spec quirk: lowercase `countersor` in TS29503, not `counterSor`.
        assert_eq!(sor["countersor"], "0001");
        assert!(obj.get("counterSor").is_none(), "TS29503 uses lowercase countersor");
        assert_eq!(sor["provisioningTime"], "2026-07-01T00:00:00Z");
    }

    #[test]
    fn build_sor_info_withholds_when_mandatory_mac_absent() {
        // Missing sorMacIausf → None (caller fail-closes).
        let no_mac = serde_json::json!({"counterSor": "0001"});
        assert!(build_sor_info(&golden_container(), true, &no_mac, "t").is_none());
        // Missing counterSor → None.
        let no_counter = serde_json::json!({"sorMacIausf": "00"});
        assert!(build_sor_info(&golden_container(), true, &no_counter, "t").is_none());
    }

    /// The injected `sorMacIausf` must be the genuine Annex A.17 MAC, byte-exact
    /// against an INDEPENDENT recompute from the KAUSF + counter + hand-derived
    /// steering wire (F-01 KDF, the same one the ausfd producer uses in F-03).
    /// This is the falsifiable "reproduce-the-MAC" check at F-04's data level;
    /// the full in-process real-ausfd loopback is F-07's strict-peer suite.
    #[test]
    fn injected_mac_is_reproducible_from_kausf_and_wire_bytes() {
        // A known KAUSF (the anchor an authenticated UE would hold).
        let mut kausf = [0u8; 32];
        for (i, b) in kausf.iter_mut().enumerate() {
            *b = 0xB1 ^ (i as u8);
        }

        // Independent Annex A.17 recompute (header 0x0E = ack + list ind + PLMN
        // list type, counter 0x0001, P2 = the golden wire bytes) — this stands
        // in for the SorSecurityInfo the AUSF returns.
        let mac =
            nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iausf(&kausf, &[0x0E], 0x0001, Some(&GOLDEN_LIST));
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&kausf, 0x0001);
        let security = serde_json::json!({
            "sorMacIausf": crate::nudm_handler::bytes_to_hex(&mac),
            "counterSor": "0001",
            "sorXmacIue": crate::nudm_handler::bytes_to_hex(&xmac),
        });

        // F-04 injection must carry that MAC verbatim into TS29503 SorInfo.
        let sor = build_sor_info(&golden_container(), true, &security, &now_rfc3339())
            .expect("full SorSecurityInfo");
        assert_eq!(sor["countersor"], "0001");
        assert_eq!(
            sor["sorMacIausf"].as_str().unwrap(),
            crate::nudm_handler::bytes_to_hex(&mac),
            "injected sorMacIausf must equal the independent Annex A.17 recompute"
        );
        // Flip one wire byte → a different MAC (non-malleability sanity).
        let mut tampered = GOLDEN_LIST;
        tampered[0] ^= 0x01;
        let mac2 =
            nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iausf(&kausf, &[0x0E], 0x0001, Some(&tampered));
        assert_ne!(mac, mac2, "the MAC must depend on the steering-list bytes");
    }

    // ---- orchestration (fail-closed + byte-identity) -------------------------

    /// No steering source (no UDR sorInfo, no config) → the response body is
    /// byte-identical to the UDR body. This is the matched-sim default guard.
    #[tokio::test]
    async fn no_source_is_byte_identical_passthrough() {
        let raw = r#"{"gpsis":["msisdn-12345"],"subscribedUeAmbr":{"uplink":"1 Gbps","downlink":"2 Gbps"}}"#;
        let out = inject_sor_info("imsi-001010000000001", raw.to_string(), None, None).await;
        assert_eq!(out, raw, "no steering source must not touch the UDR body");
    }

    /// Non-JSON / non-object UDR bodies also pass through verbatim.
    #[tokio::test]
    async fn non_object_body_is_passthrough() {
        let raw = "not-json";
        let out = inject_sor_info("imsi-x", raw.to_string(), Some(config(true)), None).await;
        assert_eq!(out, raw);
    }

    /// FAIL-CLOSED: steering configured but the AUSF is unreachable (no
    /// instance-id, none cached, no env) → the response carries NO `sorInfo`
    /// and NO `steeringContainer` anywhere, yet the rest of am-data survives.
    #[tokio::test]
    async fn ausf_unreachable_withholds_sor_info() {
        let raw = r#"{"gpsis":["msisdn-9"]}"#;
        let out = inject_sor_info("imsi-001010000000009", raw.to_string(), Some(config(true)), None)
            .await;
        assert!(!out.contains("sorInfo"), "fail-closed: no sorInfo when AUSF down: {out}");
        assert!(
            !out.contains("steeringContainer"),
            "fail-closed: an unprotected steering list must never leak: {out}"
        );
        // The rest of am-data is still returned normally.
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["gpsis"][0], "msisdn-9");
    }

    /// FAIL-CLOSED (UDR-provisioned form): a UDR body that already carries an
    /// unprotected `sorInfo.steeringContainer` must NOT leak it when the AUSF
    /// cannot protect it — the pre-existing sorInfo is stripped.
    #[tokio::test]
    async fn udr_provisioned_unprotected_sor_is_stripped_when_ausf_down() {
        let raw = r#"{"gpsis":["msisdn-3"],"sorInfo":{"steeringContainer":[{"plmnId":{"mcc":"262","mnc":"02"}}],"ackInd":true}}"#;
        let out = inject_sor_info("imsi-001010000000003", raw.to_string(), None, None).await;
        assert!(!out.contains("sorInfo"), "unprotected UDR sorInfo must be stripped: {out}");
        assert!(!out.contains("steeringContainer"), "no steering list may leak: {out}");
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["gpsis"][0], "msisdn-3");
    }
}
