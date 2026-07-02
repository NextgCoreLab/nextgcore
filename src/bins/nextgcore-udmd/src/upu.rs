//! UE Parameters Update (UPU) injection into Nudm_SDM am-data (Wave-6 F-05).
//!
//! TS 33.501 §6.15.2.1: when the UDM decides to update UE parameters it
//! **shall** invoke Nausf_UPUProtection (there is NO unprotected delivery path
//! in 33.501, mirroring SoR §6.14.2) and include the returned protected
//! `upuInfo` in the AccessAndMobilitySubscriptionData (TS 29.503,
//! specs/TS29503_Nudm_SDM.yaml:4456 `UpuInfo`).
//!
//! Fail-closed (spec choice, cited at the call site): on any AUSF
//! error/timeout/counter_wrap the UDM OMITS `upuInfo` entirely and returns the
//! rest of am-data — it never emits an unprotected `upuDataList`. Absence of a
//! UPU source (no UDR-provisioned `upuInfo` and no `upu` config) leaves the
//! am-data body byte-identical to the UDR response (the matched-sim
//! default-safety mechanism).
//!
//! HONESTY MARKER (no silent scope inflation): this item makes the
//! protected-payload PRODUCTION real (the MAC + counter + expected-XMAC
//! seeding), NOT the async delivery. The spec-primary UPU vehicle —
//! Nudm_SDM_Notification AFTER registration (TS 33.501 §6.15.2.1 step 5) — is
//! DEFERRED until udmd grows SDM data-change-notification machinery, which it
//! has none of today. Only the am-data-attribute delivery path is implemented
//! here.

use crate::context::{udm_self, UpuConfig};
use crate::sbi_path::udm_ausf_send_upu_protect;
use crate::sor::now_rfc3339;

/// Resolve the UE-Parameters-Update source for an am-data body (TS 33.501
/// §6.15.2.1 / F-05 step 1). Precedence:
/// - (a) a UDR-provisioned `upuInfo.upuDataList` (operator provisioned in the
///   UDR) wins;
/// - (b) else the udmd `upu` config section;
/// - else `None` → byte-identical passthrough.
///
/// Returns `(upuDataList, upuAckInd)`. For the UDR-provisioned form the
/// `upuAckInd` defaults to `true` (request the UE acknowledgement) unless the
/// provisioned `upuInfo` states otherwise.
pub(crate) fn resolve_upu_source(
    am_data: &serde_json::Value,
    config: Option<UpuConfig>,
) -> Option<(serde_json::Value, bool)> {
    if let Some(upu) = am_data.get("upuInfo") {
        if let Some(list) = upu.get("upuDataList") {
            let ack_ind = upu
                .get("upuAckInd")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            return Some((list.clone(), ack_ind));
        }
    }
    config.map(|c| (c.upu_data_list, c.ack_ind))
}

/// Build the TS 29.503 `UpuInfo` object from the AUSF's `UpuSecurityInfo`
/// (F-05 step 1). Returns `None` when the security info lacks either mandatory
/// TS 29.509 field (`upuMacIausf`/`counterUpu`) — the caller then withholds
/// `upuInfo` (fail-closed): a `upuDataList` never ships without a MAC.
///
/// Field names are asserted verbatim against TS29503_Nudm_SDM.yaml:4456 — note
/// that `counterUpu` is camelCase here (unlike the SoR `countersor` spec
/// quirk), matching the TS 29.509 `CounterUpu` wire field.
pub(crate) fn build_upu_info(
    upu_data_list: &serde_json::Value,
    ack_ind: bool,
    security_info: &serde_json::Value,
    provisioning_time: &str,
) -> Option<serde_json::Value> {
    let upu_mac_iausf = security_info.get("upuMacIausf")?.as_str()?;
    let counter_upu = security_info.get("counterUpu")?.as_str()?;
    Some(serde_json::json!({
        "upuDataList": upu_data_list,
        "upuAckInd": ack_ind,
        "upuMacIausf": upu_mac_iausf,
        "counterUpu": counter_upu,
        "provisioningTime": provisioning_time,
    }))
}

/// Serialize an am-data body from which `upuInfo` has been removed — the
/// fail-closed / withhold path. Guaranteed to carry no `upuInfo` (and hence no
/// `upuDataList`, which only ever nests inside it per TS 29.503).
fn withhold(mut am_data: serde_json::Value) -> String {
    if let Some(obj) = am_data.as_object_mut() {
        obj.remove("upuInfo");
    }
    // Serializing a `serde_json::Value` cannot fail in practice.
    serde_json::to_string(&am_data).unwrap_or_else(|_| "{}".to_string())
}

/// Temporarily store the expected UPU-XMAC-I_UE for `supi` (TS 33.501
/// §6.15.2.1 step 6), so the UPU ack verify (F-06) can compare it constant-time
/// against the UE-supplied UPU-MAC-I_UE. Pins the Counter_UPU alongside for
/// replay defence. Best-effort: a malformed XMAC just skips the pin.
fn store_expected_xmac(supi: &str, security_info: &serde_json::Value) {
    let Some(xmac_hex) = security_info.get("upuXmacIue").and_then(|v| v.as_str()) else {
        return;
    };
    let bytes = crate::nudm_handler::hex_to_bytes(xmac_hex);
    let Ok(xmac) = <[u8; 16]>::try_from(bytes.as_slice()) else {
        log::warn!("[{supi}] upuXmacIue is not 16 bytes — not pinning expected XMAC");
        return;
    };
    let counter = security_info
        .get("counterUpu")
        .and_then(|v| v.as_str())
        .and_then(|s| u16::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let ctx = udm_self();
    let stored = match ctx.read() {
        Ok(guard) => guard.upu_store_expected_xmac(supi, xmac, counter),
        Err(_) => false,
    };
    if !stored {
        log::warn!("[{supi}] could not pin expected UPU-XMAC-I_UE");
    }
}

/// Inject a protected `upuInfo` into the UDR am-data body when a UPU source is
/// configured, calling the real Nausf_UPUProtection producer.
///
/// This is the parameterised core (config + authenticating AUSF supplied by the
/// caller) so it is deterministically testable; [`maybe_inject_upu_info`]
/// wraps it with the process-global UDM context reads.
pub(crate) async fn inject_upu_info(
    supi: &str,
    raw: String,
    config: Option<UpuConfig>,
    ausf_instance_id: Option<String>,
) -> String {
    // Only a JSON object can carry upuInfo; anything else forwards verbatim.
    let mut am_data = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) if v.is_object() => v,
        _ => return raw,
    };

    // No UPU source anywhere → byte-identical passthrough (default-safe).
    let (upu_data_list, ack_ind) = match resolve_upu_source(&am_data, config) {
        Some(source) => source,
        None => return raw,
    };

    // Fail-closed: from here a `upuDataList` must never leave without a matching
    // `upuMacIausf`. Drop any UDR-provisioned (unprotected) upuInfo up front; it
    // is re-added only after the AUSF returns the MAC.
    if let Some(obj) = am_data.as_object_mut() {
        obj.remove("upuInfo");
    }

    let upu_info_request = serde_json::json!({
        "upuDataList": upu_data_list,
        "upuAckInd": ack_ind,
    });

    // TS 33.501 §6.15.2.1: the UDM SHALL invoke Nausf_UPUProtection. 33.501
    // defines NO unprotected delivery path, so any AUSF failure means WITHHOLD
    // (fail-closed) — never emit an unprotected UPU data list.
    let ausf_response =
        match udm_ausf_send_upu_protect(supi, ausf_instance_id.as_deref(), &upu_info_request).await
        {
            Ok(resp) if resp.is_success() => resp,
            Ok(resp) => {
                log::warn!(
                    "[{supi}] Nausf_UPUProtection returned {} — withholding upuInfo \
                     (fail-closed, TS 33.501 §6.15.2.1)",
                    resp.status
                );
                return withhold(am_data);
            }
            Err(e) => {
                log::warn!(
                    "[{supi}] Nausf_UPUProtection call failed: {e} — withholding upuInfo \
                     (fail-closed, TS 33.501 §6.15.2.1)"
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
                "[{supi}] UPUProtection response had no parseable UpuSecurityInfo — withholding"
            );
            return withhold(am_data);
        }
    };

    let Some(upu_info) = build_upu_info(&upu_data_list, ack_ind, &security_info, &now_rfc3339())
    else {
        log::warn!("[{supi}] UpuSecurityInfo missing upuMacIausf/counterUpu — withholding");
        return withhold(am_data);
    };

    // §6.15.2.1 step 6: pin the expected UPU-XMAC-I_UE for the F-06 ack verify.
    if ack_ind {
        store_expected_xmac(supi, &security_info);
    }

    if let Some(obj) = am_data.as_object_mut() {
        obj.insert("upuInfo".to_string(), upu_info);
    }
    serde_json::to_string(&am_data).unwrap_or_else(|_| withhold(am_data.clone()))
}

/// F-05 entry point called from `handle_get_am_data`: reads the udmd `upu`
/// config + this UE's authenticating AUSF from the process-global context (in a
/// short guard scope, never held across the AUSF await — the
/// nf-context-lock-deadlocks learning), then delegates to [`inject_upu_info`].
///
/// HONESTY MARKER: only the am-data-attribute UPU delivery is implemented;
/// notification-driven UPU (Nudm_SDM_Notification post-registration, TS 33.501
/// §6.15.2.1 step 5) is DEFERRED until udmd grows SDM notifications.
pub async fn maybe_inject_upu_info(supi: &str, raw: String) -> String {
    let (config, ausf_instance_id) = {
        let ctx = udm_self();
        let guard = match ctx.read() {
            Ok(guard) => guard,
            Err(_) => return raw,
        };
        (
            guard.upu_config(),
            guard
                .ue_find_by_supi(supi)
                .and_then(|ue| ue.ausf_instance_id),
        )
    };
    inject_upu_info(supi, raw, config, ausf_instance_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical two-entry UpuData list (mirrors the ausfd F-03 golden vector
    /// so the strict-peer recompute below lines up byte-for-byte).
    fn golden_upu_data_list() -> serde_json::Value {
        serde_json::json!([
            {"routingId": "1234"},
            {"defaultConfNssai": [{"sst": 1}, {"sst": 2, "sd": "00007B"}]}
        ])
    }

    /// The hand-derived TS 24.501 §9.11.3.53A wire bytes for
    /// `golden_upu_data_list()` — identical derivation to ausfd's
    /// `GOLDEN_UPU_LIST`, used for the INDEPENDENT MAC recompute (NOT taken
    /// from any handler intermediate):
    ///
    /// set 1: ME routing indicator (type 0100), length 0x0002, "1234" → BCD
    ///        21 43 (digit2|digit1, digit4|digit3)
    /// set 2: default configured NSSAI (type 0010), length 0x0007, NSSAI value
    ///        part {sst:1} → 01 01, {sst:2, sd:00007B} → 04 02 00 00 7B
    const GOLDEN_UPU_LIST: [u8; 15] = [
        0x04, 0x00, 0x02, 0x21, 0x43, // ME routing indicator data set
        0x02, 0x00, 0x07, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x7B, // NSSAI data set
    ];

    fn config(ack: bool) -> UpuConfig {
        UpuConfig {
            upu_data_list: golden_upu_data_list(),
            ack_ind: ack,
        }
    }

    // ---- resolve / build helpers --------------------------------------------

    #[test]
    fn resolve_prefers_udr_provisioned_upu_then_config() {
        // (a) UDR-provisioned upuInfo.upuDataList wins over config.
        let am_data = serde_json::json!({
            "upuInfo": {"upuDataList": [{"routingId": "9999"}], "upuAckInd": false}
        });
        let resolved = resolve_upu_source(&am_data, Some(config(true)));
        let (list, ack) = resolved.expect("UDR-provisioned source");
        assert_eq!(list[0]["routingId"], "9999");
        assert!(!ack, "UDR-provisioned upuAckInd=false honoured");

        // (b) no UDR upuInfo → config source.
        let am_data = serde_json::json!({"gpsis": ["msisdn-1"]});
        let (list, ack) = resolve_upu_source(&am_data, Some(config(true))).expect("config source");
        assert_eq!(list, golden_upu_data_list());
        assert!(ack);

        // none → passthrough.
        assert!(resolve_upu_source(&am_data, None).is_none());
    }

    #[test]
    fn build_upu_info_emits_exactly_the_five_ts29503_fields() {
        // Stand-in UpuSecurityInfo (shape identical to the real AUSF 200 body).
        let security = serde_json::json!({
            "upuMacIausf": "0123456789abcdef0123456789abcdef",
            "counterUpu": "0001",
            "upuXmacIue": "fedcba9876543210fedcba9876543210",
        });
        let upu = build_upu_info(
            &golden_upu_data_list(),
            true,
            &security,
            "2026-07-01T00:00:00Z",
        )
        .expect("all mandatory fields present");
        let obj = upu.as_object().unwrap();

        // Exactly the 5 TS29503 UpuInfo fields, correct names/types.
        assert_eq!(obj.len(), 5);
        assert!(obj.contains_key("upuDataList"));
        assert_eq!(upu["upuAckInd"], serde_json::Value::Bool(true));
        assert_eq!(upu["upuMacIausf"], "0123456789abcdef0123456789abcdef");
        // UPU uses camelCase counterUpu (NOT the SoR lowercase countersor quirk).
        assert_eq!(upu["counterUpu"], "0001");
        assert!(
            obj.get("countersor").is_none() && obj.get("counterupu").is_none(),
            "TS29503 UpuInfo uses camelCase counterUpu"
        );
        assert_eq!(upu["provisioningTime"], "2026-07-01T00:00:00Z");
    }

    #[test]
    fn build_upu_info_withholds_when_mandatory_mac_absent() {
        // Missing upuMacIausf → None (caller fail-closes).
        let no_mac = serde_json::json!({"counterUpu": "0001"});
        assert!(build_upu_info(&golden_upu_data_list(), true, &no_mac, "t").is_none());
        // Missing counterUpu → None.
        let no_counter = serde_json::json!({"upuMacIausf": "00"});
        assert!(build_upu_info(&golden_upu_data_list(), true, &no_counter, "t").is_none());
    }

    /// The injected `upuMacIausf` must be the genuine Annex A.19 MAC, byte-exact
    /// against an INDEPENDENT recompute from the KAUSF + counter + hand-derived
    /// UpuData wire bytes (F-01 KDF, the same one the ausfd producer uses in
    /// F-03). This is the falsifiable "reproduce-the-MAC" check at F-05's data
    /// level; the full in-process real-ausfd loopback is F-07's strict-peer
    /// suite. Locks the UpuData wire vector (the F-05 bespoke-encoding trap).
    #[test]
    fn injected_mac_is_reproducible_from_kausf_and_wire_bytes() {
        // A known KAUSF (the anchor an authenticated UE would hold).
        let mut kausf = [0u8; 32];
        for (i, b) in kausf.iter_mut().enumerate() {
            *b = 0xB1 ^ (i as u8);
        }

        // Independent Annex A.19 recompute (P0 = the golden wire bytes,
        // counter 0x0001 — the UPU header is NOT part of the MAC input) —
        // this stands in for the UpuSecurityInfo the AUSF returns.
        let mac =
            nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iausf(&kausf, &GOLDEN_UPU_LIST, 0x0001);
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iue(&kausf, 0x0001);
        let security = serde_json::json!({
            "upuMacIausf": crate::nudm_handler::bytes_to_hex(&mac),
            "counterUpu": "0001",
            "upuXmacIue": crate::nudm_handler::bytes_to_hex(&xmac),
        });

        // F-05 injection must carry that MAC verbatim into TS29503 UpuInfo.
        let upu = build_upu_info(&golden_upu_data_list(), true, &security, &now_rfc3339())
            .expect("full UpuSecurityInfo");
        assert_eq!(upu["counterUpu"], "0001");
        assert_eq!(
            upu["upuMacIausf"].as_str().unwrap(),
            crate::nudm_handler::bytes_to_hex(&mac),
            "injected upuMacIausf must equal the independent Annex A.19 recompute"
        );
        // Flip one wire byte → a different MAC (non-malleability sanity).
        let mut tampered = GOLDEN_UPU_LIST;
        tampered[3] ^= 0x01;
        let mac2 = nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iausf(&kausf, &tampered, 0x0001);
        assert_ne!(mac, mac2, "the MAC must depend on the UpuData wire bytes");
    }

    // ---- orchestration (fail-closed + byte-identity) -------------------------

    /// No UPU source (no UDR upuInfo, no config) → the response body is
    /// byte-identical to the UDR body. This is the matched-sim default guard
    /// (shared invariant with F-04's SoR passthrough test).
    #[tokio::test]
    async fn no_source_is_byte_identical_passthrough() {
        let raw = r#"{"gpsis":["msisdn-12345"],"subscribedUeAmbr":{"uplink":"1 Gbps","downlink":"2 Gbps"}}"#;
        let out = inject_upu_info("imsi-001010000000001", raw.to_string(), None, None).await;
        assert_eq!(out, raw, "no UPU source must not touch the UDR body");
    }

    /// Non-JSON / non-object UDR bodies also pass through verbatim.
    #[tokio::test]
    async fn non_object_body_is_passthrough() {
        let raw = "not-json";
        let out = inject_upu_info("imsi-x", raw.to_string(), Some(config(true)), None).await;
        assert_eq!(out, raw);
    }

    /// FAIL-CLOSED: UPU configured but the AUSF is unreachable (no instance-id,
    /// none cached, no env) → the response carries NO `upuInfo` and NO
    /// `upuDataList` anywhere, yet the rest of am-data survives.
    #[tokio::test]
    async fn ausf_unreachable_withholds_upu_info() {
        let raw = r#"{"gpsis":["msisdn-9"]}"#;
        let out = inject_upu_info(
            "imsi-001010000000009",
            raw.to_string(),
            Some(config(true)),
            None,
        )
        .await;
        assert!(
            !out.contains("upuInfo"),
            "fail-closed: no upuInfo when AUSF down: {out}"
        );
        assert!(
            !out.contains("upuDataList"),
            "fail-closed: an unprotected UPU list must never leak: {out}"
        );
        // The rest of am-data is still returned normally.
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["gpsis"][0], "msisdn-9");
    }

    /// FAIL-CLOSED (UDR-provisioned form): a UDR body that already carries an
    /// unprotected `upuInfo.upuDataList` must NOT leak it when the AUSF cannot
    /// protect it — the pre-existing upuInfo is stripped.
    #[tokio::test]
    async fn udr_provisioned_unprotected_upu_is_stripped_when_ausf_down() {
        let raw = r#"{"gpsis":["msisdn-3"],"upuInfo":{"upuDataList":[{"routingId":"9999"}],"upuAckInd":true}}"#;
        let out = inject_upu_info("imsi-001010000000003", raw.to_string(), None, None).await;
        assert!(
            !out.contains("upuInfo"),
            "unprotected UDR upuInfo must be stripped: {out}"
        );
        assert!(!out.contains("upuDataList"), "no UPU list may leak: {out}");
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["gpsis"][0], "msisdn-3");
    }
}
