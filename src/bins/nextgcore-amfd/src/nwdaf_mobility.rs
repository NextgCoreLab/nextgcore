//! The AMF as a UE Mobility analytics consumer for paging (nextgsim#464,
//! `paging.strategy: nwdaf-mobility`).
//!
//! TS 23.501 §5.4.3.1 (`23501-k20.txt:8758-8763`): for a CM-IDLE UE the AMF
//! determines the paging strategy, and "If NWDAF is deployed, the AMF may also use
//! analytics (i.e. statistics or predictions) on the UE's mobility as provided by
//! NWDAF". TS 23.288 §6.7.2.1 (`23288-k10.txt:14857-14863`) names the AMF as a
//! consumer of UE mobility analytics.
//!
//! # Flow
//! 1. When the N1N2 path queues a page under this strategy
//!    (`namf_handler::initiate_paging_for_idle_ue`), it marks the context
//!    `nwdaf_wait_until = now + HINT_TIMEOUT` and calls [`spawn_hint`].
//! 2. [`spawn_hint`] runs off every NGAP and SBI-server task, with bounded
//!    concurrency. It resolves an NWDAF, sends `Nnwdaf_AnalyticsInfo_Request` for
//!    UE_MOBILITY over a future window (a prediction, TS 29.520 §4.3.2.2.2), and
//!    posts the answer with `AmfContext::paging_set_nwdaf_hint`. Discovery and
//!    request together are bounded by [`HINT_TIMEOUT`].
//! 3. The paging pump holds only that context's first PAGING until the answer or
//!    the deadline (`AmfContext::paging_take_due`); it never awaits the NWDAF.
//! 4. `NgapServer::send_paging` pages, on attempt 1, the connected gNBs whose
//!    Global gNB ID owns the predicted cell and that serve the registration area;
//!    every retransmission goes to the whole area.
//!
//! # Fail-open
//! Every failure pages the registration area from the first attempt, as the
//! default strategy does. That covers no SUPI, a full concurrency bound, no
//! NWDAF, a timeout, a non-200 answer (an NWDAF without UE mobility data answers
//! 204), a body naming no NR cell, and a predicted cell no gNB in the area owns.
//! The cost of an NWDAF that is down is at most [`HINT_TIMEOUT`] on the first
//! attempt, against T3513's 5 s.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::context::{PlmnId, PredictedCell};

/// How long the first PAGING waits for the NWDAF, discovery included.
pub const HINT_TIMEOUT: Duration = Duration::from_millis(300);

/// The analytics target period asked for: a prediction from now for this long,
/// which covers T3513's whole retransmission ladder (5 × 5 s by default).
pub const PREDICTION_WINDOW: Duration = Duration::from_secs(30);

/// At most this many NWDAF queries in flight. Past that a page fails open at once
/// rather than queueing behind a slow NWDAF.
pub const MAX_IN_FLIGHT: usize = 64;

static IN_FLIGHT: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();

fn in_flight() -> Arc<Semaphore> {
    IN_FLIGHT
        .get_or_init(|| Arc::new(Semaphore::new(MAX_IN_FLIGHT)))
        .clone()
}

/// The NWDAF a test points [`resolve_nwdaf_endpoint`] at, declared beside its one
/// reader. Callers that set it hold `test_support::CONTEXT_GUARD`, which every
/// paging test already holds. Production never sets it.
static NWDAF_ENDPOINT_OVERRIDE: std::sync::Mutex<Option<(String, u16)>> =
    std::sync::Mutex::new(None);

/// Test-only: answer [`resolve_nwdaf_endpoint`] with `ep`.
#[doc(hidden)]
pub fn set_nwdaf_endpoint_for_test(ep: Option<(String, u16)>) {
    *NWDAF_ENDPOINT_OVERRIDE
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = ep;
}

/// The gNB ID that owns the 36-bit NR Cell Identity `nci`, for a gNB ID of
/// `gnb_id_len` bits. TS 38.413 §9.3.1.7: the gNB ID is the leftmost
/// `gnb_id_len` bits (22..32) of the NCI. `None` for any other length.
pub fn gnb_id_of_nci(nci: u64, gnb_id_len: u8) -> Option<u32> {
    if !(22..=32).contains(&gnb_id_len) {
        return None;
    }
    u32::try_from((nci & 0xF_FFFF_FFFF) >> (36 - u32::from(gnb_id_len))).ok()
}

/// The request path of `Nnwdaf_AnalyticsInfo_Request` for `supi`'s UE mobility
/// prediction (TS 29.520 §4.3.2.2.2): `event-id=UE_MOBILITY`, `tgt-ue` naming the
/// SUPI, and `ana-req` a window starting `now`, which makes it a prediction.
pub fn request_path(supi: &str, now: std::time::SystemTime) -> String {
    use crate::namf_server::system_time_to_rfc3339 as rfc3339;
    use nextgcore_sbi::uri_encode::encode_query_value as enc;
    let tgt_ue = json!({ "supis": [supi] }).to_string();
    let ana_req = json!({
        "startTs": rfc3339(now),
        "endTs": rfc3339(now + PREDICTION_WINDOW),
    })
    .to_string();
    format!(
        "/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY&tgt-ue={}&ana-req={}",
        enc(&tgt_ue),
        enc(&ana_req)
    )
}

/// The predicted cell in a TS 29.520 `AnalyticsData` body: across `ueMobs[]`, the
/// `locInfos[]` entry with the highest `confidence` (an absent one counts as 0)
/// whose `loc.nrLocation.ncgi` is a TS 29.571 NCGI. `None` when there is none.
pub fn parse_ue_mobility(body: &Value) -> Option<PredictedCell> {
    let mut best: Option<PredictedCell> = None;
    for mob in body.get("ueMobs")?.as_array()? {
        let Some(infos) = mob.get("locInfos").and_then(Value::as_array) else {
            continue;
        };
        for info in infos {
            let Some(ncgi) = info
                .get("loc")
                .and_then(|l| l.get("nrLocation"))
                .and_then(|n| n.get("ncgi"))
                .and_then(crate::namf_server::parse_ncgi)
            else {
                continue;
            };
            let confidence = info
                .get("confidence")
                .and_then(Value::as_u64)
                .map(|c| c.min(100) as u8);
            let better = best
                .as_ref()
                .is_none_or(|b| confidence.unwrap_or(0) > b.confidence.unwrap_or(0));
            if better {
                best = Some(PredictedCell {
                    plmn_id: ncgi.plmn_id,
                    nci: ncgi.cell_id,
                    confidence,
                });
            }
        }
    }
    best
}

/// An NWDAF serving `nnwdaf-analyticsinfo`: the discovery cache, then an
/// on-demand NRF discovery, then `NWDAF_SBI_ADDR`/`NWDAF_SBI_PORT` (logged), the
/// order `sbi_path::resolve_lmf_endpoint_for` uses.
pub async fn resolve_nwdaf_endpoint() -> Option<(String, u16)> {
    if let Some(ep) = NWDAF_ENDPOINT_OVERRIDE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return Some(ep);
    }
    let service = nextgcore_sbi::types::SbiServiceType::NnwdafAnalyticsinfo;
    let sbi_ctx = nextgcore_sbi::context::global_context();
    let pick = |instances: Vec<nextgcore_sbi::context::NfInstance>| {
        instances.first().and_then(|i| i.endpoint_for(service))
    };
    if let Some(ep) = pick(sbi_ctx.find_nf_instances_by_service(service).await) {
        return Some(ep);
    }
    if crate::sbi_path::amf_nrf_discover("NWDAF", service.to_name())
        .await
        .is_ok()
    {
        if let Some(ep) = pick(sbi_ctx.find_nf_instances_by_service(service).await) {
            return Some(ep);
        }
    }
    let host = std::env::var("NWDAF_SBI_ADDR").ok()?;
    let port = std::env::var("NWDAF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    log::info!(
        "No NWDAF discoverable via the NRF; using the configured NWDAF_SBI_ADDR={host}:{port}"
    );
    Some((host, port))
}

/// Ask the NWDAF for `supi`'s UE mobility prediction. `Ok(None)` is an answer
/// with no prediction (204, or a body naming no NR cell); `Err` is a failure.
pub async fn query_prediction(supi: &str) -> Result<Option<PredictedCell>, String> {
    let (host, port) = resolve_nwdaf_endpoint()
        .await
        .ok_or_else(|| "no NWDAF (NRF discovery found none, NWDAF_SBI_ADDR unset)".to_string())?;
    let client = crate::attach_oauth2(
        nextgcore_sbi::client::SbiClient::for_peer(&host, port),
        nextgcore_sbi::types::NfType::Nwdaf,
    );
    let response = client
        .get(&request_path(supi, std::time::SystemTime::now()))
        .await
        .map_err(|e| format!("request to {host}:{port} failed: {e}"))?;
    match response.status {
        200 => {}
        204 => return Ok(None),
        status => return Err(format!("NWDAF answered {status}")),
    }
    let body = response.http.content.unwrap_or_default();
    let body: Value =
        serde_json::from_str(&body).map_err(|e| format!("malformed AnalyticsData: {e}"))?;
    Ok(parse_ue_mobility(&body))
}

/// Start the UE mobility query for the page queued for `amf_ue_ngap_id`, and
/// post its outcome to that page. Returns `false`, having started nothing, when
/// there is no tokio runtime or the concurrency bound is full; the caller then
/// pages without waiting.
pub fn spawn_hint(amf_ue_ngap_id: u64, supi: String) -> bool {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return false;
    };
    let Ok(permit) = in_flight().try_acquire_owned() else {
        log::warn!(
            "NWDAF UE mobility: {MAX_IN_FLIGHT} queries already in flight; paging UE \
             {amf_ue_ngap_id} in the registration area"
        );
        return false;
    };
    handle.spawn(async move {
        let _permit = permit;
        let outcome = match tokio::time::timeout(HINT_TIMEOUT, query_prediction(&supi)).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                log::info!(
                    "NWDAF UE mobility: ue={supi} no prediction ({e}); paging the registration area"
                );
                None
            }
            Err(_) => {
                log::info!(
                    "NWDAF UE mobility: ue={supi} no answer within {} ms; paging the \
                     registration area",
                    HINT_TIMEOUT.as_millis()
                );
                None
            }
        };
        match &outcome {
            Some(p) => log::info!(
                "NWDAF UE mobility: ue={supi} predicted=({}, 0x{:09x}) confidence={}",
                plmn_label(&p.plmn_id),
                p.nci,
                p.confidence
                    .map_or_else(|| "-".to_string(), |c| format!("{c}%"))
            ),
            None => log::debug!("NWDAF UE mobility: ue={supi} no predicted cell"),
        }
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        if !guard.paging_set_nwdaf_hint(amf_ue_ngap_id, outcome) {
            log::info!(
                "NWDAF UE mobility: ue={supi} answer arrived after the first PAGING; not used"
            );
        }
    });
    true
}

/// `MCC-MNC` for a log line.
pub fn plmn_label(plmn: &PlmnId) -> String {
    let mnc = if plmn.mnc3 == 0xf {
        format!("{}{}", plmn.mnc1, plmn.mnc2)
    } else {
        format!("{}{}{}", plmn.mnc1, plmn.mnc2, plmn.mnc3)
    };
    format!("{}{}{}-{mnc}", plmn.mcc1, plmn.mcc2, plmn.mcc3)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TS 38.413 §9.3.1.7: the gNB ID is the NCI's leftmost bits, at 22 and at 32
    /// bits; a length outside 22..32 maps nothing.
    #[test]
    fn the_gnb_id_is_the_leftmost_bits_of_the_nci() {
        // 22-bit gNB 0x2 with a 14-bit cell 0x0005.
        let nci22 = (0x2u64 << 14) | 0x5;
        assert_eq!(gnb_id_of_nci(nci22, 22), Some(0x2));
        // 32-bit gNB 0x8000_0002 with a 4-bit cell 0x3.
        let nci32 = (0x8000_0002u64 << 4) | 0x3;
        assert_eq!(gnb_id_of_nci(nci32, 32), Some(0x8000_0002));
        // The same NCI read at the wrong length names a different gNB.
        assert_eq!(gnb_id_of_nci(nci22, 32), Some((nci22 >> 4) as u32));
        assert_ne!(gnb_id_of_nci(nci22, 32), Some(0x2));
        // Bits above 36 are not part of the NCI.
        assert_eq!(gnb_id_of_nci((1u64 << 40) | nci22, 22), Some(0x2));
        assert_eq!(gnb_id_of_nci(nci22, 21), None);
        assert_eq!(gnb_id_of_nci(nci22, 33), None);
    }

    /// The body nwdafd's `amf_mobility::ue_mobility_infos` builds for a
    /// prediction: one `UeMobility` with one `locInfos` entry carrying back the
    /// `UserLocation` the AMF reported, and `confidence` in percent.
    fn nwdafd_prediction(nr_cell_id: &str, confidence: u64) -> Value {
        json!({
            "ueMobs": [{
                "ts": "2026-11-12T10:00:00Z",
                "duration": 30,
                "locInfos": [{
                    "loc": { "nrLocation": {
                        "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000001" },
                        "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "nrCellId": nr_cell_id }
                    }},
                    "confidence": confidence
                }]
            }],
            "start": "2026-11-12T10:00:00Z",
            "expiry": "2026-11-12T10:00:30Z",
            "timeStampGen": "2026-11-12T10:00:00Z"
        })
    }

    #[test]
    fn the_prediction_is_read_from_the_nwdafd_body() {
        let p = parse_ue_mobility(&nwdafd_prediction("000008005", 67)).expect("a cell");
        assert_eq!(p.plmn_id, PlmnId::new("001", "01"));
        assert_eq!(p.nci, 0x0_0000_8005);
        assert_eq!(p.confidence, Some(67));
    }

    #[test]
    fn the_most_confident_cell_wins_and_unusable_entries_are_skipped() {
        let body = json!({ "ueMobs": [
            { "locInfos": [
                { "loc": { "nrLocation": { "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" },
                                                     "nrCellId": "000004001" } } },
                  "confidence": 20 },
                { "loc": { "eutraLocation": {} }, "confidence": 99 },
                { "loc": { "nrLocation": { "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" },
                                                     "nrCellId": "bad" } } },
                  "confidence": 99 }
            ]},
            { "locInfos": [
                { "loc": { "nrLocation": { "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" },
                                                     "nrCellId": "000008005" } } },
                  "confidence": 70 }
            ]}
        ]});
        assert_eq!(parse_ue_mobility(&body).map(|p| p.nci), Some(0x8005));
    }

    #[test]
    fn a_body_naming_no_nr_cell_is_no_prediction() {
        assert_eq!(parse_ue_mobility(&json!({})), None);
        assert_eq!(parse_ue_mobility(&json!({ "ueMobs": [] })), None);
        assert_eq!(
            parse_ue_mobility(&json!({ "ueMobs": [{ "locInfos": [{ "loc": {} }] }] })),
            None
        );
    }

    /// TS 29.520 §4.3.2.2.2: UE_MOBILITY names the target UE by `tgt-ue.supis`;
    /// a window starting now is a prediction (nwdafd: statistics iff `endTs <= now`).
    #[test]
    fn the_request_asks_for_a_prediction_for_the_supi() {
        // 2026-11-12T10:00:00Z
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1_794_477_600);
        let path = request_path("imsi-001010000000001", now);
        let (route, query) = path.split_once('?').expect("query");
        assert_eq!(route, "/nnwdaf-analyticsinfo/v1/analytics");
        let params: std::collections::HashMap<String, String> = query
            .split('&')
            .map(|kv| {
                let (k, v) = kv.split_once('=').expect("k=v");
                (k.to_string(), percent_decode(v))
            })
            .collect();
        assert_eq!(params["event-id"], "UE_MOBILITY");
        let tgt: Value = serde_json::from_str(&params["tgt-ue"]).expect("json");
        assert_eq!(tgt, json!({ "supis": ["imsi-001010000000001"] }));
        let ana: Value = serde_json::from_str(&params["ana-req"]).expect("json");
        assert_eq!(ana["startTs"], "2026-11-12T10:00:00Z");
        assert_eq!(ana["endTs"], "2026-11-12T10:00:30Z");
    }

    fn percent_decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).expect("utf-8")
    }
}
