//! PDU session establishment counters (#1368), modelled on TS 28.552 §5.3.1
//! (SM.PduSessionCreationReq / Succ / Fail.cause).
//!
//! Counted at one choke point, the Nsmf_PDUSession_CreateSMContext handler
//! (TS 29.502 §5.2.2.2), on what it answers:
//!
//! - every establishment request received is counted (an EPS→5GS handover create,
//!   TS 29.502 §5.2.2.2.3, is a session moving in, not an establishment, and is not);
//! - a 201 SmContextCreatedData, which carries the PDU SESSION ESTABLISHMENT ACCEPT, is
//!   a success;
//! - anything else is a failure, by the 5GSM cause of the PDU SESSION ESTABLISHMENT
//!   REJECT it carries (TS 24.501 §8.3.3, §9.11.4.2), or `none` when the answer carries
//!   no N1 reject (a malformed request, an SMF that is shutting down).
//!
//! `smf_session_success_total` and `smf_session_failure_total` are unlabelled, so the
//! shipped failure-rate rule divides series with equal label sets; the cause breakdown is
//! `smf_session_failure_cause_total{cause}`, the cause a number 0..=255 or `none`.

use nextgcore_metrics::nf::{write_header, write_metric};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static SUCCESSES: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
/// Failures by 5GSM cause; slot 256 is "no N1 reject".
static FAILURE_CAUSES: [AtomicU64; 257] = [const { AtomicU64::new(0) }; 257];

/// 5GSM message type of PDU SESSION ESTABLISHMENT REJECT (TS 24.501 §9.7).
const ESTABLISHMENT_REJECT: u8 = 0xC3;

/// Whether `request` is a PDU session establishment, not an EPS→5GS handover create.
pub fn is_establishment(request: &SbiRequest) -> bool {
    request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .is_none_or(|body| !crate::eps_to_5gs::is_handover_create(&body))
}

/// The 5GSM cause of the PDU SESSION ESTABLISHMENT REJECT `response` carries, if any:
/// EPD, PSI, PTI, message type, 5GSM cause (TS 24.501 §8.3.3.1).
fn reject_cause(response: &SbiResponse) -> Option<u8> {
    response.http.parts.iter().find_map(|part| {
        let n1 = part.data.as_ref();
        (n1.len() >= 5 && n1[0] == 0x2E && n1[3] == ESTABLISHMENT_REJECT).then(|| n1[4])
    })
}

/// Count one establishment request and how it was answered.
pub fn observe_establishment(response: &SbiResponse) {
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    if response.status == 201 {
        SUCCESSES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    FAILURES.fetch_add(1, Ordering::Relaxed);
    let slot = reject_cause(response).map_or(256, usize::from);
    FAILURE_CAUSES[slot].fetch_add(1, Ordering::Relaxed);
}

/// Render the session establishment families.
pub fn render(out: &mut String) {
    let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
    write_metric(
        out,
        "smf_session_requests_total",
        "counter",
        "PDU session establishment requests received (Nsmf_PDUSession_CreateSMContext, TS 28.552 SM.PduSessionCreationReq)",
        get(&REQUESTS),
    );
    write_metric(
        out,
        "smf_session_success_total",
        "counter",
        "PDU session establishments accepted (201 with PDU SESSION ESTABLISHMENT ACCEPT, SM.PduSessionCreationSucc)",
        get(&SUCCESSES),
    );
    write_metric(
        out,
        "smf_session_failure_total",
        "counter",
        "PDU session establishments refused (SM.PduSessionCreationFail)",
        get(&FAILURES),
    );
    write_header(
        out,
        "smf_session_failure_cause_total",
        "counter",
        "PDU session establishments refused, by the 5GSM cause of the PDU SESSION ESTABLISHMENT REJECT (TS 24.501 §9.11.4.2), or none",
    );
    for (slot, counter) in FAILURE_CAUSES.iter().enumerate() {
        let n = get(counter);
        if n == 0 {
            continue;
        }
        let cause = if slot == 256 {
            "none".to_string()
        } else {
            slot.to_string()
        };
        let _ = writeln!(
            out,
            "smf_session_failure_cause_total{{cause=\"{cause}\"}} {n}"
        );
    }
}

/// The value of `series` in this module's exposition (for tests).
#[cfg(test)]
pub fn value(series: &str) -> f64 {
    let mut out = String::new();
    render(&mut out);
    nextgcore_metrics::nf::sample_value(&out, series).unwrap_or(0.0)
}
