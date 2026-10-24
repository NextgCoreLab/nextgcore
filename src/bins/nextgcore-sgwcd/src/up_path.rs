//! User plane path failure and recovery, as the SGW-U reports them (#994).
//!
//! TS 23.007 §20.3.4: with CUPS, the SGW-U detects a GTP-U path failure (Echo,
//! §20.3.1) and sends the SGW-C a PFCP Node Report Request with a User Plane Path
//! Failure Report naming the remote GTP-U peers. When a failed path recovers, it sends
//! a User Plane Path Recovery Report (TS 29.244 §7.4.5.1). The SGW-C answers both
//! (`pfcp_path::SxaNode::handle_node_report_request`); this module decides what is
//! done.
//!
//! - **Failure.** A peer that is an eNodeB (the downlink S1-U endpoint of a bearer)
//!   gets the S1-U bearers toward it released at once, with Release Access Bearers
//!   semantics (`gtp_path::release_s1u_bearers`). The FARs go to BUFF + NOCP and the
//!   EPS bearer contexts are kept (TS 23.007 §20.3.1, "maintain the bearer contexts").
//!   The next downlink packet is then buffered and reported, and a Downlink Data
//!   Notification pages the UE, rather than being tunnelled into a dead path. The
//!   peer is recorded as failed.
//! - **Hold.** `SGWC_UP_PATH_FAILURE_HOLD_SECS` is the operator-configurable maximum
//!   path failure duration (default 120 s, at most 3600 s; TS 23.007 §20.3.1 NOTE 2
//!   says "few minutes at most"). A Modify Bearer that points a bearer at the peer
//!   inside the hold is answered and the UE's S1-U bearers are released at once
//!   ([`toward_failed`], [`release_toward_failed`]). If the path is still down when the hold
//!   expires, any bearer pointed at it is released, and the record is dropped, so a
//!   later report starts afresh. A repeated failure report for a peer that is
//!   already failed starts no second hold.
//! - **Finding the UEs.** The context indexes downlink tunnels by their remote peer
//!   (`SgwcContext::ue_ids_with_downlink_toward`), so a failure costs the UEs toward
//!   that eNodeB, not a scan of every UE.
//! - **Recovery.** The peer's record is cleared, which voids its pending hold.
//!   Nothing is re-activated: the next Service Request does that, through the Modify
//!   Bearer Request.
//!
//! The optional S1-U path failure notification feature (TS 23.007 §20.3.5, cause
//! "S1-U Path Failure" in the DDN and in Modify Bearer Responses) needs the MME to
//! support it (Node Features S1UN, TS 29.274 §8.83). mmed does not, so that feature
//! is not used.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::context::sgwc_self;

/// The failed peers, each with the generation of its failure record.
static FAILED: Mutex<Option<HashMap<IpAddr, u64>>> = Mutex::new(None);
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Path failures reported by the SGW-U, per peer.
pub static FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Path recoveries reported by the SGW-U, per peer that was failed.
pub static RECOVERIES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// UEs whose S1-U bearers were released because of a failed path.
pub static UES_RELEASED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Holds that expired with the path still down.
pub static HOLDS_EXPIRED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Default maximum path failure duration (TS 23.007 §20.3.1).
const DEFAULT_HOLD_SECS: u64 = 120;
/// Upper bound on the configured hold.
const MAX_HOLD_SECS: u64 = 3600;

fn with_failed<R>(f: impl FnOnce(&mut HashMap<IpAddr, u64>) -> R) -> R {
    let mut guard = FAILED.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

/// The maximum path failure duration, from `SGWC_UP_PATH_FAILURE_HOLD_SECS`.
pub fn hold() -> Duration {
    parse_hold(
        std::env::var("SGWC_UP_PATH_FAILURE_HOLD_SECS")
            .ok()
            .as_deref(),
    )
}

fn parse_hold(value: Option<&str>) -> Duration {
    let secs = match value {
        None => DEFAULT_HOLD_SECS,
        Some(v) => match v.trim().parse::<u64>() {
            Ok(n) if n > MAX_HOLD_SECS => {
                log::warn!(
                    "SGWC_UP_PATH_FAILURE_HOLD_SECS={n} is above {MAX_HOLD_SECS}; using \
                     {MAX_HOLD_SECS}"
                );
                MAX_HOLD_SECS
            }
            Ok(n) => n,
            Err(_) => {
                log::warn!(
                    "SGWC_UP_PATH_FAILURE_HOLD_SECS={v:?} is not a number of seconds; using \
                     {DEFAULT_HOLD_SECS}"
                );
                DEFAULT_HOLD_SECS
            }
        },
    };
    Duration::from_secs(secs)
}

/// How many peers are failed now.
pub fn failed_count() -> usize {
    with_failed(|m| m.len())
}

/// Whether `peer` is recorded as failed.
pub fn is_failed(peer: IpAddr) -> bool {
    with_failed(|m| m.contains_key(&peer))
}

/// Release, with Release Access Bearers semantics, the S1-U bearers of every UE whose
/// downlink endpoint is `peer`, found through the context's downlink-peer index.
/// Returns the UEs released.
pub fn release_s1u_toward(peer: IpAddr) -> usize {
    let ctx = sgwc_self();
    let mut released = 0;
    for ue_id in ctx.ue_ids_with_downlink_toward(peer) {
        let Some(ue) = ctx.ue_find_by_id(ue_id) else {
            continue;
        };
        if crate::gtp_path::release_s1u_bearers(&ue, 0) > 0 {
            released += 1;
        }
    }
    UES_RELEASED_TOTAL.fetch_add(released as u64, Ordering::Relaxed);
    released
}

/// Whether a Modify Bearer Request points one of `bearer_ids` at a peer recorded
/// as failed (#1014 review): the UE and that peer, decided before the response
/// goes so the decision does not depend on what happens while it is sent.
pub fn toward_failed(bearer_ids: &[u64]) -> Option<(u64, IpAddr)> {
    let ctx = sgwc_self();
    bearer_ids.iter().find_map(|b| {
        let dl = ctx.dl_tunnel_in_bearer(*b)?;
        if dl.remote_teid == 0 {
            return None;
        }
        let failed = dl
            .remote_ip
            .ipv4
            .map(IpAddr::from)
            .into_iter()
            .chain(dl.remote_ip.ipv6.map(IpAddr::from))
            .find(|p| is_failed(*p))?;
        Some((ctx.bearer_find_by_id(*b)?.sgwc_ue_id, failed))
    })
}

/// Release the S1-U bearers of UE `ue_id`, which a Modify Bearer pointed at the
/// failed `peer` ([`toward_failed`]): at once, as for the failure itself, rather
/// than black-holing downlink until the hold expires. Returns whether they were.
pub fn release_toward_failed(ue_id: u64, peer: IpAddr) -> bool {
    let ctx = sgwc_self();
    let Some(ue) = ctx.ue_find_by_id(ue_id) else {
        return false;
    };
    let released = crate::gtp_path::release_s1u_bearers(&ue, 0) > 0;
    if released {
        UES_RELEASED_TOTAL.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "Modify Bearer pointed UE {ue_id} at {peer}, whose user plane path is failed: its \
             S1-U bearers are released at once (TS 23.007 §20.3.4)"
        );
    }
    released
}

/// A failure report for `peers`. Each newly failed peer gets its S1-U bearers
/// released and a failure record. Returns the newly failed peers with the generation
/// their hold must still match at expiry. A peer that is already failed is not
/// returned: a repeated report starts no second hold.
pub fn on_failure(peers: &[IpAddr]) -> Vec<(IpAddr, u64)> {
    let mut fresh = Vec::new();
    for peer in peers {
        let generation = with_failed(|m| {
            if m.contains_key(peer) {
                None
            } else {
                let g = GENERATION.fetch_add(1, Ordering::Relaxed);
                m.insert(*peer, g);
                Some(g)
            }
        });
        let Some(generation) = generation else {
            log::debug!("User plane path to {peer} reported failed again");
            continue;
        };
        FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
        let released = release_s1u_toward(*peer);
        log::warn!(
            "User plane path to {peer} failed (SGW-U Node Report, TS 23.007 §20.3.4): S1-U \
             bearers of {released} UE(s) released, downlink buffered for paging; held {}s",
            hold().as_secs()
        );
        fresh.push((*peer, generation));
    }
    fresh
}

/// A recovery report for `peers`: their failure records are cleared, which voids
/// their holds. Returns the peers that were failed.
pub fn on_recovery(peers: &[IpAddr]) -> usize {
    let mut cleared = 0;
    for peer in peers {
        if with_failed(|m| m.remove(peer)).is_some() {
            cleared += 1;
            RECOVERIES_TOTAL.fetch_add(1, Ordering::Relaxed);
            log::info!("User plane path to {peer} recovered (SGW-U Node Report)");
        }
    }
    cleared
}

/// The hold for `peer`'s failure `generation` expired. If the path is still down
/// (the same record), bearers pointed at it since the failure are released, and the
/// record is dropped. Returns whether the record was still there.
pub fn on_hold_expired(peer: IpAddr, generation: u64) -> bool {
    let current = with_failed(|m| {
        if m.get(&peer) == Some(&generation) {
            m.remove(&peer);
            true
        } else {
            false
        }
    });
    if current {
        HOLDS_EXPIRED_TOTAL.fetch_add(1, Ordering::Relaxed);
        let released = release_s1u_toward(peer);
        log::warn!(
            "User plane path to {peer} still down after the maximum path failure duration \
             (TS 23.007 §20.3.1): {released} UE(s) pointed at it again released; record dropped"
        );
    }
    current
}

/// Prometheus lines for these counters.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "# TYPE sgwc_up_path_failures_total counter\nsgwc_up_path_failures_total {}",
        FAILURES_TOTAL.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# TYPE sgwc_up_path_recoveries_total counter\nsgwc_up_path_recoveries_total {}",
        RECOVERIES_TOTAL.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# TYPE sgwc_up_paths_failed gauge\nsgwc_up_paths_failed {}",
        failed_count()
    );
    let _ = writeln!(
        out,
        "# TYPE sgwc_up_path_ues_released_total counter\nsgwc_up_path_ues_released_total {}",
        UES_RELEASED_TOTAL.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# TYPE sgwc_up_path_holds_expired_total counter\nsgwc_up_path_holds_expired_total {}",
        HOLDS_EXPIRED_TOTAL.load(Ordering::Relaxed)
    );
}

/// Forget every failure record (tests).
#[cfg(test)]
pub(crate) fn clear_for_test() {
    with_failed(|m| m.clear());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hold_is_parsed_and_bounded() {
        assert_eq!(parse_hold(None), Duration::from_secs(120));
        assert_eq!(parse_hold(Some("0")), Duration::ZERO);
        assert_eq!(parse_hold(Some(" 30 ")), Duration::from_secs(30));
        assert_eq!(parse_hold(Some("99999")), Duration::from_secs(3600));
        assert_eq!(parse_hold(Some("soon")), Duration::from_secs(120));
    }
}
