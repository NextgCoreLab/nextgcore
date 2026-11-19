//! #1876: the AMF's Network Slice Admission Control counts, out as well as in.
//!
//! TS 23.502 §4.2.11.2: the AMF counts a UE in at the NSACF
//! (Nnsacf_NSAC_NumOfUEsUpdate, INCREASE) for each S-NSSAI subject to NSAC when it
//! accepts the UE's registration on it, and counts it out (DECREASE) when the UE
//! deregisters or the S-NSSAI is removed from its Allowed NSSAI. amfd only ever sent
//! the INCREASE, so every deregistration left the UE counted and the slice's maximum
//! number of UEs filled up for good; and a registration denied on a later S-NSSAI
//! kept the earlier S-NSSAIs' grants for a UE that was rejected.
//!
//! What this module holds:
//!
//! - **The admissions** the NSACF granted, keyed by (SUPI, access type, S-NSSAI),
//!   each with the NSACF that granted it and the nfId it was granted to, so the
//!   DECREASE goes to the same place under the same identity. Only an admission
//!   the NSACF actually answered is recorded: an INCREASE that degraded open
//!   because no NSACF answered counted nothing, so there is nothing to undo (one
//!   that got no answer at all is reconciled with a precautionary DECREASE, as
//!   smfd does).
//! - **The reconciler** for a DECREASE that fails: parked and retried every
//!   [`RECONCILE_PERIOD`] until the NSACF accepts it, the shape of smfd's #1875 and
//!   #1817's reconcilers. Bounded at [`MAX_PENDING`] (the oldest is evicted, counted
//!   `abandoned`); a pass sends for at most [`MAX_PASS`]. A parked DECREASE whose
//!   (SUPI, access type, S-NSSAI) has been admitted again since is `superseded` and
//!   not sent: the NSACF counts a UE once, so it would count the live registration
//!   out.
//!
//! Ceiling: memory-only. amfd has no durable store for its UE contexts either, so a
//! restart forgets both the registrations and the DECREASEs they owe; the NSACF's
//! own supervision of its UE lists is what covers that case.

use crate::context::SNssai;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

/// Records parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often the parked DECREASEs are retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// The longest one pass sends for.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_secs(2);

/// One UE's admission on one S-NSSAI, as the NSACF granted it.
#[derive(Debug, Clone, PartialEq)]
pub struct Admission {
    pub supi: String,
    /// `3GPP_ACCESS` or `NON_3GPP_ACCESS` (TS 29.571 AccessType).
    pub access_type: String,
    pub snssai: SNssai,
    /// The nfId the INCREASE carried.
    pub nf_id: String,
    /// The NSACF that granted it.
    pub nsacf_host: String,
    pub nsacf_port: u16,
}

type Key = (String, String, u8, Option<u32>);

fn key_of(supi: &str, access_type: &str, snssai: &SNssai) -> Key {
    (
        supi.to_string(),
        access_type.to_string(),
        snssai.sst,
        snssai.sd,
    )
}

/// The admissions held now.
///
/// Tests that read or write it, or [`pending`], hold [`NSAC_TEST_LOCK`], declared
/// beside them.
fn admissions() -> &'static Mutex<HashMap<Key, Admission>> {
    static ADMISSIONS: std::sync::LazyLock<Mutex<HashMap<Key, Admission>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
    &ADMISSIONS
}

/// The parked DECREASEs, oldest first.
fn pending() -> &'static Mutex<VecDeque<Admission>> {
    static PENDING: Mutex<VecDeque<Admission>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// Serialises the tests that touch [`admissions`] and [`pending`]: one test's
/// deregistration would otherwise count out, or reconcile, another's admission.
#[cfg(test)]
pub static NSAC_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `amf_nsac_ue_decreases_total{result}`: DECREASEs sent at once, by outcome.
pub static DECREASES: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "amf_nsac_ue_decreases_total",
        "Nnsacf_NSAC_NumOfUEsUpdate DECREASEs sent on deregistration, S-NSSAI removal or a \
         denied registration's rollback, by outcome (accepted, refused, failed = parked)",
        &["result"],
    );

/// `amf_nsac_ue_decreases_reconciled_total{result}`: parked DECREASEs the
/// reconciler ended: `delivered`, `superseded` (admitted again since), `refused`
/// (a 4xx a retry cannot change) or `abandoned` (evicted at the bound).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "amf_nsac_ue_decreases_reconciled_total",
        "Parked Nnsacf_NSAC_NumOfUEsUpdate DECREASEs, by how the reconciler ended them",
        &["result"],
    );

fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record an admission the NSACF granted.
pub fn record(admission: Admission) {
    let key = key_of(&admission.supi, &admission.access_type, &admission.snssai);
    lock(admissions()).insert(key, admission);
}

/// Whether (SUPI, access type, S-NSSAI) is admitted now.
pub fn is_admitted(supi: &str, access_type: &str, snssai: &SNssai) -> bool {
    lock(admissions()).contains_key(&key_of(supi, access_type, snssai))
}

/// Take the UE's admissions on `access_type` that are NOT in `keep`, so they can be
/// counted out: every one for a deregistration or a rejection (`keep` empty), the
/// removed S-NSSAIs for a registration whose Allowed NSSAI shrank.
pub fn take(supi: &str, access_type: &str, keep: &[SNssai]) -> Vec<Admission> {
    let mut map = lock(admissions());
    let gone: Vec<Key> = map
        .iter()
        .filter(|(_, a)| {
            a.supi == supi && a.access_type == access_type && !keep.contains(&a.snssai)
        })
        .map(|(k, _)| k.clone())
        .collect();
    gone.into_iter().filter_map(|k| map.remove(&k)).collect()
}

/// What [`admit_registration`] decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    /// The last answer's admission (`AmfUe::slice_admission_granted`).
    pub granted: bool,
    /// The S-NSSAI the NSACF denied, if one was: the registration is rejected.
    pub denied: Option<SNssai>,
}

/// Count a registering UE in at the NSACF on each S-NSSAI of `allowed`, in order,
/// stopping at the first denial (TS 23.502 §4.2.11.2, TS 29.536 §5.2.2.2).
///
/// #1876:
/// - each count the NSACF took is [`record`]ed, so a deregistration undoes it;
/// - an INCREASE that got no answer at all is reconciled with a precautionary
///   DECREASE, not parked (a DECREASE of a UE the NSACF does not hold is a no-op);
/// - on a denial the UE is rejected, so EVERY admission it holds on this access is
///   counted out again, the ones this request took included (they used to stay);
/// - otherwise an S-NSSAI it held and no longer has in `allowed` is counted out
///   ("removed from the Allowed NSSAI").
pub async fn admit_registration(
    supi: &str,
    access_type: &str,
    allowed: &[SNssai],
    nsacf_host: &str,
    nsacf_port: u16,
    nf_id: &str,
) -> Admitted {
    let mut granted = false;
    let mut denied = None;
    let mut unanswered = Vec::new();
    for snssai in allowed {
        let admission = Admission {
            supi: supi.to_string(),
            access_type: access_type.to_string(),
            snssai: snssai.clone(),
            nf_id: nf_id.to_string(),
            nsacf_host: nsacf_host.to_string(),
            nsacf_port,
        };
        match crate::sbi_path::call_nsacf_ue_admission(
            nsacf_host,
            nsacf_port,
            nf_id,
            supi,
            snssai.sst,
            snssai.sd,
            access_type,
            true,
        )
        .await
        {
            Ok(res) => {
                granted = res.admitted;
                if res.counted {
                    record(admission);
                } else if res.unanswered {
                    unanswered.push(admission);
                }
                if !res.admitted {
                    denied = Some(snssai.clone());
                    break;
                }
            }
            Err(e) => {
                // TS 23.501 §5.15.11: admission control could not be performed, so
                // the slice is treated as not admitted rather than over quota.
                log::error!(
                    "[{supi}] NSACF UE admission query failed for SST={}: {e}",
                    snssai.sst
                );
                granted = false;
                denied = Some(snssai.clone());
                break;
            }
        }
    }
    for a in unanswered {
        tokio::spawn(async move {
            let _ = send(&a).await;
        });
    }
    let gone = if denied.is_some() {
        take(supi, access_type, &[])
    } else {
        take(supi, access_type, allowed)
    };
    spawn_decreases(gone);
    Admitted { granted, denied }
}

/// How a DECREASE ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 2xx, or 404 (the NSACF does not hold the UE).
    Accepted,
    /// A 4xx a retry cannot change.
    Refused,
    /// No answer, a 5xx, or a refused token: worth retrying.
    Failed,
}

/// Count `admissions` out, off the caller's path; a failure is parked.
pub fn spawn_decreases(admissions: Vec<Admission>) {
    if admissions.is_empty() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        for a in admissions {
            park(a);
        }
        return;
    };
    handle.spawn(async move {
        for a in admissions {
            decrease_now(a).await;
        }
    });
}

/// One DECREASE now, parked on failure. Not sent when the slice has been admitted
/// for the UE again meanwhile (it would count the live registration out).
pub async fn decrease_now(a: Admission) -> Outcome {
    if is_admitted(&a.supi, &a.access_type, &a.snssai) {
        return Outcome::Accepted;
    }
    let outcome = send(&a).await;
    let label = match outcome {
        Outcome::Accepted => "accepted",
        Outcome::Refused => "refused",
        Outcome::Failed => "failed",
    };
    DECREASES.inc(&[label]);
    if outcome == Outcome::Failed {
        park(a);
    }
    outcome
}

async fn send(a: &Admission) -> Outcome {
    crate::sbi_path::call_nsacf_ue_decrease(
        &a.nsacf_host,
        a.nsacf_port,
        &a.nf_id,
        &a.supi,
        a.snssai.sst,
        a.snssai.sd,
        &a.access_type,
    )
    .await
}

fn evict(set: &mut VecDeque<Admission>) {
    while set.len() > MAX_PENDING {
        if let Some(old) = set.pop_front() {
            log::error!(
                "[{}] NSACF DECREASE for SST={} SD={:?} abandoned: {MAX_PENDING} are already \
                 pending; the UE stays counted at the NSACF",
                old.supi,
                old.snssai.sst,
                old.snssai.sd
            );
            RECONCILED.inc(&["abandoned"]);
        }
    }
}

/// Park a DECREASE that failed. One already parked is not parked twice.
pub fn park(a: Admission) {
    let mut set = lock(pending());
    if set.contains(&a) {
        return;
    }
    log::warn!(
        "[{}] NSACF DECREASE for SST={} SD={:?} failed; parked, retried every \
         {RECONCILE_PERIOD:?}",
        a.supi,
        a.snssai.sst,
        a.snssai.sd
    );
    set.push_back(a);
    evict(&mut set);
}

/// How many DECREASEs are parked.
pub fn pending_count() -> usize {
    lock(pending()).len()
}

/// The parked DECREASEs, for tests.
#[cfg(test)]
pub fn parked() -> Vec<Admission> {
    lock(pending()).iter().cloned().collect()
}

/// One reconcile pass over the parked DECREASEs, oldest first, for at most
/// [`MAX_PASS`]. Returns how many ended.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Admission> = lock(pending()).drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut still = Vec::new();
    for a in batch {
        if tokio::time::Instant::now() >= deadline {
            still.push(a);
            continue;
        }
        let result = if is_admitted(&a.supi, &a.access_type, &a.snssai) {
            "superseded"
        } else {
            match send(&a).await {
                Outcome::Accepted => "delivered",
                Outcome::Refused => "refused",
                Outcome::Failed => {
                    still.push(a);
                    continue;
                }
            }
        };
        log::info!(
            "[{}] parked NSACF DECREASE for SST={} SD={:?}: {result}",
            a.supi,
            a.snssai.sst,
            a.snssai.sd
        );
        RECONCILED.inc(&[result]);
        ended += 1;
    }
    let mut set = lock(pending());
    for a in still.into_iter().rev() {
        if !set.contains(&a) {
            set.push_front(a);
        }
    }
    evict(&mut set);
    ended
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        timer.tick().await;
        loop {
            timer.tick().await;
            reconcile_once().await;
        }
    })
}

/// The NSAC families, for `/metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_header(
        out,
        "amf_nsac_ue_admissions",
        "gauge",
        "UE admissions (SUPI, access type, S-NSSAI) the NSACF granted and the AMF holds",
    );
    let _ = writeln!(out, "amf_nsac_ue_admissions {}", lock(admissions()).len());
    nextgcore_metrics::nf::write_header(
        out,
        "amf_nsac_ue_decreases_pending",
        "gauge",
        "Nnsacf_NSAC_NumOfUEsUpdate DECREASEs parked for the reconciler",
    );
    let _ = writeln!(out, "amf_nsac_ue_decreases_pending {}", pending_count());
    DECREASES.render(out);
    RECONCILED.render(out);
}

/// Forget every admission and parked DECREASE (a test's own, before and after it).
#[cfg(test)]
pub fn clear_for_test() {
    lock(admissions()).clear();
    lock(pending()).clear();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nextgcore_sbi::message::{SbiRequest, SbiResponse};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;

    type Seen = Arc<Mutex<Vec<(String, u8)>>>;

    /// A stand-in NSACF recording (updateFlag, SST). An INCREASE for an SST in
    /// `deny` is refused 403 with a ProblemDetails (the quota is full); every other
    /// INCREASE is admitted 204; a DECREASE is answered with `decrease` as it stands.
    pub(crate) async fn nsacf(
        deny: &'static [u8],
        decrease: Arc<AtomicU16>,
    ) -> (nextgcore_sbi::server::SbiServer, u16, Seen) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (srv, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let sink = sink.clone();
                let decrease = decrease.load(Ordering::SeqCst);
                async move {
                    let body: serde_json::Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();
                    let op = &body["ueACRequestInfo"][0]["acuOperationList"][0];
                    let flag = op["updateFlag"].as_str().unwrap_or_default().to_string();
                    let sst = op["snssai"]["sst"].as_u64().unwrap_or(0) as u8;
                    sink.lock().unwrap().push((flag.clone(), sst));
                    if flag == "DECREASE" {
                        return SbiResponse::with_status(decrease);
                    }
                    if deny.contains(&sst) {
                        return SbiResponse::with_status(403)
                            .with_json_body(&serde_json::json!({
                                "status": 403, "cause": "UE_NOT_ALLOWED" }))
                            .unwrap();
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await;
        (srv, addr.port(), seen)
    }

    pub(crate) fn snssai(sst: u8) -> SNssai {
        SNssai { sst, sd: None }
    }

    /// Wait (bounded) until `seen` holds `n` DECREASEs, then a settle window.
    pub(crate) async fn decreases(seen: &Seen, n: usize) -> Vec<u8> {
        let get = || -> Vec<u8> {
            seen.lock()
                .unwrap()
                .iter()
                .filter(|(f, _)| f == "DECREASE")
                .map(|(_, s)| *s)
                .collect()
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while get().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        get()
    }

    /// #1876: a registration denied on its second S-NSSAI counts the UE out of the
    /// first again: the UE is rejected, so it holds no slice.
    ///
    /// REVERT-VERIFIED: with the denial taking nothing back, this fails: no
    /// DECREASE for SST 1, which stays counted.
    #[tokio::test]
    async fn a_denied_later_snssai_counts_the_earlier_grant_out_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, seen) = nsacf(&[2], Arc::new(AtomicU16::new(204))).await;
        let supi = "imsi-001010000018761";

        let out = admit_registration(
            supi,
            "3GPP_ACCESS",
            &[snssai(1), snssai(2)],
            "127.0.0.1",
            port,
            "amf-1876",
        )
        .await;
        let decreased = decreases(&seen, 1).await;
        let held = is_admitted(supi, "3GPP_ACCESS", &snssai(1));
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(out.denied, Some(snssai(2)));
        assert_eq!(decreased, vec![1], "SST 1 counted out again, and only it");
        assert!(!held, "and no admission is held");
    }

    /// #1876: a re-registration whose Allowed NSSAI drops an S-NSSAI counts the UE
    /// out of it, and keeps the one still allowed.
    ///
    /// REVERT-VERIFIED: with `take` given `&[]`-less behaviour (nothing taken on
    /// success), this fails: no DECREASE for SST 2.
    #[tokio::test]
    async fn an_snssai_removed_from_the_allowed_nssai_is_counted_out_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, seen) = nsacf(&[], Arc::new(AtomicU16::new(204))).await;
        let supi = "imsi-001010000018762";
        let admit = |allowed: Vec<SNssai>| async move {
            admit_registration(supi, "3GPP_ACCESS", &allowed, "127.0.0.1", port, "amf-1876")
                .await
        };

        admit(vec![snssai(1), snssai(2)]).await;
        let both = (
            is_admitted(supi, "3GPP_ACCESS", &snssai(1)),
            is_admitted(supi, "3GPP_ACCESS", &snssai(2)),
        );
        admit(vec![snssai(1)]).await;
        let decreased = decreases(&seen, 1).await;
        let after = (
            is_admitted(supi, "3GPP_ACCESS", &snssai(1)),
            is_admitted(supi, "3GPP_ACCESS", &snssai(2)),
        );
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(both, (true, true), "both counted in");
        assert_eq!(decreased, vec![2], "SST 2 counted out");
        assert_eq!(after, (true, false), "SST 1 kept");
    }

    /// #1876: an INCREASE that degraded open (no NSACF answered) counted nothing,
    /// so nothing is recorded and a deregistration parks nothing.
    #[tokio::test]
    async fn a_degraded_open_admission_is_not_recorded_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let supi = "imsi-001010000018763";
        let out =
            admit_registration(supi, "3GPP_ACCESS", &[snssai(1)], "127.0.0.1", 1, "amf-1876")
                .await;
        let held = is_admitted(supi, "3GPP_ACCESS", &snssai(1));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let parked_now = pending_count();
        clear_for_test();

        assert!(out.granted && out.denied.is_none(), "degrade-open admits");
        assert!(!held, "but counted nothing to undo");
        assert_eq!(parked_now, 0, "and its precautionary DECREASE is not parked");
    }

    /// #1876: a DECREASE that fails is parked, retried while the NSACF fails, and
    /// delivered once it recovers. One whose slice was admitted again meanwhile is
    /// superseded and not sent.
    ///
    /// REVERT-VERIFIED: with `decrease_now` not parking a failure, this fails:
    /// nothing is parked.
    #[tokio::test]
    async fn a_failed_decrease_is_reconciled_or_superseded_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let status = Arc::new(AtomicU16::new(503));
        let (srv, port, seen) = nsacf(&[], status.clone()).await;
        let admission = |supi: &str, sst: u8| Admission {
            supi: supi.to_string(),
            access_type: "3GPP_ACCESS".to_string(),
            snssai: snssai(sst),
            nf_id: "amf-1876".to_string(),
            nsacf_host: "127.0.0.1".to_string(),
            nsacf_port: port,
        };
        let (gone, back) = ("imsi-001010000018764", "imsi-001010000018765");
        let delivered = || RECONCILED.get(&["delivered"]);
        let superseded = || RECONCILED.get(&["superseded"]);
        let before = (delivered(), superseded());

        let first = decrease_now(admission(gone, 1)).await;
        decrease_now(admission(back, 1)).await;
        let parked_after_failure = pending_count();
        // `back` registers again before the reconciler runs.
        record(admission(back, 1));
        status.store(204, Ordering::SeqCst);
        reconcile_once().await;
        let left = pending_count();
        let sent_for_back = seen.lock().unwrap().len();
        let after = (delivered(), superseded());
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(first, Outcome::Failed);
        assert_eq!(parked_after_failure, 2, "both parked");
        assert_eq!(left, 0, "both ended");
        assert_eq!(sent_for_back, 3, "two failures, then one delivered; none for `back`");
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
    }

    /// #1876: bounded. Parking past [`MAX_PENDING`] evicts the oldest.
    ///
    /// REVERT-VERIFIED: with `evict` a no-op, this fails: MAX_PENDING + 1 are held.
    #[tokio::test]
    async fn the_parked_set_is_bounded_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let before = RECONCILED.get(&["abandoned"]);
        for n in 0..=MAX_PENDING {
            park(Admission {
                supi: format!("imsi-bound-{n}"),
                access_type: "3GPP_ACCESS".to_string(),
                snssai: snssai(1),
                nf_id: "amf-1876".to_string(),
                nsacf_host: "127.0.0.1".to_string(),
                nsacf_port: 1,
            });
        }
        let held = parked();
        clear_for_test();

        assert_eq!(held.len(), MAX_PENDING);
        assert_eq!(held[0].supi, "imsi-bound-1", "the oldest went");
        assert_eq!(RECONCILED.get(&["abandoned"]) - before, 1);
    }
}
