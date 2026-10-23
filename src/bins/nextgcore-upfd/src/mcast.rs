//! UPF Multicast Forwarding (TS 23.247)
//!
//! MBS (Multicast/Broadcast Service) support in the User Plane Function:
//! - Multicast PDR/FAR rules (1-to-many forwarding)
//! - Multicast GTP-U tunnel setup (single DL tunnel to multiple gNBs)
//! - MBS session activate/deactivate via PFCP (N4mb)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{RwLock, RwLockWriteGuard};

/// Multicast session in UPF
#[derive(Debug, Clone)]
pub struct McastSession {
    /// N4mb PFCP SEID (from MB-SMF)
    pub n4mb_seid: u64,
    /// Multicast PDR ID
    pub mcast_pdr_id: u16,
    /// Multicast FAR ID
    pub mcast_far_id: u32,
    /// GTP-U TEID for multicast DL data (from content source)
    pub ingress_teid: u32,
    /// Ingress GTP-U endpoint address
    pub ingress_addr: Ipv4Addr,
    /// gNB forwarding endpoints (1-to-many)
    pub gnb_endpoints: Vec<McastGnbEndpoint>,
    /// Session active flag
    pub active: bool,
    /// Total packets forwarded
    pub packets_forwarded: u64,
    /// Total bytes forwarded
    pub bytes_forwarded: u64,
}

/// gNB endpoint for multicast GTP-U delivery
#[derive(Debug, Clone)]
pub struct McastGnbEndpoint {
    /// gNB GTP-U address
    pub gnb_addr: Ipv4Addr,
    /// gNB GTP-U TEID
    pub gnb_teid: u32,
    /// gNB identifier
    pub gnb_id: String,
}

/// Multicast forwarding context in UPF
pub struct McastContext {
    /// Active multicast sessions (N4mb SEID -> session)
    sessions: RwLock<HashMap<u64, McastSession>>,
    /// Ingress TEID -> N4mb SEID index (for fast forwarding lookup)
    teid_index: RwLock<HashMap<u32, u64>>,
    /// Next TEID allocator for ingress
    next_teid: AtomicU32,
}

impl McastContext {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            teid_index: RwLock::new(HashMap::new()),
            next_teid: AtomicU32::new(0x0C00_0001),
        }
    }

    /// Write-lock BOTH maps, in THE order: `sessions`, then `teid_index` (#770).
    ///
    /// The only place in this type that holds both locks at once. Every other method
    /// holds at most one, and `forward_lookup` releases `teid_index` before it takes
    /// `sessions`, so the order cannot be inverted by editing one call site.
    #[allow(clippy::type_complexity)]
    fn lock_both_mut(
        &self,
    ) -> Option<(
        RwLockWriteGuard<'_, HashMap<u64, McastSession>>,
        RwLockWriteGuard<'_, HashMap<u32, u64>>,
    )> {
        let sessions = self.sessions.write().ok()?;
        let teid_index = self.teid_index.write().ok()?;
        Some((sessions, teid_index))
    }

    /// Activate a multicast session (N4mb Session Establishment)
    pub fn session_activate(
        &self,
        n4mb_seid: u64,
        mcast_pdr_id: u16,
        mcast_far_id: u32,
        ingress_addr: Ipv4Addr,
    ) -> Option<McastSession> {
        let (mut sessions, mut teid_index) = self.lock_both_mut()?;

        // A second activation of a SEID (e.g. a retransmitted Establishment) replaces
        // the session, so the TEID it held must stop resolving: left in the index it
        // kept `is_multicast_pdr` true forever, even after `session_deactivate` (which
        // only knows the current TEID).
        if let Some(old) = sessions.get(&n4mb_seid) {
            teid_index.remove(&old.ingress_teid);
        }

        let ingress_teid = self.next_teid.fetch_add(1, Ordering::SeqCst);

        let session = McastSession {
            n4mb_seid,
            mcast_pdr_id,
            mcast_far_id,
            ingress_teid,
            ingress_addr,
            gnb_endpoints: Vec::new(),
            active: true,
            packets_forwarded: 0,
            bytes_forwarded: 0,
        };

        teid_index.insert(ingress_teid, n4mb_seid);
        sessions.insert(n4mb_seid, session.clone());

        log::info!(
            "Multicast session activated: seid={n4mb_seid} pdr={mcast_pdr_id} far={mcast_far_id} teid={ingress_teid:#x}"
        );

        Some(session)
    }

    /// Deactivate a multicast session (N4mb Session Release)
    pub fn session_deactivate(&self, n4mb_seid: u64) -> Option<McastSession> {
        let (mut sessions, mut teid_index) = self.lock_both_mut()?;

        if let Some(session) = sessions.remove(&n4mb_seid) {
            teid_index.remove(&session.ingress_teid);
            log::info!(
                "Multicast session deactivated: seid={} (forwarded {} pkts, {} bytes)",
                n4mb_seid,
                session.packets_forwarded,
                session.bytes_forwarded
            );
            return Some(session);
        }
        None
    }

    /// Add a gNB endpoint to a multicast session (N4mb Session Modification)
    pub fn add_gnb_endpoint(
        &self,
        n4mb_seid: u64,
        gnb_addr: Ipv4Addr,
        gnb_teid: u32,
        gnb_id: &str,
    ) -> bool {
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(session) = sessions.get_mut(&n4mb_seid) {
                session.gnb_endpoints.push(McastGnbEndpoint {
                    gnb_addr,
                    gnb_teid,
                    gnb_id: gnb_id.to_string(),
                });
                log::info!(
                    "Multicast gNB added: seid={} gnb={} teid={:#x} addr={} (total={})",
                    n4mb_seid,
                    gnb_id,
                    gnb_teid,
                    gnb_addr,
                    session.gnb_endpoints.len()
                );
                return true;
            }
        }
        false
    }

    /// Remove a gNB endpoint from a multicast session
    pub fn remove_gnb_endpoint(&self, n4mb_seid: u64, gnb_id: &str) -> bool {
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(session) = sessions.get_mut(&n4mb_seid) {
                let before = session.gnb_endpoints.len();
                session.gnb_endpoints.retain(|e| e.gnb_id != gnb_id);
                if session.gnb_endpoints.len() < before {
                    log::info!("Multicast gNB removed: seid={n4mb_seid} gnb={gnb_id}");
                    return true;
                }
            }
        }
        false
    }

    /// Perform 1-to-many multicast forwarding
    /// Returns the list of (gnb_addr, gnb_teid) destinations for a given ingress TEID
    /// This function handles PDR matching for source interface = N3mb
    pub fn forward_lookup(&self, ingress_teid: u32) -> Vec<(Ipv4Addr, u32)> {
        // #770: copy the SEID out and RELEASE `teid_index` before taking `sessions`.
        // `session_activate`/`session_deactivate` take `sessions` then `teid_index`;
        // holding `teid_index` while waiting for `sessions` here was the reverse
        // order, so a lookup racing an activation deadlocked both. No call in this
        // type now holds `teid_index` while acquiring `sessions`.
        let seid = match self
            .teid_index
            .read()
            .ok()
            .and_then(|idx| idx.get(&ingress_teid).copied())
        {
            Some(s) => s,
            None => return vec![],
        };
        let sessions = match self.sessions.read().ok() {
            Some(s) => s,
            None => return vec![],
        };

        // The index is no longer held, so re-check that the session still owns this
        // TEID: it may have been deactivated (and its SEID re-activated on a new
        // TEID) in between, and a stale TEID must not reach the new tree.
        let session = match sessions.get(&seid) {
            Some(s) if s.active && s.ingress_teid == ingress_teid => s,
            _ => return vec![],
        };

        // Multicast replication: one incoming packet → multiple outgoing GTP-U tunnels
        session
            .gnb_endpoints
            .iter()
            .map(|e| (e.gnb_addr, e.gnb_teid))
            .collect()
    }

    /// Check if a TEID corresponds to a multicast PDR (source interface = N3mb)
    pub fn is_multicast_pdr(&self, ingress_teid: u32) -> bool {
        if let Ok(teid_index) = self.teid_index.read() {
            return teid_index.contains_key(&ingress_teid);
        }
        false
    }

    /// Get multicast distribution tree size for a session
    pub fn get_distribution_tree_size(&self, n4mb_seid: u64) -> usize {
        self.sessions
            .read()
            .ok()
            .and_then(|s| s.get(&n4mb_seid).map(|sess| sess.gnb_endpoints.len()))
            .unwrap_or(0)
    }

    /// Record forwarded packet statistics
    pub fn record_forwarded(&self, n4mb_seid: u64, bytes: u64) {
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(session) = sessions.get_mut(&n4mb_seid) {
                session.packets_forwarded += 1;
                session.bytes_forwarded += bytes;
            }
        }
    }

    /// Get multicast session by SEID
    pub fn session_find(&self, n4mb_seid: u64) -> Option<McastSession> {
        self.sessions.read().ok()?.get(&n4mb_seid).cloned()
    }

    /// Get all active multicast sessions
    pub fn active_sessions(&self) -> Vec<McastSession> {
        self.sessions
            .read()
            .map(|s| s.values().filter(|s| s.active).cloned().collect())
            .unwrap_or_default()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().map(|s| s.len()).unwrap_or(0)
    }
}

impl Default for McastContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcast_context_new() {
        let ctx = McastContext::new();
        assert_eq!(ctx.session_count(), 0);
    }

    #[test]
    fn test_session_activate_deactivate() {
        let ctx = McastContext::new();

        let session = ctx
            .session_activate(0x100, 1001, 2001, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        assert!(session.active);
        assert_eq!(session.n4mb_seid, 0x100);
        assert_eq!(ctx.session_count(), 1);

        let found = ctx.session_find(0x100).unwrap();
        assert_eq!(found.mcast_pdr_id, 1001);

        ctx.session_deactivate(0x100);
        assert_eq!(ctx.session_count(), 0);
    }

    #[test]
    fn test_gnb_endpoint_management() {
        let ctx = McastContext::new();
        ctx.session_activate(0x200, 1002, 2002, Ipv4Addr::new(10, 0, 0, 1));

        assert!(ctx.add_gnb_endpoint(0x200, Ipv4Addr::new(10, 0, 1, 1), 0x3001, "gnb-001"));
        assert!(ctx.add_gnb_endpoint(0x200, Ipv4Addr::new(10, 0, 1, 2), 0x3002, "gnb-002"));

        let session = ctx.session_find(0x200).unwrap();
        assert_eq!(session.gnb_endpoints.len(), 2);

        assert!(ctx.remove_gnb_endpoint(0x200, "gnb-001"));
        let session = ctx.session_find(0x200).unwrap();
        assert_eq!(session.gnb_endpoints.len(), 1);
    }

    #[test]
    fn test_forward_lookup() {
        let ctx = McastContext::new();
        let session = ctx
            .session_activate(0x300, 1003, 2003, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();

        ctx.add_gnb_endpoint(0x300, Ipv4Addr::new(10, 0, 1, 1), 0x4001, "gnb-001");
        ctx.add_gnb_endpoint(0x300, Ipv4Addr::new(10, 0, 1, 2), 0x4002, "gnb-002");
        ctx.add_gnb_endpoint(0x300, Ipv4Addr::new(10, 0, 1, 3), 0x4003, "gnb-003");

        let destinations = ctx.forward_lookup(session.ingress_teid);
        assert_eq!(destinations.len(), 3);
    }

    /// #770: a forwarding lookup racing session activation/deactivation must not
    /// deadlock. Before the fix `forward_lookup` held `teid_index` while taking
    /// `sessions`, the reverse of activate/deactivate's order. Both loops run on their
    /// own threads under a deadline so a deadlock is a failure, not a hung suite.
    #[test]
    fn forward_lookup_racing_activation_does_not_deadlock() {
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let ctx = Arc::new(McastContext::new());
        let s = ctx
            .session_activate(0x770, 1, 1, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        ctx.add_gnb_endpoint(0x770, Ipv4Addr::new(10, 0, 1, 1), 0x4001, "gnb-770");
        let teid = s.ingress_teid;
        let run_for = Duration::from_secs(2);

        let (tx, rx) = std::sync::mpsc::channel();
        let c = Arc::clone(&ctx);
        let tx1 = tx.clone();
        let tx1_extra = tx.clone();
        std::thread::spawn(move || {
            let t0 = Instant::now();
            let mut hits = 0u64;
            while t0.elapsed() < run_for {
                hits += c.forward_lookup(teid).len() as u64;
            }
            let _ = tx1.send(("lookup", hits));
        });
        let c = Arc::clone(&ctx);
        std::thread::spawn(move || {
            let t0 = Instant::now();
            let mut n = 0u64;
            while t0.elapsed() < run_for {
                c.session_activate(0x771, 2, 2, Ipv4Addr::new(10, 0, 0, 2));
                c.session_deactivate(0x771);
                n += 1;
            }
            let _ = tx.send(("churn", n));
        });
        // A second churner on another SEID, so activate and deactivate also race EACH
        // OTHER: an inversion between those two (e.g. deactivate taking teid_index
        // first) deadlocks here even though forward_lookup is innocent.
        let c = Arc::clone(&ctx);
        let tx2 = tx1_extra.clone();
        std::thread::spawn(move || {
            let t0 = Instant::now();
            let mut n = 0u64;
            while t0.elapsed() < run_for {
                c.session_activate(0x772, 3, 3, Ipv4Addr::new(10, 0, 0, 3));
                c.session_deactivate(0x772);
                n += 1;
            }
            let _ = tx2.send(("churn2", n));
        });

        let mut lookups = None;
        for _ in 0..3 {
            let (who, n) = rx
                .recv_timeout(run_for + Duration::from_secs(8))
                .expect("forward_lookup / session_activate / session_deactivate deadlocked (#770)");
            if who == "lookup" {
                lookups = Some(n);
            }
        }
        // Positive: the lookup kept resolving the untouched session throughout.
        assert!(lookups.expect("lookup finished") > 0);
        assert_eq!(
            ctx.forward_lookup(teid),
            vec![(Ipv4Addr::new(10, 0, 1, 1), 0x4001)]
        );
    }

    /// #770 review m1/m2: re-activating a SEID without a deactivation (a retransmitted
    /// Establishment) retires the TEID it held. The old TEID must neither resolve to
    /// the NEW session's distribution tree (the `forward_lookup` re-check) nor remain
    /// in the index -- before, `is_multicast_pdr(old)` stayed true even after the
    /// session was deactivated.
    #[test]
    fn re_activating_a_seid_retires_its_old_teid() {
        let ctx = McastContext::new();
        let first = ctx
            .session_activate(0x773, 1, 1, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        let second = ctx
            .session_activate(0x773, 1, 1, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        ctx.add_gnb_endpoint(0x773, Ipv4Addr::new(10, 0, 1, 1), 0x4001, "gnb-773");
        assert_ne!(first.ingress_teid, second.ingress_teid);

        assert!(ctx.forward_lookup(first.ingress_teid).is_empty());
        assert!(!ctx.is_multicast_pdr(first.ingress_teid));
        assert_eq!(ctx.forward_lookup(second.ingress_teid).len(), 1);
        assert!(ctx.is_multicast_pdr(second.ingress_teid));

        ctx.session_deactivate(0x773);
        assert!(!ctx.is_multicast_pdr(second.ingress_teid));
        assert!(!ctx.is_multicast_pdr(first.ingress_teid));
    }

    #[test]
    fn test_forward_lookup_inactive() {
        let ctx = McastContext::new();

        // Non-existent TEID returns empty
        let destinations = ctx.forward_lookup(0xDEAD);
        assert!(destinations.is_empty());
    }

    #[test]
    fn test_record_forwarded() {
        let ctx = McastContext::new();
        ctx.session_activate(0x400, 1004, 2004, Ipv4Addr::new(10, 0, 0, 1));

        ctx.record_forwarded(0x400, 1500);
        ctx.record_forwarded(0x400, 1200);

        let session = ctx.session_find(0x400).unwrap();
        assert_eq!(session.packets_forwarded, 2);
        assert_eq!(session.bytes_forwarded, 2700);
    }

    #[test]
    fn test_active_sessions() {
        let ctx = McastContext::new();
        ctx.session_activate(0x500, 1005, 2005, Ipv4Addr::new(10, 0, 0, 1));
        ctx.session_activate(0x501, 1006, 2006, Ipv4Addr::new(10, 0, 0, 2));

        let active = ctx.active_sessions();
        assert_eq!(active.len(), 2);
    }
}
