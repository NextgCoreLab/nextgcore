//! The one authoritative live-UE store for `amfd` (#341).
//!
//! # Why this module exists
//!
//! `amfd` had **two** UE stores: `NgapServer::ue_auth_state`, which the whole
//! NGAP registration path wrote and only the NGAP receive loop read, and
//! `AmfContext::{amf_ue_list, ran_ue_list, supi_hash, guti_ue_hash}`, which
//! **every Namf SBI handler read and only tests wrote**. Production reader,
//! test-only writer — so for a UE that had actually registered over NGAP,
//! `Namf_Communication_N1N2MessageTransfer`, `Namf_MT_EnableUeReachability`,
//! `Namf_MT_ProvideDomainSelectionInfo` and per-UE `Namf_EventExposure`
//! subscriptions all answered `404 CONTEXT_NOT_FOUND`. That is the defect class
//! of #325 (`upfd`, merged) and #223 (`smfd`, open), and this was the widest of
//! the three because the dead store is what the entire SBI surface resolved
//! against.
//!
//! # Why the live map moved here rather than the NGAP path publishing into the context
//!
//! Option 1 on the issue was to have the NGAP path also write the context's
//! lists. That is *two stores updated from one path*, which #325 named as the
//! worst of its options, and the duplicated object here is `AmfUe` — ~90 fields,
//! mutated at every step of authentication, security mode, registration,
//! handover and release. Divergence would not fail loudly; the Namf surface
//! would act on a stale UE (wrong keys, wrong GUTI, wrong CM state), which is
//! worse than a 404.
//!
//! # Why the resolvers DERIVE instead of being indexed
//!
//! `supi_hash` and `guti_ue_hash` are gone. [`UeStore::find_by_supi`] and
//! [`UeStore::find_by_guti`] scan the one map instead. An index maintained
//! beside a collection that can disagree with it is the exact shape this tree
//! keeps finding broken — #325, #365 and #363's own root cause — and deriving
//! makes divergence impossible by construction rather than by discipline. The
//! cost is O(n) per Namf request, against O(1) with an index that can lie; the
//! scan runs per *SBI request*, not per NGAP message, and `max_num_of_ue` bounds
//! n.
//!
//! # The hazard this API is shaped to prevent
//!
//! The store lives behind a `std::sync::RwLock` whose guard is **not `Send`**, so
//! holding one across an `.await` fails to compile — a good failure mode, and
//! clippy's `await_holding_lock` catches the rest. What does **not** fail to
//! compile is a closure that re-enters the store while a guard is held: that
//! deadlocks at runtime. So every accessor here takes the lock, does its work,
//! and releases it before returning. **None of them takes a callback**, which is
//! what makes re-entrancy unexpressible rather than merely discouraged: there is
//! no lexical region in a caller during which a guard is live.
//!
//! The price is that a mutation is `with_ue`-style read-modify-write on a clone
//! rather than a `&mut` borrow. [`UeStore::update`] exists for that, and
//! `snapshot_ids` exists so the timer sweeps can iterate *without* holding the
//! lock across the per-UE work they do — the loop shape that would otherwise
//! deadlock.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::context::{AmfUe, Guti5gs};

/// The live per-UE NAS/registration state, keyed by AMF-UE-NGAP-ID.
///
/// Generic over the per-UE record so `ngap_path`'s `UeNasContext` — which holds
/// types private to that module (`NasRetx`, `Reachability`, `GmmFsm`) — can live
/// in the context without those types becoming part of the context's public
/// surface. The store needs exactly two things of a record: that it can be
/// cloned out, and that the UE identity can be read back off it for the derived
/// resolvers.
#[derive(Debug, Default)]
pub struct UeStore<T> {
    ues: RwLock<HashMap<u64, T>>,
}

/// What the derived resolvers need to read off a record.
///
/// A trait rather than closures passed at each call, so a record type cannot be
/// stored with one notion of its SUPI and looked up by another.
pub trait UeIdentity {
    /// The UE's full AMF context, which carries SUPI and GUTI.
    fn amf_ue(&self) -> &AmfUe;
    /// The RAN UE NGAP ID currently serving this UE.
    fn ran_ue_ngap_id(&self) -> u32;
}

impl<T: Clone + UeIdentity> UeStore<T> {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            ues: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or replace the record for `amf_ue_ngap_id`, returning the previous
    /// one if there was one.
    ///
    /// A poisoned lock is recovered from rather than propagated: a panic in one
    /// UE's handling must not make the AMF unable to serve any other UE, and the
    /// map's invariant is per-key. Same posture as #363 took for the context.
    pub fn insert(&self, amf_ue_ngap_id: u64, ue: T) -> Option<T> {
        self.write().insert(amf_ue_ngap_id, ue)
    }

    /// Remove and return the record for `amf_ue_ngap_id`.
    pub fn remove(&self, amf_ue_ngap_id: u64) -> Option<T> {
        self.write().remove(&amf_ue_ngap_id)
    }

    /// A clone of the record for `amf_ue_ngap_id`.
    ///
    /// Returns a clone rather than a guard on purpose: a guard handed to a caller
    /// is a guard whose lifetime the caller controls, and the callers here are
    /// `async fn`s that would then hold it across an `.await`.
    pub fn get(&self, amf_ue_ngap_id: u64) -> Option<T> {
        self.read().get(&amf_ue_ngap_id).cloned()
    }

    /// Whether a record exists for `amf_ue_ngap_id`.
    pub fn contains(&self, amf_ue_ngap_id: u64) -> bool {
        self.read().contains_key(&amf_ue_ngap_id)
    }

    /// Apply `f` to the record for `amf_ue_ngap_id` in place, returning its
    /// result, or `None` if there is no such record.
    ///
    /// `f` runs **while the write lock is held**, so it must not touch the store
    /// again and must not block. It is `FnOnce(&mut T) -> R` rather than an async
    /// closure precisely so it cannot `.await`: use this for field updates, and
    /// [`UeStore::get`] plus [`UeStore::update`] when the work between reading
    /// and writing needs to `.await`.
    pub fn with_mut<R>(&self, amf_ue_ngap_id: u64, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.write().get_mut(&amf_ue_ngap_id).map(f)
    }

    /// Replace an existing record, returning whether one was there to replace.
    ///
    /// The read-modify-write partner of [`UeStore::get`], for a caller that had
    /// to `.await` in between and so could not hold a lock. Note the semantics
    /// that follow: a concurrent mutation between the `get` and the `update` is
    /// overwritten. Every caller in `ngap_path` is on the single-threaded NGAP
    /// receive loop for one UE's procedure, so there is no second writer for the
    /// same key — but this is the reason `with_mut` is preferred where it fits.
    pub fn update(&self, amf_ue_ngap_id: u64, ue: T) -> bool {
        let mut guard = self.write();
        if let std::collections::hash_map::Entry::Occupied(mut e) = guard.entry(amf_ue_ngap_id) {
            e.insert(ue);
            true
        } else {
            false
        }
    }

    /// Every AMF-UE-NGAP-ID currently in the store.
    ///
    /// **This is how you iterate.** The timer sweeps need to visit each UE and do
    /// per-UE work that sends NGAP PDUs and therefore `.await`s; iterating the map
    /// directly would either hold the guard across those awaits (which does not
    /// compile, since the guard is not `Send`) or re-enter the store from inside
    /// the loop (which deadlocks and does NOT fail to compile). Collecting the
    /// keys first releases the lock before any of that work begins.
    ///
    /// Sorted, so a sweep's order is deterministic: `HashMap` iteration order
    /// would otherwise make the order in which UEs are serviced observable to a
    /// test and different run to run.
    pub fn snapshot_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.read().keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Every (id, record) pair, cloned. For the sweeps that need to filter on
    /// record state before deciding which UEs to visit.
    ///
    /// Sorted by id for the same determinism reason as [`UeStore::snapshot_ids`].
    pub fn snapshot(&self) -> Vec<(u64, T)> {
        let mut all: Vec<(u64, T)> = self
            .read()
            .iter()
            .map(|(id, ue)| (*id, ue.clone()))
            .collect();
        all.sort_unstable_by_key(|(id, _)| *id);
        all
    }

    /// How many UEs are live.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// Drop every record. Used by `amf_context_final` and by test setup.
    pub fn clear(&self) {
        self.write().clear();
    }

    /// Remove every record for which `pred` returns false, returning the ids
    /// removed.
    ///
    /// The ids are returned rather than the records because the callers
    /// (NG Reset, gNB teardown) then have per-UE `.await` work to do, and the
    /// lock must be gone by then.
    pub fn retain_ids(&self, pred: impl Fn(&T) -> bool) -> Vec<u64> {
        let mut guard = self.write();
        let dropped: Vec<u64> = guard
            .iter()
            .filter(|(_, ue)| !pred(ue))
            .map(|(id, _)| *id)
            .collect();
        for id in &dropped {
            guard.remove(id);
        }
        dropped
    }

    // ========================================================================
    // Derived resolvers (#341): no index, so no index can disagree with the map
    // ========================================================================

    /// The AMF-UE-NGAP-ID and record of the UE with this SUPI.
    ///
    /// Derived by scanning, which is the whole point — see the module docs. The
    /// SUPI is unique per registered UE (TS 23.501 §5.9.2), so the first match is
    /// the only match; ties would mean the store already held two records for one
    /// subscriber, which is a bug this cannot paper over.
    pub fn find_by_supi(&self, supi: &str) -> Option<(u64, T)> {
        self.read()
            .iter()
            .find(|(_, ue)| ue.amf_ue().supi.as_deref() == Some(supi))
            .map(|(id, ue)| (*id, ue.clone()))
    }

    /// The AMF-UE-NGAP-ID and record of the UE holding this 5G-GUTI.
    pub fn find_by_guti(&self, guti: &Guti5gs) -> Option<(u64, T)> {
        self.read()
            .iter()
            .find(|(_, ue)| &ue.amf_ue().current_guti == guti)
            .map(|(id, ue)| (*id, ue.clone()))
    }

    /// The AMF-UE-NGAP-ID and record of the UE currently served by this
    /// RAN-UE-NGAP-ID.
    ///
    /// Unlike SUPI and GUTI this is **not** globally unique — a RAN UE NGAP ID is
    /// only unique within one gNB — so a caller that can see more than one gNB
    /// must narrow by association itself. The single production caller resolves a
    /// UE whose association it already knows.
    pub fn find_by_ran_ue_ngap_id(&self, ran_ue_ngap_id: u32) -> Option<(u64, T)> {
        self.read()
            .iter()
            .find(|(_, ue)| ue.ran_ue_ngap_id() == ran_ue_ngap_id)
            .map(|(id, ue)| (*id, ue.clone()))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<u64, T>> {
        self.ues.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<u64, T>> {
        self.ues.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal record, so these tests exercise the STORE and not `UeNasContext`.
    #[derive(Debug, Clone)]
    struct TestUe {
        amf_ue: AmfUe,
        ran_ue_ngap_id: u32,
    }

    impl UeIdentity for TestUe {
        fn amf_ue(&self) -> &AmfUe {
            &self.amf_ue
        }
        fn ran_ue_ngap_id(&self) -> u32 {
            self.ran_ue_ngap_id
        }
    }

    fn ue(id: u64, supi: Option<&str>) -> TestUe {
        let mut amf_ue = AmfUe::new(id, id);
        amf_ue.supi = supi.map(str::to_string);
        TestUe {
            amf_ue,
            ran_ue_ngap_id: id as u32,
        }
    }

    /// The defect #341 is about, as a store-level property: what the NGAP path
    /// inserts is what a SUPI lookup finds. Before this there were two maps and
    /// the answer was `None`.
    #[test]
    fn a_ue_inserted_by_id_is_findable_by_its_supi() {
        let store = UeStore::new();
        store.insert(7, ue(7, Some("imsi-001010000000001")));

        let (id, found) = store
            .find_by_supi("imsi-001010000000001")
            .expect("the inserted UE must be findable by SUPI");
        assert_eq!(id, 7, "and it must be the same AMF-UE-NGAP-ID");
        assert_eq!(found.amf_ue().supi.as_deref(), Some("imsi-001010000000001"));
    }

    /// A UE with no SUPI yet (pre-authentication) must not be found by a SUPI
    /// lookup, and must not make the scan mis-resolve a different UE. The
    /// `Option<String>` comparison is the part that could go wrong: a `None`
    /// SUPI matching a `None` query would hand out an arbitrary UE.
    #[test]
    fn a_ue_without_a_supi_is_not_resolvable() {
        let store = UeStore::new();
        store.insert(1, ue(1, None));
        store.insert(2, ue(2, Some("imsi-001010000000002")));

        assert!(store.find_by_supi("imsi-001010000000001").is_none());
        assert_eq!(
            store.find_by_supi("imsi-001010000000002").map(|(id, _)| id),
            Some(2),
            "the SUPI-less sibling must not shadow the one that has one"
        );
    }

    /// The derived GUTI resolver, which is what #69's criteria 1 and 2 need.
    #[test]
    fn a_ue_is_findable_by_its_guti() {
        let store = UeStore::new();
        let mut a = ue(1, Some("imsi-001010000000001"));
        a.amf_ue.current_guti.tmsi = 0xAAAA;
        let mut b = ue(2, Some("imsi-001010000000002"));
        b.amf_ue.current_guti.tmsi = 0xBBBB;
        let target = a.amf_ue.current_guti.clone();
        store.insert(1, a);
        store.insert(2, b);

        assert_eq!(
            store.find_by_guti(&target).map(|(id, _)| id),
            Some(1),
            "the GUTI must resolve to the UE that holds it, not merely to some UE"
        );
    }

    /// Re-keying is the operation an INDEX would get wrong: the old value must
    /// stop resolving, and there must be no stale entry pointing at this UE. With
    /// a derived resolver this holds by construction, which is the property the
    /// test pins.
    #[test]
    fn updating_a_supi_retires_the_old_one_with_no_stale_index() {
        let store = UeStore::new();
        store.insert(3, ue(3, Some("imsi-old")));

        store
            .with_mut(3, |u| {
                u.amf_ue.supi = Some("imsi-new".to_string());
            })
            .expect("the UE is present");

        assert!(
            store.find_by_supi("imsi-old").is_none(),
            "the old SUPI must no longer resolve; an index left behind is exactly \
             the divergence this design removes"
        );
        assert_eq!(store.find_by_supi("imsi-new").map(|(id, _)| id), Some(3));
    }

    /// Removal must clear every resolver at once, again by construction.
    #[test]
    fn removing_a_ue_clears_every_resolver() {
        let store = UeStore::new();
        let u = ue(4, Some("imsi-001010000000004"));
        let guti = u.amf_ue.current_guti.clone();
        store.insert(4, u);

        assert!(store.remove(4).is_some());
        assert!(store.find_by_supi("imsi-001010000000004").is_none());
        assert!(store.find_by_guti(&guti).is_none());
        assert!(store.get(4).is_none());
        assert!(store.is_empty());
    }

    /// `update` must not resurrect a UE that has been released. Insert-on-absent
    /// would recreate a context the release path deliberately destroyed.
    #[test]
    fn update_does_not_resurrect_a_removed_ue() {
        let store = UeStore::new();
        assert!(
            !store.update(9, ue(9, Some("imsi-gone"))),
            "update must report that there was nothing to update"
        );
        assert!(
            store.get(9).is_none(),
            "and must not have inserted the record"
        );
    }

    /// The iteration order the sweeps depend on. Unsorted `HashMap` order would
    /// make the order in which UEs are serviced vary run to run.
    #[test]
    fn snapshots_are_ordered_by_id() {
        let store = UeStore::new();
        for id in [5_u64, 1, 9, 3] {
            store.insert(id, ue(id, None));
        }
        assert_eq!(store.snapshot_ids(), vec![1, 3, 5, 9]);
        assert_eq!(
            store
                .snapshot()
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            vec![1, 3, 5, 9]
        );
    }

    /// `retain_ids` reports what it dropped, because the caller has `.await` work
    /// to do per dropped UE and cannot be holding the lock by then.
    #[test]
    fn retain_ids_returns_the_ids_it_dropped() {
        let store = UeStore::new();
        store.insert(1, ue(1, Some("keep")));
        store.insert(2, ue(2, Some("drop")));
        store.insert(3, ue(3, Some("drop")));

        let dropped = store.retain_ids(|u| u.amf_ue().supi.as_deref() == Some("keep"));
        let mut dropped = dropped;
        dropped.sort_unstable();
        assert_eq!(dropped, vec![2, 3]);
        assert_eq!(store.len(), 1);
        assert!(store.get(1).is_some());
    }

    /// A poisoned lock must not take the AMF down: the map's invariant is
    /// per-key, so a panic while handling one UE must leave every other UE
    /// serviceable. Same posture #363 took for the context itself.
    #[test]
    fn a_poisoned_lock_is_recovered_from() {
        let store = std::sync::Arc::new(UeStore::new());
        store.insert(1, ue(1, Some("imsi-survivor")));

        let poisoner = std::sync::Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.write();
            panic!("poison the lock");
        })
        .join();

        assert_eq!(
            store.find_by_supi("imsi-survivor").map(|(id, _)| id),
            Some(1),
            "the store must still answer after a writer panicked"
        );
        store.insert(2, ue(2, None));
        assert_eq!(store.len(), 2, "and must still accept writes");
    }
}
