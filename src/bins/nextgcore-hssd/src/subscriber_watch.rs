//! Subscriber-change detection, so administrative edits reach the serving MME
//! (#56, TS 29.272 §5.2.2.1.1 / §5.2.1.2.1).
//!
//! # Why this module exists at all
//!
//! Issue #56's suggested approach was to *"wire IDR/CLR/DSR into the existing DB
//! change-poll loop"*. **There is no such loop.** `main.rs`'s event loop is a
//! 100 ms `sleep` with comments describing what a full implementation would do and
//! no database access of any kind. So the detection had to be built, not wired.
//!
//! # Shape, and what it buys
//!
//! The **decision** — given a previous view of the subscriber set and the current
//! one, which S6a messages should go out — is [`diff_subscribers`], a pure function
//! over two maps. Every branch of it is unit-testable with no Mongo, no peer and no
//! timer. The **wiring** is [`poll_once`], which reads the current view out of
//! MongoDB and hands the resulting actions to the S6a sender.
//!
//! That split is deliberate, and its risk is named rather than hidden: this repo has
//! a recorded hazard that "the helper is tested and the wiring is not — and the
//! better the helper's test, the more convincing the illusion". So the wiring here is
//! kept as thin as it can be (one query, one diff call, one send per action) and the
//! ceiling is stated in the spec: `poll_once`'s Mongo read is verified by inspection
//! only, because no test harness in this tree runs a MongoDB.

use std::collections::HashMap;

use crate::s6a_path::{self, CancellationType};

/// What the watcher knows about one subscriber between polls.
///
/// Deliberately small: a full subscription document per subscriber would make the
/// watcher's memory grow with the subscriber base for no gain, since the only
/// question is *"did this change?"* and not *"how did it change?"*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberView {
    /// The serving MME's Origin-Host, when one is registered. `None` means the
    /// subscriber is not attached anywhere.
    pub mme_host: Option<String>,
    /// A content fingerprint of the subscription data the MME was given.
    ///
    /// A fingerprint rather than the data itself so a change is detectable without
    /// storing what changed — the IDR re-reads the record anyway, so keeping a copy
    /// here would only create a second version to disagree with the first.
    pub fingerprint: u64,
}

/// An S6a message the watcher decided to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeAction {
    /// Subscription data changed while the subscriber is attached: push it
    /// (TS 29.272 §5.2.2.1.1 — Insert Subscriber Data is used "due to
    /// administrative changes of the user data in the HSS").
    InsertSubscriberData { imsi_bcd: String },
    /// The subscriber was deleted: detach it (TS 29.272 §5.2.1.2.1, Cancellation-Type
    /// SUBSCRIPTION_WITHDRAWAL).
    CancelLocation { imsi_bcd: String },
}

/// Decide what to send, given the previous and current views of every subscriber
/// that has a serving MME.
///
/// The rules, and why each one is the way it is:
///
/// * **Present before and after, fingerprint changed ⇒ IDR.** This is the
///   administrative-change case §5.2.2.1.1 names.
/// * **Present before, gone now ⇒ CLR(SUBSCRIPTION_WITHDRAWAL).** The subscriber's
///   record no longer exists, so the MME must stop serving it.
/// * **Absent before, present now ⇒ nothing.** A newly *attached* subscriber was
///   just given its data in the ULA it attached with; pushing an IDR on top would
///   duplicate it. A newly *provisioned* subscriber has no MME yet and so is not in
///   either map.
/// * **The serving MME changed ⇒ nothing.** That is an inter-MME location update,
///   and the Cancel Location it needs is sent by `handle_ulr` from the ULR itself
///   (TS 29.272 §5.2.1.1.3) — which knows the *previous* identity, while the
///   watcher only sees that the value differs. Acting here too would send a second,
///   duplicate Cancel Location to a node that has already been cancelled.
/// * **Fingerprint changed but no MME ⇒ nothing.** There is nobody to tell.
///
/// Returns actions in IMSI order, so a poll's behaviour does not depend on hash
/// iteration order.
pub fn diff_subscribers(
    previous: &HashMap<String, SubscriberView>,
    current: &HashMap<String, SubscriberView>,
) -> Vec<ChangeAction> {
    let mut actions = Vec::new();

    let mut imsis: Vec<&String> = previous.keys().chain(current.keys()).collect();
    imsis.sort();
    imsis.dedup();

    for imsi in imsis {
        match (previous.get(imsi), current.get(imsi)) {
            (Some(prev), Some(curr)) => {
                if prev.mme_host != curr.mme_host {
                    // Inter-MME move: handle_ulr owns the Cancel Location.
                    continue;
                }
                if curr.mme_host.is_none() {
                    continue;
                }
                if prev.fingerprint != curr.fingerprint {
                    actions.push(ChangeAction::InsertSubscriberData {
                        imsi_bcd: imsi.clone(),
                    });
                }
            }
            (Some(prev), None) => {
                // Deleted. Only worth a CLR if somebody was serving it.
                if prev.mme_host.is_some() {
                    actions.push(ChangeAction::CancelLocation {
                        imsi_bcd: imsi.clone(),
                    });
                }
            }
            // Newly attached, or newly provisioned with no MME: nothing to push.
            (None, _) => {}
        }
    }
    actions
}

/// Fingerprint the parts of a subscription document an MME is given.
///
/// Only the fields `subscription_data_from_db` actually serialises into
/// Subscription-Data are hashed. Hashing the whole document would fire an IDR for
/// every SQN increment — which happens on **every authentication** — turning the
/// watcher into a per-attach IDR generator.
pub fn fingerprint_subscription(db: &nextgcore_dbi::NextgcoreSubscriptionData) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    db.subscriber_status.hash(&mut h);
    db.operator_determined_barring.hash(&mut h);
    db.access_restriction_data.hash(&mut h);
    db.network_access_mode.hash(&mut h);
    db.subscribed_rau_tau_timer.hash(&mut h);
    db.ambr.uplink.hash(&mut h);
    db.ambr.downlink.hash(&mut h);
    for m in &db.msisdn {
        m.buf[..m.len.min(m.buf.len())].hash(&mut h);
    }
    for slice in &db.slice {
        for session in &slice.session {
            session.name.hash(&mut h);
            session.session_type.hash(&mut h);
            session.qos.index.hash(&mut h);
            session.qos.arp.priority_level.hash(&mut h);
            session.qos.arp.pre_emption_capability.hash(&mut h);
            session.qos.arp.pre_emption_vulnerability.hash(&mut h);
            session.ambr.uplink.hash(&mut h);
            session.ambr.downlink.hash(&mut h);
        }
    }
    h.finish()
}

/// Carry out one decided action (#56).
pub fn apply_action(action: &ChangeAction) {
    match action {
        ChangeAction::InsertSubscriberData { imsi_bcd } => {
            if let Err(e) =
                s6a_path::hss_s6a_send_idr(imsi_bcd, 0, s6a_path::NEXTGCORE_DIAM_S6A_SUBDATA_ALL)
            {
                log::warn!("[{imsi_bcd}] change-driven IDR not delivered: {e}");
            }
        }
        ChangeAction::CancelLocation { imsi_bcd } => {
            // The subscriber's record is gone, so `lookup_serving_mme` cannot find
            // the MME any more — which is why the previous view's host is passed in
            // by the caller. Here the record may still exist (a soft delete), so
            // the lookup is attempted and its failure is reported rather than
            // guessed around.
            if let Err(e) = s6a_path::hss_s6a_send_clr(
                imsi_bcd,
                None,
                None,
                CancellationType::SubscriptionWithdrawal,
            ) {
                log::warn!("[{imsi_bcd}] change-driven CLR not delivered: {e}");
            }
        }
    }
}

/// Carry out one decided action, using the last known MME for a deleted
/// subscriber (#56).
///
/// A deleted subscriber has no record left to look its serving MME up from, so the
/// destination has to come from the watcher's previous view. Without this, every
/// SUBSCRIPTION_WITHDRAWAL would fail with "no serving MME recorded" — the
/// procedure would look implemented and never fire.
pub fn apply_action_with_previous(
    action: &ChangeAction,
    previous: &HashMap<String, SubscriberView>,
) {
    match action {
        ChangeAction::CancelLocation { imsi_bcd } => {
            let host = previous.get(imsi_bcd).and_then(|v| v.mme_host.clone());
            let Some(host) = host else {
                log::warn!(
                    "[{imsi_bcd}] deleted subscriber had no recorded serving MME; no Cancel \
                     Location sent"
                );
                return;
            };
            // Realm derived from the host, as in `hss_s6a_send_rsr_to_all`: an S6a
            // Diameter identity is <name>.<realm>.
            let realm = host.split_once('.').map(|(_, r)| r).unwrap_or(&host);
            if let Err(e) = s6a_path::hss_s6a_send_clr(
                imsi_bcd,
                Some(&host),
                Some(realm),
                CancellationType::SubscriptionWithdrawal,
            ) {
                log::warn!("[{imsi_bcd}] change-driven CLR not delivered: {e}");
            }
        }
        other => apply_action(other),
    }
}

/// Read the current view of every subscriber that has a serving MME.
///
/// **This is the untested half** (see the module docs): it needs a live MongoDB,
/// which no test harness in this tree provides.
pub fn read_current_view() -> Result<HashMap<String, SubscriberView>, String> {
    use nextgcore_dbi::mongodb::bson::doc;
    use nextgcore_dbi::{mongoc::get_subscriber_collection, nextgcore_dbi_subscription_data};

    let collection = get_subscriber_collection().map_err(|e| e.to_string())?;
    // Only subscribers with a serving MME: one with no MME has nobody to notify, so
    // fetching it would cost a query per poll for a change that can never be sent.
    let cursor = collection
        .find(doc! { "mme_host": { "$exists": true, "$ne": "" } }, None)
        .map_err(|e| e.to_string())?;

    let mut view = HashMap::new();
    for doc in cursor {
        let doc = match doc {
            Ok(d) => d,
            Err(e) => {
                log::warn!("subscriber watch: skipping unreadable document: {e}");
                continue;
            }
        };
        let Ok(imsi) = doc.get_str("imsi") else {
            continue;
        };
        let mme_host = doc.get_str("mme_host").ok().map(str::to_string);
        let supi = format!("imsi-{imsi}");
        let fingerprint = match nextgcore_dbi_subscription_data(&supi) {
            Ok(db) => fingerprint_subscription(&db),
            Err(e) => {
                log::warn!("subscriber watch: [{imsi}] subscription unreadable: {e}");
                continue;
            }
        };
        view.insert(
            imsi.to_string(),
            SubscriberView {
                mme_host,
                fingerprint,
            },
        );
    }
    Ok(view)
}

/// Run one poll: read the current view, diff it against `previous`, send what the
/// diff decided, and return the new view to carry forward.
///
/// On a read failure `previous` is returned **unchanged**, so a transient Mongo
/// outage does not look like "every subscriber was deleted" and fire a Cancel
/// Location storm. That is the one failure mode of a polling differ that is worse
/// than not polling at all.
pub fn poll_once(previous: HashMap<String, SubscriberView>) -> HashMap<String, SubscriberView> {
    let current = match read_current_view() {
        Ok(v) => v,
        Err(e) => {
            log::warn!("subscriber watch: read failed, keeping the previous view: {e}");
            return previous;
        }
    };
    let actions = diff_subscribers(&previous, &current);
    if !actions.is_empty() {
        log::info!("subscriber watch: {} change action(s)", actions.len());
    }
    for action in &actions {
        apply_action_with_previous(action, &previous);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(mme: Option<&str>, fp: u64) -> SubscriberView {
        SubscriberView {
            mme_host: mme.map(str::to_string),
            fingerprint: fp,
        }
    }

    fn map(entries: &[(&str, SubscriberView)]) -> HashMap<String, SubscriberView> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    /// The case §5.2.2.1.1 exists for: the operator edited a subscription and the
    /// subscriber is attached.
    #[test]
    fn a_changed_subscription_for_an_attached_subscriber_drives_an_idr() {
        let prev = map(&[("001010000000001", view(Some("mme1.example.org"), 111))]);
        let curr = map(&[("001010000000001", view(Some("mme1.example.org"), 222))]);
        assert_eq!(
            diff_subscribers(&prev, &curr),
            vec![ChangeAction::InsertSubscriberData {
                imsi_bcd: "001010000000001".to_string()
            }]
        );
    }

    /// The case §5.2.1.2.1 exists for.
    #[test]
    fn a_deleted_subscriber_drives_a_cancel_location() {
        let prev = map(&[("001010000000002", view(Some("mme1.example.org"), 111))]);
        let curr = map(&[]);
        assert_eq!(
            diff_subscribers(&prev, &curr),
            vec![ChangeAction::CancelLocation {
                imsi_bcd: "001010000000002".to_string()
            }]
        );
    }

    /// An unchanged subscription must send NOTHING. Without this the watcher would
    /// emit an IDR to every attached subscriber on every poll — 10 per second at
    /// the current interval.
    #[test]
    fn an_unchanged_subscription_sends_nothing() {
        let prev = map(&[("001010000000003", view(Some("mme1.example.org"), 111))]);
        let curr = prev.clone();
        assert!(diff_subscribers(&prev, &curr).is_empty());
    }

    /// A newly attached subscriber was just given its data in the ULA. An IDR here
    /// would duplicate it.
    #[test]
    fn a_newly_attached_subscriber_sends_nothing() {
        let prev = map(&[]);
        let curr = map(&[("001010000000004", view(Some("mme1.example.org"), 111))]);
        assert!(diff_subscribers(&prev, &curr).is_empty());
    }

    /// An inter-MME move is `handle_ulr`'s Cancel Location to send, not the
    /// watcher's. Acting here too would cancel the same UE twice — and the second
    /// one would go to the NEW MME once the watcher's next poll caught up, detaching
    /// a UE that had just attached.
    #[test]
    fn an_inter_mme_move_is_left_to_the_ulr_handler() {
        let prev = map(&[("001010000000005", view(Some("mme1.example.org"), 111))]);
        let curr = map(&[("001010000000005", view(Some("mme2.example.org"), 111))]);
        assert!(diff_subscribers(&prev, &curr).is_empty());
        // Even when the data ALSO changed: the ULA the new MME just received
        // carries the current subscription, so there is nothing to push.
        let curr = map(&[("001010000000005", view(Some("mme2.example.org"), 999))]);
        assert!(diff_subscribers(&prev, &curr).is_empty());
    }

    /// A change to a subscriber nobody is serving has no destination.
    #[test]
    fn a_change_with_no_serving_mme_sends_nothing() {
        let prev = map(&[("001010000000006", view(None, 111))]);
        let curr = map(&[("001010000000006", view(None, 222))]);
        assert!(diff_subscribers(&prev, &curr).is_empty());
    }

    /// A deleted subscriber nobody was serving needs no Cancel Location.
    #[test]
    fn a_deleted_unattached_subscriber_sends_nothing() {
        let prev = map(&[("001010000000007", view(None, 111))]);
        let curr = map(&[]);
        assert!(diff_subscribers(&prev, &curr).is_empty());
    }

    /// Actions are IMSI-ordered, so a poll does not behave differently run to run.
    #[test]
    fn actions_are_deterministically_ordered() {
        let prev = map(&[
            ("001010000000020", view(Some("mme1"), 1)),
            ("001010000000010", view(Some("mme1"), 1)),
            ("001010000000030", view(Some("mme1"), 1)),
        ]);
        let curr = map(&[
            ("001010000000020", view(Some("mme1"), 2)),
            ("001010000000010", view(Some("mme1"), 2)),
            ("001010000000030", view(Some("mme1"), 2)),
        ]);
        let actions = diff_subscribers(&prev, &curr);
        let imsis: Vec<&str> = actions
            .iter()
            .map(|a| match a {
                ChangeAction::InsertSubscriberData { imsi_bcd }
                | ChangeAction::CancelLocation { imsi_bcd } => imsi_bcd.as_str(),
            })
            .collect();
        assert_eq!(
            imsis,
            vec!["001010000000010", "001010000000020", "001010000000030"]
        );
    }
}
