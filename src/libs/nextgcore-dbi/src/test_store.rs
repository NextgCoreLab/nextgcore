//! In-memory subscriber store for hermetic unit tests (WSB-6).
//!
//! Test-only backend (`cfg(any(test, feature = "test-helpers"))`) that lets NF
//! crates exercise their **real** Nudr handlers without a MongoDB instance.
//! When [`enable`]d, the `subscription` module's authentication-data
//! functions (`nextgcore_dbi_auth_info`, `nextgcore_dbi_update_sqn`,
//! `nextgcore_dbi_increment_sqn`, `nextgcore_dbi_provision_auth_info`)
//! operate on this store instead of the global MongoDB singleton.
//!
//! The store is a **faithful mirror** of the MongoDB semantics — in
//! particular [`inc_sqn`] reproduces `nextgcore_dbi_increment_sqn`'s
//! `+32` (one IND-aware SEQ step, indLength = 5) followed by the 48-bit
//! mask.  This faithfulness is what makes the WSB-6 PATCH-exactness test
//! falsifiable: reintroducing a UDR-side `increment_sqn` side effect makes
//! the stored SQN visibly drift by +32 and the test fail.
//!
//! Never compiled into production builds: the `test-helpers` feature is only
//! enabled from `[dev-dependencies]` of NF crates.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::mongoc::{DbiError, DbiResult};
use crate::subscription::{NextgcoreDbiAuthInfo, NextgcoreDbiAuthProvision};
use crate::types::{nextgcore_ascii_to_hex, NEXTGCORE_MAX_SQN};

/// `None` = store disabled (production Mongo path is used).
static STORE: Mutex<Option<HashMap<String, NextgcoreDbiAuthInfo>>> = Mutex::new(None);

/// Enable the in-memory store. Idempotent: an already-enabled store keeps its
/// contents so parallel tests (using distinct SUPIs) do not clobber each other.
pub fn enable() {
    let mut guard = STORE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// Disable the store (subsequent calls hit the real MongoDB path again).
pub fn disable() {
    *STORE.lock().unwrap() = None;
}

/// Whether the store is currently enabled.
pub fn active() -> bool {
    STORE.lock().unwrap().is_some()
}

/// Exact stored SQN for a subscriber — no IND-zeroing, no masking beyond what
/// the write operations themselves applied. `None` when the store is disabled
/// or the subscriber does not exist.
pub fn stored_sqn(supi: &str) -> Option<u64> {
    STORE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(supi))
        .map(|a| a.sqn)
}

/// Mirror of `nextgcore_dbi_auth_info` against the in-memory store.
pub(crate) fn auth_info(supi: &str) -> DbiResult<NextgcoreDbiAuthInfo> {
    STORE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(supi).cloned())
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))
}

/// Mirror of `nextgcore_dbi_update_sqn`: store exactly the written value.
pub(crate) fn update_sqn(supi: &str, sqn: u64) -> DbiResult<()> {
    let mut guard = STORE.lock().unwrap();
    let map = guard.as_mut().expect("test store enabled");
    let entry = map
        .get_mut(supi)
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;
    entry.sqn = sqn;
    Ok(())
}

/// Mirror of `nextgcore_dbi_increment_sqn`: `+32` (one IND-aware SEQ step)
/// then 48-bit mask — byte-for-byte the MongoDB `$inc` + `$bit` behavior.
pub(crate) fn inc_sqn(supi: &str) -> DbiResult<()> {
    let mut guard = STORE.lock().unwrap();
    let map = guard.as_mut().expect("test store enabled");
    let entry = map
        .get_mut(supi)
        .ok_or_else(|| DbiError::SubscriberNotFound(supi.to_string()))?;
    entry.sqn = (entry.sqn.wrapping_add(32)) & NEXTGCORE_MAX_SQN;
    Ok(())
}

/// Mirror of `nextgcore_dbi_provision_auth_info`: upsert the security
/// sub-document. Returns `Ok(true)` when the subscriber was created.
pub(crate) fn provision_auth_info(supi: &str, p: &NextgcoreDbiAuthProvision) -> DbiResult<bool> {
    let mut guard = STORE.lock().unwrap();
    let map = guard.as_mut().expect("test store enabled");
    let created = !map.contains_key(supi);
    let entry = map.entry(supi.to_string()).or_default();
    nextgcore_ascii_to_hex(&p.k_hex, &mut entry.k);
    nextgcore_ascii_to_hex(&p.amf_hex, &mut entry.amf);
    if let Some(opc) = &p.opc_hex {
        entry.use_opc = true;
        nextgcore_ascii_to_hex(opc, &mut entry.opc);
    }
    if let Some(op) = &p.op_hex {
        nextgcore_ascii_to_hex(op, &mut entry.op);
    }
    entry.sqn = p.sqn;
    entry.authentication_method = p.auth_method.clone();
    Ok(created)
}

#[cfg(test)]
mod tests {
    //! Faithfulness tests (WSB-6): the mirror must reproduce the MongoDB
    //! semantics exactly — in particular the `+32` (one SEQ step) increment
    //! plus 48-bit mask — otherwise the udrd PATCH-exactness tests lose
    //! their falsifiability.
    //!
    //! Exercised through the PUBLIC `subscription` functions so the
    //! store-diversion hooks themselves are covered.

    use crate::subscription::{
        nextgcore_dbi_auth_info, nextgcore_dbi_increment_sqn, nextgcore_dbi_provision_auth_info,
        nextgcore_dbi_update_sqn, NextgcoreDbiAuthProvision,
    };
    use crate::types::NEXTGCORE_MAX_SQN;

    fn provision(supi: &str, sqn: u64) {
        super::enable();
        let created = nextgcore_dbi_provision_auth_info(
            supi,
            &NextgcoreDbiAuthProvision {
                k_hex: "465b5ce8b199b49faa5f0a2ee238a6bc".into(),
                opc_hex: Some("e8ed289deba952e4283b54e88e6183ca".into()),
                op_hex: None,
                amf_hex: "8000".into(),
                sqn,
                auth_method: "5G_AKA".into(),
            },
        )
        .expect("provision");
        assert!(created, "first provision must create");
    }

    #[test]
    fn update_sqn_stores_exact_value_and_increment_mirrors_plus_32() {
        let supi = "imsi-999990000000701";
        provision(supi, 0x20);
        assert_eq!(super::stored_sqn(supi), Some(0x20));

        // update_sqn: exactly the written value, no side effects.
        nextgcore_dbi_update_sqn(supi, 0xA0C5).expect("update");
        assert_eq!(super::stored_sqn(supi), Some(0xA0C5));
        assert_eq!(
            nextgcore_dbi_auth_info(supi).expect("auth_info").sqn,
            0xA0C5
        );

        // increment_sqn: +32 (one IND-aware SEQ step), mirroring Mongo's
        // `$inc: 32` + `$bit and MAX_SQN`.
        nextgcore_dbi_increment_sqn(supi).expect("increment");
        assert_eq!(super::stored_sqn(supi), Some(0xA0C5 + 32));
    }

    #[test]
    fn increment_sqn_wraps_at_48_bits_like_mongo() {
        let supi = "imsi-999990000000702";
        provision(supi, NEXTGCORE_MAX_SQN); // 0xFFFF_FFFF_FFFF
        nextgcore_dbi_increment_sqn(supi).expect("increment");
        // (MAX + 32) & MAX == 31: identical to `$inc` then `$bit and`.
        assert_eq!(super::stored_sqn(supi), Some(31));
    }

    #[test]
    fn second_provision_updates_instead_of_creating() {
        let supi = "imsi-999990000000703";
        provision(supi, 0x20);
        let created = nextgcore_dbi_provision_auth_info(
            supi,
            &NextgcoreDbiAuthProvision {
                k_hex: "465b5ce8b199b49faa5f0a2ee238a6bc".into(),
                opc_hex: None,
                op_hex: None,
                amf_hex: "8000".into(),
                sqn: 0x40,
                auth_method: "5G_AKA".into(),
            },
        )
        .expect("re-provision");
        assert!(!created, "existing subscriber must be updated, not created");
        assert_eq!(super::stored_sqn(supi), Some(0x40));
    }
}
