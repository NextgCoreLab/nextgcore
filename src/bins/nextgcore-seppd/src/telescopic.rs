//! `Nsepp_Telescopic_FQDN_Mapping` (TS 29.573 §5.4 / §6.3,
//! `TS29573_SeppTelescopicFqdnMapping.yaml`).
//!
//! The service an NF in **this** PLMN calls on its local SEPP when TLS between the
//! NF and the SEPP relies on a telescopic FQDN (TS 23.003 §28.5.2, TS 29.500
//! §6.1.4.3). It is the fallback path when `3gpp-Sbi-Target-apiRoot` forwarding is
//! not supported by a peer, and it did not exist here at all — there was no
//! `nsepp-telescopic/v1` route and no handler.
//!
//! Two procedures, one resource (`GET /mapping`), distinguished by which query
//! parameter is present:
//!
//! * **§5.4.2, `foreign-fqdn`** — an NF (typically the NRF or NSSF) needs to reach
//!   a NF in a foreign PLMN and must build a *flattened* telescopic FQDN for it.
//!   The SEPP answers with the single label to use plus its own domain, so the
//!   consumer forms `<telescopicLabel>.<seppDomain>`.
//! * **§5.4.3, `telescopic-label`** — a SEPP that received a request bearing a
//!   telescopic label it does not recognise asks a sibling SEPP whether *it* has a
//!   mapping. The clause's own wording — "determine if there is an **existing
//!   mapping**" — is why this side is a store lookup and can legitimately 404.
//!
//! # Why the label is a hash
//!
//! TS 23.003 §28.5.2 requires the foreign FQDN to be replaced by **one** label
//! (RFC 2818 wildcard certificates cover a single subdomain level only) and NOTE 1
//! says explicitly that *"how a SEPP constructs the label to replace the other PLMN
//! FQDN is implementation specific"*.
//!
//! This SEPP uses `tl` + the first 16 octets of `SHA-256(foreign FQDN)` in hex:
//!
//! * **One label, always valid.** 34 characters of `[a-z0-9]` starting with a
//!   letter, so it is inside the 63-octet DNS label limit and is a legal hostname
//!   label for *any* input FQDN — including ones already containing hyphens, which
//!   a dots-to-hyphens transliteration could not encode unambiguously.
//! * **Deterministic.** The same foreign FQDN always yields the same label, so
//!   repeated §5.4.2 requests are idempotent and a consumer can cache.
//! * **Not invertible without the store**, which is what §5.4.3 already assumes.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use sha2::{Digest, Sha256};

/// `TelescopicMapping` (`TS29573_SeppTelescopicFqdnMapping.yaml:76-86`). The schema
/// declares no `required` list, so every member is optional; which ones are
/// populated depends on the procedure (§5.4.2 vs §5.4.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelescopicMapping {
    /// The first label of the telescopic FQDN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telescopic_label: Option<String>,
    /// The local SEPP's domain, to be appended after the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sepp_domain: Option<String>,
    /// The FQDN of the NF in the foreign PLMN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_fqdn: Option<String>,
}

/// Cap on stored label→FQDN mappings.
///
/// The store only exists to answer §5.4.3, and every entry is a permanent
/// derivation from a foreign FQDN some consumer asked about, so nothing ever
/// expires it. Unbounded, that is a memory leak driven by remote input. At the cap
/// new mappings are **not** stored and a warning is logged: §5.4.2 still returns a
/// usable telescopic FQDN (the label is a pure function of the input), and the only
/// loss is that a sibling SEPP's §5.4.3 lookup for that label answers 404 — which
/// is a response the procedure already defines.
pub const MAX_TELESCOPIC_MAPPINGS: usize = 8192;

/// Prefix on every generated label. A DNS label must not start with a digit for
/// some resolvers and must not start with a hyphen at all, so the hex digest is
/// prefixed rather than used bare.
const LABEL_PREFIX: &str = "tl";

static MAPPINGS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn store() -> &'static RwLock<HashMap<String, String>> {
    MAPPINGS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// The single label that stands for `foreign_fqdn` in a telescopic FQDN.
///
/// Case-insensitive: DNS names are, so `NRF.Example.Com` and `nrf.example.com` are
/// the same NF and must not get two different labels (a consumer that normalised
/// its input differently would otherwise fail a sibling SEPP's reverse lookup).
/// A trailing root dot is stripped for the same reason.
pub fn label_for(foreign_fqdn: &str) -> String {
    let normalised = normalise_fqdn(foreign_fqdn);
    let digest = Sha256::digest(normalised.as_bytes());
    let mut label = String::with_capacity(LABEL_PREFIX.len() + 32);
    label.push_str(LABEL_PREFIX);
    for byte in &digest[..16] {
        use std::fmt::Write;
        let _ = write!(label, "{byte:02x}");
    }
    label
}

/// Lower-case and drop a trailing root dot. See [`label_for`].
fn normalise_fqdn(fqdn: &str) -> String {
    fqdn.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// §5.4.2: derive the telescopic label for `foreign_fqdn` and remember it so a
/// §5.4.3 lookup can reverse it. `sepp_domain` is the local SEPP's own FQDN.
///
/// Returns the mapping to answer with. Storing is best-effort — see
/// [`MAX_TELESCOPIC_MAPPINGS`].
pub fn map_foreign_fqdn(foreign_fqdn: &str, sepp_domain: &str) -> TelescopicMapping {
    let normalised = normalise_fqdn(foreign_fqdn);
    let label = label_for(&normalised);
    if let Ok(mut map) = store().write() {
        match map.get(&label) {
            // Already known: nothing to do, and re-inserting must not count
            // against the cap.
            Some(existing) if *existing == normalised => {}
            Some(existing) => {
                // 128 bits of digest; reaching here means either a genuine
                // collision or a bug. Either way the stored mapping is the one a
                // sibling SEPP may already have handed out, so it is NOT replaced.
                log::error!(
                    "telescopic label collision on [{label}]: kept [{existing}], refused \
                     [{normalised}]"
                );
            }
            None if map.len() >= MAX_TELESCOPIC_MAPPINGS => {
                log::warn!(
                    "telescopic mapping store full ({MAX_TELESCOPIC_MAPPINGS}); not storing \
                     [{label}] -> [{normalised}], so a reverse lookup for it will 404"
                );
            }
            None => {
                map.insert(label.clone(), normalised.clone());
            }
        }
    }
    TelescopicMapping {
        telescopic_label: Some(label),
        sepp_domain: Some(sepp_domain.to_string()),
        foreign_fqdn: Some(normalised),
    }
}

/// §5.4.3: the foreign FQDN a previously-issued `label` stands for, if this SEPP
/// issued it. `None` is the procedure's own "no existing mapping" answer.
pub fn resolve_label(label: &str) -> Option<String> {
    store()
        .read()
        .ok()?
        .get(&label.trim().to_ascii_lowercase())
        .cloned()
}

/// Number of stored mappings (diagnostics and tests).
pub fn mapping_count() -> usize {
    store().read().map(|m| m.len()).unwrap_or(0)
}

/// Drop every stored mapping. Test support; also the honest thing to call if the
/// local SEPP domain ever changes, since every issued telescopic FQDN was formed
/// against the old one.
pub fn clear_mappings() {
    if let Ok(mut map) = store().write() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that touch the process-global mapping store.
    static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The label is one legal DNS label, whatever the input FQDN looks like — the
    /// whole point of "flattening" per TS 23.003 §28.5.2.
    #[test]
    fn the_label_is_always_a_single_legal_dns_label() {
        for fqdn in [
            "nrf.5gc.mnc001.mcc001.3gppnetwork.org",
            "a",
            "nf-with-hyphens.and.many.dots.example.com",
            &"x".repeat(200),
        ] {
            let label = label_for(fqdn);
            assert!(
                !label.contains('.'),
                "a telescopic label must be a SINGLE label; got {label}"
            );
            assert!(
                label.len() <= 63,
                "a DNS label is at most 63 octets; got {} for {fqdn}",
                label.len()
            );
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "label must be a legal hostname label; got {label}"
            );
            assert!(
                label.starts_with(|c: char| c.is_ascii_alphabetic()),
                "label must start with a letter; got {label}"
            );
        }
    }

    /// Deterministic, and case/trailing-dot insensitive: the same NF must never get
    /// two labels, or a sibling SEPP's reverse lookup fails for a mapping this SEPP
    /// really did issue.
    #[test]
    fn the_label_is_deterministic_and_fqdn_case_insensitive() {
        let a = label_for("nrf.example.com");
        assert_eq!(a, label_for("nrf.example.com"));
        assert_eq!(a, label_for("NRF.Example.COM"));
        assert_eq!(a, label_for("nrf.example.com."));
        assert_eq!(a, label_for("  nrf.example.com  "));
        assert_ne!(a, label_for("nssf.example.com"));
    }

    /// §5.4.2 then §5.4.3: the label handed out is the label that reverses.
    #[test]
    fn a_mapped_fqdn_reverses_through_its_label() {
        let _g = lock();
        clear_mappings();
        let mapping = map_foreign_fqdn("NRF.Foreign.Example.Com", "sepp.local.example.com");
        let label = mapping.telescopic_label.clone().expect("label");
        assert_eq!(
            mapping.sepp_domain.as_deref(),
            Some("sepp.local.example.com")
        );
        assert_eq!(
            mapping.foreign_fqdn.as_deref(),
            Some("nrf.foreign.example.com")
        );
        assert_eq!(
            resolve_label(&label).as_deref(),
            Some("nrf.foreign.example.com")
        );
        // An unissued label has no mapping — §5.4.3's own 404 case.
        assert_eq!(resolve_label("tldeadbeefdeadbeefdeadbeefdeadbeef"), None);

        // Idempotent: mapping the same FQDN again neither changes the label nor
        // grows the store.
        let before = mapping_count();
        let again = map_foreign_fqdn("nrf.foreign.example.com", "sepp.local.example.com");
        assert_eq!(again.telescopic_label, mapping.telescopic_label);
        assert_eq!(mapping_count(), before);
        clear_mappings();
    }
}
