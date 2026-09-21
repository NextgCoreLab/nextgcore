//! This NF's own `nfInstanceId`, resolved once per process (issue #187).
//!
//! # Why this is shared rather than per-daemon
//!
//! An `nfInstanceId` is the name every other party knows this NF by. The NRF
//! registry is keyed by it, an access token's `sub` is it, and — the reason this
//! module exists — the CCA trust store the NRF verifies client authentication
//! against is keyed by it (TS 33.501 §13.3.8.3: the receiving node verifies the
//! NF instance ID in the CCA against the key used to sign it).
//!
//! Before this module each daemon minted its own `Uuid::new_v4()` inline, at up
//! to three separate sites per crate. Two consequences, both verified at
//! `6ba388d` and both fatal to an authenticated token endpoint:
//!
//! 1. **Nothing could pin the ID.** No NF read one from its environment, so a
//!    restart produced a new identity and no NRF-side trust store could be
//!    provisioned in advance — there was no stable key to provision it under.
//! 2. **One process had SEVERAL identities.** `amfd` built its OAuth2 client
//!    under one UUID, its self NF instance under a second and its NRF
//!    registration under a third. So the ID a CCA asserted was not the ID that
//!    was registered — and the token endpoint requires the requester to be
//!    registered — which made the authenticated path unreachable even with a
//!    pinned ID and a trusted key.
//!
//! Resolving here, once, fixes both **structurally**: every call site in a
//! process observes the same value because there is only one value. A new call
//! site cannot reintroduce the divergence, which a per-daemon refactor that
//! threaded an ID through `main` could.
//!
//! # Precedence
//!
//! 1. [`seed`] — an explicit programmatic pin, used by the daemons that already
//!    expose a `--nf-instance-id` CLI flag so that flag keeps working and keeps
//!    winning.
//! 2. [`ANY_NF_INSTANCE_ID_ENV`] (`NEXTGCORE_NF_INSTANCE_ID`) — pins whichever
//!    NF reads it. One value per container.
//! 3. `NEXTGCORE_<TYPE>_INSTANCE_ID`, e.g. `NEXTGCORE_AMF_INSTANCE_ID` — lets a
//!    single compose/Helm environment block pin every NF at once without a
//!    per-service command override.
//! 4. A generated UUIDv4, as before.
//!
//! The resolved value is a bare UUID, not the `"amf-<uuid>"` form some daemons
//! used: TS 29.571 types `NfInstanceId` as a UUID, and a prefixed string is not
//! one.

use crate::types::NfType;
use std::sync::OnceLock;

/// Pins this NF's instance ID regardless of type. Highest-precedence
/// environment source, so one container-wide value covers any daemon.
pub const ANY_NF_INSTANCE_ID_ENV: &str = "NEXTGCORE_NF_INSTANCE_ID";

/// The resolved ID. A `OnceLock` rather than a recomputation because the value
/// must not be able to differ between two call sites in one process — that
/// divergence is the defect this module closes.
static NF_INSTANCE_ID: OnceLock<String> = OnceLock::new();

/// Per-NF-type environment variable name, e.g. `NEXTGCORE_AMF_INSTANCE_ID`.
///
/// Derived from the TS 29.510 NF type string so a new `NfType` needs no edit
/// here. `5G_EIR` contains a character that cannot appear in a shell
/// identifier, so non-alphanumerics become `_`.
pub fn type_env_var(nf_type: NfType) -> String {
    let t: String = nf_type
        .to_str()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("NEXTGCORE_{t}_INSTANCE_ID")
}

/// Pin this NF's instance ID before anything reads it, overriding both
/// environment sources.
///
/// For the daemons that already accept `--nf-instance-id`: call this from
/// startup so the flag keeps its meaning. Returns whether the pin took effect —
/// `false` means the ID had already been resolved, which is a startup-ordering
/// bug worth logging rather than a value to silently discard.
///
/// An empty or whitespace-only `id` is ignored (returns `false`): a cleared
/// environment variable or an unset flag must fall through to the next source,
/// not register this NF under the empty string.
pub fn seed(id: &str) -> bool {
    let id = id.trim();
    if id.is_empty() {
        return false;
    }
    NF_INSTANCE_ID.set(id.to_string()).is_ok()
}

/// This NF's `nfInstanceId`, resolved on first call and stable thereafter.
///
/// See the module docs for the precedence. Call this instead of minting a UUID:
/// the `no_daemon_mints_its_own_nf_instance_id` guard in `security.rs` fails the
/// build for a `bins/` crate that does otherwise.
pub fn nf_instance_id(nf_type: NfType) -> &'static str {
    NF_INSTANCE_ID.get_or_init(|| {
        if let Some(id) = non_empty_env(ANY_NF_INSTANCE_ID_ENV) {
            log::info!(
                "nfInstanceId {id} pinned by {ANY_NF_INSTANCE_ID_ENV} (NF type {})",
                nf_type.to_str()
            );
            return id;
        }
        let per_type = type_env_var(nf_type);
        if let Some(id) = non_empty_env(&per_type) {
            log::info!("nfInstanceId {id} pinned by {per_type}");
            return id;
        }
        let id = uuid::Uuid::new_v4().to_string();
        // Worth an info!: an operator who meant to pin this and mistyped the
        // variable otherwise sees a working NF that no NRF trust store matches,
        // and the only symptom is `invalid_client` at the token endpoint.
        log::info!(
            "nfInstanceId {id} generated for NF type {} (set {ANY_NF_INSTANCE_ID_ENV} or \
             {per_type} to pin it; a CCA trust store keyed by nfInstanceId needs a pinned \
             value to be provisioned in advance)",
            nf_type.to_str()
        );
        id
    })
}

/// Whether the ID has been resolved yet. Lets a daemon log a startup-ordering
/// mistake instead of a bare `seed` failure.
pub fn is_resolved() -> bool {
    NF_INSTANCE_ID.get().is_some()
}

fn non_empty_env(key: &str) -> Option<String> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-type variable name is derived, so adding an `NfType` needs no
    /// edit here — and `5G_EIR` proves the non-alphanumeric mapping, since
    /// `NEXTGCORE_5G_EIR_INSTANCE_ID` would otherwise not be a shell name.
    #[test]
    fn per_type_env_var_names_are_derived_from_the_ts29510_nf_type() {
        assert_eq!(type_env_var(NfType::Amf), "NEXTGCORE_AMF_INSTANCE_ID");
        assert_eq!(type_env_var(NfType::Nrf), "NEXTGCORE_NRF_INSTANCE_ID");
        assert_eq!(type_env_var(NfType::Udm), "NEXTGCORE_UDM_INSTANCE_ID");
        assert_eq!(
            type_env_var(NfType::FiveGEir),
            "NEXTGCORE_5G_EIR_INSTANCE_ID"
        );
        assert!(type_env_var(NfType::Smf)
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    /// An empty pin must fall through rather than register this NF under "".
    /// A compose file with `NEXTGCORE_NF_INSTANCE_ID=` set but unfilled is the
    /// realistic way to hit this.
    #[test]
    fn an_empty_or_blank_seed_is_ignored() {
        assert!(!seed(""));
        assert!(!seed("   "));
    }

    /// The resolver is memoized, which is the property that dissolves the
    /// several-identities-per-process defect: two call sites cannot disagree.
    ///
    /// This test seeds the process-wide lock, so it is the ONLY test in this
    /// module permitted to resolve it — see the note on `seed` above. Other
    /// properties are tested through pure helpers or from
    /// `tests/nf_instance_id_resolution.rs`, which gets a fresh process per
    /// integration-test binary.
    #[test]
    fn a_seeded_id_is_returned_to_every_caller_and_never_changes() {
        // A distinct literal, not a UUID, so a failure names this test rather
        // than looking like a plausible generated value.
        assert!(
            seed("issue-187-memoization-probe"),
            "nothing else in this test binary may resolve the ID before this runs"
        );
        assert!(is_resolved());
        // Both the type this was seeded "for" and a different one observe it:
        // there is one identity per process, not one per NF type.
        assert_eq!(
            nf_instance_id(NfType::Amf),
            "issue-187-memoization-probe",
            "the seeded pin must win over generation"
        );
        assert_eq!(
            nf_instance_id(NfType::Udm),
            "issue-187-memoization-probe",
            "a second call site must observe the SAME id -- this is the property that \
             makes a CCA subject equal the registered nfInstanceId"
        );
        // A later seed cannot move the identity out from under a party that has
        // already registered or verified against it.
        assert!(!seed("issue-187-second-pin-must-lose"));
        assert_eq!(nf_instance_id(NfType::Amf), "issue-187-memoization-probe");
    }
}
