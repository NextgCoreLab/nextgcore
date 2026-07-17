//! EASDF Context Management
//!
//! Edge Application Server Discovery Function context (TS 23.548 §6.2):
//! the per-PDU-session DNS contexts managed via `Neasdf_DNSContext`
//! (TS 29.556), and the static FQDN → EAS-address map that answers edge
//! DNS resolution in Phase 1 (issue #21).
//!
//! All state is in-memory (`RwLock<HashMap<..>>`), matching the other small
//! NFs (pind, nefd); the EAS map and miss behavior are set once at startup
//! from the YAML config.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// One static FQDN → EAS mapping entry. An `fqdn` starting with `*.`
/// matches any subdomain of the remainder (e.g. `*.edge.example.com`
/// matches `app.edge.example.com` but not `edge.example.com` itself);
/// otherwise the match is exact. Matching is case-insensitive and ignores a
/// trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EasMapEntry {
    pub fqdn: String,
    pub addresses: Vec<String>,
}

/// What the EASDF does with a DNS query whose FQDN is not in the EAS map
/// (the "defined miss/forward behavior" of issue #21).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnsMissBehavior {
    /// Report the configured upstream DNS server the querier should forward
    /// to (TS 23.548 §6.2.3.2.2 baseline DNS-forwarding role).
    Forward(String),
    /// Report a miss (NXDOMAIN-equivalent at the SBI level).
    #[default]
    NxDomain,
}

/// Outcome of an FQDN resolution against the EAS map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// FQDN is edge-served: the configured EAS addresses.
    Resolved(Vec<String>),
    /// Not edge-served: forward to this upstream DNS server.
    Forward(String),
    /// Not edge-served and no upstream configured.
    Miss,
}

/// A stored `Neasdf_DNSContext` (TS 29.556 §5.2): the per-PDU-session DNS
/// handling context an SMF creates toward the EASDF.
#[derive(Debug, Clone)]
pub struct EasdfDnsContext {
    /// EASDF-assigned DNS-context ID (the northbound resource ID).
    pub id: String,
    /// UE identity (SUPI) the context belongs to.
    pub supi: String,
    /// PDU session the context belongs to.
    pub pdu_session_id: u64,
    /// Raw DnsContext JSON as received (DNS message-handling rules are
    /// stored, not yet enforced — Phase 1 keeps rule evaluation out of
    /// scope alongside UL-CL insertion).
    pub raw: String,
}

impl EasdfDnsContext {
    pub fn new(supi: impl Into<String>, pdu_session_id: u64, raw: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            supi: supi.into(),
            pdu_session_id,
            raw: raw.into(),
        }
    }
}

/// EASDF context errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasdfContextError {
    MaxDnsContextsReached,
    LockPoisoned,
}

impl EasdfContextError {
    pub fn detail(&self) -> &'static str {
        match self {
            Self::MaxDnsContextsReached => "Maximum number of DNS contexts reached",
            Self::LockPoisoned => "EASDF context lock poisoned",
        }
    }

    pub fn cause(&self) -> &'static str {
        match self {
            Self::MaxDnsContextsReached => "MAX_DNS_CONTEXTS_REACHED",
            Self::LockPoisoned => "INTERNAL",
        }
    }
}

/// EASDF Context
pub struct EasdfContext {
    /// DNS contexts (by EASDF-assigned context ID).
    dns_contexts: RwLock<HashMap<String, EasdfDnsContext>>,
    /// Static FQDN → EAS map (set once at startup from YAML).
    eas_map: Vec<EasMapEntry>,
    /// Behavior for FQDNs not present in the EAS map.
    miss_behavior: DnsMissBehavior,
    /// Maximum stored DNS contexts.
    max_dns_contexts: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl EasdfContext {
    pub fn new() -> Self {
        Self {
            dns_contexts: RwLock::new(HashMap::new()),
            eas_map: Vec::new(),
            miss_behavior: DnsMissBehavior::default(),
            max_dns_contexts: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_dns_contexts: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_dns_contexts = max_dns_contexts;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("EASDF context initialized (max {max_dns_contexts} DNS contexts)");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut contexts) = self.dns_contexts.write() {
            contexts.clear();
        }
        self.eas_map.clear();
        self.miss_behavior = DnsMissBehavior::default();
        self.initialized.store(false, Ordering::SeqCst);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Install the static EAS map and miss behavior (once, from `main()`).
    pub fn set_dns_config(&mut self, eas_map: Vec<EasMapEntry>, miss_behavior: DnsMissBehavior) {
        self.eas_map = eas_map;
        self.miss_behavior = miss_behavior;
    }

    pub fn eas_map_len(&self) -> usize {
        self.eas_map.len()
    }

    /// Resolve an FQDN against the static EAS map (TS 23.548 edge DNS
    /// handling, Phase-1 static-map variant).
    pub fn resolve_fqdn(&self, fqdn: &str) -> ResolveOutcome {
        let query = fqdn.trim_end_matches('.').to_ascii_lowercase();
        for entry in &self.eas_map {
            let key = entry.fqdn.trim_end_matches('.').to_ascii_lowercase();
            let matched = if let Some(suffix) = key.strip_prefix("*.") {
                // Wildcard: any subdomain of `suffix`, not `suffix` itself.
                query.len() > suffix.len() + 1 && query.ends_with(&format!(".{suffix}"))
            } else {
                query == key
            };
            if matched {
                return ResolveOutcome::Resolved(entry.addresses.clone());
            }
        }
        match &self.miss_behavior {
            DnsMissBehavior::Forward(upstream) => ResolveOutcome::Forward(upstream.clone()),
            DnsMissBehavior::NxDomain => ResolveOutcome::Miss,
        }
    }

    /// Insert a DNS context, enforcing the capacity cap.
    pub fn dns_context_insert(&self, ctx: EasdfDnsContext) -> Result<(), EasdfContextError> {
        let mut contexts = self
            .dns_contexts
            .write()
            .map_err(|_| EasdfContextError::LockPoisoned)?;
        if contexts.len() >= self.max_dns_contexts {
            return Err(EasdfContextError::MaxDnsContextsReached);
        }
        let id = ctx.id.clone();
        contexts.insert(id.clone(), ctx);
        log::debug!("EASDF DNS context inserted (id={id})");
        Ok(())
    }

    /// Find a DNS context by ID.
    pub fn dns_context_find(&self, id: &str) -> Option<EasdfDnsContext> {
        let contexts = self.dns_contexts.read().ok()?;
        contexts.get(id).cloned()
    }

    /// Replace an existing DNS context (Neasdf_DNSContext Update). Returns
    /// false when the ID is unknown; the stored ID is preserved.
    pub fn dns_context_replace(&self, id: &str, mut ctx: EasdfDnsContext) -> bool {
        let Ok(mut contexts) = self.dns_contexts.write() else {
            return false;
        };
        if !contexts.contains_key(id) {
            return false;
        }
        ctx.id = id.to_string();
        contexts.insert(id.to_string(), ctx);
        true
    }

    /// Remove a DNS context by ID.
    pub fn dns_context_remove(&self, id: &str) -> Option<EasdfDnsContext> {
        let mut contexts = self.dns_contexts.write().ok()?;
        contexts.remove(id)
    }

    /// Number of stored DNS contexts (NRF `/load` gauge source).
    pub fn dns_context_count(&self) -> usize {
        self.dns_contexts.read().map(|c| c.len()).unwrap_or(0)
    }
}

impl Default for EasdfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global EASDF context
static GLOBAL_EASDF_CONTEXT: std::sync::OnceLock<Arc<RwLock<EasdfContext>>> =
    std::sync::OnceLock::new();

pub fn easdf_self() -> Arc<RwLock<EasdfContext>> {
    GLOBAL_EASDF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(EasdfContext::new())))
        .clone()
}

pub fn easdf_context_init(max_dns_contexts: usize) {
    let ctx = easdf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_dns_contexts);
    };
}

pub fn easdf_context_final() {
    let ctx = easdf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Local `EasdfContext` instances — race-free without a global test lock.

    fn ctx_with_map(max: usize) -> EasdfContext {
        let mut context = EasdfContext::new();
        context.init(max);
        context.set_dns_config(
            vec![
                EasMapEntry {
                    fqdn: "app.edge.example.com".to_string(),
                    addresses: vec!["10.60.0.10".to_string(), "10.60.0.11".to_string()],
                },
                EasMapEntry {
                    fqdn: "*.media.example.com".to_string(),
                    addresses: vec!["10.61.0.5".to_string()],
                },
            ],
            DnsMissBehavior::NxDomain,
        );
        context
    }

    fn dns_ctx(supi: &str) -> EasdfDnsContext {
        EasdfDnsContext::new(supi, 5, "{}")
    }

    #[test]
    fn dns_context_insert_find_remove_roundtrip() {
        let context = ctx_with_map(16);
        let c = dns_ctx("imsi-001010000000001");
        let id = c.id.clone();

        context.dns_context_insert(c).expect("insert");
        assert_eq!(context.dns_context_count(), 1);

        let found = context.dns_context_find(&id).expect("find");
        assert_eq!(found.supi, "imsi-001010000000001");
        assert_eq!(found.pdu_session_id, 5);

        let removed = context.dns_context_remove(&id).expect("remove");
        assert_eq!(removed.id, id);
        assert_eq!(context.dns_context_count(), 0);
        assert!(context.dns_context_find(&id).is_none());
    }

    #[test]
    fn dns_context_replace_preserves_id_and_rejects_unknown() {
        let context = ctx_with_map(16);
        let original = dns_ctx("imsi-a");
        let id = original.id.clone();
        context.dns_context_insert(original).expect("insert");

        let replacement = EasdfDnsContext::new("imsi-b", 9, r#"{"v":2}"#);
        assert!(context.dns_context_replace(&id, replacement));
        let stored = context.dns_context_find(&id).expect("still there");
        assert_eq!(stored.id, id, "stored ID must be preserved on replace");
        assert_eq!(stored.supi, "imsi-b");
        assert_eq!(stored.pdu_session_id, 9);

        assert!(
            !context.dns_context_replace("absent", dns_ctx("imsi-c")),
            "replacing an unknown ID must fail"
        );
        assert_eq!(context.dns_context_count(), 1);
    }

    #[test]
    fn dns_context_cap_is_enforced() {
        let context = ctx_with_map(1);
        context.dns_context_insert(dns_ctx("imsi-a")).expect("fits");
        let err = context
            .dns_context_insert(dns_ctx("imsi-b"))
            .expect_err("cap");
        assert_eq!(err, EasdfContextError::MaxDnsContextsReached);
        assert_eq!(err.cause(), "MAX_DNS_CONTEXTS_REACHED");
    }

    #[test]
    fn resolve_exact_match_case_and_trailing_dot_insensitive() {
        let context = ctx_with_map(4);
        let expected =
            ResolveOutcome::Resolved(vec!["10.60.0.10".to_string(), "10.60.0.11".to_string()]);
        assert_eq!(context.resolve_fqdn("app.edge.example.com"), expected);
        assert_eq!(context.resolve_fqdn("APP.Edge.Example.COM."), expected);
    }

    #[test]
    fn resolve_wildcard_matches_subdomains_only() {
        let context = ctx_with_map(4);
        assert_eq!(
            context.resolve_fqdn("cdn1.media.example.com"),
            ResolveOutcome::Resolved(vec!["10.61.0.5".to_string()])
        );
        assert_eq!(
            context.resolve_fqdn("a.b.media.example.com"),
            ResolveOutcome::Resolved(vec!["10.61.0.5".to_string()])
        );
        // The wildcard base itself is NOT covered by `*.`.
        assert_eq!(
            context.resolve_fqdn("media.example.com"),
            ResolveOutcome::Miss
        );
    }

    #[test]
    fn resolve_miss_behaviors() {
        // Default NxDomain → Miss.
        let context = ctx_with_map(4);
        assert_eq!(
            context.resolve_fqdn("other.example.org"),
            ResolveOutcome::Miss
        );

        // Forward → the configured upstream.
        let mut fwd = EasdfContext::new();
        fwd.init(4);
        fwd.set_dns_config(
            Vec::new(),
            DnsMissBehavior::Forward("10.0.0.53:53".to_string()),
        );
        assert_eq!(
            fwd.resolve_fqdn("anything.example.org"),
            ResolveOutcome::Forward("10.0.0.53:53".to_string())
        );
    }

    #[test]
    fn init_guards_reinit_and_fini_clears() {
        let mut context = EasdfContext::new();
        assert!(!context.is_initialized());
        context.init(8);
        assert!(context.is_initialized());
        context.init(1); // guarded no-op
        context.dns_context_insert(dns_ctx("a")).expect("insert");
        context
            .dns_context_insert(dns_ctx("b"))
            .expect("cap kept from first init");

        context.fini();
        assert!(!context.is_initialized());
        assert_eq!(context.dns_context_count(), 0);
        assert_eq!(context.eas_map_len(), 0);
    }

    #[test]
    fn uninitialized_context_rejects_inserts() {
        let context = EasdfContext::new();
        let err = context.dns_context_insert(dns_ctx("a")).expect_err("cap 0");
        assert_eq!(err, EasdfContextError::MaxDnsContextsReached);
    }

    #[test]
    fn generated_ids_are_unique() {
        assert_ne!(dns_ctx("a").id, dns_ctx("a").id);
    }
}
