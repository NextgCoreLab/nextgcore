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

/// One parsed DNS message-handling rule (#114).
///
/// # Schema caveat, stated plainly
///
/// TS 29.556 is **not vendored** in this repo, so — unlike every other wire type
/// in this tree — these member names cannot be checked against an OpenAPI file.
/// They follow TS 23.548 §6.2.3.2.2's description of a DNS message-handling rule
/// and accept several spellings for the same thing (see
/// [`DnsHandlingRule::from_json`]). Anything not recognised is preserved in the
/// context's [`EasdfDnsContext::raw`], so nothing an SMF sends is lost, and a
/// later vendoring of TS 29.556 can tighten this without losing data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsHandlingRule {
    /// FQDN patterns this rule applies to. `*.` prefix is a subdomain wildcard,
    /// matching [`EasdfContext::resolve_fqdn`]'s existing EAS-map semantics so a
    /// rule and a static entry mean the same thing by the same syntax.
    pub domain_patterns: Vec<String>,
    /// EAS addresses to answer a matching query with. Empty means the rule does
    /// not itself answer (it may still ask for a report, or a forward).
    pub eas_addresses: Vec<String>,
    /// Report a matching DNS message to the SMF (TS 23.548 §6.2.3.2.2 DNS
    /// message reporting).
    pub report: bool,
    /// Forward a matching query to this upstream DNS server instead of
    /// answering it.
    pub forward_to: Option<String>,
}

impl DnsHandlingRule {
    /// Parse one rule from its JSON object.
    ///
    /// Several key spellings are accepted for each member because the normative
    /// names cannot be verified here: `domainNames` / `dnsQueryMdt` / `fqdnList` /
    /// `fqdn` for the patterns, `easIpAddresses` / `easAddresses` / `easIpv4Addrs`
    /// for the addresses. Accepting a superset is the safer error: rejecting a
    /// conformant spelling would silently drop the rule and leave the context
    /// inert, which is the defect being fixed.
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        let obj = value.as_object()?;
        let strings = |keys: &[&str]| -> Vec<String> {
            for key in keys {
                match obj.get(*key) {
                    Some(serde_json::Value::Array(items)) => {
                        let out: Vec<String> = items
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect();
                        if !out.is_empty() {
                            return out;
                        }
                    }
                    Some(serde_json::Value::String(s)) if !s.is_empty() => return vec![s.clone()],
                    _ => {}
                }
            }
            Vec::new()
        };
        let domain_patterns = strings(&["domainNames", "dnsQueryMdt", "fqdnList", "fqdn"]);
        let eas_addresses = strings(&["easIpAddresses", "easAddresses", "easIpv4Addrs"]);
        let report = ["reportInd", "dnsMessageReportInd", "report"]
            .iter()
            .find_map(|k| obj.get(*k).and_then(|v| v.as_bool()))
            .unwrap_or(false);
        let forward_to = ["forwardTo", "dnsServerAddress", "upstreamDns"]
            .iter()
            .find_map(|k| obj.get(*k).and_then(|v| v.as_str()))
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // A rule that names no domain cannot be matched against a query, and a
        // rule that neither answers, forwards nor reports has no effect. Either
        // way it is dropped with a warn rather than stored as a rule that looks
        // active and is not.
        if domain_patterns.is_empty() {
            log::warn!("DNS handling rule names no domain pattern; ignoring it: {value}");
            return None;
        }
        if eas_addresses.is_empty() && forward_to.is_none() && !report {
            log::warn!("DNS handling rule has no action (no EAS address, no forward, no report); ignoring it: {value}");
            return None;
        }
        Some(Self {
            domain_patterns,
            eas_addresses,
            report,
            forward_to,
        })
    }

    /// Does this rule apply to `query` (already lowercased and dot-trimmed)?
    pub fn matches(&self, query: &str) -> bool {
        self.domain_patterns
            .iter()
            .any(|pattern| fqdn_pattern_matches(pattern, query))
    }
}

/// Shared FQDN pattern match, used by both the EAS map and the handling rules so
/// `*.edge.example.com` cannot mean two different things in the two places.
///
/// A `*.` prefix matches any **subdomain** of the remainder, not the remainder
/// itself; otherwise the match is exact. Case-insensitive, trailing dot ignored.
pub fn fqdn_pattern_matches(pattern: &str, query: &str) -> bool {
    let key = pattern.trim_end_matches('.').to_ascii_lowercase();
    let query = query.trim_end_matches('.').to_ascii_lowercase();
    match key.strip_prefix("*.") {
        Some(suffix) => query.len() > suffix.len() + 1 && query.ends_with(&format!(".{suffix}")),
        None => query == key,
    }
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
    /// Raw DnsContext JSON as received. Still kept after #114 added typed rule
    /// parsing: the parse recognises a documented subset, and the raw body is
    /// what makes the unrecognised remainder recoverable rather than lost.
    pub raw: String,
    /// DNS message-handling rules, PARSED (#114).
    ///
    /// Previously the rules existed only inside `raw` and were never consulted,
    /// so a per-session context had no effect on what the EASDF answered — the
    /// EASDF's entire reason for existing.
    pub handling_rules: Vec<DnsHandlingRule>,
    /// Where to send a DNS-message report for this context (#114). Taken from
    /// the SMF's callback member in the create body; without it a rule asking for
    /// a report has nowhere to send one.
    pub notify_uri: Option<String>,
}

impl EasdfDnsContext {
    pub fn new(supi: impl Into<String>, pdu_session_id: u64, raw: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            supi: supi.into(),
            pdu_session_id,
            raw: raw.into(),
            handling_rules: Vec::new(),
            notify_uri: None,
        }
    }

    /// Parse the handling rules and the notify URI out of a create/update body
    /// (#114).
    ///
    /// As with the rule members, several spellings of each container key are
    /// accepted because TS 29.556 is not vendored here.
    pub fn with_parsed(mut self, body: &serde_json::Value) -> Self {
        let rules = [
            "dnsHandlingRules",
            "dnsMessageHandlingRules",
            "handlingRules",
        ]
        .iter()
        .find_map(|k| body.get(*k).and_then(|v| v.as_array()));
        if let Some(rules) = rules {
            self.handling_rules = rules
                .iter()
                .filter_map(DnsHandlingRule::from_json)
                .collect();
            log::info!(
                "DNS context {}: {} of {} handling rule(s) parsed",
                self.id,
                self.handling_rules.len(),
                rules.len()
            );
        }
        self.notify_uri = [
            "notificationUri",
            "notifyUri",
            "smfCallbackUri",
            "dnsMessageReportUri",
        ]
        .iter()
        .find_map(|k| body.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string);
        self
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
    /// Baseline DNS patterns (`Neasdf_BaselineDNSPattern`, #114), keyed by a
    /// server-minted pattern id. EASDF-wide rather than per-session: these are
    /// the fallback a query falls through to when no session context rule and no
    /// static EAS-map entry matched.
    baseline_patterns: RwLock<HashMap<String, DnsHandlingRule>>,
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
            baseline_patterns: RwLock::new(HashMap::new()),
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
        if let Ok(mut patterns) = self.baseline_patterns.write() {
            patterns.clear();
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
            if fqdn_pattern_matches(&entry.fqdn, &query) {
                return ResolveOutcome::Resolved(entry.addresses.clone());
            }
        }
        // #114: baseline DNS patterns are the last stop before the configured
        // miss behaviour.
        if let Some(outcome) = self.resolve_baseline(&query) {
            return outcome;
        }
        match &self.miss_behavior {
            DnsMissBehavior::Forward(upstream) => ResolveOutcome::Forward(upstream.clone()),
            DnsMissBehavior::NxDomain => ResolveOutcome::Miss,
        }
    }

    /// Resolve `fqdn` **in the scope of a DNS context** (#114): the context's
    /// own handling rules first, then the static EAS map, then the miss
    /// behaviour.
    ///
    /// This is the ordering TS 23.548 §6.2.3.2.2 implies: a rule the SMF
    /// installed for this session is more specific than the EASDF's static
    /// configuration, so it wins.
    ///
    /// Returns the outcome plus whether a matching rule asked for a DNS-message
    /// report, so the caller can emit one without re-evaluating the rules.
    ///
    /// Scoped deliberately: an unscoped query is answered from the static map
    /// only ([`Self::resolve_fqdn`]). Consulting *some other session's* rules for
    /// an unscoped query would leak one subscriber's edge steering into
    /// another's answer.
    pub fn resolve_in_context(&self, ctx_id: &str, fqdn: &str) -> (ResolveOutcome, bool) {
        let query = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let Some(ctx) = self.dns_context_find(ctx_id) else {
            // Unknown context: fall back to the static map rather than refusing,
            // so a stale context id degrades to the pre-#114 answer.
            return (self.resolve_fqdn(fqdn), false);
        };
        for rule in &ctx.handling_rules {
            if !rule.matches(&query) {
                continue;
            }
            let outcome = if !rule.eas_addresses.is_empty() {
                ResolveOutcome::Resolved(rule.eas_addresses.clone())
            } else if let Some(upstream) = &rule.forward_to {
                ResolveOutcome::Forward(upstream.clone())
            } else {
                // A report-only rule states no answer, so the static map decides
                // what the answer is while the rule still drives the report.
                self.resolve_fqdn(fqdn)
            };
            return (outcome, rule.report);
        }
        (self.resolve_fqdn(fqdn), false)
    }

    /// The notify URI recorded for a context, if any (#114).
    pub fn dns_context_notify_uri(&self, ctx_id: &str) -> Option<String> {
        self.dns_context_find(ctx_id).and_then(|c| c.notify_uri)
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

    // ---- #114: Neasdf_BaselineDNSPattern -------------------------------------

    /// Store a baseline DNS pattern; returns its minted id.
    ///
    /// Shares `max_dns_contexts` as its ceiling: both stores are remote-driven,
    /// and a second unbounded map on a network-facing NF is the resource-growth
    /// concern the first one already has a cap for.
    pub fn baseline_pattern_insert(
        &self,
        rule: DnsHandlingRule,
    ) -> Result<String, EasdfContextError> {
        let mut patterns = self
            .baseline_patterns
            .write()
            .map_err(|_| EasdfContextError::LockPoisoned)?;
        if patterns.len() >= self.max_dns_contexts {
            return Err(EasdfContextError::MaxDnsContextsReached);
        }
        let id = Uuid::new_v4().to_string();
        patterns.insert(id.clone(), rule);
        Ok(id)
    }

    pub fn baseline_pattern_find(&self, id: &str) -> Option<DnsHandlingRule> {
        self.baseline_patterns.read().ok()?.get(id).cloned()
    }

    pub fn baseline_pattern_ids(&self) -> Vec<String> {
        self.baseline_patterns
            .read()
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn baseline_pattern_remove(&self, id: &str) -> Option<DnsHandlingRule> {
        self.baseline_patterns.write().ok()?.remove(id)
    }

    pub fn baseline_pattern_count(&self) -> usize {
        self.baseline_patterns.read().map(|p| p.len()).unwrap_or(0)
    }

    /// Resolve against the baseline patterns — the last stop before the
    /// configured miss behaviour (#114).
    ///
    /// Consulted by [`Self::resolve_in_context`] and [`Self::resolve_fqdn`] only
    /// after the session rules and the static map have both missed, which is the
    /// precedence order TS 23.548 implies: session-specific beats
    /// EASDF-configured, and explicit configuration beats a baseline default.
    pub fn resolve_baseline(&self, fqdn: &str) -> Option<ResolveOutcome> {
        let query = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let patterns = self.baseline_patterns.read().ok()?;
        for rule in patterns.values() {
            if !rule.matches(&query) {
                continue;
            }
            if !rule.eas_addresses.is_empty() {
                return Some(ResolveOutcome::Resolved(rule.eas_addresses.clone()));
            }
            if let Some(upstream) = &rule.forward_to {
                return Some(ResolveOutcome::Forward(upstream.clone()));
            }
        }
        None
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
