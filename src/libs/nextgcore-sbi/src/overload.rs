//! SBI Overload Control (OCI) and Load Control (LCI) — TS 29.500 §6.3 / §6.4
//!
//! This module (sbi-08) provides parsing and emission of the
//! `3gpp-Sbi-Oci` (Overload Control Information) and `3gpp-Sbi-Lci`
//! (Load Control Information) headers, plus a minimal consumer-side
//! throttling reaction that honours an OCI Overload-Reduction-Metric.
//!
//! # Status: dormant by default
//!
//! Nothing in [`crate::client`] or [`crate::server`] consumes or emits these
//! headers automatically. The reaction is gated behind
//! [`OverloadControl::enabled`], which defaults to `false`: a default
//! [`OverloadControl`] never sheds a request. An NF that wants overload
//! reaction opts in explicitly. This keeps the change additive — existing
//! request/response bytes and behaviour are unchanged unless an NF wires the
//! module in and enables it.
//!
//! # Header format (TS 29.500 §6.3.3 / §6.4.3)
//!
//! Both headers are a list of `Name: value` parameters separated by `;`:
//!
//! ```text
//! 3gpp-Sbi-Oci: Timestamp: 2019-03-28T14:30:50Z; Period-of-Validity: 75s; Overload-Reduction-Metric: 50
//! 3gpp-Sbi-Lci: Timestamp: 2019-03-28T14:30:50Z; Load-Metric: 25
//! ```
//!
//! The `Timestamp` is treated as an opaque string here (no date parsing, so no
//! time/date dependency is introduced). Unrecognised scope parameters
//! (e.g. `NF-Instance`, `S-NSSAI`, `DNN`) are preserved verbatim in `extra` so
//! a parsed header re-emits losslessly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

/// Split a header value into its `Name: value` parameters and route the
/// recognised keys to `on_known`, collecting the rest into `extra`.
///
/// Keys are matched case-insensitively (TS 29.500 names are mixed-case but
/// HTTP is case-insensitive for these tokens). Returns `extra` — the
/// parameters not consumed by `on_known`.
fn parse_params<F>(value: &str, mut on_known: F) -> Vec<(String, String)>
where
    F: FnMut(&str, &str) -> bool,
{
    let mut extra = Vec::new();
    for segment in value.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        // Split on the FIRST ':' only; timestamps contain ':' themselves.
        let (key, val) = match segment.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (segment, ""),
        };
        if !on_known(key, val) {
            extra.push((key.to_string(), val.to_string()));
        }
    }
    extra
}

/// Parse an integer metric, tolerating an optional trailing `%`, and clamp it
/// to the valid 0..=100 percentage range.
fn parse_metric(val: &str) -> Option<u8> {
    let trimmed = val.trim().trim_end_matches('%').trim();
    trimmed.parse::<u32>().ok().map(|m| m.min(100) as u8)
}

/// Overload Control Information (OCI) — TS 29.500 §6.3.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Oci {
    /// Opaque timestamp string identifying this OCI instance (not parsed).
    pub timestamp: Option<String>,
    /// Period of validity, in seconds (the `Period-of-Validity` parameter).
    pub period_of_validity_secs: Option<u64>,
    /// Overload-Reduction-Metric: the percentage (0..=100) of traffic the
    /// overloaded producer requests the consumer to reduce.
    pub reduction_metric: u8,
    /// Scope / extension parameters preserved verbatim for lossless re-emit.
    pub extra: Vec<(String, String)>,
}

impl Oci {
    /// Create an OCI carrying a reduction metric (clamped to 0..=100).
    pub fn new(reduction_metric: u8) -> Self {
        Self {
            reduction_metric: reduction_metric.min(100),
            ..Default::default()
        }
    }

    /// Set the period of validity, in seconds.
    pub fn with_validity_secs(mut self, secs: u64) -> Self {
        self.period_of_validity_secs = Some(secs);
        self
    }

    /// Set the opaque timestamp string.
    pub fn with_timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    /// Parse an OCI from a `3gpp-Sbi-Oci` header value. Returns `None` when no
    /// Overload-Reduction-Metric is present (a malformed/empty OCI).
    pub fn parse(value: &str) -> Option<Self> {
        let mut timestamp = None;
        let mut period = None;
        let mut metric = None;
        let extra = parse_params(value, |key, val| {
            if key.eq_ignore_ascii_case("Timestamp") {
                timestamp = Some(val.to_string());
                true
            } else if key.eq_ignore_ascii_case("Period-of-Validity") {
                period = val.trim().trim_end_matches('s').trim().parse::<u64>().ok();
                true
            } else if key.eq_ignore_ascii_case("Overload-Reduction-Metric") {
                metric = parse_metric(val);
                true
            } else {
                false
            }
        });
        let reduction_metric = metric?;
        Some(Self {
            timestamp,
            period_of_validity_secs: period,
            reduction_metric,
            extra,
        })
    }

    /// Emit the `3gpp-Sbi-Oci` header value.
    pub fn to_header(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(ts) = &self.timestamp {
            parts.push(format!("Timestamp: {ts}"));
        }
        if let Some(secs) = self.period_of_validity_secs {
            parts.push(format!("Period-of-Validity: {secs}s"));
        }
        parts.push(format!(
            "Overload-Reduction-Metric: {}",
            self.reduction_metric
        ));
        for (k, v) in &self.extra {
            parts.push(format!("{k}: {v}"));
        }
        parts.join("; ")
    }
}

/// Load Control Information (LCI) — TS 29.500 §6.4.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lci {
    /// Opaque timestamp string (not parsed).
    pub timestamp: Option<String>,
    /// Load-Metric: the current load of the producer as a percentage (0..=100).
    pub load_metric: u8,
    /// Scope / extension parameters preserved verbatim for lossless re-emit.
    pub extra: Vec<(String, String)>,
}

impl Lci {
    /// Create an LCI carrying a load metric (clamped to 0..=100).
    pub fn new(load_metric: u8) -> Self {
        Self {
            load_metric: load_metric.min(100),
            ..Default::default()
        }
    }

    /// Set the opaque timestamp string.
    pub fn with_timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    /// Parse an LCI from a `3gpp-Sbi-Lci` header value. Returns `None` when no
    /// Load-Metric is present.
    pub fn parse(value: &str) -> Option<Self> {
        let mut timestamp = None;
        let mut metric = None;
        let extra = parse_params(value, |key, val| {
            if key.eq_ignore_ascii_case("Timestamp") {
                timestamp = Some(val.to_string());
                true
            } else if key.eq_ignore_ascii_case("Load-Metric") {
                metric = parse_metric(val);
                true
            } else {
                false
            }
        });
        let load_metric = metric?;
        Some(Self {
            timestamp,
            load_metric,
            extra,
        })
    }

    /// Emit the `3gpp-Sbi-Lci` header value.
    pub fn to_header(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(ts) = &self.timestamp {
            parts.push(format!("Timestamp: {ts}"));
        }
        parts.push(format!("Load-Metric: {}", self.load_metric));
        for (k, v) in &self.extra {
            parts.push(format!("{k}: {v}"));
        }
        parts.join("; ")
    }
}

/// Consumer-side overload reaction (sbi-08). Dormant by default: a fresh
/// [`OverloadControl`] has `enabled == false` and never sheds traffic.
#[derive(Debug, Clone, Copy, Default)]
pub struct OverloadControl {
    /// Master switch. When `false` (default), [`OverloadControl::should_shed`]
    /// always returns `false` regardless of the OCI metric, so wiring the
    /// module in is a no-op until an operator opts in.
    pub enabled: bool,
}

impl OverloadControl {
    /// A disabled controller (the default): never sheds.
    pub fn disabled() -> Self {
        Self { enabled: false }
    }

    /// An enabled controller: honours the OCI Overload-Reduction-Metric.
    pub fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Decide whether to shed (drop/defer) a request bound for a peer that
    /// advertised `oci`, drawing randomness from `rng`.
    ///
    /// When enabled, a request is shed with probability
    /// `oci.reduction_metric / 100`. A metric of `0` never sheds; `100` always
    /// sheds. When disabled, always returns `false`.
    pub fn should_shed<R: rand::Rng>(&self, oci: &Oci, rng: &mut R) -> bool {
        if !self.enabled || oci.reduction_metric == 0 {
            return false;
        }
        // random_range(0..100) yields 0..=99; shed when below the metric.
        rng.random_range(0..100u32) < oci.reduction_metric as u32
    }

    /// [`should_shed`](Self::should_shed) using the thread-local CSPRNG.
    pub fn should_shed_thread(&self, oci: &Oci) -> bool {
        self.should_shed(oci, &mut rand::rng())
    }
}

/// Longest period of validity honoured for an OCI that declares none (#65).
///
/// TS 29.500 §6.4.3.3 makes `Period-of-Validity` optional and says an OCI stays
/// valid until superseded. Taken literally, a producer that once reported
/// `Overload-Reduction-Metric: 100` and then went quiet would be avoided by this
/// consumer **forever** — one header turning into a permanent self-inflicted
/// outage toward a healthy NF. A ceiling makes the worst case "wrong for 30
/// seconds" instead of "wrong until restart"; a producer that is really still
/// overloaded restates the OCI on the next response, which refreshes the entry.
const DEFAULT_OCI_VALIDITY: Duration = Duration::from_secs(30);

/// What the consumer should do with a request bound for a given producer (#65).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDecision {
    /// Send it: no live OCI, or the OCI does not call for reduction.
    Send,
    /// Route it to an alternate producer instead — the preferred reaction
    /// whenever one exists, because it neither loads the overloaded producer nor
    /// fails the caller (TS 29.500 §6.5).
    Reselect(Oci),
    /// Reject locally without sending (§6.4.2.2 abatement). Only ever returned
    /// when shedding has been explicitly enabled; see [`OverloadRegistry`].
    Shed(Oci),
}

/// One recorded OCI and when it stops applying.
#[derive(Debug, Clone)]
struct OciEntry {
    oci: Oci,
    expires_at: Instant,
}

/// Consumer-side record of which producers have reported overload (#65).
///
/// # Why this exists
///
/// [`Oci`] could already be parsed and emitted before this, and
/// [`OverloadControl`] could already decide whether to shed — but nothing ever
/// called either from the request path, so a 503 carrying an OCI was handed
/// straight to the caller and the next request went to the same overloaded
/// producer. This is the missing piece: the memory between the response that
/// reported overload and the request that should react to it.
///
/// # Default posture: react by rerouting, not by dropping
///
/// * Recording and **reselection** are ON by default. Neither can lose a
///   request: rerouting sends it somewhere healthier, and with no alternate
///   configured the decision degrades to [`SendDecision::Send`], i.e. exactly
///   the previous behaviour.
/// * **Shedding** — failing a request locally without sending it — is OFF by
///   default and must be enabled explicitly. It is the spec's literal §6.4.2.2
///   reaction, but it is also the one that turns a producer's header into
///   dropped requests here: a metric of 100 with no `Period-of-Validity`, sent
///   in error, would stop this consumer talking to that producer at all. The
///   validity ceiling above bounds that, and this switch means an operator opts
///   into it knowingly.
///
/// # Scoped OCI is recorded but not matched
///
/// §6.4.3.3 allows an OCI to name a scope (`NF-Instance`, `S-NSSAI`, `DNN`).
/// Only the **unscoped** (whole-producer) OCI is acted upon: matching a
/// per-S-NSSAI or per-DNN scope needs the request's S-NSSAI/DNN, which is in the
/// body and not available at this layer. Scoped occurrences are still stored and
/// countable via [`OverloadRegistry::live_count`], so a scope-aware reaction can
/// be added without changing the ingest side — and, until it is, this reports
/// honestly rather than silently applying a per-DNN metric to every request.
#[derive(Debug, Default)]
pub struct OverloadRegistry {
    /// Keyed by producer (`scheme://host:port`), then by scope key — `""` for
    /// the unscoped OCI, the verbatim scope parameters otherwise.
    entries: std::sync::Mutex<HashMap<String, HashMap<String, OciEntry>>>,
    /// Governs shedding only. Recording and reselection do not consult it.
    shed: OverloadControl,
}

impl OverloadRegistry {
    /// A registry that records and reselects but never sheds (the default).
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry that also applies §6.4.2.2 shedding.
    pub fn with_shedding() -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            shed: OverloadControl::enabled(),
        }
    }

    /// Whether local shedding is enabled on this registry.
    pub fn sheds(&self) -> bool {
        self.shed.enabled
    }

    /// Record every OCI occurrence carried by a response from `target`.
    ///
    /// Takes the occurrences already split by
    /// [`SbiHttpMessage::get_header_all`](crate::message::SbiHttpMessage::get_header_all),
    /// so a producer reporting several scopes is recorded as several entries
    /// rather than only its last. Returns how many were stored.
    ///
    /// A metric of `0` is stored like any other: §6.4.3.3 uses it to signal
    /// recovery, so it must overwrite a previous non-zero entry rather than being
    /// dropped as uninteresting.
    pub fn record(&self, target: &str, oci_headers: &[String], now: Instant) -> usize {
        let mut stored = 0;
        let Ok(mut entries) = self.entries.lock() else {
            // A poisoned lock means another thread panicked while recording.
            // Overload state is advisory: losing it degrades to the pre-#65
            // behaviour (send anyway), which is strictly better than propagating
            // the panic into the request path.
            return 0;
        };
        let per_target = entries.entry(target.to_string()).or_default();
        for raw in oci_headers {
            let Some(oci) = Oci::parse(raw) else { continue };
            // A declared Period-of-Validity is honoured as sent — the producer
            // said how long it means it. Only an ABSENT one falls back to the
            // ceiling, which is the case that would otherwise never expire.
            let validity = oci
                .period_of_validity_secs
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_OCI_VALIDITY);
            let scope_key = oci
                .extra
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(";");
            per_target.insert(
                scope_key,
                OciEntry {
                    oci,
                    expires_at: now + validity,
                },
            );
            stored += 1;
        }
        stored
    }

    /// Decide what to do with a request bound for `target`.
    ///
    /// `alternate_available` says whether the caller has somewhere else to send
    /// it; when it does, reselection wins over shedding, because rerouting keeps
    /// the request alive.
    pub fn decide(&self, target: &str, alternate_available: bool, now: Instant) -> SendDecision {
        let Some(oci) = self.effective_oci(target, now) else {
            return SendDecision::Send;
        };
        if oci.reduction_metric == 0 {
            return SendDecision::Send;
        }
        if alternate_available {
            return SendDecision::Reselect(oci);
        }
        if self.shed.should_shed_thread(&oci) {
            return SendDecision::Shed(oci);
        }
        SendDecision::Send
    }

    /// The live **unscoped** OCI for `target`, if any, dropping expired entries.
    pub fn effective_oci(&self, target: &str, now: Instant) -> Option<Oci> {
        let mut entries = self.entries.lock().ok()?;
        let per_target = entries.get_mut(target)?;
        per_target.retain(|_, e| e.expires_at > now);
        let result = per_target.get("").map(|e| e.oci.clone());
        if per_target.is_empty() {
            entries.remove(target);
        }
        result
    }

    /// Number of live OCI entries recorded for `target`, scoped ones included.
    /// Exists so a caller (and the tests) can see that scoped occurrences were
    /// kept rather than silently discarded.
    pub fn live_count(&self, target: &str, now: Instant) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let Some(per_target) = entries.get_mut(target) else {
            return 0;
        };
        per_target.retain(|_, e| e.expires_at > now);
        per_target.len()
    }

    /// Forget everything recorded for `target` — used when a producer answers
    /// normally again and the consumer wants to stop reacting immediately.
    pub fn clear(&self, target: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(target);
        }
    }
}

/// Producer-side overload reporter (#65).
///
/// An NF that knows it is overloaded stores a reduction metric here; the SBI
/// server then stamps `3gpp-Sbi-Oci` on every response it sends, which is the
/// half of TS 29.500 §6.4 that no NF in this tree could perform before — the
/// emission code existed, but nothing was wired to a server response.
///
/// This deliberately does **not** measure load itself. A generic HTTP layer has
/// no basis for deciding that an AMF is overloaded (queue depth, UE count and
/// N2 backlog are the NF's business), and inventing a metric from request
/// latency here would report overload that the NF does not believe in. The NF
/// sets the number; this carries it.
#[derive(Debug, Default)]
pub struct OverloadReporter {
    /// 0 = not overloaded, and no header is emitted at all.
    metric: AtomicU8,
    /// `Period-of-Validity` in seconds; 0 omits the parameter.
    validity_secs: AtomicU64,
}

impl OverloadReporter {
    /// A reporter that is not overloaded and emits nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the reduction metric (0..=100). `0` stops emission.
    pub fn set_reduction_metric(&self, metric: u8) {
        self.metric.store(metric.min(100), AtomicOrdering::Relaxed);
    }

    /// Set the advertised `Period-of-Validity`, in seconds. `0` omits it.
    pub fn set_validity_secs(&self, secs: u64) {
        self.validity_secs.store(secs, AtomicOrdering::Relaxed);
    }

    /// The current metric.
    pub fn reduction_metric(&self) -> u8 {
        self.metric.load(AtomicOrdering::Relaxed)
    }

    /// The OCI to stamp on a response, or `None` when not overloaded.
    pub fn oci(&self) -> Option<Oci> {
        let metric = self.reduction_metric();
        if metric == 0 {
            return None;
        }
        let mut oci = Oci::new(metric);
        let validity = self.validity_secs.load(AtomicOrdering::Relaxed);
        if validity > 0 {
            oci.period_of_validity_secs = Some(validity);
        }
        Some(oci)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_oci_round_trip() {
        let value =
            "Timestamp: 2019-03-28T14:30:50Z; Period-of-Validity: 75s; Overload-Reduction-Metric: 50";
        let oci = Oci::parse(value).expect("valid OCI");
        assert_eq!(oci.timestamp.as_deref(), Some("2019-03-28T14:30:50Z"));
        assert_eq!(oci.period_of_validity_secs, Some(75));
        assert_eq!(oci.reduction_metric, 50);
        assert!(oci.extra.is_empty());

        // Re-emit and re-parse is stable.
        let emitted = oci.to_header();
        assert_eq!(Oci::parse(&emitted), Some(oci));
    }

    #[test]
    fn test_oci_tolerates_percent_and_scope() {
        // Percent suffix on the metric and an extra scope param are handled.
        let value = "Overload-Reduction-Metric: 30%; NF-Instance: 54804518-abcd";
        let oci = Oci::parse(value).expect("valid OCI");
        assert_eq!(oci.reduction_metric, 30);
        assert_eq!(
            oci.extra,
            vec![("NF-Instance".to_string(), "54804518-abcd".to_string())]
        );
        // The scope param survives re-emit.
        assert!(oci.to_header().contains("NF-Instance: 54804518-abcd"));
    }

    #[test]
    fn test_oci_metric_clamped_and_missing() {
        // Out-of-range metric is clamped to 100.
        assert_eq!(
            Oci::parse("Overload-Reduction-Metric: 250")
                .unwrap()
                .reduction_metric,
            100
        );
        // No metric => not a valid OCI.
        assert!(Oci::parse("Timestamp: x").is_none());
        assert!(Oci::parse("").is_none());
    }

    #[test]
    fn test_lci_round_trip() {
        let value = "Timestamp: 2019-03-28T14:30:50Z; Load-Metric: 25";
        let lci = Lci::parse(value).expect("valid LCI");
        assert_eq!(lci.timestamp.as_deref(), Some("2019-03-28T14:30:50Z"));
        assert_eq!(lci.load_metric, 25);
        assert_eq!(Lci::parse(&lci.to_header()), Some(lci));

        assert!(Lci::parse("Timestamp: only").is_none());
    }

    #[test]
    fn test_overload_disabled_never_sheds() {
        // The default controller is disabled and never sheds, even at 100%.
        let ctl = OverloadControl::default();
        assert!(!ctl.enabled);
        let oci = Oci::new(100);
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..1000 {
            assert!(!ctl.should_shed(&oci, &mut rng));
        }
    }

    #[test]
    fn test_overload_boundary_metrics() {
        let ctl = OverloadControl::enabled();
        let mut rng = StdRng::seed_from_u64(7);
        // 0% never sheds; 100% always sheds (deterministic boundaries).
        for _ in 0..1000 {
            assert!(!ctl.should_shed(&Oci::new(0), &mut rng));
            assert!(ctl.should_shed(&Oci::new(100), &mut rng));
        }
    }

    /// #65: a later OCI supersedes an earlier one for the same scope, so a
    /// producer signalling recovery with `Overload-Reduction-Metric: 0` stops the
    /// reaction (TS 29.500 §6.4.3.3).
    ///
    /// Both states are asserted — Reselect while the reduction is live, Send once
    /// it is withdrawn. Asserting only the second would pass against a registry
    /// that never reacted at all.
    #[test]
    fn metric_zero_supersedes_a_live_reduction() {
        let registry = OverloadRegistry::new();
        let now = Instant::now();
        let target = "http://127.0.0.1:8080";

        assert_eq!(registry.record(target, &[Oci::new(70).to_header()], now), 1);
        assert!(
            matches!(registry.decide(target, true, now), SendDecision::Reselect(o) if o.reduction_metric == 70),
            "a live reduction with an alternate available must reselect"
        );

        // Recovery.
        assert_eq!(registry.record(target, &[Oci::new(0).to_header()], now), 1);
        assert_eq!(
            registry.decide(target, true, now),
            SendDecision::Send,
            "metric 0 must supersede the earlier reduction"
        );
    }

    /// #65: each scope is an independent entry, and only the UNSCOPED one drives
    /// the decision — a per-DNN metric must not be applied to every request.
    ///
    /// Uses a SHEDDING registry deliberately. With the default (non-shedding) one
    /// every branch ends in `Send`, so the first version of this test passed even
    /// when `effective_oci` was reverted to "return any live entry, scoped or
    /// not": the outcome was decided by shedding being off, not by the scope
    /// logic. With shedding on, scope is the only variable left.
    #[test]
    fn scoped_oci_is_recorded_but_only_the_unscoped_one_decides() {
        let registry = OverloadRegistry::with_shedding();
        let now = Instant::now();
        let target = "http://127.0.0.1:8080";

        let scoped = "Overload-Reduction-Metric: 100; DNN: internet";
        assert_eq!(registry.record(target, &[scoped.to_string()], now), 1);
        assert_eq!(registry.live_count(target, now), 1, "it IS recorded");
        assert_eq!(
            registry.decide(target, false, now),
            SendDecision::Send,
            "a per-DNN metric must not gate unrelated requests, even at 100%"
        );

        // Add the whole-producer OCI: now the decision changes, and both entries
        // are still held.
        registry.record(target, &[Oci::new(100).to_header()], now);
        assert_eq!(registry.live_count(target, now), 2);
        assert!(
            matches!(registry.decide(target, false, now), SendDecision::Shed(o) if o.reduction_metric == 100),
            "an unscoped 100% reduction with no alternate must shed"
        );
        // With an alternate, rerouting is preferred over shedding.
        assert!(matches!(
            registry.decide(target, true, now),
            SendDecision::Reselect(_)
        ));
    }

    /// #65: an OCI with no `Period-of-Validity` expires under the local ceiling
    /// instead of applying forever. One erroneous `metric: 100` must not become a
    /// permanent outage toward a healthy producer.
    #[test]
    fn an_oci_without_a_validity_period_expires_under_the_ceiling() {
        let registry = OverloadRegistry::new();
        let now = Instant::now();
        let target = "http://127.0.0.1:8080";

        // No Period-of-Validity in the header at all.
        registry.record(target, &["Overload-Reduction-Metric: 100".to_string()], now);
        assert!(registry.effective_oci(target, now).is_some());

        let after = now + DEFAULT_OCI_VALIDITY + Duration::from_secs(1);
        assert!(
            registry.effective_oci(target, after).is_none(),
            "an OCI with no declared validity must not outlive the ceiling"
        );
        assert_eq!(registry.decide(target, false, after), SendDecision::Send);

        // A DECLARED validity is honoured as sent, even a long one.
        registry.record(
            target,
            &["Period-of-Validity: 600s; Overload-Reduction-Metric: 100".to_string()],
            now,
        );
        assert!(
            registry
                .effective_oci(target, now + Duration::from_secs(500))
                .is_some(),
            "a producer's declared validity is not shortened by the ceiling"
        );
    }

    #[test]
    fn test_overload_metric_approximates_shed_rate() {
        // At metric=50, ~50% of requests are shed (within tolerance).
        let ctl = OverloadControl::enabled();
        let oci = Oci::new(50);
        let mut rng = StdRng::seed_from_u64(123_456);
        let n = 20_000;
        let shed = (0..n).filter(|_| ctl.should_shed(&oci, &mut rng)).count();
        let rate = shed as f64 / n as f64;
        assert!(
            (0.45..0.55).contains(&rate),
            "expected ~50% shed at metric=50, got {rate}"
        );
    }
}
