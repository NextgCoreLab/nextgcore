//! SBI Overload Control (OCI) and Load Control (LCI) — TS 29.500 §6.3 / §6.4
//!
//! This module provides parsing and emission of the `3gpp-Sbi-Oci` (Overload
//! Control Information) and `3gpp-Sbi-Lci` (Load Control Information) headers,
//! the consumer-side reaction to a received OCI, and the producer-side metric
//! that drives emission.
//!
//! # Status: §6.4.2.2 abatement is performed by default (#273)
//!
//! sbi-08 shipped the parser with no caller; #65/#272 wired the reaction but
//! left local **shedding** off, so a default deployment still did not perform
//! the §6.4.2.2 abatement the spec mandates. #273 decided the posture:
//!
//! * A **bounded** OCI — one that carries the mandatory `Period-of-Validity`
//!   (§6.4.3.4.1, §6.4.3.4.4) — is shed against by default. It expires by
//!   itself, so the worst case of a wrong metric is bounded by what the
//!   producer itself declared.
//! * An OCI that declares **no** validity is recorded and reselected away from,
//!   but never shed against, at any metric. Such a header is malformed
//!   (`Period-of-Validity` is a *mandatory* parameter, TS 29.500 §5.2.3.2.9),
//!   and it is the one shape that can turn a single erroneous
//!   `Overload-Reduction-Metric: 100` from a peer that then goes quiet into
//!   dropped requests toward a healthy NF.
//!
//! [`ShedPolicy`] carries that decision and is overridable per client and,
//! process-wide, by an operator through [`SHED_POLICY_ENV`].
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

/// Which received OCIs this consumer is willing to **shed** against — i.e. to
/// fail a request locally, without sending it, per TS 29.500 §6.4.2.2 (#273).
///
/// Recording an OCI and reselecting away from an overloaded producer are not
/// governed by this at all: neither can lose a request. This governs only the
/// destructive reaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShedPolicy {
    /// **The default (#273 decision 1).** Shed only when the OCI carries an
    /// explicit `Period-of-Validity`.
    ///
    /// `Period-of-Validity` is a *mandatory* OCI parameter (TS 29.500
    /// §5.2.3.2.9: "Period-of-Validity (Mandatory parameter)", and §6.4.3.4.1:
    /// "The OCI shall always include the Overload Timestamp, Overload Reduction
    /// Metric, OCI Period of Validity and Scope parameters"). So every
    /// conformant producer is honoured in full, and §6.4.2.2 abatement happens
    /// in a default deployment — the substance of the original complaint.
    ///
    /// What this excludes is the non-conformant OCI, and it is excluded because
    /// that is exactly the dangerous shape: with no declared validity there is
    /// nothing to expire, so one erroneous `Overload-Reduction-Metric: 100` from
    /// a peer that then goes quiet is the only way a peer's header can wedge
    /// this consumer off a healthy NF. A local ceiling
    /// ([`DEFAULT_OCI_VALIDITY`]) bounds the *record*, but the ceiling is this
    /// consumer's invention, not the producer's declaration, and inventing a
    /// number is not a basis for dropping traffic. Such an OCI is still recorded
    /// and still drives reselection, which loses nothing.
    #[default]
    BoundedOnly,
    /// Shed against any OCI with a non-zero metric, validity declared or not.
    ///
    /// The literal reading of §6.4.3.4.4 ("valid ... until another OCI ... is
    /// received"), for an operator who trusts their producers and would rather
    /// abate against a malformed OCI than send into a declared overload. The
    /// [`DEFAULT_OCI_VALIDITY`] ceiling still bounds how long a validity-less
    /// OCI is believed.
    Always,
    /// Never shed: record and reselect only. The pre-#273 default.
    ///
    /// Retained because an operator may genuinely prefer "send into the overload
    /// and let the producer 503 it" to any local failure — e.g. a deployment
    /// whose consumers cannot distinguish a local shed from a real outage.
    Never,
}

/// Environment variable overriding [`ShedPolicy`] process-wide (#273).
///
/// `bounded` (default), `always`, `off`/`never`. An unrecognised value keeps the
/// default and warns: a typo must neither silently disable mandated abatement
/// nor silently enable the unbounded form.
pub const SHED_POLICY_ENV: &str = "NEXTGCORE_SBI_OVERLOAD_SHED";

/// Programmatic override of the process-wide policy: `0` = consult
/// [`SHED_POLICY_ENV`], `1` = [`ShedPolicy::BoundedOnly`], `2` =
/// [`ShedPolicy::Always`], `3` = [`ShedPolicy::Never`].
static SHED_POLICY_MODE: AtomicU8 = AtomicU8::new(0);

/// Force the process-wide [`ShedPolicy`], overriding [`SHED_POLICY_ENV`].
///
/// Mirrors [`crate::security::set_sbi_profile_override`], and exists for the
/// same reason: a test that needs a specific posture should say so rather than
/// depend on whatever the environment holds. Storing the same value from several
/// threads is benign.
pub fn set_shed_policy_override(policy: ShedPolicy) {
    SHED_POLICY_MODE.store(
        match policy {
            ShedPolicy::BoundedOnly => 1,
            ShedPolicy::Always => 2,
            ShedPolicy::Never => 3,
        },
        AtomicOrdering::Relaxed,
    );
}

/// Clear an override set by [`set_shed_policy_override`], restoring env-driven
/// resolution.
pub fn reset_shed_policy_override() {
    SHED_POLICY_MODE.store(0, AtomicOrdering::Relaxed);
}

impl ShedPolicy {
    /// Resolve the process-wide policy: the programmatic override first, then
    /// [`SHED_POLICY_ENV`], then the [`ShedPolicy::BoundedOnly`] default.
    pub fn resolve() -> Self {
        match SHED_POLICY_MODE.load(AtomicOrdering::Relaxed) {
            1 => Self::BoundedOnly,
            2 => Self::Always,
            3 => Self::Never,
            _ => Self::from_env_value(std::env::var(SHED_POLICY_ENV).ok().as_deref()),
        }
    }

    /// Pure resolution of an env value, unit-testable without touching the
    /// process environment.
    pub fn from_env_value(value: Option<&str>) -> Self {
        let Some(raw) = value else {
            return Self::BoundedOnly;
        };
        let v = raw.trim();
        if v.is_empty() {
            return Self::BoundedOnly;
        }
        match v.to_ascii_lowercase().as_str() {
            "bounded" | "bounded-only" | "bounded_only" => Self::BoundedOnly,
            "always" | "any" | "on" => Self::Always,
            "never" | "off" | "none" => Self::Never,
            other => {
                log::warn!(
                    "{SHED_POLICY_ENV}={other:?} is not a recognised overload shedding policy; \
                     using 'bounded'. Accepted values: bounded, always, never."
                );
                Self::BoundedOnly
            }
        }
    }

    /// Whether an OCI of this shape is eligible to be shed against at all,
    /// before the probabilistic draw.
    fn admits(&self, oci: &Oci) -> bool {
        match self {
            Self::Never => false,
            Self::Always => true,
            Self::BoundedOnly => oci.period_of_validity_secs.is_some(),
        }
    }
}

/// Consumer-side overload reaction. Carries the [`ShedPolicy`] that decides
/// which received OCIs may cause a local failure.
#[derive(Debug, Clone, Copy, Default)]
pub struct OverloadControl {
    /// Which OCIs are eligible for shedding. Defaults to
    /// [`ShedPolicy::BoundedOnly`] (#273).
    pub policy: ShedPolicy,
}

impl OverloadControl {
    /// A controller that never sheds.
    pub fn disabled() -> Self {
        Self {
            policy: ShedPolicy::Never,
        }
    }

    /// A controller that sheds against any non-zero metric, bounded or not.
    pub fn enabled() -> Self {
        Self {
            policy: ShedPolicy::Always,
        }
    }

    /// A controller carrying an explicit policy.
    pub fn with_policy(policy: ShedPolicy) -> Self {
        Self { policy }
    }

    /// Whether this controller can ever shed.
    pub fn sheds_anything(&self) -> bool {
        self.policy != ShedPolicy::Never
    }

    /// Decide whether to shed (drop/defer) a request bound for a peer that
    /// advertised `oci`, drawing randomness from `rng`.
    ///
    /// A request is shed with probability `oci.reduction_metric / 100`, but only
    /// if the policy admits this OCI's shape at all. A metric of `0` never
    /// sheds (§6.4.3.4.3: `0` signals the sender is *not* overloaded); `100`
    /// always sheds an admitted OCI.
    pub fn should_shed<R: rand::Rng>(&self, oci: &Oci, rng: &mut R) -> bool {
        if oci.reduction_metric == 0 || !self.policy.admits(oci) {
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
/// TS 29.500 §5.2.3.2.9 lists `Period-of-Validity` as a **mandatory** OCI
/// parameter, and §6.4.3.4.1 repeats it ("The OCI shall always include the
/// Overload Timestamp, Overload Reduction Metric, OCI Period of Validity and
/// Scope parameters"). An OCI without one is therefore malformed — but §6.4.3.4.4
/// defines validity as running "until the Overload Control Period of Validity
/// expires or until another OCI ... is received", so there is no expiry to apply.
/// Taken literally, a producer that once reported `Overload-Reduction-Metric: 100`
/// and then went quiet would be avoided by this consumer **forever** — one header
/// turning into a permanent self-inflicted outage toward a healthy NF. A ceiling
/// makes the worst case "wrong for 30 seconds" instead of "wrong until restart";
/// a producer that is really still overloaded restates the OCI on the next
/// response, which refreshes the entry.
///
/// #273 draws the further conclusion that a ceiling this consumer *invented* is
/// not a basis for *dropping* traffic — see [`ShedPolicy::BoundedOnly`]. The
/// ceiling bounds the record and the reselection; shedding needs the producer's
/// own declaration.
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
    /// Reject locally without sending (§6.4.2.2 abatement). Returned when the
    /// registry's [`ShedPolicy`] admits this OCI and the probabilistic draw says
    /// this request is one of the reduced fraction; see [`OverloadRegistry`].
    Shed(Oci),
}

/// One recorded OCI and when it stops applying.
#[derive(Debug, Clone)]
struct OciEntry {
    oci: Oci,
    expires_at: Instant,
}

/// Whether `oci`'s scope covers **every** request a consumer could send to the
/// producer it came from (#273).
///
/// Per TS 29.500 Table 6.4.3.4.5.2-1, two of the four producer scopes do:
/// `NF-Instance` is "all services of the NF instance identified by the NF Instance
/// ID", and `NF-Set` is "all services of all NF instances of the NF set". Since
/// this consumer keys its record by the producer's `scheme://host:port` — one NF
/// instance — both cover anything it will dial there.
///
/// The other two do not. `NF-Service-Instance` and `NF-Service-Set` name a service
/// instance or set, which only NRF discovery can map onto the endpoint being
/// dialled, and the SMF's additional `S-NSSAI`/`DNN` parameters (§6.4.3.4.5.2.2)
/// describe traffic identified in the request *body*, which this layer never sees.
///
/// An OCI carrying no scope at all is also admitted: §6.4.3.4.1 makes a scope
/// mandatory, so such a header is malformed, but the only reading available for a
/// producer that named nothing is "all of me" — and refusing it would silently
/// ignore the shape #272 was the only one to act on.
///
/// The check is on parameter NAMES only. A value this consumer cannot verify (it
/// does not know its producers' NF Instance IDs without NRF discovery) is taken as
/// the producer's own word about itself, which is the same trust the reduction
/// metric already requires.
pub fn scope_applies_to_whole_target(oci: &Oci) -> bool {
    if oci.extra.is_empty() {
        return true;
    }
    // Every declared parameter must be whole-target. A conformant SMF reporting
    // per-DNN overload sends `NF-Instance` AND `S-NSSAI`/`DNN` in ONE header
    // (§6.4.3.4.5.2.2 NOTE 1), and that header must NOT gate every request just
    // because it also happens to name the instance.
    oci.extra.iter().all(|(key, _)| {
        key.eq_ignore_ascii_case("NF-Instance") || key.eq_ignore_ascii_case("NF-Set")
    })
}

/// Sort key ordering whole-target scopes finest-first, for §6.4.3.4.1's "consider
/// the OCI received with the finer scope".
///
/// Only meaningful for an OCI that [`scope_applies_to_whole_target`] admits.
fn scope_precedence(oci: &Oci) -> u8 {
    if oci
        .extra
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("NF-Instance"))
    {
        0
    } else if oci
        .extra
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("NF-Set"))
    {
        1
    } else {
        // No scope: the least specific statement available.
        2
    }
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
/// # Default posture (#273): reroute where possible, shed a BOUNDED OCI
///
/// * Recording and **reselection** are always on. Neither can lose a request:
///   rerouting sends it somewhere healthier, and with no alternate configured
///   the decision degrades to [`SendDecision::Send`].
/// * **Shedding** — failing a request locally without sending it — is on by
///   default for an OCI that carries the mandatory `Period-of-Validity`, and
///   off for one that does not. See [`ShedPolicy::BoundedOnly`] for the full
///   argument; in short, that makes §6.4.2.2 abatement happen against every
///   conformant producer while leaving no shape of peer header that can wedge
///   this consumer off a healthy NF.
///
/// # Which scopes are acted on (corrected by #273)
///
/// §6.4.3.4.1 makes the scope **mandatory** and §6.4.3.4.5.2 fixes the permitted
/// set, so "only the unscoped OCI decides" — what #272 implemented — meant no
/// conformant producer was ever acted on. Found while wiring the producer half:
/// this tree's own NFs emit `NF-Instance`, and a consumer ignored them. See
/// [`scope_applies_to_whole_target`].
///
/// An OCI is acted on when its scope covers **every** request this consumer could
/// send to that target — `NF-Instance` ("all services of the NF instance") and
/// `NF-Set` ("all services of all NF instances of the NF set"), per
/// Table 6.4.3.4.5.2-1 — or when it names no scope at all.
///
/// A narrower scope is recorded but does not gate requests, because matching it
/// needs information this layer does not have: `S-NSSAI`/`DNN`
/// (§6.4.3.4.5.2.2) live in the request body, and `NF-Service-Instance` /
/// `NF-Service-Set` identify a service instance or set that only NRF discovery
/// can resolve to the endpoint being dialled. Applying such a metric to every
/// request would shed traffic for a reason the producer did not state. Narrower
/// occurrences stay countable via [`OverloadRegistry::live_count`].
#[derive(Debug, Default)]
pub struct OverloadRegistry {
    /// Keyed by producer (`scheme://host:port`), then by scope key — `""` for
    /// the unscoped OCI, the verbatim scope parameters otherwise.
    entries: std::sync::Mutex<HashMap<String, HashMap<String, OciEntry>>>,
    /// Governs shedding only. Recording and reselection do not consult it.
    shed: OverloadControl,
}

impl OverloadRegistry {
    /// A registry using the process-wide resolved [`ShedPolicy`] — by default
    /// [`ShedPolicy::BoundedOnly`], i.e. §6.4.2.2 abatement against a
    /// conformant OCI (#273).
    pub fn new() -> Self {
        Self::with_policy(ShedPolicy::resolve())
    }

    /// A registry that sheds against any non-zero metric, validity declared or
    /// not ([`ShedPolicy::Always`]).
    pub fn with_shedding() -> Self {
        Self::with_policy(ShedPolicy::Always)
    }

    /// A registry that records and reselects but never sheds
    /// ([`ShedPolicy::Never`]).
    pub fn without_shedding() -> Self {
        Self::with_policy(ShedPolicy::Never)
    }

    /// A registry carrying an explicit [`ShedPolicy`], ignoring the process-wide
    /// resolution.
    pub fn with_policy(policy: ShedPolicy) -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            shed: OverloadControl::with_policy(policy),
        }
    }

    /// Whether local shedding can happen at all on this registry.
    pub fn sheds(&self) -> bool {
        self.shed.sheds_anything()
    }

    /// The [`ShedPolicy`] in force on this registry.
    pub fn shed_policy(&self) -> ShedPolicy {
        self.shed.policy
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

    /// The live OCI that applies to **every** request bound for `target`, if any,
    /// dropping expired entries.
    ///
    /// Selects among the target's recorded occurrences with
    /// [`scope_applies_to_whole_target`]; the finest such scope wins, per
    /// §6.4.3.4.1 ("the NF Service Consumer should perform overload control ...
    /// considering the OCI received with the finer scope"). `NF-Instance` is finer
    /// than `NF-Set`, which is finer than an OCI naming no scope at all.
    pub fn effective_oci(&self, target: &str, now: Instant) -> Option<Oci> {
        let mut entries = self.entries.lock().ok()?;
        let per_target = entries.get_mut(target)?;
        per_target.retain(|_, e| e.expires_at > now);
        let result = per_target
            .values()
            .filter(|e| scope_applies_to_whole_target(&e.oci))
            .min_by_key(|e| scope_precedence(&e.oci))
            .map(|e| e.oci.clone());
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

/// Default `Period-of-Validity` this NF advertises on its own OCI (#273).
///
/// §6.4.3.4.4 says the parameter exists so the overloaded NF need not restate
/// the OCI on every message, and so a peer's enforcement resets by itself if
/// signalling between them stops. It must therefore outlive the interval at
/// which this NF refreshes the metric — the heartbeat tick is 5s at every
/// registering NF in this tree — while staying short enough that a recovered NF
/// which then goes completely silent is not avoided for long. 30s is six ticks:
/// five may be lost before a peer's enforcement lapses while this NF is still
/// overloaded.
///
/// This is emitted, not assumed, precisely so consumers can shed against it
/// under [`ShedPolicy::BoundedOnly`]: an NF of this tree talking to another is a
/// conformant producer by construction.
pub const DEFAULT_REPORTED_VALIDITY_SECS: u64 = 30;

/// Load percentage at or above which [`OverloadReporter::report_load`] starts
/// asking peers to reduce traffic (#273).
///
/// Below this the NF is busy but coping, and §6.4.3.4.3 warns against
/// advertising small variations at all ("the sender should refrain from
/// advertising every small variation"). 80% leaves a fifth of capacity as the
/// headroom in which abatement has time to take effect before admission control
/// starts refusing outright — `amf_ue_add` / `smf_ue_add` return `None` at 100%,
/// which is a hard failure the peer cannot anticipate.
pub const LOAD_OVERLOAD_THRESHOLD: u8 = 80;

/// Producer-side overload reporter (#65, driven for real by #273).
///
/// An NF stores a reduction metric here; the SBI server then stamps
/// `3gpp-Sbi-Oci` on every response it sends (TS 29.500 §6.4.3.2), which is the
/// emission half of §6.4 that no NF in this tree could perform before.
///
/// # Where the metric comes from (#273 decision 2)
///
/// Three sources, which the spec's "How an NF Service Producer/Consumer
/// identifies that it is overloaded is implementation specific" (§6.4.3.1)
/// leaves open, and which are deliberately **not** exclusive:
///
/// 1. [`report_load`](Self::report_load) — derived from the NF's own load gauge,
///    the same `NFProfile.load` number it already PATCHes to the NRF every
///    heartbeat (TS 29.510 §5.2.2.3.2). This is the automatic source and it is
///    genuinely per-NF: the AMF's gauge is registered UEs against configured
///    capacity, the SMF's is PDU sessions, and each NF owns its own definition.
///    Wiring it into the existing heartbeat tick is what makes the producer half
///    *driven* rather than merely reachable.
/// 2. [`set_reduction_metric`](Self::set_reduction_metric) — an NF that knows
///    something its load gauge does not (N2 backlog, PFCP queue depth) sets the
///    number directly. Unchanged from #272.
/// 3. [`set_operator_metric`](Self::set_operator_metric) — an operator floor for
///    planned drain-down, which §6.4 has no opinion about but operations does.
///    It **overrides downward-only**: the reported metric is the maximum of the
///    operator floor and whatever load says, so a drain cannot mask a genuine
///    overload and a genuine overload cannot cancel a drain.
///
/// What is deliberately NOT a source is anything this transport could measure by
/// itself. In-flight streams against `max_concurrent_streams` measures the
/// transport, not the NF: an AMF whose N2 queue is saturated while its SBI
/// concurrency is idle would report `0`, and one behind a slow UDR would report
/// overload it does not have. Either direction is a lie told in a mandatory
/// header, so the honest generic signal is no signal.
#[derive(Debug)]
pub struct OverloadReporter {
    /// Load-derived component, 0..=100. 0 = this source reports no overload.
    load_metric: AtomicU8,
    /// Operator floor, 0..=100, for planned drain-down. Never reduces the
    /// load-derived component.
    operator_metric: AtomicU8,
    /// `Period-of-Validity` in seconds; 0 omits the parameter.
    validity_secs: AtomicU64,
    /// Scope parameters emitted verbatim, e.g.
    /// `("NF-Instance", "<uuid>")`. §6.4.3.4.1 makes a scope mandatory and
    /// §6.4.3.4.5.2 fixes the permitted set; empty omits it, which is what a
    /// test server with no NF identity wants.
    scope: std::sync::Mutex<Vec<(String, String)>>,
}

impl Default for OverloadReporter {
    /// A reporter that is not overloaded and emits nothing, but which will
    /// advertise [`DEFAULT_REPORTED_VALIDITY_SECS`] once it is.
    ///
    /// The default is conformant deliberately: `AtomicU64::default()` would be
    /// `0`, which omits the mandatory `Period-of-Validity` and so emits a header
    /// that a [`ShedPolicy::BoundedOnly`] consumer records but will not act on.
    /// An NF that forgot to set a validity would then have its overload silently
    /// ignored by every peer in this tree.
    fn default() -> Self {
        Self {
            load_metric: AtomicU8::new(0),
            operator_metric: AtomicU8::new(0),
            validity_secs: AtomicU64::new(DEFAULT_REPORTED_VALIDITY_SECS),
            scope: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl OverloadReporter {
    /// A reporter that is not overloaded and emits nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the reduction metric directly (0..=100), source (2) above.
    ///
    /// Shares the load-derived slot: an NF that computes its own metric is
    /// making the same statement `report_load` makes, just from a better input,
    /// so the two must not add up. An NF that uses both wins with whichever
    /// wrote last, which is why an NF should pick one.
    pub fn set_reduction_metric(&self, metric: u8) {
        self.load_metric
            .store(metric.min(100), AtomicOrdering::Relaxed);
    }

    /// Set the reduction metric from this NF's own load percentage, source (1).
    ///
    /// Below [`LOAD_OVERLOAD_THRESHOLD`] nothing is reported. At or above it the
    /// requested reduction ramps linearly from 0% at the threshold to 100% at
    /// 100% load, so a peer's abatement grows with the overload rather than
    /// stepping from nothing to everything. Returns the metric now in force from
    /// this source, so a caller can log it.
    ///
    /// § references: §6.4.3.4.3 for the metric's meaning and its "refrain from
    /// advertising every small variation" guidance, which the threshold and the
    /// ramp together satisfy; §6.4.3.1 for load being the NF's own business.
    pub fn report_load(&self, load_percent: u8) -> u8 {
        let load = load_percent.min(100);
        let metric = if load < LOAD_OVERLOAD_THRESHOLD {
            0
        } else {
            // Linear ramp across the remaining headroom. Integer arithmetic on
            // u32 so the numerator cannot overflow u8 before the divide.
            let span = 100u32 - LOAD_OVERLOAD_THRESHOLD as u32;
            (((load as u32 - LOAD_OVERLOAD_THRESHOLD as u32) * 100) / span).min(100) as u8
        };
        self.load_metric.store(metric, AtomicOrdering::Relaxed);
        metric
    }

    /// Set the operator floor for planned drain-down (0..=100), source (3).
    ///
    /// `0` withdraws the drain. The reported metric is
    /// `max(operator_floor, load_metric)`, so this raises the requested
    /// reduction but can never lower one the NF's own state justifies.
    pub fn set_operator_metric(&self, metric: u8) {
        self.operator_metric
            .store(metric.min(100), AtomicOrdering::Relaxed);
    }

    /// The operator floor currently in force.
    pub fn operator_metric(&self) -> u8 {
        self.operator_metric.load(AtomicOrdering::Relaxed)
    }

    /// Set the advertised `Period-of-Validity`, in seconds. `0` omits it, which
    /// emits a non-conformant OCI that a [`ShedPolicy::BoundedOnly`] consumer
    /// will record but not shed against — so this is for tests and for an
    /// operator who knows what they are giving up.
    pub fn set_validity_secs(&self, secs: u64) {
        self.validity_secs.store(secs, AtomicOrdering::Relaxed);
    }

    /// Declare the OCI scope (TS 29.500 §6.4.3.4.5.2), e.g.
    /// `set_scope("NF-Instance", nf_instance_id)`.
    ///
    /// §6.4.3.4.1 makes a scope mandatory, and it is what lets a consumer keep a
    /// per-instance and a per-set OCI apart. A reporter with no scope set emits
    /// the unscoped OCI the pre-#273 code emitted.
    pub fn set_scope(&self, parameter: impl Into<String>, value: impl Into<String>) {
        if let Ok(mut scope) = self.scope.lock() {
            *scope = vec![(parameter.into(), value.into())];
        }
    }

    /// The effective metric: the greater of the operator floor and the
    /// load-derived / NF-set component.
    pub fn reduction_metric(&self) -> u8 {
        self.load_metric
            .load(AtomicOrdering::Relaxed)
            .max(self.operator_metric.load(AtomicOrdering::Relaxed))
    }

    /// The OCI to stamp on a response, or `None` when not overloaded.
    ///
    /// Carries `Timestamp` (§6.4.3.4.2, for collating out-of-order occurrences),
    /// `Period-of-Validity` (§6.4.3.4.4) and the scope (§6.4.3.4.5.2) whenever
    /// each is available, so the emitted header is the conformant shape a
    /// [`ShedPolicy::BoundedOnly`] consumer will act on.
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
        // §6.4.3.4.2 requires a Timestamp so the receiver can tell a new OCI
        // from a restatement. Generated per emission from the shared TS 29.571
        // DateTime helper rather than cached: a cached one would make every
        // response look like the same OCI, and §6.4.3.4.2 says the receiver
        // "shall discard" an OCI whose timestamp is not newer.
        oci.timestamp = Some(crate::datetime::epoch_to_rfc3339(
            crate::datetime::now_epoch_secs(),
        ));
        if let Ok(scope) = self.scope.lock() {
            oci.extra = scope.clone();
        }
        Some(oci)
    }
}

/// This process's own [`OverloadReporter`] — the one the SBI server stamps from
/// and the heartbeat tick drives (#273 decision 2).
///
/// A process-global rather than a per-NF field because the two ends of the wiring
/// live in different crates and neither can hand the other an `Arc`: the metric
/// source is [`crate::heartbeat::spawn_heartbeat_worker_with_load`], called from
/// each daemon's registration path, and the emitter is
/// [`crate::server::SbiServerConfig`], built earlier in that same `main`. Passing
/// one `Arc` between them would mean editing all 19 daemons and getting it right
/// at each; a global means the NF metric a daemon already computes for its
/// `NFProfile.load` gauge reaches its own responses with no per-daemon wiring at
/// all. An NF wanting a *different* reporter still passes one explicitly to
/// [`crate::server::SbiServerConfig::with_overload_reporter`], which wins.
///
/// Starts at metric 0, so a process that never drives it emits no OCI — which is
/// every test binary, and is byte-identical to the pre-#273 behaviour.
static SELF_OVERLOAD_REPORTER: std::sync::OnceLock<std::sync::Arc<OverloadReporter>> =
    std::sync::OnceLock::new();

/// Serialises tests that mutate [`SELF_OVERLOAD_REPORTER`]'s contents.
///
/// Declared here, beside the global it protects, rather than inside any `mod
/// tests`: the global is reachable from `heartbeat`, `server` and `client` tests
/// in this crate, and a second lock over one variable has hung this suite before.
/// Every test that drives the shared reporter — in ANY module of this crate —
/// must take this one.
///
/// A `std::sync::Mutex` even though the async holders keep it across awaits (they
/// carry `#[allow(clippy::await_holding_lock)]`): every holder is a test in this
/// crate, none blocks on another, and a second `tokio` lock for the async half
/// would recreate exactly the two-locks-over-one-variable split this comment
/// exists to prevent. Same reasoning, and same shape, as `smfd`'s `STORE_LOCK`.
#[cfg(test)]
pub(crate) static SELF_REPORTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`SELF_REPORTER_TEST_LOCK`], recovering a poisoned guard so one failing
/// test does not cascade into every other holder.
#[cfg(test)]
pub(crate) fn lock_self_reporter() -> std::sync::MutexGuard<'static, ()> {
    SELF_REPORTER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// This process's own overload reporter (see [`SELF_OVERLOAD_REPORTER`]).
pub fn self_overload_reporter() -> &'static std::sync::Arc<OverloadReporter> {
    SELF_OVERLOAD_REPORTER.get_or_init(|| std::sync::Arc::new(OverloadReporter::new()))
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
        // An explicitly disabled controller never sheds, even at 100% with a
        // declared validity. This is `ShedPolicy::Never`, no longer the default.
        let ctl = OverloadControl::disabled();
        assert!(!ctl.sheds_anything());
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..1000 {
            assert!(!ctl.should_shed(&Oci::new(100), &mut rng));
            assert!(!ctl.should_shed(&Oci::new(100).with_validity_secs(75), &mut rng));
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

    /// #273 decision 1, at the unit level: the DEFAULT controller sheds against a
    /// conformant OCI (one declaring `Period-of-Validity`, TS 29.500 §5.2.3.2.9 /
    /// §6.4.3.4.1) and never against one that omits it.
    ///
    /// Both halves asserted in one test deliberately: the "does shed" half is the
    /// positive assertion that proves the default performs §6.4.2.2 at all, and
    /// without it the "does not shed" half would also pass against a controller
    /// that sheds nothing — the pre-#273 default.
    #[test]
    fn the_default_policy_sheds_a_bounded_oci_and_never_an_unbounded_one() {
        let ctl = OverloadControl::default();
        assert_eq!(ctl.policy, ShedPolicy::BoundedOnly);
        assert!(ctl.sheds_anything());

        let bounded = Oci::new(100).with_validity_secs(75);
        let unbounded = Oci::new(100);
        assert!(unbounded.period_of_validity_secs.is_none());

        let mut rng = StdRng::seed_from_u64(99);
        for _ in 0..1000 {
            assert!(
                ctl.should_shed(&bounded, &mut rng),
                "the default must abate against a conformant 100% reduction (§6.4.2.2)"
            );
            assert!(
                !ctl.should_shed(&unbounded, &mut rng),
                "an OCI omitting the mandatory Period-of-Validity must never drop traffic"
            );
        }

        // A validity of 0s still COUNTS as declared — the producer said "expire
        // immediately", which is a statement, not an omission. It is admitted by
        // the policy; the registry then expires it at once, which is the
        // producer's own instruction being honoured rather than ignored.
        assert!(ctl.should_shed(&Oci::new(100).with_validity_secs(0), &mut rng));
    }

    /// #273: the operator escape hatches in both directions resolve as documented,
    /// and an unrecognised value falls back to the mandated default rather than to
    /// either extreme.
    #[test]
    fn shed_policy_resolves_from_operator_configuration() {
        assert_eq!(ShedPolicy::from_env_value(None), ShedPolicy::BoundedOnly);
        assert_eq!(
            ShedPolicy::from_env_value(Some("  ")),
            ShedPolicy::BoundedOnly
        );
        assert_eq!(
            ShedPolicy::from_env_value(Some("BOUNDED")),
            ShedPolicy::BoundedOnly
        );
        assert_eq!(
            ShedPolicy::from_env_value(Some("always")),
            ShedPolicy::Always
        );
        assert_eq!(ShedPolicy::from_env_value(Some("on")), ShedPolicy::Always);
        assert_eq!(ShedPolicy::from_env_value(Some("off")), ShedPolicy::Never);
        assert_eq!(ShedPolicy::from_env_value(Some("never")), ShedPolicy::Never);
        // A typo must not silently disable mandated abatement, nor silently widen
        // it to the unbounded form.
        assert_eq!(
            ShedPolicy::from_env_value(Some("bounded-ish")),
            ShedPolicy::BoundedOnly
        );
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
        // Explicit policy, not `new()`: since #273 `new()` resolves the
        // process-wide policy from the environment, and a test asserting spec
        // behaviour must not change meaning with an operator's env var.
        let registry = OverloadRegistry::with_policy(ShedPolicy::BoundedOnly);
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

    /// #65: each scope is an independent entry, and only a scope covering the
    /// WHOLE target drives the decision — a per-DNN metric must not be applied to
    /// every request.
    ///
    /// #273 corrected which scopes qualify. #272 acted only on an OCI naming NO
    /// scope, but §6.4.3.4.1 makes a scope mandatory, so that rule ignored every
    /// conformant producer — including this tree's own NFs, which emit
    /// `NF-Instance`. The name is kept and the assertions extended:
    /// `NF-Instance`/`NF-Set` now decide, `DNN`/`S-NSSAI`/`NF-Service-*` still do
    /// not.
    ///
    /// Uses a SHEDDING registry deliberately. With `ShedPolicy::Never` every
    /// branch ends in `Send`, so an earlier version of this test passed even with
    /// `effective_oci` reverted to "return any live entry, scoped or not": the
    /// outcome was decided by shedding being off, not by the scope logic. With
    /// shedding on, scope is the only variable left.
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

        // A service-level scope is likewise not actionable here: resolving
        // `NF-Service-Set` onto the endpoint being dialled needs NRF discovery.
        registry.record(
            target,
            &[
                "Overload-Reduction-Metric: 100; NF-Service-Set: setxyz.snnsmf-pdusession"
                    .to_string(),
            ],
            now,
        );
        assert_eq!(registry.live_count(target, now), 2);
        assert_eq!(
            registry.decide(target, false, now),
            SendDecision::Send,
            "a per-service-set metric must not gate every request either"
        );

        // A conformant SMF reporting per-DNN overload puts NF-Instance AND
        // S-NSSAI/DNN in ONE header (§6.4.3.4.5.2.2 NOTE 1). That must stay
        // non-actionable: it describes DNN traffic, not everything.
        registry.record(
            target,
            &["Overload-Reduction-Metric: 100; NF-Instance: nf-1; DNN: internet".to_string()],
            now,
        );
        assert_eq!(registry.live_count(target, now), 3);
        assert_eq!(
            registry.decide(target, false, now),
            SendDecision::Send,
            "naming the instance alongside a DNN must not widen the OCI to all traffic"
        );

        // #273: the whole-NF scope every conformant producer in this tree emits.
        // This is the entry that must decide, and the one #272 ignored.
        registry.record(
            target,
            &["Overload-Reduction-Metric: 100; NF-Instance: nf-1".to_string()],
            now,
        );
        assert_eq!(registry.live_count(target, now), 4, "all four are held");
        assert!(
            matches!(registry.decide(target, false, now), SendDecision::Shed(o) if o.reduction_metric == 100),
            "an NF-Instance-scoped 100% reduction with no alternate must shed"
        );
        // With an alternate, rerouting is preferred over shedding.
        assert!(matches!(
            registry.decide(target, true, now),
            SendDecision::Reselect(_)
        ));
    }

    /// #273: among scopes that DO cover the whole target, the finest wins
    /// (§6.4.3.4.1: "consider the OCI received with the finer scope").
    ///
    /// Asserted through the metric rather than through Shed/Send, so the outcome
    /// names WHICH entry was chosen. A Shed/Send assertion would pass if either
    /// entry had been picked.
    #[test]
    fn the_finest_whole_target_scope_decides() {
        let registry = OverloadRegistry::with_policy(ShedPolicy::BoundedOnly);
        let now = Instant::now();
        let target = "http://127.0.0.1:8080";

        // The set says 20%, the instance within it says 50% — §6.4.3.4.1's own
        // worked example, with the AMF/SMF roles played by this registry.
        registry.record(
            target,
            &[
                "Period-of-Validity: 75s; Overload-Reduction-Metric: 20; \
                 NF-Set: set1.smfset.5gc.mnc012.mcc345"
                    .to_string(),
                "Period-of-Validity: 75s; Overload-Reduction-Metric: 50; NF-Instance: nf-1"
                    .to_string(),
            ],
            now,
        );
        assert_eq!(registry.live_count(target, now), 2);
        assert_eq!(
            registry
                .effective_oci(target, now)
                .map(|o| o.reduction_metric),
            Some(50),
            "the NF-Instance scope is finer than the NF-Set it belongs to"
        );

        // With only the set-level OCI live, that one applies — so the assertion
        // above is about precedence, not about NF-Set being ignored outright.
        let set_only = "http://127.0.0.1:8083";
        registry.record(
            set_only,
            &["Period-of-Validity: 75s; Overload-Reduction-Metric: 20; NF-Set: set1".to_string()],
            now,
        );
        assert_eq!(
            registry
                .effective_oci(set_only, now)
                .map(|o| o.reduction_metric),
            Some(20),
            "an NF-Set scope covers all instances of the set, so it gates this target"
        );
    }

    /// #65: an OCI with no `Period-of-Validity` expires under the local ceiling
    /// instead of applying forever. One erroneous `metric: 100` must not become a
    /// permanent outage toward a healthy producer.
    ///
    /// #273 INVERTS the shedding half of this guard rather than deleting it: under
    /// the default [`ShedPolicy::BoundedOnly`] such an OCI is now not merely
    /// bounded, it never sheds at all — so the ceiling is the bound on the
    /// *record* and on reselection, and the policy is the bound on dropped
    /// traffic. Both are asserted here, because the ceiling alone is what a
    /// `ShedPolicy::Always` operator is left with.
    #[test]
    fn an_oci_without_a_validity_period_expires_under_the_ceiling() {
        // `Always` so the ceiling is the only thing that can end the shedding.
        // Under the default policy this OCI never sheds, and the expiry assertion
        // below would then pass with the ceiling deleted.
        let registry = OverloadRegistry::with_policy(ShedPolicy::Always);
        let now = Instant::now();
        let target = "http://127.0.0.1:8080";

        // No Period-of-Validity in the header at all.
        registry.record(target, &["Overload-Reduction-Metric: 100".to_string()], now);
        assert!(registry.effective_oci(target, now).is_some());
        assert!(
            matches!(registry.decide(target, false, now), SendDecision::Shed(_)),
            "with ShedPolicy::Always a live unbounded OCI sheds, so the expiry below \
             is what ends it"
        );

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

    /// #273 decision 1 at the registry level: the DEFAULT registry sheds a
    /// conformant OCI and sends an unbounded one, with no alternate available in
    /// either case.
    ///
    /// `alternate_available: false` throughout, so reselection cannot mask the
    /// difference — the two outcomes differ only by whether the header declared a
    /// `Period-of-Validity`.
    #[test]
    fn the_default_registry_sheds_only_against_a_conformant_oci() {
        let registry = OverloadRegistry::with_policy(ShedPolicy::BoundedOnly);
        let now = Instant::now();
        let bounded_target = "http://127.0.0.1:8081";
        let unbounded_target = "http://127.0.0.1:8082";
        // Distinct targets, not one reused: the registry keys entries by target,
        // so recording the second OCI against the same key would SUPERSEDE the
        // first (§6.4.3.4.2) and the test would assert about one entry twice.

        registry.record(
            bounded_target,
            &["Period-of-Validity: 75s; Overload-Reduction-Metric: 100".to_string()],
            now,
        );
        assert!(
            matches!(
                registry.decide(bounded_target, false, now),
                SendDecision::Shed(o) if o.reduction_metric == 100
            ),
            "a conformant 100% reduction must be abated locally — this is §6.4.2.2 \
             happening in a DEFAULT deployment, which is what #65 complained was missing"
        );

        registry.record(
            unbounded_target,
            &["Overload-Reduction-Metric: 100".to_string()],
            now,
        );
        assert_eq!(
            registry.decide(unbounded_target, false, now),
            SendDecision::Send,
            "an OCI omitting the mandatory Period-of-Validity must not drop traffic"
        );
        // It IS still recorded, so reselection can use it and a later conformant
        // restatement supersedes it.
        assert_eq!(registry.live_count(unbounded_target, now), 1);
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

    /// #273 decision 2, source (1): a load percentage becomes a reduction metric,
    /// silent below the threshold and ramping above it.
    ///
    /// Uses a LOCAL reporter, not `self_overload_reporter()`, so it needs no lock
    /// and cannot perturb the process-global one every other test reads.
    #[test]
    fn a_load_gauge_becomes_a_reduction_metric_above_the_threshold() {
        let reporter = OverloadReporter::new();

        // Below the threshold nothing is claimed — §6.4.3.4.3 warns against
        // advertising small variations, and a busy-but-coping NF is not overloaded.
        for load in [0u8, 50, LOAD_OVERLOAD_THRESHOLD - 1] {
            assert_eq!(
                reporter.report_load(load),
                0,
                "load {load}% must claim nothing"
            );
            assert!(
                reporter.oci().is_none(),
                "no OCI header at all below the threshold"
            );
        }

        // At the threshold exactly: admitted, but asking for 0% reduction, so
        // still no header. This is the boundary the ramp starts from.
        assert_eq!(reporter.report_load(LOAD_OVERLOAD_THRESHOLD), 0);

        // The ramp: 90% load is halfway through the remaining headroom.
        assert_eq!(reporter.report_load(90), 50);
        // Saturated at the top.
        assert_eq!(reporter.report_load(100), 100);
        // An out-of-range reading is clamped rather than wrapping.
        assert_eq!(reporter.report_load(255), 100);

        // Recovery: a later low reading withdraws the claim, which is §6.4.3.4.3's
        // "metric 0 signals the overload has ceased" — asserted as a TRANSITION
        // from 100, so a reporter that never reacted at all cannot pass this.
        assert_eq!(reporter.report_load(10), 0);
        assert!(reporter.oci().is_none());
    }

    /// #273 decision 2: the emitted OCI is the CONFORMANT shape — Timestamp
    /// (§6.4.3.4.2), Period-of-Validity (§6.4.3.4.4) and a scope
    /// (§6.4.3.4.5.2) — which is precisely what makes a peer running the default
    /// [`ShedPolicy::BoundedOnly`] able to act on it.
    ///
    /// The round-trip through `Oci::parse` is the point: it asserts the bytes a
    /// peer would actually receive, not the struct this side built.
    #[test]
    fn the_emitted_oci_is_shed_eligible_at_a_default_consumer() {
        let reporter = OverloadReporter::new();
        reporter.set_scope("NF-Instance", "54804518-4191-46b3-955c-ac631f953ed8");
        reporter.report_load(95);

        let header = reporter
            .oci()
            .expect("overloaded, so an OCI is emitted")
            .to_header();
        let parsed = Oci::parse(&header).expect("the emitted header must re-parse");

        assert_eq!(parsed.reduction_metric, 75);
        assert_eq!(
            parsed.period_of_validity_secs,
            Some(DEFAULT_REPORTED_VALIDITY_SECS),
            "a conformant producer declares its validity (§5.2.3.2.9: mandatory)"
        );
        assert!(
            parsed
                .timestamp
                .as_deref()
                .is_some_and(|t| t.ends_with('Z')),
            "§6.4.3.4.2 requires a Timestamp so the receiver can collate occurrences"
        );
        assert_eq!(
            parsed.extra,
            vec![(
                "NF-Instance".to_string(),
                "54804518-4191-46b3-955c-ac631f953ed8".to_string()
            )],
            "§6.4.3.4.1 makes the scope mandatory; Table 6.4.3.4.5.2-1 permits NF-Instance"
        );

        // The closing of the loop, and the reason the validity default is
        // conformant: a DEFAULT consumer must shed against what a DEFAULT producer
        // emits. Without this assertion the two defaults could drift apart and
        // both halves would still pass their own tests.
        //
        // Asserted against the SHAPE at metric 100 rather than against the
        // emitted metric of 75: `should_shed` is probabilistic, so a direct
        // assertion at 75 would fail one run in four. At 100 the draw is
        // deterministic, and the metric is the one parameter this is not about —
        // eligibility turns on the validity and nothing else.
        let mut at_full = parsed.clone();
        at_full.reduction_metric = 100;
        let mut rng = StdRng::seed_from_u64(4242);
        assert!(
            OverloadControl::default().should_shed(&at_full, &mut rng),
            "what an NF of this tree emits must be shed-eligible at a default consumer"
        );
        // And the mandatory scope must not disqualify it at the registry. This is
        // the half #272 got wrong: acting only on an UNSCOPED OCI meant a
        // conformant producer was recorded and ignored.
        assert!(
            scope_applies_to_whole_target(&parsed),
            "an NF-Instance scope covers every request to this producer (Table 6.4.3.4.5.2-1)"
        );
    }

    /// #273 decision 2, source (3): the operator floor raises the metric for a
    /// planned drain but can never lower one the NF's own load justifies.
    #[test]
    fn the_operator_floor_raises_but_never_masks_a_real_overload() {
        let reporter = OverloadReporter::new();

        // Drain-down with the NF otherwise idle: the operator's number is what
        // peers see. This is the case §6.4 has no opinion about and operations
        // needs.
        reporter.report_load(0);
        reporter.set_operator_metric(30);
        assert_eq!(reporter.reduction_metric(), 30);
        assert_eq!(reporter.oci().map(|o| o.reduction_metric), Some(30));

        // A genuine overload above the floor wins — a 30% drain must not cap a
        // 100% reduction the NF's capacity demands.
        reporter.report_load(100);
        assert_eq!(reporter.reduction_metric(), 100);

        // And recovery does not cancel the drain: the floor is still in force.
        reporter.report_load(0);
        assert_eq!(reporter.reduction_metric(), 30);

        // Withdrawing the drain with the NF idle stops emission entirely.
        reporter.set_operator_metric(0);
        assert_eq!(reporter.reduction_metric(), 0);
        assert!(reporter.oci().is_none());
    }

    /// #273: a reporter left at its defaults emits a header a
    /// [`ShedPolicy::BoundedOnly`] consumer will act on.
    ///
    /// Guards the trap that `AtomicU64::default()` is `0`, which omits the
    /// mandatory `Period-of-Validity` — an NF would then be silently ignored by
    /// every peer in this tree while believing it had asked for abatement.
    #[test]
    fn a_default_reporter_declares_a_validity_period() {
        let reporter = OverloadReporter::default();
        reporter.set_reduction_metric(60);
        let oci = reporter.oci().expect("metric 60 emits");
        assert_eq!(
            oci.period_of_validity_secs,
            Some(DEFAULT_REPORTED_VALIDITY_SECS)
        );
        // Explicitly opting out is still possible, and is honestly non-conformant.
        reporter.set_validity_secs(0);
        assert_eq!(reporter.oci().unwrap().period_of_validity_secs, None);
    }
}
