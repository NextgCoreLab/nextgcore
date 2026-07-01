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
