//! The Prometheus exposition every 5GC network function shares (#1334).
//!
//! What a scrape of any NF's `/metrics` returns before its own series:
//!
//! - **SBI server traffic** ([`record_sbi_request`]): `nextgcore_sbi_request_total`
//!   and `nextgcore_sbi_error_total` by `service`, `operation` and `status`, and the
//!   `nextgcore_sbi_request_duration_seconds` histogram by `service`. Recorded by the
//!   shared SBI server (`nextgcore-sbi`), so every NF that serves SBI gets them.
//! - **NRF client state** ([`nrf_registered`], [`nrf_heartbeat`]): whether this NF holds
//!   a registration at the NRF (`nextgcore_nrf_registered`), its registrations and its
//!   heartbeats by result. Recorded by the shared NRF heartbeat worker.
//! - **Process** ([`render_process`]): the standard `process_*` series a Prometheus
//!   client library exports (resident memory, CPU seconds, open descriptors, start
//!   time), read from `/proc/self`, and `nextgcore_uptime_seconds`.
//! - `nextgcore_build_info{nf,version}`.
//!
//! # No subscriber identifiers in labels
//!
//! An SBI resource path names subscribers (`/nudm-sdm/v2/imsi-001010000000001/am-data`),
//! session and context IDs, and sometimes IP addresses. [`sbi_operation`] keeps only the
//! segments that are resource NAMES and replaces every other one with `{id}`, so the
//! `operation` label is a resource template (`GET {id}/am-data`). A segment is a name
//! only if it is lowercase letters, digits and hyphens, does not end in a digit, has no
//! run of three digits and is not an identity-prefixed value (`imsi-`, `suci-`, `nai-`,
//! ...). Every SUPI, GPSI, PEI, UUID, IP address and numeric reference fails one of those.
//!
//! # Bounded cardinality
//!
//! A peer chooses the paths it sends, so the label sets are capped: past
//! [`MAX_SBI_SERIES`] distinct (service, operation, status) sets a new one is counted
//! under `service="other",operation="other"`.
//!
//! # Where it listens
//!
//! [`serve_nf_metrics`] binds `NEXTGCORE_METRICS_BIND` (loopback by default, #837,
//! #1310) on the port the NF's `<NF>_METRICS_PORT` names (9090 by default), the model
//! `smfd`, `upfd` and `sgwud` already use.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The `/metrics` port an NF uses when its `<NF>_METRICS_PORT` is unset: the port every
/// shipped scrape configuration targets.
pub const DEFAULT_NF_METRICS_PORT: u16 = 9090;

/// Distinct (service, operation, status) label sets kept before new ones are folded
/// into `service="other",operation="other"`.
pub const MAX_SBI_SERIES: usize = 1024;

/// Upper bounds of `nextgcore_sbi_request_duration_seconds` (seconds).
pub const SBI_DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// The address an NF's `/metrics` listener binds: the host from
/// `NEXTGCORE_METRICS_BIND` (loopback by default) and the port from `port_env`
/// ([`DEFAULT_NF_METRICS_PORT`] when unset). A port that does not parse is logged and
/// the default used.
pub fn nf_metrics_addr(port_env: &str) -> SocketAddr {
    nf_metrics_addr_from(
        std::env::var(crate::nes_energy::METRICS_BIND_ENV)
            .ok()
            .as_deref(),
        port_env,
        std::env::var(port_env).ok().as_deref(),
    )
}

/// [`nf_metrics_addr`] with the environment values passed in.
pub fn nf_metrics_addr_from(bind: Option<&str>, port_env: &str, port: Option<&str>) -> SocketAddr {
    let port = match port.map(str::trim).filter(|p| !p.is_empty()) {
        None => DEFAULT_NF_METRICS_PORT,
        Some(p) => p.parse().unwrap_or_else(|_| {
            log::warn!(
                "{port_env}={p:?} is not a port; the metrics endpoint uses \
                 {DEFAULT_NF_METRICS_PORT}"
            );
            DEFAULT_NF_METRICS_PORT
        }),
    };
    crate::nes_energy::metrics_bind_addr_from(bind, port)
}

/// Serve `render()` at `GET /metrics` on [`nf_metrics_addr`]`(port_env)`.
///
/// Non-fatal, like `smfd`'s: an NF that cannot expose metrics (the port is taken)
/// still serves its interfaces, so a failure is logged and `None` returned. The
/// Prometheus `up` series of the target then reports the gap.
pub async fn serve_nf_metrics(
    nf: &str,
    port_env: &str,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
    process_started();
    let addr = nf_metrics_addr(port_env);
    match crate::nes_energy::serve_metrics(addr, render).await {
        Ok((bound, handle)) => {
            log::info!("{nf} metrics endpoint on http://{bound}/metrics");
            Some((bound, handle))
        }
        Err(e) => {
            log::warn!("{nf} metrics endpoint on {addr} not available: {e}");
            None
        }
    }
}

/// `GET /metrics` from `addr` and return the body. For the NFs' tests, which scrape
/// their own endpoint; not used by any daemon.
pub async fn scrape_for_test(addr: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to the metrics endpoint");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("send the scrape");
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .await
        .expect("read the scrape");
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    reply
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

/// Whether the exposition `text` has a sample of the metric `name` (any labels).
pub fn has_series(text: &str, name: &str) -> bool {
    text.lines().filter(|l| !l.starts_with('#')).any(|l| {
        l.strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
    })
}

/// The value of the sample `series` (the metric name with its labels exactly as
/// rendered, e.g. `amf_ngap_messages_total{direction="rx",procedure="NGSetup",outcome="initiating"}`),
/// or `None` when the exposition has no such sample.
pub fn sample_value(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .filter_map(|l| l.strip_prefix(series))
        .find_map(|rest| rest.strip_prefix(' ').and_then(|v| v.trim().parse().ok()))
}

// ─── Exposition helpers ─────────────────────────────────────────────────────

/// Write a `# HELP` / `# TYPE` header.
pub fn write_header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Write one metric family with a single unlabelled sample.
pub fn write_metric(
    out: &mut String,
    name: &str,
    kind: &str,
    help: &str,
    value: impl std::fmt::Display,
) {
    write_header(out, name, kind, help);
    let _ = writeln!(out, "{name} {value}");
}

/// Escape a label value (`\`, `"` and newline, per the text exposition format).
pub fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Format a label set: `{a="x",b="y"}` (empty for no labels).
pub fn labels(pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
        .collect();
    format!("{{{}}}", body.join(","))
}

// ─── SBI server requests ────────────────────────────────────────────────────

/// The `service` label of an SBI request path: its first segment when it is an SBI
/// service name (`namf-comm`, `nudm-sdm`, ...), `nnrf-oauth2` for the NRF's
/// `/oauth2/token`, else `unknown`.
pub fn sbi_service(path: &str) -> String {
    let first = path
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    if first == "oauth2" {
        return "nnrf-oauth2".to_string();
    }
    let valid = first.len() <= 48
        && first.starts_with('n')
        && first.contains('-')
        && !first.ends_with('-')
        && first
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if valid {
        first.to_string()
    } else {
        "unknown".to_string()
    }
}

/// Prefixes of the TS 29.571 identity encodings that appear as path segments
/// (SUPI, GPSI, PEI, SUCI, external and group identifiers).
const IDENTITY_PREFIXES: [&str; 10] = [
    "imsi-", "nai-", "suci-", "gli-", "gci-", "msisdn-", "extid-", "imei-", "imeisv-", "mac-",
];

/// Whether a path segment is a resource NAME (kept in the `operation` label) rather
/// than a value (replaced by `{id}`). See the module documentation.
fn is_resource_name(segment: &str) -> bool {
    if segment.is_empty() || segment.len() > 40 {
        return false;
    }
    // Letters (resource names are kebab-case or camelCase, e.g. `pcfBindings`),
    // digits and hyphens; `@`, `.`, `:`, `%`, `+`, `=` mark NAIs, addresses and
    // encoded values.
    if !segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return false;
    }
    if segment.as_bytes().last().is_some_and(u8::is_ascii_digit)
        || !segment.as_bytes()[0].is_ascii_alphabetic() && !segment.starts_with("5g")
    {
        return false;
    }
    if IDENTITY_PREFIXES.iter().any(|p| segment.starts_with(p)) {
        return false;
    }
    // A run of three digits is part of a number, not of a name (`amf-3gpp-access`
    // and `n1-n2-messages` have runs of one).
    let mut run = 0;
    for b in segment.bytes() {
        run = if b.is_ascii_digit() { run + 1 } else { 0 };
        if run >= 3 {
            return false;
        }
    }
    // Hexadecimal of eight or more characters is an identifier (a bare UUID half,
    // a hex context reference), whatever its digits.
    let hex_only = segment.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    !(hex_only && segment.len() >= 8)
}

/// The `operation` label of an SBI request: the method and the resource path after the
/// service and version segments, every value segment replaced by `{id}`, e.g.
/// `PUT nf-instances/{id}`. At most six segments are kept.
pub fn sbi_operation(method: &str, path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let rest: &[&str] = if segments.first() == Some(&"oauth2") {
        // `/oauth2/token` has no service or version segment (TS 29.510 §6.3).
        &segments
    } else {
        let after_service = segments.get(1..).unwrap_or(&[]);
        match after_service.first() {
            // The API version (`v1`, `v2`, ...).
            Some(v)
                if v.len() >= 2
                    && v.starts_with('v')
                    && v[1..].bytes().all(|b| b.is_ascii_digit()) =>
            {
                &after_service[1..]
            }
            _ => after_service,
        }
    };
    let mut template: Vec<&str> = rest
        .iter()
        .take(6)
        .enumerate()
        .map(|(i, s)| {
            // `oauth2` ends in a digit but is the fixed root of the token endpoint.
            if is_resource_name(s) || (i == 0 && *s == "oauth2") {
                *s
            } else {
                "{id}"
            }
        })
        .collect();
    if rest.len() > 6 {
        template.push("...");
    }
    let method = match method.to_ascii_uppercase().as_str() {
        m @ ("GET" | "PUT" | "POST" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS") => m.to_string(),
        _ => "OTHER".to_string(),
    };
    if template.is_empty() {
        method
    } else {
        format!("{method} {}", template.join("/"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SbiKey {
    service: String,
    operation: String,
    status: u16,
}

#[derive(Debug, Default, Clone)]
struct Histogram {
    buckets: [u64; SBI_DURATION_BUCKETS.len()],
    count: u64,
    sum: f64,
}

impl Histogram {
    fn observe(&mut self, seconds: f64) {
        for (i, bound) in SBI_DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                self.buckets[i] += 1;
            }
        }
        self.count += 1;
        self.sum += seconds;
    }
}

#[derive(Debug, Default)]
struct SbiStats {
    requests: HashMap<SbiKey, u64>,
    durations: HashMap<String, Histogram>,
}

fn sbi_stats() -> &'static Mutex<SbiStats> {
    static STATS: OnceLock<Mutex<SbiStats>> = OnceLock::new();
    STATS.get_or_init(|| Mutex::new(SbiStats::default()))
}

/// Count one SBI request this process served and its duration: `method` and the
/// request `path` (query included or not), the response `status`.
pub fn record_sbi_request(method: &str, path: &str, status: u16, elapsed: Duration) {
    let mut key = SbiKey {
        service: sbi_service(path),
        operation: sbi_operation(method, path),
        status,
    };
    let Ok(mut stats) = sbi_stats().lock() else {
        return;
    };
    if !stats.requests.contains_key(&key) && stats.requests.len() >= MAX_SBI_SERIES {
        key.service = "other".to_string();
        key.operation = "other".to_string();
    }
    let service = key.service.clone();
    *stats.requests.entry(key).or_insert(0) += 1;
    if !stats.durations.contains_key(&service) && stats.durations.len() >= MAX_SBI_SERIES {
        return;
    }
    stats
        .durations
        .entry(service)
        .or_default()
        .observe(elapsed.as_secs_f64());
}

/// Render the SBI request families.
pub fn render_sbi(out: &mut String) {
    let Ok(stats) = sbi_stats().lock() else {
        return;
    };
    let mut rows: Vec<(&SbiKey, &u64)> = stats.requests.iter().collect();
    rows.sort_by(|a, b| {
        (&a.0.service, &a.0.operation, a.0.status).cmp(&(&b.0.service, &b.0.operation, b.0.status))
    });
    write_header(
        out,
        "nextgcore_sbi_request_total",
        "counter",
        "SBI requests this NF served, by service, operation (method and resource template) and response status",
    );
    for (k, v) in &rows {
        let status = k.status.to_string();
        let l = labels(&[
            ("service", &k.service),
            ("operation", &k.operation),
            ("status", &status),
        ]);
        let _ = writeln!(out, "nextgcore_sbi_request_total{l} {v}");
    }
    write_header(
        out,
        "nextgcore_sbi_error_total",
        "counter",
        "SBI requests this NF answered with a 4xx or 5xx status",
    );
    for (k, v) in rows.iter().filter(|(k, _)| k.status >= 400) {
        let status = k.status.to_string();
        let l = labels(&[
            ("service", &k.service),
            ("operation", &k.operation),
            ("status", &status),
        ]);
        let _ = writeln!(out, "nextgcore_sbi_error_total{l} {v}");
    }
    write_header(
        out,
        "nextgcore_sbi_request_duration_seconds",
        "histogram",
        "Time this NF took to answer an SBI request, by service",
    );
    let mut services: Vec<(&String, &Histogram)> = stats.durations.iter().collect();
    services.sort_by(|a, b| a.0.cmp(b.0));
    for (service, h) in services {
        let s = escape_label(service);
        for (bound, count) in SBI_DURATION_BUCKETS.iter().zip(h.buckets.iter()) {
            let _ = writeln!(
                out,
                "nextgcore_sbi_request_duration_seconds_bucket{{service=\"{s}\",le=\"{bound}\"}} {count}"
            );
        }
        let _ = writeln!(
            out,
            "nextgcore_sbi_request_duration_seconds_bucket{{service=\"{s}\",le=\"+Inf\"}} {}",
            h.count
        );
        let _ = writeln!(
            out,
            "nextgcore_sbi_request_duration_seconds_sum{{service=\"{s}\"}} {}",
            h.sum
        );
        let _ = writeln!(
            out,
            "nextgcore_sbi_request_duration_seconds_count{{service=\"{s}\"}} {}",
            h.count
        );
    }
}

// ─── NRF client state ───────────────────────────────────────────────────────

/// How one NRF heartbeat (NFUpdate PATCH, TS 29.510 §5.2.2.3) ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    /// 200/204: the NRF holds the profile.
    Ok,
    /// 404: the NRF no longer holds it.
    NotFound,
    /// Any other status.
    Rejected,
    /// No answer (connection or timeout).
    TransportError,
}

impl HeartbeatOutcome {
    const ALL: [HeartbeatOutcome; 4] = [
        HeartbeatOutcome::Ok,
        HeartbeatOutcome::NotFound,
        HeartbeatOutcome::Rejected,
        HeartbeatOutcome::TransportError,
    ];

    fn label(self) -> &'static str {
        match self {
            HeartbeatOutcome::Ok => "ok",
            HeartbeatOutcome::NotFound => "not_found",
            HeartbeatOutcome::Rejected => "rejected",
            HeartbeatOutcome::TransportError => "transport_error",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

static NRF_REGISTERED: AtomicBool = AtomicBool::new(false);
static NRF_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static NRF_HEARTBEATS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static NRF_LAST_HEARTBEAT_OK: AtomicU64 = AtomicU64::new(0);

/// Record whether this NF holds a registration at the NRF now.
pub fn nrf_registered(registered: bool) {
    NRF_REGISTERED.store(registered, Ordering::Release);
}

/// Whether this NF holds a registration at the NRF, as last recorded.
pub fn is_nrf_registered() -> bool {
    NRF_REGISTERED.load(Ordering::Acquire)
}

/// Count a successful NFRegister (initial or a re-registration) and mark the NF
/// registered.
pub fn nrf_registration_succeeded() {
    NRF_REGISTRATIONS.fetch_add(1, Ordering::AcqRel);
    nrf_registered(true);
}

/// Count one heartbeat. An `Ok` one also marks the NF registered and stamps the time;
/// a `NotFound` one marks it not registered (the NRF lost the profile).
pub fn nrf_heartbeat(outcome: HeartbeatOutcome) {
    NRF_HEARTBEATS[outcome.index()].fetch_add(1, Ordering::AcqRel);
    match outcome {
        HeartbeatOutcome::Ok => {
            nrf_registered(true);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            NRF_LAST_HEARTBEAT_OK.store(now, Ordering::Release);
        }
        HeartbeatOutcome::NotFound => nrf_registered(false),
        HeartbeatOutcome::Rejected | HeartbeatOutcome::TransportError => {}
    }
}

/// The count of heartbeats that ended with `outcome`.
pub fn nrf_heartbeat_count(outcome: HeartbeatOutcome) -> u64 {
    NRF_HEARTBEATS[outcome.index()].load(Ordering::Acquire)
}

/// Render the NRF client families.
pub fn render_nrf_client(out: &mut String) {
    write_metric(
        out,
        "nextgcore_nrf_registered",
        "gauge",
        "1 while this NF holds a registration at the NRF (NFRegister answered, heartbeats not answered 404)",
        u8::from(is_nrf_registered()),
    );
    write_metric(
        out,
        "nextgcore_nrf_registrations_total",
        "counter",
        "Successful NFRegister requests (TS 29.510 §5.2.2.2), re-registrations included",
        NRF_REGISTRATIONS.load(Ordering::Acquire),
    );
    write_header(
        out,
        "nextgcore_nrf_heartbeats_total",
        "counter",
        "NRF heartbeats (NFUpdate, TS 29.510 §5.2.2.3) by result",
    );
    for o in HeartbeatOutcome::ALL {
        let _ = writeln!(
            out,
            "nextgcore_nrf_heartbeats_total{{result=\"{}\"}} {}",
            o.label(),
            nrf_heartbeat_count(o)
        );
    }
    let last = NRF_LAST_HEARTBEAT_OK.load(Ordering::Acquire);
    if last > 0 {
        write_metric(
            out,
            "nextgcore_nrf_last_heartbeat_success_timestamp_seconds",
            "gauge",
            "Unix time of the last heartbeat the NRF accepted",
            last,
        );
    }
}

// ─── Process ────────────────────────────────────────────────────────────────

/// `USER_HZ`: the unit of the CPU times and start time in `/proc/<pid>/stat`. Fixed at
/// 100 by the Linux user-space ABI on every architecture, whatever the kernel's HZ.
const USER_HZ: f64 = 100.0;

fn process_started() -> Instant {
    static STARTED: OnceLock<Instant> = OnceLock::new();
    *STARTED.get_or_init(Instant::now)
}

/// A `Vm*` value from `/proc/self/status`, in bytes.
fn proc_status_bytes(status: &str, key: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with(key))?;
    let kb: u64 = line[key.len()..]
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb * 1024)
}

/// (utime + stime seconds, start time in ticks since boot) from `/proc/self/stat`.
fn proc_stat_times(stat: &str) -> Option<(f64, u64)> {
    // The command name (field 2) is parenthesised and may hold spaces.
    let after = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // Field 3 (state) is fields[0]; utime 14 -> [11], stime 15 -> [12], starttime 22 -> [19].
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    let start: u64 = fields.get(19)?.parse().ok()?;
    Some(((utime + stime) / USER_HZ, start))
}

fn boot_time() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// Render the `process_*` families (Linux; elsewhere only what is portable) and
/// `nextgcore_uptime_seconds`.
pub fn render_process(out: &mut String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let mut start_time = None;
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some((cpu, start_ticks)) = proc_stat_times(&stat) {
            write_metric(
                out,
                "process_cpu_seconds_total",
                "counter",
                "Total user and system CPU time spent in seconds",
                cpu,
            );
            if let Some(btime) = boot_time() {
                let start = btime as f64 + start_ticks as f64 / USER_HZ;
                start_time = Some(start);
                write_metric(
                    out,
                    "process_start_time_seconds",
                    "gauge",
                    "Start time of the process since unix epoch in seconds",
                    start,
                );
            }
        }
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(rss) = proc_status_bytes(&status, "VmRSS:") {
            write_metric(
                out,
                "process_resident_memory_bytes",
                "gauge",
                "Resident memory size in bytes",
                rss,
            );
        }
        if let Some(vsz) = proc_status_bytes(&status, "VmSize:") {
            write_metric(
                out,
                "process_virtual_memory_bytes",
                "gauge",
                "Virtual memory size in bytes",
                vsz,
            );
        }
    }
    if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
        write_metric(
            out,
            "process_open_fds",
            "gauge",
            "Number of open file descriptors",
            fds.count(),
        );
    }
    let uptime = match start_time {
        Some(start) if now >= start => now - start,
        _ => process_started().elapsed().as_secs_f64(),
    };
    write_metric(
        out,
        "nextgcore_uptime_seconds",
        "gauge",
        "Seconds since this NF process started",
        format!("{uptime:.3}"),
    );
}

/// What [`render_common`] needs to know about the NF.
#[derive(Debug, Clone, Copy)]
pub struct NfIdentity {
    /// The NF type in lower case (`amf`, `pcf`, ...): the `nf` label of
    /// `nextgcore_build_info`.
    pub nf: &'static str,
    /// The daemon's version (`env!("CARGO_PKG_VERSION")`).
    pub version: &'static str,
    /// Whether this NF registers at an NRF (every NF but the NRF itself), so the NRF
    /// client families are rendered.
    pub nrf_client: bool,
}

/// The families every NF exports: build info, process, SBI server, and (for an NRF
/// client) NRF registration and heartbeat state.
pub fn render_common(id: &NfIdentity) -> String {
    let mut out = String::with_capacity(4096);
    write_header(
        &mut out,
        "nextgcore_build_info",
        "gauge",
        "Constant 1, labelled with the NF type and version",
    );
    let _ = writeln!(
        out,
        "nextgcore_build_info{} 1",
        labels(&[("nf", id.nf), ("version", id.version)])
    );
    render_process(&mut out);
    render_sbi(&mut out);
    if id.nrf_client {
        render_nrf_client(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operation_label_keeps_resource_names_and_drops_every_identifier() {
        let cases = [
            (
                "PUT",
                "/nnrf-nfm/v1/nf-instances/3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "PUT nf-instances/{id}",
            ),
            (
                "GET",
                "/nudm-sdm/v2/imsi-001010000000001/am-data?plmn-id=x",
                "GET {id}/am-data",
            ),
            (
                "GET",
                "/nudm-sdm/v2/imsi-001010000000001/sm-data",
                "GET {id}/sm-data",
            ),
            (
                "PUT",
                "/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access",
                "PUT {id}/registrations/amf-3gpp-access",
            ),
            (
                "POST",
                "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages",
                "POST ue-contexts/{id}/n1-n2-messages",
            ),
            (
                "PUT",
                "/nausf-auth/v1/ue-authentications/abc123def4567/5g-aka-confirmation",
                "PUT ue-authentications/{id}/5g-aka-confirmation",
            ),
            (
                "POST",
                "/nausf-auth/v1/ue-authentications",
                "POST ue-authentications",
            ),
            (
                "GET",
                "/nudr-dr/v1/subscription-data/imsi-001010000000001/00101/provisioned-data/sm-data",
                "GET subscription-data/{id}/{id}/provisioned-data/sm-data",
            ),
            (
                "DELETE",
                "/npcf-am-policy-control/v1/policies/1",
                "DELETE policies/{id}",
            ),
            (
                "DELETE",
                "/npcf-am-policy-control/v1/policies/am-pol-12",
                "DELETE policies/{id}",
            ),
            (
                "GET",
                "/nbsf-management/v1/pcfBindings?ipv4Addr=10.45.0.2",
                "GET pcfBindings",
            ),
            (
                "DELETE",
                "/nbsf-management/v1/pcfBindings/3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "DELETE pcfBindings/{id}",
            ),
            ("GET", "/nudm-sdm/v2/DEADbeef01/am-data", "GET {id}/am-data"),
            (
                "DELETE",
                "/nbsf-management/v1/pcf-bindings/10.45.0.2",
                "DELETE pcf-bindings/{id}",
            ),
            (
                "GET",
                "/nudm-sdm/v2/msisdn-15551234567/am-data",
                "GET {id}/am-data",
            ),
            (
                "GET",
                "/nudm-sdm/v2/nai-user@realm/am-data",
                "GET {id}/am-data",
            ),
            (
                "GET",
                "/nnrf-disc/v1/nf-instances?target-nf-type=AMF",
                "GET nf-instances",
            ),
            ("POST", "/oauth2/token", "POST oauth2/token"),
            (
                "POST",
                "/nsmf-pdusession/v1/sm-contexts/deadbeefcafe/modify",
                "POST sm-contexts/{id}/modify",
            ),
            ("BREW", "/nudm-sdm/v2/x", "OTHER x"),
        ];
        for (method, path, want) in cases {
            assert_eq!(sbi_operation(method, path), want, "{method} {path}");
        }
        // No digit string of a SUPI, an IP address or a UUID survives in any of them.
        for (method, path, _) in cases {
            let op = sbi_operation(method, path);
            assert!(!op.contains("0010100"), "{op}");
            assert!(!op.contains("10.45"), "{op}");
            assert!(!op.contains("5717"), "{op}");
        }
    }

    #[test]
    fn the_service_label_is_the_sbi_service_name_or_unknown() {
        assert_eq!(sbi_service("/namf-comm/v1/ue-contexts"), "namf-comm");
        assert_eq!(
            sbi_service("/npcf-am-policy-control/v1/policies"),
            "npcf-am-policy-control"
        );
        assert_eq!(sbi_service("/oauth2/token"), "nnrf-oauth2");
        assert_eq!(sbi_service("/imsi-001010000000001/x"), "unknown");
        assert_eq!(sbi_service("/NAMF-COMM/v1"), "unknown");
        assert_eq!(sbi_service("/"), "unknown");
    }

    #[test]
    fn requests_render_as_request_error_and_duration_families() {
        let path = "/ntest-render/v1/things/imsi-001019999999999";
        record_sbi_request("GET", path, 200, Duration::from_millis(3));
        record_sbi_request("GET", path, 404, Duration::from_millis(30));
        let mut out = String::new();
        render_sbi(&mut out);
        let ok = r#"nextgcore_sbi_request_total{service="ntest-render",operation="GET things/{id}",status="200"}"#;
        let nf = r#"nextgcore_sbi_request_total{service="ntest-render",operation="GET things/{id}",status="404"}"#;
        let err = r#"nextgcore_sbi_error_total{service="ntest-render",operation="GET things/{id}",status="404"}"#;
        assert!(sample_value(&out, ok).unwrap() >= 1.0, "{out}");
        assert!(sample_value(&out, nf).unwrap() >= 1.0, "{out}");
        assert!(sample_value(&out, err).unwrap() >= 1.0, "{out}");
        assert!(
            sample_value(&out, r#"nextgcore_sbi_error_total{service="ntest-render",operation="GET things/{id}",status="200"}"#).is_none(),
            "a 200 is no error"
        );
        let count = sample_value(
            &out,
            r#"nextgcore_sbi_request_duration_seconds_count{service="ntest-render"}"#,
        )
        .unwrap();
        assert!(count >= 2.0, "{out}");
        let le_5ms = sample_value(
            &out,
            r#"nextgcore_sbi_request_duration_seconds_bucket{service="ntest-render",le="0.005"}"#,
        )
        .unwrap();
        let le_inf = sample_value(
            &out,
            r#"nextgcore_sbi_request_duration_seconds_bucket{service="ntest-render",le="+Inf"}"#,
        )
        .unwrap();
        assert!(le_5ms >= 1.0 && le_inf >= le_5ms + 1.0, "{out}");
        assert!(
            !out.contains("001019999999999"),
            "no SUPI in any label: {out}"
        );
    }

    #[test]
    fn heartbeats_drive_the_registered_gauge() {
        nrf_registration_succeeded();
        let mut out = String::new();
        render_nrf_client(&mut out);
        assert_eq!(
            sample_value(&out, "nextgcore_nrf_registered"),
            Some(1.0),
            "{out}"
        );
        let lost_before = nrf_heartbeat_count(HeartbeatOutcome::NotFound);
        nrf_heartbeat(HeartbeatOutcome::NotFound);
        assert_eq!(
            nrf_heartbeat_count(HeartbeatOutcome::NotFound),
            lost_before + 1
        );
        let mut out = String::new();
        render_nrf_client(&mut out);
        assert_eq!(
            sample_value(&out, "nextgcore_nrf_registered"),
            Some(0.0),
            "{out}"
        );
        nrf_heartbeat(HeartbeatOutcome::Ok);
        let mut out = String::new();
        render_nrf_client(&mut out);
        assert_eq!(
            sample_value(&out, "nextgcore_nrf_registered"),
            Some(1.0),
            "{out}"
        );
        assert!(has_series(
            &out,
            "nextgcore_nrf_last_heartbeat_success_timestamp_seconds"
        ));
        assert!(
            sample_value(&out, r#"nextgcore_nrf_heartbeats_total{result="ok"}"#).unwrap() >= 1.0
        );
    }

    #[test]
    fn process_families_are_read_from_proc() {
        let mut out = String::new();
        render_process(&mut out);
        assert!(has_series(&out, "nextgcore_uptime_seconds"), "{out}");
        if cfg!(target_os = "linux") {
            for name in [
                "process_cpu_seconds_total",
                "process_start_time_seconds",
                "process_resident_memory_bytes",
                "process_open_fds",
            ] {
                assert!(has_series(&out, name), "{name}: {out}");
            }
            assert!(sample_value(&out, "process_resident_memory_bytes").unwrap() > 0.0);
        }
    }

    #[test]
    fn the_metrics_address_defaults_to_loopback_9090_and_takes_the_overrides() {
        assert_eq!(
            nf_metrics_addr_from(None, "X_METRICS_PORT", None),
            "127.0.0.1:9090".parse().unwrap()
        );
        assert_eq!(
            nf_metrics_addr_from(Some("0.0.0.0"), "X_METRICS_PORT", Some("9191")),
            "0.0.0.0:9191".parse().unwrap()
        );
        assert_eq!(
            nf_metrics_addr_from(Some("not-an-ip"), "X_METRICS_PORT", Some("nope")),
            "127.0.0.1:9090".parse().unwrap()
        );
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(labels(&[("a", "x\"y\\z\n")]), "{a=\"x\\\"y\\\\z\\n\"}");
    }
}
