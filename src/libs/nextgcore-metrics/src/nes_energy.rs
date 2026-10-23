//! Network Energy Saving (NES) live energy/utilization metrics (issue #22).
//!
//! Bridges the dormant [`crate::ai_native`] energy descriptors (TS 28.310
//! KPI families) onto a LIVE Prometheus endpoint: [`EnergyGauges`] holds the
//! per-NF values behind lock-free atomics, renders the TS 28.310 energy
//! family plus a new `nf_utilization_ratio` gauge as Prometheus text, and
//! [`serve_metrics`] is a minimal real HTTP/1.1 listener serving it at
//! `/metrics` (the pre-existing [`crate::server::MetricsServer`] is a
//! non-binding stub kept for API compatibility).
//!
//! The energy numbers an NF feeds in here are expected to come from a
//! SYNTHETIC power model (no hardware counters exist in this research core);
//! callers must document their model. The NES sleep policy itself is
//! non-normative — no frozen Rel-20 Stage-3 exists.

use crate::ai_native::{AiMetricCategory, AiMetricDef};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// NF utilization ratio (0.0-1.0), the issue-#22 companion gauge to the
/// TS 28.310 energy family.
pub const NF_UTILIZATION_RATIO: AiMetricDef = AiMetricDef {
    name: "nf_utilization_ratio",
    help: "NF utilization ratio derived from the NF-supplied load (0.0-1.0)",
    category: AiMetricCategory::Energy,
    labels: &["nf_type", "nf_id"],
};

/// Lock-free f64 cell (bit-cast into an `AtomicU64`).
#[derive(Debug, Default)]
struct AtomicF64(AtomicU64);

impl AtomicF64 {
    fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }

    fn set(&self, value: f64) {
        self.0.store(value.to_bits(), Ordering::Relaxed);
    }

    /// Add (single-writer model: the NES poll tick is the only writer, so a
    /// plain read-modify-write is race-free in practice; documented).
    fn add(&self, delta: f64) {
        self.set(self.get() + delta);
    }
}

/// Live per-NF energy/utilization gauges (thread-safe, shareable).
#[derive(Debug)]
pub struct EnergyGauges {
    nf_type: String,
    nf_id: String,
    power_watts: AtomicF64,
    total_joules: AtomicF64,
    sleep_ratio: AtomicF64,
    utilization: AtomicF64,
    data_bits_total: AtomicU64,
}

impl EnergyGauges {
    pub fn new(nf_type: impl Into<String>, nf_id: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            nf_type: nf_type.into(),
            nf_id: nf_id.into(),
            power_watts: AtomicF64::default(),
            total_joules: AtomicF64::default(),
            sleep_ratio: AtomicF64::default(),
            utilization: AtomicF64::default(),
            data_bits_total: AtomicU64::new(0),
        })
    }

    pub fn set_power_watts(&self, watts: f64) {
        self.power_watts.set(watts.max(0.0));
    }

    pub fn add_joules(&self, joules: f64) {
        if joules > 0.0 {
            self.total_joules.add(joules);
        }
    }

    pub fn set_sleep_ratio(&self, ratio: f64) {
        self.sleep_ratio.set(ratio.clamp(0.0, 1.0));
    }

    pub fn set_utilization(&self, ratio: f64) {
        self.utilization.set(ratio.clamp(0.0, 1.0));
    }

    pub fn add_data_bits(&self, bits: u64) {
        self.data_bits_total.fetch_add(bits, Ordering::Relaxed);
    }

    /// TS 28.310 EE_DV: bits per joule over the whole lifetime (0 until any
    /// energy is recorded).
    pub fn bits_per_joule(&self) -> f64 {
        let joules = self.total_joules.get();
        if joules > 0.0 {
            self.data_bits_total.load(Ordering::Relaxed) as f64 / joules
        } else {
            0.0
        }
    }

    /// Register the energy family with the (dormant) `MetricsContext` spec
    /// registry so registry consumers see the definitions; the LIVE values
    /// are rendered by [`Self::render_prometheus`].
    pub fn register_specs(&self) {
        use crate::ai_native::{
            ENERGY_BITS_PER_JOULE, ENERGY_CONSUMPTION_WATTS, ENERGY_DATA_VOLUME_BITS,
            ENERGY_SLEEP_RATIO, ENERGY_TOTAL_JOULES,
        };
        use crate::context::MetricsContext;
        use crate::spec::MetricsSpec;

        MetricsContext::init();
        let Some(ctx) = MetricsContext::get() else {
            return;
        };
        let Ok(mut ctx) = ctx.write() else {
            return;
        };
        for def in [
            &ENERGY_CONSUMPTION_WATTS,
            &ENERGY_SLEEP_RATIO,
            &ENERGY_BITS_PER_JOULE,
            &NF_UTILIZATION_RATIO,
        ] {
            ctx.add_spec(MetricsSpec::gauge(def.name, def.help, 0, def.labels));
        }
        for def in [&ENERGY_TOTAL_JOULES, &ENERGY_DATA_VOLUME_BITS] {
            ctx.add_spec(MetricsSpec::counter(def.name, def.help, def.labels));
        }
    }

    /// Render the live energy family as Prometheus text-format 0.0.4.
    pub fn render_prometheus(&self) -> String {
        use crate::ai_native::{
            ENERGY_BITS_PER_JOULE, ENERGY_CONSUMPTION_WATTS, ENERGY_DATA_VOLUME_BITS,
            ENERGY_SLEEP_RATIO, ENERGY_TOTAL_JOULES,
        };

        let base = format!("nf_type=\"{}\",nf_id=\"{}\"", self.nf_type, self.nf_id);
        let mut out = String::with_capacity(1024);
        let mut emit = |def: &AiMetricDef, kind: &str, labels: &str, value: f64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name}{{{labels}}} {value}\n",
                name = def.name,
                help = def.help,
            ));
        };

        emit(
            &ENERGY_CONSUMPTION_WATTS,
            "gauge",
            &format!("{base},component=\"process\""),
            self.power_watts.get(),
        );
        emit(
            &ENERGY_TOTAL_JOULES,
            "counter",
            &base,
            self.total_joules.get(),
        );
        emit(
            &ENERGY_DATA_VOLUME_BITS,
            "counter",
            &format!("{base},direction=\"total\""),
            self.data_bits_total.load(Ordering::Relaxed) as f64,
        );
        emit(
            &ENERGY_BITS_PER_JOULE,
            "gauge",
            &format!("{base},slice_sst=\"0\""),
            self.bits_per_joule(),
        );
        emit(
            &ENERGY_SLEEP_RATIO,
            "gauge",
            &format!("{base},cell_id=\"nf\""),
            self.sleep_ratio.get(),
        );
        emit(
            &NF_UTILIZATION_RATIO,
            "gauge",
            &base,
            self.utilization.get(),
        );
        out
    }
}

/// Environment variable naming the host every NF's auxiliary listeners
/// (`/metrics`) bind to (#837).
pub const METRICS_BIND_ENV: &str = "NEXTGCORE_METRICS_BIND";

/// The host an auxiliary listener binds to when [`METRICS_BIND_ENV`] is unset:
/// loopback. The endpoint is unauthenticated and reveals per-session counters
/// and topology, so on a bare-metal or host-network deployment it must not be
/// reachable from other machines by default. Container and pod deployments set
/// `NEXTGCORE_METRICS_BIND=0.0.0.0` inside their private network, with no
/// published host port, so Prometheus can still scrape.
pub const DEFAULT_METRICS_BIND: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

/// The address an NF's `/metrics` listener binds to: the host from
/// [`METRICS_BIND_ENV`] (an IPv4 or IPv6 address) or [`DEFAULT_METRICS_BIND`],
/// and `port`. A value that is not an IP address is ignored with a warning,
/// falling back to loopback rather than to every interface.
pub fn metrics_bind_addr(port: u16) -> SocketAddr {
    metrics_bind_addr_from(std::env::var(METRICS_BIND_ENV).ok().as_deref(), port)
}

/// [`metrics_bind_addr`] with the environment value passed in.
pub fn metrics_bind_addr_from(host: Option<&str>, port: u16) -> SocketAddr {
    let ip = match host.map(str::trim).filter(|h| !h.is_empty()) {
        None => DEFAULT_METRICS_BIND,
        Some(h) => match h.trim_matches(|c| c == '[' || c == ']').parse() {
            Ok(ip) => ip,
            Err(_) => {
                log::warn!(
                    "{METRICS_BIND_ENV}={h:?} is not an IP address; the metrics endpoint \
                     stays on {DEFAULT_METRICS_BIND}"
                );
                DEFAULT_METRICS_BIND
            }
        },
    };
    SocketAddr::new(ip, port)
}

/// Serve `render()` at `GET /metrics` over a minimal real HTTP/1.1 listener
/// (`GET /` and `GET /healthz` answer `ok`; anything else is 404). Returns
/// the bound address (useful with port 0) and the accept-loop task handle.
pub async fn serve_metrics(
    addr: SocketAddr,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    serve_metrics_with(addr, render, METRICS_IO_TIMEOUT, MAX_METRICS_CONNECTIONS).await
}

/// How long a metrics client has to send its request (#837). Short, so an idle
/// client gives its slot back quickly: a scraper sends the request at once.
pub const METRICS_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// How long one metrics connection may take to receive the response (#837).
pub const METRICS_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Connections served at once; further ones are closed immediately (#837), so
/// a burst of idle clients cannot pile up tasks and sockets.
pub const MAX_METRICS_CONNECTIONS: usize = 64;

/// [`serve_metrics`] with the response timeout and the connection cap passed
/// in. The request must still arrive within the smaller of `io_timeout` and
/// [`METRICS_REQUEST_TIMEOUT`].
pub async fn serve_metrics_with(
    addr: SocketAddr,
    render: Arc<dyn Fn() -> String + Send + Sync>,
    io_timeout: std::time::Duration,
    max_connections: usize,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    log::info!("metrics endpoint listening on http://{bound}/metrics");
    let slots = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let request_timeout = io_timeout.min(METRICS_REQUEST_TIMEOUT);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                // At capacity: close at once rather than queue another task.
                drop(stream);
                continue;
            };
            let render = render.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let mut buf = vec![0u8; 4096];
                let n = match tokio::time::timeout(request_timeout, stream.read(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    // Read error, or no request within the timeout: drop it.
                    _ => return,
                };
                let head = String::from_utf8_lossy(&buf[..n]);
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let path = target.split('?').next().unwrap_or("/");
                let (status, content_type, body) = match path {
                    "/metrics" => (
                        "200 OK",
                        "text/plain; version=0.0.4; charset=utf-8",
                        render(),
                    ),
                    "/" | "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
                    _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tokio::time::timeout(io_timeout, async {
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                })
                .await;
            });
        }
    });

    Ok((bound, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connections_over_the_cap_are_closed_and_a_freed_slot_serves_again() {
        // #837 review: the cap is the DoS guard against a burst of idle clients.
        const CAP: usize = 4;
        let (bound, handle) = serve_metrics_with(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(|| "x 1\n".to_string()),
            std::time::Duration::from_secs(30),
            CAP,
        )
        .await
        .unwrap();
        // CAP idle clients take every slot (their 1 s request timeout has not
        // run out yet when the next one arrives).
        let mut idle = Vec::new();
        for _ in 0..CAP {
            idle.push(tokio::net::TcpStream::connect(bound).await.unwrap());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut over = tokio::net::TcpStream::connect(bound).await.unwrap();
        let _ = over.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").await;
        let mut sink = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            over.read_to_end(&mut sink),
        )
        .await;
        assert!(
            closed.is_ok(),
            "a connection over the cap is closed at once"
        );
        assert!(sink.is_empty(), "and is answered nothing: {sink:?}");

        // Free one slot; a real request is answered again.
        drop(idle.pop());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut client = tokio::net::TcpStream::connect(bound).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        handle.abort();
    }

    #[tokio::test]
    async fn an_idle_metrics_client_is_dropped_after_the_io_timeout() {
        // #837: a client that connects and sends nothing used to hold its task
        // forever. With the timeout the server closes it.
        let (bound, handle) = serve_metrics_with(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(|| "x 1\n".to_string()),
            std::time::Duration::from_millis(200),
            MAX_METRICS_CONNECTIONS,
        )
        .await
        .unwrap();
        let mut idle = tokio::net::TcpStream::connect(bound).await.unwrap();
        let mut sink = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            idle.read_to_end(&mut sink),
        )
        .await;
        assert!(closed.is_ok(), "the server must close an idle connection");
        assert!(
            sink.is_empty(),
            "nothing is sent to a client that asked nothing"
        );

        // A real request is still answered.
        let mut client = tokio::net::TcpStream::connect(bound).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        assert!(reply.ends_with("x 1\n"), "{reply}");
        handle.abort();
    }

    #[test]
    fn metrics_bind_defaults_to_loopback_and_honours_the_override() {
        // #837: unset, blank or garbage never means every interface.
        for host in [
            None,
            Some(""),
            Some("  "),
            Some("not-an-ip"),
            Some("0.0.0.0.0"),
        ] {
            let addr = metrics_bind_addr_from(host, 9090);
            assert!(addr.ip().is_loopback(), "{host:?} -> {addr}");
            assert_eq!(addr.port(), 9090);
        }
        assert_eq!(
            metrics_bind_addr_from(Some("0.0.0.0"), 9091).to_string(),
            "0.0.0.0:9091"
        );
        assert_eq!(
            metrics_bind_addr_from(Some("[::]"), 9090).to_string(),
            "[::]:9090"
        );
        assert_eq!(
            metrics_bind_addr_from(Some("10.0.0.7"), 9090).to_string(),
            "10.0.0.7:9090"
        );
    }
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    #[test]
    fn atomic_f64_roundtrip() {
        let cell = AtomicF64::default();
        assert_eq!(cell.get(), 0.0);
        cell.set(12.75);
        assert_eq!(cell.get(), 12.75);
        cell.add(0.25);
        assert_eq!(cell.get(), 13.0);
    }

    #[test]
    fn gauges_render_all_energy_families_with_labels() {
        let gauges = EnergyGauges::new("UDM", "udm-test-1");
        gauges.set_power_watts(42.5);
        gauges.add_joules(100.0);
        gauges.add_data_bits(1_000_000);
        gauges.set_sleep_ratio(0.25);
        gauges.set_utilization(0.5);

        let text = gauges.render_prometheus();
        for family in [
            "energy_consumption_watts",
            "energy_consumed_joules_total",
            "energy_data_volume_bits_total",
            "energy_efficiency_bits_per_joule",
            "energy_sleep_ratio",
            "nf_utilization_ratio",
        ] {
            assert!(text.contains(&format!("# TYPE {family} ")), "{family} TYPE");
            assert!(
                text.contains(&format!("{family}{{")),
                "{family} sample line"
            );
        }
        assert!(text.contains("nf_type=\"UDM\",nf_id=\"udm-test-1\""));
        assert!(text.contains("energy_consumption_watts{nf_type=\"UDM\",nf_id=\"udm-test-1\",component=\"process\"} 42.5"));
        // EE_DV = 1e6 bits / 100 J = 10000 bits/J.
        assert!(text.contains("energy_efficiency_bits_per_joule{nf_type=\"UDM\",nf_id=\"udm-test-1\",slice_sst=\"0\"} 10000"));
        assert!(text.contains("nf_utilization_ratio{nf_type=\"UDM\",nf_id=\"udm-test-1\"} 0.5"));
    }

    #[test]
    fn gauges_clamp_and_guard() {
        let gauges = EnergyGauges::new("UDM", "udm-x");
        gauges.set_sleep_ratio(7.0);
        gauges.set_utilization(-3.0);
        gauges.set_power_watts(-1.0);
        assert!(gauges
            .render_prometheus()
            .contains("energy_sleep_ratio{nf_type=\"UDM\",nf_id=\"udm-x\",cell_id=\"nf\"} 1"));
        assert!(gauges
            .render_prometheus()
            .contains("nf_utilization_ratio{nf_type=\"UDM\",nf_id=\"udm-x\"} 0"));
        // No energy recorded → bits/J stays 0 (no div-by-zero).
        assert_eq!(gauges.bits_per_joule(), 0.0);
    }

    #[test]
    fn register_specs_populates_the_registry() {
        let gauges = EnergyGauges::new("UDM", "udm-spec");
        gauges.register_specs();
        let ctx = crate::context::MetricsContext::get().expect("initialized");
        let ctx = ctx.read().expect("read");
        let names: Vec<String> = ctx.specs().iter().map(|s| s.name().to_string()).collect();
        assert!(names.iter().any(|n| n == "energy_consumption_watts"));
        assert!(names.iter().any(|n| n == "nf_utilization_ratio"));
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        String::from_utf8_lossy(&response).to_string()
    }

    /// Acceptance (issue #22): a real HTTP GET of /metrics returns the
    /// energy family and the utilization gauge.
    #[tokio::test]
    async fn serve_metrics_answers_real_http() {
        let gauges = EnergyGauges::new("UDM", "udm-http");
        gauges.set_power_watts(5.0);
        let render_gauges = gauges.clone();
        let (bound, handle) = serve_metrics(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(move || render_gauges.render_prometheus()),
        )
        .await
        .expect("bind");

        let response = http_get(bound, "/metrics").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("energy_consumption_watts"));
        assert!(response.contains("nf_utilization_ratio"));

        let health = http_get(bound, "/healthz").await;
        assert!(health.starts_with("HTTP/1.1 200 OK"));

        let missing = http_get(bound, "/nope").await;
        assert!(missing.starts_with("HTTP/1.1 404"));

        handle.abort();
    }
}
