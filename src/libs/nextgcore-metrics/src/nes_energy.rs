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

/// Serve `render()` at `GET /metrics` over a minimal real HTTP/1.1 listener
/// (`GET /` and `GET /healthz` answer `ok`; anything else is 404). Returns
/// the bound address (useful with port 0) and the accept-loop task handle.
pub async fn serve_metrics(
    addr: SocketAddr,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    log::info!("NES metrics endpoint listening on http://{bound}/metrics");

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            let render = render.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
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
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok((bound, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
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
