//! SBA transport benchmark harness (issue #15, non-normative 6G research).
//!
//! Measures a warm GET round-trip (one reused connection, new stream per
//! request) over the SBI loopback for each transport:
//!
//! - `h2c`    — the production path: prior-knowledge HTTP/2 over plaintext
//!   TCP, `SbiClient` → `SbiServer` (TS 29.500 baseline).
//! - `h2-tls` — the same path over TLS 1.2/1.3 (rustls, self-signed cert).
//! - `h3`     — the feature-gated HTTP/3-over-QUIC prototype
//!   (`--features http3`); QUIC has no plaintext mode, so compare it against
//!   `h2-tls`, not `h2c`.
//!
//! Every transport serves the identical JSON body from the identical
//! `SbiRequestHandler` closure. The measured client path includes the real
//! `SbiClient` per-request costs (traceparent stamping, timeout wrappers,
//! body/header conversion) — this benchmarks the SBI stack as NFs use it,
//! not the bare wire.
//!
//! Run: `cargo bench -p nextgcore-sbi` (baseline) or
//! `cargo bench -p nextgcore-sbi --features http3` (adds the h3 rows).

use std::net::SocketAddr;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput};
use nextgcore_sbi::{
    SbiClient, SbiClientConfig, SbiRequest, SbiResponse, SbiServer, SbiServerConfig,
};

const PATH: &str = "/nbench/v1/fixed";
const BODY_SIZES: [usize; 2] = [256, 16 * 1024];

/// ASCII JSON body of exactly `len` bytes (ASCII survives the client's
/// lossy UTF-8 conversion byte-for-byte).
fn json_body(len: usize) -> String {
    let prefix = r#"{"data":""#;
    let suffix = r#""}"#;
    let fill = len
        .checked_sub(prefix.len() + suffix.len())
        .expect("body length too small");
    format!("{prefix}{}{suffix}", "x".repeat(fill))
}

/// Fixed-body handler shared by every transport under test.
fn fixed_body_handler(
    body: Arc<String>,
) -> impl Fn(SbiRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = SbiResponse> + Send>>
       + Clone {
    move |_request: SbiRequest| {
        let body = Arc::clone(&body);
        Box::pin(async move { SbiResponse::ok().with_body(body.as_str(), "application/json") })
    }
}

/// Pick a free loopback port (probe-bind-drop; single-process bench, and
/// server starts retry to absorb the small TOCTOU window).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe bind")
        .local_addr()
        .expect("probe addr")
        .port()
}

/// Start an `SbiServer` on a free port, retrying if the probed port was
/// stolen between probe and bind.
async fn start_h2_server<H>(
    make_config: impl Fn(SocketAddr) -> SbiServerConfig,
    handler: H,
) -> (SbiServer, u16)
where
    H: Fn(SbiRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = SbiResponse> + Send>>
        + Clone
        + Send
        + Sync
        + 'static,
{
    for _ in 0..5 {
        let port = free_port();
        let server = SbiServer::new(make_config(SocketAddr::from(([127, 0, 0, 1], port))));
        if server.start(handler.clone()).await.is_ok() {
            return (server, port);
        }
    }
    panic!("could not bind an SbiServer after 5 attempts");
}

/// One warm GET against an `SbiClient`, asserting success and full body.
async fn h2_get(client: &SbiClient, expected_len: usize) {
    let response = client.get(PATH).await.expect("GET round-trip");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.http.content.as_deref().map(str::len),
        Some(expected_len)
    );
}

/// One warm GET against an `Http3Client`, asserting success and full body.
#[cfg(feature = "http3")]
async fn h3_get(client: &nextgcore_sbi::Http3Client, expected_len: usize) {
    let response = client.get(PATH).await.expect("h3 GET round-trip");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.http.content.as_deref().map(str::len),
        Some(expected_len)
    );
}

fn bench_transports(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("sbi_get_roundtrip");

    for len in BODY_SIZES {
        let body = Arc::new(json_body(len));
        let handler = fixed_body_handler(Arc::clone(&body));
        group.throughput(Throughput::Bytes(len as u64));

        // --- h2c: prior-knowledge HTTP/2 over plaintext TCP (production path).
        {
            let (server, port) =
                rt.block_on(start_h2_server(SbiServerConfig::new, handler.clone()));
            let client = SbiClient::new(SbiClientConfig::new("127.0.0.1", port).with_pool_size(1));
            rt.block_on(h2_get(&client, len)); // warm the pooled connection
            group.bench_function(BenchmarkId::new("h2c", len), |b| {
                b.iter(|| rt.block_on(h2_get(&client, len)));
            });
            rt.block_on(async {
                client.close().await;
                server.stop().await.expect("h2c server stop");
            });
        }

        // --- h2-tls: the same HTTP/2 path over TLS (self-signed, rustls).
        {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("self-signed cert");
            let dir =
                std::env::temp_dir().join(format!("nextgcore-sbi-bench-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("bench temp dir");
            let cert_path = dir.join("cert.pem");
            let key_path = dir.join("key.pem");
            std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
            std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

            let make_config = |addr: SocketAddr| {
                SbiServerConfig::new(addr).with_tls(
                    key_path.to_str().expect("key path"),
                    cert_path.to_str().expect("cert path"),
                )
            };
            let (server, port) = rt.block_on(start_h2_server(make_config, handler.clone()));
            let mut config = SbiClientConfig::new("127.0.0.1", port)
                .with_https()
                .with_pool_size(1);
            config.insecure_skip_verify = true; // self-signed loopback cert
            let client = SbiClient::new(config);
            rt.block_on(h2_get(&client, len));
            group.bench_function(BenchmarkId::new("h2-tls", len), |b| {
                b.iter(|| rt.block_on(h2_get(&client, len)));
            });
            rt.block_on(async {
                client.close().await;
                server.stop().await.expect("h2-tls server stop");
            });
            let _ = std::fs::remove_dir_all(&dir);
        }

        // --- h3: HTTP/3-over-QUIC prototype (feature-gated).
        #[cfg(feature = "http3")]
        {
            use nextgcore_sbi::{Http3Client, Http3LoopbackServer, Http3ServerConfig};

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("self-signed cert");
            let cert_der = cert.cert.der().to_vec();
            let (server, client) = rt.block_on(async {
                let server = Http3LoopbackServer::start(
                    Http3ServerConfig {
                        addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                        cert_der: cert_der.clone(),
                        key_der: cert.key_pair.serialize_der(),
                    },
                    handler.clone(),
                )
                .await
                .expect("http3 server");
                let client = Http3Client::connect(server.local_addr(), &cert_der)
                    .await
                    .expect("http3 client");
                (server, client)
            });
            rt.block_on(h3_get(&client, len)); // warm the QUIC connection
            group.bench_function(BenchmarkId::new("h3", len), |b| {
                b.iter(|| rt.block_on(h3_get(&client, len)));
            });
            rt.block_on(async {
                client.close().await;
                server.stop().await;
            });
        }
    }

    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_transports(&mut criterion);
    criterion.final_summary();
}
