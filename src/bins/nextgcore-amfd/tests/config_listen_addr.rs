//! #1311: amfd binds the NGAP and SBI addresses of its YAML config
//! (`amf.ngap.server`, `amf.sbi.server`) when neither the command line nor the
//! environment names one; `--ngap-addr` overrides the YAML.

use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_tcp(ip: &str) -> u16 {
    TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp(ip: &str) -> u16 {
    UdpSocket::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(config: &std::path::Path, extra: &[&str]) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-amfd"))
            .arg("-c")
            .arg(config)
            .args(extra)
            .env_remove("AMF_SBI_ADDR")
            .env_remove("AMF_SBI_PORT")
            .env_remove("NEXTGCORE_SBI_ADVERTISE")
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn amfd"),
    )
}

fn wait(what: impl Fn() -> bool, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if what() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The userspace NGAP backend is SCTP over UDP: a bound address refuses a second bind.
fn udp_taken(addr: SocketAddr) -> bool {
    UdpSocket::bind(addr).is_err()
}

#[test]
fn amfd_binds_its_yaml_ngap_and_sbi_addresses_unless_overridden() {
    let dir = std::env::temp_dir().join(format!("amfd-1311-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 127.0.0.2: loopback, but not the 127.0.0.1 default.
    let ngap = free_udp("127.0.0.2");
    let sbi = free_tcp("127.0.0.2");
    let config = dir.join("amf.yaml");
    std::fs::write(
        &config,
        format!(
            "amf:\n  sbi:\n    server:\n      - address: 127.0.0.2\n        port: {sbi}\n  \
             ngap:\n    server:\n      - address: 127.0.0.2\n        port: {ngap}\n"
        ),
    )
    .unwrap();
    {
        let _amfd = start(&config, &[]);
        let sbi_addr: SocketAddr = format!("127.0.0.2:{sbi}").parse().unwrap();
        assert!(
            wait(
                || TcpStream::connect_timeout(&sbi_addr, Duration::from_millis(100)).is_ok(),
                Duration::from_secs(20)
            ),
            "amf.sbi.server is bound"
        );
        let ngap_addr: SocketAddr = format!("127.0.0.2:{ngap}").parse().unwrap();
        assert!(udp_taken(ngap_addr), "amf.ngap.server is bound");
    }
    let cli = free_udp("127.0.0.1");
    let cli_addr: SocketAddr = format!("127.0.0.1:{cli}").parse().unwrap();
    let _amfd = start(&config, &["--ngap-addr", &cli_addr.to_string()]);
    assert!(
        wait(|| udp_taken(cli_addr), Duration::from_secs(20)),
        "--ngap-addr wins"
    );
}

/// #1322: a wildcard SBI bind with nothing reachable to advertise refuses to start
/// (before any socket is bound), rather than hand 0.0.0.0 to peers in its callback
/// URIs and NFProfile.
#[test]
fn amfd_refuses_a_wildcard_sbi_bind_with_nothing_to_advertise() {
    let dir = std::env::temp_dir().join(format!("amfd-1322-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("amf.yaml");
    std::fs::write(
        &config,
        // Port 1: were the check gone, the bind would fail (unprivileged), so no
        // wildcard is ever bound; the stderr says which check refused it.
        "amf:\n  sbi:\n    server:\n      - address: 0.0.0.0\n        port: 1\n",
    )
    .unwrap();
    let mut amfd = Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-amfd"))
            .arg("-c")
            .arg(&config)
            .env_remove("AMF_SBI_ADDR")
            .env_remove("AMF_SBI_PORT")
            .env_remove("NEXTGCORE_SBI_ADVERTISE")
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn amfd"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = amfd.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let status = status.expect("amfd exits instead of advertising 0.0.0.0");
    assert!(!status.success());
    let mut stderr = String::new();
    if let Some(mut pipe) = amfd.0.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
    }
    assert!(stderr.contains("refusing to start"), "{stderr}");
}
