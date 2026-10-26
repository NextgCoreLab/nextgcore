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
