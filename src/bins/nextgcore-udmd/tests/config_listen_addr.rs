//! #1312: udmd binds `udm.sbi.server[0]` from its YAML config when the command
//! line names no SBI address, and `--sbi-addr` / `--sbi-port` override it (they
//! used to lose to the YAML).

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port(ip: &str) -> u16 {
    TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(config: &std::path::Path, extra: &[&str]) -> Killed {
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-udmd"))
            .arg("-c")
            .arg(config)
            .args(extra)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env_remove("NEXTGCORE_SBI_ADVERTISE")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn udmd"),
    )
}

fn listening(addr: SocketAddr, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn udmd_binds_its_yaml_sbi_address_unless_the_command_line_overrides() {
    let dir = std::env::temp_dir().join(format!("udmd-1312-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 127.0.0.2: on loopback, but not the 127.0.0.1 default.
    let port = free_port("127.0.0.2");
    let config = dir.join("udm.yaml");
    std::fs::write(
        &config,
        format!("udm:\n  sbi:\n    server:\n      - address: 127.0.0.2\n        port: {port}\n"),
    )
    .unwrap();
    {
        let _nf = start(&config, &[]);
        let yaml: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
        assert!(
            listening(yaml, Duration::from_secs(40)),
            "the YAML address is bound"
        );
    }
    let cli_port = free_port("127.0.0.1");
    let _nf = start(
        &config,
        &[
            "--sbi-addr",
            "127.0.0.1",
            "--sbi-port",
            &cli_port.to_string(),
        ],
    );
    let cli: SocketAddr = format!("127.0.0.1:{cli_port}").parse().unwrap();
    assert!(
        listening(cli, Duration::from_secs(40)),
        "the command line beats the YAML"
    );
    let yaml: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
    assert!(
        TcpStream::connect_timeout(&yaml, Duration::from_millis(200)).is_err(),
        "and the YAML address is not bound as well"
    );
}
