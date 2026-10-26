//! #1311: nrfd binds the SBI address of its YAML config (`nrf.sbi.server`) when
//! the command line names none, and `--sbi-addr` overrides it.

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
    let dir = config.parent().unwrap();
    Killed(
        Command::new(env!("CARGO_BIN_EXE_nextgcore-nrfd"))
            .arg("-c")
            .arg(config)
            .args(extra)
            .arg("--signing-key-file")
            .arg(dir.join("key.pem"))
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn nrfd"),
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
fn nrfd_binds_its_yaml_sbi_address_unless_the_command_line_overrides() {
    let dir = std::env::temp_dir().join(format!("nrfd-1311-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 127.0.0.2: on loopback, but not the 127.0.0.1 default, so only the YAML
    // can have put the listener there.
    let port = free_port("127.0.0.2");
    let config = dir.join("nrf.yaml");
    std::fs::write(
        &config,
        format!("nrf:\n  sbi:\n    server:\n      - address: 127.0.0.2\n        port: {port}\n"),
    )
    .unwrap();
    {
        let _nrfd = start(&config, &[]);
        let yaml: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
        assert!(
            listening(yaml, Duration::from_secs(20)),
            "the YAML address is bound"
        );
        let default: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert!(
            !listening(default, Duration::from_millis(300)),
            "not the default"
        );
    }
    let cli_port = free_port("127.0.0.1");
    let _nrfd = start(
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
        listening(cli, Duration::from_secs(20)),
        "the command line wins"
    );
}
