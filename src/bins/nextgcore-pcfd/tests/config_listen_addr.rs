//! #1312: pcfd binds `pcf.sbi.server[0]` from its YAML config when the command
//! line names no SBI address, and `--sbi-addr` / `--sbi-port` override it (they
//! used to lose to the YAML).

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use nextgcore_sbi::test_support::{NfProcess, NfSpawn};

/// Spawn pcfd and wait until `ip:port` accepts, `port` being the one this spawn
/// hands it. `config(port)` writes its YAML and `extra(port)` gives its extra
/// arguments, once per spawn.
///
/// #1521: through the shared `NfSpawn`, which respawns on a fresh port when
/// pcfd loses a probed one to another process (the #1497 race: a sibling's
/// outbound connection can be handed it as a source port before pcfd binds).
fn start(
    ip: &str,
    config: impl Fn(u16) -> std::path::PathBuf,
    extra: impl Fn(u16) -> Vec<String>,
) -> NfProcess {
    NfSpawn::new(
        env!("CARGO_BIN_EXE_nextgcore-pcfd"),
        &format!("pcfd-listen-{ip}"),
    )
    .ready_when_accepting(ip.parse().unwrap())
    .within(Duration::from_secs(40))
    .spawn(|cmd, port, _| {
        let config = config(port);
        cmd.arg("-c")
            .arg(&config)
            .args(extra(port))
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env_remove("NEXTGCORE_SBI_ADVERTISE");
    })
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
fn pcfd_binds_its_yaml_sbi_address_unless_the_command_line_overrides() {
    let dir = std::env::temp_dir().join(format!("pcfd-1312-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 127.0.0.2: on loopback, but not the 127.0.0.1 default.
    let config = dir.join("pcf.yaml");
    let yaml_nf = start(
        "127.0.0.2",
        |port| {
            std::fs::write(
                &config,
                format!(
                    "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.2\n        port: {port}\n"
                ),
            )
            .unwrap();
            config.clone()
        },
        |_| Vec::new(),
    );
    let port = yaml_nf.port();
    {
        let _nf = yaml_nf;
        let yaml: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
        assert!(
            listening(yaml, Duration::from_secs(40)),
            "the YAML address is bound"
        );
    }
    let cli_nf = start(
        "127.0.0.1",
        |_| config.clone(),
        |port| {
            vec![
                "--sbi-addr".to_string(),
                "127.0.0.1".to_string(),
                "--sbi-port".to_string(),
                port.to_string(),
            ]
        },
    );
    let cli_port = cli_nf.port();
    let _nf = cli_nf;
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
