//! The shipped dev PKI for tests that run a real `nextgcore-nrfd` binary.
//!
//! Since #1617 step f the NRF refuses NFRegister / NFUpdate / NFDeregister from
//! a caller with no verified certificate identity, plaintext included, so a test
//! that has a real NF register at a real nrfd runs both over TLS with
//! certificates from `docker/rust/certs/generate-dev-certs.sh` (the generator
//! every deployment issues from; TS 33.310 §6.1.3c.3 profile: a `urn:uuid` URI
//! SAN and the RFC 9310 NFTypes extension).

use std::path::{Path, PathBuf};
use std::process::Command;

/// A dev PKI issued into a fresh temporary directory, removed on drop (it holds
/// private keys).
pub struct DevPki {
    dir: PathBuf,
    nrf_id: String,
}

impl DevPki {
    /// Issue `nrf` (the NRF's certificate, instance `nrf_id`) and one certificate
    /// per `(name, nfType, nfInstanceId)` row through the shipped generator.
    /// Every certificate names `DNS:<name>`, so clients verify the NRF as `nrf`.
    ///
    /// # Panics
    ///
    /// When bash/openssl are missing or the generator fails.
    pub fn generate(nrf_id: &str, rows: &[(&str, &str, &str)]) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir =
            std::env::temp_dir().join(format!("nextgcore-dev-pki-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dev PKI directory");
        let mut table = format!("nrf NRF {nrf_id} -\n");
        for (name, nf_type, id) in rows {
            table.push_str(&format!("{name} {nf_type} {id} -\n"));
        }
        let ids = dir.join("ids.txt");
        std::fs::write(&ids, table).expect("identity table");
        let out = Command::new("bash")
            .arg(root.join("docker/rust/certs/generate-dev-certs.sh"))
            .arg("--out")
            .arg(&dir)
            .arg("--ids")
            .arg(&ids)
            .output()
            .expect("run generate-dev-certs.sh (needs bash and openssl)");
        assert!(
            out.status.success(),
            "generate-dev-certs.sh failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Self {
            dir,
            nrf_id: nrf_id.to_string(),
        }
    }

    /// The path of an issued file (`ca.crt`, `<name>.crt`, `<name>.key`).
    pub fn file(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }

    /// Environment for a `nextgcore-nrfd` child: its listener serves TLS with
    /// `nrf.crt`, client authentication optional (the shipped setting), and its
    /// instance ID is the one `nrf.crt` names, so its own token client presents
    /// that certificate.
    pub fn nrf_server_env(&self, cmd: &mut Command) {
        cmd.env("NEXTGCORE_NRF_SERVER_TLS", "true")
            .env("NEXTGCORE_NRF_SERVER_TLS_CERT", self.file("nrf.crt"))
            .env("NEXTGCORE_NRF_SERVER_TLS_KEY", self.file("nrf.key"))
            .env("NEXTGCORE_NRF_SERVER_TLS_CA", self.file("ca.crt"))
            .env("NEXTGCORE_NRF_SERVER_TLS_CLIENT_AUTH", "optional")
            .env("NEXTGCORE_NRF_INSTANCE_ID", &self.nrf_id);
    }

    /// Environment for an NRF client child presenting certificate `name`, and
    /// verifying the NRF as `nrf` (the name `nrf.crt` carries) against the CA.
    pub fn nrf_client_env(&self, cmd: &mut Command, name: &str) {
        cmd.env("NEXTGCORE_NRF_TLS_CA", self.file("ca.crt"))
            .env(
                "NEXTGCORE_NRF_TLS_CLIENT_CERT",
                self.file(&format!("{name}.crt")),
            )
            .env(
                "NEXTGCORE_NRF_TLS_CLIENT_KEY",
                self.file(&format!("{name}.key")),
            )
            .env("NEXTGCORE_NRF_TLS_SERVER_NAME", "nrf");
    }

    /// An in-process client of the NRF at `127.0.0.1:port`: https, verifying
    /// the NRF as `nrf`, presenting no certificate (discovery needs none).
    pub fn nrf_client_config(&self, port: u16) -> crate::client::SbiClientConfig {
        let mut c = crate::client::SbiClientConfig::new("127.0.0.1", port)
            .with_https()
            .with_tls_server_name("nrf");
        c.ca_cert = Some(self.file("ca.crt"));
        c
    }
}

impl Drop for DevPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
