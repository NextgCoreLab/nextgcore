//! EASDF selection and DNS-context lifecycle (issue #114).
//!
//! TS 23.501 §5.6.7 / TS 23.548: for an edge-enabled PDU session the SMF
//! **selects an EASDF** and drives its DNS handling — creating a DNS context at
//! session establishment and deleting it at release.
//!
//! # Why this module exists
//!
//! Before it, nothing in the workspace selected an EASDF or created a DNS
//! context: a `grep` for `neasdf` across `src/bins/` found only easdfd itself and
//! two enum entries in `nextgcore-sbi`. So the EASDF's whole northbound surface
//! had **no driver** — it could be exercised by hand with `curl` and by nothing
//! else. That is the sub-item #114 itself names as highest value.
//!
//! # Off by default
//!
//! Gated on `--easdf` / `SMF_EASDF` (default off). Edge DNS steering is not part
//! of a plain PDU session, the EASDF is off by default in this stack, and an
//! unreachable EASDF must not be able to slow or fail session establishment for
//! deployments that do not use it.
//!
//! The issue suggests a *cargo feature*. A runtime switch is used instead, for
//! the same reason as dccfd's coordination switch (#112): CI builds default
//! features, so a cargo feature would leave this path **uncompiled** in CI, where
//! it would rot. A runtime switch is compiled always and exercised in both states
//! by one `cargo test` run.
//!
//! # Failure posture
//!
//! Every failure here is **non-fatal to the session**. A session that cannot get
//! edge DNS steering is still a working session; refusing it would turn an
//! EASDF outage into a total service outage for edge-enabled DNNs. Failures are
//! logged with the consequence named.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::message::SbiRequest;

/// Is the EASDF leg enabled for this process?
static EASDF_ENABLED: AtomicBool = AtomicBool::new(false);

/// The NRF used to discover an EASDF, and the SMF's own callback root.
///
/// A `RwLock<Option<_>>` and not a `OnceLock`: production sets it once at
/// startup either way, but a `OnceLock` cannot be re-set, so two tests
/// installing two configs would silently share whichever won — and the second
/// test would then dial the first one's (stopped) loopback NRF. That is exactly
/// how `releasing_a_session_deletes_its_easdf_dns_context` failed on its first
/// run.
static EASDF_CONFIG: RwLock<Option<EasdfConfig>> = RwLock::new(None);

/// What the EASDF leg needs to discover an EASDF and to be reported to.
#[derive(Debug, Clone)]
pub struct EasdfConfig {
    /// NRF root, e.g. `http://127.0.0.1:7777`.
    pub nrf_uri: String,
    /// Where the EASDF should send DNS-message reports for sessions this SMF
    /// creates. Supplied as the context's notification URI.
    pub report_uri: String,
    /// FQDN patterns this deployment treats as edge-served, one DNS
    /// handling rule per pattern. Supplied by the operator alongside the switch
    /// (`--easdf-edge-fqdn`), because there is no other source of truth for it in
    /// this tree: guessing which FQDNs are edge-served would install rules for
    /// traffic the operator never designated as edge.
    ///
    /// Empty means no session gets a DNS context, which is why enabling the
    /// switch without naming a pattern is logged as a no-op at startup.
    pub edge_fqdn_patterns: Vec<String>,
}

/// Enable the EASDF leg (called once at startup when `SMF_EASDF` is set).
pub fn enable(config: EasdfConfig) {
    if let Ok(mut slot) = EASDF_CONFIG.write() {
        *slot = Some(config);
    }
    EASDF_ENABLED.store(true, Ordering::SeqCst);
    log::info!("[SMF] EASDF DNS-context leg ENABLED (TS 23.501 §5.6.7)");
}

/// Whether the EASDF leg is enabled.
pub fn enabled() -> bool {
    EASDF_ENABLED.load(Ordering::SeqCst)
}

/// Test-only: enable/disable without going through startup.
///
/// `EASDF_ENABLED` is a static and `EASDF_CONFIG` a `RwLock`, so a test that toggles
/// either while a sibling is mid-flight changes the sibling's answer — which is
/// exactly how the two tests in this module failed on their first run (#114).
///
/// The caller must therefore hold [`crate::context::PROCESS_STATE_TEST_LOCK`]. This
/// module kept a switch lock of its own until #308, which showed that one lock per
/// switch cannot order a test that names no switch at all.
#[cfg(test)]
pub fn set_for_test(config: Option<EasdfConfig>) {
    let enabled = config.is_some();
    if let Ok(mut slot) = EASDF_CONFIG.write() {
        *slot = config;
    }
    EASDF_ENABLED.store(enabled, Ordering::SeqCst);
}

/// A snapshot of the config, cloned so no lock is held across an `await`.
fn config() -> Option<EasdfConfig> {
    if !enabled() {
        return None;
    }
    EASDF_CONFIG.read().ok()?.clone()
}

/// Should a DNS context be created at all?
///
/// A **pure** function over the config so the decision is testable without the
/// process-global switch. `EASDF_CONFIG` is a `OnceLock`: it can be set once per
/// process, so two tests cannot install two different configs, and a test that
/// tried would silently assert against whichever one won the race.
fn should_create(cfg: Option<&EasdfConfig>) -> bool {
    matches!(cfg, Some(c) if !c.edge_fqdn_patterns.is_empty())
}

/// Create a DNS context on an EASDF for a newly established session (#114).
///
/// Returns the EASDF-assigned context id, to be stored on the session so the
/// matching delete can be issued at release. `None` means no context exists — the
/// leg is disabled, no EASDF is registered, or the EASDF refused — and the
/// session proceeds without edge DNS steering.
///
/// The created context carries a DNS message-handling rule per edge FQDN pattern
/// this DNN is configured for, each asking for a report so this SMF learns the
/// resolved EAS address and can drive UL-CL / PSA re-selection.
pub async fn create_dns_context(
    supi: &str,
    pdu_session_id: u8,
    dnn: &str,
    ue_ipv4: std::net::Ipv4Addr,
) -> Option<String> {
    let cfg = config()?;
    if !should_create(Some(&cfg)) {
        // Not an edge-enabled deployment: TS 23.501 §5.6.7 applies to sessions
        // that need edge DNS handling, and creating a context with no rules would
        // ask the EASDF to store something inert.
        log::debug!("[{supi}] DNN {dnn} has no edge FQDN patterns; no DNS context created");
        return None;
    }
    let edge_fqdn_patterns = &cfg.edge_fqdn_patterns;

    let (host, port) = discover_easdf(&cfg.nrf_uri).await?;
    let body = serde_json::json!({
        "supi": supi,
        "pduSessionId": pdu_session_id,
        "dnn": dnn,
        // #276: the UE's own address. Without it the EASDF can serve this
        // session's rules over the SBI shim only -- a DNS query arriving on
        // UDP/53 carries no context id, so the source address is the sole
        // correlator between a datagram and a session.
        "ueIpv4Address": ue_ipv4.to_string(),
        "notificationUri": cfg.report_uri,
        // One rule per configured edge pattern. `reportInd` is what makes the
        // EASDF tell this SMF what it resolved -- without it the context would be
        // installed and the SMF would still learn nothing.
        "dnsHandlingRules": edge_fqdn_patterns
            .iter()
            .map(|pattern| serde_json::json!({
                "domainNames": [pattern],
                "reportInd": true,
            }))
            .collect::<Vec<_>>(),
    });

    let client = SbiClient::with_host_port(&host, port);
    match client
        .post_json("/neasdf-dnscontext/v1/dns-contexts", &body)
        .await
    {
        Ok(resp) if resp.status == 201 => {
            // Prefer the body's `dnsContextId`; fall back to the last segment of
            // `Location`. Both are populated by easdfd, and an EASDF that supplies
            // only one of them still works.
            let id = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| {
                    v.get("dnsContextId")
                        .and_then(|i| i.as_str())
                        .map(str::to_string)
                })
                .or_else(|| {
                    resp.http
                        .get_header("location")
                        .and_then(|l| l.rsplit('/').next().map(str::to_string))
                })
                .filter(|id| !id.is_empty());
            match id {
                Some(id) => {
                    log::info!(
                        "[{supi}] EASDF DNS context created: id={id} psi={pdu_session_id} dnn={dnn}"
                    );
                    Some(id)
                }
                None => {
                    log::warn!(
                        "[{supi}] EASDF answered 201 with neither dnsContextId nor a usable \
                         Location: the context cannot be deleted at release, so it is not recorded"
                    );
                    None
                }
            }
        }
        Ok(resp) => {
            log::warn!(
                "[{supi}] EASDF refused the DNS context ({}); the session proceeds without edge \
                 DNS steering",
                resp.status
            );
            None
        }
        Err(e) => {
            log::warn!(
                "[{supi}] EASDF DNS context create failed: {e}; the session proceeds without \
                 edge DNS steering"
            );
            None
        }
    }
}

/// Delete a session's DNS context at release (#114).
///
/// Best-effort: a failure leaves an orphaned context on the EASDF, which its own
/// capacity cap bounds. Failing the release instead would leave the SMF's own
/// session state inconsistent with the AMF's, which is worse.
pub async fn delete_dns_context(supi: &str, ctx_id: &str) {
    let Some(cfg) = config() else { return };
    let Some((host, port)) = discover_easdf(&cfg.nrf_uri).await else {
        log::warn!("[{supi}] cannot delete EASDF DNS context {ctx_id}: no EASDF discoverable");
        return;
    };
    let client = SbiClient::with_host_port(&host, port);
    let path = format!("/neasdf-dnscontext/v1/dns-contexts/{ctx_id}");
    match client.delete(&path).await {
        Ok(resp) => log::info!(
            "[{supi}] EASDF DNS context {ctx_id} deleted (status {})",
            resp.status
        ),
        Err(e) => log::warn!("[{supi}] EASDF DNS context {ctx_id} delete failed: {e}"),
    }
}

/// Discover an EASDF via the NRF (TS 29.510 NF discovery, `target-nf-type=EASDF`).
///
/// Returns the `(host, port)` of its `neasdf-dnscontext` service. `None` when no
/// EASDF is registered, which is the normal state in a deployment that does not
/// run one — logged at debug, not warn, for exactly that reason.
async fn discover_easdf(nrf_uri: &str) -> Option<(String, u16)> {
    let (nrf_host, nrf_port) = split_authority(nrf_uri)?;
    let client = SbiClient::with_host_port(&nrf_host, nrf_port);
    let mut request = SbiRequest::get("/nnrf-disc/v1/nf-instances");
    request.http.set_param("target-nf-type", "EASDF");
    request.http.set_param("requester-nf-type", "SMF");
    let resp = client.send_request(request).await.ok()?;
    if resp.status != 200 {
        log::debug!("NRF answered {} for an EASDF discovery", resp.status);
        return None;
    }
    let result: serde_json::Value = serde_json::from_str(resp.http.content.as_deref()?).ok()?;
    let instances = result.get("nfInstances")?.as_array()?;
    for instance in instances {
        if let Some(endpoint) = dnscontext_endpoint(instance) {
            return Some(endpoint);
        }
    }
    log::debug!("no registered EASDF advertises a neasdf-dnscontext endpoint");
    None
}

/// Pick the `neasdf-dnscontext` endpoint out of an EASDF's NF profile.
///
/// Matches on the SERVICE NAME rather than taking `nfServices[0]`: easdfd now
/// advertises two services (#114 added `neasdf-baselinednspattern`), so indexing
/// the first entry would silently start dialling whichever one the NRF happened
/// to return first. That is the same defect scpd's #207 fixed on the proxy path.
fn dnscontext_endpoint(instance: &serde_json::Value) -> Option<(String, u16)> {
    let services = instance.get("nfServices")?.as_array()?;
    let service = services.iter().find(|s| {
        s.get("serviceName")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("neasdf-dnscontext"))
    })?;
    if let Some(ep) = service
        .get("ipEndPoints")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let host = ep
            .get("ipv4Address")
            .and_then(|v| v.as_str())
            .or_else(|| ep.get("fqdn").and_then(|v| v.as_str()))?;
        let port = ep.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
        return Some((host.to_string(), port));
    }
    let host = instance
        .get("ipv4Addresses")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())?;
    Some((host.to_string(), 80))
}

/// Split `scheme://host:port` into `(host, port)`.
fn split_authority(uri: &str) -> Option<(String, u16)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        (80u16, uri)
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    (!host.is_empty()).then_some((host, port))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn split_authority_handles_scheme_and_port() {
        assert_eq!(
            split_authority("http://10.0.0.1:7777"),
            Some(("10.0.0.1".to_string(), 7777))
        );
        assert_eq!(
            split_authority("http://nrf.example/nnrf-disc/v1"),
            Some(("nrf.example".to_string(), 80))
        );
        assert_eq!(split_authority("http://"), None);
    }

    /// The endpoint is chosen by SERVICE NAME, not by position — easdfd advertises
    /// two services, and `nfServices[0]` would dial whichever came first.
    #[test]
    fn the_dnscontext_service_is_chosen_by_name() {
        let profile = serde_json::json!({
            "nfInstanceId": "easdf-1",
            "nfType": "EASDF",
            "nfServices": [
                {"serviceName": "neasdf-baselinednspattern",
                 "ipEndPoints": [{"ipv4Address": "10.0.0.5", "port": 9999}]},
                {"serviceName": "neasdf-dnscontext",
                 "ipEndPoints": [{"ipv4Address": "10.0.0.5", "port": 7777}]}
            ]
        });
        assert_eq!(
            dnscontext_endpoint(&profile),
            Some(("10.0.0.5".to_string(), 7777)),
            "the baseline-pattern service must not be dialled for a DNS context"
        );

        // No dnscontext service at all: nothing is dialled rather than guessing.
        let profile = serde_json::json!({
            "nfServices": [{"serviceName": "neasdf-baselinednspattern"}]
        });
        assert_eq!(dnscontext_endpoint(&profile), None);
    }

    /// The create decision, as a pure function: no config, or a config naming no
    /// edge pattern, means no DNS context.
    ///
    /// Pure on purpose. The `OnceLock` config cannot be re-set per test, so
    /// asserting "an empty pattern list creates nothing" through the global would
    /// require installing a second config and could only ever test whichever one
    /// won.
    #[test]
    fn no_config_or_no_edge_pattern_means_no_context() {
        assert!(!should_create(None), "no config: nothing to do");
        assert!(
            !should_create(Some(&EasdfConfig {
                nrf_uri: "http://nrf".into(),
                report_uri: "http://smf/cb".into(),
                edge_fqdn_patterns: Vec::new(),
            })),
            "enabled with no edge pattern must not create an inert context"
        );
        assert!(
            should_create(Some(&EasdfConfig {
                nrf_uri: "http://nrf".into(),
                report_uri: "http://smf/cb".into(),
                edge_fqdn_patterns: vec!["*.edge.example.com".into()],
            })),
            "a named pattern is what makes a context worth creating"
        );
    }

    /// With the leg off (the default), nothing is dialled and no context id is
    /// produced — the guard on the default posture.
    #[tokio::test]
    async fn the_leg_is_off_by_default() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        set_for_test(None);
        assert!(!enabled());
        assert_eq!(
            create_dns_context(
                "imsi-1",
                5,
                "internet",
                std::net::Ipv4Addr::new(10, 45, 0, 2)
            )
            .await,
            None
        );
    }

    /// A loopback NRF answering EASDF discovery, plus a loopback EASDF recording
    /// the requests it receives.
    /// The recorded requests: `(method, path, body)`.
    ///
    /// #276 widened this from `(method, path)`. The create body is the only place
    /// the UE address appears, and a test that records just the path cannot tell a
    /// create carrying it from one that does not.
    pub(crate) type SeenRequests = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>;

    pub(crate) async fn spawn_nrf_and_easdf() -> (
        nextgcore_sbi::server::SbiServer,
        nextgcore_sbi::server::SbiServer,
        SeenRequests,
    ) {
        use nextgcore_sbi::message::SbiResponse;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::net::SocketAddr;

        let seen: SeenRequests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        // EASDF: 201 + Location + dnsContextId on create, 204 on delete.
        let sink = seen.clone();
        let easdf_port = nextgcore_sbi::test_support::free_port();
        let easdf = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            easdf_port,
        ))));
        easdf
            .start(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                        req.header.method.clone(),
                        req.header.uri.clone(),
                        req.http.content.clone().unwrap_or_default(),
                    ));
                    if req.header.method == "POST" {
                        return SbiResponse::with_status(201)
                            .with_header("Location", "/neasdf-dnscontext/v1/dns-contexts/ctx-abc")
                            .with_json_body(&serde_json::json!({"dnsContextId": "ctx-abc"}))
                            .unwrap_or_else(|_| SbiResponse::with_status(201));
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("easdf start");

        // NRF: one EASDF advertising BOTH services, the dnscontext one pointing at
        // the EASDF above and the other at a dead port — so selecting the wrong
        // service fails loudly rather than silently working.
        let nrf_port = nextgcore_sbi::test_support::free_port();
        let nrf = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            nrf_port,
        ))));
        nrf.start(move |_req: SbiRequest| async move {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "easdf-1",
                        "nfType": "EASDF",
                        "nfStatus": "REGISTERED",
                        "ipv4Addresses": ["127.0.0.1"],
                        "nfServices": [
                            {"serviceName": "neasdf-baselinednspattern",
                             "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": 1}]},
                            {"serviceName": "neasdf-dnscontext",
                             "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": easdf_port}]}
                        ]
                    }]
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        })
        .await
        .expect("nrf start");

        set_for_test(Some(EasdfConfig {
            nrf_uri: format!("http://127.0.0.1:{nrf_port}"),
            report_uri: "http://127.0.0.1:9/nsmf-pdusession/v1/easdf-dns-reports".to_string(),
            edge_fqdn_patterns: vec!["*.edge.example.com".to_string()],
        }));
        (nrf, easdf, seen)
    }

    /// #114 acceptance: with the leg enabled, the SMF discovers an EASDF, POSTs a
    /// DNS context, returns the assigned id, and DELETEs it on release.
    ///
    /// Over real HTTP against loopback NRF and EASDF servers, so the discovery
    /// query, the create body and the delete path are all on the wire rather than
    /// stubbed. The recorded `(method, path)` list is the assertion: a test that
    /// only checked the returned id would pass against a create that never
    /// happened.
    #[tokio::test]
    async fn the_dns_context_is_created_and_deleted_over_the_wire() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let (nrf, easdf, seen) = spawn_nrf_and_easdf().await;

        let ctx_id = create_dns_context(
            "imsi-001010000000001",
            5,
            "internet",
            std::net::Ipv4Addr::new(10, 45, 0, 2),
        )
        .await
        .expect("a context id");
        assert_eq!(ctx_id, "ctx-abc", "the EASDF-assigned id must be returned");

        delete_dns_context("imsi-001010000000001", &ctx_id).await;

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            requests
                .iter()
                .filter(|(m, p, _)| m == "POST" && p == "/neasdf-dnscontext/v1/dns-contexts")
                .count(),
            1,
            "exactly one DNS context create, got {requests:?}"
        );
        assert_eq!(
            requests
                .iter()
                .filter(
                    |(m, p, _)| m == "DELETE" && p == "/neasdf-dnscontext/v1/dns-contexts/ctx-abc"
                )
                .count(),
            1,
            "the matching delete must be issued, got {requests:?}"
        );

        // #276: the create body must carry the UE's own address. Without it the
        // EASDF can serve this session's handling rules over the SBI shim only --
        // a DNS datagram carries no context id, so the source address is the sole
        // correlator between a query and a session. Asserted on the BODY rather
        // than on the path, which is why the recorder was widened to capture it.
        let create = requests
            .iter()
            .find(|(m, p, _)| m == "POST" && p == "/neasdf-dnscontext/v1/dns-contexts")
            .expect("the create request");
        let body: serde_json::Value =
            serde_json::from_str(&create.2).expect("the create body is JSON");
        assert_eq!(
            body["ueIpv4Address"],
            serde_json::json!("10.45.0.2"),
            "the UE address must reach the EASDF, got {body}"
        );
        assert_eq!(body["supi"], serde_json::json!("imsi-001010000000001"));
        assert_eq!(body["pduSessionId"], serde_json::json!(5));

        set_for_test(None);
        easdf.stop().await.expect("stop");
        nrf.stop().await.expect("stop");
    }
}
