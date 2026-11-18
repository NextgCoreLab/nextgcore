//! MB-SMF -> AMF client: AMF discovery and the Namf MBS invocations
//! (TS 23.247 §7.2.5.2 and §7.3.1 step 2, TS 29.518 §5.6-5.7).
//!
//! Before this module the create handler terminated at `session_add` and no AMF
//! interaction happened at all, so the N2 MBS SM containers this MB-SMF builds
//! correctly were never carried onward and the RAN never learned of a session.
//!
//! TS 23.247 §7.3.1 step 2 makes the AMF discovery the MB-SMF's job: it selects
//! the serving AMF(s) for the MBS service area, then drives broadcast setup
//! toward the RAN through them.
//!
//! Resource names come from the OpenAPI in `6g_docs/specs`
//! (`TS29518_Namf_MBSBroadcast.yaml` server url `{apiRoot}/namf-mbs-bc/v1`,
//! `TS29518_Namf_MBSCommunication.yaml` `{apiRoot}/namf-mbs-comm/v1`), not from
//! prose.

use std::time::Duration;

use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::global_context;
use serde_json::{json, Value};

use crate::context::Tmgi;

/// An AMF the MB-SMF may drive MBS N2 signalling through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAmf {
    pub host: String,
    pub port: u16,
    pub nf_instance_id: Option<String>,
}

/// Discover an AMF serving MBS via the NRF
/// (`GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=MB_SMF
/// &service-names=namf-mbs-bc`).
///
/// `None` on ANY failure -- no NRF configured, transport error, or no instance
/// advertising the service. The caller treats that as "no AMF to drive" and says
/// so, rather than falling back to a hardcoded address: a wrong AMF would set up
/// a bearer in the wrong service area.
pub async fn discover_amf() -> Option<DiscoveredAmf> {
    let nrf_uri = global_context().get_nrf_uri().await?;
    // #1617: the NRF client TLS (https + this NF's certificate) for an https
    // NRF URI or the production profile.
    let client = SbiClient::new(
        nextgcore_sbi::nrf_tls::nrf_client_config_for_uri(&nrf_uri)?
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );

    // `service-names` filters to AMFs that actually advertise the MBS broadcast
    // service; an AMF without it would 404 the ContextCreate.
    let path = "/nnrf-disc/v1/nf-instances?target-nf-type=AMF\
                &requester-nf-type=MB_SMF&service-names=namf-mbs-bc";
    let response = match client.get(path).await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("MBS: NRF discovery of a serving AMF failed: {e}");
            return None;
        }
    };
    if response.status != 200 {
        log::warn!(
            "MBS: NRF discovery of a serving AMF returned status {}",
            response.status
        );
        return None;
    }

    let json: Value = serde_json::from_str(&response.http.content?).ok()?;
    parse_amf_search_result(&json)
}

/// Pick an AMF out of an NRF `SearchResult` (TS 29.510 §6.2.6.2.2).
///
/// Takes the first instance carrying a usable `namf-mbs-bc` endpoint. No
/// load-balancing or priority ordering: with one AMF in this deployment a
/// selection policy would be untestable code.
fn parse_amf_search_result(json: &Value) -> Option<DiscoveredAmf> {
    for instance in json.get("nfInstances")?.as_array()? {
        let nf_instance_id = instance
            .get("nfInstanceId")
            .and_then(Value::as_str)
            .map(str::to_owned);

        // Prefer an ipEndPoint on the namf-mbs-bc service, then fall back to the
        // instance's own ipv4Addresses -- the same order the other consumers use.
        let from_service = instance
            .get("nfServices")
            .and_then(Value::as_array)
            .and_then(|services| {
                services
                    .iter()
                    .filter(|s| {
                        s.get("serviceName")
                            .and_then(Value::as_str)
                            .is_some_and(|n| n == "namf-mbs-bc")
                    })
                    // #1324: the endpoint's IPv4 or IPv6 address, else the
                    // service's or the AMF's (IPv4, IPv6, FQDN), on the endpoint port.
                    .find_map(|s| {
                        let host = nextgcore_sbi::nf_addressing::service_host(instance, Some(s))?;
                        let port =
                            nextgcore_sbi::nf_addressing::service_port(Some(s)).unwrap_or(80);
                        Some((host, port))
                    })
            });

        let endpoint = from_service
            .or_else(|| Some((nextgcore_sbi::nf_addressing::profile_host(instance)?, 80)));

        if let Some((host, port)) = endpoint {
            return Some(DiscoveredAmf {
                host,
                port,
                nf_instance_id,
            });
        }
    }
    None
}

/// `MbsSessionId` as TS 29.571 spells it, for a Namf request body.
fn mbs_session_id_json(tmgi: &Tmgi) -> Value {
    json!({
        "tmgi": {
            "mbsServiceId": hex::encode(tmgi.mbs_service_id),
            "plmnId": { "mcc": tmgi.plmn_id.mcc, "mnc": tmgi.plmn_id.mnc },
        }
    })
}

/// The MBS context reference an AMF returned from ContextCreate.
pub type MbsContextRef = String;

/// `POST /namf-mbs-bc/v1/mbs-contexts` — Namf_MBSBroadcast ContextCreate
/// (TS 29.518 §5.6), i.e. TS 23.247 §7.3.1's request for broadcast setup toward
/// the RAN.
///
/// Returns the AMF's `mbsContextRef` on 201. `None` on any failure, logged:
/// this is best-effort relative to the session create, which has already
/// succeeded locally by the time it runs. A failed AMF leg means the RAN does
/// not have the session, which the caller reports rather than hides.
pub async fn context_create(amf: &DiscoveredAmf, tmgi: &Tmgi) -> Option<MbsContextRef> {
    // #1662: a service request to the AMF, so it carries the NRF-issued token.
    let client = crate::attach_oauth2(
        SbiClient::new(
            nextgcore_sbi::security::sbi_peer_client_config(&amf.host, amf.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        ),
        nextgcore_sbi::types::NfType::Amf,
    );

    let body = json!({ "mbsSessionId": mbs_session_id_json(tmgi) });
    let response = match client
        .post_json("/namf-mbs-bc/v1/mbs-contexts", &body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "MBS: Namf_MBSBroadcast ContextCreate to {}:{} failed: {e}",
                amf.host,
                amf.port
            );
            return None;
        }
    };

    if response.status != 201 {
        log::warn!(
            "MBS: Namf_MBSBroadcast ContextCreate returned status {} from {}:{}",
            response.status,
            amf.host,
            amf.port
        );
        return None;
    }

    let json: Value = serde_json::from_str(&response.http.content?).ok()?;
    let context_ref = json
        .get("mbsContextRef")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if context_ref.is_none() {
        log::warn!("MBS: ContextCreate 201 carried no mbsContextRef");
    }
    context_ref
}

/// How one Namf_MBSBroadcast ContextDelete ended (#1758).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextDeleteOutcome {
    /// 204: the AMF deleted the context.
    Deleted,
    /// 404: the AMF holds no such context, so it is already gone.
    Gone,
    /// Not delivered, or refused otherwise: worth retrying.
    Failed,
}

/// `DELETE /namf-mbs-bc/v1/mbs-contexts/{mbsContextRef}` — Namf_MBSBroadcast
/// ContextDelete (TS 29.518 §5.6, `TS29518_Namf_MBSBroadcast.yaml` operationId
/// `ContextDelete`), TS 23.247 §7.3.2's broadcast session release toward the AMF.
/// Carries the NRF-issued token, as ContextCreate does (#1662).
pub async fn context_delete(context: &crate::context::AmfMbsContext) -> ContextDeleteOutcome {
    let client = crate::attach_oauth2(
        SbiClient::new(
            nextgcore_sbi::security::sbi_peer_client_config(&context.host, context.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        ),
        nextgcore_sbi::types::NfType::Amf,
    );
    let path = format!(
        "/namf-mbs-bc/v1/mbs-contexts/{}",
        nextgcore_sbi::uri_encode::encode_query_value(&context.context_ref)
    );
    match client.delete(&path).await {
        Ok(r) if r.status == 204 || r.status == 200 => ContextDeleteOutcome::Deleted,
        Ok(r) if r.status == 404 => ContextDeleteOutcome::Gone,
        Ok(r) => {
            log::warn!(
                "MBS: Namf_MBSBroadcast ContextDelete of {} returned status {} from {}:{}",
                context.context_ref,
                r.status,
                context.host,
                context.port
            );
            ContextDeleteOutcome::Failed
        }
        Err(e) => {
            log::warn!(
                "MBS: Namf_MBSBroadcast ContextDelete of {} to {}:{} failed: {e}",
                context.context_ref,
                context.host,
                context.port
            );
            ContextDeleteOutcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;

    fn tmgi() -> Tmgi {
        Tmgi {
            mbs_service_id: [0x00, 0xBE, 0xEF],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        }
    }

    /// #1662: ContextCreate passes an OAuth2-required AMF with the installed
    /// client, and is refused 401 without one. The stand-in AMF is gated by
    /// nextgcore-sbi's own check (JWKS, audience AMF), so `Some(ref)` is a
    /// request that passed it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_create_passes_an_oauth2_required_amf_1662() {
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        use nextgcore_sbi::types::NfType;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (_nrf, nrf_port) = stand_in::token_nrf(sk.clone()).await;
        let (_amf, amf_port, seen) = stand_in::oauth2_producer(&sk, NfType::Amf, |_| {
            nextgcore_sbi::message::SbiResponse::with_status(201)
                .with_json_body(&json!({ "mbsContextRef": "ctx-1662" }))
                .expect("json")
        })
        .await;
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: amf_port,
            nf_instance_id: None,
        };

        let without = context_create(&amf, &tmgi()).await;
        let with = crate::TEST_OAUTH2_CLIENT
            .scope(
                stand_in::oauth2_client_for(nrf_port, NfType::Mbsmf),
                context_create(&amf, &tmgi()),
            )
            .await;

        assert_eq!(without, None, "refused 401 without a token");
        assert_eq!(with.as_deref(), Some("ctx-1662"));
        assert_eq!(
            stand_in::bearer_requests(&seen, "POST", "/namf-mbs-bc/v1/mbs-contexts"),
            1
        );
    }

    /// #1662, failure-path property 1 (a failed request applies nothing): when
    /// the token cannot be obtained, ContextCreate is not sent at all, not even
    /// bare. The recorder here is UNGATED, so it would see a bare send.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_token_fetch_sends_nothing_1662() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        use nextgcore_sbi::types::NfType;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = std::sync::Arc::clone(&seen);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let recorder = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        recorder
            .start(move |_req| {
                let sink = std::sync::Arc::clone(&sink);
                async move {
                    sink.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    nextgcore_sbi::message::SbiResponse::with_status(201)
                }
            })
            .await
            .expect("recorder starts");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };

        // Port 1 on loopback: nothing listens, so the token request fails.
        let outcome = crate::TEST_OAUTH2_CLIENT
            .scope(
                stand_in::oauth2_client_for(1, NfType::Mbsmf),
                context_create(&amf, &tmgi()),
            )
            .await;

        assert_eq!(outcome, None);
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no token: nothing is sent, not even bare"
        );
    }

    /// #1662, failure-path properties 1, 2 and 4 against the RECEIVING peer:
    /// amfd's real Namf handler behind an OAuth2-required listener (nextgcore-sbi's
    /// gate, audience AMF).
    /// - A bare ContextCreate is refused 401 and creates no MBS context (1).
    /// - With the token it creates one, and a retry of the same request returns
    ///   the same ref without a second context (2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn context_create_reaches_the_real_amf_handler_behind_its_oauth2_gate_1662() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        use nextgcore_sbi::types::NfType;
        // #1758: counts amfd's process-global contexts, which the release tests delete.
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        nextgcore_amfd::test_support::init_context();
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (_nrf, nrf_port) = stand_in::token_nrf(sk.clone()).await;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr).with_expected_audience_nf_type(NfType::Amf);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(stand_in::jwks_for(&sk, stand_in::TEST_NRF_KID));
        let amf_server = SbiServer::on_listener(cfg, listener);
        amf_server
            .start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd Namf server starts");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };
        let sessions = || nextgcore_amfd::context::amf_mcast().session_count();
        let before = sessions();

        let bare = context_create(&amf, &tmgi()).await;
        let after_bare = sessions();
        let oauth2 = stand_in::oauth2_client_for(nrf_port, NfType::Mbsmf);
        let first = crate::TEST_OAUTH2_CLIENT
            .scope(
                std::sync::Arc::clone(&oauth2),
                context_create(&amf, &tmgi()),
            )
            .await;
        let after_first = sessions();
        let retry = crate::TEST_OAUTH2_CLIENT
            .scope(oauth2, context_create(&amf, &tmgi()))
            .await;

        assert_eq!(bare, None, "the AMF's gate refuses a bare ContextCreate");
        assert_eq!(
            after_bare, before,
            "a refused ContextCreate creates nothing"
        );
        let first = first.expect("with the token amfd creates the MBS context");
        assert_eq!(after_first, before + 1);
        assert_eq!(
            retry.as_deref(),
            Some(first.as_str()),
            "a retry returns the same ref"
        );
        assert_eq!(sessions(), before + 1, "and creates no second context");
    }

    /// #1758: amfd's real Namf handler behind an OAuth2-required listener, and the
    /// OAuth2 client the MB-SMF uses toward it.
    async fn gated_real_amf() -> (
        nextgcore_sbi::server::SbiServer,
        nextgcore_sbi::server::SbiServer,
        DiscoveredAmf,
        std::sync::Arc<nextgcore_sbi::oauth::OAuth2Client>,
    ) {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use nextgcore_sbi::test_support::oauth2 as stand_in;
        use nextgcore_sbi::types::NfType;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        nextgcore_amfd::test_support::init_context();
        crate::mbsmf_context_init(256);
        let sk = nextgcore_sbi::oauth::generate_es256_key();
        let (nrf, nrf_port) = stand_in::token_nrf(sk.clone()).await;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr).with_expected_audience_nf_type(NfType::Amf);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(stand_in::jwks_for(&sk, stand_in::TEST_NRF_KID));
        let amf_server = SbiServer::on_listener(cfg, listener);
        amf_server
            .start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd Namf server starts");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };
        (
            nrf,
            amf_server,
            amf,
            stand_in::oauth2_client_for(nrf_port, NfType::Mbsmf),
        )
    }

    fn tmgi_1758(svc: [u8; 3]) -> Tmgi {
        Tmgi {
            mbs_service_id: svc,
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        }
    }

    fn amf_holds(context_ref: &str) -> bool {
        // #1856: the ref is `<epoch>-<id>` and names the context, not the session.
        nextgcore_amfd::ngap_mcast::parse_context_ref(context_ref)
            .and_then(|id| nextgcore_amfd::context::amf_mcast().broadcast_context_find(id))
            .is_some()
    }

    /// #1758: releasing an MBS session deletes the broadcast MBS context it created
    /// at amfd's real, OAuth2-gated handler (so the ContextDelete carries the
    /// token), and a repeated release is a 404 that touches nothing.
    ///
    /// REVERT-VERIFIED: with the release sending no ContextDelete, or sending it
    /// without the token, the AMF still holds the context.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_released_session_deletes_its_context_at_the_real_amf_1758() {
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        // R24: after MBS_CONTEXT_LOCK, the order every holder of both takes them in.
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let tmgi = tmgi_1758([0x00, 0x17, 0x58]);
        let session = crate::mbsmf_self()
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("session");

        crate::TEST_OAUTH2_CLIENT
            .scope(oauth2, async {
                let context_ref = crate::create_amf_mbs_context(session.id, tmgi, amf)
                    .await
                    .expect("the AMF creates the context");
                assert!(amf_holds(&context_ref));
                assert_eq!(
                    crate::mbsmf_self()
                        .read()
                        .unwrap()
                        .amf_contexts_of(session.id)[0]
                        .context_ref,
                    context_ref,
                    "the MB-SMF records the context it created"
                );

                let id = format!("mbs-sess-{}", session.id);
                assert_eq!(crate::handle_mbs_session_release(&id).await.status, 204);
                assert!(
                    !amf_holds(&context_ref),
                    "after release the AMF holds no context for the session"
                );
                assert_eq!(
                    crate::handle_mbs_session_release(&id).await.status,
                    404,
                    "a repeated release is idempotent"
                );
            })
            .await;
    }

    /// #1758: a ContextCreate that lands after its session was released (that release
    /// found nothing to delete) deletes its own context at the AMF.
    ///
    /// REVERT-VERIFIED: without that delete, the AMF keeps the context.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_context_created_after_its_release_is_deleted_1758() {
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        // R24: after MBS_CONTEXT_LOCK, the order every holder of both takes them in.
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let tmgi = tmgi_1758([0x01, 0x17, 0x58]);
        let ctx = crate::mbsmf_self();
        let session = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("session");
        ctx.read().unwrap().session_remove(session.id);

        crate::TEST_OAUTH2_CLIENT
            .scope(oauth2, async {
                assert_eq!(
                    crate::create_amf_mbs_context(session.id, tmgi.clone(), amf).await,
                    None
                );
            })
            .await;
        let amf_tmgi = nextgcore_amfd::ngap_mcast::Tmgi::new(0x011758, [0x00, 0xF1, 0x10]);
        assert!(
            nextgcore_amfd::context::amf_mcast()
                .session_find_by_tmgi(&amf_tmgi)
                .is_none(),
            "the late context is deleted at the AMF"
        );
    }

    /// #1758: a stand-in AMF that holds the FIRST ContextDelete until `release`
    /// (signalling `arrived`), and answers the successive deletes `statuses` (204
    /// once exhausted). Counts the deletes.
    async fn scripted_amf(
        hold_first: bool,
        statuses: &[u16],
    ) -> (
        nextgcore_sbi::server::SbiServer,
        crate::context::AmfMbsContext,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let deletes = Arc::new(AtomicUsize::new(0));
        let arrived = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let held = Arc::new(AtomicBool::new(!hold_first));
        let statuses = Arc::new(Mutex::new(
            statuses
                .iter()
                .copied()
                .collect::<std::collections::VecDeque<u16>>(),
        ));
        let (d, a, r, h, st) = (
            deletes.clone(),
            arrived.clone(),
            release.clone(),
            held.clone(),
            statuses.clone(),
        );
        let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: nextgcore_sbi::message::SbiRequest| {
                let (d, a, r, h, st) = (d.clone(), a.clone(), r.clone(), h.clone(), st.clone());
                async move {
                    d.fetch_add(1, Ordering::SeqCst);
                    if !h.swap(true, Ordering::SeqCst) {
                        a.notify_one();
                        r.notified().await;
                    }
                    let status = st.lock().unwrap().pop_front().unwrap_or(204);
                    nextgcore_sbi::message::SbiResponse::with_status(status)
                }
            },
        )
        .await;
        let context = crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
            context_ref: "7".to_string(),
            tmgi: None,
        };
        (server, context, deletes, arrived, release)
    }

    async fn eventually(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// #1758 (failure-path check 1): a ContextDelete the AMF refuses is retried,
    /// not forgotten.
    ///
    /// REVERT-VERIFIED: with no retry, the AMF sees one delete only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_context_delete_is_retried_1758() {
        use std::sync::atomic::Ordering;
        // R24: `release_amf_contexts` can park into the reconciler's set.
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        let (_server, context, deletes, _arrived, _release) =
            scripted_amf(false, &[500, 503]).await;
        assert!(!crate::release_amf_contexts(vec![context]).await);
        eventually("the AMF accepts a retried delete", || {
            deletes.load(Ordering::SeqCst) == 3
        })
        .await;
    }

    /// #1817: an AMF that comes back AFTER the retry budget still gets the delete.
    /// Every fast retry is refused, the record is parked, a reconcile pass that is
    /// still refused keeps it, and the next pass delivers it.
    ///
    /// REVERT-VERIFIED: with `reconcile::park(failed)` removed from the retry task,
    /// nothing is parked and the "parked after the budget" wait times out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_amf_back_after_the_retry_budget_still_gets_the_delete_1817() {
        use std::sync::atomic::Ordering;
        let _g = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        let budget = crate::AMF_RELEASE_RETRY_DELAYS.len() + 1;
        // The first attempt, every retry, and one reconcile pass are refused.
        let refusals = vec![503u16; budget + 1];
        let (_server, context, deletes, _arrived, _release) = scripted_amf(false, &refusals).await;
        let before = crate::reconcile::RECONCILED.get(&["deleted"]);
        assert!(!crate::release_amf_contexts(vec![context.clone()]).await);
        eventually("the record is parked after the budget", || {
            crate::reconcile::pending_count() == 1
        })
        .await;
        assert_eq!(deletes.load(Ordering::SeqCst), budget);

        assert_eq!(crate::reconcile::reconcile_once().await, 0, "still refused");
        assert_eq!(crate::reconcile::pending_count(), 1, "kept, not dropped");

        assert_eq!(
            crate::reconcile::reconcile_once().await,
            1,
            "the AMF accepts"
        );
        assert_eq!(deletes.load(Ordering::SeqCst), budget + 2);
        assert_eq!(crate::reconcile::pending_count(), 0);
        assert_eq!(crate::reconcile::RECONCILED.get(&["deleted"]), before + 1);
    }

    /// R24 (#1817 review): a parked ContextDelete is not sent for a context a live
    /// session holds again. The AMF's ContextCreate is idempotent on the TMGI, so a
    /// new session reusing a released one's TMGI is handed the same
    /// `mbsContextRef`. Recording it unparks the delete; and a delete parked while
    /// the context is held is dropped by the pass rather than sent.
    ///
    /// REVERT-VERIFIED: with the `unpark` call removed from `record_amf_context`,
    /// "recording the reused context unparks its delete" fails; with the
    /// in-use check removed from `delete_in_lane`, the AMF sees
    /// the delete ("the live context is not deleted").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_parked_delete_spares_a_context_a_live_session_reuses_1817() {
        use std::sync::atomic::Ordering;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        let (_server, context, deletes, _arrived, _release) = scripted_amf(false, &[]).await;
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        let before = crate::reconcile::RECONCILED.get(&["reused"]);

        // Session A was released while the AMF was down: its delete is parked.
        crate::reconcile::park(vec![context.clone()]);
        // Session B reuses the TMGI and gets the same context back.
        let b = ctx
            .read()
            .unwrap()
            .session_add(
                tmgi_1758([0x03, 0x18, 0x17]),
                crate::MbsSessionType::Broadcast,
            )
            .expect("session");
        assert!(ctx
            .read()
            .unwrap()
            .record_amf_context(b.id, context.clone()));
        assert_eq!(
            crate::reconcile::pending_count(),
            0,
            "recording the reused context unparks its delete"
        );

        // A delete parked while B holds it is dropped by the pass, not sent.
        crate::reconcile::park(vec![context.clone()]);
        let accepted = crate::reconcile::reconcile_once().await;
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            0,
            "the live context is not deleted"
        );
        assert_eq!(accepted, 0);
        assert_eq!(crate::reconcile::pending_count(), 0);
        assert_eq!(crate::reconcile::RECONCILED.get(&["reused"]), before + 2);
        ctx.read().unwrap().take_amf_contexts(b.id);
        ctx.read().unwrap().session_remove(b.id);
    }

    /// R24: the fast retries of a refused ContextDelete stop once a live session
    /// holds that context again, and nothing is parked for it.
    ///
    /// REVERT-VERIFIED: with the `amf_context_in_use` check removed from the retry
    /// loop in `release_amf_contexts`, the retry deletes the live context ("no
    /// retry deletes the reused context").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_fast_retries_spare_a_context_a_live_session_reuses_1817() {
        use std::sync::atomic::Ordering;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        let (_server, context, deletes, _arrived, _release) = scripted_amf(false, &[500]).await;
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        assert!(!crate::release_amf_contexts(vec![context.clone()]).await);
        let b = ctx
            .read()
            .unwrap()
            .session_add(
                tmgi_1758([0x04, 0x18, 0x17]),
                crate::MbsSessionType::Broadcast,
            )
            .expect("session");
        assert!(ctx
            .read()
            .unwrap()
            .record_amf_context(b.id, context.clone()));
        tokio::time::sleep(crate::AMF_RELEASE_RETRY_DELAYS[0] * 10).await;
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            1,
            "no retry deletes the reused context"
        );
        assert_eq!(crate::reconcile::pending_count(), 0);
        ctx.read().unwrap().take_amf_contexts(b.id);
        ctx.read().unwrap().session_remove(b.id);
    }

    /// R24: one pass sends for at most `MAX_PASS`. Against a blackholed AMF the
    /// records it does not reach are re-parked, in order, for the next pass.
    ///
    /// REVERT-VERIFIED: with the deadline check removed, the pass runs for every
    /// record's client timeout ("the pass is bounded").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pass_against_a_blackholed_amf_is_bounded_1817() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Accepts connections and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hole = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let parked: Vec<_> = (0..8)
            .map(|n| crate::context::AmfMbsContext {
                host: "127.0.0.1".to_string(),
                port,
                nf_instance_id: None,
                context_ref: format!("hole-{n}"),
                tmgi: None,
            })
            .collect();
        crate::reconcile::park(parked);
        let started = std::time::Instant::now();
        assert_eq!(crate::reconcile::reconcile_once().await, 0);
        assert!(
            started.elapsed() < crate::reconcile::MAX_PASS + Duration::from_secs(4),
            "the pass is bounded: {:?}",
            started.elapsed()
        );
        assert_eq!(
            crate::reconcile::pending_count(),
            8,
            "every record re-parked"
        );
        crate::reconcile::clear_for_test();
        hole.abort();
    }

    /// **#1854**: a ContextCreate for session B lands while session A's ContextDelete
    /// for the same TMGI is in flight at the (real, TMGI-idempotent) AMF. B's create
    /// waits for the delete in their (AMF, TMGI) lane, so the AMF hands it a FRESH
    /// context rather than A's, and B's recorded context is live at the AMF
    /// afterwards. No lane is left behind.
    ///
    /// REVERT-VERIFIED: with the create taking no lane, B is handed A's context,
    /// the delete then removes it, and "B's context is live at the AMF" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_create_racing_a_delete_on_one_tmgi_gets_a_live_context_1854() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        nextgcore_amfd::test_support::init_context();
        crate::mbsmf_context_init(256);
        // The real amfd handler, its ContextDelete held 400 ms on the way in.
        let arrived = std::sync::Arc::new(tokio::sync::Notify::new());
        let a = arrived.clone();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let amf_server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        amf_server
            .start(move |req: nextgcore_sbi::message::SbiRequest| {
                let a = a.clone();
                async move {
                    if req.header.method == "DELETE" {
                        a.notify_one();
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                    nextgcore_amfd::namf_request_handler(req).await
                }
            })
            .await
            .expect("AMF starts");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };
        let tmgi = tmgi_1758([0x05, 0x18, 0x54]);
        let ctx = crate::mbsmf_self();
        let session = |ctx: &std::sync::Arc<std::sync::RwLock<crate::MbSmfContext>>| {
            ctx.read()
                .unwrap()
                .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
                .expect("session")
        };
        let a_session = session(&ctx);
        let a_ref = crate::create_amf_mbs_context(a_session.id, tmgi.clone(), amf.clone())
            .await
            .expect("A's context");

        // A is released; its ContextDelete is held at the AMF.
        let a_id = format!("mbs-sess-{}", a_session.id);
        let release = tokio::spawn(async move { crate::handle_mbs_session_release(&a_id).await });
        arrived.notified().await;
        // B, on the same TMGI, is created while that delete is in flight.
        let b_session = session(&ctx);
        let b_ref = crate::create_amf_mbs_context(b_session.id, tmgi.clone(), amf.clone())
            .await
            .expect("B's context");
        release.await.expect("release");

        let live = b_ref
            .parse::<u64>()
            .ok()
            .and_then(|r| nextgcore_amfd::context::amf_mcast().broadcast_context_find(r));
        assert!(
            live.is_some(),
            "B's context is live at the AMF (A's was {a_ref}, B's is {b_ref})"
        );
        assert_eq!(
            crate::lane::count_for_port(addr.port()),
            0,
            "no lane is left behind"
        );
        ctx.read().unwrap().take_amf_contexts(b_session.id);
        ctx.read().unwrap().session_remove(b_session.id);
    }

    /// **#1854**, the other order: session B's ContextCreate on the TMGI takes the
    /// lane first (the AMF holds it), and released session A's ContextDelete waits
    /// behind it. B is handed A's context (the AMF is idempotent on the TMGI) and
    /// records it, so A's delete, in the lane, sees B holding it and is not sent.
    ///
    /// REVERT-VERIFIED: with the in-use check removed from `delete_in_lane`, A's
    /// delete removes B's live context ("B keeps the context A released").
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_release_spares_the_context_a_later_session_holds_1854() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        nextgcore_amfd::test_support::init_context();
        crate::mbsmf_context_init(256);
        // The real amfd handler; once armed, the next ContextCreate is held 400 ms.
        let arm = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let arrived = std::sync::Arc::new(tokio::sync::Notify::new());
        let deletes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (ar, a2, d2) = (arm.clone(), arrived.clone(), deletes.clone());
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let amf_server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
        amf_server
            .start(move |req: nextgcore_sbi::message::SbiRequest| {
                let (ar, a2, d2) = (ar.clone(), a2.clone(), d2.clone());
                async move {
                    if req.header.method == "DELETE" {
                        d2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    if req.header.method == "POST"
                        && ar.swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        a2.notify_one();
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    }
                    nextgcore_amfd::namf_request_handler(req).await
                }
            })
            .await
            .expect("AMF starts");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };
        let tmgi = tmgi_1758([0x06, 0x18, 0x54]);
        let ctx = crate::mbsmf_self();
        let a = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("A");
        let a_ref = crate::create_amf_mbs_context(a.id, tmgi.clone(), amf.clone())
            .await
            .expect("A's context");
        // A's release, up to its ContextDelete: removed here, contexts taken.
        ctx.read().unwrap().session_remove(a.id);
        let a_contexts = ctx.read().unwrap().take_amf_contexts(a.id);
        // B's ContextCreate takes the lane first; the AMF holds it.
        let b = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("B");
        arm.store(true, std::sync::atomic::Ordering::SeqCst);
        let (b_id, b_tmgi, b_amf) = (b.id, tmgi.clone(), amf.clone());
        let create = tokio::spawn(crate::create_amf_mbs_context(b_id, b_tmgi, b_amf));
        arrived.notified().await;
        // A's delete now waits behind B's create in the lane.
        let release = tokio::spawn(crate::release_amf_contexts(a_contexts));
        let b_ref = create.await.expect("create").expect("B's context");
        release.await.expect("release");
        assert_eq!(a_ref, b_ref, "the AMF handed B the context A held");
        let live = b_ref
            .parse::<u64>()
            .ok()
            .and_then(|r| nextgcore_amfd::context::amf_mcast().broadcast_context_find(r));
        assert!(live.is_some(), "B keeps the context A released");
        assert_eq!(deletes.load(std::sync::atomic::Ordering::SeqCst), 0);
        ctx.read().unwrap().take_amf_contexts(b.id);
        ctx.read().unwrap().session_remove(b.id);
    }

    /// #1758 (check 3): a session release whose consumer disconnects while the AMF
    /// holds its ContextDelete still releases the context: the refused delete is
    /// retried on its own task.
    ///
    /// REVERT-VERIFIED: with the release awaited inline, dropping the handler drops
    /// the retry and the AMF sees one delete only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_release_still_releases_the_amf_context_1758() {
        use std::sync::atomic::Ordering;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        let (_server, context, deletes, arrived, release) = scripted_amf(true, &[500]).await;
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        let session = ctx
            .read()
            .unwrap()
            .session_add(
                tmgi_1758([0x02, 0x17, 0x58]),
                crate::MbsSessionType::Broadcast,
            )
            .expect("session");
        assert!(ctx.read().unwrap().record_amf_context(session.id, context));

        let id = format!("mbs-sess-{}", session.id);
        tokio::select! {
            _ = crate::handle_mbs_session_release(&id) => {
                panic!("the AMF holds the delete; the release cannot finish")
            }
            _ = arrived.notified() => {}
        }
        release.notify_one();
        eventually("the refused delete is retried", || {
            deletes.load(Ordering::SeqCst) == 2
        })
        .await;
    }

    /// The `mbsServiceId` is 6 hex digits, which is what the OpenAPI's
    /// `pattern: '^[A-Fa-f0-9]{6}$'` requires -- a 3-byte array rendered any
    /// other way is refused by the AMF with a 400.
    #[test]
    fn an_mbs_session_id_body_renders_the_service_id_as_six_hex_digits() {
        let body = mbs_session_id_json(&tmgi());
        assert_eq!(body["tmgi"]["mbsServiceId"], json!("00beef"));
        assert_eq!(body["tmgi"]["plmnId"]["mcc"], json!("001"));
        assert_eq!(body["tmgi"]["plmnId"]["mnc"], json!("01"));
    }

    /// Discovery prefers the `namf-mbs-bc` service's own endpoint over the
    /// instance-level address, because an AMF may serve MBS on a different port
    /// from its other services.
    #[test]
    fn discovery_prefers_the_mbs_service_endpoint_over_the_instance_address() {
        let json = json!({
            "nfInstances": [{
                "nfInstanceId": "amf-1",
                "ipv4Addresses": ["10.0.0.1"],
                "nfServices": [
                    { "serviceName": "namf-comm",
                      "ipEndPoints": [{ "ipv4Address": "10.0.0.1", "port": 7777 }] },
                    { "serviceName": "namf-mbs-bc",
                      "ipEndPoints": [{ "ipv4Address": "10.0.0.2", "port": 8888 }] },
                ],
            }]
        });
        let amf = parse_amf_search_result(&json).expect("an AMF must be selected");
        assert_eq!(amf.host, "10.0.0.2");
        assert_eq!(amf.port, 8888, "the namf-mbs-bc endpoint, not namf-comm's");
        assert_eq!(amf.nf_instance_id.as_deref(), Some("amf-1"));
    }

    /// An instance with no MBS service falls back to its instance address, so a
    /// minimal NRF registration still yields a usable AMF.
    #[test]
    fn discovery_falls_back_to_the_instance_address() {
        let json = json!({
            "nfInstances": [{ "nfInstanceId": "amf-2", "ipv4Addresses": ["10.0.0.9"] }]
        });
        let amf = parse_amf_search_result(&json).expect("an AMF must be selected");
        assert_eq!((amf.host.as_str(), amf.port), ("10.0.0.9", 80));
    }

    /// An empty or addressless SearchResult yields None rather than a default
    /// address: driving the wrong AMF would set up a bearer in the wrong service
    /// area, so no AMF is better than a guessed one.
    #[test]
    fn discovery_yields_none_rather_than_a_default_address() {
        assert!(parse_amf_search_result(&json!({ "nfInstances": [] })).is_none());
        assert!(parse_amf_search_result(&json!({})).is_none());
        assert!(
            parse_amf_search_result(&json!({ "nfInstances": [{ "nfInstanceId": "amf-3" }] }))
                .is_none(),
            "an instance with no address at all must not be selected"
        );
    }
}

/// #1324 review: producer to consumer. A peer profile built with an IPv4, IPv6 or
/// FQDN host (as this codebase's producers build them) resolves to that host.
#[cfg(test)]
mod tests_peer_host_kind_1324 {
    use super::*;
    use nextgcore_sbi::nf_addressing::{dialled_host, sample_search_result, SAMPLE_HOSTS};

    #[test]
    fn a_peer_at_any_host_type_is_resolved() {
        for host in SAMPLE_HOSTS {
            let r = sample_search_result("AMF", "namf-mbs-bc", host, 7797);
            let amf = parse_amf_search_result(&r).expect("an AMF");
            assert_eq!((amf.host, amf.port), (dialled_host(host), 7797));
        }
    }
}
