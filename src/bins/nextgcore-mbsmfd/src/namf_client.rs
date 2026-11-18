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
        nextgcore_amfd::context::amf_mcast()
            .session_find(context_ref.parse().expect("numeric ref"))
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
        let (_server, context, deletes, _arrived, _release) =
            scripted_amf(false, &[500, 503]).await;
        assert!(!crate::release_amf_contexts(vec![context]).await);
        eventually("the AMF accepts a retried delete", || {
            deletes.load(Ordering::SeqCst) == 3
        })
        .await;
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
