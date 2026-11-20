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

/// #1796: the path under which this MB-SMF serves the AMF's
/// Namf_MBSBroadcast_ContextStatusNotify (TS 29.518 §5.6.2.5):
/// `{AMF_NOTIFY_PREFIX}/{token}`, the token minted for the ContextCreate.
pub const AMF_NOTIFY_PREFIX: &str = "/nmbsmf-mbssession/v1/amf-context-status";

/// The `notifyUri` for `token` under `base` (`{scheme}://{host:port}`).
pub fn amf_notify_uri(base: &str, token: &str) -> String {
    format!("{}{AMF_NOTIFY_PREFIX}/{token}", base.trim_end_matches('/'))
}

/// The binary part carrying the N2 MBS SM container of a ContextCreate.
const N2_CONTENT_ID: &str = "n2MbsSmInfo";

/// What the MB-SMF hands the AMF for a broadcast session (TS 23.247 §7.3.1
/// step 2: TMGI, N2 SM information, MBS service area), #1796.
#[derive(Debug, Clone)]
pub struct AmfLeg {
    /// The session's TS 29.571 `MbsServiceArea`, as the consumer gave it.
    pub mbs_service_area: Value,
    /// The session's TS 29.571 `Snssai`.
    pub snssai: Value,
    /// The MBS QoS flow of the N2 SM information.
    pub qfi: u8,
    pub five_qi: u8,
}

/// `POST /namf-mbs-bc/v1/mbs-contexts` — Namf_MBSBroadcast ContextCreate
/// (TS 29.518 §5.6.2.2), i.e. TS 23.247 §7.3.1's request for broadcast setup toward
/// the RAN.
///
/// #1796: a `ContextCreateReqData` with every member the AMF needs to drive the
/// Broadcast Session Setup: the TMGI, the MBS service area, the MBS Session Setup
/// or Modification Request Transfer as an `MBS_SES_REQ` binary part, the S-NSSAI,
/// and the `notifyUri` the AMF reports later NG-RAN answers to.
///
/// Returns the AMF's `mbsContextRef` on 201. `None` on any failure, logged:
/// this is best-effort relative to the session create, which has already
/// succeeded locally by the time it runs. A failed AMF leg means the RAN does
/// not have the session, which the caller reports rather than hides.
pub async fn context_create(
    amf: &DiscoveredAmf,
    tmgi: &Tmgi,
    leg: &AmfLeg,
    notify_base: &str,
    notify_token: &str,
) -> Option<MbsContextRef> {
    let request = context_create_request(tmgi, leg, notify_base, notify_token)?;
    // #1662: a service request to the AMF, so it carries the NRF-issued token.
    let client = crate::attach_oauth2(
        SbiClient::new(
            nextgcore_sbi::security::sbi_peer_client_config(&amf.host, amf.port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        ),
        nextgcore_sbi::types::NfType::Amf,
    );
    let response = match client.send_request(request).await {
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
    log::info!(
        "MBS: ContextCreate answered with {} N2 container(s), operationStatus {:?}",
        json.get("n2MbsSmInfoList")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        json.get("operationStatus").and_then(Value::as_str)
    );
    context_ref
}

/// The multipart ContextCreate request (`ContextCreateReqData` and the N2 MBS SM
/// container part), with the `notifyUri` for `notify_token` under `notify_base`.
/// Built here so the notifyUri, a callback URI, stays out of everything the
/// caller logs.
fn context_create_request(
    tmgi: &Tmgi,
    leg: &AmfLeg,
    notify_base: &str,
    notify_token: &str,
) -> Option<nextgcore_sbi::message::SbiRequest> {
    let transfer = match crate::n2_mbs_transfer::setup_or_mod_request_transfer(leg.qfi, leg.five_qi)
    {
        Ok(t) => t,
        Err(e) => {
            log::warn!("MBS: no ContextCreate: the N2 MBS SM container could not be built: {e}");
            return None;
        }
    };
    let body = json!({
        "mbsSessionId": mbs_session_id_json(tmgi),
        "mbsServiceArea": leg.mbs_service_area,
        "n2MbsSmInfo": {
            "ngapIeType": "MBS_SES_REQ",
            "ngapData": { "contentId": N2_CONTENT_ID },
        },
        "notifyUri": amf_notify_uri(notify_base, notify_token),
        "snssai": leg.snssai,
    });
    match nextgcore_sbi::message::SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
        .with_json_body(&body)
    {
        Ok(r) => Some(r.with_part(nextgcore_sbi::message::SbiPart::with_content(
            N2_CONTENT_ID,
            nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
            bytes::Bytes::from(transfer),
        ))),
        Err(e) => {
            log::warn!("MBS: ContextCreate body build failed: {e}");
            None
        }
    }
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

    /// #1796: the TAC of the MBS service area the stand-in gNB serves.
    const AREA_TAC: u32 = 0x00_1796;

    /// #1796: the broadcast session's AMF leg: one TAI, SST 1, QFI 1 / 5QI 9.
    fn leg() -> AmfLeg {
        AmfLeg {
            mbs_service_area: json!({ "taiList": [ { "plmnId": { "mcc": "001", "mnc": "01" },
                                                     "tac": format!("{AREA_TAC:06x}") } ] }),
            snssai: json!({ "sst": 1 }),
            qfi: 1,
            five_qi: 9,
        }
    }

    const NOTIFY_BASE: &str = "http://127.0.0.1:1";

    /// #1796: a gNB of the AMF serving [`AREA_TAC`], as amfd's NGAP task sees it.
    fn stand_in_gnb(association_id: u64) -> nextgcore_amfd::mbs_broadcast::LiveGnb {
        let plmn = nextgcore_amfd::context::PlmnId::new("001", "01");
        nextgcore_amfd::mbs_broadcast::LiveGnb {
            association_id,
            node: nextgcore_amfd::mbs_broadcast::RanNode {
                plmn: plmn.clone(),
                gnb_id: association_id as u32,
                gnb_id_len: 32,
            },
            tais: vec![(plmn, AREA_TAC)],
        }
    }

    type SentPdus = std::sync::Arc<
        std::sync::Mutex<Vec<(nextgcore_amfd::mbs_broadcast::BroadcastProcedure, Vec<u8>)>>,
    >;

    /// #1796: the AMF's NGAP side for amfd's real Namf handler, which in this
    /// process has no NGAP task: every 5 ms it runs amfd's broadcast step against
    /// the `live` gNBs, records each Broadcast Session Setup / Release Request,
    /// answers each with a Response from the gNB it went to, and sends the
    /// resulting ContextStatusNotify requests. Aborted on drop.
    struct StandInNgap {
        task: tokio::task::JoinHandle<()>,
        sent: SentPdus,
        live: std::sync::Arc<std::sync::Mutex<Vec<nextgcore_amfd::mbs_broadcast::LiveGnb>>>,
    }

    impl Drop for StandInNgap {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn stand_in_ngap() -> StandInNgap {
        use nextgcore_amfd::mbs_broadcast::{dispatch_notifies, BroadcastProcedure};
        let sent: SentPdus = std::sync::Arc::default();
        let live = std::sync::Arc::new(std::sync::Mutex::new(vec![stand_in_gnb(1)]));
        let (s, l) = (sent.clone(), live.clone());
        let task = tokio::spawn(async move {
            loop {
                let mcast = nextgcore_amfd::context::amf_mcast();
                let gnbs = l.lock().unwrap().clone();
                let plan = mcast.broadcast_plan(&gnbs, std::time::Instant::now());
                let mut notifies = plan.notifies;
                for send in plan.sends {
                    for assoc in &send.associations {
                        s.lock().unwrap().push((send.procedure, send.pdu.clone()));
                        notifies.extend(match send.procedure {
                            BroadcastProcedure::Setup => {
                                mcast.broadcast_setup_outcome(&send.tmgi, *assoc, true, None)
                            }
                            BroadcastProcedure::Release => {
                                mcast.broadcast_release_outcome(&send.tmgi, *assoc, None)
                            }
                        });
                    }
                }
                dispatch_notifies(notifies);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        StandInNgap { task, sent, live }
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

        let without = context_create(&amf, &tmgi(), &leg(), NOTIFY_BASE, "t").await;
        let with = crate::TEST_OAUTH2_CLIENT
            .scope(
                stand_in::oauth2_client_for(nrf_port, NfType::Mbsmf),
                context_create(&amf, &tmgi(), &leg(), NOTIFY_BASE, "t"),
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
                context_create(&amf, &tmgi(), &leg(), NOTIFY_BASE, "t"),
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
        // #1796: the AMF answers ContextCreate on the NG-RAN's response.
        let _ngap = stand_in_ngap();
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

        let bare = context_create(&amf, &tmgi(), &leg(), NOTIFY_BASE, "t").await;
        let after_bare = sessions();
        let oauth2 = stand_in::oauth2_client_for(nrf_port, NfType::Mbsmf);
        let first = crate::TEST_OAUTH2_CLIENT
            .scope(
                std::sync::Arc::clone(&oauth2),
                context_create(&amf, &tmgi(), &leg(), NOTIFY_BASE, "t"),
            )
            .await;
        let after_first = sessions();
        let retry = crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2,
                context_create(&amf, &tmgi(), &leg(), NOTIFY_BASE, "t"),
            )
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
        crate::mbsmf_self()
            .read()
            .unwrap()
            .set_amf_notify_base("http://127.0.0.1:1");
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
        // #1796: the AMF answers ContextCreate on the NG-RAN's response.
        let _ngap = stand_in_ngap();
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let tmgi = tmgi_1758([0x00, 0x17, 0x58]);
        let session = crate::mbsmf_self()
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("session");

        crate::TEST_OAUTH2_CLIENT
            .scope(oauth2, async {
                let context_ref = crate::create_amf_mbs_context(session.id, tmgi, amf, leg())
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
                assert_eq!(
                    crate::handle_mbs_session_release(
                        &id,
                        &nextgcore_sbi::message::SbiRequest::default()
                    )
                    .await
                    .status,
                    204
                );
                assert!(
                    !amf_holds(&context_ref),
                    "after release the AMF holds no context for the session"
                );
                assert_eq!(
                    crate::handle_mbs_session_release(
                        &id,
                        &nextgcore_sbi::message::SbiRequest::default()
                    )
                    .await
                    .status,
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
        // #1796: the AMF answers ContextCreate on the NG-RAN's response.
        let _ngap = stand_in_ngap();
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
                    crate::create_amf_mbs_context(session.id, tmgi.clone(), amf, leg()).await,
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
            notify_token: String::new(),
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

    /// **#2062**: a ContextCreate dropped mid-flight -- here its task aborted
    /// while the AMF holds the request -- forgets the notify token it minted. The
    /// token was Live, which the mint cap never reclaims, so leaked ones would
    /// fill it and refuse every later create.
    ///
    /// REVERT-VERIFIED: with the token held as a plain `String` (forgotten only
    /// on a failed answer), the aborted create leaves it behind and "the
    /// cancelled create forgets its token" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_create_forgets_its_notify_token_2062() {
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let arrived = std::sync::Arc::new(tokio::sync::Notify::new());
        let a = arrived.clone();
        // Holds every ContextCreate unanswered.
        let (_server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: nextgcore_sbi::message::SbiRequest| {
                let a = a.clone();
                async move {
                    a.notify_one();
                    std::future::pending::<nextgcore_sbi::message::SbiResponse>().await
                }
            },
        )
        .await;
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        ctx.read()
            .unwrap()
            .set_amf_notify_base("http://127.0.0.1:1");
        let session = ctx
            .read()
            .unwrap()
            .session_add(
                tmgi_1758([0x20, 0x62, 0x01]),
                crate::MbsSessionType::Broadcast,
            )
            .expect("session");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };
        let create = tokio::spawn(crate::create_amf_mbs_context(
            session.id,
            tmgi_1758([0x20, 0x62, 0x01]),
            amf,
            leg(),
        ));
        tokio::time::timeout(Duration::from_secs(5), arrived.notified())
            .await
            .expect("the ContextCreate reaches the AMF");
        assert_eq!(
            ctx.read().unwrap().amf_notify_tokens_of(session.id).len(),
            1,
            "the create in flight holds its token"
        );
        create.abort();
        assert!(create.await.expect_err("aborted").is_cancelled());
        assert_eq!(
            ctx.read().unwrap().amf_notify_tokens_of(session.id),
            Vec::<String>::new(),
            "the cancelled create forgets its token"
        );
    }

    /// **#2068**: a create whose task is aborted after the AMF's 201 but before
    /// the context is accounted for parks the context's ContextDelete, so the
    /// AMF's context is not left recorded nowhere. Deterministic: the stand-in
    /// AMF holds the 201 until the session is released (so no record is made),
    /// then holds the create's own ContextDelete, and the task is aborted there.
    ///
    /// REVERT-VERIFIED: with `CreatedAmfContext` never parking, the abort
    /// leaves nothing parked and "the aborted create's context is parked for the
    /// reconciler" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_aborted_unrecorded_create_parks_its_delete_2068() {
        use std::sync::Arc;
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let created = Arc::new(tokio::sync::Notify::new());
        let answer = Arc::new(tokio::sync::Notify::new());
        let deleting = Arc::new(tokio::sync::Notify::new());
        let (c, a, d) = (created.clone(), answer.clone(), deleting.clone());
        let (_server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |req: nextgcore_sbi::message::SbiRequest| {
                let (c, a, d) = (c.clone(), a.clone(), d.clone());
                async move {
                    if req.header.method == "DELETE" {
                        // Held: the create is aborted while its delete is here.
                        d.notify_one();
                        return std::future::pending().await;
                    }
                    c.notify_one();
                    a.notified().await;
                    nextgcore_sbi::message::SbiResponse::with_status(201)
                        .with_json_body(&json!({ "mbsContextRef": "orphan-2068" }))
                        .expect("json")
                }
            },
        )
        .await;
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        ctx.read()
            .unwrap()
            .set_amf_notify_base("http://127.0.0.1:1");
        let tmgi = tmgi_1758([0x20, 0x68, 0x01]);
        let session = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("session");
        let amf = DiscoveredAmf {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            nf_instance_id: None,
        };
        let create = tokio::spawn(crate::create_amf_mbs_context(session.id, tmgi, amf, leg()));
        let within = Duration::from_secs(5);
        tokio::time::timeout(within, created.notified())
            .await
            .expect("the ContextCreate reaches the AMF");
        // Released mid-create: the 201's context gets no record.
        ctx.read()
            .unwrap()
            .session_remove(session.id)
            .expect("removed");
        answer.notify_one();
        tokio::time::timeout(within, deleting.notified())
            .await
            .expect("the unrecorded context's ContextDelete reaches the AMF");
        assert!(
            !crate::reconcile::is_parked_for_test(addr.port(), "orphan-2068"),
            "nothing is parked while the create is running"
        );
        create.abort();
        assert!(create.await.expect_err("aborted").is_cancelled());
        assert!(
            crate::reconcile::is_parked_for_test(addr.port(), "orphan-2068"),
            "the aborted create's context is parked for the reconciler"
        );
        crate::reconcile::clear_for_test();
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
        // #1961: the AMF that refused is backing off; the next pass is after it.
        tokio::time::sleep(crate::reconcile::BACKOFF_BASE + std::time::Duration::from_millis(50))
            .await;

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

    /// **#2075**: a `release_retries` task aborted while the AMF holds one of its
    /// ContextDeletes parks every delete it had not delivered -- the one in
    /// flight and the ones behind it -- with the reconciler, instead of losing
    /// them. Deterministic: the stand-in AMF holds the first retry, and the task
    /// is aborted there.
    ///
    /// REVERT-VERIFIED: with `UndeliveredDeletes` parking nothing on drop, the
    /// abort leaves nothing parked and "the aborted retries park both deletes"
    /// fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborted_release_retries_park_their_deletes_2075() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        let (_server, context, _deletes, arrived, _release) = scripted_amf(true, &[]).await;
        crate::mbsmf_context_init(256);
        let second = crate::context::AmfMbsContext {
            context_ref: "8".to_string(),
            ..context.clone()
        };
        let retries = crate::release_retries(vec![context, second]);
        tokio::time::timeout(Duration::from_secs(5), arrived.notified())
            .await
            .expect("the first retry reaches the AMF");
        assert_eq!(
            crate::reconcile::pending_count(),
            0,
            "nothing is parked while the retries run"
        );
        retries.abort();
        assert!(retries.await.expect_err("aborted").is_cancelled());
        assert_eq!(
            crate::reconcile::pending_count(),
            2,
            "the aborted retries park both deletes"
        );
        crate::reconcile::clear_for_test();
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
                notify_token: String::new(),
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
        // #1796: the AMF answers ContextCreate on the NG-RAN's response.
        let _ngap = stand_in_ngap();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        nextgcore_amfd::test_support::init_context();
        crate::mbsmf_context_init(256);
        crate::mbsmf_self()
            .read()
            .unwrap()
            .set_amf_notify_base("http://127.0.0.1:1");
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
        let a_ref = crate::create_amf_mbs_context(a_session.id, tmgi.clone(), amf.clone(), leg())
            .await
            .expect("A's context");

        // A is released; its ContextDelete is held at the AMF.
        let a_id = format!("mbs-sess-{}", a_session.id);
        let release = tokio::spawn(async move {
            crate::handle_mbs_session_release(&a_id, &nextgcore_sbi::message::SbiRequest::default())
                .await
        });
        arrived.notified().await;
        // B, on the same TMGI, is created while that delete is in flight.
        let b_session = session(&ctx);
        let b_ref = crate::create_amf_mbs_context(b_session.id, tmgi.clone(), amf.clone(), leg())
            .await
            .expect("B's context");
        release.await.expect("release");

        // #1856: the ref is `<epoch>-<id>`.
        let live = nextgcore_amfd::ngap_mcast::parse_context_ref(&b_ref)
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
        // #1796: the AMF answers ContextCreate on the NG-RAN's response.
        let _ngap = stand_in_ngap();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        nextgcore_amfd::test_support::init_context();
        crate::mbsmf_context_init(256);
        crate::mbsmf_self()
            .read()
            .unwrap()
            .set_amf_notify_base("http://127.0.0.1:1");
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
        let a_ref = crate::create_amf_mbs_context(a.id, tmgi.clone(), amf.clone(), leg())
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
        let create = tokio::spawn(crate::create_amf_mbs_context(b_id, b_tmgi, b_amf, leg()));
        arrived.notified().await;
        // A's delete now waits behind B's create in the lane.
        let release = tokio::spawn(crate::release_amf_contexts(a_contexts));
        let b_ref = create.await.expect("create").expect("B's context");
        release.await.expect("release");
        assert_eq!(a_ref, b_ref, "the AMF handed B the context A held");
        // #1856: the ref is `<epoch>-<id>`.
        let live = nextgcore_amfd::ngap_mcast::parse_context_ref(&b_ref)
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
        let anonymous = nextgcore_sbi::message::SbiRequest::default();
        tokio::select! {
            _ = crate::handle_mbs_session_release(&id, &anonymous) => {
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

    /// #1796 (R29): after the AMF's 204 to ContextDelete the notify token is still
    /// admitted for the grace, so a Release Response Transfer the AMF reports late
    /// is accepted; after the grace it is refused. On a 404 it goes at once.
    ///
    /// REVERT-VERIFIED: with the token forgotten at the 204, the late notification
    /// is refused and "a late Release Response Transfer is still accepted" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_release_transfer_is_still_admitted_after_the_204_1796() {
        let (_server, mut context, _deletes, _arrived, _release) = scripted_amf(false, &[]).await;
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        let token = ctx
            .read()
            .unwrap()
            .mint_amf_notify_token(1796)
            .expect("a token");
        context.notify_token = token.clone();
        let late = || {
            nextgcore_sbi::message::SbiRequest::post(format!("{AMF_NOTIFY_PREFIX}/{token}"))
                .with_json_body(&json!({
                    "mbsSessionId": {},
                    "n2MbsSmInfoList": [ { "ngapIeType": "MBS_SES_REL_RSP",
                                           "ngapData": { "contentId": "n2-1" } } ],
                }))
                .unwrap()
        };

        assert!(crate::release_amf_contexts(vec![context]).await, "204");
        assert_eq!(
            crate::handle_amf_context_status_notify(&token, &late())
                .await
                .status,
            204,
            "a late Release Response Transfer is still accepted"
        );
        eventually("the token goes after the grace", || {
            ctx.read().unwrap().amf_notify_session(&token).is_none()
        })
        .await;
        assert_eq!(
            crate::handle_amf_context_status_notify(&token, &late())
                .await
                .status,
            404
        );

        // A 404 from the AMF: nothing left to notify, so the token goes at once.
        let (_server, mut gone, _d, _a, _r) = scripted_amf(false, &[404]).await;
        let token = ctx
            .read()
            .unwrap()
            .mint_amf_notify_token(1797)
            .expect("a token");
        gone.notify_token = token.clone();
        assert!(crate::release_amf_contexts(vec![gone]).await);
        assert!(ctx.read().unwrap().amf_notify_session(&token).is_none());
    }

    /// #1796, MB-SMF -> AMF: the ContextCreate this MB-SMF sends passes amfd's
    /// real handler (which refuses one lacking any mandatory member), and the
    /// BROADCAST SESSION SETUP REQUEST the gNB then receives carries the MBS
    /// service area's TAI and, byte for byte, the MBS Session Setup or
    /// Modification Request Transfer this MB-SMF built: one QoS flow, QFI 1, 5QI 9.
    ///
    /// REVERT-VERIFIED: with the n2MbsSmInfo part left out of the request, amfd
    /// answers 400 and no Setup is sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_context_create_carries_the_n2_container_to_the_gnb_1796() {
        use nextgcore_ngap_gen::generated as g;
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let ngap = stand_in_ngap();
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let tmgi = tmgi_1758([0x02, 0x17, 0x96]);

        let context_ref = crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2.clone(),
                context_create(&amf, &tmgi, &leg(), NOTIFY_BASE, "t"),
            )
            .await
            .expect("amfd creates the context");
        let sent = ngap.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "one Setup to the one gNB");
        let g::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(&sent[0].1).unwrap()
        else {
            panic!("an initiating message");
        };
        let g::InitiatingMessageValue::Id_BroadcastSessionSetup(req) = m.value else {
            panic!("a Broadcast Session Setup Request");
        };
        let (mut transfer, mut tais) = (None, None);
        for ie in req.protocol_i_es.0 {
            match ie.value {
                g::BroadcastSessionSetupRequestProtocolIEs_EntryValue::Id_MBSSessionSetupRequestTransfer(t) => transfer = Some(t.0),
                g::BroadcastSessionSetupRequestProtocolIEs_EntryValue::Id_MBS_ServiceArea(
                    g::MBS_ServiceArea::Locationindependent(a),
                ) => tais = a.mbs_service_area_tai_list.map(|l| l.0),
                _ => {}
            }
        }
        let tais = tais.expect("the service area's TAI list");
        assert_eq!(tais.len(), 1);
        assert_eq!(tais[0].tac.0, vec![0x00, 0x17, 0x96]);
        let transfer = transfer.expect("the MB-SMF's container");
        assert_eq!(
            transfer,
            crate::n2_mbs_transfer::setup_or_mod_request_transfer(1, 9).unwrap()
        );
        let decoded =
            nextgcore_ngap_gen::decode_contained::<g::MBSSessionSetupOrModRequestTransfer>(
                &transfer,
            )
            .unwrap();
        let g::MBSSessionSetupOrModRequestTransferProtocolIEs_EntryValue::Id_MBS_QoSFlowsToBeSetupModList(flows) =
            &decoded.protocol_i_es.0[0].value
        else {
            panic!("the QoS flow list");
        };
        assert_eq!(flows.0[0].mb_sqos_flow_identifier.0, 1);

        let record = crate::context::AmfMbsContext {
            host: amf.host.clone(),
            port: amf.port,
            nf_instance_id: None,
            context_ref,
            notify_token: String::new(),
            tmgi: None,
        };
        crate::TEST_OAUTH2_CLIENT
            .scope(oauth2, async {
                assert_eq!(context_delete(&record).await, ContextDeleteOutcome::Deleted);
            })
            .await;
    }

    /// #1796, AMF -> MB-SMF: when the last gNB holding the session is lost, amfd
    /// releases the context and sends a token-less ContextStatusNotify with
    /// `releasedInd` to the `notifyUri` this MB-SMF minted; the MB-SMF's
    /// OAuth2-required listener admits it on the token and drops its record of
    /// the context. A forged token is refused at the gate.
    ///
    /// REVERT-VERIFIED: with the callback exemption not installed, the notify is
    /// refused 401 and the record stays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_amfs_status_notify_passes_the_mbsmf_gate_on_its_token_1796() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let ngap = stand_in_ngap();
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr)
            .with_oauth2_callback_exemptions(crate::oauth2_callback_exemptions());
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(json!({ "keys": [] }));
        let mbsmf = SbiServer::on_listener(cfg, listener);
        mbsmf
            .start(crate::mbsmf_sbi_request_handler)
            .await
            .expect("mbsmfd listener");
        let ctx = crate::mbsmf_self();
        ctx.read()
            .unwrap()
            .set_amf_notify_base(format!("http://127.0.0.1:{}", addr.port()));
        let tmgi = tmgi_1758([0x03, 0x17, 0x96]);
        let session = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("session");

        let context_ref = crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2,
                crate::create_amf_mbs_context(session.id, tmgi, amf, leg()),
            )
            .await
            .expect("created");
        let records = ctx.read().unwrap().amf_contexts_of(session.id);
        assert_eq!(records.len(), 1);
        let token = records[0].notify_token.clone();

        let forged = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port())
            .post_json(
                &format!("{AMF_NOTIFY_PREFIX}/forged"),
                &json!({ "mbsSessionId": {}, "releasedInd": true }),
            )
            .await
            .expect("answered");
        assert_eq!(forged.status, 401, "a token this MB-SMF never minted");

        ngap.live.lock().unwrap().clear();
        nextgcore_amfd::context::amf_mcast().broadcast_rescan();
        eventually("the MB-SMF drops the record the AMF released", || {
            ctx.read().unwrap().amf_contexts_of(session.id).is_empty()
        })
        .await;
        assert!(!amf_holds(&context_ref), "and the AMF holds no context");
        assert!(
            ctx.read().unwrap().amf_notify_session(&token).is_none(),
            "nor is the token admitted any more"
        );
        ctx.read().unwrap().session_remove(session.id);
    }

    /// **#1930**: a released session's ContextDelete dropped because a later
    /// session holds the same AMF context leaves no notify token behind. The
    /// released session's token (the one the AMF notifies: it keeps the first
    /// create's notifyUri) passes to the session holding the context, and every
    /// token of the context goes with that session's release.
    ///
    /// REVERT-VERIFIED: with `forget_amf_context_tokens` forgetting only the
    /// record's own token, A's token outlives B's release ("A's token goes with the
    /// context"); with the hand-over loop in `record_amf_context` removed, A's
    /// token still names the released session ("A's token is B's now").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_delete_leaves_no_token_behind_1930() {
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        let _ngap = stand_in_ngap();
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let tmgi = tmgi_1758([0x07, 0x19, 0x30]);
        let ctx = crate::mbsmf_self();
        crate::TEST_OAUTH2_CLIENT
            .scope(oauth2, async {
                let a = ctx
                    .read()
                    .unwrap()
                    .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
                    .expect("A");
                let a_ref = crate::create_amf_mbs_context(a.id, tmgi.clone(), amf.clone(), leg())
                    .await
                    .expect("A's context");
                // A's release, up to its ContextDelete.
                ctx.read().unwrap().session_remove(a.id);
                let a_contexts = ctx.read().unwrap().take_amf_contexts(a.id);
                let a_token = a_contexts[0].notify_token.clone();
                // B, on the same TMGI, is handed the same AMF context.
                let b = ctx
                    .read()
                    .unwrap()
                    .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
                    .expect("B");
                let b_ref = crate::create_amf_mbs_context(b.id, tmgi.clone(), amf.clone(), leg())
                    .await
                    .expect("B's context");
                assert_eq!(a_ref, b_ref, "the AMF handed B the context A held");
                let b_token = ctx.read().unwrap().amf_contexts_of(b.id)[0]
                    .notify_token
                    .clone();
                // A's delete is dropped: B holds the context.
                assert!(crate::release_amf_contexts(a_contexts).await);
                assert!(amf_holds(&b_ref), "B keeps the context");
                assert_eq!(
                    ctx.read().unwrap().amf_notify_session(&a_token),
                    Some(b.id),
                    "A's token is B's now"
                );

                let id = format!("mbs-sess-{}", b.id);
                assert_eq!(
                    crate::handle_mbs_session_release(
                        &id,
                        &nextgcore_sbi::message::SbiRequest::default()
                    )
                    .await
                    .status,
                    204
                );
                eventually("A's token goes with the context", || {
                    let c = ctx.read().unwrap();
                    c.amf_notify_session(&a_token).is_none()
                        && c.amf_notify_session(&b_token).is_none()
                })
                .await;
            })
            .await;
    }

    /// **#1930**: more dropped deletes than MAX_AMF_NOTIFY_TOKENS, each followed by
    /// the release of the session that held the context, leave the token map with
    /// room: a new ContextCreate still gets a token.
    ///
    /// REVERT-VERIFIED: with `forget_amf_context_tokens` forgetting only the
    /// record's own token, every released session's token stays, the map fills,
    /// and a mint inside the loop fails ("B's token").
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_deletes_past_the_cap_still_let_a_create_through_1930() {
        crate::mbsmf_context_init(256);
        let ctx = crate::mbsmf_self();
        let tmgi = tmgi_1758([0x08, 0x19, 0x30]);
        let record = |token: String, n: usize| crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            // Nothing is sent: the delete of a context in use is dropped first.
            port: 9,
            nf_instance_id: None,
            context_ref: format!("cap-1930-{n}"),
            notify_token: token,
            tmgi: Some(tmgi.clone()),
        };
        let add = || {
            ctx.read()
                .unwrap()
                .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
                .expect("session")
        };
        for n in 0..crate::context::MAX_AMF_NOTIFY_TOKENS + 8 {
            let a = add();
            let a_token = ctx
                .read()
                .unwrap()
                .mint_amf_notify_token(a.id)
                .expect("A's token");
            assert!(ctx
                .read()
                .unwrap()
                .record_amf_context(a.id, record(a_token, n)));
            let a_contexts = ctx.read().unwrap().take_amf_contexts(a.id);
            ctx.read().unwrap().session_remove(a.id);
            let b = add();
            let b_token = ctx
                .read()
                .unwrap()
                .mint_amf_notify_token(b.id)
                .expect("B's token");
            assert!(ctx
                .read()
                .unwrap()
                .record_amf_context(b.id, record(b_token, n)));
            assert_eq!(crate::delete_in_lane(&a_contexts[0]).await, None, "dropped");
            // B's release: the AMF answers 404 (gone), so its tokens go at once.
            // Taken first: retiring re-reads the global context, and a read guard
            // held across it deadlocks behind another test's queued writer
            // (`mbsmf_context_init`).
            let b_contexts = ctx.read().unwrap().take_amf_contexts(b.id);
            for c in b_contexts {
                crate::retire_amf_notify_token(&c, ContextDeleteOutcome::Gone);
            }
            ctx.read().unwrap().session_remove(b.id);
        }
        let c = add();
        assert!(
            ctx.read().unwrap().mint_amf_notify_token(c.id).is_some(),
            "a token is still minted past the cap"
        );
        ctx.read().unwrap().session_remove(c.id);
    }

    /// #1985: a released session's context record with a fresh notify token, as
    /// its ContextCreate left it, ready for its release's ContextDelete.
    fn released_record_1985(
        mut context: crate::context::AmfMbsContext,
        svc: [u8; 3],
    ) -> (crate::context::AmfMbsContext, String) {
        let ctx = crate::mbsmf_self();
        let s = ctx
            .read()
            .unwrap()
            .session_add(tmgi_1758(svc), crate::MbsSessionType::Broadcast)
            .expect("session");
        let token = ctx
            .read()
            .unwrap()
            .mint_amf_notify_token(s.id)
            .expect("token");
        context.notify_token = token.clone();
        assert!(ctx.read().unwrap().record_amf_context(s.id, context));
        let taken = ctx.read().unwrap().take_amf_contexts(s.id);
        ctx.read().unwrap().session_remove(s.id);
        (taken.into_iter().next().expect("record"), token)
    }

    fn admitted(token: &str) -> bool {
        crate::mbsmf_self()
            .read()
            .unwrap()
            .amf_notify_session(token)
            .is_some()
    }

    /// **#1985**, both peers: a ContextDelete parked after its retry budget keeps
    /// the released session's notify token, because the context still exists at
    /// the AMF. A later session on the TMGI is handed that same context by amfd's
    /// real handler, which keeps notifying the FIRST create's notifyUri; so when
    /// the stand-in NG-RAN drops the session, amfd's `releasedInd` arrives on A's
    /// token at this MB-SMF's real listener and B's record is dropped.
    ///
    /// A's deletes are sent without an access token, so the OAuth2-gated amfd
    /// refuses each (401) and the record is parked; B's create carries one.
    ///
    /// REVERT-VERIFIED: with the retry task forgetting the tokens before it parks
    /// (main), "a parked delete keeps the token" fails, and with it and "A's token
    /// is B's now" skipped, "B is notified on A's token" times out (amfd's notify
    /// on A's token is answered 404).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_parked_delete_keeps_the_token_a_reusing_session_is_notified_on_1985() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        let ngap = stand_in_ngap();
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr)
            .with_oauth2_callback_exemptions(crate::oauth2_callback_exemptions());
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(json!({ "keys": [] }));
        let mbsmf = SbiServer::on_listener(cfg, listener);
        mbsmf
            .start(crate::mbsmf_sbi_request_handler)
            .await
            .expect("mbsmfd listener");
        let ctx = crate::mbsmf_self();
        ctx.read()
            .unwrap()
            .set_amf_notify_base(format!("http://127.0.0.1:{}", addr.port()));
        let tmgi = tmgi_1758([0x09, 0x19, 0x85]);

        let a = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("A");
        let a_ref = crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2.clone(),
                crate::create_amf_mbs_context(a.id, tmgi.clone(), amf.clone(), leg()),
            )
            .await
            .expect("A's context");
        ctx.read().unwrap().session_remove(a.id);
        let a_contexts = ctx.read().unwrap().take_amf_contexts(a.id);
        let a_token = a_contexts[0].notify_token.clone();
        // Unscoped: no access token, so every delete is refused and it is parked.
        assert!(!crate::release_amf_contexts(a_contexts).await);
        eventually("A's delete is parked after the budget", || {
            crate::reconcile::pending_count() == 1
        })
        .await;
        assert!(amf_holds(&a_ref), "the AMF still holds A's context");
        assert!(admitted(&a_token), "a parked delete keeps the token");

        let b = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("B");
        let b_ref = crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2,
                crate::create_amf_mbs_context(b.id, tmgi.clone(), amf, leg()),
            )
            .await
            .expect("B's context");
        assert_eq!(a_ref, b_ref, "the AMF handed B the context A held");
        assert_eq!(
            crate::reconcile::pending_count(),
            0,
            "B's record unparks it"
        );
        assert_eq!(
            ctx.read().unwrap().amf_notify_session(&a_token),
            Some(b.id),
            "A's token is B's now"
        );

        ngap.live.lock().unwrap().clear();
        nextgcore_amfd::context::amf_mcast().broadcast_rescan();
        eventually("B is notified on A's token", || {
            ctx.read().unwrap().amf_contexts_of(b.id).is_empty()
        })
        .await;
        assert!(!amf_holds(&b_ref));
        assert!(!admitted(&a_token), "releasedInd ends the context's tokens");
        ctx.read().unwrap().session_remove(b.id);
    }

    /// **#1985**: a parked delete never re-recorded still ends its tokens: the
    /// reconciler's 404 forgets them at once. A re-driven park of the same record
    /// is one delete (retries are idempotent), and a refused pass keeps them.
    ///
    /// REVERT-VERIFIED: with the `retire_amf_notify_token` call removed from
    /// `reconcile_once`, "the reconciler's 404 ends the token" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_reconcilers_404_ends_a_parked_contexts_token_1985() {
        use std::sync::atomic::Ordering;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        crate::mbsmf_context_init(256);
        let budget = crate::AMF_RELEASE_RETRY_DELAYS.len() + 1;
        // The first attempt, every retry and one pass are refused; then 404.
        let mut statuses = vec![503u16; budget + 1];
        statuses.push(404);
        let (_server, context, deletes, _arrived, _release) = scripted_amf(false, &statuses).await;
        let (record, token) = released_record_1985(context, [0x0a, 0x19, 0x85]);
        assert!(!crate::release_amf_contexts(vec![record.clone()]).await);
        eventually("parked after the budget", || {
            crate::reconcile::pending_count() == 1
        })
        .await;
        assert!(admitted(&token), "a parked delete keeps the token");
        crate::reconcile::park(vec![record]);
        assert_eq!(crate::reconcile::pending_count(), 1, "parked once");

        assert_eq!(crate::reconcile::reconcile_once().await, 0, "refused");
        assert!(admitted(&token), "a refused pass applies nothing");
        // #1961: the refusal backs the AMF off; a pass inside the backoff sends
        // nothing and keeps the record (and its token).
        assert_eq!(crate::reconcile::reconcile_once().await, 0, "backing off");
        assert_eq!(
            crate::reconcile::pending_count(),
            1,
            "kept through the backoff"
        );
        assert!(admitted(&token), "the backoff keeps the token");
        tokio::time::sleep(crate::reconcile::BACKOFF_BASE + std::time::Duration::from_millis(50))
            .await;
        assert_eq!(crate::reconcile::reconcile_once().await, 1, "404");
        assert!(!admitted(&token), "the reconciler's 404 ends the token");
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            budget + 2,
            "one delete a pass"
        );
        assert_eq!(crate::reconcile::pending_count(), 0);
    }

    /// **#1985**: the reconciler's 204 ends a parked context's token after the
    /// grace, not at once: the AMF may still report the release's late NG-RAN
    /// answers on it (#1796).
    ///
    /// REVERT-VERIFIED: with the `retire_amf_notify_token` call removed from
    /// `reconcile_once`, "gone after the grace" times out; with it forgetting at
    /// once (`Gone`), "admitted through the grace" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_reconcilers_204_ends_a_parked_contexts_token_after_the_grace_1985() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        crate::mbsmf_context_init(256);
        let budget = crate::AMF_RELEASE_RETRY_DELAYS.len() + 1;
        let (_server, context, _deletes, _arrived, _release) =
            scripted_amf(false, &vec![503u16; budget]).await;
        let (record, token) = released_record_1985(context, [0x0b, 0x19, 0x85]);
        assert!(!crate::release_amf_contexts(vec![record]).await);
        eventually("parked after the budget", || {
            crate::reconcile::pending_count() == 1
        })
        .await;
        assert_eq!(crate::reconcile::reconcile_once().await, 1, "204");
        assert!(admitted(&token), "admitted through the grace");
        eventually("gone after the grace", || !admitted(&token)).await;
    }

    /// **#1985** bound: a parked delete evicted at `MAX_PENDING` is abandoned, and
    /// so are its context's tokens.
    ///
    /// REVERT-VERIFIED: with `forget_abandoned` forgetting nothing, "an abandoned
    /// delete takes its token" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_abandoned_parked_delete_takes_its_token_1985() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        crate::mbsmf_context_init(256);
        let blank = |n: usize| crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: 9,
            nf_instance_id: None,
            context_ref: format!("evict-1985-{n}"),
            notify_token: String::new(),
            tmgi: None,
        };
        let (record, token) = released_record_1985(blank(usize::MAX), [0x0c, 0x19, 0x85]);
        crate::reconcile::park(vec![record]);
        crate::reconcile::park((0..crate::reconcile::MAX_PENDING - 1).map(blank).collect());
        assert!(admitted(&token), "kept while it is parked");
        crate::reconcile::park(vec![blank(crate::reconcile::MAX_PENDING)]);
        assert!(!admitted(&token), "an abandoned delete takes its token");
        crate::reconcile::clear_for_test();
    }

    /// **#1985** x #1961: a parked delete that expires after `MAX_AGE` is given
    /// up, so its context is no longer tracked and its tokens go with it.
    ///
    /// REVERT-VERIFIED: with `reconcile_once` not handing expired records to
    /// `forget_abandoned`, "an expired delete takes its token" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_parked_delete_takes_its_token_1985() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        crate::mbsmf_context_init(256);
        let blank = crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: 9,
            nf_instance_id: None,
            context_ref: "expire-1985".to_string(),
            notify_token: String::new(),
            tmgi: None,
        };
        let (record, token) = released_record_1985(blank, [0x0e, 0x19, 0x85]);
        crate::reconcile::park(vec![record]);
        assert!(admitted(&token), "kept while it is parked");
        crate::reconcile::backdate_for_test(
            crate::reconcile::MAX_AGE + std::time::Duration::from_secs(1),
        );
        assert_eq!(crate::reconcile::reconcile_once().await, 0);
        let left = crate::reconcile::pending_count();
        let kept = admitted(&token);
        crate::reconcile::clear_for_test();
        assert_eq!(left, 0, "expired");
        assert!(!kept, "an expired delete takes its token");
    }

    /// **#2015** (item 4): a session that re-records a context after its parked
    /// delete left the pending set (drained by the pass, then expired) found
    /// nothing to unpark; the expiry's forget must then leave the tokens, which
    /// are that session's now. The seam lands B's record exactly between the
    /// expiry and the forget.
    ///
    /// REVERT-VERIFIED: with `forget_abandoned` forgetting without the held check
    /// (`forget_amf_notify_token`), "B keeps its token" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_context_re_recorded_before_the_expiry_forget_keeps_its_token_2015() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        crate::mbsmf_context_init(256);
        let blank = crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: 9,
            nf_instance_id: None,
            context_ref: "expire-2015".to_string(),
            notify_token: String::new(),
            tmgi: None,
        };
        let (record, ta) = released_record_1985(blank, [0x0f, 0x20, 0x15]);
        crate::reconcile::park(vec![record.clone()]);
        crate::reconcile::backdate_for_test(
            crate::reconcile::MAX_AGE + std::time::Duration::from_secs(1),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        *crate::reconcile::BEFORE_FORGET_SEAM.lock().unwrap() = Some(Box::new(move || {
            // B's create is answered with the same context (amfd keeps A's
            // notifyUri), and B records it.
            let ctx = crate::mbsmf_self();
            let b = ctx
                .read()
                .unwrap()
                .session_add(
                    tmgi_1758([0x0f, 0x20, 0x16]),
                    crate::MbsSessionType::Broadcast,
                )
                .expect("B");
            let tb = ctx
                .read()
                .unwrap()
                .mint_amf_notify_token(b.id)
                .expect("B's token");
            let mine = crate::context::AmfMbsContext {
                notify_token: tb.clone(),
                ..record
            };
            assert!(ctx.read().unwrap().record_amf_context(b.id, mine));
            tx.send((b.id, tb)).unwrap();
        }));
        assert_eq!(crate::reconcile::reconcile_once().await, 0);
        let fired = rx.try_recv();
        crate::reconcile::BEFORE_FORGET_SEAM.lock().unwrap().take();
        let (b, tb) = fired.expect("the seam ran between the expiry and the forget");
        let ctx = crate::mbsmf_self();
        let (on_a, on_b) = {
            let g = ctx.read().unwrap();
            (g.amf_notify_session(&ta), g.amf_notify_session(&tb))
        };
        ctx.read().unwrap().take_amf_contexts(b);
        ctx.read().unwrap().session_remove(b);
        crate::reconcile::clear_for_test();
        assert_eq!(on_b, Some(b), "B keeps its token");
        assert_eq!(on_a, Some(b), "and A's, on which amfd notifies B");
    }

    /// **#2015** (item 4), both peers through amfd's real handler: A's delete is
    /// parked and expires; between the expiry and its forget (the seam), B's
    /// create is answered by amfd with A's context, which amfd keeps notifying
    /// on A's token. The expiry's forget leaves that token, so amfd's
    /// `releasedInd` on it reaches B and ends B's record.
    ///
    /// REVERT-VERIFIED: with `forget_abandoned` forgetting without the held check,
    /// "A's token is B's" fails (amfd's notify on it would then be answered 404).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expiry_racing_a_reuse_leaves_b_notified_by_amfd_2015() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let _g = nextgcore_amfd::test_support::MBS_CONTEXT_LOCK.lock().await;
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        let ngap = stand_in_ngap();
        let (_nrf, _amf_server, amf, oauth2) = gated_real_amf().await;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = SbiServerConfig::new(addr)
            .with_oauth2_callback_exemptions(crate::oauth2_callback_exemptions());
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(json!({ "keys": [] }));
        let mbsmf = SbiServer::on_listener(cfg, listener);
        mbsmf
            .start(crate::mbsmf_sbi_request_handler)
            .await
            .expect("mbsmfd listener");
        let ctx = crate::mbsmf_self();
        ctx.read()
            .unwrap()
            .set_amf_notify_base(format!("http://127.0.0.1:{}", addr.port()));
        let tmgi = tmgi_1758([0x11, 0x20, 0x15]);

        let a = ctx
            .read()
            .unwrap()
            .session_add(tmgi.clone(), crate::MbsSessionType::Broadcast)
            .expect("A");
        let a_ref = crate::TEST_OAUTH2_CLIENT
            .scope(
                oauth2.clone(),
                crate::create_amf_mbs_context(a.id, tmgi.clone(), amf.clone(), leg()),
            )
            .await
            .expect("A's context");
        ctx.read().unwrap().session_remove(a.id);
        let a_contexts = ctx.read().unwrap().take_amf_contexts(a.id);
        let a_token = a_contexts[0].notify_token.clone();
        // Parked directly (as the retry task leaves it), then aged past MAX_AGE.
        crate::reconcile::park(a_contexts);
        crate::reconcile::backdate_for_test(
            crate::reconcile::MAX_AGE + std::time::Duration::from_secs(1),
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let rt = tokio::runtime::Handle::current();
        let (b_tmgi, b_amf) = (tmgi.clone(), amf.clone());
        *crate::reconcile::BEFORE_FORGET_SEAM.lock().unwrap() = Some(Box::new(move || {
            let ctx = crate::mbsmf_self();
            let b = ctx
                .read()
                .unwrap()
                .session_add(b_tmgi.clone(), crate::MbsSessionType::Broadcast)
                .expect("B");
            let b_ref = tokio::task::block_in_place(|| {
                rt.block_on(crate::TEST_OAUTH2_CLIENT.scope(
                    oauth2,
                    crate::create_amf_mbs_context(b.id, b_tmgi, b_amf, leg()),
                ))
            });
            tx.send((b.id, b_ref)).unwrap();
        }));
        assert_eq!(crate::reconcile::reconcile_once().await, 0, "expired");
        crate::reconcile::BEFORE_FORGET_SEAM.lock().unwrap().take();
        let (b, b_ref) = rx.try_recv().expect("the seam ran");
        assert_eq!(
            b_ref.as_ref(),
            Some(&a_ref),
            "amfd handed B the context A held"
        );
        assert_eq!(
            ctx.read().unwrap().amf_notify_session(&a_token),
            Some(b),
            "A's token is B's"
        );

        ngap.live.lock().unwrap().clear();
        nextgcore_amfd::context::amf_mcast().broadcast_rescan();
        eventually("B is notified on A's token", || {
            ctx.read().unwrap().amf_contexts_of(b).is_empty()
        })
        .await;
        assert!(!amf_holds(&a_ref));
        assert!(!admitted(&a_token), "releasedInd ends the context's tokens");
        ctx.read().unwrap().session_remove(b);
        crate::reconcile::clear_for_test();
    }

    /// **#2015**: the AMF's 204 marks the context released (only its grace is
    /// left), which is what lets the token cap reclaim it; a delete that has not
    /// been answered leaves it unmarked.
    ///
    /// REVERT-VERIFIED: with the `mark_amf_context_released` call removed from
    /// `retire_amf_notify_token`, "a 204 marks it released" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_204_marks_the_context_released_for_the_cap_2015() {
        crate::mbsmf_context_init(256);
        let blank = crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port: 9,
            nf_instance_id: None,
            context_ref: "released-2015".to_string(),
            notify_token: String::new(),
            tmgi: None,
        };
        let (record, token) = released_record_1985(blank, [0x10, 0x20, 0x15]);
        let released = |t: &str| {
            crate::mbsmf_self()
                .read()
                .unwrap()
                .amf_notify_token_released(t)
        };
        assert!(!released(&token), "pending: not released");
        crate::retire_amf_notify_token(&record, ContextDeleteOutcome::Deleted);
        assert!(released(&token), "a 204 marks it released");
        assert!(admitted(&token), "still admitted through the grace");
    }

    /// **#1985** (cancellation): a reconcile pass aborted while its delete is in
    /// flight re-parks that record, so its context's token still has a path to its
    /// end (the next pass) rather than being orphaned.
    ///
    /// REVERT-VERIFIED: with `Repark` dropping the in-flight record, "a cancelled
    /// pass re-parks its in-flight delete" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_pass_re_parks_its_in_flight_delete_1985() {
        let _p = crate::reconcile::PENDING_TEST_LOCK.lock().await;
        crate::reconcile::clear_for_test();
        crate::mbsmf_context_init(256);
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Accepts and never answers: the delete stays in flight.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(tokio::sync::Notify::new());
        let a = accepted.clone();
        let hole = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
                a.notify_one();
            }
        });
        let context = crate::context::AmfMbsContext {
            host: "127.0.0.1".to_string(),
            port,
            nf_instance_id: None,
            context_ref: "cancel-1985".to_string(),
            notify_token: String::new(),
            tmgi: None,
        };
        let (record, token) = released_record_1985(context, [0x0d, 0x19, 0x85]);
        crate::reconcile::park(vec![record.clone()]);
        let pass = tokio::spawn(crate::reconcile::reconcile_once());
        accepted.notified().await;
        // #2175: about this record, not the whole pending set: a sibling
        // session's detached release-retry task parks its own failures into the
        // same set on its own schedule (it outlives the test that started it,
        // and so the lock), which made a count of 0 / 1 fail about 1 run in 4
        // under load.
        assert!(
            !crate::reconcile::is_parked(&record),
            "drained into the pass (pending: {})",
            crate::reconcile::pending_count()
        );
        pass.abort();
        let _ = pass.await;
        assert!(
            crate::reconcile::is_parked(&record),
            "a cancelled pass re-parks its in-flight delete (pending: {})",
            crate::reconcile::pending_count()
        );
        assert!(admitted(&token), "and its token");
        crate::reconcile::clear_for_test();
        hole.abort();
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
