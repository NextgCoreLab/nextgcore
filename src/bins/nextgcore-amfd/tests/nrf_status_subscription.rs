//! #668: the AMF's NF status subscriptions at the NRF (TS 29.510 §5.2.2.5),
//! against a stand-in NRF.
//!
//! An integration test, so it runs in its own process: it points the global
//! SBI context at the stand-in NRF and seeds the process discovery cache,
//! which amfd's unit tests share with hundreds of others.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nextgcore_amfd::nrf_subscription::{
    self, MaintainOutcome, NrfSubscription, NrfSubscriptions, NOTIFY_PATH,
};
use nextgcore_amfd::sbi_path::{self, CACHED_PEER_NF_TYPES};
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::datetime::{epoch_to_rfc3339, now_epoch_secs, rfc3339_to_epoch};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    content_type: Option<String>,
    body: Option<Value>,
}

/// A stand-in NRF: records every request; answers subscribe with 201,
/// renew with 200 (or 404 when `forget` is set), unsubscribe with 204, and
/// SMF discovery with `discovery`.
struct StandInNrf {
    seen: Arc<Mutex<Vec<Seen>>>,
    forget: Arc<AtomicBool>,
    discoveries: Arc<AtomicUsize>,
    addr: std::net::SocketAddr,
    _server: nextgcore_sbi::server::SbiServer,
}

/// The lifetime the stand-in grants: short, so a renewal is due 40 s in.
const GRANTED_SECS: u64 = 100;

async fn stand_in_nrf(discovery: Value) -> StandInNrf {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let forget = Arc::new(AtomicBool::new(false));
    let discoveries = Arc::new(AtomicUsize::new(0));
    let next_id = Arc::new(AtomicUsize::new(0));
    let (s, f, d) = (seen.clone(), forget.clone(), discoveries.clone());
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let (seen, forget, discoveries, next_id, discovery) =
                (s.clone(), f.clone(), d.clone(), next_id.clone(), discovery.clone());
            async move {
                let body: Option<Value> = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|b| serde_json::from_str(b).ok());
                seen.lock().unwrap().push(Seen {
                    method: req.header.method.clone(),
                    path: req.header.uri.clone(),
                    content_type: req.http.get_header("content-type").cloned(),
                    body: body.clone(),
                });
                let with = |status: u16, v: Value| {
                    let mut r = SbiResponse::with_status(status);
                    r.http.content = Some(v.to_string());
                    r.http.set_header("Content-Type", "application/json");
                    r
                };
                let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                match (req.header.method.as_str(), path.as_str()) {
                    ("POST", "/nnrf-nfm/v1/subscriptions") => {
                        let n = next_id.fetch_add(1, Ordering::SeqCst);
                        let mut doc = body.unwrap_or(json!({}));
                        doc["subscriptionId"] = json!(format!("sub-{n}"));
                        doc["validityTime"] = json!(epoch_to_rfc3339(now_epoch_secs() + GRANTED_SECS));
                        with(201, doc)
                    }
                    ("PATCH", p) if p.starts_with("/nnrf-nfm/v1/subscriptions/") => {
                        if forget.load(Ordering::SeqCst) {
                            return SbiResponse::with_status(404);
                        }
                        let value = body
                            .as_ref()
                            .and_then(|b| b.get(0))
                            .and_then(|op| op.get("value"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        with(200, json!({ "subscriptionId": p.rsplit('/').next(), "validityTime": value }))
                    }
                    ("DELETE", p) if p.starts_with("/nnrf-nfm/v1/subscriptions/") => {
                        SbiResponse::with_status(204)
                    }
                    ("GET", "/nnrf-disc/v1/nf-instances") => {
                        discoveries.fetch_add(1, Ordering::SeqCst);
                        with(200, discovery)
                    }
                    _ => SbiResponse::with_status(404),
                }
            }
        })
        .await;
    StandInNrf {
        seen,
        forget,
        discoveries,
        addr,
        _server: server,
    }
}

impl StandInNrf {
    fn uri(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

const NOTIFY_URI: &str = "http://127.0.0.1:7777/namf-callback/v1/nf-status-notify";

fn smf_profile(id: &str, port: u16) -> Value {
    json!({
        "nfInstanceId": id, "nfType": "SMF", "nfStatus": "REGISTERED",
        "ipv4Addresses": ["127.0.0.1"],
        "nfServices": [{
            "serviceInstanceId": "1", "serviceName": "nsmf-pdusession",
            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
        }]
    })
}

fn dev_profile() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
}

/// One subscription per cached NF type, with the conformant body; then a due
/// renewal PATCHes `validityTime`; a forgotten one is re-created; shutdown
/// deletes what is held.
#[tokio::test]
async fn subscribes_per_type_renews_resubscribes_and_unsubscribes() {
    dev_profile();
    let nrf = stand_in_nrf(json!({ "nfInstances": [] })).await;
    let mut subs = NrfSubscriptions::default();

    let outcomes =
        nrf_subscription::maintain_all(&mut subs, &nrf.uri(), "amf-668", NOTIFY_URI).await;
    assert_eq!(outcomes.len(), CACHED_PEER_NF_TYPES.len());
    assert!(
        outcomes.values().all(|o| *o == MaintainOutcome::Subscribed),
        "{outcomes:?}"
    );
    let posts = nrf.take();
    assert_eq!(posts.len(), CACHED_PEER_NF_TYPES.len());
    let mut tokens = std::collections::HashSet::new();
    let mut types: Vec<String> = posts
        .iter()
        .map(|p| {
            assert_eq!(
                (p.method.as_str(), p.path.as_str()),
                ("POST", "/nnrf-nfm/v1/subscriptions")
            );
            let b = p.body.as_ref().unwrap();
            // #940 M2: each subscription is notified on its own token.
            let uri = b["nfStatusNotificationUri"].as_str().unwrap();
            let token = uri
                .strip_prefix(&format!("{NOTIFY_URI}/"))
                .unwrap_or_else(|| panic!("{uri} is not under {NOTIFY_URI}/"));
            assert!(token.len() >= 32, "{token} is guessable");
            let nf_type = b["subscrCond"]["nfType"].as_str().unwrap();
            assert_eq!(
                nrf_subscription::token_nf_type(token).as_deref(),
                Some(nf_type)
            );
            assert_eq!(subs.by_nf_type[nf_type].token, token);
            assert!(tokens.insert(token.to_string()), "a token was reused");
            assert_eq!(b["reqNfInstanceId"], "amf-668");
            assert_eq!(
                b["reqNotifEvents"],
                json!(["NF_DEREGISTERED", "NF_PROFILE_CHANGED"])
            );
            b["subscrCond"]["nfType"].as_str().unwrap().to_string()
        })
        .collect();
    types.sort();
    let mut want: Vec<String> = CACHED_PEER_NF_TYPES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(types, want);
    let smf = subs.by_nf_type["SMF"].clone();
    assert!(smf.expires_at.unwrap() >= now_epoch_secs() + GRANTED_SECS - 2);

    // Nothing due: a pass sends nothing.
    let outcomes =
        nrf_subscription::maintain_all(&mut subs, &nrf.uri(), "amf-668", NOTIFY_URI).await;
    assert!(outcomes.values().all(|o| *o == MaintainOutcome::Unchanged));
    assert!(nrf.take().is_empty());

    // The SMF subscription is 10 s from expiry: renewed by PATCH.
    let now = now_epoch_secs();
    subs.by_nf_type.insert(
        "SMF".into(),
        NrfSubscription {
            granted_at: now - (GRANTED_SECS - 10),
            expires_at: Some(now + 10),
            ..smf.clone()
        },
    );
    let outcomes =
        nrf_subscription::maintain_all(&mut subs, &nrf.uri(), "amf-668", NOTIFY_URI).await;
    assert_eq!(outcomes["SMF"], MaintainOutcome::Renewed);
    let seen = nrf.take();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let patch = &seen[0];
    assert_eq!(patch.method, "PATCH");
    assert_eq!(patch.path, format!("/nnrf-nfm/v1/subscriptions/{}", smf.id));
    assert_eq!(
        patch.content_type.as_deref(),
        Some("application/json-patch+json")
    );
    let op = &patch.body.as_ref().unwrap()[0];
    assert_eq!(
        (op["op"].as_str(), op["path"].as_str()),
        (Some("replace"), Some("/validityTime"))
    );
    let asked = rfc3339_to_epoch(op["value"].as_str().unwrap()).unwrap();
    assert!(
        asked >= now + GRANTED_SECS - 2,
        "renewal asked for too little: {asked} vs {now}"
    );
    assert_eq!(subs.by_nf_type["SMF"].expires_at, Some(asked));
    assert_eq!(subs.by_nf_type["SMF"].id, smf.id);

    // The NRF lost it (restart): the renewal's 404 becomes a new subscription.
    nrf.forget.store(true, Ordering::SeqCst);
    let now = now_epoch_secs();
    subs.by_nf_type.insert(
        "SMF".into(),
        NrfSubscription {
            granted_at: now - (GRANTED_SECS - 10),
            expires_at: Some(now + 10),
            ..smf.clone()
        },
    );
    let outcomes =
        nrf_subscription::maintain_all(&mut subs, &nrf.uri(), "amf-668", NOTIFY_URI).await;
    assert_eq!(outcomes["SMF"], MaintainOutcome::Resubscribed);
    let seen = nrf.take();
    assert_eq!(
        seen.iter().map(|s| s.method.as_str()).collect::<Vec<_>>(),
        ["PATCH", "POST"]
    );
    assert_eq!(
        seen[1].body.as_ref().unwrap()["subscrCond"]["nfType"],
        "SMF"
    );
    assert_ne!(subs.by_nf_type["SMF"].id, smf.id);
    // The replaced subscription's token no longer evicts anything.
    assert_ne!(subs.by_nf_type["SMF"].token, smf.token);
    assert_eq!(nrf_subscription::token_nf_type(&smf.token), None);
    assert_eq!(
        nrf_subscription::token_nf_type(&subs.by_nf_type["SMF"].token).as_deref(),
        Some("SMF")
    );

    // Shutdown: one DELETE per held subscription.
    let held: Vec<String> = subs.by_nf_type.values().map(|s| s.id.clone()).collect();
    let held_tokens: Vec<String> = subs.by_nf_type.values().map(|s| s.token.clone()).collect();
    let removed = nrf_subscription::unsubscribe_all(&mut subs, &nrf.uri()).await;
    assert_eq!(removed, held.len());
    assert!(held_tokens
        .iter()
        .all(|t| nrf_subscription::token_nf_type(t).is_none()));
    assert!(subs.by_nf_type.is_empty());
    let mut deleted: Vec<String> = nrf
        .take()
        .into_iter()
        .map(|s| {
            assert_eq!(s.method, "DELETE");
            s.path.rsplit('/').next().unwrap().to_string()
        })
        .collect();
    deleted.sort();
    let mut held = held;
    held.sort();
    assert_eq!(deleted, held);
}

/// A blackholed NRF (TEST-NET-1, no answer at all) costs one bounded wait
/// for the whole pass, not one per type, and leaves nothing held.
#[tokio::test]
async fn a_blackholed_nrf_bounds_the_pass() {
    dev_profile();
    let mut subs = NrfSubscriptions::default();
    let started = Instant::now();
    let outcomes =
        nrf_subscription::maintain_all(&mut subs, "http://192.0.2.1:7777", "amf-668", NOTIFY_URI)
            .await;
    let took = started.elapsed();
    assert!(
        took < nrf_subscription::NRF_REQUEST_TIMEOUT + Duration::from_secs(3),
        "the pass took {took:?}"
    );
    assert_eq!(outcomes.len(), CACHED_PEER_NF_TYPES.len());
    assert!(
        outcomes
            .values()
            .all(|o| matches!(o, MaintainOutcome::Failed(_))),
        "{outcomes:?}"
    );
    assert!(subs.by_nf_type.is_empty());
}

fn cached_smf(id: &str, port: u16) -> NfInstance {
    use nextgcore_sbi::types::{NfType, SbiServiceType};
    let mut i = NfInstance::new(id, NfType::Smf);
    let mut svc = NfService::new("nsmf-pdusession", SbiServiceType::NsmfPdusession);
    svc.ip_addresses = vec!["127.0.0.1".into()];
    svc.port = port;
    i.add_service(svc);
    i
}

/// Subscribe at `nrf` and return the SMF subscription's notification token.
async fn smf_token(nrf: &StandInNrf) -> String {
    let mut subs = NrfSubscriptions::default();
    nrf_subscription::maintain_all(&mut subs, &nrf.uri(), "amf-668", NOTIFY_URI).await;
    nrf.take();
    subs.by_nf_type["SMF"].token.clone()
}

async fn notify_dereg(token: &str, nrf_uri: &str, id: &str) -> u16 {
    nextgcore_amfd::namf_server::namf_request_handler(
        SbiRequest::post(format!("{NOTIFY_PATH}/{token}")).with_body(
            json!({
                "event": "NF_DEREGISTERED",
                "nfInstanceUri": format!("{nrf_uri}/nnrf-nfm/v1/nf-instances/{id}"),
            })
            .to_string(),
            "application/json",
        ),
    )
    .await
    .status
}

/// The point of #668: a deregistered SMF leaves the cache when the NRF says
/// so, and the next resolution reaches the replacement, with no request to the
/// old SMF having failed first.
///
/// #940 M2: the old SMF is the last one cached, so the notification does not
/// drop it outright. It re-discovers SMF, and the NRF's answer decides: here
/// the NRF lists only the replacement, so the old one goes. Then the two ways
/// the last instance must survive: an NRF that still lists it (a forged or
/// stale notification), and an NRF that does not answer (192.0.2.1). One test,
/// because every step points the process's one NRF URI somewhere.
#[tokio::test]
async fn a_deregistration_notification_makes_the_next_resolution_rediscover() {
    use nextgcore_sbi::types::NfType;
    dev_profile();
    let nrf = stand_in_nrf(json!({
        "validityPeriod": 3600,
        "nfInstances": [smf_profile("smf-668-new", 46682)],
    }))
    .await;
    let token = smf_token(&nrf).await;
    let ctx = global_context();
    ctx.set_nrf_uri(nrf.uri()).await;

    ctx.replace_nf_instances(
        NfType::Smf,
        vec![cached_smf("smf-668-old", 46681)],
        Duration::from_secs(3600),
    )
    .await;
    let ep = sbi_path::resolve_nf_endpoint_async(sbi_path::SbiServiceType::NsmfPdusession)
        .await
        .unwrap();
    assert_eq!(ep, ("127.0.0.1".to_string(), 46681));
    assert_eq!(nrf.discoveries.load(Ordering::SeqCst), 0);

    assert_eq!(notify_dereg(&token, &nrf.uri(), "smf-668-old").await, 204);
    let replaced = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(5),
        Duration::from_millis(20),
        || async {
            (ctx.get_nf_instance("smf-668-old").await.is_none()
                && ctx.get_nf_instance("smf-668-new").await.is_some())
            .then_some(())
        },
    )
    .await;
    assert!(
        replaced.is_some(),
        "the NRF's answer did not replace the old SMF"
    );
    let ep = sbi_path::resolve_nf_endpoint_async(sbi_path::SbiServiceType::NsmfPdusession)
        .await
        .unwrap();
    assert_eq!(ep, ("127.0.0.1".to_string(), 46682));
    assert_eq!(nrf.discoveries.load(Ordering::SeqCst), 1);

    // A notification for an SMF the NRF still lists: re-discovered, and kept.
    // `smf-668-new` was never acted on, so the hold does not apply.
    assert_eq!(notify_dereg(&token, &nrf.uri(), "smf-668-new").await, 204);
    let asked = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(5),
        Duration::from_millis(20),
        || async { (nrf.discoveries.load(Ordering::SeqCst) == 2).then_some(()) },
    )
    .await;
    assert!(asked.is_some(), "no re-discovery for the last SMF");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        ctx.get_nf_instance("smf-668-new").await.is_some(),
        "the last SMF was dropped although the NRF still lists it"
    );

    // The NRF stops answering: the last SMF stays, and the callback itself
    // does not wait for the NRF.
    ctx.replace_nf_instances(
        NfType::Smf,
        vec![cached_smf("smf-940-blackholed", 46684)],
        Duration::from_secs(3600),
    )
    .await;
    ctx.set_nrf_uri("http://192.0.2.1:7777").await;
    let started = Instant::now();
    assert_eq!(
        notify_dereg(&token, "http://192.0.2.1:7777", "smf-940-blackholed").await,
        204
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the callback waited {:?} on the NRF",
        started.elapsed()
    );
    tokio::time::sleep(nrf_subscription::NRF_REQUEST_TIMEOUT + Duration::from_secs(1)).await;
    assert!(
        ctx.get_nf_instance("smf-940-blackholed").await.is_some(),
        "the last SMF was dropped while the NRF could not be asked"
    );
    ctx.clear_nrf_uri().await;
}

/// Against the real `nextgcore-nrfd` binary (manual: `NEXTGCORE_LIVE_NRF_URI=http://127.0.0.1:<port>
/// cargo test -p nextgcore-amfd --test nrf_status_subscription -- --ignored`). The NRF accepts
/// the AMF's subscription and renewal, and its NF_DEREGISTERED for an SMF reaches the AMF's
/// callback route and evicts that SMF.
#[tokio::test]
#[ignore = "needs a running nextgcore-nrfd at NEXTGCORE_LIVE_NRF_URI"]
async fn live_nrfd_subscription_renewal_and_deregistration() {
    use nextgcore_sbi::types::{NfType, SbiServiceType};
    dev_profile();
    let Ok(nrf_uri) = std::env::var("NEXTGCORE_LIVE_NRF_URI") else {
        return;
    };
    let (_amf, amf_addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
        nextgcore_amfd::namf_server::namf_request_handler,
    )
    .await;
    let notify_uri = format!("http://{amf_addr}{NOTIFY_PATH}");
    let mut subs = NrfSubscriptions::default();
    let outcomes =
        nrf_subscription::maintain_all(&mut subs, &nrf_uri, "amf-668-live", &notify_uri).await;
    assert!(
        outcomes.values().all(|o| *o == MaintainOutcome::Subscribed),
        "{outcomes:?}"
    );

    // Force a renewal of the SMF subscription.
    let smf = subs.by_nf_type["SMF"].clone();
    let now = now_epoch_secs();
    subs.by_nf_type.insert(
        "SMF".into(),
        NrfSubscription {
            granted_at: now - 1000,
            expires_at: Some(now + 10),
            ..smf.clone()
        },
    );
    let outcomes =
        nrf_subscription::maintain_all(&mut subs, &nrf_uri, "amf-668-live", &notify_uri).await;
    assert_eq!(outcomes["SMF"], MaintainOutcome::Renewed);

    // An SMF registers, the AMF caches it, then it deregisters.
    let id = "6680a6c8-0000-4000-8000-000000000668";
    let (host, port) = {
        let s = nrf_uri.trim_start_matches("http://");
        let (h, p) = s.rsplit_once(':').unwrap();
        (
            h.to_string(),
            p.trim_end_matches('/').parse::<u16>().unwrap(),
        )
    };
    let client = nextgcore_sbi::client::SbiClient::for_peer(host, port);
    let put = client
        .put_json(
            &format!("/nnrf-nfm/v1/nf-instances/{id}"),
            &smf_profile(id, 46683),
        )
        .await
        .unwrap();
    assert!(
        put.status == 201 || put.status == 200,
        "register answered {}",
        put.status
    );
    let mut cached = NfInstance::new(id, NfType::Smf);
    let mut svc = NfService::new("nsmf-pdusession", SbiServiceType::NsmfPdusession);
    svc.ip_addresses = vec!["127.0.0.1".into()];
    svc.port = 46683;
    cached.add_service(svc);
    global_context().add_nf_instance(cached).await;

    let del = client
        .delete(&format!("/nnrf-nfm/v1/nf-instances/{id}"))
        .await
        .unwrap();
    assert_eq!(del.status, 204);
    let gone = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(10),
        Duration::from_millis(50),
        || async {
            global_context()
                .get_nf_instance(id)
                .await
                .is_none()
                .then_some(())
        },
    )
    .await;
    assert!(
        gone.is_some(),
        "the NRF's NF_DEREGISTERED did not evict the SMF"
    );

    assert_eq!(
        nrf_subscription::unsubscribe_all(&mut subs, &nrf_uri).await,
        CACHED_PEER_NF_TYPES.len()
    );
}
