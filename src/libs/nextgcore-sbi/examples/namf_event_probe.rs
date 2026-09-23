//! Subscribe to `Namf_EventExposure` on a LIVE AMF, then require that a real
//! registration over N2 delivers the registration-path event notifications with
//! the values the registering UE actually carries.
//!
//! # Why this exists
//!
//! Issue #397 moved `REGISTRATION_STATE_REPORT`, `LOCATION_REPORT` and
//! `ACCESS_TYPE_REPORT` onto `send_registration_accept`, and they fire there
//! **after** `send_to_association(..).await?` — deliberately, because the event is
//! "the Accept has egressed", not "the Accept was built" (TS 24.501 §5.5.1.2.4: the
//! UE enters 5GMM-REGISTERED on *receiving* the Accept). With no NG-RAN association
//! that `?` returns early and the fire point is never reached, so an in-process test
//! with no transport asserts an **unreachable site and passes whether the wiring
//! exists or not**.
//!
//! An earlier revision of PR #402 solved that with a synthetic in-process SCTP peer
//! inside amfd's unit tests. The repository owner refused it, correctly: the real
//! gNB lives in the sibling `NextgCoreLab/nextgsim` repo and the CI Docker E2E job
//! already checks that repo out, so a second loopback gNB inside nextgcore
//! duplicates a peer that exists properly next door. This probe is where that
//! coverage moved to — the egress-ordering property is now proven against
//! **nextgsim's real gNB over real N2**, or not proven at all.
//!
//! # Why it is positive, and why it can fail
//!
//! Issue #187's CI history is the reason this asserts notification BODIES and never
//! the absence of an error: its first version grepped a log for `invalid_client` and
//! passed because the log contained zero token requests. A negative assertion is
//! satisfied by every path that never arrives.
//!
//! So this requires, positively:
//!
//! * a `REGISTRATION_STATE_REPORT` for the registering SUPI whose
//!   `rmInfoList[0].rmState` is `REGISTERED` and whose `accessType` is
//!   `3GPP_ACCESS` (`RmInfo` requires both members,
//!   `TS29518_Namf_EventExposure.yaml:908-910`);
//! * a `LOCATION_REPORT` whose `nrLocation.tai` carries the PLMN and TAC **the gNB
//!   reported** — supplied on the command line from the deployed `gnb.yaml`, so a
//!   report assembled from a default `Tai5gs` (which would say `mcc 000`, `mnc 000`,
//!   `tac 0000`) fails;
//! * an `ACCESS_TYPE_REPORT` naming `3GPP_ACCESS`;
//! * every notification carrying THIS subscription's `notifyCorrelationId`, so a
//!   report cannot satisfy it by belonging to somebody else's subscription.
//!
//! And it carries a NEGATIVE control: a second subscription for the same event types
//! targeted at a SUPI that never registers must receive nothing. Without it, an AMF
//! that broadcast every event to every subscriber would pass — so the control is
//! what makes the positive half mean "delivered to the right consumer" rather than
//! "delivered to somebody".
//!
//! An example rather than a test: it needs a live AMF and a live NG-RAN, neither of
//! which exists under `cargo test`.
//!
//! # Usage
//!
//! ```text
//! namf_event_probe <amf-host:port> <sink-bind-port> <sink-advertise-host> \
//!                  <supi> <control-supi> <expect-mcc> <expect-mnc> <expect-tac-hex> \
//!                  <timeout-secs>
//! ```
//!
//! It prints `SUBSCRIBED` once both subscriptions exist, and only then may the
//! caller start the gNB and UE — the AMF delivers nothing to a subscription that
//! does not yet exist, so a registration that happens first would make this probe
//! time out for a reason unrelated to the wiring. The caller MUST wait for that
//! line rather than sleeping.
//!
//! Exits 0 only when every positive expectation holds AND the control received
//! nothing.

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

/// One notification as the sink received it: which callback path it arrived on,
/// and the parsed `AmfEventNotification` body.
struct Received {
    path: String,
    body: Value,
}

const MAIN_PATH: &str = "/notify/main";
const CONTROL_PATH: &str = "/notify/control";

fn fail(msg: &str) -> ! {
    eprintln!("::error::{msg}");
    eprintln!("FAIL: {msg}");
    std::process::exit(1);
}

/// POST one `AmfEventSubscription` and return its subscription ID.
///
/// `supi` targets the subscription (TS 29.518 §5.3.2.2.2); the AMF's
/// `event_subscriptions_matching_ue` keys on it, which is what the negative control
/// depends on.
async fn subscribe(
    client: &SbiClient,
    notify_uri: &str,
    correlation_id: &str,
    supi: &str,
    event_types: &[&str],
) -> String {
    let body = json!({
        "subscription": {
            "eventList": event_types.iter().map(|t| json!({ "type": t })).collect::<Vec<_>>(),
            "eventNotifyUri": notify_uri,
            "notifyCorrelationId": correlation_id,
            // TS 29.518 Table 6.2.6.2.3-1 marks `nfId` mandatory. A probe is not a
            // registered NF, so this is a fixed UUID that identifies the probe in
            // the AMF's log rather than a real NF Instance ID.
            "nfId": "6b1d7e3c-0000-4000-8000-00000000e397",
            "supi": supi,
        }
    });
    let response = match client.post_json("/namf-evts/v1/subscriptions", &body).await {
        Ok(r) => r,
        Err(e) => fail(&format!(
            "could not reach the AMF's Namf_EventExposure subscribe endpoint: {e}. \
             Without a subscription the AMF delivers nothing, so this probe cannot \
             assert anything -- check the AMF is up and serving namf-evts."
        )),
    };
    if response.status != 201 {
        fail(&format!(
            "the AMF answered {} to POST /namf-evts/v1/subscriptions (expected 201). \
             Body: {:?}",
            response.status, response.http.content
        ));
    }
    let parsed: Value = match response.json_body() {
        Ok(v) => v,
        Err(e) => fail(&format!("the 201 body is not JSON: {e}")),
    };
    match parsed["subscriptionId"].as_str() {
        Some(id) => id.to_string(),
        None => fail(&format!(
            "the 201 carried no subscriptionId, so the subscription cannot be \
             deleted afterwards: {parsed}"
        )),
    }
}

/// Assert `got == want` for one report member, naming the member and the reason.
fn expect_str(report: &Value, pointer: &str, want: &str, why: &str) {
    let got = report.pointer(pointer).and_then(Value::as_str);
    if got != Some(want) {
        fail(&format!(
            "{pointer} is {got:?}, expected {want:?}. {why}\nThe report was: {report}"
        ));
    }
    println!("  ok {pointer} == {want:?}");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 10 {
        eprintln!(
            "usage: {} <amf-host:port> <sink-bind-port> <sink-advertise-host> <supi> \
             <control-supi> <expect-mcc> <expect-mnc> <expect-tac-hex> <timeout-secs>",
            args[0]
        );
        std::process::exit(2);
    }
    let amf = &args[1];
    let sink_port: u16 = args[2].parse().unwrap_or_else(|e| {
        eprintln!("sink-bind-port: {e}");
        std::process::exit(2);
    });
    let sink_host = &args[3];
    let supi = &args[4];
    let control_supi = &args[5];
    let (expect_mcc, expect_mnc, expect_tac) = (&args[6], &args[7], &args[8]);
    let timeout_secs: u64 = args[9].parse().unwrap_or_else(|e| {
        eprintln!("timeout-secs: {e}");
        std::process::exit(2);
    });

    let Some((amf_host, amf_port)) = amf.rsplit_once(':') else {
        eprintln!("amf-host:port must contain a port");
        std::process::exit(2);
    };
    let amf_port: u16 = amf_port.parse().unwrap_or_else(|e| {
        eprintln!("amf port: {e}");
        std::process::exit(2);
    });

    // Bind 0.0.0.0, not loopback: the AMF POSTs to this container's routable
    // address on the core network, and a loopback-only sink would refuse the
    // connection -- which the AMF logs as a delivery warning and this probe would
    // then report as "nothing was delivered", blaming the wiring for a bind.
    let bind: std::net::SocketAddr = format!("0.0.0.0:{sink_port}")
        .parse()
        .expect("0.0.0.0 with a parsed port is a valid SocketAddr");
    let (tx, mut rx) = mpsc::channel::<Received>(32);
    let sink = SbiServer::new(SbiServerConfig::new(bind));
    let started = sink
        .start(move |req: SbiRequest| {
            let tx = tx.clone();
            async move {
                let path = req
                    .header
                    .uri
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let body: Value = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str(c).ok())
                    .unwrap_or(Value::Null);
                let _ = tx.send(Received { path, body }).await;
                // TS 29.518 §6.2.5.2: the consumer answers 204 to a notification.
                SbiResponse::no_content()
            }
        })
        .await;
    if let Err(e) = started {
        fail(&format!("the notification sink could not bind {bind}: {e}"));
    }

    let client = SbiClient::new(
        SbiClientConfig::new(amf_host, amf_port)
            .with_connect_timeout(Duration::from_secs(5))
            .with_request_timeout(Duration::from_secs(10)),
    );

    // The three registration-path types #397 wired, and no others: this probe
    // asserts the registration fire point, so subscribing to types fired elsewhere
    // would make a timeout ambiguous about which site failed.
    let events = [
        "REGISTRATION_STATE_REPORT",
        "LOCATION_REPORT",
        "ACCESS_TYPE_REPORT",
    ];
    let main_correlation = "corr-397-e2e-main";
    let control_correlation = "corr-397-e2e-control";

    let main_id = subscribe(
        &client,
        &format!("http://{sink_host}:{sink_port}{MAIN_PATH}"),
        main_correlation,
        supi,
        &events,
    )
    .await;
    let control_id = subscribe(
        &client,
        &format!("http://{sink_host}:{sink_port}{CONTROL_PATH}"),
        control_correlation,
        control_supi,
        &events,
    )
    .await;

    // The caller gates starting the gNB/UE on this line. Flushed before any wait,
    // because a registration that happens before the subscriptions exist is
    // delivered to nobody (`event_subscriptions_matching_ue` finds no match) and the
    // probe would time out for a reason that is not the wiring.
    println!("SUBSCRIBED main={main_id} control={control_id}");
    println!(
        "waiting up to {timeout_secs}s for the registration of {supi} to deliver {:?}",
        events
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // Collect until every expected type has arrived on the main callback, or the
    // budget expires. Reports are keyed by type rather than read positionally: the
    // AMF spawns one delivery task per subscriber per event, so three reports fired
    // from one site arrive in a non-deterministic order.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut collected: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let mut control_hits: Vec<Value> = Vec::new();
    while collected.len() < events.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(Some(received)) = tokio::time::timeout(remaining, rx.recv()).await else {
            break;
        };
        if received.path == CONTROL_PATH {
            control_hits.push(received.body);
            continue;
        }
        if received.path != MAIN_PATH {
            fail(&format!(
                "a notification arrived on {:?}, which is neither callback this probe \
                 registered -- the AMF is not honouring eventNotifyUri",
                received.path
            ));
        }
        let notification = received.body;
        let correlation = notification["notifyCorrelationId"].as_str();
        if correlation != Some(main_correlation) {
            fail(&format!(
                "a notification on the main callback carried notifyCorrelationId \
                 {correlation:?}, expected {main_correlation:?} (TS 29.518 §6.2.6.2.4 \
                 makes it the consumer's handle on its own subscription)"
            ));
        }
        let report = notification["reportList"][0].clone();
        let Some(ty) = report["type"].as_str() else {
            fail(&format!(
                "a report carried no `type`, which Table 6.2.6.2.5-1 marks M: {report}"
            ));
        };
        println!("received {ty}");
        collected.insert(ty.to_string(), report);
    }

    // Clean up before asserting, so a failing run still leaves the AMF with no
    // subscription pointing at a sink that is about to exit.
    for id in [&main_id, &control_id] {
        if let Err(e) = client
            .delete(&format!("/namf-evts/v1/subscriptions/{id}"))
            .await
        {
            eprintln!("warning: could not delete subscription {id}: {e}");
        }
    }

    if collected.len() < events.len() {
        let missing: Vec<&str> = events
            .iter()
            .copied()
            .filter(|t| !collected.contains_key(*t))
            .collect();
        fail(&format!(
            "after {timeout_secs}s the AMF delivered {} of {} registration-path \
             notifications for {supi}; MISSING {missing:?}.\n\
             This is the #397 property: those emitters sit AFTER \
             `send_to_association(..).await?` in `send_registration_accept`, so \
             nothing arriving means either the UE never completed registration over \
             N2 (check the nextgsim-ue and nextgsim-gnb logs for a Registration \
             Accept) or the emitters are not wired at that site.",
            collected.len(),
            events.len()
        ));
    }

    // REGISTRATION_STATE_REPORT.
    let reg = &collected["REGISTRATION_STATE_REPORT"];
    expect_str(
        reg,
        "/supi",
        supi,
        "the report must name the UE that registered, not another UE the AMF serves.",
    );
    expect_str(
        reg,
        "/rmInfoList/0/rmState",
        "REGISTERED",
        "TS 24.501 §5.5.1.2.4: the UE enters 5GMM-REGISTERED on receiving the Accept, \
         so REGISTERED is the state this moment reports.",
    );
    expect_str(
        reg,
        "/rmInfoList/0/accessType",
        "3GPP_ACCESS",
        "`RmInfo` requires both members (TS29518_Namf_EventExposure.yaml:908-910).",
    );

    // LOCATION_REPORT -- the discriminating assertion. These three values come off
    // the InitialUEMessage's own `UserLocationInformation`, so a report assembled
    // from a default `Tai5gs` would say mcc 000 / mnc 000 / tac 0000.
    let loc = &collected["LOCATION_REPORT"];
    expect_str(
        loc,
        "/location/nrLocation/tai/plmnId/mcc",
        expect_mcc,
        "the MCC the gNB reported; a default PlmnId gives 000.",
    );
    expect_str(
        loc,
        "/location/nrLocation/tai/plmnId/mnc",
        expect_mnc,
        "the MNC the gNB reported; a default PlmnId gives 000.",
    );
    expect_str(
        loc,
        "/location/nrLocation/tai/tac",
        expect_tac,
        "the TAC the gNB reported for THIS UE (TS 29.571 hex); a report assembled from \
         a default `Tai5gs` would say 0000.",
    );

    // ACCESS_TYPE_REPORT.
    expect_str(
        &collected["ACCESS_TYPE_REPORT"],
        "/accessTypeList/0",
        "3GPP_ACCESS",
        "N2 from an NG-RAN is the 3GPP access, so this registration IS the 3GPP one.",
    );

    // The negative control. Checked last so its diagnostic can name what the
    // positive half already proved.
    if !control_hits.is_empty() {
        fail(&format!(
            "the control subscription, targeted at {control_supi} which never \
             registers, received {} notification(s). The AMF is delivering events to \
             subscribers they were not targeted at, so the positive assertions above \
             prove delivery but NOT correct targeting. First body: {}",
            control_hits.len(),
            control_hits[0]
        ));
    }

    println!(
        "PASS: nextgsim's gNB registered {supi} over real N2 and the AMF DELIVERED \
         REGISTRATION_STATE_REPORT (REGISTERED / 3GPP_ACCESS), LOCATION_REPORT \
         (mcc {expect_mcc} mnc {expect_mnc} tac {expect_tac}) and ACCESS_TYPE_REPORT \
         to the subscribed callback, and delivered NOTHING to the control \
         subscription for {control_supi}"
    );
    let _ = sink.stop().await;
}
