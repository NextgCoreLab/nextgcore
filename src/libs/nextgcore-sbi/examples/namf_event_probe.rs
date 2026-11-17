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
//! # The two fire points, and why they are separate PHASES
//!
//! `handle_service_request_nas` has its own emitters, and issue #403 is about proving
//! them. They cannot be folded into the registration assertion above, because the
//! registration fires several of the same types. So the phase is a command-line
//! argument and the caller runs **two processes**: the `service-request` phase
//! subscribes only after the registration phase has passed, so every notification it
//! receives was fired after that point.
//!
//! ## What the service-request phase asserts, and why (#1734)
//!
//! The gNB suspends the UE to RRC_INACTIVE, which is RAN-local: the AMF keeps the NG
//! connection, and the Service Request comes back on it, from the cell the UE
//! registered in, through `handle_service_request_nas`. Per TS 29.518, that Service
//! Request owes this subscriber NO notification:
//!
//! * **LOCATION_REPORT** reports "when AMF becomes aware of a location change of the
//!   UE" (§5.3.1, `29518-k00.txt:4832-4835`), and a same-cell Service Request is no
//!   change (#1424).
//! * **CONNECTIVITY_STATE_REPORT / REACHABILITY_REPORT** report an updated state
//!   (§6.2, `:24011-24017`; §5.3.1, `:5042-5057`), and a Service Request on a live NG
//!   connection changes neither (#1593: `handle_service_request_nas` fires neither).
//!
//! So this phase asserts what the spec does require, positively, plus the absence the
//! spec requires, made meaningful:
//!
//! 1. **The current location, on request.** A subscriber that wants it asks with the
//!    `immediateFlag` and gets it in the subscribe response (§5.3.2.2.2,
//!    `:5702-5705`: "last known location information is included if the subscribed
//!    event is LOCATION_REPORT"). The 201 body's `reportList` must carry the TAI the
//!    gNB reported, and the control's must carry no location.
//! 2. **A live callback.** REACHABILITY_REPORT (default filter, no `immediateFlag`)
//!    is first reported in a notification "regardless of whether the immediateFlag is
//!    set or not" (§5.3.1, `:5042-5044`, #1641), so a REACHABLE notification must
//!    arrive. It comes from the subscribe, NOT the Service Request, and is not claimed
//!    to; it proves this subscription's notifications reach this sink, which is what
//!    makes 3 more than silence.
//! 3. **No LOCATION_REPORT notification for the same-cell Service Request.** The probe
//!    listens for its whole window. The caller proves the Service Request completed
//!    inside that window (it checks the probe is still running when the Service
//!    Accept has been seen), so a LOCATION_REPORT the AMF wrongly fired would have
//!    arrived here.
//!
//! The immediate LOCATION_REPORT comes back in the 201 BODY, never POSTed to the
//! callback, so it cannot be mistaken for a notification.
//!
//! # Usage
//!
//! ```text
//! namf_event_probe <phase> <amf-host:port> <sink-bind-port> <sink-advertise-host> \
//!                  <supi> <control-supi> <expect-mcc> <expect-mnc> <expect-tac-hex> \
//!                  <timeout-secs>
//! ```
//!
//! `<phase>` is `registration` (`REGISTRATION_STATE_REPORT`, `LOCATION_REPORT`,
//! `ACCESS_TYPE_REPORT`) or `service-request`
//! (`REACHABILITY_REPORT`, and `LOCATION_REPORT` with the `immediateFlag`).
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

/// Which fire point this run asserts.
///
/// Separate runs rather than one subscription covering both, because the two sites
/// fire some of the same types and a single run could not attribute them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `send_registration_accept` (#397).
    Registration,
    /// `handle_service_request_nas` (#403).
    ServiceRequest,
}

impl Phase {
    /// The `eventList` to subscribe with, and no other types: subscribing to a type
    /// fired elsewhere would make a timeout ambiguous about which site failed.
    fn event_list(self) -> Vec<Value> {
        match self {
            Phase::Registration => vec![
                json!({ "type": "REGISTRATION_STATE_REPORT" }),
                json!({ "type": "LOCATION_REPORT" }),
                json!({ "type": "ACCESS_TYPE_REPORT" }),
            ],
            // See "What the service-request phase asserts" above.
            Phase::ServiceRequest => vec![
                json!({ "type": "REACHABILITY_REPORT" }),
                json!({ "type": "LOCATION_REPORT", "immediateFlag": true }),
            ],
        }
    }

    /// `notifyCorrelationId` suffix, so the two phases' subscriptions are
    /// distinguishable in the AMF's log and a report cannot satisfy the wrong phase.
    fn correlation_tag(self) -> &'static str {
        match self {
            Phase::Registration => "397",
            Phase::ServiceRequest => "403",
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("::error::{msg}");
    eprintln!("FAIL: {msg}");
    std::process::exit(1);
}

/// POST one `AmfEventSubscription` and return its subscription ID and the 201 body's
/// `reportList` (the immediate reports, TS 29.518 §5.3.2.2.2).
///
/// `supi` targets the subscription (TS 29.518 §5.3.2.2.2); the AMF's
/// `event_subscriptions_matching_ue` keys on it, which is what the negative control
/// depends on.
async fn subscribe(
    client: &SbiClient,
    notify_uri: &str,
    correlation_id: &str,
    supi: &str,
    event_list: &[Value],
) -> (String, Vec<Value>) {
    let body = json!({
        "subscription": {
            "eventList": event_list,
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
    let Some(id) = parsed["subscriptionId"].as_str() else {
        fail(&format!(
            "the 201 carried no subscriptionId, so the subscription cannot be \
             deleted afterwards: {parsed}"
        ));
    };
    let reports = parsed["reportList"].as_array().cloned().unwrap_or_default();
    (id.to_string(), reports)
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
    if args.len() != 11 {
        eprintln!(
            "usage: {} <registration|service-request> <amf-host:port> <sink-bind-port> \
             <sink-advertise-host> <supi> <control-supi> <expect-mcc> <expect-mnc> \
             <expect-tac-hex> <timeout-secs>",
            args[0]
        );
        std::process::exit(2);
    }
    let phase = match args[1].as_str() {
        "registration" => Phase::Registration,
        "service-request" => Phase::ServiceRequest,
        other => {
            eprintln!("phase must be `registration` or `service-request`, not {other:?}");
            std::process::exit(2);
        }
    };
    let amf = &args[2];
    let sink_port: u16 = args[3].parse().unwrap_or_else(|e| {
        eprintln!("sink-bind-port: {e}");
        std::process::exit(2);
    });
    let sink_host = &args[4];
    let supi = &args[5];
    let control_supi = &args[6];
    let (expect_mcc, expect_mnc, expect_tac) = (&args[7], &args[8], &args[9]);
    let timeout_secs: u64 = args[10].parse().unwrap_or_else(|e| {
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

    let event_list = phase.event_list();
    let main_correlation = &format!("corr-{}-e2e-main", phase.correlation_tag());
    let control_correlation = &format!("corr-{}-e2e-control", phase.correlation_tag());

    let (main_id, main_immediate) = subscribe(
        &client,
        &format!("http://{sink_host}:{sink_port}{MAIN_PATH}"),
        main_correlation,
        supi,
        &event_list,
    )
    .await;
    let (control_id, control_immediate) = subscribe(
        &client,
        &format!("http://{sink_host}:{sink_port}{CONTROL_PATH}"),
        control_correlation,
        control_supi,
        &event_list,
    )
    .await;

    // The caller gates starting the gNB/UE (or suspending the UE) on this line.
    // Flushed before any wait, because an event that happens before the subscriptions
    // exist is delivered to nobody (`event_subscriptions_matching_ue` finds no match).
    println!("SUBSCRIBED main={main_id} control={control_id}");
    match phase {
        Phase::Registration => println!(
            "waiting up to {timeout_secs}s for the registration of {supi} to deliver \
             REGISTRATION_STATE_REPORT, LOCATION_REPORT and ACCESS_TYPE_REPORT"
        ),
        Phase::ServiceRequest => println!(
            "listening {timeout_secs}s: {supi}'s first REACHABILITY_REPORT must arrive, \
             and its same-cell Service Request must deliver no LOCATION_REPORT"
        ),
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // Registration: collect until every expected type has arrived on the main callback,
    // or the budget expires. Service request: listen for the whole window, since what
    // it asserts includes an absence. Reports are keyed by type rather than read
    // positionally: the AMF spawns one delivery task per subscriber per event, so
    // reports fired from one site arrive in a non-deterministic order.
    let registration_types = [
        "REGISTRATION_STATE_REPORT",
        "LOCATION_REPORT",
        "ACCESS_TYPE_REPORT",
    ];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut collected: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    let mut location_notifications: Vec<Value> = Vec::new();
    let mut control_hits: Vec<Value> = Vec::new();
    loop {
        if phase == Phase::Registration && collected.len() == registration_types.len() {
            break;
        }
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
        if correlation != Some(main_correlation.as_str()) {
            fail(&format!(
                "a notification on the main callback carried notifyCorrelationId \
                 {correlation:?}, expected {main_correlation:?} (TS 29.518 §6.2.6.2.4 \
                 makes it the consumer's handle on its own subscription)"
            ));
        }
        let report = notification["reportList"][0].clone();
        let Some(ty) = report["type"].as_str().map(str::to_string) else {
            fail(&format!(
                "a report carried no `type`, which Table 6.2.6.2.5-1 marks M: {report}"
            ));
        };
        println!("received {ty}");
        if phase == Phase::ServiceRequest && ty == "LOCATION_REPORT" {
            location_notifications.push(report);
            continue;
        }
        // The first of each type: a repeated REACHABILITY_REPORT is not the first one.
        collected.entry(ty).or_insert(report);
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

    // The TAI each LOCATION_REPORT must carry. These three values come off the NGAP
    // message's own `UserLocationInformation`, so a report assembled from a default
    // `Tai5gs` would say mcc 000 / mnc 000 / tac 0000.
    let expect_tai = |loc: &Value| {
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
            "the TAC the gNB reported for THIS UE (TS 29.571 hex); a report assembled \
             from a default `Tai5gs` would say 0000.",
        );
    };

    match phase {
        Phase::Registration => {
            let missing: Vec<&str> = registration_types
                .iter()
                .copied()
                .filter(|t| !collected.contains_key(*t))
                .collect();
            if !missing.is_empty() {
                fail(&format!(
                    "after {timeout_secs}s the AMF delivered {} of {} registration-path \
                     notifications for {supi}; MISSING {missing:?}.\n\
                     Those emitters sit AFTER `send_to_association(..).await?` in \
                     `send_registration_accept`, so nothing arriving means either the UE \
                     never completed registration over N2 (check the nextgsim-ue and \
                     nextgsim-gnb logs for a Registration Accept) or the emitters are not \
                     wired at that site.",
                    collected.len(),
                    registration_types.len(),
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
                "TS 24.501 §5.5.1.2.4: the UE enters 5GMM-REGISTERED on receiving the \
                 Accept, so REGISTERED is the state this moment reports.",
            );
            expect_str(
                reg,
                "/rmInfoList/0/accessType",
                "3GPP_ACCESS",
                "`RmInfo` requires both members (TS29518_Namf_EventExposure.yaml:908-910).",
            );
            // LOCATION_REPORT: the registration is where the AMF first becomes aware
            // of the UE's location (TS 29.518 §5.3.1, `29518-k00.txt:4832-4835`).
            expect_tai(&collected["LOCATION_REPORT"]);
            // ACCESS_TYPE_REPORT.
            expect_str(
                &collected["ACCESS_TYPE_REPORT"],
                "/accessTypeList/0",
                "3GPP_ACCESS",
                "N2 from an NG-RAN is the 3GPP access, so this registration IS the 3GPP one.",
            );
        }
        Phase::ServiceRequest => {
            // 1. The immediate LOCATION_REPORT, from the 201 body (TS 29.518
            //    §5.3.2.2.2, `29518-k00.txt:5702-5705`).
            let Some(loc) = main_immediate
                .iter()
                .find(|r| r["type"] == "LOCATION_REPORT")
            else {
                fail(&format!(
                    "the subscribe response for {supi} carried no immediate \
                     LOCATION_REPORT, though LOCATION_REPORT was subscribed with \
                     immediateFlag true and the UE is registered: TS 29.518 §5.3.2.2.2 \
                     (`29518-k00.txt:5702-5705`) has the AMF include \"last known \
                     location information\". reportList was: {main_immediate:?}"
                ));
            };
            println!("immediate LOCATION_REPORT in the subscribe response:");
            expect_str(
                loc,
                "/supi",
                supi,
                "the immediate report names the subscribed UE.",
            );
            expect_tai(loc);
            if let Some(r) = control_immediate
                .iter()
                .find(|r| r["type"] == "LOCATION_REPORT")
            {
                fail(&format!(
                    "the control subscription for {control_supi}, a UE that never \
                     registers, got an immediate LOCATION_REPORT: the AMF reported a \
                     location it cannot have. Report: {r}"
                ));
            }

            // 2. The live callback: the subscription's first REACHABILITY_REPORT.
            let Some(reach) = collected.get("REACHABILITY_REPORT") else {
                fail(&format!(
                    "no REACHABILITY_REPORT arrived in {timeout_secs}s. A new \
                     subscription is first told the UE's current reachability in a \
                     notification \"regardless of whether the immediateFlag is set or \
                     not\" (TS 29.518 §5.3.1, `29518-k00.txt:5042-5044`), so either the \
                     AMF is not sending that first report or its notifications do not \
                     reach this sink -- and without a live callback the absence checked \
                     below would mean nothing."
                ));
            };
            println!("first REACHABILITY_REPORT (from the subscribe; the callback is live):");
            expect_str(reach, "/supi", supi, "the report names the subscribed UE.");
            expect_str(
                reach,
                "/reachability",
                "REACHABLE",
                "a registered, CM-CONNECTED UE is REACHABLE.",
            );

            // 3. No LOCATION_REPORT notification: the Service Request came from the
            //    cell the UE registered in, which is no location change (§5.3.1,
            //    `29518-k00.txt:4832-4835`; #1424).
            if let Some(r) = location_notifications.first() {
                fail(&format!(
                    "the AMF NOTIFIED {} LOCATION_REPORT(s) for {supi}, whose Service \
                     Request came from the cell it registered in. TS 29.518 §5.3.1 \
                     (`29518-k00.txt:4832-4835`) reports an UPDATED location \"when AMF \
                     becomes aware of a location change\", and the current one was \
                     already given in the subscribe response. First report: {r}",
                    location_notifications.len()
                ));
            }
            println!("  ok no LOCATION_REPORT notification in {timeout_secs}s");
        }
    }

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

    match phase {
        Phase::Registration => println!(
            "PASS: nextgsim's gNB registered {supi} over real N2 and the AMF DELIVERED \
             REGISTRATION_STATE_REPORT (REGISTERED / 3GPP_ACCESS), LOCATION_REPORT \
             (mcc {expect_mcc} mnc {expect_mnc} tac {expect_tac}) and ACCESS_TYPE_REPORT \
             to the subscribed callback, and delivered NOTHING to the control \
             subscription for {control_supi}"
        ),
        Phase::ServiceRequest => println!(
            "PASS: the AMF answered the immediateFlag LOCATION_REPORT subscription for \
             {supi} with its current location (mcc {expect_mcc} mnc {expect_mnc} tac \
             {expect_tac}), delivered its first REACHABILITY_REPORT (REACHABLE) to the \
             subscribed callback, notified NO LOCATION_REPORT in {timeout_secs}s for its \
             same-cell Service Request, and delivered NOTHING to the control \
             subscription for {control_supi}"
        ),
    }
    let _ = sink.stop().await;
}
