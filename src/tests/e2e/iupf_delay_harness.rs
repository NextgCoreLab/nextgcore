//! #2222: the stand-ins around the REAL smfd and two REAL upfd binaries in the
//! nightly I-UPF per-flow delay run (`docker/iupf-delay-e2e/run.sh`).
//!
//! One process plays three parts:
//! - **the AMF**: it creates the SM context (Nsmf_PDUSession_CreateSMContext with
//!   a PDU Session Establishment Request), reads the UL N3 F-TEID from the
//!   PDUSessionResourceSetupRequestTransfer and the UE address from the
//!   Establishment Accept, and answers PDU_RES_SETUP_RSP with the gNB's DL F-TEID;
//! - **the PCF**: its SM policy create answer carries a PCC rule whose `refQosMon`
//!   names a `qosMonDecs` instance (DL, UL and round trip, Periodic every 1 s,
//!   TS 29.512 §4.2.3.25.1), and it records the `qosMonReports` the SMF sends in
//!   Npcf_SMPolicyControl_Update;
//! - **the gNB, on GTP-U only**: it holds every Echo Response for `--echo-hold-ms`
//!   (so the I-UPF's N3 delay is half of that) and sends uplink G-PDUs whose PDU
//!   Session Container carries the RAN DL/UL Delay Result (TS 38.415 §5.5.3.18-19).
//!
//! It exits 0 when the third report with delays has DL = RAN DL + N3 + N9 and
//! UL = RAN UL + N3 + N9 within the tolerance, and RTT = DL + UL; otherwise it
//! prints what it saw and exits 1.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use nextgcore_gtp::v1::types::{PduSessionContainer, UlPduSessionInformation};
use nextgcore_ngap_gen::generated as g;
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::message::{SbiPart, SbiRequest, SbiResponse};
use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

/// The command line: `--name value` pairs, every one required.
struct Args {
    /// The SMF's SBI endpoint, `host:port`.
    smf: SocketAddr,
    /// Where the stand-in PCF listens (the SMF's `PCF_URI`).
    pcf: SocketAddr,
    /// The stand-in gNB's GTP-U address (port 2152).
    gnb: Ipv4Addr,
    /// The I-UPF's N3 address: the NG-RAN must be given it.
    iupf_n3: Ipv4Addr,
    echo_hold_ms: u64,
    /// The one-way N9 delay the run injects between the I-UPF and the PSA.
    n9_ms: u64,
    ran_dl_ms: u32,
    ran_ul_ms: u32,
    /// How far above the expected value a report may be (a loaded runner).
    tolerance_ms: u64,
    timeout_s: u64,
}

fn parse_args() -> Result<Args> {
    let mut map = std::collections::HashMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let k = k
            .strip_prefix("--")
            .ok_or_else(|| anyhow!("unexpected argument {k:?}"))?
            .to_string();
        let v = it.next().ok_or_else(|| anyhow!("--{k} needs a value"))?;
        map.insert(k, v);
    }
    let get = |k: &str| -> Result<String> {
        map.get(k)
            .cloned()
            .ok_or_else(|| anyhow!("--{k} is required"))
    };
    Ok(Args {
        smf: get("smf")?.parse().context("--smf")?,
        pcf: get("pcf")?.parse().context("--pcf")?,
        gnb: get("gnb")?.parse().context("--gnb")?,
        iupf_n3: get("iupf-n3")?.parse().context("--iupf-n3")?,
        echo_hold_ms: get("echo-hold-ms")?.parse().context("--echo-hold-ms")?,
        n9_ms: get("n9-ms")?.parse().context("--n9-ms")?,
        ran_dl_ms: get("ran-dl-ms")?.parse().context("--ran-dl-ms")?,
        ran_ul_ms: get("ran-ul-ms")?.parse().context("--ran-ul-ms")?,
        tolerance_ms: get("tolerance-ms")?.parse().context("--tolerance-ms")?,
        timeout_s: get("timeout-s")?.parse().context("--timeout-s")?,
    })
}

/// The PCF's policy and the reports it was sent.
async fn start_pcf(addr: SocketAddr) -> Result<(SbiServer, Arc<Mutex<Vec<serde_json::Value>>>)> {
    let reports: Arc<Mutex<Vec<serde_json::Value>>> = Default::default();
    let sink = reports.clone();
    let pcf = SbiServer::new(SbiServerConfig::new(addr));
    pcf.start(move |req: SbiRequest| {
        let sink = sink.clone();
        async move {
            if req.header.uri.ends_with("/sm-policies") {
                println!("PCF: SM policy create");
                let d = serde_json::json!({
                    "sessRules": {},
                    "pccRules": { "r1": { "pccRuleId": "r1", "precedence": 10, "refQosMon": ["qm1"] } },
                    "qosMonDecs": { "qm1": {
                        "qmId": "qm1",
                        "reqQosMonParams": ["DOWNLINK", "UPLINK", "ROUND_TRIP"],
                        "repFreqs": ["PERIODIC"],
                        "repPeriod": 1,
                    }},
                    "policyCtrlReqTriggers": ["QOS_MONITORING"],
                    // Features 9 and 24 (QosMonitoring), TS 29.512 §5.8.
                    "suppFeat": "800100",
                });
                return SbiResponse::with_status(201)
                    .with_header("Location", "/npcf-smpolicycontrol/v1/sm-policies/pol-2222")
                    .with_body(d.to_string(), "application/json");
            }
            if req.header.uri.ends_with("/update") {
                if let Some(b) = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                {
                    println!("PCF: update {}", b["qosMonReports"]);
                    sink.lock().unwrap().push(b);
                }
                return SbiResponse::with_status(200).with_body("{}".to_string(), "application/json");
            }
            SbiResponse::with_status(204)
        }
    })
    .await
    .map_err(|e| anyhow!("the stand-in PCF does not start on {addr}: {e:?}"))?;
    Ok((pcf, reports))
}

/// The stand-in gNB's Echo responder: each Echo Response held `hold`.
fn spawn_echo(sock: Arc<tokio::net::UdpSocket>, hold: Duration) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if n >= 12 && buf[1] == 1 {
                // Echo Request (TS 29.281 §7.2.1): answer with its sequence number
                // and a Recovery IE.
                let mut resp = vec![0x32, 2, 0, 6, 0, 0, 0, 0];
                resp.extend_from_slice(&buf[8..10]);
                resp.extend_from_slice(&[0, 0, 14, 0]);
                let s = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(hold).await;
                    let _ = s.send_to(&resp, from).await;
                });
            }
        }
    });
}

/// An uplink G-PDU on `teid`, its PDU Session Container (TS 38.415 §5.5.2.2)
/// carrying the RAN's DL and UL Delay Results.
fn ul_gpdu(teid: u32, qfi: u8, ue: [u8; 4], ran_dl: u32, ran_ul: u32) -> Vec<u8> {
    let content = PduSessionContainer::Ul(UlPduSessionInformation {
        qfi,
        dl_delay_result: Some(ran_dl),
        ul_delay_result: Some(ran_ul),
        ..Default::default()
    })
    .encode_content();
    // An IPv4/UDP packet from the UE toward 192.0.2.1 (TEST-NET-1).
    let mut inner = vec![0u8; 28];
    inner[0] = 0x45;
    inner[2..4].copy_from_slice(&28u16.to_be_bytes());
    inner[8] = 64;
    inner[9] = 17;
    inner[12..16].copy_from_slice(&ue);
    inner[16..20].copy_from_slice(&[192, 0, 2, 1]);
    // The extension header is a whole number of 4 octets, with its length octet
    // and next-type octet (TS 29.281 §5.2.1).
    let mut padded = content;
    while !(padded.len() + 2).is_multiple_of(4) {
        padded.push(0);
    }
    let ext_len = padded.len() + 2;
    let mut pkt = vec![0x34, 0xff];
    pkt.extend_from_slice(&((4 + ext_len + inner.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&teid.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0x85]);
    pkt.push((ext_len / 4) as u8);
    pkt.extend_from_slice(&padded);
    pkt.push(0);
    pkt.extend_from_slice(&inner);
    pkt
}

/// The UL N3 F-TEID and the first QFI of a PDUSessionResourceSetupRequestTransfer
/// (TS 38.413 §9.3.4.1).
fn setup_request(bytes: &[u8]) -> Result<((u32, Ipv4Addr), u8)> {
    use g::PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue as Ie;
    let (t, _) = nextgcore_ngap_gen::decode_contained_with_unknown_ies::<
        g::PDUSessionResourceSetupRequestTransfer,
    >(bytes)
    .map_err(|e| anyhow!("PDUSessionResourceSetupRequestTransfer: {e:?}"))?;
    let mut tunnel = None;
    let mut qfi = None;
    for ie in t.protocol_i_es.0 {
        match ie.value {
            Ie::Id_UL_NGU_UP_TNLInformation(g::UPTransportLayerInformation::GTPTunnel(gt)) => {
                let bits = &gt.transport_layer_address.0;
                if bits.len() != 32 {
                    bail!("the UL NG-U address is {} bits, not IPv4", bits.len());
                }
                let mut a = [0u8; 4];
                for (i, b) in bits.iter().enumerate() {
                    a[i / 8] |= u8::from(*b) << (7 - i % 8);
                }
                let teid: [u8; 4] = gt.gtp_teid.0.as_slice().try_into()?;
                tunnel = Some((u32::from_be_bytes(teid), Ipv4Addr::from(a)));
            }
            Ie::Id_QosFlowSetupRequestList(l) => {
                qfi = l.0.first().map(|f| f.qos_flow_identifier.0);
            }
            _ => {}
        }
    }
    Ok((
        tunnel.ok_or_else(|| anyhow!("no UL NG-U UP TNL Information"))?,
        qfi.ok_or_else(|| anyhow!("no QoS Flow Setup Request List"))?,
    ))
}

/// The IPv4 PDU address of a PDU Session Establishment Accept (TS 24.501
/// §8.3.2, IEI 0x29: length 5, type IPv4).
fn ue_address(n1: &[u8]) -> Result<[u8; 4]> {
    n1.windows(7)
        .find(|w| w[0] == 0x29 && w[1] == 5 && w[2] & 0x07 == 1)
        .map(|w| [w[3], w[4], w[5], w[6]])
        .ok_or_else(|| anyhow!("no IPv4 PDU address in the Establishment Accept"))
}

/// A PDUSessionResourceSetupResponseTransfer naming the gNB's DL F-TEID and one
/// QoS flow: the octets nextgsim's gNB produces (smfd's
/// `GNB_SETUP_RESPONSE_TRANSFER`), with the address, TEID and QFI substituted.
fn setup_response(teid: u32, addr: Ipv4Addr, qfi: u8) -> Vec<u8> {
    let mut b = vec![0x00, 0x03, 0xe0];
    b.extend_from_slice(&addr.octets());
    b.extend_from_slice(&teid.to_be_bytes());
    b.extend_from_slice(&[0x00, qfi]);
    b
}

fn part<'a>(resp: &'a SbiResponse, content_type: &str) -> Option<&'a SbiPart> {
    resp.http
        .parts
        .iter()
        .find(|p| p.content_type.as_deref() == Some(content_type))
}

async fn run(a: Args) -> Result<()> {
    let (_pcf, reports) = start_pcf(a.pcf).await?;
    let gnb = Arc::new(
        tokio::net::UdpSocket::bind((a.gnb, 2152))
            .await
            .with_context(|| format!("the gNB's GTP-U socket on {}:2152", a.gnb))?,
    );
    spawn_echo(gnb.clone(), Duration::from_millis(a.echo_hold_ms));

    let smf = SbiClient::with_host_port(a.smf.ip().to_string(), a.smf.port());
    // Nsmf_PDUSession_CreateSMContext: PSI 1, PTI 1, IPv4 (TS 24.501 §8.3.1).
    let psi = 1u8;
    let n1 = [0x2E, psi, 1, 0xC1, 0xFF, 0xFF, 0x91];
    let body = serde_json::json!({
        "pduSessionId": psi,
        "supi": "imsi-001010000022220",
        "sNssai": { "sst": 1, "sd": "010203" },
        "dnn": "internet",
        "anType": "3GPP_ACCESS",
        "ratType": "NR",
        "servingNfId": "6b1d7e3c-0000-4000-8000-000000002222",
        "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "020040" },
        "ueLocation": { "nrLocation": {
            "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000001" },
            "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "nrCellId": "000000010" },
        }},
        "n1SmMsg": { "contentId": "n1SmMsg" },
    });
    let mut created = None;
    let deadline = Instant::now() + Duration::from_secs(a.timeout_s);
    while Instant::now() < deadline {
        let req = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts")
            .with_body(body.to_string(), "application/json")
            .with_part(SbiPart::with_content(
                "n1SmMsg",
                "application/vnd.3gpp.5gnas",
                Bytes::copy_from_slice(&n1),
            ));
        match smf.send_request(req).await {
            Ok(r) if r.status == 201 => {
                created = Some(r);
                break;
            }
            // The SMF is up before its N4 associations are: retried until then.
            Ok(r) => println!("AMF: create answered {} {:?}", r.status, r.http.content),
            Err(e) => println!("AMF: create failed: {e:?}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let created = created.ok_or_else(|| anyhow!("no SM context was created"))?;
    let root: serde_json::Value =
        serde_json::from_str(created.http.content.as_deref().unwrap_or("{}"))?;
    let reference = root["smContextRef"]
        .as_str()
        .ok_or_else(|| anyhow!("no smContextRef in {root}"))?
        .to_string();
    let n2 = part(&created, "application/vnd.3gpp.ngap")
        .ok_or_else(|| anyhow!("no N2 part in the create answer"))?;
    let ((ul_teid, ul_addr), qfi) = setup_request(&n2.data)?;
    let ue = ue_address(
        &part(&created, "application/vnd.3gpp.5gnas")
            .ok_or_else(|| anyhow!("no N1 part in the create answer"))?
            .data,
    )?;
    println!(
        "AMF: SM context {reference}: UL N3 F-TEID {ul_teid:#x}@{ul_addr}, QFI {qfi}, UE {}",
        Ipv4Addr::from(ue)
    );
    if ul_addr != a.iupf_n3 {
        bail!(
            "the NG-RAN was given {ul_addr} as its UL N3 endpoint, not the I-UPF's {}",
            a.iupf_n3
        );
    }

    // PDU Session Resource Setup Response: the DL tunnel to this gNB.
    let gnb_teid = 0x2222u32;
    let req = SbiRequest::post(format!(
        "/nsmf-pdusession/v1/sm-contexts/{reference}/modify"
    ))
    .with_body(
        serde_json::json!({
            "n2SmInfoType": "PDU_RES_SETUP_RSP",
            "n2SmInfo": { "contentId": "n2SmInfo" },
        })
        .to_string(),
        "application/json",
    )
    .with_part(SbiPart::with_content(
        "n2SmInfo",
        "application/vnd.3gpp.ngap",
        Bytes::from(setup_response(gnb_teid, a.gnb, qfi)),
    ));
    let r = smf
        .send_request(req)
        .await
        .map_err(|e| anyhow!("PDU_RES_SETUP_RSP: {e:?}"))?;
    if r.status != 200 && r.status != 204 {
        bail!(
            "PDU_RES_SETUP_RSP answered {} {:?}",
            r.status,
            r.http.content
        );
    }
    println!(
        "AMF: user plane activated (DL F-TEID {gnb_teid:#x}@{})",
        a.gnb
    );

    // Uplink until three reports with delays: the first period can end before
    // either UPF's first Echo round (an unknown delay is not added, #2197).
    let pkt = ul_gpdu(ul_teid, qfi, ue, a.ran_dl_ms, a.ran_ul_ms);
    let mut report = None;
    while Instant::now() < deadline {
        let _ = gnb.send_to(&pkt, (ul_addr, 2152)).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let got: Vec<serde_json::Value> = reports
            .lock()
            .unwrap()
            .iter()
            .flat_map(|b| b["qosMonReports"].as_array().cloned().unwrap_or_default())
            .filter(|r| r["dlDelays"].is_array())
            .collect();
        if got.len() >= 3 {
            report = got.into_iter().nth(2);
            break;
        }
    }
    let r = report.ok_or_else(|| {
        anyhow!("fewer than three QoS monitoring reports with delays reached the PCF")
    })?;
    println!("RESULT report {r}");
    let ms = |k: &str| -> Result<u64> { r[k][0].as_u64().ok_or_else(|| anyhow!("no {k} in {r}")) };
    let (dl, ul, rt) = (ms("dlDelays")?, ms("ulDelays")?, ms("rtDelays")?);
    let n3 = a.echo_hold_ms / 2;
    let want_dl = u64::from(a.ran_dl_ms) + n3 + a.n9_ms;
    let want_ul = u64::from(a.ran_ul_ms) + n3 + a.n9_ms;
    println!(
        "RESULT DL {dl} ms (RAN {} + N3 ~{n3} + N9 ~{}), UL {ul} ms (RAN {} + N3 ~{n3} + N9 ~{}), RTT {rt} ms",
        a.ran_dl_ms, a.n9_ms, a.ran_ul_ms, a.n9_ms
    );
    let mut failed = Vec::new();
    if r["refPccRuleIds"] != serde_json::json!(["r1"]) {
        failed.push(format!("refPccRuleIds {}", r["refPccRuleIds"]));
    }
    // One millisecond under: a delay is reported in whole milliseconds.
    for (what, got, want) in [("DL", dl, want_dl), ("UL", ul, want_ul)] {
        if !(want.saturating_sub(1)..=want + a.tolerance_ms).contains(&got) {
            failed.push(format!(
                "{what} {got} ms is not in [{}, {}]",
                want.saturating_sub(1),
                want + a.tolerance_ms
            ));
        }
    }
    if rt != dl + ul {
        failed.push(format!(
            "RTT {rt} != DL + UL {} (TS 29.244 §5.24.5.4)",
            dl + ul
        ));
    }
    if !failed.is_empty() {
        bail!("{}", failed.join("; "));
    }
    println!("PASS");
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("iupf-delay-harness: {e:#}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(args).await {
        println!("FAIL: {e:#}");
        std::process::exit(1);
    }
}
