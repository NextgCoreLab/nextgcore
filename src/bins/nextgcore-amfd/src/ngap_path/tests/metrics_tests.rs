//! #1334: the AMF's `/metrics` counters move with the NGAP and NAS it really
//! receives and sends, driven through `process_ngap_message` with the egress
//! captured. The counters are process-wide and the tests run in parallel, so each
//! assertion is on this test's own increments (at least), never on a total.

use super::*;

/// The exposition value of `series`, 0 when it is not rendered yet.
pub(super) fn scraped(series: &str) -> f64 {
    let mut out = String::new();
    crate::metrics::render_amf_families(&mut out, &crate::metrics::AmfCensus::default());
    nextgcore_metrics::nf::sample_value(&out, series).unwrap_or(0.0)
}

/// The NAS-PDU of a DOWNLINK NAS TRANSPORT, `None` for any other PDU.
fn downlink_nas(pdu: &[u8]) -> Option<Vec<u8>> {
    use nextgcore_ngap_gen::generated as g;
    let Ok(g::NGAP_PDU::InitiatingMessage(m)) = nextgcore_ngap_gen::decode(pdu) else {
        return None;
    };
    let g::InitiatingMessageValue::Id_DownlinkNASTransport(dl) = m.value else {
        return None;
    };
    dl.protocol_i_es
        .0
        .into_iter()
        .find_map(|ie| match ie.value {
            g::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(n) => Some(n.0),
            _ => None,
        })
}

/// A REGISTRATION REQUEST that cannot be parsed is answered REGISTRATION REJECT #96
/// (TS 24.501 §5.5.1.2.8). Every counter on the way moves: the Initial UE Message
/// received, the Downlink NAS Transport sent, the request by its registration type,
/// the reject and its cause.
///
/// REVERT-VERIFIED: without `observe_registration_request` the request count stays,
/// without the `observe_downlink_nas` in `send_nas_pdu` the reject counts stay, and
/// without the `observe_ngap` calls the NGAP counts stay; each fails its assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_registration_moves_the_ngap_and_registration_counters_1334() {
    crate::context::amf_context_init(64, 1024, 4096);
    let mut server = capturing_ngap_server().await;
    let assoc = 13_341u64;
    seed_gnb_session(&server, assoc).await;

    let rx_initial_ue = r#"amf_ngap_messages_total{direction="rx",procedure="InitialUEMessage",outcome="initiating"}"#;
    let tx_dl_nas = r#"amf_ngap_messages_total{direction="tx",procedure="DownlinkNASTransport",outcome="initiating"}"#;
    let initial = r#"amf_registration_requests_total{type="initial"}"#;
    let rejects = "amf_registration_failure_total";
    let cause_96 = r#"amf_registration_reject_cause_total{cause="96"}"#;
    let before: Vec<f64> = [rx_initial_ue, tx_dl_nas, initial, rejects, cause_96]
        .iter()
        .map(|s| scraped(s))
        .collect();

    // 5GS registration type 1 (initial), ngKSI 7, and nothing else: no 5GS mobile
    // identity, so the request is malformed.
    let nas = vec![0x7E, 0x00, 0x41, 0x71];
    server
        .process_ngap_message(
            assoc,
            &service_request_initial_ue_with(
                nas,
                nextgcore_ngap::types::RrcEstablishmentCause::MoSignalling,
            ),
        )
        .await
        .expect("handled");
    let sent = take_sent_ngap(&mut server);
    let reject = sent
        .iter()
        .find_map(|(_, pdu)| downlink_nas(pdu))
        .expect("a Downlink NAS Transport was sent");
    assert_eq!(
        &reject[..4],
        &[0x7E, 0x00, 0x44, 96],
        "REGISTRATION REJECT #96"
    );

    let after: Vec<f64> = [rx_initial_ue, tx_dl_nas, initial, rejects, cause_96]
        .iter()
        .map(|s| scraped(s))
        .collect();
    for ((name, b), a) in [rx_initial_ue, tx_dl_nas, initial, rejects, cause_96]
        .iter()
        .zip(&before)
        .zip(&after)
    {
        assert!(a >= &(b + 1.0), "{name}: {b} -> {a}");
    }
}

/// An NG SETUP REQUEST the AMF cannot decode is answered NG SETUP FAILURE
/// (TS 38.413 §10.2), an unsuccessful outcome, which `amf_ngap_failures_total`
/// counts.
///
/// REVERT-VERIFIED: without the `observe_ngap` in `send_to_association` the failure
/// count stays and the assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_setup_failure_is_counted_as_an_ngap_failure_1334() {
    let mut server = capturing_ngap_server().await;
    let assoc = 13_342u64;
    seed_gnb_session(&server, assoc).await;
    let failures = r#"amf_ngap_failures_total{direction="tx",procedure="NGSetup"}"#;
    let rx = r#"amf_ngap_messages_total{direction="rx",procedure="NGSetup",outcome="initiating"}"#;
    let (f0, r0) = (scraped(failures), scraped(rx));
    server
        .process_ngap_message(assoc, &[0x00, 0x15, 0x00, 0x01, 0xff])
        .await
        .expect("handled");
    let sent = take_sent_ngap(&mut server);
    assert!(
        sent.iter().any(|(_, pdu)| pdu.starts_with(&[0x40, 0x15])),
        "an NG SETUP FAILURE was sent: {sent:?}"
    );
    assert!(scraped(failures) >= f0 + 1.0);
    assert!(scraped(rx) >= r0 + 1.0);
}

/// A Registration Accept the AMF protects is counted as a successful registration
/// (TS 28.552 §5.2.2.1, "on transmission of Registration Accept"): every protected
/// downlink 5GMM message passes `nas_5gs_security_encode` exactly once.
///
/// REVERT-VERIFIED: without the `observe_downlink_nas` in `nas_5gs_security_encode`
/// the count stays and the assertion fails.
#[test]
fn a_protected_registration_accept_is_counted_as_a_success_1334() {
    let mut amf_ue = crate::context::AmfUe::default();
    amf_ue.selected_int_algorithm = 2;
    amf_ue.selected_enc_algorithm = 2;
    amf_ue.knas_int = [0x11; 16];
    amf_ue.knas_enc = [0x22; 16];
    amf_ue.security_context_available = true;
    let before = scraped("amf_registration_success_total");
    let accept = [0x7E, 0x00, 0x42, 0x01, 0x01];
    nas_security::nas_5gs_security_encode(
        &mut amf_ue,
        &accept,
        security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
    )
    .expect("protected");
    assert!(scraped("amf_registration_success_total") >= before + 1.0);
}

/// An AUTHENTICATION FAILURE from a UE is counted on receipt (TS 28.552 AMF.AuthFail).
///
/// REVERT-VERIFIED: without `observe_ue_authentication_failure` the count stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authentication_failure_from_the_ue_is_counted_1334() {
    let mut server = capturing_ngap_server().await;
    let series = r#"amf_auth_failure_total{source="ue"}"#;
    let before = scraped(series);
    // 5GMM cause #20 MAC failure, for a UE this AMF does not hold.
    let nas = [0x7E, 0x00, message_type::AUTHENTICATION_FAILURE, 20];
    let _ = server
        .handle_authentication_failure_nas(13_343, 13_343_001, 1, &nas)
        .await;
    assert!(scraped(series) >= before + 1.0);
}
