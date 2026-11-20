//! #2208 unit tests: the I-UPF's rules and the split of a Session Modification.

use super::*;
use crate::n4_build::{build_session_modification_request, SessionModificationParams};

const LEG: IupfLeg = IupfLeg {
    smf_seid: (1 << 48) | LEG_SEID_BIT | 7,
    upf_seid: 0x99,
    n3: (0x1111, [127, 0, 0, 21]),
    n9: (0x2222, [127, 0, 0, 22]),
    psa_ul: (0x3333, [127, 0, 0, 31]),
    dl_tunnel: Some((0x77, [10, 0, 0, 4])),
};

fn top(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    tlvs(body)
        .into_iter()
        .map(|(t, v)| (t, v.to_vec()))
        .collect()
}

fn ohc_of(update_far: &[u8]) -> Option<(u32, [u8; 4])> {
    let fp = tlvs(update_far)
        .into_iter()
        .find(|(t, _)| *t == pfcp_ie::UPDATE_FORWARDING_PARAMETERS)?
        .1;
    let ohc = tlvs(fp)
        .into_iter()
        .find(|(t, _)| *t == pfcp_ie::OUTER_HEADER_CREATION)?
        .1;
    Some((
        u32::from_be_bytes(ohc[2..6].try_into().unwrap()),
        ohc[6..10].try_into().unwrap(),
    ))
}

/// The leg SEID is the PSA's with bit 47, and the two map back and forth;
/// a CP SEID (`FIVE_G_CP_SEID_BASE` + derivation) never has it.
#[test]
fn a_leg_seid_is_the_psa_seid_with_bit_47_2208() {
    let psa = crate::context::derive_cp_n4_seid("some-ref");
    assert!(!is_leg_seid(psa), "a CP SEID is no leg's");
    assert!(is_leg_seid(leg_seid(psa)));
    assert_eq!(psa_seid_of(leg_seid(psa)), psa);
    assert_eq!(psa_seid_of(psa), psa);
}

/// TS 23.502 §4.3.5.4: activating the NG-RAN tunnel (FAR 2 with an OHC, and
/// SNDEM) goes to the I-UPF as sent, and the PSA's FAR 2 is pointed at the
/// I-UPF's N9 F-TEID; the PSA's other rules (a QER) stay with it.
#[test]
fn a_tunnel_activation_goes_to_the_i_upf_and_the_psa_forwards_over_n9_2208() {
    let body = build_session_modification_request(&SessionModificationParams {
        update_fars_activate: vec![(2, 0, Some((0x0100, 0x77, Some([10, 0, 0, 5]), None)), true)],
        update_qers: vec![crate::n4_build::QerParams {
            qer_id: 1,
            gate_status: (0, 0),
            mbr: Some((1, 2)),
            gbr: None,
            qfi: Some(9),
        }],
        ..Default::default()
    });
    let sp = split_modification(&body, &LEG);
    let (psa, iupf) = (sp.psa.clone(), sp.iupf.clone());
    let iupf = top(&iupf.expect("the I-UPF gets the tunnel"));
    assert_eq!(
        iupf[0].0,
        pfcp_ie::PFCPSMREQ_FLAGS,
        "SNDEM goes with the tunnel"
    );
    let far = &iupf
        .iter()
        .find(|(t, _)| *t == pfcp_ie::UPDATE_FAR)
        .unwrap()
        .1;
    assert_eq!(
        ohc_of(far),
        Some((0x77, [10, 0, 0, 5])),
        "the NG-RAN tunnel"
    );
    assert!(iupf.iter().all(|(t, _)| *t != pfcp_ie::UPDATE_QER));

    let psa = top(&psa);
    assert!(psa.iter().all(|(t, _)| *t != pfcp_ie::PFCPSMREQ_FLAGS));
    let far = &psa
        .iter()
        .find(|(t, _)| *t == pfcp_ie::UPDATE_FAR)
        .unwrap()
        .1;
    assert_eq!(
        ohc_of(far),
        Some(LEG.n9),
        "the PSA forwards to the I-UPF over N9"
    );
    assert!(psa.iter().any(|(t, _)| *t == pfcp_ie::UPDATE_QER));
    // R43 M1: toward active, and what undoes the I-UPF's half: its previous tunnel.
    assert_eq!(sp.direction, Direction::TowardActive((0x77, [10, 0, 0, 5])));
    let restore = top(&sp.iupf_restore);
    assert_eq!(
        ohc_of(&restore[0].1),
        LEG.dl_tunnel,
        "back to the previous NG-RAN tunnel"
    );
}

/// R43 minor 2: PFCPSMReq-Flags go by flag: SNDEM to the I-UPF (its NG-RAN
/// tunnel), DROBU and QAURR to the PSA (its buffer and URRs).
#[test]
fn pfcpsmreq_flags_go_to_the_upf_that_acts_on_them_2208() {
    let mut body = Vec::new();
    body.extend_from_slice(&pfcp_ie::PFCPSMREQ_FLAGS.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(0x07);
    body.extend(build_session_modification_request(
        &SessionModificationParams {
            update_fars_activate: vec![(
                2,
                0,
                Some((0x0100, 0x77, Some([10, 0, 0, 5]), None)),
                false,
            )],
            ..Default::default()
        },
    ));
    let sp = split_modification(&body, &LEG);
    let flag = |b: &[u8]| {
        top(b)
            .into_iter()
            .find(|(t, _)| *t == pfcp_ie::PFCPSMREQ_FLAGS)
            .map(|(_, v)| v[0])
    };
    assert_eq!(flag(sp.iupf.as_deref().unwrap()), Some(0x02), "SNDEM");
    assert_eq!(flag(&sp.psa), Some(0x05), "DROBU and QAURR");
}

/// AN release (TS 23.502 §4.2.6): FAR 2 to BUFF|NOCP goes to both, so the PSA
/// buffers and reports downlink data while the I-UPF's NG-RAN tunnel stops. A
/// modification without FAR 2 stays with the PSA alone, byte for byte.
#[test]
fn an_apply_action_change_goes_to_both_and_the_rest_stays_with_the_psa_2208() {
    use crate::n4_build::apply_action::{BUFF, NOCP};
    let body = build_session_modification_request(&SessionModificationParams {
        update_fars_apply_action: vec![(2, BUFF | NOCP)],
        ..Default::default()
    });
    let sp = split_modification(&body, &LEG);
    let (psa, iupf) = (sp.psa.clone(), sp.iupf.clone());
    assert_eq!(psa, body, "the PSA buffers");
    assert_eq!(iupf.as_deref(), Some(&body[..]), "the I-UPF stops");
    // R43 M1: an Apply Action change, and what undoes the PSA's half: FORW to N9.
    assert_eq!(sp.direction, Direction::ApplyAction(BUFF | NOCP));
    let restore = top(&sp.psa_restore);
    assert_eq!(ohc_of(&restore[0].1), Some(LEG.n9));

    let other = build_session_modification_request(&SessionModificationParams {
        update_fars_apply_action: vec![(5, BUFF)],
        remove_srr_ids: vec![3],
        ..Default::default()
    });
    let sp = split_modification(&other, &LEG);
    let (psa, iupf) = (sp.psa.clone(), sp.iupf.clone());
    assert_eq!(psa, other);
    assert_eq!(iupf, None);
}

/// The I-UPF's rules (module docs): PDR 1 Access with CHOOSE F-TEID and OHR to
/// FAR 1 FORW toward Core with the PSA's UL F-TEID as OHC; PDR 2 Core with
/// CHOOSE F-TEID to FAR 2 BUFF toward Access. No UE address, no QER.
#[tokio::test]
async fn the_i_upf_gets_n3_uplink_toward_the_psa_and_an_n9_downlink_2208() {
    let (client, _peer) = crate::pfcp_path::stand_in::client_with_silent_peer().await;
    let body = establishment_body(&client, 0x1000, LEG.psa_ul);
    let ies = top(&body);
    assert_eq!(
        ies.iter()
            .find(|(t, _)| *t == 57)
            .map(|(_, v)| u64::from_be_bytes(v[1..9].try_into().unwrap())),
        Some(leg_seid(0x1000)),
        "the leg's CP F-SEID"
    );
    let pdrs: Vec<_> = ies
        .iter()
        .filter(|(t, _)| *t == pfcp_ie::CREATE_PDR)
        .collect();
    let fars: Vec<_> = ies
        .iter()
        .filter(|(t, _)| *t == pfcp_ie::CREATE_FAR)
        .collect();
    assert_eq!((pdrs.len(), fars.len()), (2, 2));
    let pdi = |p: &[u8]| -> Vec<(u16, Vec<u8>)> {
        top(tlvs(p).into_iter().find(|(t, _)| *t == 2).unwrap().1)
    };
    for (p, source) in [(&pdrs[0].1, 0u8), (&pdrs[1].1, 1)] {
        let d = pdi(p);
        assert_eq!(d.iter().find(|(t, _)| *t == 20).unwrap().1, vec![source]);
        let f = &d.iter().find(|(t, _)| *t == 21).unwrap().1;
        // CHOOSE: the CH flag, or this tree's zero TEID with no address.
        assert!(
            f[0] & 0x04 != 0 || (f.len() == 5 && f[1..5] == [0; 4]),
            "CHOOSE: {f:?}"
        );
        assert!(d.iter().all(|(t, _)| *t != 93), "no UE IP address");
        assert!(tlvs(p).iter().any(|(t, v)| *t == 95 && v == &[0]), "OHR");
        assert!(tlvs(p).iter().all(|(t, _)| *t != 109), "no QER");
    }
    let fp = |f: &[u8]| -> Vec<(u16, Vec<u8>)> {
        top(tlvs(f)
            .into_iter()
            .find(|(t, _)| *t == 4)
            .map(|x| x.1)
            .unwrap_or(&[]))
    };
    let ul = fp(&fars[0].1);
    assert_eq!(
        ul.iter().find(|(t, _)| *t == 42).unwrap().1,
        vec![1],
        "toward Core"
    );
    let ohc = &ul.iter().find(|(t, _)| *t == 84).unwrap().1;
    assert_eq!(
        u32::from_be_bytes(ohc[2..6].try_into().unwrap()),
        LEG.psa_ul.0
    );
    assert_eq!(&ohc[6..10], &LEG.psa_ul.1, "the PSA's UL F-TEID (N9)");
    let action = &tlvs(&fars[1].1)
        .into_iter()
        .find(|(t, _)| *t == 44)
        .unwrap()
        .1
        .to_vec();
    assert_eq!(
        action[0] & 0x04,
        0x04,
        "FAR 2 buffers until the NG-RAN is known"
    );
}

/// The Created PDRs are read by PDR ID, so the N3 and N9 F-TEIDs cannot swap.
#[test]
fn the_created_pdrs_are_read_by_pdr_id_2208() {
    let tlv = |t: u16, v: &[u8]| {
        let mut b = t.to_be_bytes().to_vec();
        b.extend_from_slice(&(v.len() as u16).to_be_bytes());
        b.extend_from_slice(v);
        b
    };
    let created = |id: u16, teid: u32| {
        let mut f = vec![0x01];
        f.extend_from_slice(&teid.to_be_bytes());
        f.extend_from_slice(&[127, 0, 0, 2]);
        let mut c = tlv(56, &id.to_be_bytes());
        c.extend(tlv(21, &f));
        tlv(8, &c)
    };
    let mut body = tlv(19, &[1]);
    let mut fseid = vec![0x02];
    fseid.extend_from_slice(&0x55u64.to_be_bytes());
    fseid.extend_from_slice(&[127, 0, 0, 2]);
    body.extend(tlv(57, &fseid));
    body.extend(created(2, 0xb));
    body.extend(created(1, 0xa));
    let (seid, f) = parse_establishment_response(&body);
    assert_eq!(seid, Some(0x55));
    assert_eq!(f[&1], (0xa, [127, 0, 0, 2]));
    assert_eq!(f[&2], (0xb, [127, 0, 0, 2]));
}

/// A split PDU session (additional NG-RAN tunnels, #619) is not carried across
/// an I-UPF: the indication is refused with transport-resource-unavailable,
/// and nothing is sent on N4.
#[tokio::test]
async fn a_split_session_over_an_i_upf_is_refused_2208() {
    use crate::n2_transfer::{DlEndpoint, ModifyIndication, SmfCause};
    let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
    let _seeded = crate::context::SeededState::track();
    crate::smf_context_init(64, 256, 512);
    let reference = "22086";
    let psa = crate::smf_n4_seid_for(reference);
    store_leg(
        psa,
        Some(IupfLeg {
            smf_seid: leg_seid(psa),
            ..LEG
        }),
    );
    let ep = |teid: u32, qfi: u8| DlEndpoint {
        teid,
        address: vec![10, 0, 0, 5],
        bit_len: 32,
        qfis: vec![qfi],
    };
    let indication = ModifyIndication {
        dl: ep(0x10, 1),
        additional: vec![ep(0x11, 2)],
    };
    let r = crate::split_pdu_session_modification(
        reference,
        0x99,
        (0x3, [127, 0, 0, 3]),
        &indication,
        None,
    )
    .await;
    forget(psa);
    let (cause, why) = r.expect_err("refused");
    assert!(
        why.contains("over an I-UPF"),
        "refused for the I-UPF: {why}"
    );
    assert_eq!(cause, SmfCause::TransportResourceUnavailable);
}
