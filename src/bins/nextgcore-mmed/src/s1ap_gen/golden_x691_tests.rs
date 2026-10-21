//! (#514 stage 13b: moved here from the deleted hand-written codec's
//! `tests/golden_x691.rs`; the same octets now pin the generated-codec
//! builders and decode mmed's tests use.)
//!
//! S1AP wire forms derived by hand from X.691 (ALIGNED PER, TS 36.413 §9.4),
//! not captured from this encoder (#455).
//!
//! Round-trip tests cannot catch an encoder and decoder that are wrong the same
//! way, and that is exactly how #455 hid: every S1AP message value omitted the
//! extensible SEQUENCE's extension bit (X.691 §19.1) on encode AND decode, so
//! nextgcore talked to itself fine and no conformant eNB could complete S1
//! Setup. Each constant below is worked out field by field in its comment; the
//! S1 Setup Request one also equals the octets nextgsim's independently derived
//! eNB golden carries (nextgsim #186).
//!
//! Notation in the derivations: `ext` = extension bit, `opt` = OPTIONAL
//! presence bit, `|` = octet boundary after alignment. Every message value is
//! `ext 0 + pad | protocolIEs count (SIZE 0..65535, two aligned octets)`, which
//! is the `00 00 0N` that #455 was missing the first octet of.

use super::test_codec::builder::*;
use super::test_codec::decode_s1ap_pdu;
use nextgcore_s1ap::cause::{Cause, CauseMisc};
use nextgcore_s1ap::types::*;
use nextgcore_s1ap::S1apMessage;
use nextgcore_s1ap_gen::generated as g;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// PLMN 999-70 in TBCD with the F filler (TS 36.413 §9.2.3.8).
const PLMN: [u8; 3] = [0x99, 0xf9, 0x07];

fn tai() -> Tai {
    Tai {
        plmn_identity: PLMN,
        tac: 1,
    }
}

fn cgi() -> EutranCgi {
    EutranCgi {
        plmn_identity: PLMN,
        cell_identity: 0x19B01,
    }
}

/// ```text
/// 00 11 00 31   CHOICE ext 0, index 0 initiatingMessage; procedureCode 17;
///               criticality reject; open type length 49
/// 00 00 04      value: ext 0 | IE count 4
/// 00 3b 00 08   id 59 Global-ENB-ID, reject, len 8:
///   00            ext 0, opt(iE-Extensions) 0 |
///   99 f9 07      pLMNidentity (fixed 3 octets, aligned)
///   00            ENB-ID: ext 0, index 0 macroENB-ID |
///   00 19 b0      0x0019B as BIT STRING(SIZE(20)), aligned (> 16 bits, §16.10)
/// 00 3c 40 0e   id 60 eNBname, ignore, len 14:
///   05 80         ext 0, length-1 = 11 in 8 bits (SIZE(1..150,...)) |
///   6e .. 62      "nextgsim-enb", one octet per character
/// 00 40 00 07   id 64 SupportedTAs, reject, len 7:
///   00            SIZE(1..256) count-1 = 0, one aligned octet
///   00 00 40      item ext 0, opt 0 | TAC 0x0001 (2 octets, §17.6) |
///                 BPLMNs SIZE(1..6) count-1 = 0 in 3 bits, pad
///   99 f9 07      broadcast PLMN
/// 00 89 40 01   id 137 DefaultPagingDRX, ignore, len 1:
///   40            ENUMERATED{v32,v64,v128,v256,...}: ext 0, v128 = 2 in 2 bits
/// ```
const S1_SETUP_REQUEST: &str = "00110031000004003b00080099f907000019b0003c400e05806e6578746773696d2d656e62004000070000004099f9070089400140";

/// ```text
/// 20 11 00 20   CHOICE ext 0, index 1 successfulOutcome; 17; reject; len 32
/// 00 00 03      value: ext 0 | IE count 3
/// 00 3d 40 05   id 61 MMEname, ignore, len 5: 01 00 = ext 0, length-1 = 2 | "mme"
/// 00 69 00 0b   id 105 ServedGUMMEIs, reject, len 11:
///   00 00         SIZE(1..8) count-1 = 0 in 3 bits; item ext 0, opt 0;
///                 servedPLMNs SIZE(1..32) count-1 = 0 in 5 bits (10 bits, pad) |
///   99 f9 07      served PLMN
///   00 00         servedGroupIDs SIZE(1..65535) count-1 = 0, two aligned octets
///   00 02         MME-Group-ID 0x0002 (2 octets)
///   00            servedMMECs SIZE(1..256) count-1 = 0, one aligned octet
///   01            MME-Code 1
/// 00 57 40 01   id 87 RelativeMMECapacity, IGNORE (TS 36.413 §9.1.8.5), len 1:
///   ff            INTEGER(0..255) = 255
/// ```
const S1_SETUP_RESPONSE: &str =
    "20110020000003003d400501006d6d650069000b000099f90700000002000100574001ff";

/// ```text
/// 40 11 00 0d   CHOICE ext 0, index 2 unsuccessfulOutcome; 17; reject; len 13
/// 00 00 02      value: ext 0 | IE count 2
/// 00 02 40 01   id 2 Cause, ignore, len 1:
///   45            CHOICE ext 0, index 4 misc (3 bits); CauseMisc ext 0, unknown-PLMN 5
///                 in 3 bits -> 0 100 0 101
/// 00 41 40 01   id 65 TimeToWait, ignore, len 1:
///   30            ENUMERATED{v1s..v60s,...}: ext 0, v10s = 3 in 3 bits
/// ```
const S1_SETUP_FAILURE: &str = "4011000d00000200024001450041400130";

/// ```text
/// 00 0c 40 2b   initiatingMessage; procedureCode 12; criticality ignore; len 43
/// 00 00 05      value: ext 0 | IE count 5
/// 00 08 00 02   id 8 eNB-UE-S1AP-ID, reject, len 2:
///   00 01         INTEGER(0..16777215): octet count-1 = 0 in 2 bits | 01
/// 00 1a 00 03   id 26 NAS-PDU, reject, len 3: length 2 | 07 41
/// 00 43 00 06   id 67 TAI, reject, len 6: ext 0, opt 0 | PLMN | TAC 00 01
/// 00 64 40 08   id 100 EUTRAN-CGI, ignore, len 8:
///   00            ext 0, opt 0 |
///   99 f9 07      PLMN
///   00 19 b0 10   cell-ID 0x0019B01 as BIT STRING(SIZE(28)), aligned, left-justified
/// 00 86 40 01   id 134 RRC-Establishment-Cause, ignore, len 1:
///   30            ENUMERATED (5 root values, extensible): ext 0, mo-Signalling = 3
/// ```
const INITIAL_UE_MESSAGE: &str = "000c402b000005000800020001001a0003020741004300060099f9070001006440080099f9070019b0100086400130";

/// ```text
/// 00 0b 40 16   initiatingMessage; procedureCode 11; ignore; len 22
/// 00 00 03      value: ext 0 | IE count 3
/// 00 00 00 02   id 0 MME-UE-S1AP-ID, reject, len 2:
///   00 01         INTEGER(0..4294967295): octet count-1 = 0 in 2 bits | 01
/// 00 08 00 02 00 01         id 8 eNB-UE-S1AP-ID 1
/// 00 1a 00 03 02 07 52      id 26 NAS-PDU [07 52]
/// ```
const DOWNLINK_NAS_TRANSPORT: &str = "000b4016000003000000020001000800020001001a0003020752";

/// ```text
/// 00 0d 40 2c   initiatingMessage; procedureCode 13; ignore; len 44
/// 00 00 05      value: ext 0 | IE count 5
/// 00 00 00 02 00 01         id 0 MME-UE-S1AP-ID 1, reject
/// 00 08 00 02 00 01         id 8 eNB-UE-S1AP-ID 1, reject
/// 00 1a 00 03 02 07 53      id 26 NAS-PDU [07 53], reject
/// 00 64 40 08 ..            id 100 EUTRAN-CGI, ignore (as in Initial UE Message)
/// 00 43 40 06 ..            id 67 TAI, IGNORE in this message (TS 36.413 §9.1.7.3)
/// ```
const UPLINK_NAS_TRANSPORT: &str = "000d402c000005000000020001000800020001001a0003020753006440080099f9070019b010004340060099f9070001";

/// ```text
/// 00 09 00 5d   initiatingMessage; procedureCode 9; reject; len 93
/// 00 00 06      value: ext 0 | IE count 6
/// 00 00 00 02 00 01         id 0 MME-UE-S1AP-ID 1
/// 00 08 00 02 00 01         id 8 eNB-UE-S1AP-ID 1
/// 00 42 00 06   id 66 uEaggregateMaximumBitrate, reject, len 6:
///   08 03 e8      ext 0, opt 0, BitRate(0..10000000000) octet count-1 = 1 in 3 bits | 1000
///   20 03 e8      UL: octet count-1 = 1 in 3 bits | 1000
/// 00 18 00 13   id 24 E-RABToBeSetupListCtxtSUReq, reject, len 19:
///   00            SIZE(1..256) count-1 = 0, one aligned octet
///   00 34 00 0e   id 52 E-RABToBeSetupItemCtxtSUReq, reject, len 14:
///     05            ext 0, opt(nAS-PDU) 0, opt(iE-Ext) 0; e-RAB-ID ext 0, 5 in 4 bits
///     00 09         QoS: ext 0, opt 0, opt 0, pad | QCI 9
///     04            ARP: ext 0, opt 0, priority 1 in 4 bits, shall-not-trigger,
///                   not-pre-emptable
///     0f 80         transportLayerAddress BIT STRING(SIZE(1..160,...)): ext 0,
///                   length-1 = 31 in 8 bits |
///     0a 00 00 01   10.0.0.1 (aligned)
///     00 00 00 01   GTP-TEID (4 octets)
/// 00 6b 00 05   id 107 UESecurityCapabilities, reject, len 5:
///   18 00 0c 00 00  ext 0, opt 0; EEA BIT STRING(SIZE(16,...)) ext 0 + 0xC000;
///                   EIA ext 0 + 0xC000 (16-bit fixed sizes are not aligned)
/// 00 49 00 20   id 73 SecurityKey, reject, len 32: BIT STRING(SIZE(256)), aligned
///   00 * 32       an all-zero test key
/// ```
const INITIAL_CONTEXT_SETUP_REQUEST: &str = "0009005d000006000000020001000800020001004200060803e82003e800180013000034000e050009040f800a00000100000001006b000518000c0000004900200000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn s1_setup_request_matches_x691() {
    let bytes = build_s1_setup_request(&S1SetupRequest {
        global_enb_id: GlobalEnbId {
            plmn_identity: PLMN,
            enb_id: EnbId::Macro(0x19B),
        },
        enb_name: Some("nextgsim-enb".into()),
        supported_tas: vec![SupportedTaItem {
            tac: 1,
            broadcast_plmns: vec![PLMN],
        }],
        default_paging_drx: PagingDrx::V128,
    })
    .unwrap();
    assert_eq!(hex(&bytes), S1_SETUP_REQUEST);
}

#[test]
fn s1_setup_response_matches_x691() {
    let bytes = build_s1_setup_response(&S1SetupResponse {
        mme_name: Some("mme".into()),
        served_gummeis: vec![ServedGummeiItem {
            served_plmns: vec![PLMN],
            served_group_ids: vec![2],
            served_mmec_codes: vec![1],
        }],
        relative_mme_capacity: 255,
    })
    .unwrap();
    assert_eq!(hex(&bytes), S1_SETUP_RESPONSE);
}

#[test]
fn s1_setup_failure_matches_x691() {
    let bytes = build_s1_setup_failure(&S1SetupFailure {
        cause: Cause::Misc(CauseMisc::UnknownPlmn),
        time_to_wait: Some(TimeToWait::V10s),
    })
    .unwrap();
    assert_eq!(hex(&bytes), S1_SETUP_FAILURE);
}

#[test]
fn initial_ue_message_matches_x691() {
    let bytes = build_initial_ue_message(&InitialUeMessage {
        enb_ue_s1ap_id: 1,
        nas_pdu: vec![0x07, 0x41],
        tai: tai(),
        eutran_cgi: cgi(),
        rrc_establishment_cause: RrcEstablishmentCause::MoSignalling,
        s_tmsi: None,
    })
    .unwrap();
    assert_eq!(hex(&bytes), INITIAL_UE_MESSAGE);
}

#[test]
fn downlink_nas_transport_matches_x691() {
    let bytes = build_downlink_nas_transport(&DlNasTransport {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        nas_pdu: vec![0x07, 0x52],
    })
    .unwrap();
    assert_eq!(hex(&bytes), DOWNLINK_NAS_TRANSPORT);
}

#[test]
fn uplink_nas_transport_matches_x691() {
    let bytes = build_uplink_nas_transport(&UlNasTransport {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        nas_pdu: vec![0x07, 0x53],
        eutran_cgi: cgi(),
        tai: tai(),
    })
    .unwrap();
    assert_eq!(hex(&bytes), UPLINK_NAS_TRANSPORT);
}

#[test]
fn initial_context_setup_request_matches_x691() {
    let bytes = build_initial_context_setup_request(&InitialContextSetupRequest {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        ue_ambr: UeAmbr { dl: 1000, ul: 1000 },
        erab_list: vec![ErabToBeSetupItem {
            erab_id: 5,
            erab_qos: ErabLevelQosParameters {
                qci: 9,
                arp: AllocationRetentionPriority {
                    priority_level: 1,
                    pre_emption_capability: false,
                    pre_emption_vulnerability: false,
                },
                gbr_qos_info: None,
            },
            transport_layer_address: vec![10, 0, 0, 1],
            gtp_teid: 1,
            nas_pdu: None,
        }],
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: 0xC000,
            integrity_algorithms: 0xC000,
        },
        security_key: [0u8; 32],
    })
    .unwrap();
    assert_eq!(hex(&bytes), INITIAL_CONTEXT_SETUP_REQUEST);
}

/// The decode side reads the same X.691 forms: a conformant peer's octets
/// decode to the values they carry. This is the direction #455 broke for mmed
/// (`Missing mandatory IE: Global-ENB-ID`).
#[test]
fn x691_forms_decode_to_their_values() {
    match decode_s1ap_pdu(&unhex(S1_SETUP_REQUEST)).unwrap() {
        S1apMessage::S1SetupRequest(r) => {
            assert_eq!(r.global_enb_id.plmn_identity, PLMN);
            assert_eq!(r.global_enb_id.enb_id, EnbId::Macro(0x19B));
            assert_eq!(r.enb_name.as_deref(), Some("nextgsim-enb"));
            assert_eq!(r.supported_tas.len(), 1);
            assert_eq!(r.supported_tas[0].tac, 1);
            assert_eq!(r.default_paging_drx, PagingDrx::V128);
        }
        other => panic!("expected S1 Setup Request, got {other:?}"),
    }
    match decode_s1ap_pdu(&unhex(INITIAL_UE_MESSAGE)).unwrap() {
        S1apMessage::InitialUeMessage(m) => {
            assert_eq!(m.enb_ue_s1ap_id, 1);
            assert_eq!(m.nas_pdu, vec![0x07, 0x41]);
            assert_eq!(m.eutran_cgi.cell_identity, 0x19B01);
            assert_eq!(
                m.rrc_establishment_cause,
                RrcEstablishmentCause::MoSignalling
            );
        }
        other => panic!("expected Initial UE Message, got {other:?}"),
    }
    match decode_s1ap_pdu(&unhex(UPLINK_NAS_TRANSPORT)).unwrap() {
        S1apMessage::UplinkNasTransport(m) => {
            assert_eq!((m.mme_ue_s1ap_id, m.enb_ue_s1ap_id), (1, 1));
            assert_eq!(m.nas_pdu, vec![0x07, 0x53]);
            assert_eq!(m.tai.tac, 1);
        }
        other => panic!("expected Uplink NAS Transport, got {other:?}"),
    }
}

/// (id, criticality) of every IE in a built message, read straight off the
/// wire container with the generated codec rather than the typed decode.
fn ie_criticalities(bytes: &[u8]) -> Vec<(u16, u8)> {
    match nextgcore_s1ap_gen::decode(bytes).unwrap() {
        g::S1AP_PDU::SuccessfulOutcome(m) => match m.value {
            g::SuccessfulOutcomeValue::Id_PathSwitchRequest(c) => c
                .protocol_i_es
                .0
                .iter()
                .map(|f| (f.id.0, f.criticality.0))
                .collect(),
            other => panic!("{other:?}"),
        },
        g::S1AP_PDU::UnsuccessfulOutcome(m) => match m.value {
            g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(c) => c
                .protocol_i_es
                .0
                .iter()
                .map(|f| (f.id.0, f.criticality.0))
                .collect(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

/// Both UE S1AP IDs are criticality ignore in HANDOVER PREPARATION FAILURE
/// (TS 36.413 §9.1.5.3) and PATH SWITCH REQUEST ACKNOWLEDGE (§9.1.5.9), unlike
/// most UE-associated messages where they are reject. Found by auditing every
/// builder's IE criticalities against the TS 36.413 object sets (#455).
#[test]
fn ue_ids_are_criticality_ignore_where_the_object_set_says_so() {
    const IGNORE: u8 = g::Criticality::IGNORE;
    let hpf = build_handover_preparation_failure(&HandoverPreparationFailure {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        cause: Cause::Misc(CauseMisc::Unspecified),
    })
    .unwrap();
    let c = ie_criticalities(&hpf);
    assert_eq!(
        &c[..2],
        &[(0, IGNORE), (8, IGNORE)],
        "HANDOVER PREPARATION FAILURE"
    );

    let psa = build_path_switch_request_acknowledge(&PathSwitchRequestAcknowledge {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        erab_switched_ul_list: vec![],
        security_context: SecurityContext {
            next_hop_chaining_count: 0,
            next_hop_parameter: [0u8; 32],
        },
    })
    .unwrap();
    let c = ie_criticalities(&psa);
    assert_eq!(
        &c[..2],
        &[(0, IGNORE), (8, IGNORE)],
        "PATH SWITCH REQUEST ACKNOWLEDGE"
    );
}
