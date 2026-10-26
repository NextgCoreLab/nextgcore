//! Codec checks: a hand-derived APER encoding (X.691) and round trips of the
//! messages stage 2 relays.

use super::generated as g;
use super::{decode, encode};
use bitvec::prelude::*;

fn bits(bytes: &[u8], n: usize) -> BitVec<u8, Msb0> {
    let mut v = BitVec::<u8, Msb0>::from_slice(bytes);
    v.truncate(n);
    v
}

fn global_enb_id(plmn: [u8; 3], macro_id: u32) -> g::Global_ENB_ID {
    g::Global_ENB_ID {
        plm_nidentity: g::TBCD_STRING(plmn.to_vec()),
        enb_id: g::ENB_ID::MacroENB_ID(g::ENB_ID_macroENB_ID(bits(
            &(macro_id << 12).to_be_bytes(),
            20,
        ))),
        ie_extensions: None,
    }
}

fn restart(ies: Vec<g::PWS_Restart_IndicationProtocolIEs_EntryValue>) -> g::SBC_AP_PDU {
    use g::PWS_Restart_IndicationProtocolIEs_EntryValue as V;
    let entries = ies
        .into_iter()
        .map(|value| {
            let id = match &value {
                V::Id_Restarted_Cell_List(_) => 30,
                V::Id_Global_ENB_ID(_) => 28,
                V::Id_List_of_TAIs_Restart(_) => 31,
                V::Id_List_of_EAIs_Restart(_) => 32,
            };
            g::PWS_Restart_IndicationProtocolIEs_Entry {
                id: g::ProtocolIE_ID(id),
                criticality: g::Criticality(g::Criticality::REJECT),
                value,
            }
        })
        .collect();
    g::SBC_AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(5),
        criticality: g::Criticality(g::Criticality::IGNORE),
        value: g::InitiatingMessageValue::Id_PWS_Restart_Indication(g::PWS_Restart_Indication {
            protocol_i_es: g::PWS_Restart_IndicationProtocolIEs(entries),
            protocol_extensions: None,
        }),
    })
}

/// X.691 by hand for a PWS-Restart-Indication (TS 29.168 §4.3.3E, procedure code
/// 5, criticality ignore) holding one IE, Global-ENB-ID (id 28, reject): PLMN
/// 99 F9 07, macro eNB ID 1.
/// - `00`: SBC-AP-PDU CHOICE, extension bit 0, index 0 (initiatingMessage), padded;
/// - `05`: procedureCode INTEGER (0..255), one aligned octet;
/// - `40`: criticality ENUMERATED (3 values) "01", padded;
/// - `0F`: the open type's length (15);
/// - `00`: the SEQUENCE's extension bit and its one OPTIONAL's presence bit, padded;
/// - `00 01`: the IE count, a constrained whole number (0..65535) in two octets;
/// - `00 1C 00 08`: id 28, criticality reject (padded), open type length 8;
/// - `00 99 F9 07`: Global-ENB-ID's extension and OPTIONAL bits, padded, then the
///   PLMN identity (fixed SIZE (3): no length);
/// - `00 00 00 10`: ENB-ID CHOICE, extension bit 0, index 0 (macro), padded, then
///   the 20-bit macroENB-ID 0x00001.
#[test]
fn a_pws_restart_indication_encodes_as_x691_says() {
    let pdu = restart(vec![
        g::PWS_Restart_IndicationProtocolIEs_EntryValue::Id_Global_ENB_ID(global_enb_id(
            [0x99, 0xf9, 0x07],
            1,
        )),
    ]);
    let bytes = encode(&pdu).unwrap();
    assert_eq!(
        bytes,
        vec![
            0x00, 0x05, 0x40, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x1c, 0x00, 0x08, 0x00, 0x99, 0xf9,
            0x07, 0x00, 0x00, 0x00, 0x10
        ]
    );
    assert_eq!(decode(&bytes).unwrap(), pdu);
}

/// The PWS-Restart-Indication stage 2 relays (TS 23.007 §15A.1.2): restarted
/// cells, Global eNB ID, TAIs and EAIs round-trip.
#[test]
fn a_full_pws_restart_indication_round_trips() {
    use g::PWS_Restart_IndicationProtocolIEs_EntryValue as V;
    let plmn = [0x99, 0xf9, 0x07];
    let pdu = restart(vec![
        V::Id_Restarted_Cell_List(g::Restarted_Cell_List(vec![g::EUTRAN_CGI {
            plm_nidentity: g::TBCD_STRING(plmn.to_vec()),
            cell_id: g::CellIdentity(bits(&[0x00, 0x00, 0x10, 0x10], 28)),
            ie_extensions: None,
        }])),
        V::Id_Global_ENB_ID(global_enb_id(plmn, 1)),
        V::Id_List_of_TAIs_Restart(g::List_of_TAIs_Restart(vec![
            g::List_of_TAIs_Restart_Entry {
                tai: g::TAI {
                    plm_nidentity: g::TBCD_STRING(plmn.to_vec()),
                    tac: g::TAC(vec![0x00, 0x01]),
                    ie_extensions: None,
                },
            },
        ])),
        V::Id_List_of_EAIs_Restart(g::List_of_EAIs_Restart(vec![g::Emergency_Area_ID(vec![
            1, 2, 3,
        ])])),
    ]);
    let bytes = encode(&pdu).unwrap();
    assert_eq!(
        &bytes[..3],
        &[0x00, 0x05, 0x40],
        "initiating, code 5, ignore"
    );
    assert_eq!(decode(&bytes).unwrap(), pdu);
}

/// A truncated PDU is a decode error, not a panic.
#[test]
fn a_truncated_pdu_is_an_error() {
    let pdu = restart(vec![
        g::PWS_Restart_IndicationProtocolIEs_EntryValue::Id_Global_ENB_ID(global_enb_id(
            [0x99, 0xf9, 0x07],
            1,
        )),
    ]);
    let bytes = encode(&pdu).unwrap();
    for n in 0..bytes.len() {
        assert!(decode(&bytes[..n]).is_err(), "{n} octets");
    }
}
