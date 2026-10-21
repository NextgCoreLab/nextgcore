//! #514 stage 7: Paging on the generated codec.
//!
//! Oracle: `test_codec::builder::build_paging`, which since #514 stage 13b checks that the production encode decodes back to its input through an independently written mapping.
//! Golden: octets derived by hand from X.691 (APER) for TS 36.413 §9.1.6.

use super::*;
use crate::s1ap_gen::test_codec::builder;
use nextgcore_s1ap::{CnDomain, Paging, PagingDrx, STmsi, Tai, UePagingId};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// PAGING: UE Identity Index 1, S-TMSI (MMEC 1, M-TMSI 0x01020304), no DRX,
/// CN domain PS, one TAI (PLMN `00 f1 10`, TAC 1).
///
/// `00 0a 40 27`: initiatingMessage, procedure 10, criticality ignore, length
/// 39. Value `00 00 04`: four IEs, each criticality ignore (`40`).
///
/// - IE 80 `00 50 40 02`: UEIdentityIndexValue BIT STRING (SIZE(10)), fixed
///   and at most 16 bits so unaligned: `0000000001` and pad, `00 40`.
/// - IE 43 `00 2b 40 06`: UEPagingID CHOICE ext 0, index 0 (s-TMSI); S-TMSI
///   ext 0, iE-Extensions absent 0; MME-Code OCTET STRING (SIZE(1)) unaligned
///   `00000001`; so `0000 0000 | 0001` and pad = `00 10`; M-TMSI OCTET STRING
///   (SIZE(4)) octet-aligned `01 02 03 04`.
/// - IE 109 `00 6d 40 01`: CNDomain ENUMERATED {ps, cs}, 1 bit `0` and pad,
///   `00`.
/// - IE 46 `00 2e 40 0b`: TAIList SIZE(1..256), count-1 = 0 in one octet `00`;
///   item IE 47 `00 2f 40 06`, TAIItem ext 0 + iE-Ext 0, TAI ext 0 + iE-Ext 0,
///   pad, PLMNidentity (SIZE(3)) aligned `00 f1 10`, TAC (SIZE(2)) `00 01`.
const PAGING: &str =
    "000a4027000004005040020040002b4006001001020304006d400100002e400b00002f40060000f1100001";

fn golden() -> String {
    PAGING.replace(' ', "")
}

fn s_tmsi_paging() -> Paging {
    Paging {
        ue_identity_index: 1,
        ue_paging_id: UePagingId::STmsi(STmsi {
            mmec: 1,
            m_tmsi: 0x0102_0304,
        }),
        paging_drx: None,
        cn_domain: CnDomain::Ps,
        tai_list: vec![Tai {
            plmn_identity: [0x00, 0xf1, 0x10],
            tac: 1,
        }],
    }
}

#[test]
fn the_paging_is_the_x691_golden() {
    assert_eq!(hex(&build_paging(&s_tmsi_paging()).unwrap()), golden());
}

#[test]
fn the_paging_matches_the_hand_written_encoder() {
    let mut cases = 0;
    let ids = [
        UePagingId::STmsi(STmsi { mmec: 0, m_tmsi: 0 }),
        UePagingId::STmsi(STmsi {
            mmec: 0xFF,
            m_tmsi: 0xFFFF_FFFF,
        }),
        UePagingId::Imsi(vec![0x09, 0x99, 0x07]),
        UePagingId::Imsi(vec![0x99, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF1]),
    ];
    for index in [0u16, 1, 511, 512, 1023] {
        for id in &ids {
            for drx in [
                None,
                Some(PagingDrx::V32),
                Some(PagingDrx::V64),
                Some(PagingDrx::V128),
                Some(PagingDrx::V256),
            ] {
                for cn in [CnDomain::Ps, CnDomain::Cs] {
                    for tais in [1usize, 2, 16] {
                        let msg = Paging {
                            ue_identity_index: index,
                            ue_paging_id: id.clone(),
                            paging_drx: drx,
                            cn_domain: cn,
                            tai_list: (0..tais)
                                .map(|i| Tai {
                                    plmn_identity: [0x99, 0xF9, 0x07],
                                    tac: 0xFFFF - i as u16,
                                })
                                .collect(),
                        };
                        let old = builder::build_paging(&msg).unwrap();
                        let new = build_paging(&msg).unwrap();
                        assert_eq!(hex(&new), hex(&old), "{msg:?}");
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 600);
}

#[test]
fn the_production_builder_sends_the_generated_bytes() {
    // An IMSI-paged UE (no M-TMSI yet), as `s1ap_build::build_paging` sees it.
    let mut mme_ue = crate::context::MmeUe::default();
    mme_ue.imsi_bcd = "999700000000001".to_string();
    let tai = crate::context::EpsTai {
        plmn_id: crate::context::PlmnId::new("999", "70"),
        tac: 1,
    };
    let bytes =
        crate::s1ap_build::build_paging(&mme_ue, CnDomain::Ps, std::slice::from_ref(&tai), None)
            .unwrap();
    let expected = build_paging(&Paging {
        ue_identity_index: crate::s1ap_build::ue_identity_index_from_imsi(&mme_ue.imsi_bcd),
        ue_paging_id: UePagingId::Imsi(crate::s1ap_build::imsi_bcd_to_tbcd(&mme_ue.imsi_bcd)),
        paging_drx: None,
        cn_domain: CnDomain::Ps,
        tai_list: vec![crate::s1ap_build::tai_to_s1ap(&tai)],
    })
    .unwrap();
    assert_eq!(hex(&bytes), hex(&expected));
}
