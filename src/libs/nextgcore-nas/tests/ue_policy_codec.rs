//! Wave-6 E2 — golden byte-vector tests for the UPDP codec
//! (`nextgcore_nas::fiveg::ue_policy`) against the hand-derived E1 vectors in
//! `tests/ue_policy_golden_vectors/data.rs` (TS 24.526 V18.5.0 §5.2 +
//! TS 24.501 V19.6.2 Annex D — see the provenance header of that file).
//!
//! Acceptance per the WS-E spec: encoding the catch-all `UrspRule` model must
//! produce the exact E1 (a)+(e)+(f) bytes — byte-exact match, not
//! roundtrip-only — plus strict-decode rejection of malformed mutations.

use nextgcore_nas::common::types::PlmnId;
use nextgcore_nas::fiveg::ie::{PduSessionType, SscMode};
use nextgcore_nas::fiveg::ue_policy::{
    decode_ursp_rules, encode_ursp_rules, Instruction, ManageUePolicyCommand,
    ManageUePolicyCommandReject, ManageUePolicyComplete, PlmnSublist, PreferredAccessType,
    RouteSelectionDescriptor, RouteSelectionDescriptorComponent, TrafficDescriptorComponent,
    UePolicyClassmark, UePolicyPart, UePolicyPartType, UePolicyResult,
    UePolicySectionManagementList, UePolicySectionManagementResult,
    UePolicySectionManagementSubresult, UeStateIndication, UpsiList, UpsiSublist,
    UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
};

include!("ue_policy_golden_vectors/data.rs");

// All tests live in a `ue_policy_*` module so the WS-E gate command
// `cargo test -p nextgcore-nas ue_policy` selects them by name.
mod ue_policy_golden {
    use super::*;

    // =========================================================================
    // Model builders mirroring the E1 vector descriptions
    // =========================================================================

    fn plmn_001_01() -> PlmnId {
        PlmnId::new([0, 0, 1], [0, 1, 0], 2)
    }

    /// Vector (a): catch-all rule — precedence 255, match-all TD, one RSD
    /// {precedence 255, SSC mode 1, S-NSSAI SST=1, DNN "internet", PDU type
    /// IPv4v6} (matches nextgcore-pcfd `UrspRule::catch_all()`).
    fn catch_all_rule() -> nextgcore_nas::fiveg::ue_policy::UrspRule {
        nextgcore_nas::fiveg::ue_policy::UrspRule {
            precedence: 255,
            traffic_descriptor: vec![TrafficDescriptorComponent::MatchAll],
            route_selection_descriptors: vec![RouteSelectionDescriptor {
                precedence: 255,
                components: vec![
                    RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode1),
                    RouteSelectionDescriptorComponent::SNssai { sst: 1, sd: None },
                    RouteSelectionDescriptorComponent::Dnn("internet".into()),
                    RouteSelectionDescriptorComponent::PduSessionType(PduSessionType::Ipv4v6),
                ],
            }],
            ureri: None,
        }
    }

    /// Vector (b): IMS rule — precedence 10, TD = DNN(ims), one RSD {precedence
    /// 10, SSC 1, S-NSSAI SST=1, DNN "ims", IPv4v6, preferred access 3GPP}
    /// (matches nextgcore-pcfd `UrspRule::ims_rule()`).
    fn ims_rule() -> nextgcore_nas::fiveg::ue_policy::UrspRule {
        nextgcore_nas::fiveg::ue_policy::UrspRule {
            precedence: 10,
            traffic_descriptor: vec![TrafficDescriptorComponent::Dnn("ims".into())],
            route_selection_descriptors: vec![RouteSelectionDescriptor {
                precedence: 10,
                components: vec![
                    RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode1),
                    RouteSelectionDescriptorComponent::SNssai { sst: 1, sd: None },
                    RouteSelectionDescriptorComponent::Dnn("ims".into()),
                    RouteSelectionDescriptorComponent::PduSessionType(PduSessionType::Ipv4v6),
                    RouteSelectionDescriptorComponent::PreferredAccessType(
                        PreferredAccessType::ThreeGpp,
                    ),
                ],
            }],
            ureri: None,
        }
    }

    /// Vector (c): OS Id + OS App Id rule — precedence 100, TD = OS Id UUID
    /// 00112233-4455-6677-8899-AABBCCDDEEFF + App Id "app1", RSD as (a) with
    /// precedence 1.
    fn os_app_id_rule() -> nextgcore_nas::fiveg::ue_policy::UrspRule {
        nextgcore_nas::fiveg::ue_policy::UrspRule {
            precedence: 100,
            traffic_descriptor: vec![TrafficDescriptorComponent::OsIdOsAppId {
                os_id: [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                    0xDD, 0xEE, 0xFF,
                ],
                os_app_id: b"app1".to_vec(),
            }],
            route_selection_descriptors: vec![RouteSelectionDescriptor {
                precedence: 1,
                components: vec![
                    RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode1),
                    RouteSelectionDescriptorComponent::SNssai { sst: 1, sd: None },
                    RouteSelectionDescriptorComponent::Dnn("internet".into()),
                    RouteSelectionDescriptorComponent::PduSessionType(PduSessionType::Ipv4v6),
                ],
            }],
            ureri: None,
        }
    }

    /// Vector (d): one rule, two RSDs with distinct precedences 10 and 20.
    fn two_rsds_rule() -> nextgcore_nas::fiveg::ue_policy::UrspRule {
        nextgcore_nas::fiveg::ue_policy::UrspRule {
            precedence: 50,
            traffic_descriptor: vec![TrafficDescriptorComponent::Dnn("internet".into())],
            route_selection_descriptors: vec![
                RouteSelectionDescriptor {
                    precedence: 10,
                    components: vec![
                        RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode1),
                        RouteSelectionDescriptorComponent::SNssai { sst: 1, sd: None },
                        RouteSelectionDescriptorComponent::PduSessionType(PduSessionType::Ipv4v6),
                        RouteSelectionDescriptorComponent::PreferredAccessType(
                            PreferredAccessType::ThreeGpp,
                        ),
                    ],
                },
                RouteSelectionDescriptor {
                    precedence: 20,
                    components: vec![
                        RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode1),
                        RouteSelectionDescriptorComponent::PduSessionType(PduSessionType::Ipv4v6),
                        RouteSelectionDescriptorComponent::PreferredAccessType(
                            PreferredAccessType::NonThreeGpp,
                        ),
                    ],
                },
            ],
            ureri: None,
        }
    }

    /// Vector (e): one PLMN sublist (MCC=001, MNC=01), one instruction
    /// (UPSC=0x0001), one URSP part whose contents are vector (a).
    fn vec_e_list() -> UePolicySectionManagementList {
        UePolicySectionManagementList {
            sublists: vec![PlmnSublist {
                plmn_id: plmn_001_01(),
                instructions: vec![Instruction {
                    upsc: 0x0001,
                    parts: vec![UePolicyPart::ursp(&[catch_all_rule()]).unwrap()],
                }],
            }],
        }
    }

    // =========================================================================
    // Golden encode: model -> E1 bytes (byte-exact, the E2 acceptance gate)
    // =========================================================================

    #[test]
    fn encode_catch_all_rule_matches_vec_a() {
        assert_eq!(
            encode_ursp_rules(&[catch_all_rule()]).unwrap(),
            VEC_A_URSP_RULE_CATCH_ALL
        );
    }

    #[test]
    fn encode_ims_rule_matches_vec_b() {
        assert_eq!(
            encode_ursp_rules(&[ims_rule()]).unwrap(),
            VEC_B_URSP_RULE_DNN_IMS
        );
    }

    #[test]
    fn encode_os_app_id_rule_matches_vec_c() {
        assert_eq!(
            encode_ursp_rules(&[os_app_id_rule()]).unwrap(),
            VEC_C_URSP_RULE_OS_APP_ID
        );
    }

    #[test]
    fn encode_two_rsds_rule_matches_vec_d() {
        assert_eq!(
            encode_ursp_rules(&[two_rsds_rule()]).unwrap(),
            VEC_D_URSP_RULE_TWO_RSDS
        );
    }

    #[test]
    fn encode_section_list_matches_vec_e() {
        assert_eq!(
            vec_e_list().encode_lv_e().unwrap(),
            VEC_E_SECTION_MGMT_LIST_LVE
        );
    }

    #[test]
    fn encode_manage_ue_policy_command_matches_vec_f() {
        let cmd = ManageUePolicyCommand {
            pti: 0x80,
            list: vec_e_list(),
        };
        assert_eq!(cmd.encode().unwrap(), VEC_F_MANAGE_UE_POLICY_COMMAND);
    }

    // =========================================================================
    // Golden decode: E1 bytes -> model (field-level asserts)
    // =========================================================================

    #[test]
    fn decode_vec_f_yields_the_full_model() {
        let cmd = ManageUePolicyCommand::decode(VEC_F_MANAGE_UE_POLICY_COMMAND).unwrap();
        assert_eq!(cmd.pti, 0x80);
        assert_eq!(cmd.list.sublists.len(), 1);
        let sublist = &cmd.list.sublists[0];
        assert_eq!(sublist.plmn_id, plmn_001_01());
        assert_eq!(sublist.instructions.len(), 1);
        let instr = &sublist.instructions[0];
        assert_eq!(instr.upsc, 0x0001);
        assert_eq!(instr.parts.len(), 1);
        assert_eq!(instr.parts[0].part_type, UePolicyPartType::Ursp);
        assert_eq!(instr.parts[0].contents, VEC_A_URSP_RULE_CATCH_ALL);
        let rules = instr.parts[0].decode_ursp().unwrap();
        assert_eq!(rules, vec![catch_all_rule()]);
    }

    #[test]
    fn decode_ursp_vectors_yield_the_models() {
        assert_eq!(
            decode_ursp_rules(VEC_A_URSP_RULE_CATCH_ALL).unwrap(),
            vec![catch_all_rule()]
        );
        assert_eq!(
            decode_ursp_rules(VEC_B_URSP_RULE_DNN_IMS).unwrap(),
            vec![ims_rule()]
        );
        assert_eq!(
            decode_ursp_rules(VEC_C_URSP_RULE_OS_APP_ID).unwrap(),
            vec![os_app_id_rule()]
        );
        assert_eq!(
            decode_ursp_rules(VEC_D_URSP_RULE_TWO_RSDS).unwrap(),
            vec![two_rsds_rule()]
        );
    }

    // =========================================================================
    // Round-trip property: encode(decode(v)) == v for ALL E1 vectors
    // =========================================================================

    #[test]
    fn roundtrip_all_golden_vectors() {
        for v in [
            VEC_A_URSP_RULE_CATCH_ALL,
            VEC_B_URSP_RULE_DNN_IMS,
            VEC_C_URSP_RULE_OS_APP_ID,
            VEC_D_URSP_RULE_TWO_RSDS,
        ] {
            let decoded = decode_ursp_rules(v).unwrap();
            assert_eq!(
                encode_ursp_rules(&decoded).unwrap(),
                v,
                "URSP rule roundtrip"
            );
        }
        let list = UePolicySectionManagementList::decode_lv_e(VEC_E_SECTION_MGMT_LIST_LVE).unwrap();
        assert_eq!(list.encode_lv_e().unwrap(), VEC_E_SECTION_MGMT_LIST_LVE);
        let cmd = ManageUePolicyCommand::decode(VEC_F_MANAGE_UE_POLICY_COMMAND).unwrap();
        assert_eq!(cmd.encode().unwrap(), VEC_F_MANAGE_UE_POLICY_COMMAND);
    }

    // =========================================================================
    // Malformed-decode rejection (>= 8 mutations of the golden vectors)
    // =========================================================================

    #[test]
    fn mutation_1_truncated_command_rejected() {
        let v = &VEC_F_MANAGE_UE_POLICY_COMMAND[..VEC_F_MANAGE_UE_POLICY_COMMAND.len() - 1];
        assert!(ManageUePolicyCommand::decode(v).is_err());
    }

    #[test]
    fn mutation_2_lv_e_length_inflated_rejected() {
        let mut v = VEC_F_MANAGE_UE_POLICY_COMMAND.to_vec();
        v[3] += 1; // LV-E length now runs past the end of the buffer
        assert!(ManageUePolicyCommand::decode(&v).is_err());
    }

    #[test]
    fn mutation_3_lv_e_length_deflated_rejected() {
        let mut v = VEC_F_MANAGE_UE_POLICY_COMMAND.to_vec();
        v[3] -= 1; // one trailing octet left outside every scope
        assert!(ManageUePolicyCommand::decode(&v).is_err());
    }

    #[test]
    fn mutation_4_wrong_message_type_rejected() {
        let mut v = VEC_F_MANAGE_UE_POLICY_COMMAND.to_vec();
        v[1] = 0x05; // not MANAGE UE POLICY COMMAND (Table D.6.1.1)
        assert!(ManageUePolicyCommand::decode(&v).is_err());
    }

    #[test]
    fn mutation_5_pti_outside_pcf_range_rejected() {
        let mut v = VEC_F_MANAGE_UE_POLICY_COMMAND.to_vec();
        v[0] = 0x10; // outside 80H-FEH (TS 24.501 D.1.2)
        assert!(ManageUePolicyCommand::decode(&v).is_err());
    }

    #[test]
    fn mutation_6_part_type_spare_bits_rejected() {
        let mut v = VEC_E_SECTION_MGMT_LIST_LVE.to_vec();
        assert_eq!(v[13], 0x01); // part-type octet (URSP)
        v[13] = 0x11; // bits 8..5 must be spare zero (Table D.6.2.1)
        assert!(UePolicySectionManagementList::decode_lv_e(&v).is_err());
    }

    #[test]
    fn mutation_7_reserved_part_type_zero_rejected() {
        let mut v = VEC_E_SECTION_MGMT_LIST_LVE.to_vec();
        v[13] = 0x00; // 0000 = Reserved (Table D.6.2.1)
        assert!(UePolicySectionManagementList::decode_lv_e(&v).is_err());
    }

    #[test]
    fn mutation_8_reserved_part_type_seven_rejected() {
        let mut v = VEC_E_SECTION_MGMT_LIST_LVE.to_vec();
        v[13] = 0x07; // 0111 is reserved (Table D.6.2.1 lists only 0001..0110)
        assert!(UePolicySectionManagementList::decode_lv_e(&v).is_err());
    }

    #[test]
    fn mutation_9_sublist_length_corrupted_rejected() {
        for delta in [1i16, -1] {
            let mut v = VEC_E_SECTION_MGMT_LIST_LVE.to_vec();
            let len = u16::from_be_bytes([v[2], v[3]]);
            let bad = (len as i16 + delta) as u16;
            v[2..4].copy_from_slice(&bad.to_be_bytes());
            assert!(
                UePolicySectionManagementList::decode_lv_e(&v).is_err(),
                "sublist length {bad} accepted"
            );
        }
    }

    #[test]
    fn mutation_10_ssc_mode_spare_bits_rejected() {
        let mut v = VEC_A_URSP_RULE_CATCH_ALL.to_vec();
        assert_eq!(v[14], 0x01); // SSC mode value octet
        v[14] = 0x09; // bit 4 is spare (TS 24.526 :2709-2711)
        assert!(decode_ursp_rules(&v).is_err());
    }

    #[test]
    fn mutation_11_truncated_ursp_rule_rejected() {
        let v = &VEC_A_URSP_RULE_CATCH_ALL[..VEC_A_URSP_RULE_CATCH_ALL.len() - 1];
        assert!(decode_ursp_rules(v).is_err());
    }

    #[test]
    fn mutation_12_ursp_rule_length_corrupted_rejected() {
        for delta in [1i16, -1] {
            let mut v = VEC_A_URSP_RULE_CATCH_ALL.to_vec();
            let len = u16::from_be_bytes([v[0], v[1]]);
            let bad = (len as i16 + delta) as u16;
            v[0..2].copy_from_slice(&bad.to_be_bytes());
            assert!(decode_ursp_rules(&v).is_err(), "rule length {bad} accepted");
        }
    }

    #[test]
    fn mutation_13_trailing_optional_ie_rejected() {
        // The optional IEs 0x42/0x70 of Table D.5.1.1.1 are unsupported; any
        // trailing octets after the LV-E list must be rejected (fail-closed).
        let mut v = VEC_F_MANAGE_UE_POLICY_COMMAND.to_vec();
        v.extend_from_slice(&[0x42, 0x01, 0x00]);
        assert!(ManageUePolicyCommand::decode(&v).is_err());
    }

    #[test]
    fn mutation_14_unknown_td_component_identifier_rejected() {
        let mut v = VEC_A_URSP_RULE_CATCH_ALL.to_vec();
        assert_eq!(v[5], 0x01); // match-all TD component identifier
        v[5] = 0x02; // spare TD identifier (TS 24.526 Table 5.2.1)
        assert!(decode_ursp_rules(&v).is_err());
    }

    // =========================================================================
    // Hand-derived golden vectors for the UE->PCF messages (D.5.2/D.5.3/D.5.4)
    // =========================================================================

    /// MANAGE UE POLICY COMPLETE (TS 24.501 Table D.5.2.1.1): PTI echoing the
    /// command (D.1.2 response rule) + message type 0x02 (Table D.6.1.1).
    const VEC_COMPLETE: &[u8] = &[
        0x81, // PTI = 0x81 (echo of a PCF PTI in 80H-FEH)
        0x02, // MANAGE UE POLICY COMPLETE (Table D.6.1.1)
    ];

    /// MANAGE UE POLICY COMMAND REJECT (Table D.5.3.1.1) with one D.6.3
    /// subresult: PLMN 001/01, one result {UPSC 0x0001, failed instruction
    /// order 1, cause "Protocol error, unspecified"}.
    const VEC_REJECT: &[u8] = &[
        0x80, // PTI (echo)
        0x03, // MANAGE UE POLICY COMMAND REJECT (Table D.6.1.1)
        0x00, 0x09, // LV-E: length of result contents = 9
        0x01, // Number of results = 1 (Figure D.6.3.3, octet d)
        0x00, 0xF1, 0x10, // PLMN 001/01 BCD (octets d+1..d+3; MNC digit 3 = 1111)
        0x00, 0x01, // UPSC = 0x0001 (Figure D.6.3.5, octets f..f+1)
        0x00, 0x01, // Failed instruction order = 1 (1-based, Table D.6.3.1)
        0x6F, // Cause = protocol error, unspecified (0110 1111, Table D.6.3.1)
    ];

    /// UE STATE INDICATION (Table D.5.4.1.1): PTI 0 ("no procedure transaction
    /// identity assigned", D.1.2) + UPSI list with one sublist {PLMN 001/01,
    /// UPSC 0x0001} + 1-octet classmark {SupportANDSP}.
    const VEC_UE_STATE_INDICATION: &[u8] = &[
        0x00, // PTI = no procedure transaction identity assigned
        0x04, // UE STATE INDICATION (Table D.6.1.1)
        0x00, 0x07, // LV-E: length of UPSI list contents = 7
        0x00, 0x05, // Length of UPSI sublist = 5 (PLMN 3 + one UPSC 2, Fig. D.6.4.2)
        0x00, 0xF1, 0x10, // PLMN 001/01 BCD (octets d+2..d+4)
        0x00, 0x01, // UPSC 1 = 0x0001 (octets d+5..d+6)
        0x01, // LV: length of UE policy classmark contents = 1
        0x01, // octet 3: SupportANDSP (bit 1); bits 8..5 spare (Figure D.6.5.1)
    ];

    #[test]
    fn complete_golden_encode_and_decode() {
        let complete = ManageUePolicyComplete { pti: 0x81 };
        assert_eq!(complete.encode().unwrap(), VEC_COMPLETE);
        assert_eq!(
            ManageUePolicyComplete::decode(VEC_COMPLETE).unwrap(),
            complete
        );
    }

    #[test]
    fn reject_golden_encode_and_decode() {
        let reject = ManageUePolicyCommandReject {
            pti: 0x80,
            result: UePolicySectionManagementResult {
                subresults: vec![UePolicySectionManagementSubresult {
                    plmn_id: plmn_001_01(),
                    results: vec![UePolicyResult {
                        upsc: 0x0001,
                        failed_instruction_order: 1,
                        cause: UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                    }],
                }],
            },
        };
        assert_eq!(reject.encode().unwrap(), VEC_REJECT);
        assert_eq!(
            ManageUePolicyCommandReject::decode(VEC_REJECT).unwrap(),
            reject
        );
    }

    #[test]
    fn ue_state_indication_golden_encode_and_decode() {
        let usi = UeStateIndication {
            pti: 0x00,
            upsi_list: UpsiList {
                sublists: vec![UpsiSublist {
                    plmn_id: plmn_001_01(),
                    upscs: vec![0x0001],
                }],
            },
            classmark: UePolicyClassmark {
                andsp_supported: true,
                eps_ursp_supported: false,
                vps_ursp_supported: false,
                rure_supported: false,
            },
            os_ids: vec![],
        };
        assert_eq!(usi.encode().unwrap(), VEC_UE_STATE_INDICATION);
        assert_eq!(
            UeStateIndication::decode(VEC_UE_STATE_INDICATION).unwrap(),
            usi
        );
    }

    #[test]
    fn reject_truncated_result_rejected() {
        let v = &VEC_REJECT[..VEC_REJECT.len() - 1];
        assert!(ManageUePolicyCommandReject::decode(v).is_err());
    }

    #[test]
    fn ue_state_indication_classmark_spare_bits_rejected() {
        let mut v = VEC_UE_STATE_INDICATION.to_vec();
        let last = v.len() - 1;
        v[last] = 0x11; // bits 8..5 of classmark octet 3 must be zero (D.6.5)
        assert!(UeStateIndication::decode(&v).is_err());
    }
} // mod ue_policy_golden
