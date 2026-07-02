//! Wave-6 E1 — structural self-checks for the hand-derived URSP/UPDP golden
//! byte-vectors in `tests/ue_policy_golden_vectors/data.rs`.
//!
//! These tests are NOT a codec (E1 boundary: no codec code). They are an
//! independent, from-scratch recomputation of every nested length field and
//! structural invariant, written directly from the octet tables of
//! TS 24.526 V18.5.0 §5.2 (specs/24526-i50.txt:2308-2836) and
//! TS 24.501 Annex D.5.1.1.1/D.6.1/D.6.2 (specs/24501-j62.txt:96131-96712),
//! so a transcription error in the vectors and an error in this walker would
//! have to coincide to go unnoticed. The E2 encoder must additionally match
//! these bytes exactly (byte-exact golden test, not roundtrip-only).

include!("ue_policy_golden_vectors/data.rs");

/// Big-endian u16 read (all multi-octet length fields in TS 24.526 §5.2 and
/// TS 24.501 D.6.2 are 2-octet binary-encoded lengths).
fn be16(b: &[u8], i: usize) -> usize {
    (usize::from(b[i]) << 8) | usize::from(b[i + 1])
}

/// Walks one traffic descriptor and returns the component type identifiers
/// found. Component sizes are recomputed from the TS 24.526 Table 5.2.1 value
/// encodings (match-all: no value; OS Id + OS App Id: 16 + 1 + n; DNN: 1 + n).
fn walk_traffic_descriptor(td: &[u8]) -> Vec<u8> {
    let mut ids = Vec::new();
    let mut i = 0;
    while i < td.len() {
        let id = td[i];
        ids.push(id);
        i += 1;
        match id {
            // Match-all type (24526-i50.txt:2467): no value field (:2500-2502)
            0x01 => {}
            // OS Id + OS App Id type (:2468): 16-octet OS Id + 1-octet OS App
            // Id length + OS App Id (:2504-2506)
            0x08 => {
                let app_id_len = usize::from(td[i + 16]);
                i += 16 + 1 + app_id_len;
            }
            // DNN type (:2486): 1-octet DNN length + DNN value (:2593-2594)
            0x88 => {
                let dnn_len = usize::from(td[i]);
                i += 1 + dnn_len;
            }
            other => panic!("unexpected TD component type identifier {other:#04x}"),
        }
    }
    assert_eq!(i, td.len(), "traffic descriptor over/under-ran its length");
    ids
}

/// Walks one route selection descriptor contents field and returns the
/// component type identifiers found. Sizes per TS 24.526 Table 5.2.1
/// (24526-i50.txt:2709-2726).
fn walk_rsd_contents(c: &[u8]) -> Vec<u8> {
    let mut ids = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let id = c[i];
        ids.push(id);
        i += 1;
        match id {
            // SSC mode type: 1-octet value, bits 8..4 spare (:2709-2711)
            0x01 => {
                assert_eq!(c[i] & 0xF8, 0, "SSC mode spare bits set");
                i += 1;
            }
            // S-NSSAI type: 1-octet length + value (:2713-2715)
            0x02 => {
                let l = usize::from(c[i]);
                i += 1 + l;
            }
            // DNN type: 1-octet DNN length + APN (:2717-2718)
            0x04 => {
                let l = usize::from(c[i]);
                i += 1 + l;
            }
            // PDU session type type: 1-octet value, bits 8..4 spare (:2720-2722)
            0x08 => {
                assert_eq!(c[i] & 0xF8, 0, "PDU session type spare bits set");
                i += 1;
            }
            // Preferred access type type: 1-octet value, bits 8..3 spare
            // (:2724-2726)
            0x10 => {
                assert_eq!(c[i] & 0xFC, 0, "preferred access type spare bits set");
                i += 1;
            }
            other => panic!("unexpected RSD component type identifier {other:#04x}"),
        }
    }
    assert_eq!(i, c.len(), "RSD contents over/under-ran its length");
    ids
}

struct RuleSummary {
    precedence: u8,
    td_ids: Vec<u8>,
    /// (rsd precedence, component ids) per route selection descriptor
    rsds: Vec<(u8, Vec<u8>)>,
}

/// From-scratch structural walk of one URSP rule per TS 24.526 Figure 5.2.2 /
/// 5.2.3 / 5.2.4. Every length field is recomputed and asserted against the
/// actual span it must cover (length counts the octets following the field —
/// convention per TS 24.501 Table D.6.2.1 NOTE 2, 24501-j62.txt:96710-96711).
fn walk_ursp_rule(rule: &[u8]) -> RuleSummary {
    // Figure 5.2.2: [len u16][precedence][len TD u16][TD][len RSD list u16][RSDs]
    let rule_len = be16(rule, 0);
    assert_eq!(
        rule_len,
        rule.len() - 2,
        "Length of URSP rule must cover octets v+2..end"
    );
    let precedence = rule[2];
    let td_len = be16(rule, 3);
    let td = &rule[5..5 + td_len];
    let td_ids = walk_traffic_descriptor(td);
    assert!(!td_ids.is_empty(), "TD must hold at least one component");

    let rsdl_off = 5 + td_len;
    let rsdl_len = be16(rule, rsdl_off);
    let rsd_list = &rule[rsdl_off + 2..];
    assert_eq!(
        rsdl_len,
        rsd_list.len(),
        "Length of RSD list must cover exactly the remaining rule octets"
    );

    // Figure 5.2.4 per descriptor.
    let mut rsds = Vec::new();
    let mut i = 0;
    while i < rsd_list.len() {
        let rsd_len = be16(rsd_list, i);
        let rsd_prec = rsd_list[i + 2];
        let contents_len = be16(rsd_list, i + 3);
        assert_eq!(
            rsd_len,
            1 + 2 + contents_len,
            "Length of RSD must cover precedence + contents-length + contents"
        );
        let contents = &rsd_list[i + 5..i + 5 + contents_len];
        let ids = walk_rsd_contents(contents);
        assert!(!ids.is_empty(), "RSD must hold at least one component");
        rsds.push((rsd_prec, ids));
        i += 2 + rsd_len;
    }
    assert_eq!(i, rsd_list.len(), "RSD list over/under-ran its length");
    assert!(!rsds.is_empty(), "rule must hold at least one RSD");

    RuleSummary {
        precedence,
        td_ids,
        rsds,
    }
}

#[test]
fn vector_total_lengths_are_as_documented() {
    assert_eq!(VEC_A_URSP_RULE_CATCH_ALL.len(), 31);
    assert_eq!(VEC_B_URSP_RULE_DNN_IMS.len(), 33);
    assert_eq!(VEC_C_URSP_RULE_OS_APP_ID.len(), 52);
    assert_eq!(VEC_D_URSP_RULE_TWO_RSDS.len(), 43);
    assert_eq!(VEC_E_SECTION_MGMT_LIST_LVE.len(), 45);
    assert_eq!(VEC_F_MANAGE_UE_POLICY_COMMAND.len(), 47);
}

#[test]
fn vec_a_catch_all_rule_recomputes() {
    let s = walk_ursp_rule(VEC_A_URSP_RULE_CATCH_ALL);
    assert_eq!(s.precedence, 255);
    // Match-all TD must be the only component (24526-i50.txt:2500-2502).
    assert_eq!(s.td_ids, vec![0x01]);
    assert_eq!(s.rsds.len(), 1);
    let (rsd_prec, ids) = &s.rsds[0];
    assert_eq!(*rsd_prec, 255);
    // SSC mode, S-NSSAI, DNN, PDU session type.
    assert_eq!(ids, &[0x01, 0x02, 0x04, 0x08]);
    // DNN value inside the RSD is the APN-encoded "internet".
    let snssai_id_idx = 15; // 13 octets of rule/RSD headers + SSC component (2)
    assert_eq!(VEC_A_URSP_RULE_CATCH_ALL[snssai_id_idx], 0x02); // S-NSSAI id
    let tail = &VEC_A_URSP_RULE_CATCH_ALL[18..]; // after S-NSSAI (3 octets)
    assert_eq!(tail[0], 0x04); // DNN id
    assert_eq!(usize::from(tail[1]), DNN_INTERNET_APN.len());
    assert_eq!(&tail[2..2 + DNN_INTERNET_APN.len()], DNN_INTERNET_APN);
}

#[test]
fn vec_b_ims_rule_recomputes() {
    let s = walk_ursp_rule(VEC_B_URSP_RULE_DNN_IMS);
    assert_eq!(s.precedence, 10);
    assert_eq!(s.td_ids, vec![0x88]); // DNN traffic descriptor
    assert_eq!(s.rsds.len(), 1);
    let (rsd_prec, ids) = &s.rsds[0];
    assert_eq!(*rsd_prec, 10);
    assert_eq!(ids, &[0x01, 0x02, 0x04, 0x08, 0x10]);
    // TD carries the APN-encoded "ims".
    let td = &VEC_B_URSP_RULE_DNN_IMS[5..11];
    assert_eq!(td[0], 0x88);
    assert_eq!(usize::from(td[1]), DNN_IMS_APN.len());
    assert_eq!(&td[2..], DNN_IMS_APN);
    // Preferred access type value = 3GPP access (0b01,
    // 24501-j62.txt:71944-71958) is the final octet.
    assert_eq!(VEC_B_URSP_RULE_DNN_IMS[32], 0x01);
}

#[test]
fn vec_c_os_app_id_rule_recomputes() {
    let s = walk_ursp_rule(VEC_C_URSP_RULE_OS_APP_ID);
    assert_eq!(s.precedence, 100);
    assert_eq!(s.td_ids, vec![0x08]); // OS Id + OS App Id
    // TD value: 16-octet OS Id + 1-octet App Id length + "app1"
    // (24526-i50.txt:2504-2506).
    let td_len = be16(VEC_C_URSP_RULE_OS_APP_ID, 3);
    assert_eq!(td_len, 1 + 16 + 1 + 4);
    let td = &VEC_C_URSP_RULE_OS_APP_ID[5..5 + td_len];
    assert_eq!(usize::from(td[17]), 4); // OS App Id length
    assert_eq!(&td[18..22], b"app1");
    assert_eq!(s.rsds.len(), 1);
    assert_eq!(s.rsds[0].0, 1);
}

#[test]
fn vec_d_two_rsds_recompute_with_strict_precedence_order() {
    let s = walk_ursp_rule(VEC_D_URSP_RULE_TWO_RSDS);
    assert_eq!(s.precedence, 50);
    assert_eq!(s.td_ids, vec![0x88]);
    assert_eq!(s.rsds.len(), 2);
    // Distinct, ascending precedence values: RSD 1 (10) is evaluated before
    // RSD 2 (20) — higher value = lower precedence (24526-i50.txt:2674-2678).
    assert_eq!(s.rsds[0].0, 10);
    assert_eq!(s.rsds[1].0, 20);
    assert!(s.rsds[0].0 < s.rsds[1].0);
    assert_eq!(s.rsds[0].1, vec![0x01, 0x02, 0x08, 0x10]);
    assert_eq!(s.rsds[1].1, vec![0x01, 0x08, 0x10]);
    // RSD1 prefers 3GPP access (0b01), RSD2 non-3GPP access (0b10)
    // (24501-j62.txt:71944-71958).
    assert_eq!(VEC_D_URSP_RULE_TWO_RSDS[31], 0x01);
    assert_eq!(VEC_D_URSP_RULE_TWO_RSDS[42], 0x02);
}

#[test]
fn vec_e_section_list_recomputes_and_embeds_vec_a() {
    let v = VEC_E_SECTION_MGMT_LIST_LVE;
    // LV-E: 2-octet length + contents (TS 24.501 Table D.5.1.1.1, format LV-E;
    // bound 11-65533 at 24501-j62.txt:96161).
    let contents_len = be16(v, 0);
    assert_eq!(contents_len, v.len() - 2);
    assert!((11..=65533).contains(&(v.len())), "LV-E bound violated");

    // Sublist (Figure D.6.2.3): length counts MCC/MNC + sublist contents.
    let sublist_len = be16(v, 2);
    assert_eq!(sublist_len, v.len() - 4, "sublist must span the remainder");

    // PLMN MCC=001 MNC=01 (2-digit MNC => digit 3 = 0b1111):
    // d+2 = MCCd2<<4|MCCd1, d+3 = MNCd3<<4|MCCd3, d+4 = MNCd2<<4|MNCd1.
    assert_eq!(&v[4..7], &[0x00, 0xF1, 0x10]);

    // Instruction (Figure D.6.2.5): contents length counts UPSC + parts.
    let instr_len = be16(v, 7);
    assert_eq!(instr_len, v.len() - 9);
    let upsc = be16(v, 9);
    assert_eq!(upsc, 0x0001);

    // UE policy part (Figure D.6.2.7): contents length counts octet q+2..r,
    // i.e. INCLUDES the part-type octet (NOTE 2, 24501-j62.txt:96710-96711).
    let part_len = be16(v, 11);
    assert_eq!(part_len, v.len() - 13);
    let part_type_octet = v[13];
    assert_eq!(part_type_octet & 0xF0, 0, "bits 8..5 of octet q+2 are spare");
    assert_eq!(part_type_octet & 0x0F, 0x01, "part type must be URSP (0001)");

    // Part contents == exactly the catch-all rule vector (a).
    assert_eq!(&v[14..], VEC_A_URSP_RULE_CATCH_ALL);
    // And that embedded rule independently re-walks.
    let s = walk_ursp_rule(&v[14..]);
    assert_eq!(s.precedence, 255);
}

#[test]
fn vec_f_manage_ue_policy_command_recomputes_and_embeds_vec_e() {
    let v = VEC_F_MANAGE_UE_POLICY_COMMAND;
    // PTI: PCF-initiated procedures use 80H-FEH (TS 24.501 D.1.2,
    // 24501-j62.txt:95583).
    assert!((0x80..=0xFE).contains(&v[0]), "PTI outside PCF range");
    assert_eq!(v[0], 0x80);
    // Message type 0x01 = MANAGE UE POLICY COMMAND (Table D.6.1.1,
    // 24501-j62.txt:96334).
    assert_eq!(v[1], 0x01);
    // Remainder is the LV-E section management list — byte-identical to (e).
    assert_eq!(&v[2..], VEC_E_SECTION_MGMT_LIST_LVE);
    // Total message content within the 65535-octet payload container cap
    // (NOTE at 24501-j62.txt:96176-96177).
    assert!(v.len() <= 65535);
}

#[test]
fn dnn_values_are_apn_label_encoded() {
    // TS 23.003 §9.1 (23003-k00.txt:3423-3425): label = 1-octet length +
    // ASCII octets; APN is NOT zero-terminated.
    assert_eq!(DNN_INTERNET_APN[0], 8);
    assert_eq!(&DNN_INTERNET_APN[1..], b"internet");
    assert_eq!(DNN_INTERNET_APN.len(), 9);
    assert_eq!(DNN_IMS_APN[0], 3);
    assert_eq!(&DNN_IMS_APN[1..], b"ims");
    assert_eq!(DNN_IMS_APN.len(), 4);
}
