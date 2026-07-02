// =============================================================================
// Wave-6 E1 — Hand-derived URSP / UPDP golden byte-vectors
// =============================================================================
//
// PROVENANCE
//   Primary spec : 3GPP TS 24.526 V18.5.0 (2023-12), Release 18, clause 5.2
//                  Offline copy: specs/24526-i50.docx + specs/24526-i50.txt
//                  (3gpp.org/etsi.org blocked the fetcher; the docx was fetched
//                  from two INDEPENDENT public rehosts of the official 3GPP
//                  deliverable — HuggingFace datasets GSMA/3GPP-REL18
//                  original/24526-i50.docx and netop/3GPP-R18
//                  Documents/24526-i50.docx — both byte-identical,
//                  sha256 9a55b8782c7c73be8d2f9200a0235f81d7343c9cd69eb3f769afe27aec9e2704,
//                  and its clause 4.2 prose matches the ETSI TS 124 526
//                  V17.8.0 preview PDF from cdn.standards.iteh.ai).
//   Framing spec : 3GPP TS 24.501 V19.6.2 Annex D (offline: specs/24501-j62.txt)
//                  - D.1.2  PTI: PCF-initiated uses 80H-FEH  (24501-j62.txt:95583)
//                  - D.5.1.1.1 MANAGE UE POLICY COMMAND content (:96146-96177):
//                    PTI (M,V,1) + message type (M,V,1, D.6.1) +
//                    UE policy section management list (M, LV-E, 11-65533)
//                  - D.6.1  message type 0x01 = MANAGE UE POLICY COMMAND (:96334)
//                  - D.6.2  list coding, figures D.6.2.1-D.6.2.7
//                    (:96395/:96427/:96460/:96492/:96516/:96548/:96571)
//                    and Table D.6.2.1 (:96573-96712); part type 0001 = URSP
//                    (:96674); 2-digit MNC => MNC digit 3 = 1111 (:96628)
//   DNN/APN      : 3GPP TS 23.003 clause 9.1 (specs/23003-k00.txt:3423-3425):
//                  each label = one octet length + that many 8-bit ASCII octets.
//
// LENGTH-FIELD CONVENTION (the fiddly part — read before recomputing)
//   Every 2-octet length field below counts the octets FOLLOWING the length
//   field up to the end of its own structure (i.e. the length field itself is
//   NOT included, everything after it IS — including any type octet).
//   Spec evidence:
//   - TS 24.501 Table D.6.2.1 NOTE 2 (24501-j62.txt:96710-96711): "The UE
//     policy part contents length indicates the length of the value part of
//     the UE policy part field (i.e. octet q+2 to octet r)" — octet q+2 is the
//     part-type octet immediately after the 2-octet length, octet r is the
//     last contents octet.
//   - The IE minimum of 12 octets (24501-j62.txt:96372-96373) is reproduced
//     exactly by this convention: IEI(1)+L(2)+ minimal sublist
//     [len(2)+PLMN(3)+instr[len(2)+UPSC(2)]] = 12, and the D.5.1.1.1 LV-E
//     bound 11-65533 = the same IE without the IEI octet.
//
// COMPONENT TYPE IDENTIFIERS USED (verbatim rows of the offline txt)
//   Traffic descriptor (TS 24.526 Table 5.2.1):
//     0b0000_0001 Match-all type           (24526-i50.txt:2467; no value field,
//                                           :2500-2502)
//     0b0000_1000 OS Id + OS App Id type   (:2468; value = 16-octet OS Id UUID
//                                           + 1-octet OS App Id length
//                                           + OS App Id, :2504-2506)
//     0b1000_1000 DNN type                 (:2486; value = 1-octet DNN length
//                                           + DNN value (APN), :2593-2594)
//   Route selection descriptor (TS 24.526 Table 5.2.1):
//     0b0000_0001 SSC mode type            (:2691; 1 octet, bits 3..1 per
//                                           TS 24.501 9.11.4.16, :2709-2711)
//     0b0000_0010 S-NSSAI type             (:2692; 1-octet len + value per
//                                           TS 24.501 9.11.2.8, :2713-2715)
//     0b0000_0100 DNN type                 (:2693; 1-octet DNN length + APN,
//                                           :2717-2718)
//     0b0000_1000 PDU session type type    (:2694; 1 octet, bits 3..1 per
//                                           TS 24.501 9.11.4.11, :2720-2722)
//     0b0001_0000 Preferred access type    (:2695; 1 octet, bits 2..1 per
//                                           TS 24.501 9.11.2.1A, :2724-2726)
//   Referenced IE value parts (specs/24501-j62.txt):
//     SSC mode 1        = 0b001  (9.11.4.16 Table, :89815-89824)
//     PDU type IPv4v6   = 0b011  (9.11.4.11 Table, :88046-88060)
//     3GPP access       = 0b01   (9.11.2.1A Table, :71944-71958)
//     non-3GPP access   = 0b10   (9.11.2.1A Table, :71944-71958)
//     S-NSSAI len 1     = SST only (9.11.2.8 Table, :72225-72232)
//
// STRUCTURE TEMPLATES (figures)
//   URSP rule (TS 24.526 Figure 5.2.2, 24526-i50.txt:2349-2378):
//     [len rule u16][precedence u8][len TD u16][TD…][len RSD list u16][RSDs…]
//   RSD (Figure 5.2.4, :2410-2435):
//     [len RSD u16][precedence u8][len RSD contents u16][components…]
//   Section mgmt list LV-E (TS 24.501 D.5.1.1.1 + Figure D.6.2.1):
//     [len contents u16][sublists…]
//   Sublist (Figure D.6.2.3): [len sublist u16][MCC/MNC 3 oct][instructions…]
//   Instruction (Figure D.6.2.5): [instr contents len u16][UPSC u16][parts…]
//   UE policy part (Figure D.6.2.7): [part contents len u16]
//     [0000|part-type u4 (URSP=0001)][part contents…]
//
// CONSUMERS
//   E2 (nextgcore-nas UPDP codec): include! this file from the codec's unit
//     tests — `include!(concat!(env!("CARGO_MANIFEST_DIR"),
//     "/tests/ue_policy_golden_vectors/data.rs"));` — and assert byte-exact
//     encode() output.
//   E8 (nextgsim-ue, separate repo): re-cite the hex literals verbatim in the
//     nextgsim tests (do NOT share code across repos; independence is the
//     strict-peer value).
//
// Deliberately data-only: no codec here (E1 boundary). The sibling test file
// tests/ue_policy_golden_vectors.rs recomputes every length field from
// scratch and cross-checks the embeddings (f) ⊃ (e) ⊃ (a).
// =============================================================================

/// APN-encoded DNN "internet" per TS 23.003 §9.1 (23003-k00.txt:3423-3425):
/// one label, length 8, ASCII "internet".
pub const DNN_INTERNET_APN: &[u8] = &[
    0x08, // label length = 8
    0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // "internet"
];

/// APN-encoded DNN "ims" per TS 23.003 §9.1: one label, length 3, ASCII "ims".
pub const DNN_IMS_APN: &[u8] = &[
    0x03, // label length = 3
    0x69, 0x6D, 0x73, // "ims"
];

/// Vector (a) — catch-all URSP rule (matches nextgcore-pcfd
/// `UrspRule::catch_all()`: precedence 255, match-all TD, one RSD
/// {precedence 255, SSC mode 1, S-NSSAI SST=1, DNN "internet", PDU type
/// IPv4v6}). 31 octets. Encoded per TS 24.526 Figures 5.2.2/5.2.3/5.2.4 and
/// Table 5.2.1 (24526-i50.txt:2349-2733).
pub const VEC_A_URSP_RULE_CATCH_ALL: &[u8] = &[
    // -- URSP rule (Figure 5.2.2) -------------------------------------------
    0x00, 0x1D, // Length of URSP rule = 29 (octets v..v+1; counts v+2..x)
    0xFF, //       Precedence value of URSP rule = 255 (octet v+2, Table 5.2.1)
    0x00, 0x01, // Length of traffic descriptor = 1 (octets v+3..v+4)
    // -- Traffic descriptor (octets v+5..w) ---------------------------------
    0x01, //       Match-all type (Table 5.2.1, 24526-i50.txt:2467; no value
    //             field per :2500-2502)
    // -- Route selection descriptor list ------------------------------------
    0x00, 0x17, // Length of route selection descriptor list = 23 (w+1..w+2)
    // ---- RSD 1 (Figure 5.2.4) ----------------------------------------------
    0x00, 0x15, // Length of route selection descriptor = 21 (octets b..b+1)
    0xFF, //       Precedence value of RSD = 255 (octet b+2)
    0x00, 0x12, // Length of route selection descriptor contents = 18 (b+3..b+4)
    // ------ RSD contents (octets b+5..c) ------------------------------------
    0x01, 0x01, // SSC mode type (id :2691) + SSC mode 1 (24501 9.11.4.16: 0b001)
    0x02, 0x01, 0x01, // S-NSSAI type (id :2692) + len 1 + SST=1
    //             (24501 9.11.2.8: len 1 => SST only)
    0x04, 0x09, // DNN type (id :2693) + DNN length 9
    0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // APN "internet"
    0x08, 0x03, // PDU session type type (id :2694) + IPv4v6
    //             (24501 9.11.4.11: 0b011)
];

/// Vector (b) — DNN "ims" rule (matches nextgcore-pcfd `UrspRule::ims_rule()`:
/// precedence 10, TD = DNN(ims), one RSD {precedence 10, SSC mode 1, S-NSSAI
/// SST=1, DNN "ims", PDU type IPv4v6, preferred access 3GPP}). 33 octets.
pub const VEC_B_URSP_RULE_DNN_IMS: &[u8] = &[
    0x00, 0x1F, // Length of URSP rule = 31
    0x0A, //       Precedence value of URSP rule = 10
    0x00, 0x06, // Length of traffic descriptor = 6
    // -- Traffic descriptor --------------------------------------------------
    0x88, //       DNN type (Table 5.2.1, 24526-i50.txt:2486)
    0x04, //       DNN length = 4 (:2593-2594)
    0x03, 0x69, 0x6D, 0x73, // APN "ims" (TS 23.003 §9.1)
    // -- Route selection descriptor list -------------------------------------
    0x00, 0x14, // Length of route selection descriptor list = 20
    // ---- RSD 1 --------------------------------------------------------------
    0x00, 0x12, // Length of route selection descriptor = 18
    0x0A, //       Precedence value of RSD = 10
    0x00, 0x0F, // Length of route selection descriptor contents = 15
    0x01, 0x01, // SSC mode 1
    0x02, 0x01, 0x01, // S-NSSAI: len 1, SST = 1
    0x04, 0x04, 0x03, 0x69, 0x6D, 0x73, // DNN: len 4, APN "ims"
    0x08, 0x03, // PDU session type IPv4v6
    0x10, 0x01, // Preferred access type type (id 24526-i50.txt:2695)
    //             + 3GPP access (24501 9.11.2.1A: 0b01)
];

/// Vector (c) — OS Id + OS App Id TD rule. Precedence 100; TD = OS Id (UUID
/// 00112233-4455-6677-8899-AABBCCDDEEFF, an arbitrary documented test UUID)
/// plus OS App Id "app1"; RSD identical in contents to vector (a)'s RSD but
/// with precedence 1. 52 octets. Value encoding per 24526-i50.txt:2504-2506
/// (16-octet OS Id, then 1-octet OS App Id length, then OS App Id).
pub const VEC_C_URSP_RULE_OS_APP_ID: &[u8] = &[
    0x00, 0x32, // Length of URSP rule = 50
    0x64, //       Precedence value of URSP rule = 100
    0x00, 0x16, // Length of traffic descriptor = 22
    // -- Traffic descriptor --------------------------------------------------
    0x08, //       OS Id + OS App Id type (Table 5.2.1, 24526-i50.txt:2468)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // OS Id UUID (RFC 4122),
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, //   16 octets
    0x04, //       OS App Id length = 4
    0x61, 0x70, 0x70, 0x31, // OS App Id "app1"
    // -- Route selection descriptor list -------------------------------------
    0x00, 0x17, // Length of route selection descriptor list = 23
    0x00, 0x15, // Length of route selection descriptor = 21
    0x01, //       Precedence value of RSD = 1
    0x00, 0x12, // Length of route selection descriptor contents = 18
    0x01, 0x01, // SSC mode 1
    0x02, 0x01, 0x01, // S-NSSAI: len 1, SST = 1
    0x04, 0x09, // DNN: len 9
    0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // APN "internet"
    0x08, 0x03, // PDU session type IPv4v6
];

/// Vector (d) — one rule, TWO RSDs with distinct precedences (10 then 20;
/// TS 24.526 Table 5.2.1: higher precedence value = lower priority,
/// 24526-i50.txt:2674-2678). Rule precedence 50, TD = DNN "internet".
/// RSD1 {prec 10: SSC 1, S-NSSAI SST=1, IPv4v6, preferred access 3GPP};
/// RSD2 {prec 20: SSC 1, IPv4v6, preferred access non-3GPP}. 43 octets.
pub const VEC_D_URSP_RULE_TWO_RSDS: &[u8] = &[
    0x00, 0x29, // Length of URSP rule = 41
    0x32, //       Precedence value of URSP rule = 50
    0x00, 0x0B, // Length of traffic descriptor = 11
    // -- Traffic descriptor --------------------------------------------------
    0x88, //       DNN type (24526-i50.txt:2486)
    0x09, //       DNN length = 9
    0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // APN "internet"
    // -- Route selection descriptor list -------------------------------------
    0x00, 0x19, // Length of route selection descriptor list = 25
    // ---- RSD 1 (higher priority: precedence 10) -----------------------------
    0x00, 0x0C, // Length of route selection descriptor = 12
    0x0A, //       Precedence value of RSD = 10
    0x00, 0x09, // Length of route selection descriptor contents = 9
    0x01, 0x01, // SSC mode 1
    0x02, 0x01, 0x01, // S-NSSAI: len 1, SST = 1
    0x08, 0x03, // PDU session type IPv4v6
    0x10, 0x01, // Preferred access type: 3GPP access (0b01)
    // ---- RSD 2 (lower priority: precedence 20) ------------------------------
    0x00, 0x09, // Length of route selection descriptor = 9
    0x14, //       Precedence value of RSD = 20
    0x00, 0x06, // Length of route selection descriptor contents = 6
    0x01, 0x01, // SSC mode 1
    0x08, 0x03, // PDU session type IPv4v6
    0x10, 0x02, // Preferred access type: non-3GPP access (0b10)
];

/// Vector (e) — UE policy section management list in the LV-E form used inside
/// MANAGE UE POLICY COMMAND (TS 24.501 Table D.5.1.1.1: format LV-E, i.e. NO
/// IEI octet — 2-octet length + contents; figures D.6.2.1-D.6.2.7).
/// One PLMN sublist (MCC=001, MNC=01), one instruction (UPSC=0x0001), one UE
/// policy part of type URSP whose contents are exactly
/// `VEC_A_URSP_RULE_CATCH_ALL`. 45 octets.
pub const VEC_E_SECTION_MGMT_LIST_LVE: &[u8] = &[
    // -- LV-E (Figure D.6.2.1 without the IEI octet) --------------------------
    0x00, 0x2B, // Length of UE policy section management list contents = 43
    // -- Sublist (Figure D.6.2.3) ---------------------------------------------
    0x00, 0x29, // Length of UE policy section management sublist = 41
    //             (counts MCC/MNC + sublist contents; convention per
    //             Table D.6.2.1 NOTE 2, 24501-j62.txt:96710-96711)
    0x00, //       octet d+2: MCC digit 2 (0) <<4 | MCC digit 1 (0)
    0xF1, //       octet d+3: MNC digit 3 (0b1111, 2-digit MNC per Table
    //             D.6.2.1, 24501-j62.txt:96628) <<4 | MCC digit 3 (1)
    0x10, //       octet d+4: MNC digit 2 (1) <<4 | MNC digit 1 (0)
    // -- Instruction (Figure D.6.2.5) -----------------------------------------
    0x00, 0x24, // Instruction contents length = 36 (counts UPSC + parts)
    0x00, 0x01, // UPSC = 0x0001 (set by the PCF, Table D.6.2.1)
    // -- UE policy part (Figure D.6.2.7) --------------------------------------
    0x00, 0x20, // UE policy part contents length = 32 (octet q+2..r, i.e.
    //             INCLUDES the part-type octet — NOTE 2)
    0x01, //       bits 8..5 spare (0), bits 4..1 UE policy part type = 0001
    //             URSP (Table D.6.2.1, 24501-j62.txt:96674)
    // -- UE policy part contents = one URSP rule (TS 24.526 Figure 5.2.1) -----
    0x00, 0x1D, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x17, // == VEC_A bytes 0..8
    0x00, 0x15, 0xFF, 0x00, 0x12, // == VEC_A bytes 8..13
    0x01, 0x01, // SSC mode 1
    0x02, 0x01, 0x01, // S-NSSAI SST=1
    0x04, 0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // DNN
    0x08, 0x03, // PDU session type IPv4v6
];

/// Vector (f) — complete MANAGE UE POLICY COMMAND (TS 24.501 Table D.5.1.1.1,
/// 24501-j62.txt:96146-96177): PTI + message type + LV-E list from vector (e).
/// This is the full UE policy delivery service message carried as the Payload
/// container contents (container type "UE policy container" 0x05) of a DL NAS
/// TRANSPORT; total content 47 octets <= 65535 (NOTE at :96176-96177).
pub const VEC_F_MANAGE_UE_POLICY_COMMAND: &[u8] = &[
    0x80, // PTI = 0x80 — first PCF-allocated value; PCF-initiated procedures
    //       use 80H-FEH (TS 24.501 D.1.2, 24501-j62.txt:95583)
    0x01, // UE policy delivery service message type = MANAGE UE POLICY COMMAND
    //       (TS 24.501 Table D.6.1.1, 24501-j62.txt:96334)
    // -- UE policy section management list (LV-E) == VEC_E --------------------
    0x00, 0x2B, // Length of UE policy section management list contents = 43
    0x00, 0x29, 0x00, 0xF1, 0x10, // sublist header: len 41, PLMN 001/01
    0x00, 0x24, 0x00, 0x01, // instruction: contents len 36, UPSC 0x0001
    0x00, 0x20, 0x01, // part: contents len 32, type URSP (0001)
    0x00, 0x1D, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x17, // URSP rule == VEC_A
    0x00, 0x15, 0xFF, 0x00, 0x12, //
    0x01, 0x01, //
    0x02, 0x01, 0x01, //
    0x04, 0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, //
    0x08, 0x03, //
];
