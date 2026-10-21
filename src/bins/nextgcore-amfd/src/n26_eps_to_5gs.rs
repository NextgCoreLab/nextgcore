//! N26 **EPS→5GS** handover, the AMF as **target** (#418): wire codec and security mapping.
//!
//! TS 23.502 §4.11.1.2.2 ("EPS to 5GS handover using N26 interface"). The source MME sends
//! this AMF a **Forward Relocation Request** (TS 29.274 §7.3.1, type 133); the AMF converts
//! the EPS MM Context into a 5GS one, has each PDN connection's SMF+PGW-C create an SM
//! context (step 4), asks the target gNB to admit the UE (step 9), and answers the MME with a
//! **Forward Relocation Response** (§7.3.2, type 134, step 14). Once the gNB reports the UE
//! arrived, the AMF sends a **Forward Relocation Complete Notification** (§7.3.3, type 135).
//!
//! ```text
//! MME --Forward Relocation Request (133)--> AMF
//!                                           AMF --Nnrf_NFDiscovery (pgw=FQDN)--> NRF
//!                                           AMF --Nsmf_PDUSession_CreateSMContext--> SMF+PGW-C
//!                                           AMF --HandoverRequest--> target gNB
//!                                           AMF <--HandoverRequestAcknowledge-- target gNB
//!                                           AMF --Nsmf_PDUSession_UpdateSMContext--> SMF
//! MME <--Forward Relocation Response (134)- AMF
//!                                           AMF <--HandoverNotify-- target gNB
//! MME <--Fwd Reloc Complete Notification (135)- AMF
//! MME --Fwd Reloc Complete Acknowledge (136)--> AMF
//! ```
//!
//! This module is **pure**, the same split [`crate::n26_build`] makes for the opposite
//! direction: messages in, data out, data in, messages out, keys in, keys out. No socket and
//! no globals, so every wire and key assertion in its tests is a value comparison.
//!
//! # Why a module of its own and not more of `n26_build`
//!
//! `n26_build` is the AMF as **source** (5GS→EPS). Every message here has the opposite
//! sender and a different IE table: the Forward Relocation Request this module *parses* is
//! the one `n26_build` *builds*, but read against Table 7.3.1-1's EPS→5GS rows (an MME's MM
//! Context with quadruplets, DRX and UE-AMBR fields; a gNB Target Identification; container
//! type 3) rather than the AMF's own output. One module per direction keeps "which side of
//! the table am I implementing" answerable from the file name.

use bytes::{BufMut, Bytes, BytesMut};
use nextgcore_gtp::v2::{
    Gtp2BearerContextIe, Gtp2CauseIe, Gtp2EbiIe, Gtp2FTeidIe, Gtp2Header, Gtp2Ie, Gtp2IeType,
    Gtp2IndicationIe, Gtp2Message, Gtp2MessageType, Gtp2PdnConnectionIe,
};

/// GTPv2-C cause `Request accepted` (TS 29.274 Table 8.4-1).
pub const CAUSE_REQUEST_ACCEPTED: u8 = 16;
/// GTPv2-C cause `Mandatory IE incorrect` (Table 8.4-1, value 69).
pub const CAUSE_MANDATORY_IE_INCORRECT: u8 = 69;
/// GTPv2-C cause `Mandatory IE missing` (Table 8.4-1, value 70).
pub const CAUSE_MANDATORY_IE_MISSING: u8 = 70;
/// GTPv2-C cause `System failure` (Table 8.4-1, value 72).
pub const CAUSE_SYSTEM_FAILURE: u8 = 72;
/// GTPv2-C cause `Relocation failure` (Table 8.4-1, value 81) — §7.3.2's message-specific
/// cause for a Forward Relocation Response that refuses.
pub const CAUSE_RELOCATION_FAILURE: u8 = 81;
/// GTPv2-C cause `Conditional IE missing` (Table 8.4-1, value 103).
pub const CAUSE_CONDITIONAL_IE_MISSING: u8 = 103;

/// F-TEID interface type `N26 AMF GTP-C` (TS 29.274 Table 8.22-1).
pub const N26_AMF_GTP_C: u8 = 40;

/// F-Container `Container Type` for an E-UTRAN / NG-RAN transparent container.
///
/// Table 7.3.1-1's E-UTRAN Transparent Container row (`29274-j60.txt:17995-18008`): *"5GS to
/// EPS handover and EPS to 5GS handover. The Container Type shall be set to 3."* Table
/// 7.3.2-1 says the same for the Target-to-Source container in the response.
pub const F_CONTAINER_TYPE_EUTRAN: u8 = 3;

/// `Target Type` = `gNodeB ID` (TS 29.274 Table 8.51-1): *"for an EPS to 5GS handover to a
/// target gNodeB"* (§8.51.7).
pub const TARGET_TYPE_GNODEB: u8 = 5;

/// `Security Mode` = `EPS Security Context and Quadruplets` (TS 29.274 Table 8.38-2).
pub const SECURITY_MODE_EPS: u8 = 4;

/// Length of the value part of the S1 mode to N1 mode NAS transparent container
/// (TS 24.501 §9.11.2.9: "a type 4 information element with a length of 10 octets", i.e. IEI
/// + length + 8 octets of value).
pub const S1_TO_N1_CONTAINER_VALUE_LEN: usize = 8;

/// The NAS COUNT the NAS MAC of the S1 mode to N1 mode container is computed with.
///
/// TS 33.501 §8.4.2 step 3 (`33501-k20.txt:11545-11547`): *"The target AMF shall calculate the
/// NAS MAC as described in clause 6.9.2.3.3. with the COUNT parameter set to the maximal value
/// of 2³²-1."* It does not set the NAS COUNT; it only feeds the MAC.
pub const NASC_MAC_COUNT: u32 = u32::MAX;

/// The uplink NAS COUNT the temporary K_gNB is derived with (TS 33.501 §8.4.2 step 3 and
/// NOTE 3, `33501-k20.txt:11532-11541`): *"The uplink NAS COUNT value for the initial K_(gNB)
/// derivation is set to 2³²-1 ... to avoid any possibility that the value may be used to
/// derive the same K_(gNB) again."*
pub const TEMP_KGNB_UL_COUNT: u32 = u32::MAX;

/// The default UE 5G security capabilities the target AMF assumes when the MME sent none.
///
/// TS 33.501 §8.4.2 step 3 (`33501-k20.txt:11507-11518`): *"If the target AMF does not
/// receive the UE 5G security capabilities from the source MME, then the target AMF shall
/// assume that the following default set of 5G security algorithms are supported by the UE
/// ... a. NEA0, 128-NEA1 and 128-NEA2 ... b. 128-NIA1 and 128-NIA2"*.
///
/// Held in the TS 24.501 §9.11.3.54 octet layout every `UeSecurityCapability` in this daemon
/// uses: bit 8 is the null algorithm, bit 7 the first real one. So NEA0|NEA1|NEA2 is
/// `0x80 | 0x40 | 0x20` and NIA1|NIA2 is `0x40 | 0x20` — note **no NIA0**, which the clause
/// leaves out of the integrity set on purpose.
pub const DEFAULT_5G_EA_OCTET: u8 = 0xE0;
/// See [`DEFAULT_5G_EA_OCTET`].
pub const DEFAULT_5G_IA_OCTET: u8 = 0x60;

// ============================================================================
// The EPS security context (TS 29.274 §8.38, Figure 8.38-5)
// ============================================================================

/// An MME's **EPS Security Context and Quadruplets** MM Context, as far as the target AMF
/// needs it.
///
/// Parsed by [`parse_eps_security_context`] rather than by the library's
/// `Gtp2MmContextIe::decode`, and the reason is the layout, not taste. That decoder is the
/// one #347 and #408 wrote for MM Contexts **this AMF produces**: it assumes no quadruplets,
/// no DRX parameter and no UE-AMBR fields, because the AMF never sends them. An MME may send
/// all three — §8.38 has the old MME include the subscribed UE-AMBR whenever it holds one
/// (`SAMBRI`, `29274-j60.txt:27741-27746`) — and reading such a context with the AMF-shaped
/// decoder would take the UE-AMBR octets as the UE Network Capability length. So the inbound
/// direction reads Figure 8.38-5 in full, field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpsSecurityContext {
    /// `KSI_ASME` (octet 5, bits 3..1): the eKSI of the EPS context, which becomes the value
    /// field of the mapped ngKSI (TS 33.501 §8.6.2).
    pub ksi_asme: u8,
    /// `Used NAS integrity protection algorithm` (octet 7, bits 7..5): the EPS algorithm,
    /// stored in the mapped context per §8.4.2 step 3.
    pub used_nas_integrity_algorithm: u8,
    /// `Used NAS Cipher` (octet 7, bits 4..1).
    pub used_nas_cipher: u8,
    /// `NAS Downlink Count` (octets 8-10).
    pub nas_downlink_count: u32,
    /// `NAS Uplink Count` (octets 11-13).
    pub nas_uplink_count: u32,
    /// `K_ASME` (octets 14-45).
    pub kasme: [u8; 32],
    /// `NH` (octets p..p+31), present iff `NHI` (octet 5 bit 5) is set.
    ///
    /// **Required** for this procedure: TS 33.501 §8.4.2 step 2 has the source MME include
    /// the {NH, NCC} pair, and step 3 derives K_AMF' from it (Annex A.15.2). A context without
    /// it cannot be mapped, which [`map_eps_security_context`] refuses rather than guesses.
    pub nh: Option<[u8; 32]>,
    /// `NCC` (octet p+32, bits 3..1), meaningful only with [`Self::nh`].
    pub ncc: u8,
    /// `Uplink/Downlink Subscribed UE AMBR` in kbps, present iff `SAMBRI` (octet 7 bit 8).
    pub subscribed_ue_ambr_kbps: Option<(u32, u32)>,
    /// `Uplink/Downlink Used UE AMBR` in kbps, present iff `UAMBRI` (octet 6 bit 2).
    pub used_ue_ambr_kbps: Option<(u32, u32)>,
    /// `UE Network Capability` contents (TS 24.301 §9.9.3.34): octet 1 is the EEA bitmap,
    /// octet 2 the EIA bitmap.
    pub ue_network_capability: Vec<u8>,
    /// `Mobile Equipment Identity` contents (TS 29.274 §8.10 TBCD).
    pub mei: Vec<u8>,
}

/// Parse an MME's MM Context (type 107) contents per **Figure 8.38-5**.
///
/// | octets | field | gate |
/// |---|---|---|
/// | 5 | Security Mode \| NHI \| DRXI \| KSI_ASME | — |
/// | 6 | Number of Quintuplets \| Number of Quadruplets \| UAMBRI \| OSCI | — |
/// | 7 | SAMBRI \| Used NAS integrity \| Used NAS Cipher | — |
/// | 8-10, 11-13 | NAS Downlink / Uplink Count | — |
/// | 14-45 | K_ASME | — |
/// | 46..g | Authentication Quadruplets | count in octet 6 |
/// | g+1..h | Authentication Quintuplets | count in octet 6 |
/// | h+1..h+2 | DRX parameter | DRXI |
/// | p..p+32 | NH, then Spare \| NCC | NHI |
/// | j..j+7 | Subscribed UE AMBR (UL, DL) | SAMBRI |
/// | i..i+7 | Used UE AMBR (UL, DL) | UAMBRI |
/// | q.. | UE Network Capability (LV), MS Network Capability (LV), MEI (LV) | — |
///
/// Reading stops after the MEI: the fields beyond it (access restriction, the old security
/// context, voice domain preference, ...) are not used by an EPS→5GS handover, and §8.38's
/// own rule that a receiver ignores what it does not need is what lets it stop there. A
/// truncated optional tail reads as absent; a truncated **fixed** part, or a quadruplet or
/// gated field that runs past the end, is an error — those octets decide where everything
/// after them sits, so reading on would put the next field on the wrong bytes.
pub fn parse_eps_security_context(value: &[u8]) -> Result<EpsSecurityContext, String> {
    const FIXED: usize = 41; // octets 5..=45
    if value.len() < FIXED {
        return Err(format!(
            "MM Context is {} octets, shorter than Figure 8.38-5's fixed part (41 octets, \
             octets 5-45)",
            value.len()
        ));
    }
    let octet5 = value[0];
    let security_mode = octet5 >> 5;
    if security_mode != SECURITY_MODE_EPS {
        return Err(format!(
            "MM Context Security Mode is {security_mode}, not {SECURITY_MODE_EPS} ('EPS \
             Security Context and Quadruplets', Table 8.38-2): only an EPS security context can \
             be mapped to a 5G one (TS 33.501 §8.6.2)"
        ));
    }
    let nhi = octet5 & 0x10 != 0;
    let drxi = octet5 & 0x08 != 0;
    let octet6 = value[1];
    let num_quintuplets = (octet6 >> 5) & 0x07;
    let num_quadruplets = (octet6 >> 2) & 0x07;
    let uambri = octet6 & 0x02 != 0;
    let octet7 = value[2];
    let sambri = octet7 & 0x80 != 0;
    let count_at = |off: usize| -> u32 {
        (u32::from(value[off]) << 16) | (u32::from(value[off + 1]) << 8) | u32::from(value[off + 2])
    };
    let mut kasme = [0u8; 32];
    kasme.copy_from_slice(&value[9..41]);

    let mut off = FIXED;
    let need = |off: usize, n: usize, what: &str| -> Result<(), String> {
        if off + n > value.len() {
            Err(format!(
                "MM Context ends inside {what} (needs octets {}..{}, has {})",
                off,
                off + n,
                value.len()
            ))
        } else {
            Ok(())
        }
    };
    // Authentication Quadruplets (Figure 8.38-9): RAND(16), XRES length, XRES, AUTN length,
    // AUTN, K_ASME(32). Skipped -- the AMF re-authenticates in 5GS if it chooses to, and
    // never uses an EPS vector -- but walked exactly, because they push every later field.
    for _ in 0..num_quadruplets {
        need(
            off,
            17,
            "an Authentication Quadruplet's RAND and XRES length",
        )?;
        off += 16;
        let xres_len = value[off] as usize;
        off += 1;
        need(off, xres_len + 1, "an Authentication Quadruplet's XRES")?;
        off += xres_len;
        let autn_len = value[off] as usize;
        off += 1;
        need(
            off,
            autn_len + 32,
            "an Authentication Quadruplet's AUTN and K_ASME",
        )?;
        off += autn_len + 32;
    }
    // Authentication Quintuplets (Figure 8.38-8): RAND(16), XRES length, XRES, CK(16),
    // IK(16), AUTN length, AUTN. §8.38 says an MME shall not send them to an AMF; walked
    // anyway so a non-conformant one is skipped rather than misread.
    for _ in 0..num_quintuplets {
        need(
            off,
            17,
            "an Authentication Quintuplet's RAND and XRES length",
        )?;
        off += 16;
        let xres_len = value[off] as usize;
        off += 1;
        need(
            off,
            xres_len + 33,
            "an Authentication Quintuplet's XRES, CK, IK",
        )?;
        off += xres_len + 32;
        let autn_len = value[off] as usize;
        off += 1;
        need(off, autn_len, "an Authentication Quintuplet's AUTN")?;
        off += autn_len;
    }
    if drxi {
        need(off, 2, "the DRX parameter (DRXI is set)")?;
        off += 2;
    }
    let mut nh = None;
    let mut ncc = 0u8;
    if nhi {
        need(off, 33, "the NH and NCC (NHI is set)")?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&value[off..off + 32]);
        nh = Some(bytes);
        ncc = value[off + 32] & 0x07;
        off += 33;
    }
    let read_ambr = |off: usize| -> (u32, u32) {
        let ul = u32::from_be_bytes([value[off], value[off + 1], value[off + 2], value[off + 3]]);
        let dl = u32::from_be_bytes([
            value[off + 4],
            value[off + 5],
            value[off + 6],
            value[off + 7],
        ]);
        (ul, dl)
    };
    let mut subscribed_ue_ambr_kbps = None;
    if sambri {
        need(off, 8, "the Subscribed UE AMBR (SAMBRI is set)")?;
        subscribed_ue_ambr_kbps = Some(read_ambr(off));
        off += 8;
    }
    let mut used_ue_ambr_kbps = None;
    if uambri {
        need(off, 8, "the Used UE AMBR (UAMBRI is set)")?;
        used_ue_ambr_kbps = Some(read_ambr(off));
        off += 8;
    }
    // The three length-prefixed fields. A tail that stops early is a legal shorter IE.
    let mut take_lv = || -> Vec<u8> {
        let Some(&len) = value.get(off) else {
            return Vec::new();
        };
        off += 1;
        let len = (len as usize).min(value.len().saturating_sub(off));
        let out = value[off..off + len].to_vec();
        off += len;
        out
    };
    let ue_network_capability = take_lv();
    let _ms_network_capability = take_lv();
    let mei = take_lv();

    Ok(EpsSecurityContext {
        ksi_asme: octet5 & 0x07,
        used_nas_integrity_algorithm: (octet7 >> 4) & 0x07,
        used_nas_cipher: octet7 & 0x0F,
        nas_downlink_count: count_at(3),
        nas_uplink_count: count_at(6),
        kasme,
        nh,
        ncc,
        subscribed_ue_ambr_kbps,
        used_ue_ambr_kbps,
        ue_network_capability,
        mei,
    })
}

// ============================================================================
// The Forward Relocation Request (TS 29.274 §7.3.1), EPS→5GS rows
// ============================================================================

/// The target gNB a Forward Relocation Request names (TS 29.274 §8.51.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetGnb {
    /// MCC/MNC, TBCD (octets 6-8).
    pub plmn_bcd: [u8; 3],
    /// `gNodeB ID Length` in bits, 22..=32 (octet 9, bits 6..1).
    pub gnb_id_len: u8,
    /// `gNodeB ID`, right-aligned in octets 10-13 ("Bit 1 of Octet 13 is the least
    /// significant bit").
    pub gnb_id: u32,
    /// 5GS TAC (octets 14-16).
    pub tac: u32,
}

/// One PDN connection from the request's `MME/SGSN/AMF UE EPS PDN Connections` (Table
/// 7.3.1-2).
#[derive(Debug, Clone)]
pub struct InboundPdnConnection {
    /// The IE **contents**, unaltered. This is what the SMF receives as `ueEpsPdnConnection`:
    /// TS 29.502 §6.1.6.3.2 makes `EpsPdnCnxContainer` *"the UeEpsPdnConnection IE specified
    /// in Table 7.3.1-2 ... of TS 29.274"*, so the MME's own bytes are forwarded rather than a
    /// re-encoding the AMF could get subtly wrong.
    pub contents: Vec<u8>,
    /// APN (mandatory), in dotted form.
    pub apn: String,
    /// Linked EPS Bearer ID (mandatory) — the default bearer.
    pub linked_ebi: u8,
    /// `PGW node name` (FQDN, instance 0, conditional) — the S5/S8 FQDN of the SMF+PGW-C,
    /// which TS 23.502 §4.11.1.2.2.2 step 3 has the AMF give the NRF.
    pub pgw_node_name: Option<String>,
    /// `PGW S5/S8 IP Address for Control Plane` (F-TEID, instance 0, mandatory).
    pub pgw_c_fteid: Option<Gtp2FTeidIe>,
    /// The EBIs of every bearer the connection carries.
    pub bearer_ebis: Vec<u8>,
    /// APN-AMBR (`Aggregate Maximum Bit Rate`, mandatory) as (uplink, downlink) kbps.
    pub apn_ambr_kbps: Option<(u32, u32)>,
}

/// What a Forward Relocation Request carries for an **EPS→5GS** handover (Table 7.3.1-1).
#[derive(Debug, Clone)]
pub struct EpsToFivegsRelocationRequest {
    /// IMSI digits (conditional; present for every UE that is not UICCless-emergency).
    pub imsi: Option<String>,
    /// The source MME's control-plane F-TEID (Sender's F-TEID, **M**, instance 0). Every
    /// later message in the procedure is addressed to its TEID.
    pub mme_fteid: Gtp2FTeidIe,
    /// The EPS security context (MM Context, **M**).
    pub security: EpsSecurityContext,
    /// The PDN connections to move.
    pub pdn_connections: Vec<InboundPdnConnection>,
    /// The NG-RAN **Source to Target** transparent container, the F-Container (instance 0)
    /// with its Container Type octet removed.
    pub source_to_target_container: Vec<u8>,
    /// The target gNB.
    pub target: TargetGnb,
    /// `DFI` from the Indication Flags (§8.12 bit 5): whether the MME offers direct data
    /// forwarding.
    pub direct_forwarding: bool,
}

/// Why a Forward Relocation Request was refused, as the cause the response carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationRefusal {
    /// The GTPv2-C cause (Table 8.4-1).
    pub cause: u8,
    /// What was wrong, for the log.
    pub reason: String,
}

impl RelocationRefusal {
    fn new(cause: u8, reason: impl Into<String>) -> Self {
        Self {
            cause,
            reason: reason.into(),
        }
    }
}

/// Decode TS 29.274 §8.3 TBCD digits: low nibble first, `0xF` ends an odd count.
pub fn tbcd_to_digits(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b & 0x0F, b >> 4] {
            if nibble == 0x0F {
                return out;
            }
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('?'));
        }
    }
    out
}

/// Turn an RFC 1035 label sequence (TS 29.274 §8.66 FQDN, §8.6 APN) back into dotted form.
///
/// A label length that runs past the buffer stops the walk: a truncated name is a bad name,
/// and returning what was read is safer than guessing the rest.
pub fn labels_to_dotted(encoded: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut off = 0usize;
    while off < encoded.len() {
        let len = encoded[off] as usize;
        if len == 0 || off + 1 + len > encoded.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&encoded[off + 1..off + 1 + len]).to_string());
        off += 1 + len;
    }
    labels.join(".")
}

/// Parse a Target Identification IE body for a **gNodeB** (TS 29.274 §8.51.7).
pub fn parse_target_gnb(value: &[u8]) -> Result<TargetGnb, String> {
    let Some(&target_type) = value.first() else {
        return Err("Target Identification is empty".to_string());
    };
    if target_type != TARGET_TYPE_GNODEB {
        return Err(format!(
            "Target Type is {target_type}, not {TARGET_TYPE_GNODEB} ('gNodeB ID', Table \
             8.51-1). An ng-eNB target (6/7) is not served: this AMF resolves handover \
             targets only among gNBs it holds an NG association with"
        ));
    }
    // Type(1) + PLMN(3) + length(1) + gNB ID(4) + TAC(3), Figure 8.51.7-1.
    if value.len() < 12 {
        return Err(format!(
            "gNodeB Target ID is {} octets, Figure 8.51.7-1 needs 12",
            value.len()
        ));
    }
    let gnb_id_len = value[4] & 0x3F;
    if !(22..=32).contains(&gnb_id_len) {
        return Err(format!(
            "gNodeB ID Length {gnb_id_len} is outside 22..32 (§8.51.7)"
        ));
    }
    let raw = u32::from_be_bytes([value[5], value[6], value[7], value[8]]);
    // Right-aligned: bits above the length are "set to 0 by the sender and ignored by the
    // receiver", so they are masked rather than trusted.
    let gnb_id = if gnb_id_len == 32 {
        raw
    } else {
        raw & ((1u32 << gnb_id_len) - 1)
    };
    let tac = (u32::from(value[9]) << 16) | (u32::from(value[10]) << 8) | u32::from(value[11]);
    Ok(TargetGnb {
        plmn_bcd: [value[1], value[2], value[3]],
        gnb_id_len,
        gnb_id,
        tac,
    })
}

/// Parse one PDN Connection IE's contents (Table 7.3.1-2).
fn parse_inbound_pdn_connection(contents: &[u8]) -> Result<InboundPdnConnection, String> {
    let pdn = Gtp2PdnConnectionIe::decode(&Bytes::copy_from_slice(contents))
        .map_err(|e| format!("PDN Connection undecodable: {e}"))?;
    let apn_ie = pdn
        .apn()
        .map_err(|_| "PDN Connection has no APN, which Table 7.3.1-2 makes mandatory")?;
    let apn = labels_to_dotted(&apn_ie.apn);
    if apn.is_empty() {
        return Err("PDN Connection APN is empty".to_string());
    }
    let linked_ebi = pdn
        .linked_ebi()
        .map_err(|_| "PDN Connection has no Linked EPS Bearer ID (mandatory)")?;
    let pgw_node_name = pdn
        .get_ie(Gtp2IeType::Fqdn as u8, 0)
        .map(|ie| labels_to_dotted(&ie.value))
        .filter(|s| !s.is_empty());
    let pgw_c_fteid = pdn.pgw_s5s8_control_fteid().ok();
    let bearer_ebis = pdn
        .bearer_contexts()
        .unwrap_or_default()
        .iter()
        .filter_map(|b| b.ebi().ok())
        .collect();
    let apn_ambr_kbps = pdn.apn_ambr().ok().map(|a| (a.uplink, a.downlink));
    Ok(InboundPdnConnection {
        contents: contents.to_vec(),
        apn,
        linked_ebi,
        pgw_node_name,
        pgw_c_fteid,
        bearer_ebis,
        apn_ambr_kbps,
    })
}

/// Parse a **Forward Relocation Request** for an EPS→5GS handover (TS 29.274 §7.3.1).
///
/// Every refusal carries the cause the response should send: a missing mandatory IE is
/// `Mandatory IE missing` (70), one that is present but unusable is `Mandatory IE incorrect`
/// (69), and a conditional IE this procedure needs (the PDN connections, the container, the
/// target) is `Conditional IE missing` (103) — the three rows Table 8.4-1 has for exactly
/// these situations, so the MME learns which part of its message was the problem.
pub fn parse_eps_to_5gs_forward_relocation_request(
    msg: &Gtp2Message,
) -> Result<EpsToFivegsRelocationRequest, RelocationRefusal> {
    let mme_fteid = msg
        .get_ie(Gtp2IeType::FTeid as u8, 0)
        .ok_or_else(|| {
            RelocationRefusal::new(
                CAUSE_MANDATORY_IE_MISSING,
                "no Sender's F-TEID for Control Plane (Table 7.3.1-1, M)",
            )
        })
        .and_then(|ie| {
            Gtp2FTeidIe::decode(&ie.value).map_err(|e| {
                RelocationRefusal::new(
                    CAUSE_MANDATORY_IE_INCORRECT,
                    format!("Sender's F-TEID undecodable: {e}"),
                )
            })
        })?;
    let security = msg
        .get_ie(Gtp2IeType::MmContext as u8, 0)
        .ok_or_else(|| {
            RelocationRefusal::new(
                CAUSE_MANDATORY_IE_MISSING,
                "no MME/SGSN/AMF UE MM Context (Table 7.3.1-1, M)",
            )
        })
        .and_then(|ie| {
            parse_eps_security_context(&ie.value)
                .map_err(|e| RelocationRefusal::new(CAUSE_MANDATORY_IE_INCORRECT, e))
        })?;

    let imsi = msg
        .get_ie(Gtp2IeType::Imsi as u8, 0)
        .map(|ie| tbcd_to_digits(&ie.value))
        .filter(|s| !s.is_empty());

    let mut pdn_connections = Vec::new();
    for ie in msg.get_ies(Gtp2IeType::PdnConnection as u8) {
        if ie.instance != 0 {
            continue;
        }
        pdn_connections.push(
            parse_inbound_pdn_connection(&ie.value)
                .map_err(|e| RelocationRefusal::new(CAUSE_MANDATORY_IE_INCORRECT, e))?,
        );
    }
    if pdn_connections.is_empty() {
        // §7.3.1 (`29274-j60.txt:17748-17752`): the source "shall not proceed with the
        // Forward Relocation Request procedure if the UE does not have any EPS bearer
        // context(s) ... that can be transferred", so a request without one is malformed.
        return Err(RelocationRefusal::new(
            CAUSE_CONDITIONAL_IE_MISSING,
            "no MME/SGSN/AMF UE EPS PDN Connections: there is nothing to hand over",
        ));
    }

    let container_ie = msg.get_ie(Gtp2IeType::FContainer as u8, 0).ok_or_else(|| {
        RelocationRefusal::new(
            CAUSE_CONDITIONAL_IE_MISSING,
            "no E-UTRAN Transparent Container: Table 7.3.1-1 requires it for EPS to 5GS \
             handover, and the NGAP HandoverRequest has nothing to carry without it",
        )
    })?;
    let Some((&type_octet, container)) = container_ie.value.split_first() else {
        return Err(RelocationRefusal::new(
            CAUSE_MANDATORY_IE_INCORRECT,
            "E-UTRAN Transparent Container is empty",
        ));
    };
    if type_octet & 0x0F != F_CONTAINER_TYPE_EUTRAN || container.is_empty() {
        return Err(RelocationRefusal::new(
            CAUSE_MANDATORY_IE_INCORRECT,
            format!(
                "E-UTRAN Transparent Container has Container Type {} (Table 7.3.1-1 requires \
                 3) or no container field",
                type_octet & 0x0F
            ),
        ));
    }

    let target = msg
        .get_ie(Gtp2IeType::TargetIdentification as u8, 0)
        .ok_or_else(|| {
            RelocationRefusal::new(
                CAUSE_CONDITIONAL_IE_MISSING,
                "no Target Identification: Table 7.3.1-1 requires it for EPS to 5GS handover",
            )
        })
        .and_then(|ie| {
            parse_target_gnb(&ie.value)
                .map_err(|e| RelocationRefusal::new(CAUSE_MANDATORY_IE_INCORRECT, e))
        })?;

    let direct_forwarding = msg
        .get_ie(Gtp2IeType::Indication as u8, 0)
        .and_then(|ie| Gtp2IndicationIe::decode(&ie.value).ok())
        .is_some_and(|ind| ind.dfi);

    Ok(EpsToFivegsRelocationRequest {
        imsi,
        mme_fteid,
        security,
        pdn_connections,
        source_to_target_container: container.to_vec(),
        target,
        direct_forwarding,
    })
}

/// The UE-AMBR the HandoverRequest carries, as (downlink, uplink) **bps**.
///
/// The NGAP `UEAggregateMaximumBitRate` is mandatory in a HandoverRequest (TS 38.413
/// §9.2.3.4), and an EPS→5GS target AMF holds no 5G subscription data yet. TS 23.401 §4.7.3
/// bounds the EPS UE-AMBR to the sum of the APN-AMBRs of the active PDN connections, capped by
/// the subscribed UE-AMBR, so that is computed from what the MME sent: the sum of the moved
/// PDN connections' APN-AMBRs, capped by the MM Context's Subscribed UE-AMBR when present.
/// MM Context and APN-AMBR values are kbps (TS 29.274 §8.7, §8.38); NGAP's are bps.
///
/// `None` when the MME supplied neither, which leaves the gNB nothing truthful to enforce.
pub fn ue_ambr_bps(
    moved_apn_ambrs_kbps: &[(u32, u32)],
    subscribed_ue_ambr_kbps: Option<(u32, u32)>,
) -> Option<(u64, u64)> {
    let sum = if moved_apn_ambrs_kbps.is_empty() {
        None
    } else {
        Some(
            moved_apn_ambrs_kbps
                .iter()
                .fold((0u64, 0u64), |(ul, dl), (u, d)| {
                    (ul + u64::from(*u), dl + u64::from(*d))
                }),
        )
    };
    let subscribed = subscribed_ue_ambr_kbps.map(|(u, d)| (u64::from(u), u64::from(d)));
    let (ul, dl) = match (sum, subscribed) {
        (Some((su, sd)), Some((cu, cd))) => (su.min(cu), sd.min(cd)),
        (Some(s), None) | (None, Some(s)) => s,
        (None, None) => return None,
    };
    Some((dl * 1000, ul * 1000))
}

// ============================================================================
// The mapped 5G security context (TS 33.501 §8.4.2 / §8.6.2)
// ============================================================================

/// The mapped 5G security context a target AMF builds, and what it hands the target gNB.
///
/// Every field is a value the procedure fixes, and each is named for the clause that fixes
/// it so a reviewer can check them one at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedSecurity {
    /// `K_AMF'` = KDF(K_ASME, FC 0x76, NH) (§8.6.2, Annex A.15.2).
    pub kamf: [u8; 32],
    /// `K_NASint` from `K_AMF'` with the selected NIA (§8.4.2 step 3, Annex A.8).
    pub knas_int: [u8; 16],
    /// `K_NASenc` from `K_AMF'` with the selected NEA.
    pub knas_enc: [u8; 16],
    /// ngKSI value field, *"taken from the eKSI"* (§8.6.2).
    pub ngksi: u8,
    /// The selected 5G NAS integrity algorithm.
    pub nia: u8,
    /// The selected 5G NAS ciphering algorithm.
    pub nea: u8,
    /// The UE 5G security capabilities in effect: the default set unless the MME sent the
    /// UE's own (§8.4.2 step 3), as TS 24.501 §9.11.3.54 octets `(5G-EA, 5G-IA)`.
    pub ue_5g_caps: (u8, u8),
    /// The UE's EPS capabilities from the UE Network Capability `(EEA, EIA)`.
    pub ue_eps_caps: (u8, u8),
    /// The S1 mode to N1 mode NAS transparent container's **value part** (TS 24.501
    /// §9.11.2.9, octets 3-10), carried to the gNB as the NGAP `NASC` IE.
    pub nas_container: [u8; S1_TO_N1_CONTAINER_VALUE_LEN],
    /// The temporary K_gNB, from `K_AMF'` and uplink NAS COUNT 2³²-1 (Annex A.9). The
    /// HandoverRequest carries it as the NH with NCC = 0 (§8.4.2 step 4).
    pub temporary_kgnb: [u8; 32],
    /// The `{NCC = 1, NH}` pair the AMF stores after sending the HandoverRequest, the NH
    /// derived per Annex A.10 with the temporary K_gNB as SYNC-input (§8.4.2 step 4).
    pub stored_nh: [u8; 32],
    /// 5G NAS downlink COUNT after the container: 0 (§8.6.2) then incremented once
    /// (§8.4.2 step 3, "increment the downlink NAS COUNT by one after creating a NAS
    /// Container").
    pub dl_count: u32,
}

/// The stored NCC after the HandoverRequest (TS 33.501 §8.4.2 step 4: *"The target AMF shall
/// further set the NCC to one"*).
pub const STORED_NCC_AFTER_HANDOVER_REQUEST: u8 = 1;

/// Map an EPS security context to a 5G one (TS 33.501 §8.4.2 step 3, §8.6.2).
///
/// `amf_nia_mask` / `amf_nea_mask` are the AMF's configured algorithm masks (bit *n* =
/// algorithm *n*), the same masks the Security Mode Command path selects from, so a UE
/// arriving by handover gets the same algorithm policy as one that registered natively.
///
/// Refuses when the MME sent no NH — Annex A.15.2 has nothing to derive from — and when no
/// NAS integrity algorithm is common to the UE and the AMF: TS 33.501 §5.5.2 makes NAS
/// integrity mandatory, and fabricating one the UE does not support would have it reject the
/// container's MAC.
pub fn map_eps_security_context(
    ctx: &EpsSecurityContext,
    ue_5g_caps: Option<(u8, u8)>,
    amf_nia_mask: u8,
    amf_nea_mask: u8,
    mac: impl Fn(u8, &[u8; 16], u32, &[u8]) -> [u8; 4],
) -> Result<MappedSecurity, String> {
    let nh = ctx.nh.ok_or_else(|| {
        "the MM Context carries no NH (NHI = 0): TS 33.501 §8.4.2 step 2 has the source MME \
         send the {NH, NCC} pair and Annex A.15.2 derives K_AMF' from it, so without it no \
         mapped 5G security context can be built"
            .to_string()
    })?;
    let kamf = nextgcore_crypt::kdf::nextgcore_kdf_kamf_prime_from_kasme_handover(&ctx.kasme, &nh);

    let (ea_octet, ia_octet) = ue_5g_caps.unwrap_or((DEFAULT_5G_EA_OCTET, DEFAULT_5G_IA_OCTET));
    let ue_nia_mask = crate::ngap_path::wire_caps_to_mask(ia_octet);
    let ue_nea_mask = crate::ngap_path::wire_caps_to_mask(ea_octet);
    let nia = crate::nas_security::select_integrity_algorithm(ue_nia_mask, amf_nia_mask)
        .filter(|&a| a != 0)
        .ok_or_else(|| {
            format!(
                "no non-null 5G NAS integrity algorithm is common to the UE ({ia_octet:#04x}) \
                 and this AMF (mask {amf_nia_mask:#04x}): TS 33.501 §5.5.2 makes NAS integrity \
                 mandatory outside an unauthenticated emergency session"
            )
        })?;
    let nea = crate::nas_security::select_encryption_algorithm(ue_nea_mask, amf_nea_mask);

    let knas_int = nextgcore_crypt::kdf::nextgcore_kdf_nas_5gs(0x02, nia, &kamf);
    let knas_enc = nextgcore_crypt::kdf::nextgcore_kdf_nas_5gs(0x01, nea, &kamf);

    // TS 24.501 §9.11.2.9: octet 7 = ciphering (bits 8-5) | integrity (bits 4-1); octet 8 =
    // spare | NCC (bits 7-5) | TSC (bit 4) | KSI (bits 3-1); octets 9-10 spare. TSC = 1 is
    // "mapped security context" (§9.11.3.32), which §8.6.2 requires for this ngKSI.
    let ngksi = ctx.ksi_asme & 0x07;
    let params = [
        ((nea & 0x0F) << 4) | (nia & 0x0F),
        ((ctx.ncc & 0x07) << 4) | 0x08 | ngksi,
        0,
        0,
    ];
    // The NAS MAC: COUNT 2³²-1, DIRECTION downlink, over the container's content after the
    // MAC field (§8.4.2 step 3 via §6.9.2.3.3). The MAC field cannot be an input to itself,
    // so "the content of NAS Container" is read as octets 7-10.
    let nas_mac = mac(nia, &knas_int, NASC_MAC_COUNT, &params);
    let mut nas_container = [0u8; S1_TO_N1_CONTAINER_VALUE_LEN];
    nas_container[..4].copy_from_slice(&nas_mac);
    nas_container[4..].copy_from_slice(&params);

    // Annex A.9 with access type distinguisher 0x01 (3GPP access).
    let temporary_kgnb =
        nextgcore_crypt::kdf::nextgcore_kdf_kgnb_and_kn3iwf(&kamf, TEMP_KGNB_UL_COUNT, 0x01);
    let stored_nh = nextgcore_crypt::kdf::nextgcore_kdf_nh_gnb(&kamf, &temporary_kgnb);

    let ue_eps_caps = (
        ctx.ue_network_capability.first().copied().unwrap_or(0),
        ctx.ue_network_capability.get(1).copied().unwrap_or(0),
    );

    Ok(MappedSecurity {
        kamf,
        knas_int,
        knas_enc,
        ngksi,
        nia,
        nea,
        ue_5g_caps: (ea_octet, ia_octet),
        ue_eps_caps,
        nas_container,
        temporary_kgnb,
        stored_nh,
        dl_count: 1,
    })
}

// ============================================================================
// The Forward Relocation Response (§7.3.2) and Complete Notification (§7.3.3)
// ============================================================================

/// Build an **accepting** Forward Relocation Response for an EPS→5GS handover (§7.3.2,
/// step 14).
///
/// | IE | P | value |
/// |---|---|---|
/// | Cause | M | Request accepted |
/// | Sender's F-TEID (0) | C | this AMF's N26 endpoint — required when accepted |
/// | Indication | C | **SGWCI = 1**: *"This flag shall be set to 1 by the target AMF during the EPS to 5GS handover using N26 interface"* (Table 7.3.2-1) |
/// | List of Set-up Bearers (Bearer Context, 0) | C | the EPS Bearer Setup List, one per bearer |
/// | E-UTRAN Transparent Container (F-Container, 0) | C | the gNB's Target-to-Source container, Container Type 3 |
pub fn build_eps_to_5gs_forward_relocation_response(
    sequence_number: u32,
    mme_teid: u32,
    amf_fteid: &Gtp2FTeidIe,
    set_up_bearers: &[Gtp2BearerContextIe],
    target_to_source_container: &[u8],
) -> Gtp2Message {
    let mut msg = Gtp2Message::new(Gtp2Header::new(
        Gtp2MessageType::ForwardRelocationResponse as u8,
        mme_teid,
        sequence_number,
    ));
    msg.add_ie(Gtp2CauseIe::new(CAUSE_REQUEST_ACCEPTED).to_ie(0));
    msg.add_ie(amf_fteid.to_ie(0));
    let indication = Gtp2IndicationIe {
        sgwci: true,
        ..Gtp2IndicationIe::new()
    };
    msg.add_ie(indication.to_ie(0));
    for bearer in set_up_bearers {
        msg.add_ie(bearer.to_ie(0));
    }
    msg.add_ie(f_container(target_to_source_container));
    msg
}

/// Build a **refusing** Forward Relocation Response: the Cause alone.
///
/// Table 7.3.2-1 conditions the F-TEID, the bearer list and the container on "Request
/// accepted", so a refusal carrying any of them would hand the MME endpoints for a
/// relocation it was told did not happen.
pub fn build_forward_relocation_response_refusal(
    sequence_number: u32,
    mme_teid: u32,
    cause: u8,
) -> Gtp2Message {
    let mut msg = Gtp2Message::new(Gtp2Header::new(
        Gtp2MessageType::ForwardRelocationResponse as u8,
        mme_teid,
        sequence_number,
    ));
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    msg
}

/// A decoded **Relocation Cancel Request** (TS 29.274 §7.3.16, type 139), #592.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationCancel {
    /// The UE's IMSI digits (Table 7.3.16-1: present unless an emergency UICC-less UE).
    pub imsi: Option<String>,
    /// The header TEID: this AMF's N26 TEID when the MME had it from the Forward
    /// Relocation Response, else 0 (§5.5.2).
    pub amf_teid: u32,
}

/// Decode a Relocation Cancel Request (#592). Nothing in Table 7.3.16-1 is mandatory,
/// so this cannot fail on content; the caller decides what an IMSI-less one names.
pub fn parse_relocation_cancel_request(msg: &Gtp2Message) -> RelocationCancel {
    let imsi = msg
        .get_ie(Gtp2IeType::Imsi as u8, 0)
        .map(|ie| tbcd_to_digits(&ie.value))
        .filter(|d| !d.is_empty());
    RelocationCancel {
        imsi,
        amf_teid: msg.header.teid.unwrap_or(0),
    }
}

/// Build a **Relocation Cancel Response** (TS 29.274 §7.3.17, type 140), #592: the Cause
/// alone (Table 7.3.17-1), addressed to the MME's TEID when this AMF has it, else 0 (§5.5.2).
pub fn build_relocation_cancel_response(
    sequence_number: u32,
    mme_teid: u32,
    cause: u8,
) -> Gtp2Message {
    let mut msg = Gtp2Message::new(Gtp2Header::new(
        Gtp2MessageType::RelocationCancelResponse as u8,
        mme_teid,
        sequence_number,
    ));
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    msg
}

/// Build a **Forward Relocation Complete Notification** (§7.3.3, type 135) to the source MME.
///
/// Table 7.3.3-1 has no mandatory IE, and none of the Indication's three flags applies to an
/// AMF (ISRAI needs ISR, which 5GS does not have; Notify Source eNB is an S1AP HandoverNotify
/// indication; the IWK-SCEF flag names a node this core has no interface to). So this is a
/// header addressed to the MME's TEID, which is conformant rather than incomplete — the same
/// conclusion mmed's builder for the opposite direction records.
pub fn build_forward_relocation_complete_notification(
    sequence_number: u32,
    mme_teid: u32,
) -> Gtp2Message {
    Gtp2Message::new(Gtp2Header::new(
        Gtp2MessageType::ForwardRelocationCompleteNotification as u8,
        mme_teid,
        sequence_number,
    ))
}

/// An F-Container (§8.48) of Container Type 3 holding `container`.
fn f_container(container: &[u8]) -> Gtp2Ie {
    let mut value = BytesMut::with_capacity(1 + container.len());
    value.put_u8(F_CONTAINER_TYPE_EUTRAN);
    value.put_slice(container);
    Gtp2Ie::new(Gtp2IeType::FContainer as u8, 0, value.freeze())
}

/// One entry of the EPS Bearer Setup List from an SMF's `epsBearerSetup` element.
///
/// TS 29.502 §6.1.6.3.2 makes `EpsBearerContainer` *"the Bearer Context IE specified in
/// Table 7.3.2-2 of TS 29.274"*. Whether a producer put the IE's TLV header in front is not
/// stated, so the element is accepted **only** as a whole IE that consumes exactly the
/// buffer, or else as the IE's contents — never by inspecting the first octet, which is the
/// byte-range-ladder shape nextgsim #201/#202 showed routing a conformant input to the wrong
/// branch.
pub fn bearer_context_from_container(element: &[u8]) -> Option<Gtp2BearerContextIe> {
    let mut whole = Bytes::copy_from_slice(element);
    if let Ok(ie) = Gtp2Ie::decode(&mut whole) {
        if ie.ie_type == Gtp2IeType::BearerContext as u8 && whole.is_empty() {
            return Gtp2BearerContextIe::decode(&ie.value)
                .ok()
                .filter(|b| b.ebi().is_ok());
        }
    }
    Gtp2BearerContextIe::decode(&Bytes::copy_from_slice(element))
        .ok()
        .filter(|b| b.ebi().is_ok())
}

/// A Bearer Context naming only an EBI — the List of Set-up Bearers entry for a bearer whose
/// SMF returned no `epsBearerSetup` element of its own (Table 7.3.2-2 needs only the EBI for
/// "EPS to 5GS handover").
pub fn bearer_context_for_ebi(ebi: u8) -> Gtp2BearerContextIe {
    let mut bearer = Gtp2BearerContextIe::new();
    bearer.add_ie(Gtp2EbiIe::new(ebi).to_ie(0));
    bearer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Figure 8.38-5 MM Context, built octet by octet from the figure, with every gated
    /// field the inbound parser must step over.
    fn mm_context_bytes(with_quadruplet: bool, drxi: bool, sambri: bool) -> Vec<u8> {
        let mut v = Vec::new();
        // Octet 5: Security Mode 4 (bits 8-6) | NHI 1 (bit 5) | DRXI (bit 4) | KSI 3.
        v.push((4 << 5) | 0x10 | if drxi { 0x08 } else { 0 } | 0x03);
        // Octet 6: 0 quintuplets | quadruplets (bits 5-3) | UAMBRI 0 | OSCI 0.
        v.push(if with_quadruplet { 1 << 2 } else { 0 });
        // Octet 7: SAMBRI (bit 8) | integrity EIA2 (bits 7-5 = 2) | cipher EEA1 (= 1).
        v.push(if sambri { 0x80 } else { 0 } | (2 << 4) | 1);
        v.extend_from_slice(&[0x00, 0x00, 0x07]); // DL COUNT 7
        v.extend_from_slice(&[0x00, 0x00, 0x09]); // UL COUNT 9
        v.extend_from_slice(&[0xA5; 32]); // K_ASME
        if with_quadruplet {
            v.extend_from_slice(&[0x01; 16]); // RAND
            v.push(8);
            v.extend_from_slice(&[0x02; 8]); // XRES
            v.push(16);
            v.extend_from_slice(&[0x03; 16]); // AUTN
            v.extend_from_slice(&[0x04; 32]); // K_ASME of the quadruplet
        }
        if drxi {
            v.extend_from_slice(&[0xDD, 0xDD]);
        }
        v.extend_from_slice(&[0x5C; 32]); // NH
        v.push(0x02); // spare | NCC 2
        if sambri {
            v.extend_from_slice(&50_000u32.to_be_bytes()); // UL kbps
            v.extend_from_slice(&100_000u32.to_be_bytes()); // DL kbps
        }
        v.push(2);
        v.extend_from_slice(&[0xF0, 0x70]); // UE NC: EEA0-3, EIA1-3
        v.push(0); // no MS NC
        v.push(0); // no MEI
        v.push(0); // access restriction
        v
    }

    /// The inbound MM Context parser steps over every gated field Figure 8.38-5 places in
    /// front of the NH and the UE Network Capability.
    ///
    /// The library decoder #347/#408 wrote assumes none of them; fed this context it would
    /// read the quadruplet's RAND as the NH. Each combination is asserted on the fields that
    /// sit AFTER the gated ones, which is where a mis-step shows.
    #[test]
    fn an_mme_mm_context_with_quadruplets_drx_and_ue_ambr_parses_to_the_right_fields() {
        for (quad, drx, sambr) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            let ctx = parse_eps_security_context(&mm_context_bytes(quad, drx, sambr))
                .unwrap_or_else(|e| panic!("quad={quad} drx={drx} sambr={sambr}: {e}"));
            assert_eq!(ctx.ksi_asme, 3);
            assert_eq!(ctx.used_nas_integrity_algorithm, 2);
            assert_eq!(ctx.used_nas_cipher, 1);
            assert_eq!(ctx.nas_downlink_count, 7);
            assert_eq!(ctx.nas_uplink_count, 9);
            assert_eq!(ctx.kasme, [0xA5; 32]);
            assert_eq!(
                ctx.nh,
                Some([0x5C; 32]),
                "quad={quad} drx={drx}: the NH follows the quadruplets and the DRX parameter"
            );
            assert_eq!(ctx.ncc, 2);
            assert_eq!(
                ctx.ue_network_capability,
                vec![0xF0, 0x70],
                "quad={quad} drx={drx} sambr={sambr}: the UE Network Capability follows \
                 the NH and the UE-AMBR"
            );
            assert_eq!(
                ctx.subscribed_ue_ambr_kbps,
                sambr.then_some((50_000, 100_000))
            );
        }
    }

    /// A context that is not an EPS one, or is cut short inside a gated field, is refused.
    #[test]
    fn a_non_eps_or_truncated_mm_context_is_refused() {
        let mut gsm = mm_context_bytes(false, false, false);
        gsm[0] = (1 << 5) | 0x10; // Security Mode 1: UMTS key
        assert!(parse_eps_security_context(&gsm).is_err());

        let full = mm_context_bytes(true, true, false);
        // Cut inside the quadruplet, and inside the NH: both decide where later fields sit.
        for cut in [50, 41 + 16 + 1 + 8 + 1 + 16 + 32 + 2 + 10] {
            assert!(
                parse_eps_security_context(&full[..cut]).is_err(),
                "a context truncated at {cut} must not parse"
            );
        }
        assert!(parse_eps_security_context(&full[..40]).is_err());
    }

    /// The gNodeB Target ID, against Figure 8.51.7-1.
    #[test]
    fn a_gnodeb_target_identification_parses_per_figure_8_51_7_1() {
        // 22-bit gNB ID 0x3ABCDE in a 32-bit field with junk in the high bits, which the
        // receiver must ignore.
        let value = [
            TARGET_TYPE_GNODEB,
            0x00,
            0xF1,
            0x10,
            22,
            0xFF,
            0xFA,
            0xBC,
            0xDE,
            0x00,
            0x00,
            0x01,
        ];
        let t = parse_target_gnb(&value).expect("gNodeB target");
        assert_eq!(t.gnb_id_len, 22);
        assert_eq!(t.gnb_id, 0x3A_BCDE, "bits above the length are ignored");
        assert_eq!(t.tac, 1);
        assert_eq!(t.plmn_bcd, [0x00, 0xF1, 0x10]);

        let mut ng_enb = value;
        ng_enb[0] = 6;
        assert!(parse_target_gnb(&ng_enb).is_err());
        assert!(parse_target_gnb(&value[..11]).is_err());
    }

    /// UE-AMBR: the moved APN-AMBRs summed, capped by the subscribed UE-AMBR, in bps.
    #[test]
    fn the_handover_ue_ambr_is_the_capped_apn_ambr_sum_in_bps() {
        assert_eq!(
            ue_ambr_bps(&[(10_000, 20_000), (5_000, 5_000)], None),
            Some((25_000_000, 15_000_000)),
            "summed, kbps -> bps, returned (downlink, uplink)"
        );
        assert_eq!(
            ue_ambr_bps(&[(10_000, 20_000), (5_000, 5_000)], Some((12_000, 100_000))),
            Some((25_000_000, 12_000_000)),
            "the subscribed UE-AMBR caps each direction independently"
        );
        assert_eq!(ue_ambr_bps(&[], None), None);
    }

    /// TBCD and RFC 1035 labels decode the way §8.3 and §8.66 encode them.
    #[test]
    fn tbcd_and_label_decoding() {
        assert_eq!(tbcd_to_digits(&[0x00, 0x01, 0x01, 0xF1]), "0010101");
        assert_eq!(labels_to_dotted(b"\x04topo\x03smf\x03lab"), "topo.smf.lab");
        assert_eq!(
            labels_to_dotted(b"\x09short"),
            "",
            "a label past the end stops the walk"
        );
    }

    /// The mapped context, against TS 33.501 §8.4.2 and §8.6.2 clause by clause.
    #[test]
    fn the_mapped_security_context_follows_ts33501_8_4_2() {
        let ctx = parse_eps_security_context(&mm_context_bytes(false, false, false)).unwrap();
        let mapped = map_eps_security_context(&ctx, None, 0x0E, 0x0F, |alg, key, count, msg| {
            crate::nas_security::nas_mac_calculate(alg, key, count, 1, 1, msg)
        })
        .expect("mapped");

        assert_eq!(
            mapped.kamf,
            nextgcore_crypt::kdf::nextgcore_kdf_kamf_prime_from_kasme_handover(
                &[0xA5; 32],
                &[0x5C; 32]
            ),
            "K_AMF' = KDF(K_ASME, FC 0x76, NH) (§8.6.2, Annex A.15.2)"
        );
        // The default set (§8.4.2 step 3) has NIA1|NIA2 and NEA0|NEA1|NEA2; the AMF masks
        // allow NIA1-3 and NEA0-3, and the selector's priority is NIA2/NEA2.
        assert_eq!(
            mapped.ue_5g_caps,
            (DEFAULT_5G_EA_OCTET, DEFAULT_5G_IA_OCTET)
        );
        assert_eq!((mapped.nia, mapped.nea), (2, 2));
        assert_eq!(mapped.ngksi, 3, "the ngKSI value is the eKSI (§8.6.2)");
        assert_eq!(mapped.ue_eps_caps, (0xF0, 0x70));

        // The container (TS 24.501 §9.11.2.9): algorithms, then NCC|TSC=1|KSI, then spare.
        assert_eq!(mapped.nas_container[4], (2 << 4) | 2);
        assert_eq!(
            mapped.nas_container[5],
            (2 << 4) | 0x08 | 3,
            "NCC is the MME's (2), TSC is 'mapped' (1), KSI is the eKSI (3)"
        );
        assert_eq!(&mapped.nas_container[6..], &[0, 0]);
        // The MAC: NIA2 over octets 7-10 with K_NASint, COUNT 2^32-1, downlink.
        let expected_mac = crate::nas_security::nas_mac_calculate(
            2,
            &mapped.knas_int,
            u32::MAX,
            1,
            1,
            &mapped.nas_container[4..],
        );
        assert_eq!(&mapped.nas_container[..4], &expected_mac);
        assert_ne!(expected_mac, [0; 4], "NIA2 produces a real MAC");

        // Temporary K_gNB with UL COUNT 2^32-1, and the stored NH from it (Annex A.10).
        assert_eq!(
            mapped.temporary_kgnb,
            nextgcore_crypt::kdf::nextgcore_kdf_kgnb_and_kn3iwf(&mapped.kamf, u32::MAX, 1)
        );
        assert_eq!(
            mapped.stored_nh,
            nextgcore_crypt::kdf::nextgcore_kdf_nh_gnb(&mapped.kamf, &mapped.temporary_kgnb)
        );
        assert_eq!(
            mapped.dl_count, 1,
            "0 per §8.6.2, then +1 after the container"
        );
    }

    /// No NH, or no common integrity algorithm, refuses the mapping.
    #[test]
    fn a_context_without_nh_or_a_common_nia_cannot_be_mapped() {
        let mut ctx = parse_eps_security_context(&mm_context_bytes(false, false, false)).unwrap();
        let mac = |_: u8, _: &[u8; 16], _: u32, _: &[u8]| [0u8; 4];
        // The AMF allows only NIA3; the default UE set has NIA1|NIA2.
        assert!(map_eps_security_context(&ctx, None, 1 << 3, 0x0F, mac).is_err());
        ctx.nh = None;
        assert!(map_eps_security_context(&ctx, None, 0x0E, 0x0F, mac).is_err());
    }

    /// The accepting response carries Table 7.3.2-1's EPS→5GS IEs, the container with its
    /// type octet, and SGWCI.
    #[test]
    fn an_accepting_forward_relocation_response_carries_its_eps_to_5gs_ies() {
        let fteid = Gtp2FTeidIe::new_ipv4(N26_AMF_GTP_C, 0x418, [10, 0, 0, 5]);
        let msg = build_eps_to_5gs_forward_relocation_response(
            77,
            0xABCD,
            &fteid,
            &[bearer_context_for_ebi(5), bearer_context_for_ebi(6)],
            &[0xC0, 0xFF, 0xEE],
        );
        assert_eq!(msg.header.message_type, 134);
        assert_eq!(msg.header.teid, Some(0xABCD));
        assert_eq!(msg.header.sequence_number, 77);
        let cause =
            Gtp2CauseIe::decode(&msg.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value).unwrap();
        assert_eq!(cause.cause, CAUSE_REQUEST_ACCEPTED);
        let sender =
            Gtp2FTeidIe::decode(&msg.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value).unwrap();
        assert_eq!(sender.interface_type, 40);
        assert_eq!(sender.teid, 0x418);
        let ind =
            Gtp2IndicationIe::decode(&msg.get_ie(Gtp2IeType::Indication as u8, 0).unwrap().value)
                .unwrap();
        assert!(
            ind.sgwci,
            "Table 7.3.2-1: SGWCI 'shall be set to 1 by the target AMF during the EPS to 5GS \
             handover using N26 interface'"
        );
        let container = msg.get_ie(Gtp2IeType::FContainer as u8, 0).unwrap();
        assert_eq!(
            container.value.as_ref(),
            &[3, 0xC0, 0xFF, 0xEE],
            "Container Type 3 (§8.48), then the gNB's container byte for byte"
        );
        let ebis: Vec<u8> = msg
            .get_ies(Gtp2IeType::BearerContext as u8)
            .iter()
            .map(|ie| {
                Gtp2BearerContextIe::decode(&ie.value)
                    .unwrap()
                    .ebi()
                    .unwrap()
            })
            .collect();
        assert_eq!(ebis, vec![5, 6]);

        let refusal =
            build_forward_relocation_response_refusal(78, 0xABCD, CAUSE_RELOCATION_FAILURE);
        assert!(refusal.get_ie(Gtp2IeType::FTeid as u8, 0).is_none());
        assert!(refusal.get_ie(Gtp2IeType::FContainer as u8, 0).is_none());
        assert_eq!(
            build_forward_relocation_complete_notification(9, 0xABCD)
                .header
                .message_type,
            135
        );
    }

    /// An SMF's `epsBearerSetup` element is accepted with or without its TLV header.
    #[test]
    fn an_eps_bearer_setup_element_is_read_with_or_without_its_header() {
        let bearer = bearer_context_for_ebi(7);
        let mut contents = BytesMut::new();
        bearer.encode_value(&mut contents);
        let mut whole = BytesMut::new();
        bearer.to_ie(0).encode(&mut whole);
        for element in [contents.to_vec(), whole.to_vec()] {
            assert_eq!(
                bearer_context_from_container(&element).and_then(|b| b.ebi().ok()),
                Some(7)
            );
        }
        assert!(bearer_context_from_container(&[]).is_none());
    }
}
