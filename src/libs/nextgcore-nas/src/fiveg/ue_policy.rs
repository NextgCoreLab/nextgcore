//! UE policy delivery service (UPDP) codec — TS 24.501 Annex D + TS 24.526 §5.2
//!
//! Wave-6 item E2. Implements the PCF↔UE "UE policy delivery service" protocol
//! that rides inside the DL/UL NAS TRANSPORT Payload container of type
//! "UE policy container" (0x05, TS 24.501 §9.11.3.39):
//!
//! - MANAGE UE POLICY COMMAND (encode + decode) — TS 24.501 Table D.5.1.1.1
//!   (specs/24501-j62.txt:96146-96177)
//! - MANAGE UE POLICY COMPLETE (encode + decode) — Table D.5.2.1.1 (:96213)
//! - MANAGE UE POLICY COMMAND REJECT (encode + decode) with the
//!   UE policy section management result of D.6.3 (:96717-96952)
//! - UE STATE INDICATION (encode + decode) with the UPSI list of D.6.4
//!   (:96954-97108) and the UE policy classmark of D.6.5 (:97110-97196),
//!   plus the optional UE OS Id IE of D.6.6 (IEI 0x41, :97198-97236)
//! - UE policy section management list coding per figures D.6.2.1-D.6.2.7 and
//!   Table D.6.2.1 (:96362-96712)
//! - URSP part-contents encoder/decoder per TS 24.526 V18.5.0 §5.2
//!   (specs/24526-i50.txt:2308-2733, figures 5.2.1-5.2.4A + Table 5.2.1)
//!
//! # Length-field convention (the fiddly part)
//!
//! Every 2-octet length field counts the octets FOLLOWING the length field up
//! to the end of its own structure (the length field itself is NOT included,
//! everything after it IS — including any type octet). Spec evidence:
//! TS 24.501 Table D.6.2.1 NOTE 2 (specs/24501-j62.txt:96710-96711): "The UE
//! policy part contents length indicates the length of the value part of the
//! UE policy part field (i.e. octet q+2 to octet r)" — octet q+2 is the
//! part-type octet immediately after the 2-octet length. The golden vectors in
//! tests/ue_policy_golden_vectors/data.rs pin this convention byte-exactly.
//!
//! # Fail-closed policy
//!
//! Encoders return `Err` (never Ok-with-holes) for any component that cannot
//! be represented on the wire, any spec constraint violation (match-all
//! exclusivity, duplicate rule precedence, duplicate singleton RSD components,
//! PTI out of its D.1.2 range) and any length that does not fit its length
//! field or the 65535-octet Payload container cap (TS 24.501 §9.11.3.39.1,
//! cited at specs/24501-j62.txt:96176-96177). Decoders reject truncation,
//! length-scope over/under-runs, set spare bits, reserved part types and
//! unknown component identifiers.
//!
//! NOTE on the S-NSSAI *traffic descriptor*: TS 24.526 V18.5.0 Table 5.2.1
//! (specs/24526-i50.txt:2466-2498) defines NO "S-NSSAI type" traffic
//! descriptor component identifier ("All other values are spare") — S-NSSAI
//! exists only as a *route selection descriptor* component (identifier
//! 0b00000010, :2692). A [`TrafficDescriptorComponent::SNssai`] therefore
//! always fails to encode; it exists as a variant so that callers mapping the
//! pcfd `UrspRule` model get a hard `Err` instead of a silently-dropped
//! component.

use crate::common::types::PlmnId;
use crate::error::{NasError, NasResult};
use crate::fiveg::ie::{PduSessionType, SscMode};

// =========================================================================
// Constants
// =========================================================================

/// UE policy delivery service message types (TS 24.501 Table D.6.1.1,
/// specs/24501-j62.txt:96325-96360). 0x00 and 0x07..=0xFF are reserved.
pub const UPDP_MSG_MANAGE_UE_POLICY_COMMAND: u8 = 0x01;
/// MANAGE UE POLICY COMPLETE (Table D.6.1.1).
pub const UPDP_MSG_MANAGE_UE_POLICY_COMPLETE: u8 = 0x02;
/// MANAGE UE POLICY COMMAND REJECT (Table D.6.1.1).
pub const UPDP_MSG_MANAGE_UE_POLICY_COMMAND_REJECT: u8 = 0x03;
/// UE STATE INDICATION (Table D.6.1.1).
pub const UPDP_MSG_UE_STATE_INDICATION: u8 = 0x04;

/// PCF-initiated procedures use PTI 80H-FEH (TS 24.501 D.1.2,
/// specs/24501-j62.txt:95577-95583).
pub const PCF_PTI_MIN: u8 = 0x80;
/// Upper bound of the PCF PTI range (FFH is reserved).
pub const PCF_PTI_MAX: u8 = 0xFE;
/// UE-initiated procedures use PTI 01H-77H (TS 24.501 D.1.2); 00H is
/// "no procedure transaction identity assigned".
pub const UE_PTI_MAX: u8 = 0x77;

/// D.6.3 result cause "Protocol error, unspecified" (0110 1111). The
/// receiving entity shall treat any other value as this one (Table D.6.3.1).
pub const UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED: u8 = 0x6F;

/// Max LV-E *contents* of the UE policy section management list: the LV-E
/// field is 11-65533 octets in MANAGE UE POLICY COMMAND (Table D.5.1.1.1),
/// i.e. 2 length octets + at most 65531 contents octets — which also keeps
/// the whole message content (PTI 1 + type 1 + LV-E) within the 65535-octet
/// Payload container cap of TS 24.501 §9.11.3.39.1.
const MAX_LIST_LVE_CONTENTS: usize = 65531;
/// Same bound for the D.6.3 result in MANAGE UE POLICY COMMAND REJECT
/// (Table D.5.3.1.1: LV-E 11-65533).
const MAX_RESULT_LVE_CONTENTS: usize = 65531;
/// UPSI list LV-E is 2-65531 in UE STATE INDICATION (Table D.5.4.1.1), i.e.
/// contents at most 65529 octets.
const MAX_UPSI_LVE_CONTENTS: usize = 65529;

/// APN maximum length per TS 23.003 §9.1 (label = 1-octet length + up to 63
/// ASCII octets; whole APN at most 100 octets).
const MAX_APN_LEN: usize = 100;
/// FQDN maximum length per TS 23.003 §28.3.2.1 (also bounded by the 1-octet
/// value length field of the "destination FQDN type" component).
const MAX_FQDN_LEN: usize = 255;
/// DNS label maximum length (TS 23.003 §9.1 / §28.3.2.1).
const MAX_LABEL_LEN: usize = 63;

// =========================================================================
// Strict scoped reader
// =========================================================================

/// Bounds-checked cursor. Every length-scoped structure is decoded from its
/// own sub-reader and must be consumed EXACTLY (`finish`), which catches both
/// over-runs and under-runs of the D.6.2/§5.2 nested length fields.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self) -> NasResult<u8> {
        let b = *self.buf.get(self.pos).ok_or(NasError::BufferTooShort {
            expected: self.pos + 1,
            actual: self.buf.len(),
        })?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> NasResult<u16> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    fn take(&mut self, n: usize) -> NasResult<&'a [u8]> {
        if self.remaining() < n {
            return Err(NasError::BufferTooShort {
                expected: self.pos + n,
                actual: self.buf.len(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Fails unless the reader was consumed exactly.
    fn finish(self, scope: &str) -> NasResult<()> {
        if self.remaining() != 0 {
            return Err(NasError::DecodingError(format!(
                "{scope}: {} unconsumed trailing octet(s) inside length scope",
                self.remaining()
            )));
        }
        Ok(())
    }
}

/// Appends a 2-octet big-endian length field, failing closed if the value
/// does not fit (all Annex D / §5.2 multi-octet lengths are 2 octets).
fn push_u16_len(out: &mut Vec<u8>, n: usize, what: &str) -> NasResult<()> {
    let v = u16::try_from(n).map_err(|_| {
        NasError::EncodingError(format!(
            "{what} length {n} exceeds 65535 (2-octet length field)"
        ))
    })?;
    out.extend_from_slice(&v.to_be_bytes());
    Ok(())
}

// =========================================================================
// PLMN BCD coding (Figure D.6.2.3 octets d+2..d+4 + Table D.6.2.1 NOTE 1)
// =========================================================================

/// Encodes MCC/MNC per figure D.6.2.3: octet d+2 = MCC digit 2 << 4 | MCC
/// digit 1; octet d+3 = MNC digit 3 << 4 | MCC digit 3 (2-digit MNC => MNC
/// digit 3 = 0b1111, Table D.6.2.1, specs/24501-j62.txt:96628); octet d+4 =
/// MNC digit 2 << 4 | MNC digit 1. Same coding is used by D.6.3.3 and D.6.4.2.
fn encode_plmn_bcd(plmn: &PlmnId) -> NasResult<[u8; 3]> {
    if plmn.mnc_len != 2 && plmn.mnc_len != 3 {
        return Err(NasError::EncodingError(format!(
            "PLMN MNC length must be 2 or 3 digits, got {}",
            plmn.mnc_len
        )));
    }
    let digits_ok = plmn.mcc.iter().all(|d| *d <= 9)
        && plmn.mnc[..usize::from(plmn.mnc_len)]
            .iter()
            .all(|d| *d <= 9);
    if !digits_ok {
        return Err(NasError::EncodingError(
            "PLMN MCC/MNC digits must be BCD (0..=9)".into(),
        ));
    }
    let mnc3 = if plmn.mnc_len == 2 { 0x0F } else { plmn.mnc[2] };
    Ok([
        (plmn.mcc[1] << 4) | plmn.mcc[0],
        (mnc3 << 4) | plmn.mcc[2],
        (plmn.mnc[1] << 4) | plmn.mnc[0],
    ])
}

/// Strict inverse of [`encode_plmn_bcd`]: non-BCD digits are rejected.
fn decode_plmn_bcd(b: &[u8]) -> NasResult<PlmnId> {
    debug_assert_eq!(b.len(), 3);
    let mcc = [b[0] & 0x0F, (b[0] >> 4) & 0x0F, b[1] & 0x0F];
    let mnc3 = (b[1] >> 4) & 0x0F;
    let mnc12 = [b[2] & 0x0F, (b[2] >> 4) & 0x0F];
    if mcc.iter().any(|d| *d > 9) || mnc12.iter().any(|d| *d > 9) {
        return Err(NasError::DecodingError(
            "PLMN MCC/MNC contains a non-BCD digit".into(),
        ));
    }
    let (mnc, mnc_len) = if mnc3 == 0x0F {
        ([mnc12[0], mnc12[1], 0], 2)
    } else if mnc3 <= 9 {
        ([mnc12[0], mnc12[1], mnc3], 3)
    } else {
        return Err(NasError::DecodingError(
            "PLMN MNC digit 3 is neither BCD nor 0b1111".into(),
        ));
    };
    Ok(PlmnId::new(mcc, mnc, mnc_len))
}

// =========================================================================
// APN / FQDN label coding (TS 23.003 §9.1 / §28.3.2.1)
// =========================================================================

/// Encodes a dotted name as length-prefixed labels (TS 23.003 §9.1: each
/// label = one octet length + that many 8-bit ASCII octets; not
/// zero-terminated).
fn encode_labels(name: &str, max_total: usize, what: &str) -> NasResult<Vec<u8>> {
    if name.is_empty() {
        return Err(NasError::EncodingError(format!("{what} must not be empty")));
    }
    if !name.is_ascii() {
        return Err(NasError::EncodingError(format!(
            "{what} must be ASCII (TS 23.003)"
        )));
    }
    let mut out = Vec::with_capacity(name.len() + 1);
    for label in name.split('.') {
        if label.is_empty() {
            return Err(NasError::EncodingError(format!(
                "{what} contains an empty label"
            )));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(NasError::EncodingError(format!(
                "{what} label exceeds {MAX_LABEL_LEN} octets (TS 23.003)"
            )));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    if out.len() > max_total {
        return Err(NasError::EncodingError(format!(
            "{what} encoding exceeds {max_total} octets (TS 23.003)"
        )));
    }
    Ok(out)
}

/// Strict inverse of [`encode_labels`]; labels are re-joined with '.'.
fn decode_labels(bytes: &[u8], what: &str) -> NasResult<String> {
    let mut r = Reader::new(bytes);
    let mut labels: Vec<String> = Vec::new();
    while r.remaining() > 0 {
        let len = usize::from(r.u8()?);
        if len == 0 || len > MAX_LABEL_LEN {
            return Err(NasError::DecodingError(format!(
                "{what}: invalid label length {len}"
            )));
        }
        let label = r.take(len)?;
        if !label.is_ascii() {
            return Err(NasError::DecodingError(format!(
                "{what}: non-ASCII label octets"
            )));
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
    }
    if labels.is_empty() {
        return Err(NasError::DecodingError(format!(
            "{what}: at least one label required"
        )));
    }
    Ok(labels.join("."))
}

// =========================================================================
// TS 24.526 §5.2 — URSP part contents
// =========================================================================

/// Traffic descriptor component (TS 24.526 Table 5.2.1 identifiers,
/// specs/24526-i50.txt:2466-2498; value encodings :2500-2612).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficDescriptorComponent {
    /// 0b00000001 Match-all type (:2467) — no value field (:2500-2502).
    MatchAll,
    /// 0b00001000 OS Id + OS App Id type (:2468) — 16-octet OS Id UUID
    /// (RFC 4122) + 1-octet OS App Id length + OS App Id (:2504-2506).
    OsIdOsAppId { os_id: [u8; 16], os_app_id: Vec<u8> },
    /// 0b00010000 IPv4 remote address type (:2469) — 4-octet address +
    /// 4-octet mask (:2508-2509).
    Ipv4RemoteAddress { addr: [u8; 4], mask: [u8; 4] },
    /// 0b00100001 IPv6 remote address/prefix length type (:2470) — 16-octet
    /// address + 1-octet prefix length (:2511-2512).
    Ipv6RemoteAddress { addr: [u8; 16], prefix_len: u8 },
    /// 0b00110000 Protocol identifier/next header type (:2471) — one octet
    /// (:2516-2517).
    ProtocolIdentifier(u8),
    /// 0b01010000 Single remote port type (:2472) — two octets (:2519).
    SingleRemotePort(u16),
    /// 0b01010001 Remote port range type (:2473) — 2-octet low limit +
    /// 2-octet high limit, low first (:2521-2522).
    RemotePortRange { low: u16, high: u16 },
    /// 0b10001000 DNN type (:2486) — 1-octet DNN length + APN value per
    /// TS 23.003 (:2593-2594).
    Dnn(String),
    /// 0b10010001 Destination FQDN type (:2488) — 1-octet length + FQDN per
    /// TS 23.003 §28.3.2.1 (:2601-2603).
    DestinationFqdn(String),
    /// UNREPRESENTABLE: TS 24.526 V18.5.0 Table 5.2.1 defines no S-NSSAI
    /// traffic descriptor component identifier (all unlisted values are
    /// spare, specs/24526-i50.txt:2497-2498). Encoding always returns `Err`
    /// (fail-closed) — see the module docs.
    SNssai { sst: u8, sd: Option<[u8; 3]> },
}

/// Traffic descriptor component type identifiers (Table 5.2.1).
const TD_ID_MATCH_ALL: u8 = 0b0000_0001;
const TD_ID_OS_ID_OS_APP_ID: u8 = 0b0000_1000;
const TD_ID_IPV4_REMOTE: u8 = 0b0001_0000;
const TD_ID_IPV6_REMOTE: u8 = 0b0010_0001;
const TD_ID_PROTOCOL: u8 = 0b0011_0000;
const TD_ID_SINGLE_REMOTE_PORT: u8 = 0b0101_0000;
const TD_ID_REMOTE_PORT_RANGE: u8 = 0b0101_0001;
const TD_ID_DNN: u8 = 0b1000_1000;
const TD_ID_DEST_FQDN: u8 = 0b1001_0001;

impl TrafficDescriptorComponent {
    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        match self {
            Self::MatchAll => out.push(TD_ID_MATCH_ALL),
            Self::OsIdOsAppId { os_id, os_app_id } => {
                if os_app_id.len() > 255 {
                    return Err(NasError::EncodingError(
                        "OS App Id exceeds its 1-octet length field".into(),
                    ));
                }
                out.push(TD_ID_OS_ID_OS_APP_ID);
                out.extend_from_slice(os_id);
                out.push(os_app_id.len() as u8);
                out.extend_from_slice(os_app_id);
            }
            Self::Ipv4RemoteAddress { addr, mask } => {
                out.push(TD_ID_IPV4_REMOTE);
                out.extend_from_slice(addr);
                out.extend_from_slice(mask);
            }
            Self::Ipv6RemoteAddress { addr, prefix_len } => {
                if *prefix_len > 128 {
                    return Err(NasError::EncodingError(format!(
                        "IPv6 prefix length {prefix_len} exceeds 128"
                    )));
                }
                out.push(TD_ID_IPV6_REMOTE);
                out.extend_from_slice(addr);
                out.push(*prefix_len);
            }
            Self::ProtocolIdentifier(p) => {
                out.push(TD_ID_PROTOCOL);
                out.push(*p);
            }
            Self::SingleRemotePort(p) => {
                out.push(TD_ID_SINGLE_REMOTE_PORT);
                out.extend_from_slice(&p.to_be_bytes());
            }
            Self::RemotePortRange { low, high } => {
                if low > high {
                    return Err(NasError::EncodingError(format!(
                        "remote port range low limit {low} exceeds high limit {high}"
                    )));
                }
                out.push(TD_ID_REMOTE_PORT_RANGE);
                out.extend_from_slice(&low.to_be_bytes());
                out.extend_from_slice(&high.to_be_bytes());
            }
            Self::Dnn(dnn) => {
                let apn = encode_labels(dnn, MAX_APN_LEN, "TD DNN")?;
                out.push(TD_ID_DNN);
                out.push(apn.len() as u8);
                out.extend_from_slice(&apn);
            }
            Self::DestinationFqdn(fqdn) => {
                let v = encode_labels(fqdn, MAX_FQDN_LEN, "TD destination FQDN")?;
                out.push(TD_ID_DEST_FQDN);
                out.push(v.len() as u8);
                out.extend_from_slice(&v);
            }
            Self::SNssai { .. } => {
                return Err(NasError::EncodingError(
                    "S-NSSAI traffic descriptor is unrepresentable: TS 24.526 V18.5.0 \
                     Table 5.2.1 defines no S-NSSAI TD component type identifier \
                     (all other values are spare); S-NSSAI exists only as a route \
                     selection descriptor component (0b00000010) — refusing to emit"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let id = r.u8()?;
        Ok(match id {
            TD_ID_MATCH_ALL => Self::MatchAll,
            TD_ID_OS_ID_OS_APP_ID => {
                let mut os_id = [0u8; 16];
                os_id.copy_from_slice(r.take(16)?);
                let len = usize::from(r.u8()?);
                Self::OsIdOsAppId {
                    os_id,
                    os_app_id: r.take(len)?.to_vec(),
                }
            }
            TD_ID_IPV4_REMOTE => {
                let mut addr = [0u8; 4];
                addr.copy_from_slice(r.take(4)?);
                let mut mask = [0u8; 4];
                mask.copy_from_slice(r.take(4)?);
                Self::Ipv4RemoteAddress { addr, mask }
            }
            TD_ID_IPV6_REMOTE => {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(r.take(16)?);
                let prefix_len = r.u8()?;
                if prefix_len > 128 {
                    return Err(NasError::DecodingError(format!(
                        "IPv6 prefix length {prefix_len} exceeds 128"
                    )));
                }
                Self::Ipv6RemoteAddress { addr, prefix_len }
            }
            TD_ID_PROTOCOL => Self::ProtocolIdentifier(r.u8()?),
            TD_ID_SINGLE_REMOTE_PORT => Self::SingleRemotePort(r.u16()?),
            TD_ID_REMOTE_PORT_RANGE => {
                let low = r.u16()?;
                let high = r.u16()?;
                if low > high {
                    return Err(NasError::DecodingError(format!(
                        "remote port range low limit {low} exceeds high limit {high}"
                    )));
                }
                Self::RemotePortRange { low, high }
            }
            TD_ID_DNN => {
                let len = usize::from(r.u8()?);
                Self::Dnn(decode_labels(r.take(len)?, "TD DNN")?)
            }
            TD_ID_DEST_FQDN => {
                let len = usize::from(r.u8()?);
                Self::DestinationFqdn(decode_labels(r.take(len)?, "TD destination FQDN")?)
            }
            other => {
                return Err(NasError::DecodingError(format!(
                    "unknown/unsupported traffic descriptor component type identifier {other:#04x} \
                     (TS 24.526 Table 5.2.1)"
                )));
            }
        })
    }
}

/// Preferred access type value (TS 24.501 §9.11.2.1A value part, bits 2..1:
/// 0b01 = 3GPP access, 0b10 = non-3GPP access; specs/24501-j62.txt:
/// 71944-71958). A dedicated enum (rather than the 5GMM `AccessType`) keeps
/// the invalid "both" value unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PreferredAccessType {
    /// 3GPP access (0b01).
    ThreeGpp = 1,
    /// Non-3GPP access (0b10).
    NonThreeGpp = 2,
}

/// Route selection descriptor component (TS 24.526 Table 5.2.1 identifiers,
/// specs/24526-i50.txt:2686-2707; value encodings :2709-2726).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSelectionDescriptorComponent {
    /// 0b00000001 SSC mode type (:2691) — 1 octet, bits 3..1 per TS 24.501
    /// §9.11.4.16, bits 8..4 spare (:2709-2711). At most once per RSD.
    SscMode(SscMode),
    /// 0b00000010 S-NSSAI type (:2692) — 1-octet length + value per
    /// TS 24.501 §9.11.2.8 WITHOUT the mapped-HPLMN fields (:2713-2715):
    /// length 1 = SST only, length 4 = SST + 3-octet SD.
    SNssai { sst: u8, sd: Option<[u8; 3]> },
    /// 0b00000100 DNN type (:2693) — 1-octet DNN length + APN (:2717-2718).
    Dnn(String),
    /// 0b00001000 PDU session type type (:2694) — 1 octet, bits 3..1 per
    /// TS 24.501 §9.11.4.11, bits 8..4 spare (:2720-2722). At most once.
    PduSessionType(PduSessionType),
    /// 0b00010000 Preferred access type type (:2695) — 1 octet, bits 2..1
    /// per TS 24.501 §9.11.2.1A, bits 8..3 spare (:2724-2726). At most once.
    PreferredAccessType(PreferredAccessType),
}

/// RSD component type identifiers (Table 5.2.1).
const RSD_ID_SSC_MODE: u8 = 0b0000_0001;
const RSD_ID_SNSSAI: u8 = 0b0000_0010;
const RSD_ID_DNN: u8 = 0b0000_0100;
const RSD_ID_PDU_SESSION_TYPE: u8 = 0b0000_1000;
const RSD_ID_PREFERRED_ACCESS: u8 = 0b0001_0000;

impl RouteSelectionDescriptorComponent {
    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        match self {
            Self::SscMode(mode) => {
                out.push(RSD_ID_SSC_MODE);
                out.push(*mode as u8);
            }
            Self::SNssai { sst, sd } => {
                out.push(RSD_ID_SNSSAI);
                match sd {
                    None => {
                        out.push(1); // length 1 => SST only (TS 24.501 §9.11.2.8)
                        out.push(*sst);
                    }
                    Some(sd) => {
                        out.push(4); // length 4 => SST + SD
                        out.push(*sst);
                        out.extend_from_slice(sd);
                    }
                }
            }
            Self::Dnn(dnn) => {
                let apn = encode_labels(dnn, MAX_APN_LEN, "RSD DNN")?;
                out.push(RSD_ID_DNN);
                out.push(apn.len() as u8);
                out.extend_from_slice(&apn);
            }
            Self::PduSessionType(t) => {
                out.push(RSD_ID_PDU_SESSION_TYPE);
                out.push(*t as u8);
            }
            Self::PreferredAccessType(t) => {
                out.push(RSD_ID_PREFERRED_ACCESS);
                out.push(*t as u8);
            }
        }
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let id = r.u8()?;
        Ok(match id {
            RSD_ID_SSC_MODE => {
                let b = r.u8()?;
                if b & 0xF8 != 0 {
                    return Err(NasError::DecodingError(
                        "SSC mode component: spare bits 8..4 set".into(),
                    ));
                }
                let mode = match b & 0x07 {
                    1 => SscMode::SscMode1,
                    2 => SscMode::SscMode2,
                    3 => SscMode::SscMode3,
                    v => {
                        return Err(NasError::DecodingError(format!(
                            "SSC mode component: invalid SSC mode value {v} (TS 24.501 §9.11.4.16)"
                        )));
                    }
                };
                Self::SscMode(mode)
            }
            RSD_ID_SNSSAI => {
                let len = usize::from(r.u8()?);
                match len {
                    // TS 24.526 :2713-2715 — value per TS 24.501 §9.11.2.8
                    // without mapped-HPLMN fields: only SST (1) or SST+SD (4).
                    1 => Self::SNssai {
                        sst: r.u8()?,
                        sd: None,
                    },
                    4 => {
                        let sst = r.u8()?;
                        let mut sd = [0u8; 3];
                        sd.copy_from_slice(r.take(3)?);
                        Self::SNssai { sst, sd: Some(sd) }
                    }
                    other => {
                        return Err(NasError::DecodingError(format!(
                            "RSD S-NSSAI component: invalid length {other} \
                             (must be 1 or 4 without mapped-HPLMN fields)"
                        )));
                    }
                }
            }
            RSD_ID_DNN => {
                let len = usize::from(r.u8()?);
                Self::Dnn(decode_labels(r.take(len)?, "RSD DNN")?)
            }
            RSD_ID_PDU_SESSION_TYPE => {
                let b = r.u8()?;
                if b & 0xF8 != 0 {
                    return Err(NasError::DecodingError(
                        "PDU session type component: spare bits 8..4 set".into(),
                    ));
                }
                let t = match b & 0x07 {
                    1 => PduSessionType::Ipv4,
                    2 => PduSessionType::Ipv6,
                    3 => PduSessionType::Ipv4v6,
                    4 => PduSessionType::Unstructured,
                    5 => PduSessionType::Ethernet,
                    v => {
                        return Err(NasError::DecodingError(format!(
                            "PDU session type component: invalid value {v} (TS 24.501 §9.11.4.11)"
                        )));
                    }
                };
                Self::PduSessionType(t)
            }
            RSD_ID_PREFERRED_ACCESS => {
                let b = r.u8()?;
                if b & 0xFC != 0 {
                    return Err(NasError::DecodingError(
                        "preferred access type component: spare bits 8..3 set".into(),
                    ));
                }
                let t = match b & 0x03 {
                    1 => PreferredAccessType::ThreeGpp,
                    2 => PreferredAccessType::NonThreeGpp,
                    v => {
                        return Err(NasError::DecodingError(format!(
                            "preferred access type component: invalid value {v} \
                             (TS 24.501 §9.11.2.1A)"
                        )));
                    }
                };
                Self::PreferredAccessType(t)
            }
            other => {
                return Err(NasError::DecodingError(format!(
                    "unknown/unsupported RSD component type identifier {other:#04x} \
                     (TS 24.526 Table 5.2.1)"
                )));
            }
        })
    }

    /// True for components the spec forbids from appearing more than once in
    /// one RSD (TS 24.526 Table 5.2.1: SSC mode :2709-2711, PDU session type
    /// :2720-2722, preferred access type :2724-2726).
    fn is_singleton(&self) -> bool {
        matches!(
            self,
            Self::SscMode(_) | Self::PduSessionType(_) | Self::PreferredAccessType(_)
        )
    }

    fn kind_id(&self) -> u8 {
        match self {
            Self::SscMode(_) => RSD_ID_SSC_MODE,
            Self::SNssai { .. } => RSD_ID_SNSSAI,
            Self::Dnn(_) => RSD_ID_DNN,
            Self::PduSessionType(_) => RSD_ID_PDU_SESSION_TYPE,
            Self::PreferredAccessType(_) => RSD_ID_PREFERRED_ACCESS,
        }
    }
}

/// Route selection descriptor (TS 24.526 Figure 5.2.4: 2-octet length +
/// 1-octet precedence + 2-octet contents length + components).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSelectionDescriptor {
    /// Precedence among the RSDs of one rule; higher value = lower precedence
    /// (Table 5.2.1, specs/24526-i50.txt:2674-2678).
    pub precedence: u8,
    /// At least one component (Table 5.2.1, :2681-2684).
    pub components: Vec<RouteSelectionDescriptorComponent>,
}

impl RouteSelectionDescriptor {
    fn validate(&self) -> NasResult<()> {
        if self.components.is_empty() {
            return Err(NasError::EncodingError(
                "route selection descriptor must contain at least one component \
                 (TS 24.526 Table 5.2.1)"
                    .into(),
            ));
        }
        for (i, c) in self.components.iter().enumerate() {
            if c.is_singleton()
                && self.components[i + 1..]
                    .iter()
                    .any(|d| d.kind_id() == c.kind_id())
            {
                return Err(NasError::EncodingError(format!(
                    "RSD component {:#04x} shall not appear more than once in the \
                     route selection descriptor (TS 24.526 Table 5.2.1)",
                    c.kind_id()
                )));
            }
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        self.validate()?;
        let mut contents = Vec::new();
        for c in &self.components {
            c.encode_into(&mut contents)?;
        }
        // Figure 5.2.4: length of RSD counts precedence + contents-length
        // field + contents.
        push_u16_len(out, 1 + 2 + contents.len(), "route selection descriptor")?;
        out.push(self.precedence);
        push_u16_len(out, contents.len(), "route selection descriptor contents")?;
        out.extend_from_slice(&contents);
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let rsd_len = usize::from(r.u16()?);
        let mut rsd = Reader::new(r.take(rsd_len)?);
        let precedence = rsd.u8()?;
        let contents_len = usize::from(rsd.u16()?);
        let mut contents = Reader::new(rsd.take(contents_len)?);
        rsd.finish("route selection descriptor")?;
        let mut components = Vec::new();
        while contents.remaining() > 0 {
            components.push(RouteSelectionDescriptorComponent::decode_one(
                &mut contents,
            )?);
        }
        contents.finish("route selection descriptor contents")?;
        let out = Self {
            precedence,
            components,
        };
        // Re-apply the encode-side constraints (strict symmetric decode).
        out.validate()
            .map_err(|e| NasError::DecodingError(e.to_string()))?;
        Ok(out)
    }
}

/// URSP rule (TS 24.526 Figure 5.2.2). The optional trailing octet is the
/// "Additional indications" field of Figure 5.2.4A (bit 1 = URERI, bits 8..2
/// spare).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrspRule {
    /// Precedence among all rules of the URSP; higher value = lower
    /// precedence; unique within one URSP (Table 5.2.1 + NOTE 10).
    pub precedence: u8,
    /// The rule's single wire-level traffic descriptor: a set of components
    /// (at least one, Table 5.2.1 :2455-2460).
    pub traffic_descriptor: Vec<TrafficDescriptorComponent>,
    /// At least one route selection descriptor (Figure 5.2.3).
    pub route_selection_descriptors: Vec<RouteSelectionDescriptor>,
    /// Figure 5.2.4A URERI ("URSP rule enforcement report indication")
    /// additional-indications octet; `None` omits the octet.
    pub ureri: Option<bool>,
}

impl UrspRule {
    fn validate(&self) -> NasResult<()> {
        if self.traffic_descriptor.is_empty() {
            return Err(NasError::EncodingError(
                "traffic descriptor must contain at least one component \
                 (TS 24.526 Table 5.2.1)"
                    .into(),
            ));
        }
        let has_match_all = self
            .traffic_descriptor
            .contains(&TrafficDescriptorComponent::MatchAll);
        if has_match_all && self.traffic_descriptor.len() != 1 {
            return Err(NasError::EncodingError(
                "a traffic descriptor containing match-all shall contain no other \
                 component (TS 24.526 Table 5.2.1, specs/24526-i50.txt:2500-2502)"
                    .into(),
            ));
        }
        if self.route_selection_descriptors.is_empty() {
            return Err(NasError::EncodingError(
                "URSP rule must contain at least one route selection descriptor \
                 (TS 24.526 Figure 5.2.3)"
                    .into(),
            ));
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        self.validate()?;
        let mut td = Vec::new();
        for c in &self.traffic_descriptor {
            c.encode_into(&mut td)?;
        }
        let mut rsd_list = Vec::new();
        for rsd in &self.route_selection_descriptors {
            rsd.encode_into(&mut rsd_list)?;
        }
        let extra = usize::from(self.ureri.is_some());
        // Figure 5.2.2: length of URSP rule counts precedence + TD length
        // field + TD + RSD-list length field + RSD list (+ additional
        // indications when present).
        push_u16_len(
            out,
            1 + 2 + td.len() + 2 + rsd_list.len() + extra,
            "URSP rule",
        )?;
        out.push(self.precedence);
        push_u16_len(out, td.len(), "traffic descriptor")?;
        out.extend_from_slice(&td);
        push_u16_len(out, rsd_list.len(), "route selection descriptor list")?;
        out.extend_from_slice(&rsd_list);
        if let Some(ureri) = self.ureri {
            out.push(u8::from(ureri)); // Figure 5.2.4A: bit 1 URERI, rest spare
        }
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let rule_len = usize::from(r.u16()?);
        let mut rule = Reader::new(r.take(rule_len)?);
        let precedence = rule.u8()?;
        let td_len = usize::from(rule.u16()?);
        let mut td = Reader::new(rule.take(td_len)?);
        let mut traffic_descriptor = Vec::new();
        while td.remaining() > 0 {
            traffic_descriptor.push(TrafficDescriptorComponent::decode_one(&mut td)?);
        }
        td.finish("traffic descriptor")?;
        let rsdl_len = usize::from(rule.u16()?);
        let mut rsdl = Reader::new(rule.take(rsdl_len)?);
        let mut route_selection_descriptors = Vec::new();
        while rsdl.remaining() > 0 {
            route_selection_descriptors.push(RouteSelectionDescriptor::decode_one(&mut rsdl)?);
        }
        rsdl.finish("route selection descriptor list")?;
        // Figure 5.2.2: at most one optional trailing "Additional
        // indications" octet (Figure 5.2.4A) may remain in the rule scope.
        let ureri = match rule.remaining() {
            0 => None,
            1 => {
                let b = rule.u8()?;
                if b & 0xFE != 0 {
                    return Err(NasError::DecodingError(
                        "additional indications: spare bits 8..2 set (Figure 5.2.4A)".into(),
                    ));
                }
                Some(b & 0x01 == 0x01)
            }
            n => {
                return Err(NasError::DecodingError(format!(
                    "URSP rule: {n} unexpected octets after the route selection \
                     descriptor list"
                )));
            }
        };
        rule.finish("URSP rule")?;
        let out = Self {
            precedence,
            traffic_descriptor,
            route_selection_descriptors,
            ureri,
        };
        out.validate()
            .map_err(|e| NasError::DecodingError(e.to_string()))?;
        Ok(out)
    }
}

/// Encodes UE policy part contents of type URSP: one or more URSP rules
/// concatenated (TS 24.526 Figure 5.2.1). Fail-closed: rejects an empty rule
/// set, duplicate rule precedence values (Table 5.2.1: "Multiple URSP rules
/// in the URSP shall not have the same precedence value") and more than one
/// match-all traffic descriptor across the whole URSP (specs/24526-i50.txt:
/// 2500-2502).
pub fn encode_ursp_rules(rules: &[UrspRule]) -> NasResult<Vec<u8>> {
    if rules.is_empty() {
        return Err(NasError::EncodingError(
            "URSP part contents must contain at least one URSP rule \
             (TS 24.526 Figure 5.2.1)"
                .into(),
        ));
    }
    let mut seen_precedence = [false; 256];
    let mut match_all_count = 0usize;
    for rule in rules {
        let p = usize::from(rule.precedence);
        if seen_precedence[p] {
            return Err(NasError::EncodingError(format!(
                "duplicate URSP rule precedence {p}: multiple URSP rules shall not \
                 have the same precedence value (TS 24.526 Table 5.2.1)"
            )));
        }
        seen_precedence[p] = true;
        if rule
            .traffic_descriptor
            .contains(&TrafficDescriptorComponent::MatchAll)
        {
            match_all_count += 1;
        }
    }
    if match_all_count > 1 {
        return Err(NasError::EncodingError(
            "the match-all traffic descriptor component shall not appear more than \
             once among all traffic descriptors of the whole URSP rules \
             (TS 24.526 Table 5.2.1)"
                .into(),
        ));
    }
    let mut out = Vec::new();
    for rule in rules {
        rule.encode_into(&mut out)?;
    }
    Ok(out)
}

/// Strict inverse of [`encode_ursp_rules`].
pub fn decode_ursp_rules(bytes: &[u8]) -> NasResult<Vec<UrspRule>> {
    let mut r = Reader::new(bytes);
    let mut rules = Vec::new();
    while r.remaining() > 0 {
        rules.push(UrspRule::decode_one(&mut r)?);
    }
    r.finish("URSP part contents")?;
    if rules.is_empty() {
        return Err(NasError::DecodingError(
            "URSP part contents must contain at least one URSP rule".into(),
        ));
    }
    Ok(rules)
}

// =========================================================================
// TS 24.501 D.6.2 — UE policy section management list
// =========================================================================

/// UE policy part type (TS 24.501 Table D.6.2.1, specs/24501-j62.txt:
/// 96667-96690: 0001 URSP, 0010 ANDSP, 0011 V2XP, 0100 ProSeP, 0101 A2XP,
/// 0110 RSLPP; 0000 and 0111..1111 reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UePolicyPartType {
    /// URSP (0001).
    Ursp = 0x01,
    /// ANDSP (0010).
    Andsp = 0x02,
    /// V2XP (0011).
    V2xp = 0x03,
    /// ProSeP (0100).
    ProSeP = 0x04,
    /// A2XP (0101).
    A2xp = 0x05,
    /// RSLPP (0110).
    Rslpp = 0x06,
}

impl UePolicyPartType {
    fn from_bits(v: u8) -> NasResult<Self> {
        Ok(match v {
            0x01 => Self::Ursp,
            0x02 => Self::Andsp,
            0x03 => Self::V2xp,
            0x04 => Self::ProSeP,
            0x05 => Self::A2xp,
            0x06 => Self::Rslpp,
            other => {
                return Err(NasError::DecodingError(format!(
                    "reserved UE policy part type {other:#03x} (TS 24.501 Table D.6.2.1)"
                )));
            }
        })
    }
}

/// UE policy part (Figure D.6.2.7): 2-octet contents length (which INCLUDES
/// the part-type octet per Table D.6.2.1 NOTE 2) + part-type octet (bits 8..5
/// spare) + contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UePolicyPart {
    /// Part type (bits 4..1 of octet q+2).
    pub part_type: UePolicyPartType,
    /// Part contents (octets q+3..r) — for `Ursp`, the TS 24.526 §5.2 bytes.
    pub contents: Vec<u8>,
}

impl UePolicyPart {
    /// Builds a URSP part from URSP rules via [`encode_ursp_rules`].
    pub fn ursp(rules: &[UrspRule]) -> NasResult<Self> {
        Ok(Self {
            part_type: UePolicyPartType::Ursp,
            contents: encode_ursp_rules(rules)?,
        })
    }

    /// Decodes the part contents as URSP rules (fails if the part type is
    /// not URSP).
    pub fn decode_ursp(&self) -> NasResult<Vec<UrspRule>> {
        if self.part_type != UePolicyPartType::Ursp {
            return Err(NasError::DecodingError(format!(
                "UE policy part type {:?} is not URSP",
                self.part_type
            )));
        }
        decode_ursp_rules(&self.contents)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        if self.contents.is_empty() {
            return Err(NasError::EncodingError(
                "UE policy part contents must not be empty (Figure D.6.2.7)".into(),
            ));
        }
        // NOTE 2: contents length covers octet q+2..r, i.e. INCLUDES the
        // part-type octet (specs/24501-j62.txt:96710-96711).
        push_u16_len(out, 1 + self.contents.len(), "UE policy part contents")?;
        out.push(self.part_type as u8); // bits 8..5 spare = 0
        out.extend_from_slice(&self.contents);
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let part_len = usize::from(r.u16()?);
        if part_len == 0 {
            return Err(NasError::DecodingError(
                "UE policy part contents length must cover at least the part-type \
                 octet (Table D.6.2.1 NOTE 2)"
                    .into(),
            ));
        }
        let mut part = Reader::new(r.take(part_len)?);
        let type_octet = part.u8()?;
        if type_octet & 0xF0 != 0 {
            return Err(NasError::DecodingError(
                "UE policy part: spare bits 8..5 of the part-type octet set \
                 (Table D.6.2.1)"
                    .into(),
            ));
        }
        let part_type = UePolicyPartType::from_bits(type_octet & 0x0F)?;
        let contents = part.take(part.remaining())?.to_vec();
        part.finish("UE policy part")?;
        Ok(Self {
            part_type,
            contents,
        })
    }
}

/// Instruction (Figure D.6.2.5): 2-octet contents length (counts UPSC +
/// parts) + 2-octet UPSC + UE policy section contents (zero or more parts —
/// an instruction with no parts orders deletion of the section, D.2.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// UE policy section code, set by the PCF (Table D.6.2.1).
    pub upsc: u16,
    /// UE policy parts (Figure D.6.2.6).
    pub parts: Vec<UePolicyPart>,
}

impl Instruction {
    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        let mut parts = Vec::new();
        for p in &self.parts {
            p.encode_into(&mut parts)?;
        }
        push_u16_len(out, 2 + parts.len(), "instruction contents")?;
        out.extend_from_slice(&self.upsc.to_be_bytes());
        out.extend_from_slice(&parts);
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let instr_len = usize::from(r.u16()?);
        let mut instr = Reader::new(r.take(instr_len)?);
        let upsc = instr.u16()?;
        let mut parts = Vec::new();
        while instr.remaining() > 0 {
            parts.push(UePolicyPart::decode_one(&mut instr)?);
        }
        instr.finish("instruction")?;
        Ok(Self { upsc, parts })
    }
}

/// UE policy section management sublist (Figure D.6.2.3): 2-octet length
/// (counts MCC/MNC + contents) + 3-octet BCD PLMN + one or more instructions
/// (Figure D.6.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlmnSublist {
    /// The PLMN this sublist applies to (BCD coding per Table D.6.2.1;
    /// 2-digit MNC => MNC digit 3 = 0b1111, NOTE at specs/24501-j62.txt:96628).
    pub plmn_id: PlmnId,
    /// At least one instruction (Figure D.6.2.4).
    pub instructions: Vec<Instruction>,
}

impl PlmnSublist {
    fn encode_into(&self, out: &mut Vec<u8>) -> NasResult<()> {
        if self.instructions.is_empty() {
            return Err(NasError::EncodingError(
                "UE policy section management sublist must contain at least one \
                 instruction (Figure D.6.2.4)"
                    .into(),
            ));
        }
        let plmn = encode_plmn_bcd(&self.plmn_id)?;
        let mut instructions = Vec::new();
        for i in &self.instructions {
            i.encode_into(&mut instructions)?;
        }
        push_u16_len(
            out,
            3 + instructions.len(),
            "UE policy section management sublist",
        )?;
        out.extend_from_slice(&plmn);
        out.extend_from_slice(&instructions);
        Ok(())
    }

    fn decode_one(r: &mut Reader) -> NasResult<Self> {
        let sublist_len = usize::from(r.u16()?);
        let mut sublist = Reader::new(r.take(sublist_len)?);
        let plmn_id = decode_plmn_bcd(sublist.take(3)?)?;
        let mut instructions = Vec::new();
        while sublist.remaining() > 0 {
            instructions.push(Instruction::decode_one(&mut sublist)?);
        }
        sublist.finish("UE policy section management sublist")?;
        if instructions.is_empty() {
            return Err(NasError::DecodingError(
                "UE policy section management sublist must contain at least one \
                 instruction (Figure D.6.2.4)"
                    .into(),
            ));
        }
        Ok(Self {
            plmn_id,
            instructions,
        })
    }
}

/// UE policy section management list (TS 24.501 D.6.2, figures
/// D.6.2.1-D.6.2.7): one or more per-PLMN sublists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UePolicySectionManagementList {
    /// One or more sublists (Figure D.6.2.2).
    pub sublists: Vec<PlmnSublist>,
}

impl UePolicySectionManagementList {
    /// Encodes the list contents (octets 4..z of Figure D.6.2.1 — without
    /// any IEI/length prefix).
    fn encode_contents(&self) -> NasResult<Vec<u8>> {
        if self.sublists.is_empty() {
            return Err(NasError::EncodingError(
                "UE policy section management list must contain at least one \
                 sublist (Figure D.6.2.2)"
                    .into(),
            ));
        }
        let mut out = Vec::new();
        for s in &self.sublists {
            s.encode_into(&mut out)?;
        }
        if out.len() > MAX_LIST_LVE_CONTENTS {
            return Err(NasError::EncodingError(format!(
                "UE policy section management list contents {} exceed {} octets \
                 (LV-E bound 11-65533 of Table D.5.1.1.1 / 65535-octet payload \
                 container cap of TS 24.501 §9.11.3.39.1)",
                out.len(),
                MAX_LIST_LVE_CONTENTS
            )));
        }
        Ok(out)
    }

    /// Encodes the LV-E form used inside MANAGE UE POLICY COMMAND
    /// (Table D.5.1.1.1: 2-octet length + contents, no IEI).
    pub fn encode_lv_e(&self) -> NasResult<Vec<u8>> {
        let contents = self.encode_contents()?;
        let mut out = Vec::with_capacity(2 + contents.len());
        push_u16_len(
            &mut out,
            contents.len(),
            "UE policy section management list",
        )?;
        out.extend_from_slice(&contents);
        Ok(out)
    }

    fn decode_contents(bytes: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(bytes);
        let mut sublists = Vec::new();
        while r.remaining() > 0 {
            sublists.push(PlmnSublist::decode_one(&mut r)?);
        }
        r.finish("UE policy section management list contents")?;
        if sublists.is_empty() {
            return Err(NasError::DecodingError(
                "UE policy section management list must contain at least one \
                 sublist (Figure D.6.2.2)"
                    .into(),
            ));
        }
        Ok(Self { sublists })
    }

    /// Strict inverse of [`Self::encode_lv_e`]: the whole input must be the
    /// LV-E field (2-octet length matching the remaining octets exactly).
    pub fn decode_lv_e(bytes: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(bytes);
        let len = usize::from(r.u16()?);
        let contents = r.take(len)?;
        r.finish("UE policy section management list LV-E")?;
        Self::decode_contents(contents)
    }
}

// =========================================================================
// TS 24.501 D.6.3 — UE policy section management result
// =========================================================================

/// One D.6.3 result (Figure D.6.3.5): UPSC + failed instruction order
/// (1-based per Table D.6.3.1) + cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UePolicyResult {
    /// UPSC of the failed instruction's section.
    pub upsc: u16,
    /// 1-based order of the failed instruction within the sublist contents.
    pub failed_instruction_order: u16,
    /// Cause octet; only [`UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED`] is
    /// assigned — the receiving entity shall treat any other value as it
    /// (Table D.6.3.1).
    pub cause: u8,
}

/// UE policy section management subresult (Figure D.6.3.3): 1-octet result
/// count + 3-octet BCD PLMN + count x 5-octet results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UePolicySectionManagementSubresult {
    /// The PLMN the results apply to (same BCD coding as D.6.2.3).
    pub plmn_id: PlmnId,
    /// One or more results (1..=255, the count is a single octet).
    pub results: Vec<UePolicyResult>,
}

/// UE policy section management result (D.6.3): one or more subresults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UePolicySectionManagementResult {
    /// One or more subresults (Figure D.6.3.2).
    pub subresults: Vec<UePolicySectionManagementSubresult>,
}

impl UePolicySectionManagementResult {
    fn encode_contents(&self) -> NasResult<Vec<u8>> {
        if self.subresults.is_empty() {
            return Err(NasError::EncodingError(
                "UE policy section management result must contain at least one \
                 subresult (Figure D.6.3.2)"
                    .into(),
            ));
        }
        let mut out = Vec::new();
        for s in &self.subresults {
            if s.results.is_empty() {
                return Err(NasError::EncodingError(
                    "UE policy section management subresult must contain at least \
                     one result (Table D.6.3.1)"
                        .into(),
                ));
            }
            let count = u8::try_from(s.results.len()).map_err(|_| {
                NasError::EncodingError(
                    "subresult holds more than 255 results (1-octet count, \
                     Figure D.6.3.3)"
                        .into(),
                )
            })?;
            out.push(count);
            out.extend_from_slice(&encode_plmn_bcd(&s.plmn_id)?);
            for res in &s.results {
                out.extend_from_slice(&res.upsc.to_be_bytes());
                out.extend_from_slice(&res.failed_instruction_order.to_be_bytes());
                out.push(res.cause);
            }
        }
        if out.len() > MAX_RESULT_LVE_CONTENTS {
            return Err(NasError::EncodingError(format!(
                "UE policy section management result contents {} exceed {} octets \
                 (LV-E bound of Table D.5.3.1.1)",
                out.len(),
                MAX_RESULT_LVE_CONTENTS
            )));
        }
        Ok(out)
    }

    fn decode_contents(bytes: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(bytes);
        let mut subresults = Vec::new();
        while r.remaining() > 0 {
            let count = usize::from(r.u8()?);
            if count == 0 {
                return Err(NasError::DecodingError(
                    "subresult result count must be at least 1 (Table D.6.3.1)".into(),
                ));
            }
            let plmn_id = decode_plmn_bcd(r.take(3)?)?;
            let mut results = Vec::with_capacity(count);
            for _ in 0..count {
                results.push(UePolicyResult {
                    upsc: r.u16()?,
                    failed_instruction_order: r.u16()?,
                    cause: r.u8()?,
                });
            }
            subresults.push(UePolicySectionManagementSubresult { plmn_id, results });
        }
        r.finish("UE policy section management result contents")?;
        if subresults.is_empty() {
            return Err(NasError::DecodingError(
                "UE policy section management result must contain at least one \
                 subresult (Figure D.6.3.2)"
                    .into(),
            ));
        }
        Ok(Self { subresults })
    }
}

// =========================================================================
// TS 24.501 D.6.4 — UPSI list, D.6.5 — UE policy classmark
// =========================================================================

/// UPSI sublist (Figure D.6.4.2): 2-octet length (counts PLMN + UPSCs) +
/// 3-octet BCD PLMN + one or more 2-octet UPSCs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsiSublist {
    /// The PLMN part of the UPSIs.
    pub plmn_id: PlmnId,
    /// One or more UPSCs.
    pub upscs: Vec<u16>,
}

/// UPSI list (D.6.4). Zero sublists is valid: "If no UPSIs are included in
/// the UPSI list, the UE shall set the length of UPSI list contents to zero"
/// (Table D.6.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpsiList {
    /// Zero or more per-PLMN sublists.
    pub sublists: Vec<UpsiSublist>,
}

impl UpsiList {
    fn encode_contents(&self) -> NasResult<Vec<u8>> {
        let mut out = Vec::new();
        for s in &self.sublists {
            if s.upscs.is_empty() {
                return Err(NasError::EncodingError(
                    "UPSI sublist must contain at least one UPSC (Figure D.6.4.2)".into(),
                ));
            }
            push_u16_len(&mut out, 3 + 2 * s.upscs.len(), "UPSI sublist")?;
            out.extend_from_slice(&encode_plmn_bcd(&s.plmn_id)?);
            for upsc in &s.upscs {
                out.extend_from_slice(&upsc.to_be_bytes());
            }
        }
        if out.len() > MAX_UPSI_LVE_CONTENTS {
            return Err(NasError::EncodingError(format!(
                "UPSI list contents {} exceed {} octets (LV-E bound 2-65531 of \
                 Table D.5.4.1.1)",
                out.len(),
                MAX_UPSI_LVE_CONTENTS
            )));
        }
        Ok(out)
    }

    fn decode_contents(bytes: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(bytes);
        let mut sublists = Vec::new();
        while r.remaining() > 0 {
            let len = usize::from(r.u16()?);
            if len < 5 || (len - 3) % 2 != 0 {
                return Err(NasError::DecodingError(format!(
                    "UPSI sublist length {len} is not 3 + 2*n with n >= 1 \
                     (Figure D.6.4.2)"
                )));
            }
            let mut sub = Reader::new(r.take(len)?);
            let plmn_id = decode_plmn_bcd(sub.take(3)?)?;
            let mut upscs = Vec::new();
            while sub.remaining() > 0 {
                upscs.push(sub.u16()?);
            }
            sub.finish("UPSI sublist")?;
            sublists.push(UpsiSublist { plmn_id, upscs });
        }
        r.finish("UPSI list contents")?;
        Ok(Self { sublists })
    }
}

/// UE policy classmark (D.6.5, Figure D.6.5.1 octet 3; bits 8..5 spare).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UePolicyClassmark {
    /// Bit 1: SupportANDSP.
    pub andsp_supported: bool,
    /// Bit 2: EPSURSP (URSP provisioning in EPS supported).
    pub eps_ursp_supported: bool,
    /// Bit 3: SVPSU (VPS URSP supported).
    pub vps_ursp_supported: bool,
    /// Bit 4: SupportRURE (reporting URSP rule enforcement supported).
    pub rure_supported: bool,
}

impl UePolicyClassmark {
    fn flags(&self) -> u8 {
        u8::from(self.andsp_supported)
            | (u8::from(self.eps_ursp_supported) << 1)
            | (u8::from(self.vps_ursp_supported) << 2)
            | (u8::from(self.rure_supported) << 3)
    }

    /// Encodes the LV form used in UE STATE INDICATION (Table D.5.4.1.1:
    /// 1-octet length + 1..3 contents octets; we emit the minimal 1 octet).
    fn encode_lv(&self) -> [u8; 2] {
        [1, self.flags()]
    }

    fn decode_lv(r: &mut Reader) -> NasResult<Self> {
        let len = usize::from(r.u8()?);
        if !(1..=3).contains(&len) {
            return Err(NasError::DecodingError(format!(
                "UE policy classmark contents length {len} outside 1..=3 (D.6.5)"
            )));
        }
        let contents = r.take(len)?;
        if contents[0] & 0xF0 != 0 {
            return Err(NasError::DecodingError(
                "UE policy classmark: spare bits 8..5 of octet 3 set (Figure D.6.5.1)".into(),
            ));
        }
        if contents[1..].iter().any(|b| *b != 0) {
            return Err(NasError::DecodingError(
                "UE policy classmark: spare octets 4..5 must be zero (Table D.6.5.1)".into(),
            ));
        }
        Ok(Self {
            andsp_supported: contents[0] & 0x01 != 0,
            eps_ursp_supported: contents[0] & 0x02 != 0,
            vps_ursp_supported: contents[0] & 0x04 != 0,
            rure_supported: contents[0] & 0x08 != 0,
        })
    }
}

// =========================================================================
// Messages (TS 24.501 D.5)
// =========================================================================

/// Peeks the UE policy delivery service message type (octet 2 of every D.5
/// message: PTI first, then the D.6.1 message type).
pub fn peek_message_type(content: &[u8]) -> NasResult<u8> {
    if content.len() < 2 {
        return Err(NasError::BufferTooShort {
            expected: 2,
            actual: content.len(),
        });
    }
    Ok(content[1])
}

fn check_pcf_pti(pti: u8, msg: &str, encoding: bool) -> NasResult<()> {
    if (PCF_PTI_MIN..=PCF_PTI_MAX).contains(&pti) {
        return Ok(());
    }
    let text = format!(
        "{msg}: PTI {pti:#04x} outside the PCF-initiated range 80H-FEH \
         (TS 24.501 D.1.2)"
    );
    if encoding {
        Err(NasError::EncodingError(text))
    } else {
        Err(NasError::DecodingError(text))
    }
}

/// MANAGE UE POLICY COMMAND (TS 24.501 Table D.5.1.1.1): PTI (M,V,1) +
/// message type (M,V,1, D.6.1) + UE policy section management list
/// (M, LV-E, 11-65533). The optional IEs 0x42 (UE policy network classmark)
/// and 0x70 (VPS URSP configuration) are not supported; decoding rejects any
/// trailing octets (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageUePolicyCommand {
    /// PCF-allocated PTI, 80H-FEH (D.1.2).
    pub pti: u8,
    /// The section management list.
    pub list: UePolicySectionManagementList,
}

impl ManageUePolicyCommand {
    /// Encodes the full message content carried in the Payload container.
    pub fn encode(&self) -> NasResult<Vec<u8>> {
        check_pcf_pti(self.pti, "MANAGE UE POLICY COMMAND", true)?;
        let lv_e = self.list.encode_lv_e()?;
        let mut out = Vec::with_capacity(2 + lv_e.len());
        out.push(self.pti);
        out.push(UPDP_MSG_MANAGE_UE_POLICY_COMMAND);
        out.extend_from_slice(&lv_e);
        debug_assert!(out.len() <= 65535); // §9.11.3.39.1 cap, enforced via the list bound
        Ok(out)
    }

    /// Strict inverse of [`Self::encode`].
    pub fn decode(content: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(content);
        let pti = r.u8()?;
        let msg_type = r.u8()?;
        if msg_type != UPDP_MSG_MANAGE_UE_POLICY_COMMAND {
            return Err(NasError::InvalidMessageType(msg_type));
        }
        check_pcf_pti(pti, "MANAGE UE POLICY COMMAND", false)?;
        let len = usize::from(r.u16()?);
        let contents = r.take(len)?;
        r.finish("MANAGE UE POLICY COMMAND")?;
        Ok(Self {
            pti,
            list: UePolicySectionManagementList::decode_contents(contents)?,
        })
    }
}

/// MANAGE UE POLICY COMPLETE (Table D.5.2.1.1): PTI + message type only.
/// The PTI echoes the command's PTI (D.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManageUePolicyComplete {
    /// Echoed PCF PTI (80H-FEH).
    pub pti: u8,
}

impl ManageUePolicyComplete {
    /// Encodes the 2-octet message.
    pub fn encode(&self) -> NasResult<Vec<u8>> {
        check_pcf_pti(self.pti, "MANAGE UE POLICY COMPLETE", true)?;
        Ok(vec![self.pti, UPDP_MSG_MANAGE_UE_POLICY_COMPLETE])
    }

    /// Strict inverse of [`Self::encode`].
    pub fn decode(content: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(content);
        let pti = r.u8()?;
        let msg_type = r.u8()?;
        if msg_type != UPDP_MSG_MANAGE_UE_POLICY_COMPLETE {
            return Err(NasError::InvalidMessageType(msg_type));
        }
        check_pcf_pti(pti, "MANAGE UE POLICY COMPLETE", false)?;
        r.finish("MANAGE UE POLICY COMPLETE")?;
        Ok(Self { pti })
    }
}

/// MANAGE UE POLICY COMMAND REJECT (Table D.5.3.1.1): PTI + message type +
/// UE policy section management result (M, LV-E, 11-65533, D.6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageUePolicyCommandReject {
    /// Echoed PCF PTI (80H-FEH).
    pub pti: u8,
    /// The per-instruction failure report.
    pub result: UePolicySectionManagementResult,
}

impl ManageUePolicyCommandReject {
    /// Encodes the full message content.
    pub fn encode(&self) -> NasResult<Vec<u8>> {
        check_pcf_pti(self.pti, "MANAGE UE POLICY COMMAND REJECT", true)?;
        let contents = self.result.encode_contents()?;
        let mut out = Vec::with_capacity(4 + contents.len());
        out.push(self.pti);
        out.push(UPDP_MSG_MANAGE_UE_POLICY_COMMAND_REJECT);
        push_u16_len(
            &mut out,
            contents.len(),
            "UE policy section management result",
        )?;
        out.extend_from_slice(&contents);
        Ok(out)
    }

    /// Strict inverse of [`Self::encode`].
    pub fn decode(content: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(content);
        let pti = r.u8()?;
        let msg_type = r.u8()?;
        if msg_type != UPDP_MSG_MANAGE_UE_POLICY_COMMAND_REJECT {
            return Err(NasError::InvalidMessageType(msg_type));
        }
        check_pcf_pti(pti, "MANAGE UE POLICY COMMAND REJECT", false)?;
        let len = usize::from(r.u16()?);
        let contents = r.take(len)?;
        r.finish("MANAGE UE POLICY COMMAND REJECT")?;
        Ok(Self {
            pti,
            result: UePolicySectionManagementResult::decode_contents(contents)?,
        })
    }
}

/// UE OS Id IE identifier in UE STATE INDICATION (Table D.5.4.1.1).
const IEI_UE_OS_ID: u8 = 0x41;

/// UE STATE INDICATION (Table D.5.4.1.1): PTI + message type + UPSI list
/// (M, LV-E, 2-65531, D.6.4) + UE policy classmark (M, LV, 2-4, D.6.5) +
/// optional UE OS Id (IEI 0x41, TLV, 18-242, D.6.6: 1..=15 sixteen-octet
/// UUIDs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeStateIndication {
    /// UE-initiated PTI: 00H ("no procedure transaction identity assigned")
    /// or 01H-77H (D.1.2).
    pub pti: u8,
    /// UPSIs of the UE policy sections stored at the UE.
    pub upsi_list: UpsiList,
    /// The UE's policy classmark.
    pub classmark: UePolicyClassmark,
    /// Zero or more 16-octet OS Id UUIDs (D.6.6); empty omits the IE.
    pub os_ids: Vec<[u8; 16]>,
}

impl UeStateIndication {
    /// Encodes the full message content.
    pub fn encode(&self) -> NasResult<Vec<u8>> {
        if self.pti > UE_PTI_MAX {
            return Err(NasError::EncodingError(format!(
                "UE STATE INDICATION: PTI {:#04x} outside the UE-initiated range \
                 00H/01H-77H (TS 24.501 D.1.2)",
                self.pti
            )));
        }
        if self.os_ids.len() > 15 {
            return Err(NasError::EncodingError(
                "UE OS Id IE holds at most 15 OS Ids (D.6.6: max length 242)".into(),
            ));
        }
        let upsi = self.upsi_list.encode_contents()?;
        let mut out = Vec::with_capacity(6 + upsi.len() + 16 * self.os_ids.len());
        out.push(self.pti);
        out.push(UPDP_MSG_UE_STATE_INDICATION);
        push_u16_len(&mut out, upsi.len(), "UPSI list")?;
        out.extend_from_slice(&upsi);
        out.extend_from_slice(&self.classmark.encode_lv());
        if !self.os_ids.is_empty() {
            out.push(IEI_UE_OS_ID);
            out.push((16 * self.os_ids.len()) as u8);
            for os_id in &self.os_ids {
                out.extend_from_slice(os_id);
            }
        }
        Ok(out)
    }

    /// Strict inverse of [`Self::encode`]; unknown trailing IEs are rejected
    /// (fail-closed — Table D.5.4.1.1 defines exactly one optional IE, 0x41).
    pub fn decode(content: &[u8]) -> NasResult<Self> {
        let mut r = Reader::new(content);
        let pti = r.u8()?;
        let msg_type = r.u8()?;
        if msg_type != UPDP_MSG_UE_STATE_INDICATION {
            return Err(NasError::InvalidMessageType(msg_type));
        }
        if pti > UE_PTI_MAX {
            return Err(NasError::DecodingError(format!(
                "UE STATE INDICATION: PTI {pti:#04x} outside the UE-initiated range \
                 00H/01H-77H (TS 24.501 D.1.2)"
            )));
        }
        let upsi_len = usize::from(r.u16()?);
        let upsi_list = UpsiList::decode_contents(r.take(upsi_len)?)?;
        let classmark = UePolicyClassmark::decode_lv(&mut r)?;
        let mut os_ids = Vec::new();
        if r.remaining() > 0 {
            let iei = r.u8()?;
            if iei != IEI_UE_OS_ID {
                return Err(NasError::InvalidIeType(iei));
            }
            let len = usize::from(r.u8()?);
            if len == 0 || len % 16 != 0 || len > 240 {
                return Err(NasError::DecodingError(format!(
                    "UE OS Id contents length {len} is not a multiple of 16 in \
                     16..=240 (D.6.6)"
                )));
            }
            for _ in 0..(len / 16) {
                let mut os_id = [0u8; 16];
                os_id.copy_from_slice(r.take(16)?);
                os_ids.push(os_id);
            }
        }
        r.finish("UE STATE INDICATION")?;
        Ok(Self {
            pti,
            upsi_list,
            classmark,
            os_ids,
        })
    }
}

// =========================================================================
// Unit tests — encoder fail-closed validation + local round-trips.
// Golden byte-vector tests (E1 oracle) live in tests/ue_policy_codec.rs.
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn plmn_001_01() -> PlmnId {
        PlmnId::new([0, 0, 1], [0, 1, 0], 2)
    }

    fn internet_rsd() -> RouteSelectionDescriptor {
        RouteSelectionDescriptor {
            precedence: 255,
            components: vec![
                RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode1),
                RouteSelectionDescriptorComponent::SNssai { sst: 1, sd: None },
                RouteSelectionDescriptorComponent::Dnn("internet".into()),
                RouteSelectionDescriptorComponent::PduSessionType(PduSessionType::Ipv4v6),
            ],
        }
    }

    fn catch_all_rule() -> UrspRule {
        UrspRule {
            precedence: 255,
            traffic_descriptor: vec![TrafficDescriptorComponent::MatchAll],
            route_selection_descriptors: vec![internet_rsd()],
            ureri: None,
        }
    }

    fn one_part_list(contents: Vec<u8>) -> UePolicySectionManagementList {
        UePolicySectionManagementList {
            sublists: vec![PlmnSublist {
                plmn_id: plmn_001_01(),
                instructions: vec![Instruction {
                    upsc: 1,
                    parts: vec![UePolicyPart {
                        part_type: UePolicyPartType::Ursp,
                        contents,
                    }],
                }],
            }],
        }
    }

    // --- fail-closed encoding ------------------------------------------

    #[test]
    fn snssai_traffic_descriptor_is_unrepresentable() {
        let mut rule = catch_all_rule();
        rule.traffic_descriptor = vec![TrafficDescriptorComponent::SNssai { sst: 1, sd: None }];
        let err = encode_ursp_rules(&[rule]).unwrap_err();
        assert!(err.to_string().contains("unrepresentable"), "{err}");
    }

    #[test]
    fn match_all_must_be_the_only_td_component() {
        let mut rule = catch_all_rule();
        rule.traffic_descriptor = vec![
            TrafficDescriptorComponent::MatchAll,
            TrafficDescriptorComponent::Dnn("internet".into()),
        ];
        assert!(encode_ursp_rules(&[rule]).is_err());
    }

    #[test]
    fn match_all_at_most_once_across_all_rules() {
        let a = catch_all_rule();
        let mut b = catch_all_rule();
        b.precedence = 1;
        assert!(encode_ursp_rules(&[a, b]).is_err());
    }

    #[test]
    fn duplicate_rule_precedence_rejected() {
        let a = catch_all_rule();
        let mut b = catch_all_rule();
        b.traffic_descriptor = vec![TrafficDescriptorComponent::Dnn("ims".into())];
        assert!(encode_ursp_rules(&[a, b]).is_err());
    }

    #[test]
    fn empty_td_rsd_list_and_rsd_components_rejected() {
        let mut rule = catch_all_rule();
        rule.traffic_descriptor.clear();
        assert!(encode_ursp_rules(&[rule]).is_err());

        let mut rule = catch_all_rule();
        rule.route_selection_descriptors.clear();
        assert!(encode_ursp_rules(&[rule]).is_err());

        let mut rule = catch_all_rule();
        rule.route_selection_descriptors[0].components.clear();
        assert!(encode_ursp_rules(&[rule]).is_err());

        assert!(encode_ursp_rules(&[]).is_err());
    }

    #[test]
    fn duplicate_singleton_rsd_components_rejected() {
        let mut rule = catch_all_rule();
        rule.route_selection_descriptors[0].components.push(
            RouteSelectionDescriptorComponent::SscMode(SscMode::SscMode2),
        );
        assert!(encode_ursp_rules(&[rule]).is_err());
    }

    #[test]
    fn dnn_label_constraints_enforced() {
        for bad in ["", "a..b", &("x".repeat(64) + ".y"), &"y".repeat(101)] {
            let mut rule = catch_all_rule();
            rule.traffic_descriptor = vec![TrafficDescriptorComponent::Dnn(bad.to_string())];
            assert!(encode_ursp_rules(&[rule]).is_err(), "DNN {bad:?} accepted");
        }
    }

    #[test]
    fn port_range_low_above_high_rejected() {
        let mut rule = catch_all_rule();
        rule.traffic_descriptor = vec![TrafficDescriptorComponent::RemotePortRange {
            low: 9000,
            high: 80,
        }];
        assert!(encode_ursp_rules(&[rule]).is_err());
    }

    #[test]
    fn list_structural_minimums_enforced() {
        let list = UePolicySectionManagementList { sublists: vec![] };
        assert!(list.encode_lv_e().is_err());

        let list = UePolicySectionManagementList {
            sublists: vec![PlmnSublist {
                plmn_id: plmn_001_01(),
                instructions: vec![],
            }],
        };
        assert!(list.encode_lv_e().is_err());

        // Empty part contents are never emitted.
        let list = one_part_list(vec![]);
        assert!(list.encode_lv_e().is_err());
    }

    #[test]
    fn delete_section_instruction_has_no_parts_and_roundtrips() {
        // D.2.1.3: an instruction with UPSC only (no parts) is valid.
        let list = UePolicySectionManagementList {
            sublists: vec![PlmnSublist {
                plmn_id: plmn_001_01(),
                instructions: vec![Instruction {
                    upsc: 7,
                    parts: vec![],
                }],
            }],
        };
        let lv_e = list.encode_lv_e().unwrap();
        assert_eq!(
            UePolicySectionManagementList::decode_lv_e(&lv_e).unwrap(),
            list
        );
    }

    #[test]
    fn oversize_list_rejected_at_the_lv_e_bound() {
        // Two sublists of 32770 octets each: every inner length still fits
        // u16 but the list contents total 65544 > 65531.
        let big_part = vec![0xAAu8; 32760];
        let sublist = PlmnSublist {
            plmn_id: plmn_001_01(),
            instructions: vec![Instruction {
                upsc: 1,
                parts: vec![UePolicyPart {
                    part_type: UePolicyPartType::Ursp,
                    contents: big_part,
                }],
            }],
        };
        let list = UePolicySectionManagementList {
            sublists: vec![sublist.clone(), sublist],
        };
        let err = list.encode_lv_e().unwrap_err();
        assert!(err.to_string().contains("65531"), "{err}");
    }

    #[test]
    fn part_contents_length_overflowing_u16_rejected() {
        let list = one_part_list(vec![0u8; 70000]);
        assert!(list.encode_lv_e().is_err());
    }

    #[test]
    fn command_pti_range_enforced_both_ways() {
        let list = one_part_list(encode_ursp_rules(&[catch_all_rule()]).unwrap());
        for pti in [0x00u8, 0x7F, 0xFF] {
            let cmd = ManageUePolicyCommand {
                pti,
                list: list.clone(),
            };
            assert!(cmd.encode().is_err(), "PTI {pti:#04x} accepted on encode");
        }
        let good = ManageUePolicyCommand { pti: 0x80, list }.encode().unwrap();
        let mut bad = good.clone();
        bad[0] = 0x10;
        assert!(ManageUePolicyCommand::decode(&bad).is_err());
        assert!(ManageUePolicyCommand::decode(&good).is_ok());
    }

    #[test]
    fn complete_and_reject_pti_range_enforced() {
        assert!(ManageUePolicyComplete { pti: 0x00 }.encode().is_err());
        assert!(ManageUePolicyComplete { pti: 0x80 }.encode().is_ok());
        assert!(ManageUePolicyComplete::decode(&[0x00, 0x02]).is_err());

        let reject = ManageUePolicyCommandReject {
            pti: 0x00,
            result: UePolicySectionManagementResult {
                subresults: vec![UePolicySectionManagementSubresult {
                    plmn_id: plmn_001_01(),
                    results: vec![UePolicyResult {
                        upsc: 1,
                        failed_instruction_order: 1,
                        cause: UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                    }],
                }],
            },
        };
        assert!(reject.encode().is_err());
    }

    #[test]
    fn result_needs_at_least_one_subresult_and_result() {
        let empty = UePolicySectionManagementResult { subresults: vec![] };
        assert!(ManageUePolicyCommandReject {
            pti: 0x80,
            result: empty
        }
        .encode()
        .is_err());

        let no_results = UePolicySectionManagementResult {
            subresults: vec![UePolicySectionManagementSubresult {
                plmn_id: plmn_001_01(),
                results: vec![],
            }],
        };
        assert!(ManageUePolicyCommandReject {
            pti: 0x80,
            result: no_results
        }
        .encode()
        .is_err());
    }

    #[test]
    fn upsi_sublist_needs_at_least_one_upsc() {
        let usi = UeStateIndication {
            pti: 0,
            upsi_list: UpsiList {
                sublists: vec![UpsiSublist {
                    plmn_id: plmn_001_01(),
                    upscs: vec![],
                }],
            },
            classmark: UePolicyClassmark::default(),
            os_ids: vec![],
        };
        assert!(usi.encode().is_err());
    }

    #[test]
    fn ue_state_indication_pti_and_os_id_bounds() {
        let base = UeStateIndication {
            pti: 0x78, // above the UE-initiated 01H-77H range
            upsi_list: UpsiList::default(),
            classmark: UePolicyClassmark::default(),
            os_ids: vec![],
        };
        assert!(base.encode().is_err());

        let too_many = UeStateIndication {
            pti: 0,
            upsi_list: UpsiList::default(),
            classmark: UePolicyClassmark::default(),
            os_ids: vec![[0u8; 16]; 16],
        };
        assert!(too_many.encode().is_err());
    }

    #[test]
    fn plmn_bcd_validation() {
        // Non-BCD MCC digit.
        assert!(encode_plmn_bcd(&PlmnId::new([0, 0, 0x0A], [0, 1, 0], 2)).is_err());
        // Bad MNC length.
        assert!(encode_plmn_bcd(&PlmnId::new([0, 0, 1], [0, 1, 0], 1)).is_err());
        // Non-BCD digit on decode (MCC digit 2 = 0xA).
        assert!(decode_plmn_bcd(&[0xA0, 0xF1, 0x10]).is_err());
        // MNC digit 3 neither BCD nor 0b1111.
        assert!(decode_plmn_bcd(&[0x00, 0xA1, 0x10]).is_err());
        // 3-digit MNC round-trip.
        let plmn = PlmnId::new([3, 1, 0], [1, 4, 6], 3);
        let bytes = encode_plmn_bcd(&plmn).unwrap();
        assert_eq!(decode_plmn_bcd(&bytes).unwrap(), plmn);
    }

    // --- local round-trips beyond the golden vectors ---------------------

    #[test]
    fn ip_descriptor_and_fqdn_components_roundtrip() {
        let rule = UrspRule {
            precedence: 7,
            traffic_descriptor: vec![
                TrafficDescriptorComponent::Ipv4RemoteAddress {
                    addr: [192, 168, 0, 0],
                    mask: [255, 255, 0, 0],
                },
                TrafficDescriptorComponent::Ipv6RemoteAddress {
                    addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    prefix_len: 64,
                },
                TrafficDescriptorComponent::ProtocolIdentifier(17),
                TrafficDescriptorComponent::SingleRemotePort(5060),
                TrafficDescriptorComponent::RemotePortRange { low: 80, high: 443 },
                TrafficDescriptorComponent::DestinationFqdn("example.com".into()),
                TrafficDescriptorComponent::OsIdOsAppId {
                    os_id: [0x11; 16],
                    os_app_id: b"browser".to_vec(),
                },
            ],
            route_selection_descriptors: vec![RouteSelectionDescriptor {
                precedence: 1,
                components: vec![
                    RouteSelectionDescriptorComponent::SNssai {
                        sst: 1,
                        sd: Some([0x00, 0x00, 0x2A]),
                    },
                    RouteSelectionDescriptorComponent::PreferredAccessType(
                        PreferredAccessType::NonThreeGpp,
                    ),
                ],
            }],
            ureri: Some(true),
        };
        let bytes = encode_ursp_rules(std::slice::from_ref(&rule)).unwrap();
        let decoded = decode_ursp_rules(&bytes).unwrap();
        assert_eq!(decoded, vec![rule]);
        assert_eq!(encode_ursp_rules(&decoded).unwrap(), bytes);
    }

    #[test]
    fn ue_state_indication_roundtrips_with_os_ids() {
        let usi = UeStateIndication {
            pti: 0x00,
            upsi_list: UpsiList {
                sublists: vec![UpsiSublist {
                    plmn_id: plmn_001_01(),
                    upscs: vec![1, 2],
                }],
            },
            classmark: UePolicyClassmark {
                andsp_supported: true,
                eps_ursp_supported: false,
                vps_ursp_supported: false,
                rure_supported: true,
            },
            os_ids: vec![[0x22; 16]],
        };
        let bytes = usi.encode().unwrap();
        assert_eq!(UeStateIndication::decode(&bytes).unwrap(), usi);
    }

    #[test]
    fn empty_upsi_list_is_valid_and_roundtrips() {
        // Table D.6.4.1: no UPSIs => length of UPSI list contents = 0.
        let usi = UeStateIndication {
            pti: 0x01,
            upsi_list: UpsiList::default(),
            classmark: UePolicyClassmark::default(),
            os_ids: vec![],
        };
        let bytes = usi.encode().unwrap();
        assert_eq!(bytes[2..4], [0x00, 0x00]);
        assert_eq!(UeStateIndication::decode(&bytes).unwrap(), usi);
    }

    #[test]
    fn reject_roundtrips() {
        let reject = ManageUePolicyCommandReject {
            pti: 0x81,
            result: UePolicySectionManagementResult {
                subresults: vec![UePolicySectionManagementSubresult {
                    plmn_id: plmn_001_01(),
                    results: vec![
                        UePolicyResult {
                            upsc: 1,
                            failed_instruction_order: 1,
                            cause: UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                        },
                        UePolicyResult {
                            upsc: 2,
                            failed_instruction_order: 3,
                            cause: UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                        },
                    ],
                }],
            },
        };
        let bytes = reject.encode().unwrap();
        assert_eq!(ManageUePolicyCommandReject::decode(&bytes).unwrap(), reject);
    }

    #[test]
    fn peek_message_type_reads_octet_2() {
        assert_eq!(peek_message_type(&[0x80, 0x01, 0x00]).unwrap(), 0x01);
        assert!(peek_message_type(&[0x80]).is_err());
    }

    #[test]
    fn ureri_spare_bits_rejected_on_decode() {
        let mut rule_bytes = encode_ursp_rules(&[UrspRule {
            ureri: Some(false),
            ..catch_all_rule()
        }])
        .unwrap();
        let last = rule_bytes.len() - 1;
        rule_bytes[last] = 0x02; // set a spare bit of Figure 5.2.4A
        assert!(decode_ursp_rules(&rule_bytes).is_err());
    }
}
