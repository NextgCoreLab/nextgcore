//! UE Radio Capability ID (TS 23.003 §29.2) and its three wire forms.
//!
//! One identifier, three encodings, and the UCMF must never confuse them
//! (the contract agreed with the RAN side in nextg
//! `specs/gnb-racs-other-messages-254.md`):
//!
//! 1. **Digits** (TS 23.003 §29.2): hexadecimal digits — Type Field (1), then
//!    for a manufacturer-assigned ID the Vendor ID (8) and RCI (11), 20 digits;
//!    for a network (PLMN) assigned ID the Version ID (2) and RCI (11), 14
//!    digits.
//! 2. **NAS / NGAP / S1AP value octets** (TS 24.501 §9.11.3.68): the digits
//!    packed two per octet, the first digit of each pair in bits 1–4. Both
//!    defined lengths are even, so there is never a `1111` filler. NGAP's and
//!    S1AP's `UERadioCapabilityID` OCTET STRING carries exactly these octets.
//! 3. **Nucmf form** (TS 29.571 `PlmnAssiUeRadioCapId` / `ManAssiUeRadioCapId`,
//!    type `Bytes`): base64 of the complete NAS IE starting at octet 1, i.e.
//!    `0x67`, the length octet, then the value octets.
//!
//! The UCMF stores and answers the Nucmf form; anything received is decoded
//! from its bytes, never re-derived from a digit string.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::fmt;

/// TS 24.501 Table 9.11.3.1: IEI of the "UE radio capability ID" IE.
pub const UE_RADIO_CAPABILITY_ID_IEI: u8 = 0x67;

/// TS 23.003 §29.2 field widths, in hexadecimal digits.
const TF_DIGITS: usize = 1;
const VENDOR_ID_DIGITS: usize = 8;
const VERSION_ID_DIGITS: usize = 2;
const RCI_DIGITS: usize = 11;
/// Manufacturer-assigned: TF + Vendor ID + RCI.
pub const MANUFACTURER_ASSIGNED_DIGITS: usize = TF_DIGITS + VENDOR_ID_DIGITS + RCI_DIGITS;
/// Network-assigned: TF + Version ID + RCI.
pub const PLMN_ASSIGNED_DIGITS: usize = TF_DIGITS + VERSION_ID_DIGITS + RCI_DIGITS;
/// Largest RCI an 11-hex-digit field can hold.
pub const MAX_RCI: u64 = (1u64 << (4 * RCI_DIGITS)) - 1;

/// A UE radio capability ID, by type (TS 23.003 §29.2 Type Field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RacsId {
    /// TF = 0.
    ManufacturerAssigned { vendor_id: u32, rci: u64 },
    /// TF = 1. `version_id` is the UCMF's Version ID when it was assigned.
    PlmnAssigned { version_id: u8, rci: u64 },
}

/// Why bytes or digits do not form a UE radio capability ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RacsIdError {
    NotBase64,
    WrongIei(u8),
    LengthMismatch { declared: usize, actual: usize },
    /// Type Field 2..F are spare (TS 23.003 §29.2).
    SpareTypeField(u8),
    WrongLength { type_field: u8, digits: usize },
    NotHexDigit(char),
    RciOutOfRange(u64),
}

impl fmt::Display for RacsIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64 => write!(f, "not base64"),
            Self::WrongIei(i) => write!(f, "IEI 0x{i:02X} is not 0x67 (UE radio capability ID)"),
            Self::LengthMismatch { declared, actual } => {
                write!(f, "IE length octet says {declared}, {actual} value octets present")
            }
            Self::SpareTypeField(t) => write!(f, "Type Field {t:X} is a spare value"),
            Self::WrongLength { type_field, digits } => {
                write!(f, "Type Field {type_field} needs a fixed length, got {digits} digits")
            }
            Self::NotHexDigit(c) => write!(f, "'{c}' is not a hexadecimal digit"),
            Self::RciOutOfRange(r) => write!(f, "RCI {r:#x} does not fit 11 hex digits"),
        }
    }
}

impl std::error::Error for RacsIdError {}

impl RacsId {
    /// A PLMN-assigned ID. `rci` must fit 11 hex digits.
    pub fn plmn_assigned(version_id: u8, rci: u64) -> Result<Self, RacsIdError> {
        if rci > MAX_RCI {
            return Err(RacsIdError::RciOutOfRange(rci));
        }
        Ok(Self::PlmnAssigned { version_id, rci })
    }

    /// The TS 23.003 §29.2 digits, as nibble values 0..=15.
    pub fn digits(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(MANUFACTURER_ASSIGNED_DIGITS);
        let push = |d: &mut Vec<u8>, value: u64, width: usize| {
            for i in (0..width).rev() {
                d.push(((value >> (4 * i)) & 0xF) as u8);
            }
        };
        match *self {
            Self::ManufacturerAssigned { vendor_id, rci } => {
                d.push(0);
                push(&mut d, u64::from(vendor_id), VENDOR_ID_DIGITS);
                push(&mut d, rci, RCI_DIGITS);
            }
            Self::PlmnAssigned { version_id, rci } => {
                d.push(1);
                push(&mut d, u64::from(version_id), VERSION_ID_DIGITS);
                push(&mut d, rci, RCI_DIGITS);
            }
        }
        d
    }

    /// Parse the digit form (provisioning input, TS 29.122 RACS ID).
    pub fn from_digit_str(s: &str) -> Result<Self, RacsIdError> {
        let digits = s
            .chars()
            .map(|c| c.to_digit(16).map(|v| v as u8).ok_or(RacsIdError::NotHexDigit(c)))
            .collect::<Result<Vec<u8>, _>>()?;
        Self::from_digits(&digits)
    }

    fn from_digits(d: &[u8]) -> Result<Self, RacsIdError> {
        let fold = |ds: &[u8]| ds.iter().fold(0u64, |acc, &n| (acc << 4) | u64::from(n));
        match d.first().copied() {
            Some(0) if d.len() == MANUFACTURER_ASSIGNED_DIGITS => Ok(Self::ManufacturerAssigned {
                vendor_id: fold(&d[1..1 + VENDOR_ID_DIGITS]) as u32,
                rci: fold(&d[1 + VENDOR_ID_DIGITS..]),
            }),
            Some(1) if d.len() == PLMN_ASSIGNED_DIGITS => Ok(Self::PlmnAssigned {
                version_id: fold(&d[1..1 + VERSION_ID_DIGITS]) as u8,
                rci: fold(&d[1 + VERSION_ID_DIGITS..]),
            }),
            Some(tf @ (0 | 1)) => Err(RacsIdError::WrongLength {
                type_field: tf,
                digits: d.len(),
            }),
            Some(tf) => Err(RacsIdError::SpareTypeField(tf)),
            None => Err(RacsIdError::WrongLength {
                type_field: 0,
                digits: 0,
            }),
        }
    }

    /// TS 24.501 §9.11.3.68 value octets (what NGAP/S1AP carry).
    pub fn to_value_octets(&self) -> Vec<u8> {
        self.digits()
            .chunks(2)
            .map(|p| p[0] | (p.get(1).copied().unwrap_or(0xF) << 4))
            .collect()
    }

    /// Decode TS 24.501 §9.11.3.68 value octets. The Type Field fixes the
    /// length (20 or 14 digits, both even), so every nibble is a digit — a high
    /// nibble of `F` in the last octet is the digit `f`, not a filler.
    pub fn from_value_octets(octets: &[u8]) -> Result<Self, RacsIdError> {
        let digits: Vec<u8> = octets.iter().flat_map(|o| [o & 0xF, o >> 4]).collect();
        Self::from_digits(&digits)
    }

    /// TS 29.571 `Bytes` form: base64 of the whole NAS IE (`67 LL value`).
    pub fn to_nucmf(&self) -> String {
        let value = self.to_value_octets();
        let mut ie = Vec::with_capacity(value.len() + 2);
        ie.push(UE_RADIO_CAPABILITY_ID_IEI);
        ie.push(value.len() as u8);
        ie.extend_from_slice(&value);
        B64.encode(ie)
    }

    /// Parse the TS 29.571 `Bytes` form, checking the IEI and length octet.
    pub fn from_nucmf(s: &str) -> Result<Self, RacsIdError> {
        let ie = B64.decode(s.trim()).map_err(|_| RacsIdError::NotBase64)?;
        match ie.as_slice() {
            [iei, len, value @ ..] => {
                if *iei != UE_RADIO_CAPABILITY_ID_IEI {
                    return Err(RacsIdError::WrongIei(*iei));
                }
                if usize::from(*len) != value.len() {
                    return Err(RacsIdError::LengthMismatch {
                        declared: usize::from(*len),
                        actual: value.len(),
                    });
                }
                Self::from_value_octets(value)
            }
            _ => Err(RacsIdError::LengthMismatch {
                declared: 0,
                actual: ie.len(),
            }),
        }
    }

    pub fn is_plmn_assigned(&self) -> bool {
        matches!(self, Self::PlmnAssigned { .. })
    }
}

impl fmt::Display for RacsId {
    /// The TS 23.003 digit string, lower-case hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for d in self.digits() {
            write!(f, "{d:x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-derived (TS 23.003 §29.2 + TS 24.501 §9.11.3.68 + RFC 4648):
    /// TF 1, VID 0x05, RCI 1 → digits 1 0 5 0 0 0 0 0 0 0 0 0 0 1;
    /// pairs (1,0)(5,0)(0,0)(0,0)(0,0)(0,0)(0,1), first digit low →
    /// 01 05 00 00 00 00 10; IE 67 07 ‖ value; base64 of
    /// 67 07 01 | 05 00 00 | 00 00 10 = "ZwcB" "BQAA" "AAAQ".
    #[test]
    fn plmn_assigned_id_matches_hand_derived_bytes() {
        let id = RacsId::plmn_assigned(0x05, 1).unwrap();
        assert_eq!(id.to_string(), "10500000000001");
        assert_eq!(id.to_value_octets(), [0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10]);
        assert_eq!(id.to_nucmf(), "ZwcBBQAAAAAQ");
        assert_eq!(RacsId::from_nucmf("ZwcBBQAAAAAQ").unwrap(), id);
    }

    /// The vector nextgsim's #250/#251 pinned on the UE side: an ID whose last
    /// digit is `f` must keep it (no filler at an even length).
    #[test]
    fn a_final_f_digit_is_a_digit_not_a_filler() {
        let id = RacsId::from_digit_str("1ab0123456789f").unwrap();
        assert_eq!(
            id.to_value_octets(),
            [0xA1, 0x0B, 0x21, 0x43, 0x65, 0x87, 0xF9]
        );
        assert_eq!(
            RacsId::from_value_octets(&[0xA1, 0x0B, 0x21, 0x43, 0x65, 0x87, 0xF9]).unwrap(),
            id
        );
    }

    /// Manufacturer-assigned, using TS 23.003 §29.2 NOTE's example vendor
    /// 32473 = 0x00007ED9: 20 digits, 10 octets.
    #[test]
    fn manufacturer_assigned_id_round_trips_all_forms() {
        let id = RacsId::from_digit_str("000007ed900000000abc").unwrap();
        assert_eq!(
            id,
            RacsId::ManufacturerAssigned {
                vendor_id: 0x7ED9,
                rci: 0xABC
            }
        );
        let octets = id.to_value_octets();
        // digits 0 | 0 0 0 0 7 e d 9 | 0 0 0 0 0 0 0 0 a b c, paired first-digit-low:
        // (0,0)(0,0)(0,7)(e,d)(9,0)(0,0)(0,0)(0,0)(0,a)(b,c).
        assert_eq!(octets, [0x00, 0x00, 0x70, 0xDE, 0x09, 0x00, 0x00, 0x00, 0xA0, 0xCB]);
        assert_eq!(RacsId::from_value_octets(&octets).unwrap(), id);
        assert_eq!(RacsId::from_nucmf(&id.to_nucmf()).unwrap(), id);
    }

    #[test]
    fn malformed_forms_are_refused() {
        assert_eq!(RacsId::from_nucmf("!!"), Err(RacsIdError::NotBase64));
        // IEI 0x68 instead of 0x67.
        let wrong_iei = B64.encode([0x68, 0x07, 1, 5, 0, 0, 0, 0, 0x10]);
        assert_eq!(RacsId::from_nucmf(&wrong_iei), Err(RacsIdError::WrongIei(0x68)));
        // Length octet disagrees with the value length.
        let bad_len = B64.encode([0x67, 0x08, 1, 5, 0, 0, 0, 0, 0x10]);
        assert!(matches!(
            RacsId::from_nucmf(&bad_len),
            Err(RacsIdError::LengthMismatch { .. })
        ));
        // Spare Type Field 2.
        assert_eq!(
            RacsId::from_digit_str("20500000000001"),
            Err(RacsIdError::SpareTypeField(2))
        );
        // A PLMN-assigned ID must be 14 digits.
        assert!(matches!(
            RacsId::from_digit_str("1050000000001"),
            Err(RacsIdError::WrongLength { .. })
        ));
        assert_eq!(
            RacsId::plmn_assigned(0, MAX_RCI + 1),
            Err(RacsIdError::RciOutOfRange(MAX_RCI + 1))
        );
    }
}
