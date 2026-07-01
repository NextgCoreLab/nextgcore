//! LPP A-GNSS assistance data — `GNSS-ReferenceTime` (3GPP TS 37.355, 6.5.2).
//!
//! Provides the GNSS-specific system time (with uncertainty) and the
//! relationship between GNSS system time and the air-interface network timing
//! of the reference cell (and, optionally, up to 16 additional cells for fine
//! time assistance).
//!
//! Encoding: X.691 UNALIGNED PER (UPER), via [`crate::uper`].

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

use super::common::{GnssSystemTime, NetworkTime};

/// `GNSS-ReferenceTime` (TS 37.355 6.5.2):
///
/// ```asn1
/// GNSS-ReferenceTime ::= SEQUENCE {
///     gnss-SystemTime             GNSS-SystemTime,
///     referenceTimeUnc            INTEGER (0..127)                          OPTIONAL, -- Cond noFTA
///     gnss-ReferenceTimeForCells  SEQUENCE (SIZE (1..16)) OF
///                                     GNSS-ReferenceTimeForOneCell          OPTIONAL, -- Need ON
///     ...
/// }
/// ```
///
/// Extensible SEQUENCE, 2 root OPTIONALs. Extension additions (past `...`) are
/// DEFERRED: none are emitted, and an extension-present bit on decode yields a
/// decode error.
#[derive(Debug, Clone, PartialEq)]
pub struct GnssReferenceTime {
    /// GNSS-specific system time (mandatory).
    pub gnss_system_time: GnssSystemTime,
    /// Uncertainty of the timing relation, coded value K on 7 bits.
    /// `INTEGER (0..127)`, `Cond noFTA` (present when the per-cell list is absent).
    pub reference_time_unc: Option<u8>,
    /// Fine time assistance for up to 16 (neighbour) cells. `SEQUENCE (SIZE (1..16))`.
    pub gnss_reference_time_for_cells: Option<Vec<GnssReferenceTimeForOneCell>>,
}

impl GnssReferenceTime {
    /// `referenceTimeUnc INTEGER (0..127)`.
    const REFERENCE_TIME_UNC: Constraint = Constraint::new(0, 127);
    /// `SEQUENCE (SIZE (1..16)) OF GNSS-ReferenceTimeForOneCell`.
    const CELLS_SIZE: Constraint = Constraint::new(1, 16);
}

impl UperEncode for GnssReferenceTime {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE (no extension additions emitted) + 2 optionals.
        e.encode_sequence_preamble(
            Some(false),
            &[
                self.reference_time_unc.is_some(),
                self.gnss_reference_time_for_cells.is_some(),
            ],
        );
        self.gnss_system_time.encode_uper(e)?;
        if let Some(unc) = self.reference_time_unc {
            e.encode_constrained_whole_number(unc as i64, &Self::REFERENCE_TIME_UNC)?;
        }
        if let Some(cells) = &self.gnss_reference_time_for_cells {
            let count = cells.len();
            if !(1..=16).contains(&count) {
                return Err(PerError::InvalidLength { length: count });
            }
            e.encode_constrained_whole_number(count as i64, &Self::CELLS_SIZE)?;
            for cell in cells {
                cell.encode_uper(e)?;
            }
        }
        Ok(())
    }
}

impl UperDecode for GnssReferenceTime {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 2)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-ReferenceTime extension additions not supported".into(),
            ));
        }
        let gnss_system_time = GnssSystemTime::decode_uper(d)?;
        let reference_time_unc = if opts[0] {
            Some(d.decode_constrained_whole_number(&Self::REFERENCE_TIME_UNC)? as u8)
        } else {
            None
        };
        let gnss_reference_time_for_cells = if opts[1] {
            let count = d.decode_constrained_whole_number(&Self::CELLS_SIZE)? as usize;
            let mut cells = Vec::with_capacity(count);
            for _ in 0..count {
                cells.push(GnssReferenceTimeForOneCell::decode_uper(d)?);
            }
            Some(cells)
        } else {
            None
        };
        Ok(GnssReferenceTime {
            gnss_system_time,
            reference_time_unc,
            gnss_reference_time_for_cells,
        })
    }
}

/// `GNSS-ReferenceTimeForOneCell` (TS 37.355 6.5.2):
///
/// ```asn1
/// GNSS-ReferenceTimeForOneCell ::= SEQUENCE {
///     networkTime         NetworkTime,
///     referenceTimeUnc    INTEGER (0..127),
///     bsAlign             ENUMERATED {true}   OPTIONAL,
///     ...
/// }
/// ```
///
/// Extensible SEQUENCE, 1 root OPTIONAL. `bsAlign` is a single-value
/// `ENUMERATED {true}`: it carries NO content bits, so its entire information
/// is the OPTIONAL presence bit in the preamble — modelled here as
/// [`Option`]`<()>` (`Some(())` == present/true). Extension additions past
/// `...` are DEFERRED (rejected on decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnssReferenceTimeForOneCell {
    /// Cellular network time at the epoch corresponding to `gnss-SystemTime`.
    pub network_time: NetworkTime,
    /// Accuracy of the GNSS-system-time / network-time relation, K on 7 bits.
    pub reference_time_unc: u8,
    /// `bsAlign ENUMERATED {true}` — `Some(())` when the flag is present
    /// (cells sharing carrier + TA/LA/RA are frame aligned); `None` when absent.
    pub bs_align: Option<()>,
}

impl GnssReferenceTimeForOneCell {
    /// `referenceTimeUnc INTEGER (0..127)`.
    const REFERENCE_TIME_UNC: Constraint = Constraint::new(0, 127);
}

impl UperEncode for GnssReferenceTimeForOneCell {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE (no extension additions emitted) + 1 optional.
        e.encode_sequence_preamble(Some(false), &[self.bs_align.is_some()]);
        self.network_time.encode_uper(e)?;
        e.encode_constrained_whole_number(
            self.reference_time_unc as i64,
            &Self::REFERENCE_TIME_UNC,
        )?;
        // bsAlign is ENUMERATED {true}: range = 1, so it contributes 0 content
        // bits — its presence is conveyed entirely by the preamble bit above.
        Ok(())
    }
}

impl UperDecode for GnssReferenceTimeForOneCell {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 1)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-ReferenceTimeForOneCell extension additions not supported".into(),
            ));
        }
        let network_time = NetworkTime::decode_uper(d)?;
        let reference_time_unc =
            d.decode_constrained_whole_number(&Self::REFERENCE_TIME_UNC)? as u8;
        // bsAlign: single-value ENUMERATED, no content bits to read.
        let bs_align = if opts[0] { Some(()) } else { None };
        Ok(GnssReferenceTimeForOneCell {
            network_time,
            reference_time_unc,
            bs_align,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpp::a_gnss::common::{GnssId, GnssIdValue, NetworkCellId, NetworkTimeEUtra};

    fn sample_gnss_system_time() -> GnssSystemTime {
        GnssSystemTime {
            gnss_time_id: GnssId {
                gnss_id: GnssIdValue::Galileo,
            },
            gnss_day_number: 100,
            gnss_time_of_day: 5000,
            gnss_time_of_day_frac_msec: Some(500),
            notification_of_leap_second: None,
        }
    }

    fn sample_network_time() -> NetworkTime {
        NetworkTime {
            seconds_from_frame_structure_start: 1000,
            fractional_seconds_from_frame_structure_start: 200_000,
            frame_drift: Some(-10),
            cell_id: NetworkCellId::EUtra(NetworkTimeEUtra {
                phys_cell_id: 42,
                earfcn: 1800,
            }),
        }
    }

    #[test]
    fn round_trip_gnss_reference_time_minimal() {
        // Only the mandatory gnss-SystemTime; both optionals absent.
        let original = GnssReferenceTime {
            gnss_system_time: sample_gnss_system_time(),
            reference_time_unc: None,
            gnss_reference_time_for_cells: None,
        };
        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssReferenceTime::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_gnss_reference_time_full() {
        let original = GnssReferenceTime {
            gnss_system_time: sample_gnss_system_time(),
            reference_time_unc: Some(63),
            gnss_reference_time_for_cells: Some(vec![
                GnssReferenceTimeForOneCell {
                    network_time: sample_network_time(),
                    reference_time_unc: 0,
                    bs_align: Some(()),
                },
                GnssReferenceTimeForOneCell {
                    network_time: sample_network_time(),
                    reference_time_unc: 127,
                    bs_align: None,
                },
            ]),
        };
        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssReferenceTime::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_one_cell() {
        let original = GnssReferenceTimeForOneCell {
            network_time: sample_network_time(),
            reference_time_unc: 55,
            bs_align: Some(()),
        };
        let mut enc = UperEncoder::new();
        original.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = GnssReferenceTimeForOneCell::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, original);
    }
}
