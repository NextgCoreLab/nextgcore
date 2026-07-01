//! LPP A-GNSS GNSS-RealTimeIntegrity assistance data (3GPP TS 37.355 §6.5.2.6),
//! UNALIGNED PER (X.691), LMF -> UE.
//!
//! ASN.1 (TS 37.355 LPP-PDU-Definitions):
//! GNSS-RealTimeIntegrity ::= SEQUENCE { gnss-BadSignalList BadSignalList, ... }
//! BadSignalList ::= SEQUENCE (SIZE(1..64)) OF BadSignalElement
//! BadSignalElement ::= SEQUENCE { badSVID SV-ID, badSignalID GNSS-SignalIDs OPTIONAL, ... }

use super::common::{GnssSignalIds, SvId};
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// BadSignalElement ::= SEQUENCE { badSVID SV-ID, badSignalID GNSS-SignalIDs OPTIONAL, ... }
#[derive(Debug, Clone, PartialEq)]
pub struct BadSignalElement {
    pub bad_svid: SvId,
    pub bad_signal_id: Option<GnssSignalIds>,
}

impl UperEncode for BadSignalElement {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[self.bad_signal_id.is_some()]);
        self.bad_svid.encode_uper(e)?;
        if let Some(sig) = &self.bad_signal_id {
            sig.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for BadSignalElement {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = d.decode_sequence_preamble(true, 1)?;
        if ext {
            return Err(PerError::DecodeError(
                "BadSignalElement extension additions not supported".into(),
            ));
        }
        let bad_svid = SvId::decode_uper(d)?;
        let bad_signal_id = if opts[0] {
            Some(GnssSignalIds::decode_uper(d)?)
        } else {
            None
        };
        Ok(BadSignalElement { bad_svid, bad_signal_id })
    }
}

/// GNSS-RealTimeIntegrity ::= SEQUENCE { gnss-BadSignalList BadSignalList, ... }
/// BadSignalList ::= SEQUENCE (SIZE(1..64)) OF BadSignalElement
#[derive(Debug, Clone, PartialEq)]
pub struct GnssRealTimeIntegrity {
    pub gnss_bad_signal_list: Vec<BadSignalElement>,
}

impl GnssRealTimeIntegrity {
    const BAD_SIGNAL_LIST_SIZE: Constraint = Constraint::new(1, 64);
}

impl UperEncode for GnssRealTimeIntegrity {
    fn encode_uper(&self, e: &mut UperEncoder) -> PerResult<()> {
        e.encode_sequence_preamble(Some(false), &[]);
        e.encode_constrained_whole_number(
            self.gnss_bad_signal_list.len() as i64,
            &Self::BAD_SIGNAL_LIST_SIZE,
        )?;
        for el in &self.gnss_bad_signal_list {
            el.encode_uper(e)?;
        }
        Ok(())
    }
}

impl UperDecode for GnssRealTimeIntegrity {
    fn decode_uper(d: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = d.decode_sequence_preamble(true, 0)?;
        if ext {
            return Err(PerError::DecodeError(
                "GNSS-RealTimeIntegrity extension additions not supported".into(),
            ));
        }
        let count = d.decode_constrained_whole_number(&Self::BAD_SIGNAL_LIST_SIZE)? as usize;
        let mut gnss_bad_signal_list = Vec::with_capacity(count);
        for _ in 0..count {
            gnss_bad_signal_list.push(BadSignalElement::decode_uper(d)?);
        }
        Ok(GnssRealTimeIntegrity { gnss_bad_signal_list })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpp::a_gnss::common::{GnssSignalIds, SvId};

    #[test]
    fn round_trip_gnss_real_time_integrity() {
        let original = GnssRealTimeIntegrity {
            gnss_bad_signal_list: vec![
                BadSignalElement { bad_svid: SvId { satellite_id: 12 }, bad_signal_id: None },
                BadSignalElement { bad_svid: SvId { satellite_id: 63 }, bad_signal_id: Some(GnssSignalIds { signals: 0x81 }) },
                BadSignalElement { bad_svid: SvId { satellite_id: 0 }, bad_signal_id: Some(GnssSignalIds { signals: 0x40 }) },
            ],
        };
        let mut e = UperEncoder::new();
        original.encode_uper(&mut e).unwrap();
        let bytes = e.into_bytes();
        let mut d = UperDecoder::new(&bytes);
        let decoded = GnssRealTimeIntegrity::decode_uper(&mut d).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_single_bad_signal() {
        let original = GnssRealTimeIntegrity {
            gnss_bad_signal_list: vec![BadSignalElement {
                bad_svid: SvId { satellite_id: 33 },
                bad_signal_id: None,
            }],
        };
        let mut e = UperEncoder::new();
        original.encode_uper(&mut e).unwrap();
        let bytes = e.into_bytes();
        let mut d = UperDecoder::new(&bytes);
        let decoded = GnssRealTimeIntegrity::decode_uper(&mut d).unwrap();
        assert_eq!(decoded, original);
    }
}
