//! LPP `RequestAssistanceData` / `ProvideAssistanceData` message bodies
//! (3GPP TS 37.355 §6.2), the `c1` alternatives 2 and 3, UNALIGNED PER.
//!
//! These are the top-level LPP-MessageBody/c1 bodies that carry the A-GNSS
//! assistance data. Both follow the standard
//! `criticalExtensions → c1 → *-r9-IEs` wrapper (identical to
//! [`crate::lpp::capabilities::ProvideCapabilities`]); the `*-r9-IEs` SEQUENCE
//! carries the per-method assistance-data containers as root optionals.
//!
//! v1 wires only the **a-gnss** method. The other per-method optionals
//! (commonIEs, OTDOA, EPDU, sensor/…) are modeled UNSUPPORTED — never emitted,
//! rejected on decode.

use crate::per::{PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

use super::common::{AGnssProvideAssistanceData, AGnssRequestAssistanceData};

// ---------------------------------------------------------------------------
// ProvideAssistanceData (LPP-MessageBody/c1 index 3)
// ---------------------------------------------------------------------------

/// ProvideAssistanceData ::= SEQUENCE {
///     criticalExtensions CHOICE {
///         c1 CHOICE {
///             provideAssistanceData-r9 ProvideAssistanceData-r9-IEs,
///             spare3 NULL, spare2 NULL, spare1 NULL },
///         criticalExtensionsFuture SEQUENCE {} } }
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideAssistanceData {
    pub ies: ProvideAssistanceDataR9,
}

impl UperEncode for ProvideAssistanceData {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_choice_index(0, 2, false)?; // criticalExtensions -> c1
        encoder.encode_choice_index(0, 4, false)?; // c1 -> provideAssistanceData-r9 (0 of 4)
        self.ies.encode_uper(encoder)
    }
}

impl UperDecode for ProvideAssistanceData {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        if decoder.decode_choice_index(2, false)? != 0 {
            return Err(PerError::DecodeError(
                "LPP ProvideAssistanceData criticalExtensionsFuture not supported".to_string(),
            ));
        }
        let c1 = decoder.decode_choice_index(4, false)?;
        if c1 != 0 {
            return Err(PerError::DecodeError(format!(
                "LPP ProvideAssistanceData c1 index {c1} (spare) not supported"
            )));
        }
        Ok(ProvideAssistanceData {
            ies: ProvideAssistanceDataR9::decode_uper(decoder)?,
        })
    }
}

/// ProvideAssistanceData-r9-IEs ::= SEQUENCE {   -- EXTENSIBLE
///     commonIEsProvideAssistanceData OPTIONAL,           -- [0] UNSUPPORTED
///     a-gnss-ProvideAssistanceData A-GNSS-ProvideAssistanceData OPTIONAL, -- [1]
///     otdoa-ProvideAssistanceData OPTIONAL,              -- [2] UNSUPPORTED
///     epdu-ProvideAssistanceData OPTIONAL,               -- [3] UNSUPPORTED
///     ..., [[ ...later-release methods... ]] }
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideAssistanceDataR9 {
    pub a_gnss: Option<AGnssProvideAssistanceData>,
}

impl UperEncode for ProvideAssistanceDataR9 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, 4 root optionals; only a-gnss ([1]) supported.
        encoder.encode_sequence_preamble(
            Some(false),
            &[false, self.a_gnss.is_some(), false, false],
        );
        if let Some(a) = &self.a_gnss {
            a.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for ProvideAssistanceDataR9 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, opts) = decoder.decode_sequence_preamble(true, 4)?;
        if opts[0] || opts[2] || opts[3] {
            return Err(PerError::DecodeError(
                "unsupported LPP ProvideAssistanceData method (v1 supports a-gnss only)".to_string(),
            ));
        }
        let a_gnss = if opts[1] {
            Some(AGnssProvideAssistanceData::decode_uper(decoder)?)
        } else {
            None
        };
        Ok(ProvideAssistanceDataR9 { a_gnss })
    }
}

// ---------------------------------------------------------------------------
// RequestAssistanceData (LPP-MessageBody/c1 index 2)
// ---------------------------------------------------------------------------

/// RequestAssistanceData ::= SEQUENCE {
///     criticalExtensions CHOICE {
///         c1 CHOICE {
///             requestAssistanceData-r9 RequestAssistanceData-r9-IEs,
///             spare3 NULL, spare2 NULL, spare1 NULL },
///         criticalExtensionsFuture SEQUENCE {} } }
#[derive(Debug, Clone, PartialEq)]
pub struct RequestAssistanceData {
    pub ies: RequestAssistanceDataR9,
}

impl UperEncode for RequestAssistanceData {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_choice_index(0, 2, false)?; // criticalExtensions -> c1
        encoder.encode_choice_index(0, 4, false)?; // c1 -> requestAssistanceData-r9 (0 of 4)
        self.ies.encode_uper(encoder)
    }
}

impl UperDecode for RequestAssistanceData {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        if decoder.decode_choice_index(2, false)? != 0 {
            return Err(PerError::DecodeError(
                "LPP RequestAssistanceData criticalExtensionsFuture not supported".to_string(),
            ));
        }
        let c1 = decoder.decode_choice_index(4, false)?;
        if c1 != 0 {
            return Err(PerError::DecodeError(format!(
                "LPP RequestAssistanceData c1 index {c1} (spare) not supported"
            )));
        }
        Ok(RequestAssistanceData {
            ies: RequestAssistanceDataR9::decode_uper(decoder)?,
        })
    }
}

/// RequestAssistanceData-r9-IEs ::= SEQUENCE {   -- EXTENSIBLE
///     commonIEsRequestAssistanceData OPTIONAL,           -- [0] UNSUPPORTED
///     a-gnss-RequestAssistanceData A-GNSS-RequestAssistanceData OPTIONAL, -- [1]
///     otdoa-RequestAssistanceData OPTIONAL,              -- [2] UNSUPPORTED
///     ..., [[ ...later-release methods... ]] }
#[derive(Debug, Clone, PartialEq)]
pub struct RequestAssistanceDataR9 {
    pub a_gnss: Option<AGnssRequestAssistanceData>,
}

impl UperEncode for RequestAssistanceDataR9 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, 3 root optionals; only a-gnss ([1]) supported.
        encoder.encode_sequence_preamble(Some(false), &[false, self.a_gnss.is_some(), false]);
        if let Some(a) = &self.a_gnss {
            a.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for RequestAssistanceDataR9 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        if opts[0] || opts[2] {
            return Err(PerError::DecodeError(
                "unsupported LPP RequestAssistanceData method (v1 supports a-gnss only)".to_string(),
            ));
        }
        let a_gnss = if opts[1] {
            Some(AGnssRequestAssistanceData::decode_uper(decoder)?)
        } else {
            None
        };
        Ok(RequestAssistanceDataR9 { a_gnss })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: UperEncode + UperDecode + PartialEq + std::fmt::Debug>(v: &T) {
        let mut e = UperEncoder::new();
        v.encode_uper(&mut e).unwrap();
        let bytes = e.into_bytes();
        let mut d = UperDecoder::new(&bytes);
        let got = T::decode_uper(&mut d).unwrap();
        assert_eq!(&got, v);
    }

    #[test]
    fn provide_assistance_data_empty_round_trip() {
        round_trip(&ProvideAssistanceData {
            ies: ProvideAssistanceDataR9 { a_gnss: None },
        });
    }

    #[test]
    fn request_assistance_data_empty_round_trip() {
        round_trip(&RequestAssistanceData {
            ies: RequestAssistanceDataR9 { a_gnss: None },
        });
    }

    #[test]
    fn provide_assistance_data_with_agnss_round_trip() {
        round_trip(&ProvideAssistanceData {
            ies: ProvideAssistanceDataR9 {
                a_gnss: Some(AGnssProvideAssistanceData::default()),
            },
        });
    }
}
