//! NRPPa Cause types
//!
//! Cause CHOICE and its member enumerations from NRPPA-IEs (3GPP TS 38.455
//! §9.3.4, ASN.1 L13645+).
//!
//! KEY DIVERGENCE from NGAP: the NRPPa `Cause` CHOICE has only FOUR
//! alternatives — radioNetwork, protocol, misc, choice-Extension — and is
//! NON-extensible (no `...`), so its index is a constrained whole number 0..3
//! (2 bits) with no leading extension bit. NRPPa has no `transport` or `nas`
//! cause category (unlike NGAP).

use crate::per::{
    AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerError, PerResult,
};

/// CauseRadioNetwork
/// ASN.1: ENUMERATED { unspecified, requested-item-not-supported,
///        requested-item-temporarily-not-available, ...,
///        serving-NG-RAN-node-changed, requested-item-not-supported-on-time }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseRadioNetwork {
    Unspecified = 0,
    RequestedItemNotSupported = 1,
    RequestedItemTemporarilyNotAvailable = 2,
    // Extension additions (root ends at index 2)
    ServingNgRanNodeChanged = 3,
    RequestedItemNotSupportedOnTime = 4,
}

impl CauseRadioNetwork {
    // Root enumeration has 3 values (0..2), extensible.
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 2);
}

impl TryFrom<i64> for CauseRadioNetwork {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::RequestedItemNotSupported),
            2 => Ok(Self::RequestedItemTemporarilyNotAvailable),
            3 => Ok(Self::ServingNgRanNodeChanged),
            4 => Ok(Self::RequestedItemNotSupportedOnTime),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseRadioNetwork value: {value}"
            ))),
        }
    }
}

impl AperEncode for CauseRadioNetwork {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseRadioNetwork {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        Self::try_from(value)
    }
}

/// CauseProtocol
/// ASN.1: ENUMERATED { transfer-syntax-error, abstract-syntax-error-reject,
///        abstract-syntax-error-ignore-and-notify,
///        message-not-compatible-with-receiver-state, semantic-error,
///        unspecified, abstract-syntax-error-falsely-constructed-message, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseProtocol {
    TransferSyntaxError = 0,
    AbstractSyntaxErrorReject = 1,
    AbstractSyntaxErrorIgnoreAndNotify = 2,
    MessageNotCompatibleWithReceiverState = 3,
    SemanticError = 4,
    Unspecified = 5,
    AbstractSyntaxErrorFalselyConstructedMessage = 6,
}

impl CauseProtocol {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 6);
}

impl TryFrom<i64> for CauseProtocol {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TransferSyntaxError),
            1 => Ok(Self::AbstractSyntaxErrorReject),
            2 => Ok(Self::AbstractSyntaxErrorIgnoreAndNotify),
            3 => Ok(Self::MessageNotCompatibleWithReceiverState),
            4 => Ok(Self::SemanticError),
            5 => Ok(Self::Unspecified),
            6 => Ok(Self::AbstractSyntaxErrorFalselyConstructedMessage),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseProtocol value: {value}"
            ))),
        }
    }
}

impl AperEncode for CauseProtocol {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseProtocol {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        Self::try_from(value)
    }
}

/// CauseMisc
/// ASN.1: ENUMERATED { unspecified, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseMisc {
    Unspecified = 0,
}

impl CauseMisc {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 0);
}

impl TryFrom<i64> for CauseMisc {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unspecified),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseMisc value: {value}"
            ))),
        }
    }
}

impl AperEncode for CauseMisc {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseMisc {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        Self::try_from(value)
    }
}

/// Cause - CHOICE over the NRPPa cause categories
/// ASN.1: Cause ::= CHOICE { radioNetwork, protocol, misc, choice-Extension }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    RadioNetwork(CauseRadioNetwork),
    Protocol(CauseProtocol),
    Misc(CauseMisc),
}

impl Cause {
    // TS 38.455 §9.3.4: NON-extensible CHOICE with 4 alternatives
    // (radioNetwork, protocol, misc, choice-Extension). The index is a
    // constrained whole number 0..3 (2 bits) with NO leading extension bit.
    // `Cause-ExtensionIE` is an empty extension set, so a conformant peer never
    // selects alternative 3 (choice-Extension); we surface it as a decode error.
    pub const NUM_ALTERNATIVES: usize = 4;
    pub const EXTENSIBLE: bool = false;
}

impl AperEncode for Cause {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            Cause::RadioNetwork(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            Cause::Protocol(v) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            Cause::Misc(v) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for Cause {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(Cause::RadioNetwork(CauseRadioNetwork::decode_aper(
                decoder,
            )?)),
            1 => Ok(Cause::Protocol(CauseProtocol::decode_aper(decoder)?)),
            2 => Ok(Cause::Misc(CauseMisc::decode_aper(decoder)?)),
            3 => Err(PerError::DecodeError(
                "Cause choice-Extension selected but Cause-ExtensionIE is empty in TS 38.455"
                    .to_string(),
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(cause: Cause) {
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        assert_eq!(Cause::decode_aper(&mut decoder).unwrap(), cause);
    }

    #[test]
    fn test_cause_all_alternatives_roundtrip() {
        roundtrip(Cause::RadioNetwork(CauseRadioNetwork::Unspecified));
        roundtrip(Cause::RadioNetwork(
            CauseRadioNetwork::ServingNgRanNodeChanged,
        ));
        roundtrip(Cause::Protocol(CauseProtocol::SemanticError));
        roundtrip(Cause::Misc(CauseMisc::Unspecified));
    }

    #[test]
    fn test_cause_choice_index_is_2bit_no_extension_bit() {
        // Non-extensible 4-alternative CHOICE -> 2-bit index in the top bits.
        // misc = index 2 must appear as `10` in the high 2 bits of octet 0.
        let mut encoder = AperEncoder::new();
        Cause::Misc(CauseMisc::Unspecified)
            .encode_aper(&mut encoder)
            .unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        assert_eq!(
            bytes[0] >> 6,
            2,
            "Cause choice index must occupy the top 2 bits with no extension bit"
        );
    }
}
