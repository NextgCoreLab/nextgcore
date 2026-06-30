//! LPP envelope primitives (3GPP TS 37.355 §6.1), UNALIGNED PER.
//!
//! These are the transaction-management header types that wrap every LPP
//! message body: the `Initiator`/`TransactionNumber` pair carried inside an
//! `LPP-TransactionID`, the standalone `SequenceNumber`, and the
//! `Acknowledgement` SEQUENCE. They mirror the NRPPa house style (a per-type
//! `CONSTRAINT` const plus a hand-written `UperEncode`/`UperDecode`) but ride
//! the standalone UPER codepath ([`crate::uper`]) rather than APER, because LPP
//! is specified with the UNALIGNED PER variant (X.691).

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// Initiator ::= ENUMERATED { locationServer, targetDevice, ... } -- EXTENSIBLE
///
/// Identifies which side opened the LPP transaction (TS 37.355 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Initiator {
    LocationServer = 0,
    TargetDevice = 1,
}

impl Initiator {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 1);
}

impl UperEncode for Initiator {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl UperDecode for Initiator {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(Initiator::LocationServer),
            1 => Ok(Initiator::TargetDevice),
            _ => Err(PerError::DecodeError(format!(
                "Initiator extension value {value} not supported in v1 foundation"
            ))),
        }
    }
}

/// TransactionNumber ::= INTEGER (0..255)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionNumber(pub u8);

impl TransactionNumber {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 255);
}

impl UperEncode for TransactionNumber {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl UperDecode for TransactionNumber {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(TransactionNumber(value as u8))
    }
}

/// SequenceNumber ::= INTEGER (0..255)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SequenceNumber(pub u8);

impl SequenceNumber {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 255);
}

impl UperEncode for SequenceNumber {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl UperDecode for SequenceNumber {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(SequenceNumber(value as u8))
    }
}

/// LPP-TransactionID ::= SEQUENCE { initiator, transactionNumber, ... } -- EXTENSIBLE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LppTransactionId {
    pub initiator: Initiator,
    pub transaction_number: TransactionNumber,
}

impl UperEncode for LppTransactionId {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Extensible SEQUENCE, no optional root fields, no additions emitted.
        encoder.encode_sequence_preamble(Some(false), &[]);
        self.initiator.encode_uper(encoder)?;
        self.transaction_number.encode_uper(encoder)?;
        Ok(())
    }
}

impl UperDecode for LppTransactionId {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let initiator = Initiator::decode_uper(decoder)?;
        let transaction_number = TransactionNumber::decode_uper(decoder)?;
        if ext {
            // Forward-compat: discard any extension additions a newer peer added.
            decoder.decode_extension_additions()?;
        }
        Ok(LppTransactionId {
            initiator,
            transaction_number,
        })
    }
}

/// Acknowledgement ::= SEQUENCE {           -- NON-extensible
///     ackRequested BOOLEAN,
///     ackIndicator SequenceNumber OPTIONAL }
///
/// `ackRequested` is declared first (mandatory) so it is written *after* the
/// preamble; the single OPTIONAL (`ackIndicator`) contributes the one presence
/// bit in the preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acknowledgement {
    pub ack_requested: bool,
    pub ack_indicator: Option<SequenceNumber>,
}

impl UperEncode for Acknowledgement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(None, &[self.ack_indicator.is_some()]);
        // A BOOLEAN is a single bit (there is no encode_boolean helper).
        encoder.write_bit(self.ack_requested);
        if let Some(indicator) = self.ack_indicator {
            indicator.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for Acknowledgement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, opts) = decoder.decode_sequence_preamble(false, 1)?;
        let ack_requested = decoder.read_bit()?;
        let ack_indicator = if opts[0] {
            Some(SequenceNumber::decode_uper(decoder)?)
        } else {
            None
        };
        Ok(Acknowledgement {
            ack_requested,
            ack_indicator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: UperEncode + UperDecode + PartialEq + std::fmt::Debug,
    {
        let mut enc = UperEncoder::new();
        value.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = T::decode_uper(&mut dec).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn rt_initiator() {
        roundtrip(&Initiator::LocationServer);
        roundtrip(&Initiator::TargetDevice);
    }

    #[test]
    fn rt_transaction_and_sequence_number() {
        for v in [0u8, 1, 7, 128, 255] {
            roundtrip(&TransactionNumber(v));
            roundtrip(&SequenceNumber(v));
        }
    }

    #[test]
    fn rt_lpp_transaction_id() {
        roundtrip(&LppTransactionId {
            initiator: Initiator::LocationServer,
            transaction_number: TransactionNumber(0),
        });
        roundtrip(&LppTransactionId {
            initiator: Initiator::TargetDevice,
            transaction_number: TransactionNumber(200),
        });
    }

    #[test]
    fn rt_acknowledgement() {
        roundtrip(&Acknowledgement {
            ack_requested: true,
            ack_indicator: Some(SequenceNumber(5)),
        });
        roundtrip(&Acknowledgement {
            ack_requested: false,
            ack_indicator: None,
        });
        roundtrip(&Acknowledgement {
            ack_requested: true,
            ack_indicator: None,
        });
    }

    /// LPP-TransactionID { locationServer, 0 } derived by hand:
    ///   SEQUENCE ext-marker 0
    ///   initiator: ext-bit 0 + 1-bit value 0 (locationServer) = `00`
    ///   transactionNumber: 8 bits 0 = `00000000`
    /// = `0 00 00000000` (11 bits) -> pad to 16 = 0x00 0x00.
    #[test]
    fn vec_lpp_transaction_id_zero() {
        let id = LppTransactionId {
            initiator: Initiator::LocationServer,
            transaction_number: TransactionNumber(0),
        };
        let mut enc = UperEncoder::new();
        id.encode_uper(&mut enc).unwrap();
        assert_eq!(enc.bit_length(), 11);
        assert_eq!(enc.into_bytes().as_ref(), &[0x00, 0x00]);
    }
}
