//! LPP message envelope (3GPP TS 37.355 §6.1), UNALIGNED PER.
//!
//! `LPP-Message` is the top-level PDU exchanged between the LMF (location
//! server) and the UE (target device). It carries optional transaction
//! management (transaction id / sequence number / acknowledgement) plus an
//! optional `LPP-MessageBody`. v1 types the `c1` message-body indices 4 and 5
//! (request / provide location information); the other 14 `c1` alternatives and
//! the `messageClassExtension` arm are carried by follow-on chunks.

use bytes::Bytes;

use super::ecid::{ProvideLocationInformation, RequestLocationInformation};
use super::types::{Acknowledgement, LppTransactionId, SequenceNumber};
use crate::per::{PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// LPP-Message ::= SEQUENCE {              -- NON-extensible
///     transactionID   LPP-TransactionID OPTIONAL,
///     endTransaction  BOOLEAN,
///     sequenceNumber  SequenceNumber OPTIONAL,
///     acknowledgement Acknowledgement OPTIONAL,
///     lpp-MessageBody LPP-MessageBody OPTIONAL }
///
/// The four OPTIONAL fields produce four presence bits in the preamble, in
/// declaration order `[transactionID, sequenceNumber, acknowledgement,
/// lpp-MessageBody]`. The mandatory `endTransaction` BOOLEAN is written between
/// `transactionID` and `sequenceNumber`, i.e. after the preamble.
#[derive(Debug, Clone, PartialEq)]
pub struct LppMessage {
    pub transaction_id: Option<LppTransactionId>,
    pub end_transaction: bool,
    pub sequence_number: Option<SequenceNumber>,
    pub acknowledgement: Option<Acknowledgement>,
    pub message_body: Option<LppMessageBody>,
}

impl LppMessage {
    /// Encode this message to UPER octets (final octet padding applied).
    pub fn encode(&self) -> PerResult<Bytes> {
        let mut encoder = UperEncoder::new();
        self.encode_uper(&mut encoder)?;
        Ok(encoder.into_bytes())
    }

    /// Decode an `LPP-Message` from UPER octets.
    pub fn decode(bytes: &[u8]) -> PerResult<Self> {
        let mut decoder = UperDecoder::new(bytes);
        Self::decode_uper(&mut decoder)
    }
}

impl UperEncode for LppMessage {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            None,
            &[
                self.transaction_id.is_some(),
                self.sequence_number.is_some(),
                self.acknowledgement.is_some(),
                self.message_body.is_some(),
            ],
        );
        if let Some(tid) = &self.transaction_id {
            tid.encode_uper(encoder)?;
        }
        encoder.write_bit(self.end_transaction);
        if let Some(seq) = &self.sequence_number {
            seq.encode_uper(encoder)?;
        }
        if let Some(ack) = &self.acknowledgement {
            ack.encode_uper(encoder)?;
        }
        if let Some(body) = &self.message_body {
            body.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for LppMessage {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, opts) = decoder.decode_sequence_preamble(false, 4)?;
        // opts = [transactionID, sequenceNumber, acknowledgement, lpp-MessageBody]
        let transaction_id = if opts[0] {
            Some(LppTransactionId::decode_uper(decoder)?)
        } else {
            None
        };
        let end_transaction = decoder.read_bit()?;
        let sequence_number = if opts[1] {
            Some(SequenceNumber::decode_uper(decoder)?)
        } else {
            None
        };
        let acknowledgement = if opts[2] {
            Some(Acknowledgement::decode_uper(decoder)?)
        } else {
            None
        };
        let message_body = if opts[3] {
            Some(LppMessageBody::decode_uper(decoder)?)
        } else {
            None
        };
        Ok(LppMessage {
            transaction_id,
            end_transaction,
            sequence_number,
            acknowledgement,
            message_body,
        })
    }
}

/// LPP-MessageBody ::= CHOICE {            -- NON-extensible, 2 alternatives
///     c1 CHOICE { ...16 alternatives... },
///     messageClassExtension SEQUENCE {} }
#[derive(Debug, Clone, PartialEq)]
pub enum LppMessageBody {
    C1(MessageBodyC1),
    /// messageClassExtension SEQUENCE {} — an empty SEQUENCE (no content bits).
    MessageClassExtension,
}

impl LppMessageBody {
    const NUM_ALTERNATIVES: usize = 2;
}

impl UperEncode for LppMessageBody {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        match self {
            LppMessageBody::C1(c1) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, false)?;
                c1.encode_uper(encoder)
            }
            LppMessageBody::MessageClassExtension => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, false)?;
                // Empty SEQUENCE {} -> no further bits.
                Ok(())
            }
        }
    }
}

impl UperDecode for LppMessageBody {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, false)?;
        match index {
            0 => Ok(LppMessageBody::C1(MessageBodyC1::decode_uper(decoder)?)),
            1 => Ok(LppMessageBody::MessageClassExtension),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// The `c1` inner CHOICE of `LPP-MessageBody` (16 alternatives in TS 37.355):
///   0 requestCapabilities         1 provideCapabilities
///   2 requestAssistanceData       3 provideAssistanceData
///   4 requestLocationInformation  5 provideLocationInformation
///   6 abort                       7 error
///   8..15 spare7 NULL .. spare0 NULL
///
/// v1 implements only the location-information request/provide pair (indices 4
/// and 5); all other indices are carried by a follow-on chunk.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageBodyC1 {
    RequestLocationInformation(RequestLocationInformation),
    ProvideLocationInformation(ProvideLocationInformation),
}

impl MessageBodyC1 {
    const NUM_ALTERNATIVES: usize = 16;
    const IDX_REQUEST_LOCATION_INFORMATION: usize = 4;
    const IDX_PROVIDE_LOCATION_INFORMATION: usize = 5;
}

impl UperEncode for MessageBodyC1 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        match self {
            MessageBodyC1::RequestLocationInformation(body) => {
                encoder.encode_choice_index(
                    Self::IDX_REQUEST_LOCATION_INFORMATION,
                    Self::NUM_ALTERNATIVES,
                    false,
                )?;
                body.encode_uper(encoder)
            }
            MessageBodyC1::ProvideLocationInformation(body) => {
                encoder.encode_choice_index(
                    Self::IDX_PROVIDE_LOCATION_INFORMATION,
                    Self::NUM_ALTERNATIVES,
                    false,
                )?;
                body.encode_uper(encoder)
            }
        }
    }
}

impl UperDecode for MessageBodyC1 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, false)?;
        match index {
            4 => Ok(MessageBodyC1::RequestLocationInformation(
                RequestLocationInformation::decode_uper(decoder)?,
            )),
            5 => Ok(MessageBodyC1::ProvideLocationInformation(
                ProvideLocationInformation::decode_uper(decoder)?,
            )),
            n => Err(PerError::DecodeError(format!(
                "LPP c1 body index {n} not implemented in v1 foundation"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpp::ecid::{
        EcidProvideLocationInformation, EcidRequestLocationInformation,
        EcidSignalMeasurementInformation, MeasuredResultsElement, ProvideLocationInformationR9,
        RequestLocationInformationR9,
    };
    use crate::lpp::types::{Initiator, TransactionNumber};
    use bitvec::prelude::*;

    fn measurements(values: &[bool]) -> BitVec<u8, Msb0> {
        let mut bv: BitVec<u8, Msb0> = BitVec::new();
        for &b in values {
            bv.push(b);
        }
        bv
    }

    fn sample_element() -> MeasuredResultsElement {
        MeasuredResultsElement {
            phys_cell_id: 42,
            arfcn_eutra: 1850,
            system_frame_number: None,
            rsrp_result: Some(50),
            rsrq_result: Some(20),
            ue_rx_tx_time_diff: None,
        }
    }

    /// Hand-derived UPER reference vector (no golden capture exists; LPP is
    /// UNALIGNED PER with no network egress here, so this is self-attesting from
    /// X.691 + TS 37.355). The message is:
    ///
    ///   LPP-Message {
    ///     transactionID   = { initiator locationServer, transactionNumber 0 }
    ///     endTransaction  = TRUE
    ///     (sequenceNumber / acknowledgement absent)
    ///     lpp-MessageBody = c1 : requestLocationInformation :
    ///       criticalExtensions c1 : requestLocationInformation-r9 :
    ///         { ecid-RequestLocationInformation { requestedMeasurements '11000'B } }
    ///   }
    ///
    /// requestedMeasurements `11000` sets rsrpReq(0) + rsrqReq(1), length 5.
    ///
    /// Bit-by-bit derivation (39 bits, padded to 40 = 5 octets):
    ///   LPP-Message preamble (non-ext, opts [tid,seq,ack,body]):  1 0 0 1
    ///   transactionID (LPP-TransactionID, ext SEQ, 0 opt):
    ///     SEQUENCE ext-marker:                                    0
    ///     initiator locationServer (ext ENUM): ext-bit 0 + 0     0 0
    ///     transactionNumber 0 (INTEGER 0..255, 8 bits):          0 0 0 0 0 0 0 0
    ///   endTransaction TRUE:                                      1
    ///   lpp-MessageBody:
    ///     outer CHOICE -> c1 (index 0 of 2, 1 bit):              0
    ///     c1 CHOICE -> reqLocInfo (index 4 of 16, 4 bits):       0 1 0 0
    ///     RequestLocationInformation (non-ext SEQ, no preamble):
    ///       criticalExtensions CHOICE -> c1 (index 0 of 2):      0
    ///       c1 CHOICE -> r9 (index 0 of 4, 2 bits):              0 0
    ///       r9-IEs (ext SEQ, 5 opts): ext 0 + [0,0,0,ecid=1,0]:  0 0 0 0 1 0
    ///         ECID-RequestLocationInformation (ext SEQ, 0 opt):
    ///           SEQUENCE ext-marker:                             0
    ///           requestedMeasurements BIT STRING(1..8) = 11000:
    ///             constrained length offset (5-1=4, 3 bits):    1 0 0
    ///             content (5 bits):                             1 1 0 0 0
    ///   ----------------------------------------------------------------
    ///   Concatenated and grouped into octets (last 0 is trailing pad):
    ///     1001 0000 | 0000 0001 | 0010 0000 | 0000 1001 | 0011 0000
    ///     = 0x90      0x01        0x20        0x09        0x30
    #[test]
    fn test_request_location_information_reference_hex() {
        let reference: [u8; 5] = [0x90, 0x01, 0x20, 0x09, 0x30];

        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::LocationServer,
                transaction_number: TransactionNumber(0),
            }),
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::RequestLocationInformation(RequestLocationInformation {
                    ies: RequestLocationInformationR9 {
                        ecid: Some(EcidRequestLocationInformation {
                            requested_measurements: measurements(&[
                                true, true, false, false, false,
                            ]),
                        }),
                    },
                }),
            )),
        };

        // Encode must equal the hand-derived vector...
        assert_eq!(msg.encode().unwrap().as_ref(), &reference[..]);
        // ...and the vector must decode back to the same value.
        assert_eq!(LppMessage::decode(&reference).unwrap(), msg);
    }

    #[test]
    fn rt_lpp_message_request_path() {
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::LocationServer,
                transaction_number: TransactionNumber(11),
            }),
            end_transaction: false,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::RequestLocationInformation(RequestLocationInformation {
                    ies: RequestLocationInformationR9 {
                        ecid: Some(EcidRequestLocationInformation {
                            requested_measurements: measurements(&[true, false, true]),
                        }),
                    },
                }),
            )),
        };
        let bytes = msg.encode().unwrap();
        assert_eq!(LppMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn rt_lpp_message_provide_path_full_envelope() {
        // Exercises every envelope OPTIONAL plus the provide body.
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::TargetDevice,
                transaction_number: TransactionNumber(7),
            }),
            end_transaction: true,
            sequence_number: Some(SequenceNumber(3)),
            acknowledgement: Some(Acknowledgement {
                ack_requested: true,
                ack_indicator: Some(SequenceNumber(2)),
            }),
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                    ies: ProvideLocationInformationR9 {
                        ecid: Some(EcidProvideLocationInformation {
                            signal_measurement_information: Some(
                                EcidSignalMeasurementInformation {
                                    primary_cell_measured_results: Some(sample_element()),
                                    measured_results_list: vec![sample_element()],
                                },
                            ),
                            ecid_error: None,
                        }),
                    },
                }),
            )),
        };
        let bytes = msg.encode().unwrap();
        assert_eq!(LppMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn rt_lpp_message_minimal() {
        // Only the mandatory endTransaction BOOLEAN; everything else absent.
        // Preamble 0000 + endTransaction 0 = 5 bits -> one zero octet.
        let msg = LppMessage {
            transaction_id: None,
            end_transaction: false,
            sequence_number: None,
            acknowledgement: None,
            message_body: None,
        };
        let bytes = msg.encode().unwrap();
        assert_eq!(bytes.as_ref(), &[0x00]);
        assert_eq!(LppMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn rt_lpp_message_class_extension() {
        let msg = LppMessage {
            transaction_id: None,
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::MessageClassExtension),
        };
        let bytes = msg.encode().unwrap();
        assert_eq!(LppMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn err_unsupported_c1_body_index() {
        // c1 CHOICE index 0 (requestCapabilities) is not implemented in v1.
        // Build a minimal stream: LPP-Message preamble [0,0,0,body=1] + end 0 +
        // outer choice c1 (0) + c1 index 0 (0000).
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(None, &[false, false, false, true]);
        enc.write_bit(false); // endTransaction
        enc.encode_choice_index(0, 2, false).unwrap(); // outer -> c1
        enc.encode_choice_index(0, 16, false).unwrap(); // c1 -> requestCapabilities (index 0)
        let bytes = enc.into_bytes();
        assert!(LppMessage::decode(&bytes).is_err());
    }
}
