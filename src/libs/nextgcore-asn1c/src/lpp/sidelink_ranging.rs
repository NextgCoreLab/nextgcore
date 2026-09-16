//! Sidelink ranging report, UE → LMF (TS 23.586 §5.3.3), UPER.
//!
//! Carried in the **fourth** extension-addition group of
//! `ProvideLocationInformation-r9-IEs`; see
//! [`crate::lpp::ecid::ProvideLocationInformationR9`] for the group framing.
//!
//! # This is a simulator-defined IE, not a cited Rel-18 structure
//!
//! TS 23.586 defines the ranging *procedure*; the LPP IE that carries a sidelink
//! range to an LMF is Rel-18 and is not in any schema this repo vendors. So the
//! structure below is **nextg's own**, and the reason it is safe to define is the
//! reason it is limited: the only peer that sends it is nextgsim's UE
//! (`nextgsim-ue/src/nas/lpp/message.rs`), and the two are held together by a
//! hand-derived golden vector that appears identically in both repos. A real UE
//! would not send this, and a real LMF would not read it.
//!
//! # Why group 4
//!
//! TS 37.355 declares three addition groups on `ProvideLocationInformation-r9-IEs`
//! — G1(r13), G2(r16), G3(r19). G2 is where nr-Multi-RTT and nr-DL-TDOA ride, and
//! G1/G3 this codec skips for forward compatibility. A simulator IE must therefore
//! sit **past** all three rather than squat on one: putting it in G1 would have it
//! silently skipped here while looking correct at the sender (nextgsim #137).

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// How a sidelink range was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidelinkRangingMethod {
    /// Round-trip time over SL-PRS. Metre-level.
    Rtt,
    /// Multi-frequency carrier phase, ambiguity resolved against the RTT.
    /// Centimetre-level.
    CarrierPhase,
}

impl SidelinkRangingMethod {
    /// `ENUMERATED { rtt, carrierPhase, ... }` — extensible, two root values.
    const CONSTRAINT: Constraint = Constraint::extensible(0, 1);

    fn index(self) -> i64 {
        match self {
            Self::Rtt => 0,
            Self::CarrierPhase => 1,
        }
    }

    fn from_index(index: i64) -> PerResult<Self> {
        match index {
            0 => Ok(Self::Rtt),
            1 => Ok(Self::CarrierPhase),
            other => Err(PerError::DecodeError(format!(
                "unknown sidelink ranging method index {other}"
            ))),
        }
    }
}

/// One measured range to one sidelink peer.
///
/// ```text
/// SidelinkRangingResult ::= SEQUENCE {   -- EXTENSIBLE
///     peerLayer2Id      INTEGER (0..16777215),
///     rangeCm           INTEGER (0..1000000),
///     accuracyCm        INTEGER (0..65535),
///     method            ENUMERATED { rtt, carrierPhase, ... },
///     measurementCount  INTEGER (0..65535),
///     ... }
/// ```
///
/// Centimetres because the sender's carrier-phase estimate is centimetre-level;
/// whole metres would make an RTT fix and a carrier-phase fix indistinguishable in
/// the number the LMF stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidelinkRangingResult {
    /// The peer's PC5 Layer-2 identity (TS 23.303 §8.2: 24 bits).
    pub peer_layer2_id: u32,
    /// Range in centimetres.
    pub range_cm: u32,
    /// Reported accuracy in centimetres.
    pub accuracy_cm: u16,
    /// How it was measured.
    pub method: SidelinkRangingMethod,
    /// How many measurements the estimate rests on.
    pub measurement_count: u16,
}

impl SidelinkRangingResult {
    const PEER_ID: Constraint = Constraint::new(0, 16_777_215);
    const RANGE_CM: Constraint = Constraint::new(0, 1_000_000);
    const ACCURACY_CM: Constraint = Constraint::new(0, 65_535);
    const COUNT: Constraint = Constraint::new(0, 65_535);

    /// The range in metres, for a consumer that wants one.
    #[must_use]
    pub fn range_m(&self) -> f64 {
        f64::from(self.range_cm) / 100.0
    }

    /// The reported accuracy in metres.
    #[must_use]
    pub fn accuracy_m(&self) -> f64 {
        f64::from(self.accuracy_cm) / 100.0
    }
}

impl UperEncode for SidelinkRangingResult {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_constrained_whole_number(i64::from(self.peer_layer2_id), &Self::PEER_ID)?;
        encoder.encode_constrained_whole_number(i64::from(self.range_cm), &Self::RANGE_CM)?;
        encoder.encode_constrained_whole_number(i64::from(self.accuracy_cm), &Self::ACCURACY_CM)?;
        encoder.encode_enumerated(self.method.index(), &SidelinkRangingMethod::CONSTRAINT)?;
        encoder.encode_constrained_whole_number(i64::from(self.measurement_count), &Self::COUNT)
    }
}

impl UperDecode for SidelinkRangingResult {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _) = decoder.decode_sequence_preamble(true, 0)?;
        let peer_layer2_id = decoder.decode_constrained_whole_number(&Self::PEER_ID)? as u32;
        let range_cm = decoder.decode_constrained_whole_number(&Self::RANGE_CM)? as u32;
        let accuracy_cm = decoder.decode_constrained_whole_number(&Self::ACCURACY_CM)? as u16;
        let method = SidelinkRangingMethod::from_index(
            decoder.decode_enumerated(&SidelinkRangingMethod::CONSTRAINT)?,
        )?;
        let measurement_count = decoder.decode_constrained_whole_number(&Self::COUNT)? as u16;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(Self {
            peer_layer2_id,
            range_cm,
            accuracy_cm,
            method,
            measurement_count,
        })
    }
}

/// The sidelink ranging report as a whole.
///
/// ```text
/// SidelinkRangingReport ::= SEQUENCE {   -- EXTENSIBLE
///     results  SEQUENCE (SIZE(1..32)) OF SidelinkRangingResult,
///     ... }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidelinkRangingReport {
    /// One entry per ranged peer; at least one, because the list is `SIZE(1..32)`.
    pub results: Vec<SidelinkRangingResult>,
}

impl SidelinkRangingReport {
    /// `SEQUENCE (SIZE(1..32))`.
    const COUNT: Constraint = Constraint::new(1, 32);
}

impl UperEncode for SidelinkRangingReport {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        if self.results.is_empty() || self.results.len() > Self::COUNT.max as usize {
            return Err(PerError::InvalidLength {
                length: self.results.len(),
            });
        }
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_constrained_whole_number(self.results.len() as i64, &Self::COUNT)?;
        for result in &self.results {
            result.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for SidelinkRangingReport {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _) = decoder.decode_sequence_preamble(true, 0)?;
        let count = decoder.decode_constrained_whole_number(&Self::COUNT)? as usize;
        let mut results = Vec::with_capacity(count);
        for _ in 0..count {
            results.push(SidelinkRangingResult::decode_uper(decoder)?);
        }
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(Self { results })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sender's own hand-derived vector, copied from nextgsim's
    /// `GOLDEN_SIDELINK_RANGING_REPORT` together with its bit-by-bit derivation:
    ///
    /// ```text
    ///   SidelinkRangingReport SEQUENCE, extensible, no additions:   0
    ///   results count 1, SIZE(1..32) -> 5 bits of (1-1):            0 0000
    ///   SidelinkRangingResult SEQUENCE, extensible, no additions:   0
    ///   peerLayer2Id 0xA5A5A5, INTEGER(0..16777215) -> 24 bits:     1010 0101 1010 0101 1010 0101
    ///   rangeCm 5000, INTEGER(0..1000000) -> 20 bits:               0000 0001 0011 1000 1000
    ///   accuracyCm 1, INTEGER(0..65535) -> 16 bits:                 0000 0000 0000 0001
    ///   method: extensible ENUMERATED, root value:                  0
    ///          index 1 (carrierPhase), root max 1 -> 1 bit:         1
    ///   measurementCount 3, INTEGER(0..65535) -> 16 bits:           0000 0000 0000 0011
    ///                                                              = 85 bits, padded to 11 octets
    /// ```
    ///
    /// This is the ONLY evidence the two codecs agree: they are separate products,
    /// so a round trip through this one alone would pass however wrong both were.
    const SENDER_GOLDEN_REPORT: &[u8] = &[
        0x01, 0x4B, 0x4B, 0x4A, 0x02, 0x71, 0x00, 0x00, 0x28, 0x00, 0x18,
    ];

    fn golden_report() -> SidelinkRangingReport {
        SidelinkRangingReport {
            results: vec![SidelinkRangingResult {
                peer_layer2_id: 0x00A5_A5A5,
                range_cm: 5_000,
                accuracy_cm: 1,
                method: SidelinkRangingMethod::CarrierPhase,
                measurement_count: 3,
            }],
        }
    }

    #[test]
    fn the_senders_golden_report_decodes_to_what_it_says_it_is() {
        let mut decoder = UperDecoder::new(SENDER_GOLDEN_REPORT);
        let report = SidelinkRangingReport::decode_uper(&mut decoder).expect("decodes");
        assert_eq!(report, golden_report());
        assert_eq!(report.results[0].range_m(), 50.0, "50.00 m");
        assert_eq!(report.results[0].accuracy_m(), 0.01, "1 cm");
    }

    #[test]
    fn this_codec_produces_the_senders_golden_bytes() {
        let mut encoder = UperEncoder::new();
        golden_report().encode_uper(&mut encoder).expect("encodes");
        assert_eq!(encoder.into_bytes().to_vec(), SENDER_GOLDEN_REPORT);
    }

    #[test]
    fn an_empty_result_list_is_refused_rather_than_encoded() {
        let mut encoder = UperEncoder::new();
        assert!(
            SidelinkRangingReport { results: vec![] }
                .encode_uper(&mut encoder)
                .is_err(),
            "SIZE(1..32) cannot be empty, and an empty encoding would not decode"
        );
    }

    #[test]
    fn several_results_round_trip_in_order() {
        let report = SidelinkRangingReport {
            results: (0..4)
                .map(|index| SidelinkRangingResult {
                    peer_layer2_id: 100 + index,
                    range_cm: 1_000 * (index + 1),
                    accuracy_cm: 100,
                    method: SidelinkRangingMethod::Rtt,
                    measurement_count: 1,
                })
                .collect(),
        };
        let mut encoder = UperEncoder::new();
        report.encode_uper(&mut encoder).expect("encodes");
        let bytes = encoder.into_bytes().to_vec();
        let mut decoder = UperDecoder::new(&bytes);
        assert_eq!(
            SidelinkRangingReport::decode_uper(&mut decoder).expect("decodes"),
            report,
            "order matters: an LMF pairs each range with its peer id"
        );
    }
}
