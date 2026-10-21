//! Sidelink ranging report carried in an LPP EPDU (nextgcore #542, option 2).
//!
//! # This is a non-standard payload in a standard envelope
//!
//! TS 23.586 §5.3.3 defines sidelink ranging as a *procedure*; the 3GPP protocol
//! that carries the result to an LMF is SLPP (TS 38.355, Rel-18), which this repo
//! does not implement yet (post-0.2.0 issue #557). Until it does, nextgsim's UE
//! reports ranges in a payload of nextg's own design, and the only peer that sends
//! it is nextgsim's UE (`nextgsim-ue/src/nas/lpp/message.rs`). A real UE will never
//! send it, and a real LMF would not read it.
//!
//! The payload used to sit in an invented fourth extension-addition group of
//! `ProvideLocationInformation-r9-IEs`, which a conformant LPP codec must skip as an
//! unknown addition (X.691 §19.9). It now rides where TS 37.355 puts non-3GPP data:
//! `epdu-ProvideLocationInformation`, an `EPDU-Sequence` (TS 37.355 §6.5.7). The
//! envelope is decoded by the generated codec (`nextgcore-lpp-gen`); only the
//! `EPDU-Body` octets below are nextg's.
//!
//! # Identifier
//!
//! `EPDU-ID` is `INTEGER (1..256)` and 3GPP assigns no values to it; TS 37.355
//! §6.5.7 leaves the meaning to the external protocol. nextg uses
//! [`EPDU_ID_NEXTG_SIDELINK_RANGING`] together with the name
//! [`EPDU_NAME_NEXTG_SIDELINK_RANGING`]. An EPDU with that ID but a *different*
//! name is someone else's payload and is ignored, so a peer that happens to use the
//! same number cannot be misread as a range report.
//!
//! # Body (unchanged from nextgsim #137)
//!
//! UPER, octet-padded:
//!
//! ```text
//! SidelinkRangingReport ::= SEQUENCE {        -- extensible
//!     results  SEQUENCE (SIZE(1..32)) OF SidelinkRangingResult,
//!     ... }
//! SidelinkRangingResult ::= SEQUENCE {        -- extensible
//!     peerLayer2Id      INTEGER (0..16777215),
//!     rangeCm           INTEGER (0..1000000),
//!     accuracyCm        INTEGER (0..65535),
//!     method            ENUMERATED { rtt, carrierPhase, ... },
//!     measurementCount  INTEGER (0..65535),
//!     ... }
//! ```
//!
//! A body with an extension bit set is refused: this is version 1 of nextg's own
//! format and no later version exists, so a set bit means a corrupt or foreign body.

use nextgcore_lpp_gen::generated as lpp;

/// `EPDU-ID` nextg uses for its sidelink ranging payload. Not 3GPP-assigned.
pub const EPDU_ID_NEXTG_SIDELINK_RANGING: u16 = 256;

/// `EPDU-Name` that must accompany [`EPDU_ID_NEXTG_SIDELINK_RANGING`].
pub const EPDU_NAME_NEXTG_SIDELINK_RANGING: &str = "nextg-sidelink-ranging";

/// How a sidelink range was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidelinkRangingMethod {
    /// Round-trip time over SL-PRS. Metre-level.
    Rtt,
    /// Multi-frequency carrier phase. Centimetre-level.
    CarrierPhase,
}

/// One measured range to one sidelink peer, as encoded in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidelinkRangingResult {
    /// The peer's PC5 Layer-2 identity (TS 23.303 §8.2: 24 bits).
    pub peer_layer2_id: u32,
    /// Range in centimetres.
    pub range_cm: u32,
    /// Accuracy in centimetres.
    pub accuracy_cm: u16,
    /// Measurement method.
    pub method: SidelinkRangingMethod,
    /// Number of measurements the estimate rests on.
    pub measurement_count: u16,
}

/// The ranging report: one entry per ranged peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidelinkRangingReport {
    /// At least one, at most 32.
    pub results: Vec<SidelinkRangingResult>,
}

const PEER_ID_BITS: u32 = 24;
const RANGE_CM_MAX: u32 = 1_000_000;
const RANGE_CM_BITS: u32 = 20;
const U16_BITS: u32 = 16;
const COUNT_BITS: u32 = 5;
const MAX_RESULTS: usize = 32;

struct BitWriter {
    bytes: Vec<u8>,
    bit: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit: 0,
        }
    }

    fn put(&mut self, value: u32, width: u32) {
        for i in (0..width).rev() {
            if self.bit.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> i) & 1 == 1 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 0x80 >> (self.bit % 8);
            }
            self.bit += 1;
        }
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl BitReader<'_> {
    fn take(&mut self, width: u32) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..width {
            let byte = *self
                .bytes
                .get(self.bit / 8)
                .ok_or_else(|| "sidelink ranging body truncated".to_string())?;
            value = (value << 1) | u32::from((byte >> (7 - (self.bit % 8))) & 1);
            self.bit += 1;
        }
        Ok(value)
    }

    fn no_extension(&mut self, what: &str) -> Result<(), String> {
        if self.take(1)? == 1 {
            return Err(format!(
                "sidelink ranging body: {what} has its extension bit set, which no \
                 version of nextg's payload defines"
            ));
        }
        Ok(())
    }
}

/// Encode a report into `EPDU-Body` octets.
pub fn encode_body(report: &SidelinkRangingReport) -> Result<Vec<u8>, String> {
    if report.results.is_empty() || report.results.len() > MAX_RESULTS {
        return Err(format!(
            "sidelink ranging report needs 1..={MAX_RESULTS} results, got {}",
            report.results.len()
        ));
    }
    let mut w = BitWriter::new();
    w.put(0, 1);
    w.put(report.results.len() as u32 - 1, COUNT_BITS);
    for r in &report.results {
        if r.peer_layer2_id >= 1 << PEER_ID_BITS || r.range_cm > RANGE_CM_MAX {
            return Err("sidelink ranging result out of range".to_string());
        }
        w.put(0, 1);
        w.put(r.peer_layer2_id, PEER_ID_BITS);
        w.put(r.range_cm, RANGE_CM_BITS);
        w.put(u32::from(r.accuracy_cm), U16_BITS);
        w.put(0, 1);
        w.put(
            u32::from(r.method == SidelinkRangingMethod::CarrierPhase),
            1,
        );
        w.put(u32::from(r.measurement_count), U16_BITS);
    }
    Ok(w.bytes)
}

/// Decode `EPDU-Body` octets into a report.
pub fn decode_body(body: &[u8]) -> Result<SidelinkRangingReport, String> {
    let mut r = BitReader {
        bytes: body,
        bit: 0,
    };
    r.no_extension("SidelinkRangingReport")?;
    let count = r.take(COUNT_BITS)? as usize + 1;
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        r.no_extension("SidelinkRangingResult")?;
        let peer_layer2_id = r.take(PEER_ID_BITS)?;
        let range_cm = r.take(RANGE_CM_BITS)?;
        if range_cm > RANGE_CM_MAX {
            return Err(format!("rangeCm {range_cm} exceeds {RANGE_CM_MAX}"));
        }
        let accuracy_cm = r.take(U16_BITS)? as u16;
        r.no_extension("method")?;
        let method = if r.take(1)? == 1 {
            SidelinkRangingMethod::CarrierPhase
        } else {
            SidelinkRangingMethod::Rtt
        };
        let measurement_count = r.take(U16_BITS)? as u16;
        results.push(SidelinkRangingResult {
            peer_layer2_id,
            range_cm,
            accuracy_cm,
            method,
            measurement_count,
        });
    }
    Ok(SidelinkRangingReport { results })
}

/// Whether `epdu` is nextg's sidelink ranging payload: the ID matches and the name,
/// if present, matches too.
fn is_ours(epdu: &lpp::EPDU) -> bool {
    epdu.epdu_identifier.epdu_id.0 == EPDU_ID_NEXTG_SIDELINK_RANGING
        && epdu
            .epdu_identifier
            .epdu_name
            .as_ref()
            .is_none_or(|n| n.0 == EPDU_NAME_NEXTG_SIDELINK_RANGING)
}

/// The sidelink ranging report in a `ProvideLocationInformation-r9-IEs`, if any.
///
/// `None` when the message carries no EPDU of nextg's; `Some(Err)` when it does but
/// the body does not decode.
pub fn report_in(
    ies: &lpp::ProvideLocationInformation_r9_IEs,
) -> Option<Result<SidelinkRangingReport, String>> {
    let seq = ies.epdu_provide_location_information.as_ref()?;
    let epdu = seq.0.iter().find(|e| is_ours(e))?;
    Some(decode_body(&epdu.epdu_body.0))
}

/// Build the `EPDU` that carries `report`.
pub fn epdu_for(report: &SidelinkRangingReport) -> Result<lpp::EPDU, String> {
    Ok(lpp::EPDU {
        epdu_identifier: lpp::EPDU_Identifier {
            epdu_id: lpp::EPDU_ID(EPDU_ID_NEXTG_SIDELINK_RANGING),
            epdu_name: Some(lpp::EPDU_Name(EPDU_NAME_NEXTG_SIDELINK_RANGING.to_string())),
        },
        epdu_body: lpp::EPDU_Body(encode_body(report)?),
    })
}

/// An uplink LPP `ProvideLocationInformation` from the target device carrying
/// `report` in nextg's EPDU and nothing else -- what nextgsim's UE sends.
#[cfg(test)]
pub(crate) fn build_message(transaction_number: u8, report: &SidelinkRangingReport) -> Vec<u8> {
    let ies = lpp::ProvideLocationInformation_r9_IEs {
        common_i_es_provide_location_information: None,
        a_gnss_provide_location_information: None,
        otdoa_provide_location_information: None,
        ecid_provide_location_information: None,
        epdu_provide_location_information: Some(lpp::EPDU_Sequence(vec![
            epdu_for(report).expect("epdu")
        ])),
        extensions: Default::default(),
    };
    let msg = lpp::LPP_Message {
        transaction_id: Some(lpp::LPP_TransactionID {
            initiator: lpp::Initiator(lpp::Initiator::TARGET_DEVICE),
            transaction_number: lpp::TransactionNumber(transaction_number),
        }),
        end_transaction: lpp::LPP_MessageEndTransaction(true),
        sequence_number: None,
        acknowledgement: None,
        lpp_message_body: Some(lpp::LPP_MessageBody::C1(
            lpp::LPP_MessageBody_c1::ProvideLocationInformation(lpp::ProvideLocationInformation {
                critical_extensions: lpp::ProvideLocationInformationCriticalExtensions::C1(
                    lpp::ProvideLocationInformationCriticalExtensions_c1::ProvideLocationInformation_r9(ies),
                ),
            }),
        )),
    };
    nextgcore_lpp_gen::encode(&msg).expect("encode")
}

#[cfg(test)]
mod tests;
