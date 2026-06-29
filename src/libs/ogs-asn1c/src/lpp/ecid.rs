//! LPP E-CID location-information bodies (3GPP TS 37.355 §6.4 / §6.5), UPER.
//!
//! Implements the Enhanced-Cell-ID (E-CID) location loop:
//!   * `RequestLocationInformation` / `ProvideLocationInformation` message
//!     bodies and their `criticalExtensions` → `c1` → `*-r9-IEs` nesting,
//!   * `ECID-RequestLocationInformation` (the requested-measurements bit map),
//!   * `ECID-ProvideLocationInformation` → `ECID-SignalMeasurementInformation`
//!     → `MeasuredResultsList`/`MeasuredResultsElement`, and
//!   * `ECID-Error` (location-server / target-device cause SEQUENCEs).
//!
//! v1 FOUNDATION scope: only the E-CID method is typed. The other root
//! positioning methods (commonIEs, A-GNSS, OTDOA, EPDU, and the
//! `CellGlobalIdEUTRA-AndUTRA` field inside a measured-results element) are
//! modeled UNSUPPORTED-ABSENT — never emitted on encode, and rejected on decode
//! if a peer sets the corresponding presence bit. Follow-on chunks type them.

use bitvec::prelude::*;

use super::nr_dl_tdoa::NrDlTdoaProvideLocationInformation;
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// RequestLocationInformation
// ---------------------------------------------------------------------------

/// RequestLocationInformation ::= SEQUENCE {
///     criticalExtensions CHOICE {
///         c1 CHOICE {
///             requestLocationInformation-r9 RequestLocationInformation-r9-IEs,
///             spare3 NULL, spare2 NULL, spare1 NULL },
///         criticalExtensionsFuture SEQUENCE {} } }
///
/// The outer SEQUENCE is non-extensible with no optional root fields, so it
/// contributes NO preamble bits.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestLocationInformation {
    pub ies: RequestLocationInformationR9,
}

impl UperEncode for RequestLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // criticalExtensions CHOICE: c1 (index 0 of 2, non-extensible) -> 1 bit.
        encoder.encode_choice_index(0, 2, false)?;
        // c1 CHOICE: requestLocationInformation-r9 (index 0 of 4) -> 2 bits.
        encoder.encode_choice_index(0, 4, false)?;
        self.ies.encode_uper(encoder)
    }
}

impl UperDecode for RequestLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let critical_extensions = decoder.decode_choice_index(2, false)?;
        if critical_extensions != 0 {
            return Err(PerError::DecodeError(
                "LPP RequestLocationInformation criticalExtensionsFuture not supported".to_string(),
            ));
        }
        let c1 = decoder.decode_choice_index(4, false)?;
        if c1 != 0 {
            return Err(PerError::DecodeError(format!(
                "LPP RequestLocationInformation c1 index {c1} (spare) not supported"
            )));
        }
        let ies = RequestLocationInformationR9::decode_uper(decoder)?;
        Ok(RequestLocationInformation { ies })
    }
}

/// RequestLocationInformation-r9-IEs ::= SEQUENCE {  -- EXTENSIBLE
///     commonIEsRequestLocationInformation OPTIONAL,
///     a-gnss-RequestLocationInformation   OPTIONAL,
///     otdoa-RequestLocationInformation    OPTIONAL,
///     ecid-RequestLocationInformation     OPTIONAL,
///     epdu-RequestLocationInformation     OPTIONAL,
///     ..., [[ ...later release groups... ]] }
///
/// v1 types ONLY the `ecid` root method. The other four root optionals
/// (commonIEs, a-gnss, otdoa, epdu) are UNSUPPORTED-ABSENT.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestLocationInformationR9 {
    pub ecid: Option<EcidRequestLocationInformation>,
}

impl UperEncode for RequestLocationInformationR9 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Root presence bits: [commonIEs, a-gnss, otdoa, ecid, epdu].
        encoder.encode_sequence_preamble(
            Some(false),
            &[false, false, false, self.ecid.is_some(), false],
        );
        if let Some(ecid) = &self.ecid {
            ecid.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for RequestLocationInformationR9 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 5)?;
        // opts = [commonIEs, a-gnss, otdoa, ecid, epdu]
        if opts[0] || opts[1] || opts[2] || opts[4] {
            return Err(PerError::DecodeError(
                "unsupported LPP RequestLocationInformation method present (v1 supports E-CID only)"
                    .to_string(),
            ));
        }
        let ecid = if opts[3] {
            Some(EcidRequestLocationInformation::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(RequestLocationInformationR9 { ecid })
    }
}

// ---------------------------------------------------------------------------
// ProvideLocationInformation
// ---------------------------------------------------------------------------

/// ProvideLocationInformation ::= SEQUENCE {
///     criticalExtensions CHOICE {
///         c1 CHOICE {
///             provideLocationInformation-r9 ProvideLocationInformation-r9-IEs,
///             spare3 NULL, spare2 NULL, spare1 NULL },
///         criticalExtensionsFuture SEQUENCE {} } }
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideLocationInformation {
    pub ies: ProvideLocationInformationR9,
}

impl UperEncode for ProvideLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_choice_index(0, 2, false)?;
        encoder.encode_choice_index(0, 4, false)?;
        self.ies.encode_uper(encoder)
    }
}

impl UperDecode for ProvideLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let critical_extensions = decoder.decode_choice_index(2, false)?;
        if critical_extensions != 0 {
            return Err(PerError::DecodeError(
                "LPP ProvideLocationInformation criticalExtensionsFuture not supported".to_string(),
            ));
        }
        let c1 = decoder.decode_choice_index(4, false)?;
        if c1 != 0 {
            return Err(PerError::DecodeError(format!(
                "LPP ProvideLocationInformation c1 index {c1} (spare) not supported"
            )));
        }
        let ies = ProvideLocationInformationR9::decode_uper(decoder)?;
        Ok(ProvideLocationInformation { ies })
    }
}

/// ProvideLocationInformation-r9-IEs ::= SEQUENCE {  -- EXTENSIBLE
///     commonIEsProvideLocationInformation OPTIONAL,
///     a-gnss-ProvideLocationInformation   OPTIONAL,
///     otdoa-ProvideLocationInformation    OPTIONAL,
///     ecid-ProvideLocationInformation     OPTIONAL,
///     epdu-ProvideLocationInformation     OPTIONAL,
///     ...,
///     [[ G1(r13): sensor / tbs / wlan / bt ]],
///     [[ G2(r16): nr-ECID / nr-Multi-RTT / nr-DL-AoD / nr-DL-TDOA ]],
///     [[ G3(r19): nr-DL-AIML ]] }
///
/// The 5 root optionals type ONLY the `ecid` method (others UNSUPPORTED-ABSENT,
/// as on the request side). The NR DL-TDOA provide-body rides in the **r16
/// extension-addition group G2, member index 3** (4th of
/// `[nr-ECID, nr-Multi-RTT, nr-DL-AoD, nr-DL-TDOA]`). Per X.691 §18.9 the group
/// is itself encoded as a non-extensible SEQUENCE of its 4 OPTIONAL members,
/// open-type-wrapped as the 2nd of the 3 declared addition groups (G1/G2/G3).
///
/// BACKWARD COMPAT: when `nr_dl_tdoa` is `None`, no addition is emitted
/// (extension marker 0), so the encoding is byte-identical to the E-CID-only
/// v1 form.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideLocationInformationR9 {
    pub ecid: Option<EcidProvideLocationInformation>,
    /// NR DL-TDOA provide-body, carried in the r16 extension-addition group.
    pub nr_dl_tdoa: Option<NrDlTdoaProvideLocationInformation>,
}

impl UperEncode for ProvideLocationInformationR9 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        let has_add = self.nr_dl_tdoa.is_some();
        // Extension marker = whether any extension addition follows.
        encoder.encode_sequence_preamble(
            Some(has_add),
            &[false, false, false, self.ecid.is_some(), false],
        );
        if let Some(ecid) = &self.ecid {
            ecid.encode_uper(encoder)?;
        }
        if has_add {
            // Build the r16 group (G2) content: a non-extensible SEQUENCE whose
            // 4 OPTIONAL members are [nr-ECID, nr-Multi-RTT, nr-DL-AoD,
            // nr-DL-TDOA]; only nr-DL-TDOA (index 3) is present.
            let mut g2 = UperEncoder::new();
            g2.encode_sequence_preamble(
                None,
                &[false, false, false, self.nr_dl_tdoa.is_some()],
            );
            if let Some(tdoa) = &self.nr_dl_tdoa {
                tdoa.encode_uper(&mut g2)?;
            }
            let g2_bytes = g2.into_bytes().to_vec();
            // Addition groups [G1(r13), G2(r16), G3(r19)] — only G2 present.
            // Canonical X.691 §18.8: the extension-presence bit-field is trimmed
            // to the last present addition, so the trailing-absent G3 is dropped.
            encoder.encode_extension_additions(&[None, Some(g2_bytes)])?;
        }
        Ok(())
    }
}

impl UperDecode for ProvideLocationInformationR9 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 5)?;
        if opts[0] || opts[1] || opts[2] || opts[4] {
            return Err(PerError::DecodeError(
                "unsupported LPP ProvideLocationInformation method present (v1 supports E-CID only)"
                    .to_string(),
            ));
        }
        let ecid = if opts[3] {
            Some(EcidProvideLocationInformation::decode_uper(decoder)?)
        } else {
            None
        };
        let mut nr_dl_tdoa = None;
        if ext {
            // groups[0]=G1(r13), groups[1]=G2(r16), groups[2]=G3(r19) — index by
            // position; a peer may send fewer groups (trailing-absent trimmed).
            let groups = decoder.decode_extension_additions()?;
            if let Some(Some(g2_bytes)) = groups.get(1) {
                let mut g2 = UperDecoder::new(g2_bytes);
                let (_g_ext, g_opts) = g2.decode_sequence_preamble(false, 4)?;
                // g_opts = [nr-ECID, nr-Multi-RTT, nr-DL-AoD, nr-DL-TDOA]
                if g_opts[0] || g_opts[1] || g_opts[2] {
                    return Err(PerError::DecodeError(
                        "LPP r16 provide group: nr-ECID / nr-Multi-RTT / nr-DL-AoD not supported \
                         in C3 (nr-DL-TDOA only)"
                            .to_string(),
                    ));
                }
                if g_opts[3] {
                    nr_dl_tdoa =
                        Some(NrDlTdoaProvideLocationInformation::decode_uper(&mut g2)?);
                }
            }
            // groups[0] (r13) and groups[2] (r19), if present, are ignored
            // (forward-compat skip).
        }
        Ok(ProvideLocationInformationR9 { ecid, nr_dl_tdoa })
    }
}

// ---------------------------------------------------------------------------
// ECID-RequestLocationInformation
// ---------------------------------------------------------------------------

/// ECID-RequestLocationInformation ::= SEQUENCE {  -- EXTENSIBLE
///     requestedMeasurements BIT STRING {
///         rsrpReq(0), rsrqReq(1), ueRxTxReq(2),
///         nrsrpReq-r14(3), nrsrqReq-r14(4) } (SIZE(1..8)),
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct EcidRequestLocationInformation {
    /// requestedMeasurements bit map, SIZE(1..8): bit 0 = rsrpReq, bit 1 =
    /// rsrqReq, bit 2 = ueRxTxReq, bit 3 = nrsrpReq-r14, bit 4 = nrsrqReq-r14.
    pub requested_measurements: BitVec<u8, Msb0>,
}

impl UperEncode for EcidRequestLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_bit_string(&self.requested_measurements, Some(1), Some(8))
    }
}

impl UperDecode for EcidRequestLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let requested_measurements = decoder.decode_bit_string(Some(1), Some(8))?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidRequestLocationInformation {
            requested_measurements,
        })
    }
}

// ---------------------------------------------------------------------------
// ECID-ProvideLocationInformation
// ---------------------------------------------------------------------------

/// ECID-ProvideLocationInformation ::= SEQUENCE {  -- EXTENSIBLE
///     ecid-SignalMeasurementInformation ECID-SignalMeasurementInformation OPTIONAL,
///     ecid-Error ECID-Error OPTIONAL,
///     ... }
#[derive(Debug, Clone, PartialEq)]
pub struct EcidProvideLocationInformation {
    pub signal_measurement_information: Option<EcidSignalMeasurementInformation>,
    pub ecid_error: Option<EcidError>,
}

impl UperEncode for EcidProvideLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.signal_measurement_information.is_some(),
                self.ecid_error.is_some(),
            ],
        );
        if let Some(sig) = &self.signal_measurement_information {
            sig.encode_uper(encoder)?;
        }
        if let Some(err) = &self.ecid_error {
            err.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for EcidProvideLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 2)?;
        let signal_measurement_information = if opts[0] {
            Some(EcidSignalMeasurementInformation::decode_uper(decoder)?)
        } else {
            None
        };
        let ecid_error = if opts[1] {
            Some(EcidError::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidProvideLocationInformation {
            signal_measurement_information,
            ecid_error,
        })
    }
}

// ---------------------------------------------------------------------------
// ECID-SignalMeasurementInformation / MeasuredResultsList
// ---------------------------------------------------------------------------

/// ECID-SignalMeasurementInformation ::= SEQUENCE {  -- EXTENSIBLE
///     primaryCellMeasuredResults MeasuredResultsElement OPTIONAL,
///     measuredResultsList MeasuredResultsList,
///     ... }
/// MeasuredResultsList ::= SEQUENCE (SIZE(1..32)) OF MeasuredResultsElement
#[derive(Debug, Clone, PartialEq)]
pub struct EcidSignalMeasurementInformation {
    pub primary_cell_measured_results: Option<MeasuredResultsElement>,
    pub measured_results_list: Vec<MeasuredResultsElement>,
}

impl EcidSignalMeasurementInformation {
    /// MeasuredResultsList size constraint (1..32 -> 5-bit count).
    const LIST_CONSTRAINT: Constraint = Constraint::new(1, 32);
}

impl UperEncode for EcidSignalMeasurementInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[self.primary_cell_measured_results.is_some()],
        );
        if let Some(primary) = &self.primary_cell_measured_results {
            primary.encode_uper(encoder)?;
        }
        // SEQUENCE-OF length as a constrained whole number (1..32), then elements.
        encoder.encode_constrained_whole_number(
            self.measured_results_list.len() as i64,
            &Self::LIST_CONSTRAINT,
        )?;
        for element in &self.measured_results_list {
            element.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for EcidSignalMeasurementInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 1)?;
        let primary_cell_measured_results = if opts[0] {
            Some(MeasuredResultsElement::decode_uper(decoder)?)
        } else {
            None
        };
        let count = decoder.decode_constrained_whole_number(&Self::LIST_CONSTRAINT)? as usize;
        let mut measured_results_list = Vec::with_capacity(count);
        for _ in 0..count {
            measured_results_list.push(MeasuredResultsElement::decode_uper(decoder)?);
        }
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidSignalMeasurementInformation {
            primary_cell_measured_results,
            measured_results_list,
        })
    }
}

/// MeasuredResultsElement ::= SEQUENCE {  -- EXTENSIBLE
///     physCellId        INTEGER (0..503),
///     cellGlobalId      CellGlobalIdEUTRA-AndUTRA OPTIONAL,  -- UNSUPPORTED-ABSENT
///     arfcnEUTRA        ARFCN-ValueEUTRA,                    -- INTEGER (0..65535)
///     systemFrameNumber BIT STRING (SIZE(10)) OPTIONAL,
///     rsrp-Result       INTEGER (0..97)   OPTIONAL,
///     rsrq-Result       INTEGER (0..34)   OPTIONAL,
///     ue-RxTxTimeDiff   INTEGER (0..4095) OPTIONAL,
///     ..., [[ ...later release groups... ]] }
///
/// Root optionals in declaration order:
/// `[cellGlobalId, systemFrameNumber, rsrp-Result, rsrq-Result, ue-RxTxTimeDiff]`.
/// `cellGlobalId` (CellGlobalIdEUTRA-AndUTRA) is UNSUPPORTED-ABSENT in v1:
/// always absent on encode, rejected on decode if its presence bit is set.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredResultsElement {
    pub phys_cell_id: u16,
    pub arfcn_eutra: u32,
    pub system_frame_number: Option<BitVec<u8, Msb0>>,
    pub rsrp_result: Option<u8>,
    pub rsrq_result: Option<u8>,
    pub ue_rx_tx_time_diff: Option<u16>,
}

impl MeasuredResultsElement {
    const PHYS_CELL_ID: Constraint = Constraint::new(0, 503);
    const ARFCN_EUTRA: Constraint = Constraint::new(0, 65535);
    const RSRP_RESULT: Constraint = Constraint::new(0, 97);
    const RSRQ_RESULT: Constraint = Constraint::new(0, 34);
    const UE_RX_TX_TIME_DIFF: Constraint = Constraint::new(0, 4095);
    const SFN_BITS: usize = 10;
}

impl UperEncode for MeasuredResultsElement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                false, // cellGlobalId: UNSUPPORTED-ABSENT
                self.system_frame_number.is_some(),
                self.rsrp_result.is_some(),
                self.rsrq_result.is_some(),
                self.ue_rx_tx_time_diff.is_some(),
            ],
        );
        encoder.encode_constrained_whole_number(self.phys_cell_id as i64, &Self::PHYS_CELL_ID)?;
        // cellGlobalId absent -> no content.
        encoder.encode_constrained_whole_number(self.arfcn_eutra as i64, &Self::ARFCN_EUTRA)?;
        if let Some(sfn) = &self.system_frame_number {
            encoder.encode_bit_string(sfn, Some(Self::SFN_BITS), Some(Self::SFN_BITS))?;
        }
        if let Some(rsrp) = self.rsrp_result {
            encoder.encode_constrained_whole_number(rsrp as i64, &Self::RSRP_RESULT)?;
        }
        if let Some(rsrq) = self.rsrq_result {
            encoder.encode_constrained_whole_number(rsrq as i64, &Self::RSRQ_RESULT)?;
        }
        if let Some(rxtx) = self.ue_rx_tx_time_diff {
            encoder.encode_constrained_whole_number(rxtx as i64, &Self::UE_RX_TX_TIME_DIFF)?;
        }
        Ok(())
    }
}

impl UperDecode for MeasuredResultsElement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 5)?;
        // opts = [cellGlobalId, systemFrameNumber, rsrp, rsrq, ueRxTx]
        if opts[0] {
            return Err(PerError::DecodeError(
                "LPP MeasuredResultsElement cellGlobalId not supported in v1 foundation".to_string(),
            ));
        }
        let phys_cell_id = decoder.decode_constrained_whole_number(&Self::PHYS_CELL_ID)? as u16;
        let arfcn_eutra = decoder.decode_constrained_whole_number(&Self::ARFCN_EUTRA)? as u32;
        let system_frame_number = if opts[1] {
            Some(decoder.decode_bit_string(Some(Self::SFN_BITS), Some(Self::SFN_BITS))?)
        } else {
            None
        };
        let rsrp_result = if opts[2] {
            Some(decoder.decode_constrained_whole_number(&Self::RSRP_RESULT)? as u8)
        } else {
            None
        };
        let rsrq_result = if opts[3] {
            Some(decoder.decode_constrained_whole_number(&Self::RSRQ_RESULT)? as u8)
        } else {
            None
        };
        let ue_rx_tx_time_diff = if opts[4] {
            Some(decoder.decode_constrained_whole_number(&Self::UE_RX_TX_TIME_DIFF)? as u16)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(MeasuredResultsElement {
            phys_cell_id,
            arfcn_eutra,
            system_frame_number,
            rsrp_result,
            rsrq_result,
            ue_rx_tx_time_diff,
        })
    }
}

// ---------------------------------------------------------------------------
// ECID-Error
// ---------------------------------------------------------------------------

/// ECID-Error ::= CHOICE {  -- EXTENSIBLE, 2 root alternatives
///     locationServerErrorCauses ECID-LocationServerErrorCauses,
///     targetDeviceErrorCauses   ECID-TargetDeviceErrorCauses,
///     ... }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcidError {
    LocationServerErrorCauses(EcidLocationServerErrorCauses),
    TargetDeviceErrorCauses(EcidTargetDeviceErrorCauses),
}

impl EcidError {
    const NUM_ALTERNATIVES: usize = 2;
}

impl UperEncode for EcidError {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        match self {
            EcidError::LocationServerErrorCauses(causes) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, true)?;
                causes.encode_uper(encoder)
            }
            EcidError::TargetDeviceErrorCauses(causes) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, true)?;
                causes.encode_uper(encoder)
            }
        }
    }
}

impl UperDecode for EcidError {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, true)?;
        match index {
            0 => Ok(EcidError::LocationServerErrorCauses(
                EcidLocationServerErrorCauses::decode_uper(decoder)?,
            )),
            1 => Ok(EcidError::TargetDeviceErrorCauses(
                EcidTargetDeviceErrorCauses::decode_uper(decoder)?,
            )),
            n => Err(PerError::DecodeError(format!(
                "LPP ECID-Error extension alternative {n} not supported in v1 foundation"
            ))),
        }
    }
}

/// ECID-LocationServerErrorCauses ::= SEQUENCE {  -- EXTENSIBLE
///     cause ENUMERATED { undefined, ... },        -- EXTENSIBLE, root size 1
///     ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcidLocationServerErrorCauses {
    /// `cause` enum value; the root has a single value `undefined`(0).
    pub cause: u8,
}

impl EcidLocationServerErrorCauses {
    const CAUSE: Constraint = Constraint::extensible(0, 0);
}

impl UperEncode for EcidLocationServerErrorCauses {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_enumerated(self.cause as i64, &Self::CAUSE)
    }
}

impl UperDecode for EcidLocationServerErrorCauses {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let cause = decoder.decode_enumerated(&Self::CAUSE)? as u8;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidLocationServerErrorCauses { cause })
    }
}

/// ECID-TargetDeviceErrorCauses ::= SEQUENCE {  -- EXTENSIBLE
///     cause ENUMERATED {
///         undefined,
///         requestedMeasurementNotAvailable,
///         notAllrequestedMeasurementsPossible, ... },  -- EXTENSIBLE, root size 3
///     rsrpMeasurementNotPossible   NULL OPTIONAL,
///     rsrqMeasurementNotPossible   NULL OPTIONAL,
///     ueRxTxMeasurementNotPossible NULL OPTIONAL,
///     ... }
///
/// Each NULL OPTIONAL contributes a presence bit but no content, so it is
/// modeled as a bool: present (`true`) means the NULL is signalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcidTargetDeviceErrorCauses {
    /// `cause` enum: 0 = undefined, 1 = requestedMeasurementNotAvailable,
    /// 2 = notAllrequestedMeasurementsPossible.
    pub cause: u8,
    pub rsrp_measurement_not_possible: bool,
    pub rsrq_measurement_not_possible: bool,
    pub ue_rx_tx_measurement_not_possible: bool,
}

impl EcidTargetDeviceErrorCauses {
    const CAUSE: Constraint = Constraint::extensible(0, 2);
}

impl UperEncode for EcidTargetDeviceErrorCauses {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Presence bits for the three NULL OPTIONALs, in declaration order.
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.rsrp_measurement_not_possible,
                self.rsrq_measurement_not_possible,
                self.ue_rx_tx_measurement_not_possible,
            ],
        );
        // `cause` (mandatory) follows the preamble; the NULLs carry no content.
        encoder.encode_enumerated(self.cause as i64, &Self::CAUSE)?;
        Ok(())
    }
}

impl UperDecode for EcidTargetDeviceErrorCauses {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        let cause = decoder.decode_enumerated(&Self::CAUSE)? as u8;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidTargetDeviceErrorCauses {
            cause,
            rsrp_measurement_not_possible: opts[0],
            rsrq_measurement_not_possible: opts[1],
            ue_rx_tx_measurement_not_possible: opts[2],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpp::nr_dl_tdoa::{
        DlPrsIdInfo, NrDlTdoaMeasElement, NrDlTdoaMeasList, NrDlTdoaSignalMeasurementInformation,
        NrRstd, NrSlot, NrTimeStamp, NrTimingQuality,
    };

    fn minimal_nr_dl_tdoa() -> NrDlTdoaProvideLocationInformation {
        NrDlTdoaProvideLocationInformation {
            signal_measurement_information: Some(NrDlTdoaSignalMeasurementInformation {
                dl_prs_reference_info: DlPrsIdInfo { dl_prs_id: 0 },
                meas_list: NrDlTdoaMeasList {
                    items: vec![NrDlTdoaMeasElement {
                        dl_prs_id: 0,
                        nr_phys_cell_id: None,
                        nr_arfcn: None,
                        nr_time_stamp: NrTimeStamp {
                            dl_prs_id: 0,
                            nr_phys_cell_id: None,
                            nr_arfcn: None,
                            nr_sfn: 0,
                            nr_slot: NrSlot::Scs15(0),
                        },
                        nr_rstd: NrRstd::K0(0),
                        nr_timing_quality: NrTimingQuality {
                            timing_quality_value: 0,
                            timing_quality_resolution: 0,
                        },
                        nr_dl_prs_rsrp_result: None,
                    }],
                },
            }),
        }
    }

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

    fn bits(values: &[bool]) -> BitVec<u8, Msb0> {
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

    fn all_present_element() -> MeasuredResultsElement {
        MeasuredResultsElement {
            phys_cell_id: 503,
            arfcn_eutra: 65535,
            system_frame_number: Some(bits(&[
                true, false, true, false, true, false, true, false, true, false,
            ])),
            rsrp_result: Some(97),
            rsrq_result: Some(34),
            ue_rx_tx_time_diff: Some(4095),
        }
    }

    fn none_element() -> MeasuredResultsElement {
        MeasuredResultsElement {
            phys_cell_id: 0,
            arfcn_eutra: 0,
            system_frame_number: None,
            rsrp_result: None,
            rsrq_result: None,
            ue_rx_tx_time_diff: None,
        }
    }

    #[test]
    fn rt_ecid_request_location_information() {
        let cases: [&[bool]; 3] = [
            &[true],
            &[true, true, false, false, false],
            &[true, true, true, true, true, true, true, true],
        ];
        for case in cases {
            roundtrip(&EcidRequestLocationInformation {
                requested_measurements: bits(case),
            });
        }
    }

    #[test]
    fn rt_request_location_information() {
        roundtrip(&RequestLocationInformation {
            ies: RequestLocationInformationR9 {
                ecid: Some(EcidRequestLocationInformation {
                    requested_measurements: bits(&[true, true, false, false, false]),
                }),
            },
        });
        // ecid absent (an otherwise-empty request).
        roundtrip(&RequestLocationInformation {
            ies: RequestLocationInformationR9 { ecid: None },
        });
    }

    #[test]
    fn rt_measured_results_element() {
        roundtrip(&sample_element());
        roundtrip(&all_present_element());
        roundtrip(&none_element());
    }

    #[test]
    fn rt_ecid_signal_measurement_information() {
        roundtrip(&EcidSignalMeasurementInformation {
            primary_cell_measured_results: Some(sample_element()),
            measured_results_list: vec![sample_element()],
        });
        roundtrip(&EcidSignalMeasurementInformation {
            primary_cell_measured_results: None,
            measured_results_list: vec![all_present_element(), none_element(), sample_element()],
        });
    }

    #[test]
    fn rt_ecid_provide_location_information() {
        // signal only
        roundtrip(&EcidProvideLocationInformation {
            signal_measurement_information: Some(EcidSignalMeasurementInformation {
                primary_cell_measured_results: Some(sample_element()),
                measured_results_list: vec![sample_element(), none_element()],
            }),
            ecid_error: None,
        });
        // error only
        roundtrip(&EcidProvideLocationInformation {
            signal_measurement_information: None,
            ecid_error: Some(EcidError::LocationServerErrorCauses(
                EcidLocationServerErrorCauses { cause: 0 },
            )),
        });
        // both
        roundtrip(&EcidProvideLocationInformation {
            signal_measurement_information: Some(EcidSignalMeasurementInformation {
                primary_cell_measured_results: None,
                measured_results_list: vec![sample_element()],
            }),
            ecid_error: Some(EcidError::TargetDeviceErrorCauses(
                EcidTargetDeviceErrorCauses {
                    cause: 0,
                    rsrp_measurement_not_possible: false,
                    rsrq_measurement_not_possible: false,
                    ue_rx_tx_measurement_not_possible: false,
                },
            )),
        });
        // neither
        roundtrip(&EcidProvideLocationInformation {
            signal_measurement_information: None,
            ecid_error: None,
        });
    }

    #[test]
    fn rt_provide_location_information() {
        // E-CID-only provide body: nr_dl_tdoa None -> no extension addition,
        // byte-identical to the pre-C3 encoding (backward compatibility).
        roundtrip(&ProvideLocationInformation {
            ies: ProvideLocationInformationR9 {
                ecid: Some(EcidProvideLocationInformation {
                    signal_measurement_information: Some(EcidSignalMeasurementInformation {
                        primary_cell_measured_results: Some(all_present_element()),
                        measured_results_list: vec![sample_element()],
                    }),
                    ecid_error: None,
                }),
                nr_dl_tdoa: None,
            },
        });
    }

    #[test]
    fn rt_provide_location_information_nr_dl_tdoa() {
        // nr-DL-TDOA only (no E-CID).
        roundtrip(&ProvideLocationInformation {
            ies: ProvideLocationInformationR9 {
                ecid: None,
                nr_dl_tdoa: Some(minimal_nr_dl_tdoa()),
            },
        });
        // E-CID AND nr-DL-TDOA together.
        roundtrip(&ProvideLocationInformation {
            ies: ProvideLocationInformationR9 {
                ecid: Some(EcidProvideLocationInformation {
                    signal_measurement_information: Some(EcidSignalMeasurementInformation {
                        primary_cell_measured_results: None,
                        measured_results_list: vec![sample_element()],
                    }),
                    ecid_error: None,
                }),
                nr_dl_tdoa: Some(minimal_nr_dl_tdoa()),
            },
        });
    }

    /// Backward compatibility: an E-CID-only provide body (nr_dl_tdoa None) must
    /// encode byte-identically whether or not the C3 field exists — i.e. NO
    /// extension addition is emitted (extension marker 0, no group bytes).
    #[test]
    fn ecid_only_provide_r9_has_no_extension_addition() {
        let r9 = ProvideLocationInformationR9 {
            ecid: Some(EcidProvideLocationInformation {
                signal_measurement_information: None,
                ecid_error: None,
            }),
            nr_dl_tdoa: None,
        };
        let mut enc = UperEncoder::new();
        r9.encode_uper(&mut enc).unwrap();
        // Preamble: ext-marker 0 + [0,0,0,ecid=1,0] = `0 00010` (6 bits), then
        // ECID-ProvideLocationInformation preamble `0 00` (ext 0 + [sig=0,err=0])
        // = 9 bits total -> `0000_1000 0` -> padded 0x08, 0x00.
        assert_eq!(enc.bit_length(), 9);
        assert_eq!(enc.into_bytes().as_ref(), &[0x08, 0x00]);
    }

    /// REQUIRED hand-derived bit-annotated vector for the r16 GROUP FRAMING.
    ///
    /// Encodes `ProvideLocationInformationR9 { ecid: None, nr_dl_tdoa: Some(min) }`
    /// and verifies the framing prefix bit-for-bit (X.691 §18.9 extension-
    /// addition-group encoding). The deep nr-DL-TDOA sub-type internals are
    /// covered by the round-trip tests; here we pin the GROUP framing.
    ///
    /// Bit-level derivation of the main encoder:
    ///   ProvideLocationInformation-r9-IEs SEQUENCE preamble:
    ///     pos0  ext-marker = 1   (an extension addition follows)
    ///     pos1  commonIEs  = 0
    ///     pos2  a-gnss     = 0
    ///     pos3  otdoa      = 0
    ///     pos4  ecid       = 0   (None)
    ///     pos5  epdu       = 0
    ///   encode_extension_additions(&[None, Some(G2)]):   // canonical: trailing-absent G3 trimmed
    ///     normally-small-length(2) = `0` + (2-1)=1 in 6 bits `000001`
    ///       pos6=0 pos7=0 pos8=0 pos9=0 pos10=0 pos11=0 pos12=1
    ///     group presence bitmap [G1=0, G2=1]   (X.691 §18.8 trims trailing-absent G3)
    ///       pos13=0 pos14=1
    ///   => byte0 = pos0..7  = 1000_0000 = 0x80
    ///      byte1 = pos8..15 = 0000_1010 = 0x0A
    ///        (pos8..12 nsl tail 00001, pos13..14 bitmap 01, pos15 open-type len hi-bit 0)
    ///   After the trimmed 2-bit bitmap (ends pos14) the G2 open type follows
    ///   bit-UNALIGNED at pos15 (length determinant, then content) — a correct
    ///   UPER property (no realignment), so the G2 content is not octet-aligned.
    ///   The G2 content (group preamble `0001` + NR-DL-TDOA provide preamble
    ///   `0100`) and the length are therefore verified by the round-trip below,
    ///   not as fixed octets; only the byte-aligned framing prefix is pinned.
    #[test]
    fn test_nr_dl_tdoa_r16_group_framing_reference_hex() {
        let r9 = ProvideLocationInformationR9 {
            ecid: None,
            nr_dl_tdoa: Some(minimal_nr_dl_tdoa()),
        };
        let mut enc = UperEncoder::new();
        r9.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();

        // Framing prefix (cleanly byte-aligned): root preamble + normally-small-
        // length(2) + 2-bit group bitmap. The G2 open type follows bit-unaligned
        // (correct UPER) and is verified by the round-trip below.
        assert_eq!(bytes[0], 0x80, "ext-marker 1 + 5 root presence bits (all 0)");
        assert_eq!(
            bytes[1], 0x0A,
            "normally-small-length(2) tail + group presence bitmap 01 (trailing G3 trimmed)"
        );

        // The full vector must also round-trip back to the same value.
        let mut dec = UperDecoder::new(&bytes);
        let decoded = ProvideLocationInformationR9::decode_uper(&mut dec).unwrap();
        assert_eq!(decoded, r9);
    }

    /// Negative: a peer's r16 group with nr-Multi-RTT (member index 1) present is
    /// rejected in C3 (only nr-DL-TDOA, index 3, is typed).
    #[test]
    fn err_r16_group_multi_rtt_present() {
        let mut main = UperEncoder::new();
        // Root preamble: ext-marker 1, all root optionals absent.
        main.encode_sequence_preamble(Some(true), &[false, false, false, false, false]);
        // G2 group with nr-Multi-RTT (index 1) present, no content needed (the
        // decoder rejects on the group bitmap before reading any body).
        let mut g2 = UperEncoder::new();
        g2.encode_sequence_preamble(None, &[false, true, false, false]);
        let g2_bytes = g2.into_bytes().to_vec();
        main.encode_extension_additions(&[None, Some(g2_bytes)])
            .unwrap();
        let bytes = main.into_bytes();

        let mut dec = UperDecoder::new(&bytes);
        assert!(ProvideLocationInformationR9::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn rt_ecid_error_both_arms() {
        roundtrip(&EcidError::LocationServerErrorCauses(
            EcidLocationServerErrorCauses { cause: 0 },
        ));
        roundtrip(&EcidError::TargetDeviceErrorCauses(
            EcidTargetDeviceErrorCauses {
                cause: 1,
                rsrp_measurement_not_possible: true,
                rsrq_measurement_not_possible: false,
                ue_rx_tx_measurement_not_possible: true,
            },
        ));
        roundtrip(&EcidError::TargetDeviceErrorCauses(
            EcidTargetDeviceErrorCauses {
                cause: 2,
                rsrp_measurement_not_possible: false,
                rsrq_measurement_not_possible: false,
                ue_rx_tx_measurement_not_possible: false,
            },
        ));
    }

    // ---- Negative tests -----------------------------------------------------

    #[test]
    fn err_request_location_information_future() {
        // criticalExtensions CHOICE index 1 (criticalExtensionsFuture). The first
        // bit `1` selects index 1 of the 2-alternative non-extensible CHOICE.
        let mut dec = UperDecoder::new(&[0x80]);
        assert!(RequestLocationInformation::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn err_request_r9_unsupported_method() {
        // Preamble: ext-marker 0 + presence [commonIEs=0, a-gnss=1, otdoa=0,
        // ecid=0, epdu=0] = `0 0 1 0 0 0` -> 0010_0000 = 0x20. a-gnss present
        // is an unsupported root method in v1.
        let mut dec = UperDecoder::new(&[0x20]);
        assert!(RequestLocationInformationR9::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn err_ecid_request_bad_bitstring_length() {
        // Empty requestedMeasurements (length 0) violates SIZE(1..8).
        let empty = EcidRequestLocationInformation {
            requested_measurements: BitVec::new(),
        };
        let mut enc = UperEncoder::new();
        assert!(empty.encode_uper(&mut enc).is_err());

        // Nine bits exceeds SIZE(1..8).
        let too_long = EcidRequestLocationInformation {
            requested_measurements: bits(&[true; 9]),
        };
        let mut enc = UperEncoder::new();
        assert!(too_long.encode_uper(&mut enc).is_err());
    }

    #[test]
    fn err_measured_results_list_empty_rejected_on_encode() {
        // MeasuredResultsList SIZE(1..32) -> an empty list violates the lower bound.
        let info = EcidSignalMeasurementInformation {
            primary_cell_measured_results: None,
            measured_results_list: vec![],
        };
        let mut enc = UperEncoder::new();
        assert!(info.encode_uper(&mut enc).is_err());
    }
}
