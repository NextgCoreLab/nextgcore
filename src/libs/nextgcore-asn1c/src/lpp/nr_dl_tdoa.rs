//! LPP NR DL-TDOA location-information bodies (3GPP TS 37.355 §6.5.10), UPER.
//!
//! Types the UE's NR DL-TDOA RSTD measurement-report path carried in the r16
//! extension-addition group of `ProvideLocationInformation-r9-IEs` (see
//! [`crate::lpp::ecid::ProvideLocationInformationR9`] for the group framing):
//!
//!   NR-DL-TDOA-ProvideLocationInformation-r16
//!     → NR-DL-TDOA-SignalMeasurementInformation-r16
//!       → DL-PRS-ID-Info-r16 + NR-DL-TDOA-MeasList-r16
//!         → NR-DL-TDOA-MeasElement-r16
//!           → NR-TimeStamp-r16, nr-RSTD CHOICE, NR-TimingQuality-r16, ...
//!
//! BOUNDED v1 (chunk C3): only the measurement path is typed. The
//! location-information / error provide-bodies, the NCGI cell-global-id, the
//! DL-PRS resource id/set-id, additional-path and additional-measurement lists,
//! and every r17/r18 extension group are modeled UNSUPPORTED — never emitted,
//! and rejected on decode if a peer sets/selects them (each deferral documented
//! inline). The r18 `kMinus*` nr-RSTD CHOICE additions decode-error too.

use bitvec::prelude::*;

use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// DL-PRS-ID-Info-r16
// ---------------------------------------------------------------------------

/// DL-PRS-ID-Info-r16 ::= SEQUENCE {     -- NON-extensible
///     dl-PRS-ID-r16 INTEGER (0..255),
///     nr-DL-PRS-ResourceID-List-r16 ... OPTIONAL,
///     nr-DL-PRS-ResourceSetID-r16 ... OPTIONAL }
///
/// The two optionals (resource-id list, resource-set-id) are UNSUPPORTED in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlPrsIdInfo {
    pub dl_prs_id: u8,
}

impl DlPrsIdInfo {
    const DL_PRS_ID: Constraint = Constraint::new(0, 255);
}

impl UperEncode for DlPrsIdInfo {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Non-extensible SEQUENCE, 2 presence bits (both absent in v1).
        encoder.encode_sequence_preamble(None, &[false, false]);
        encoder.encode_constrained_whole_number(self.dl_prs_id as i64, &Self::DL_PRS_ID)
    }
}

impl UperDecode for DlPrsIdInfo {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, opts) = decoder.decode_sequence_preamble(false, 2)?;
        if opts[0] || opts[1] {
            return Err(PerError::DecodeError(
                "DL-PRS-ID-Info resource-id-list / resource-set-id not supported in C3".to_string(),
            ));
        }
        let dl_prs_id = decoder.decode_constrained_whole_number(&Self::DL_PRS_ID)? as u8;
        Ok(DlPrsIdInfo { dl_prs_id })
    }
}

// ---------------------------------------------------------------------------
// NR-TimeStamp-r16
// ---------------------------------------------------------------------------

/// nr-Slot-r16 ::= CHOICE { scs15 INTEGER(0..9), scs30 INTEGER(0..19),
///        scs60 INTEGER(0..39), scs120 INTEGER(0..79) }
/// Non-extensible CHOICE, 4 alternatives -> 2-bit index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrSlot {
    Scs15(u8),
    Scs30(u8),
    Scs60(u8),
    Scs120(u8),
}

impl NrSlot {
    const NUM_ALTERNATIVES: usize = 4;
    const SCS15: Constraint = Constraint::new(0, 9);
    const SCS30: Constraint = Constraint::new(0, 19);
    const SCS60: Constraint = Constraint::new(0, 39);
    const SCS120: Constraint = Constraint::new(0, 79);
}

impl UperEncode for NrSlot {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        match self {
            NrSlot::Scs15(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, false)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::SCS15)
            }
            NrSlot::Scs30(v) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, false)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::SCS30)
            }
            NrSlot::Scs60(v) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, false)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::SCS60)
            }
            NrSlot::Scs120(v) => {
                encoder.encode_choice_index(3, Self::NUM_ALTERNATIVES, false)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::SCS120)
            }
        }
    }
}

impl UperDecode for NrSlot {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, false)?;
        match index {
            0 => Ok(NrSlot::Scs15(
                decoder.decode_constrained_whole_number(&Self::SCS15)? as u8,
            )),
            1 => Ok(NrSlot::Scs30(
                decoder.decode_constrained_whole_number(&Self::SCS30)? as u8,
            )),
            2 => Ok(NrSlot::Scs60(
                decoder.decode_constrained_whole_number(&Self::SCS60)? as u8,
            )),
            3 => Ok(NrSlot::Scs120(
                decoder.decode_constrained_whole_number(&Self::SCS120)? as u8,
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// NR-TimeStamp-r16 ::= SEQUENCE {        -- EXTENSIBLE
///     dl-PRS-ID-r16 INTEGER (0..255),
///     nr-PhysCellID-r16 (0..1007) OPTIONAL,
///     nr-CellGlobalID-r16 NCGI-r15 OPTIONAL,   -- UNSUPPORTED
///     nr-ARFCN-r16 (0..3279165) OPTIONAL,
///     nr-SFN-r16 INTEGER (0..1023),
///     nr-Slot-r16 CHOICE {...},
///     ..., [[ nr-Symbol-r18 OPTIONAL ]] }
///
/// Three root optionals `[nr-PhysCellID, nr-CellGlobalID, nr-ARFCN]`;
/// `nr-CellGlobalID` (NCGI) is UNSUPPORTED in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrTimeStamp {
    pub dl_prs_id: u8,
    pub nr_phys_cell_id: Option<u16>,
    pub nr_arfcn: Option<u32>,
    pub nr_sfn: u16,
    pub nr_slot: NrSlot,
}

impl NrTimeStamp {
    const DL_PRS_ID: Constraint = Constraint::new(0, 255);
    const PHYS_CELL_ID: Constraint = Constraint::new(0, 1007);
    const ARFCN: Constraint = Constraint::new(0, 3_279_165);
    const SFN: Constraint = Constraint::new(0, 1023);
}

impl UperEncode for NrTimeStamp {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.nr_phys_cell_id.is_some(),
                false, // nr-CellGlobalID (NCGI) UNSUPPORTED
                self.nr_arfcn.is_some(),
            ],
        );
        encoder.encode_constrained_whole_number(self.dl_prs_id as i64, &Self::DL_PRS_ID)?;
        if let Some(pci) = self.nr_phys_cell_id {
            encoder.encode_constrained_whole_number(pci as i64, &Self::PHYS_CELL_ID)?;
        }
        if let Some(arfcn) = self.nr_arfcn {
            encoder.encode_constrained_whole_number(arfcn as i64, &Self::ARFCN)?;
        }
        encoder.encode_constrained_whole_number(self.nr_sfn as i64, &Self::SFN)?;
        self.nr_slot.encode_uper(encoder)
    }
}

impl UperDecode for NrTimeStamp {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        // opts = [nr-PhysCellID, nr-CellGlobalID, nr-ARFCN]
        if opts[1] {
            return Err(PerError::DecodeError(
                "NR-TimeStamp nr-CellGlobalID (NCGI) not supported in C3".to_string(),
            ));
        }
        let dl_prs_id = decoder.decode_constrained_whole_number(&Self::DL_PRS_ID)? as u8;
        let nr_phys_cell_id = if opts[0] {
            Some(decoder.decode_constrained_whole_number(&Self::PHYS_CELL_ID)? as u16)
        } else {
            None
        };
        let nr_arfcn = if opts[2] {
            Some(decoder.decode_constrained_whole_number(&Self::ARFCN)? as u32)
        } else {
            None
        };
        let nr_sfn = decoder.decode_constrained_whole_number(&Self::SFN)? as u16;
        let nr_slot = NrSlot::decode_uper(decoder)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrTimeStamp {
            dl_prs_id,
            nr_phys_cell_id,
            nr_arfcn,
            nr_sfn,
            nr_slot,
        })
    }
}

// ---------------------------------------------------------------------------
// NR-TimingQuality-r16
// ---------------------------------------------------------------------------

/// NR-TimingQuality-r16 ::= SEQUENCE {    -- EXTENSIBLE
///     timingQualityValue-r16 INTEGER (0..31),
///     timingQualityResolution-r16 ENUMERATED {mdot1, m1, m10, m30, ...} }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrTimingQuality {
    pub timing_quality_value: u8,
    /// 0 = mdot1 (0.1 m), 1 = m1, 2 = m10, 3 = m30 (extensible).
    pub timing_quality_resolution: u8,
}

impl NrTimingQuality {
    const VALUE: Constraint = Constraint::new(0, 31);
    const RESOLUTION: Constraint = Constraint::extensible(0, 3);
}

impl UperEncode for NrTimingQuality {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_constrained_whole_number(self.timing_quality_value as i64, &Self::VALUE)?;
        encoder.encode_enumerated(self.timing_quality_resolution as i64, &Self::RESOLUTION)
    }
}

impl UperDecode for NrTimingQuality {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let timing_quality_value = decoder.decode_constrained_whole_number(&Self::VALUE)? as u8;
        let timing_quality_resolution = decoder.decode_enumerated(&Self::RESOLUTION)? as u8;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrTimingQuality {
            timing_quality_value,
            timing_quality_resolution,
        })
    }
}

// ---------------------------------------------------------------------------
// nr-RSTD-r16 CHOICE
// ---------------------------------------------------------------------------

/// nr-RSTD-r16 ::= CHOICE {               -- EXTENSIBLE, 6 root alternatives
///     k0 INTEGER (0..1970049), k1 (0..985025), k2 (0..492513),
///     k3 (0..246257), k4 (0..123129), k5 (0..61565),
///     ..., kMinus6-r18 .. kMinus1-r18 }
///
/// The r18 `kMinus*` extension additions are DEFERRED (decode-error; never
/// encoded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrRstd {
    K0(u32),
    K1(u32),
    K2(u32),
    K3(u32),
    K4(u32),
    K5(u32),
}

impl NrRstd {
    const NUM_ALTERNATIVES: usize = 6;
    const EXTENSIBLE: bool = true;
    // `*_RANGE` suffix avoids colliding with the same-named enum variants.
    const K0_RANGE: Constraint = Constraint::new(0, 1_970_049);
    const K1_RANGE: Constraint = Constraint::new(0, 985_025);
    const K2_RANGE: Constraint = Constraint::new(0, 492_513);
    const K3_RANGE: Constraint = Constraint::new(0, 246_257);
    const K4_RANGE: Constraint = Constraint::new(0, 123_129);
    const K5_RANGE: Constraint = Constraint::new(0, 61_565);
}

impl UperEncode for NrRstd {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        match self {
            NrRstd::K0(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::K0_RANGE)
            }
            NrRstd::K1(v) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::K1_RANGE)
            }
            NrRstd::K2(v) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::K2_RANGE)
            }
            NrRstd::K3(v) => {
                encoder.encode_choice_index(3, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::K3_RANGE)
            }
            NrRstd::K4(v) => {
                encoder.encode_choice_index(4, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::K4_RANGE)
            }
            NrRstd::K5(v) => {
                encoder.encode_choice_index(5, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                encoder.encode_constrained_whole_number(*v as i64, &Self::K5_RANGE)
            }
        }
    }
}

impl UperDecode for NrRstd {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(NrRstd::K0(
                decoder.decode_constrained_whole_number(&Self::K0_RANGE)? as u32,
            )),
            1 => Ok(NrRstd::K1(
                decoder.decode_constrained_whole_number(&Self::K1_RANGE)? as u32,
            )),
            2 => Ok(NrRstd::K2(
                decoder.decode_constrained_whole_number(&Self::K2_RANGE)? as u32,
            )),
            3 => Ok(NrRstd::K3(
                decoder.decode_constrained_whole_number(&Self::K3_RANGE)? as u32,
            )),
            4 => Ok(NrRstd::K4(
                decoder.decode_constrained_whole_number(&Self::K4_RANGE)? as u32,
            )),
            5 => Ok(NrRstd::K5(
                decoder.decode_constrained_whole_number(&Self::K5_RANGE)? as u32,
            )),
            n => Err(PerError::DecodeError(format!(
                "nr-RSTD kMinus-r18 extension alternative {n} not supported in C3"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// NR-DL-TDOA-MeasElement-r16 / MeasList
// ---------------------------------------------------------------------------

/// NR-DL-TDOA-MeasElement-r16 ::= SEQUENCE {   -- EXTENSIBLE, 8 root optionals
///     dl-PRS-ID-r16 INTEGER (0..255),
///     nr-PhysCellID-r16 (0..1007) OPTIONAL,                 -- opt0 TYPED
///     nr-CellGlobalID-r16 NCGI-r15 OPTIONAL,                -- opt1 UNSUPPORTED
///     nr-ARFCN-r16 (0..3279165) OPTIONAL,                   -- opt2 TYPED
///     nr-DL-PRS-ResourceID-r16 OPTIONAL,                    -- opt3 UNSUPPORTED
///     nr-DL-PRS-ResourceSetID-r16 OPTIONAL,                 -- opt4 UNSUPPORTED
///     nr-TimeStamp-r16 NR-TimeStamp-r16,                    -- mandatory
///     nr-RSTD-r16 CHOICE {...},                             -- mandatory
///     nr-AdditionalPathList-r16 OPTIONAL,                   -- opt5 UNSUPPORTED
///     nr-TimingQuality-r16 NR-TimingQuality-r16,            -- mandatory
///     nr-DL-PRS-RSRP-Result-r16 (0..126) OPTIONAL,          -- opt6 TYPED
///     nr-DL-TDOA-AdditionalMeasurements-r16 OPTIONAL,       -- opt7 UNSUPPORTED
///     ..., [[ r17 ]], [[ r18 ]] }
///
/// Root optionals in declaration order:
/// `[physCellID, cellGlobalID, arfcn, resourceID, resourceSetID,
///   additionalPathList, rsrpResult, additionalMeasurements]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrDlTdoaMeasElement {
    pub dl_prs_id: u8,
    pub nr_phys_cell_id: Option<u16>,
    pub nr_arfcn: Option<u32>,
    pub nr_time_stamp: NrTimeStamp,
    pub nr_rstd: NrRstd,
    pub nr_timing_quality: NrTimingQuality,
    pub nr_dl_prs_rsrp_result: Option<u8>,
}

impl NrDlTdoaMeasElement {
    const DL_PRS_ID: Constraint = Constraint::new(0, 255);
    const PHYS_CELL_ID: Constraint = Constraint::new(0, 1007);
    const ARFCN: Constraint = Constraint::new(0, 3_279_165);
    const RSRP_RESULT: Constraint = Constraint::new(0, 126);
}

impl UperEncode for NrDlTdoaMeasElement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.nr_phys_cell_id.is_some(),       // opt0
                false,                                // opt1 nr-CellGlobalID UNSUPPORTED
                self.nr_arfcn.is_some(),              // opt2
                false,                                // opt3 nr-DL-PRS-ResourceID UNSUPPORTED
                false,                                // opt4 nr-DL-PRS-ResourceSetID UNSUPPORTED
                false,                                // opt5 nr-AdditionalPathList UNSUPPORTED
                self.nr_dl_prs_rsrp_result.is_some(), // opt6
                false, // opt7 nr-DL-TDOA-AdditionalMeasurements UNSUPPORTED
            ],
        );
        encoder.encode_constrained_whole_number(self.dl_prs_id as i64, &Self::DL_PRS_ID)?;
        if let Some(pci) = self.nr_phys_cell_id {
            encoder.encode_constrained_whole_number(pci as i64, &Self::PHYS_CELL_ID)?;
        }
        // nr-CellGlobalID absent.
        if let Some(arfcn) = self.nr_arfcn {
            encoder.encode_constrained_whole_number(arfcn as i64, &Self::ARFCN)?;
        }
        // nr-DL-PRS-ResourceID / ResourceSetID absent.
        self.nr_time_stamp.encode_uper(encoder)?;
        self.nr_rstd.encode_uper(encoder)?;
        // nr-AdditionalPathList absent.
        self.nr_timing_quality.encode_uper(encoder)?;
        if let Some(rsrp) = self.nr_dl_prs_rsrp_result {
            encoder.encode_constrained_whole_number(rsrp as i64, &Self::RSRP_RESULT)?;
        }
        // nr-DL-TDOA-AdditionalMeasurements absent.
        Ok(())
    }
}

impl UperDecode for NrDlTdoaMeasElement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 8)?;
        // opts = [physCellID, cellGlobalID, arfcn, resourceID, resourceSetID,
        //         additionalPathList, rsrpResult, additionalMeasurements]
        if opts[1] || opts[3] || opts[4] || opts[5] || opts[7] {
            return Err(PerError::DecodeError(
                "NR-DL-TDOA-MeasElement carries an unsupported optional (NCGI / DL-PRS resource \
                 id/set / additional-path / additional-measurements) not typed in C3"
                    .to_string(),
            ));
        }
        let dl_prs_id = decoder.decode_constrained_whole_number(&Self::DL_PRS_ID)? as u8;
        let nr_phys_cell_id = if opts[0] {
            Some(decoder.decode_constrained_whole_number(&Self::PHYS_CELL_ID)? as u16)
        } else {
            None
        };
        let nr_arfcn = if opts[2] {
            Some(decoder.decode_constrained_whole_number(&Self::ARFCN)? as u32)
        } else {
            None
        };
        let nr_time_stamp = NrTimeStamp::decode_uper(decoder)?;
        let nr_rstd = NrRstd::decode_uper(decoder)?;
        let nr_timing_quality = NrTimingQuality::decode_uper(decoder)?;
        let nr_dl_prs_rsrp_result = if opts[6] {
            Some(decoder.decode_constrained_whole_number(&Self::RSRP_RESULT)? as u8)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrDlTdoaMeasElement {
            dl_prs_id,
            nr_phys_cell_id,
            nr_arfcn,
            nr_time_stamp,
            nr_rstd,
            nr_timing_quality,
            nr_dl_prs_rsrp_result,
        })
    }
}

/// NR-DL-TDOA-MeasList-r16 ::= SEQUENCE (SIZE(1..nrMaxTRPs-r16=256)) OF
///        NR-DL-TDOA-MeasElement-r16
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NrDlTdoaMeasList {
    pub items: Vec<NrDlTdoaMeasElement>,
}

impl NrDlTdoaMeasList {
    /// nrMaxTRPs-r16 = 256.
    const SIZE: Constraint = Constraint::new(1, 256);
}

impl UperEncode for NrDlTdoaMeasList {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.items.len() as i64, &Self::SIZE)?;
        for item in &self.items {
            item.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for NrDlTdoaMeasList {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            items.push(NrDlTdoaMeasElement::decode_uper(decoder)?);
        }
        Ok(NrDlTdoaMeasList { items })
    }
}

// ---------------------------------------------------------------------------
// NR-DL-TDOA-SignalMeasurementInformation-r16 / ProvideLocationInformation-r16
// ---------------------------------------------------------------------------

/// NR-DL-TDOA-SignalMeasurementInformation-r16 ::= SEQUENCE {  -- EXTENSIBLE
///     dl-PRS-ReferenceInfo-r16 DL-PRS-ID-Info-r16,
///     nr-DL-TDOA-MeasList-r16 NR-DL-TDOA-MeasList-r16,
///     ..., [[ nr-UE-RxTEG-TimingErrorMargin-r17 OPTIONAL ]] }
///
/// Both root fields are mandatory; the r17 extension group is UNSUPPORTED
/// (skipped on decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrDlTdoaSignalMeasurementInformation {
    pub dl_prs_reference_info: DlPrsIdInfo,
    pub meas_list: NrDlTdoaMeasList,
}

impl UperEncode for NrDlTdoaSignalMeasurementInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        self.dl_prs_reference_info.encode_uper(encoder)?;
        self.meas_list.encode_uper(encoder)
    }
}

impl UperDecode for NrDlTdoaSignalMeasurementInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let dl_prs_reference_info = DlPrsIdInfo::decode_uper(decoder)?;
        let meas_list = NrDlTdoaMeasList::decode_uper(decoder)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrDlTdoaSignalMeasurementInformation {
            dl_prs_reference_info,
            meas_list,
        })
    }
}

/// NR-DL-TDOA-ProvideLocationInformation-r16 ::= SEQUENCE {   -- EXTENSIBLE
///     nr-DL-TDOA-SignalMeasurementInformation-r16 OPTIONAL,  -- opt0 TYPED
///     nr-dl-tdoa-LocationInformation-r16 OPTIONAL,           -- opt1 UNSUPPORTED
///     nr-DL-TDOA-Error-r16 OPTIONAL,                         -- opt2 UNSUPPORTED
///     ..., [[ r17 instances x2 ]] }
///
/// v1 types only the signal-measurement body; the location-information and
/// error bodies (and the r17 batch instances) are UNSUPPORTED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrDlTdoaProvideLocationInformation {
    pub signal_measurement_information: Option<NrDlTdoaSignalMeasurementInformation>,
}

impl UperEncode for NrDlTdoaProvideLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.signal_measurement_information.is_some(),
                false, // nr-dl-tdoa-LocationInformation UNSUPPORTED
                false, // nr-DL-TDOA-Error UNSUPPORTED
            ],
        );
        if let Some(sig) = &self.signal_measurement_information {
            sig.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for NrDlTdoaProvideLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        // opts = [signalMeas, locationInfo, error]
        if opts[1] || opts[2] {
            return Err(PerError::DecodeError(
                "NR-DL-TDOA-ProvideLocationInformation location-information / error body not \
                 supported in C3"
                    .to_string(),
            ));
        }
        let signal_measurement_information = if opts[0] {
            Some(NrDlTdoaSignalMeasurementInformation::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrDlTdoaProvideLocationInformation {
            signal_measurement_information,
        })
    }
}

// ---------------------------------------------------------------------------
// NR-DL-TDOA-RequestLocationInformation-r16 (LMF -> UE ask side)
// ---------------------------------------------------------------------------

/// NR-DL-TDOA-RequestLocationInformation-r16 ::= SEQUENCE {   -- EXTENSIBLE
///     nr-DL-PRS-RstdMeasurementInfoRequest-r16 ENUMERATED{true} OPTIONAL, -- opt0
///     nr-RequestedMeasurements-r16 BIT STRING {
///         prsrsrpReq(0), firstPathRsrpReq-r17(1), dl-PRS-RSCPD-Request-r18(2)
///       } (SIZE(1..8)),                                                    -- mandatory
///     nr-AssistanceAvailability-r16 BOOLEAN,                              -- mandatory
///     nr-DL-TDOA-ReportConfig-r16 OPTIONAL,                              -- opt1 UNSUPPORTED
///     additionalPaths-r16 ENUMERATED{requested} OPTIONAL,                -- opt2
///     ..., [[ r17 ]], [[ r18 ]] }
///
/// The two single-value enums (`ENUMERATED{true}` / `ENUMERATED{requested}`)
/// carry NO content — their only signal is the OPTIONAL presence bit — so they
/// are modeled as `bool`. `nr-DL-TDOA-ReportConfig` (opt1) is UNSUPPORTED in v1
/// (absent on encode; rejected on decode if its presence bit is set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrDlTdoaRequestLocationInformation {
    /// nr-DL-PRS-RstdMeasurementInfoRequest presence (ENUMERATED{true}).
    pub rstd_measurement_info_request: bool,
    /// nr-RequestedMeasurements bit map, SIZE(1..8): bit 0 = prsrsrpReq,
    /// bit 1 = firstPathRsrpReq-r17, bit 2 = dl-PRS-RSCPD-Request-r18.
    pub requested_measurements: BitVec<u8, Msb0>,
    pub assistance_availability: bool,
    /// additionalPaths presence (ENUMERATED{requested}).
    pub additional_paths: bool,
}

impl UperEncode for NrDlTdoaRequestLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // 3 root optionals in declaration order:
        // [rstdMeasurementInfoRequest, nr-DL-TDOA-ReportConfig (UNSUPPORTED),
        //  additionalPaths].
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.rstd_measurement_info_request,
                false,
                self.additional_paths,
            ],
        );
        // rstdMeasurementInfoRequest: ENUMERATED{true} -> presence only, no content.
        encoder.encode_bit_string(&self.requested_measurements, Some(1), Some(8))?;
        encoder.write_bit(self.assistance_availability);
        // reportConfig absent; additionalPaths: presence only, no content.
        Ok(())
    }
}

impl UperDecode for NrDlTdoaRequestLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 3)?;
        // opts = [rstdMeasurementInfoRequest, reportConfig, additionalPaths]
        if opts[1] {
            return Err(PerError::DecodeError(
                "NR-DL-TDOA-RequestLocationInformation nr-DL-TDOA-ReportConfig not supported in C5"
                    .to_string(),
            ));
        }
        let requested_measurements = decoder.decode_bit_string(Some(1), Some(8))?;
        let assistance_availability = decoder.read_bit()?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrDlTdoaRequestLocationInformation {
            rstd_measurement_info_request: opts[0],
            requested_measurements,
            assistance_availability,
            additional_paths: opts[2],
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

    fn sample_time_stamp() -> NrTimeStamp {
        NrTimeStamp {
            dl_prs_id: 3,
            nr_phys_cell_id: Some(500),
            nr_arfcn: Some(640_000),
            nr_sfn: 512,
            nr_slot: NrSlot::Scs30(15),
        }
    }

    fn sample_element() -> NrDlTdoaMeasElement {
        NrDlTdoaMeasElement {
            dl_prs_id: 1,
            nr_phys_cell_id: Some(42),
            nr_arfcn: None,
            nr_time_stamp: sample_time_stamp(),
            nr_rstd: NrRstd::K2(123_456),
            nr_timing_quality: NrTimingQuality {
                timing_quality_value: 7,
                timing_quality_resolution: 1,
            },
            nr_dl_prs_rsrp_result: Some(60),
        }
    }

    fn minimal_element() -> NrDlTdoaMeasElement {
        NrDlTdoaMeasElement {
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
        }
    }

    #[test]
    fn rt_dl_prs_id_info() {
        roundtrip(&DlPrsIdInfo { dl_prs_id: 0 });
        roundtrip(&DlPrsIdInfo { dl_prs_id: 255 });
    }

    #[test]
    fn rt_nr_slot_each_scs() {
        roundtrip(&NrSlot::Scs15(9));
        roundtrip(&NrSlot::Scs30(19));
        roundtrip(&NrSlot::Scs60(39));
        roundtrip(&NrSlot::Scs120(79));
    }

    #[test]
    fn rt_nr_time_stamp() {
        roundtrip(&sample_time_stamp());
        roundtrip(&NrTimeStamp {
            dl_prs_id: 0,
            nr_phys_cell_id: None,
            nr_arfcn: None,
            nr_sfn: 1023,
            nr_slot: NrSlot::Scs120(0),
        });
    }

    #[test]
    fn rt_nr_timing_quality() {
        for res in 0..=3u8 {
            roundtrip(&NrTimingQuality {
                timing_quality_value: 31,
                timing_quality_resolution: res,
            });
        }
    }

    #[test]
    fn rt_nr_rstd_each_root() {
        roundtrip(&NrRstd::K0(1_970_049));
        roundtrip(&NrRstd::K1(985_025));
        roundtrip(&NrRstd::K2(492_513));
        roundtrip(&NrRstd::K3(246_257));
        roundtrip(&NrRstd::K4(123_129));
        roundtrip(&NrRstd::K5(61_565));
    }

    #[test]
    fn rt_meas_element() {
        roundtrip(&sample_element());
        roundtrip(&minimal_element());
    }

    #[test]
    fn rt_meas_list() {
        roundtrip(&NrDlTdoaMeasList {
            items: vec![minimal_element()],
        });
        roundtrip(&NrDlTdoaMeasList {
            items: vec![sample_element(), minimal_element(), sample_element()],
        });
    }

    #[test]
    fn rt_signal_measurement_information() {
        roundtrip(&NrDlTdoaSignalMeasurementInformation {
            dl_prs_reference_info: DlPrsIdInfo { dl_prs_id: 7 },
            meas_list: NrDlTdoaMeasList {
                items: vec![sample_element()],
            },
        });
    }

    #[test]
    fn rt_provide_location_information() {
        roundtrip(&NrDlTdoaProvideLocationInformation {
            signal_measurement_information: Some(NrDlTdoaSignalMeasurementInformation {
                dl_prs_reference_info: DlPrsIdInfo { dl_prs_id: 0 },
                meas_list: NrDlTdoaMeasList {
                    items: vec![minimal_element()],
                },
            }),
        });
    }

    #[test]
    fn err_rstd_extension_alternative_rejected() {
        // Extensible CHOICE: ext bit 1 selects an addition (kMinus-r18) -> error.
        // `1` (ext) + normally-small index 0 -> deferred.
        let mut enc = UperEncoder::new();
        enc.write_bit(true); // extension present
        enc.encode_normally_small_non_negative(0).unwrap(); // first addition
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(NrRstd::decode_uper(&mut dec).is_err());
    }

    fn bits(values: &[bool]) -> BitVec<u8, Msb0> {
        let mut bv: BitVec<u8, Msb0> = BitVec::new();
        for &b in values {
            bv.push(b);
        }
        bv
    }

    #[test]
    fn rt_request_location_information() {
        // All optionals present.
        roundtrip(&NrDlTdoaRequestLocationInformation {
            rstd_measurement_info_request: true,
            requested_measurements: bits(&[true, false, true]),
            assistance_availability: true,
            additional_paths: true,
        });
        // Minimal: only the two mandatory fields.
        roundtrip(&NrDlTdoaRequestLocationInformation {
            rstd_measurement_info_request: false,
            requested_measurements: bits(&[true]),
            assistance_availability: false,
            additional_paths: false,
        });
    }

    #[test]
    fn err_request_report_config_present() {
        // Preamble ext 0 + [rstd=0, reportConfig=1, additionalPaths=0] = `0 010`.
        // The deferred nr-DL-TDOA-ReportConfig (opt1) must be rejected.
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(Some(false), &[false, true, false]);
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(NrDlTdoaRequestLocationInformation::decode_uper(&mut dec).is_err());
    }
}
