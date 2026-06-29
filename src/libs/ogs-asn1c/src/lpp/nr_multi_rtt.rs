//! LPP NR Multi-RTT location-information bodies (3GPP TS 37.355 §6.5.12), UPER.
//!
//! Types the UE's NR Multi-RTT Rx-Tx-time-difference (RTT) measurement-report
//! path carried in the r16 extension-addition group of
//! `ProvideLocationInformation-r9-IEs` as **G2 member index 1** (nr-Multi-RTT);
//! see [`crate::lpp::ecid::ProvideLocationInformationR9`] for the group framing.
//!
//!   NR-Multi-RTT-ProvideLocationInformation-r16
//!     → NR-Multi-RTT-SignalMeasurementInformation-r16
//!       → NR-Multi-RTT-MeasList-r16
//!         → NR-Multi-RTT-MeasElement-r16
//!           → nr-UE-RxTxTimeDiff CHOICE, NR-TimeStamp-r16, NR-TimingQuality-r16
//!
//! DRY: `nr-UE-RxTxTimeDiff-r16` is structurally identical to `nr-RSTD-r16`
//! (same k0..k5 root ranges, extensible, r18 `kMinus*` deferred), and
//! `NR-TimeStamp-r16` / `NR-TimingQuality-r16` are shared verbatim — all reused
//! from [`crate::lpp::nr_dl_tdoa`].
//!
//! BOUNDED v1 (chunk C4): only the measurement path is typed. The error
//! provide-body, the nr-NTA-Offset, the NCGI cell-global-id, DL-PRS resource
//! id/set-id, additional-path and additional-measurement lists, and every
//! r17/r18 extension group are UNSUPPORTED — never emitted, rejected on decode
//! if a peer sets/selects them (each deferral documented inline).

use bitvec::prelude::*;

use super::nr_dl_tdoa::{NrRstd, NrTimeStamp, NrTimingQuality};
use crate::per::{Constraint, PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

/// nr-UE-RxTxTimeDiff-r16 ::= CHOICE {   -- EXTENSIBLE, 6 root alternatives
///     k0 INTEGER (0..1970049), k1 (0..985025), k2 (0..492513),
///     k3 (0..246257), k4 (0..123129), k5 (0..61565),
///     ..., kMinus6-r18 .. kMinus1-r18 }
///
/// Structurally identical to `nr-RSTD-r16`, so its codec is shared via
/// [`NrRstd`] (root k0..k5 typed; r18 `kMinus*` additions decode-error).
pub type NrUeRxTxTimeDiff = NrRstd;

// ---------------------------------------------------------------------------
// NR-Multi-RTT-MeasElement-r16 / MeasList
// ---------------------------------------------------------------------------

/// NR-Multi-RTT-MeasElement-r16 ::= SEQUENCE {   -- EXTENSIBLE, 8 root optionals
///     dl-PRS-ID-r16 INTEGER (0..255),
///     nr-PhysCellID-r16 (0..1007) OPTIONAL,                 -- opt0 TYPED
///     nr-CellGlobalID-r16 NCGI-r15 OPTIONAL,                -- opt1 UNSUPPORTED
///     nr-ARFCN-r16 (0..3279165) OPTIONAL,                   -- opt2 TYPED
///     nr-DL-PRS-ResourceID-r16 OPTIONAL,                    -- opt3 UNSUPPORTED
///     nr-DL-PRS-ResourceSetID-r16 OPTIONAL,                 -- opt4 UNSUPPORTED
///     nr-UE-RxTxTimeDiff-r16 CHOICE {...},                  -- mandatory (RTT)
///     nr-AdditionalPathList-r16 OPTIONAL,                   -- opt5 UNSUPPORTED
///     nr-TimeStamp-r16 NR-TimeStamp-r16,                    -- mandatory
///     nr-TimingQuality-r16 NR-TimingQuality-r16,            -- mandatory
///     nr-DL-PRS-RSRP-Result-r16 (0..126) OPTIONAL,          -- opt6 TYPED
///     nr-Multi-RTT-AdditionalMeasurements-r16 OPTIONAL,     -- opt7 UNSUPPORTED
///     ..., [[ r17 ]] }
///
/// Root optionals in declaration order:
/// `[physCellID, cellGlobalID, arfcn, resourceID, resourceSetID,
///   additionalPathList, rsrpResult, additionalMeasurements]`. NOTE the
/// mandatory `nr-UE-RxTxTimeDiff` precedes `nr-TimeStamp` here (the inverse of
/// NR-DL-TDOA's ordering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrMultiRttMeasElement {
    pub dl_prs_id: u8,
    pub nr_phys_cell_id: Option<u16>,
    pub nr_arfcn: Option<u32>,
    pub nr_ue_rx_tx_time_diff: NrUeRxTxTimeDiff,
    pub nr_time_stamp: NrTimeStamp,
    pub nr_timing_quality: NrTimingQuality,
    pub nr_dl_prs_rsrp_result: Option<u8>,
}

impl NrMultiRttMeasElement {
    const DL_PRS_ID: Constraint = Constraint::new(0, 255);
    const PHYS_CELL_ID: Constraint = Constraint::new(0, 1007);
    const ARFCN: Constraint = Constraint::new(0, 3_279_165);
    const RSRP_RESULT: Constraint = Constraint::new(0, 126);
}

impl UperEncode for NrMultiRttMeasElement {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.nr_phys_cell_id.is_some(), // opt0
                false,                          // opt1 nr-CellGlobalID UNSUPPORTED
                self.nr_arfcn.is_some(),        // opt2
                false,                          // opt3 nr-DL-PRS-ResourceID UNSUPPORTED
                false,                          // opt4 nr-DL-PRS-ResourceSetID UNSUPPORTED
                false,                          // opt5 nr-AdditionalPathList UNSUPPORTED
                self.nr_dl_prs_rsrp_result.is_some(), // opt6
                false,                          // opt7 nr-Multi-RTT-AdditionalMeasurements UNSUPPORTED
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
        self.nr_ue_rx_tx_time_diff.encode_uper(encoder)?;
        // nr-AdditionalPathList absent.
        self.nr_time_stamp.encode_uper(encoder)?;
        self.nr_timing_quality.encode_uper(encoder)?;
        if let Some(rsrp) = self.nr_dl_prs_rsrp_result {
            encoder.encode_constrained_whole_number(rsrp as i64, &Self::RSRP_RESULT)?;
        }
        // nr-Multi-RTT-AdditionalMeasurements absent.
        Ok(())
    }
}

impl UperDecode for NrMultiRttMeasElement {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 8)?;
        // opts = [physCellID, cellGlobalID, arfcn, resourceID, resourceSetID,
        //         additionalPathList, rsrpResult, additionalMeasurements]
        if opts[1] || opts[3] || opts[4] || opts[5] || opts[7] {
            return Err(PerError::DecodeError(
                "NR-Multi-RTT-MeasElement carries an unsupported optional (NCGI / DL-PRS resource \
                 id/set / additional-path / additional-measurements) not typed in C4"
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
        let nr_ue_rx_tx_time_diff = NrUeRxTxTimeDiff::decode_uper(decoder)?;
        let nr_time_stamp = NrTimeStamp::decode_uper(decoder)?;
        let nr_timing_quality = NrTimingQuality::decode_uper(decoder)?;
        let nr_dl_prs_rsrp_result = if opts[6] {
            Some(decoder.decode_constrained_whole_number(&Self::RSRP_RESULT)? as u8)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrMultiRttMeasElement {
            dl_prs_id,
            nr_phys_cell_id,
            nr_arfcn,
            nr_ue_rx_tx_time_diff,
            nr_time_stamp,
            nr_timing_quality,
            nr_dl_prs_rsrp_result,
        })
    }
}

/// NR-Multi-RTT-MeasList-r16 ::= SEQUENCE (SIZE(1..nrMaxTRPs-r16=256)) OF
///        NR-Multi-RTT-MeasElement-r16
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NrMultiRttMeasList {
    pub items: Vec<NrMultiRttMeasElement>,
}

impl NrMultiRttMeasList {
    /// nrMaxTRPs-r16 = 256.
    const SIZE: Constraint = Constraint::new(1, 256);
}

impl UperEncode for NrMultiRttMeasList {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.items.len() as i64, &Self::SIZE)?;
        for item in &self.items {
            item.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for NrMultiRttMeasList {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let count = decoder.decode_constrained_whole_number(&Self::SIZE)? as usize;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            items.push(NrMultiRttMeasElement::decode_uper(decoder)?);
        }
        Ok(NrMultiRttMeasList { items })
    }
}

// ---------------------------------------------------------------------------
// NR-Multi-RTT-SignalMeasurementInformation-r16 / ProvideLocationInformation
// ---------------------------------------------------------------------------

/// NR-Multi-RTT-SignalMeasurementInformation-r16 ::= SEQUENCE {  -- EXTENSIBLE
///     nr-Multi-RTT-MeasList-r16 NR-Multi-RTT-MeasList-r16,
///     nr-NTA-Offset-r16 ENUMERATED { nTA1, nTA2, nTA3, nTA4, ... } OPTIONAL,
///     ..., [[ r17 x2 groups ]] }
///
/// The mandatory measurement list is typed; the optional `nr-NTA-Offset` (opt0)
/// is UNSUPPORTED in v1, and the r17 extension groups are skipped on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrMultiRttSignalMeasurementInformation {
    pub meas_list: NrMultiRttMeasList,
}

impl UperEncode for NrMultiRttSignalMeasurementInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // One root optional (nr-NTA-Offset), always absent in v1.
        encoder.encode_sequence_preamble(Some(false), &[false]);
        self.meas_list.encode_uper(encoder)
    }
}

impl UperDecode for NrMultiRttSignalMeasurementInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 1)?;
        if opts[0] {
            return Err(PerError::DecodeError(
                "NR-Multi-RTT-SignalMeasurementInformation nr-NTA-Offset not supported in C4"
                    .to_string(),
            ));
        }
        let meas_list = NrMultiRttMeasList::decode_uper(decoder)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrMultiRttSignalMeasurementInformation { meas_list })
    }
}

/// NR-Multi-RTT-ProvideLocationInformation-r16 ::= SEQUENCE {   -- EXTENSIBLE
///     nr-Multi-RTT-SignalMeasurementInformation-r16 OPTIONAL,  -- opt0 TYPED
///     nr-Multi-RTT-Error-r16 OPTIONAL,                         -- opt1 UNSUPPORTED
///     ..., [[ r17 instances ]] }
///
/// v1 types only the signal-measurement body; the error body (and the r17 batch
/// instances) are UNSUPPORTED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrMultiRttProvideLocationInformation {
    pub signal_measurement_information: Option<NrMultiRttSignalMeasurementInformation>,
}

impl UperEncode for NrMultiRttProvideLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.signal_measurement_information.is_some(),
                false, // nr-Multi-RTT-Error UNSUPPORTED
            ],
        );
        if let Some(sig) = &self.signal_measurement_information {
            sig.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for NrMultiRttProvideLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 2)?;
        // opts = [signalMeas, error]
        if opts[1] {
            return Err(PerError::DecodeError(
                "NR-Multi-RTT-ProvideLocationInformation error body not supported in C4"
                    .to_string(),
            ));
        }
        let signal_measurement_information = if opts[0] {
            Some(NrMultiRttSignalMeasurementInformation::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrMultiRttProvideLocationInformation {
            signal_measurement_information,
        })
    }
}

// ---------------------------------------------------------------------------
// NR-Multi-RTT-RequestLocationInformation-r16 (LMF -> UE ask side)
// ---------------------------------------------------------------------------

/// NR-Multi-RTT-ReportConfig-r16 ::= SEQUENCE {   -- NON-extensible
///     maxDL-PRS-RxTxTimeDiffMeasPerTRP-r16 INTEGER (1..4) OPTIONAL,
///     timingReportingGranularityFactor-r16 INTEGER (0..5) OPTIONAL }
///
/// Both optionals are simple constrained integers and are fully typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NrMultiRttReportConfig {
    pub max_dl_prs_rx_tx_time_diff_meas_per_trp: Option<u8>,
    pub timing_reporting_granularity_factor: Option<u8>,
}

impl NrMultiRttReportConfig {
    const MAX_MEAS: Constraint = Constraint::new(1, 4);
    const TIMING_GRANULARITY: Constraint = Constraint::new(0, 5);
}

impl UperEncode for NrMultiRttReportConfig {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            None,
            &[
                self.max_dl_prs_rx_tx_time_diff_meas_per_trp.is_some(),
                self.timing_reporting_granularity_factor.is_some(),
            ],
        );
        if let Some(max) = self.max_dl_prs_rx_tx_time_diff_meas_per_trp {
            encoder.encode_constrained_whole_number(max as i64, &Self::MAX_MEAS)?;
        }
        if let Some(gran) = self.timing_reporting_granularity_factor {
            encoder.encode_constrained_whole_number(gran as i64, &Self::TIMING_GRANULARITY)?;
        }
        Ok(())
    }
}

impl UperDecode for NrMultiRttReportConfig {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (_ext, opts) = decoder.decode_sequence_preamble(false, 2)?;
        let max_dl_prs_rx_tx_time_diff_meas_per_trp = if opts[0] {
            Some(decoder.decode_constrained_whole_number(&Self::MAX_MEAS)? as u8)
        } else {
            None
        };
        let timing_reporting_granularity_factor = if opts[1] {
            Some(decoder.decode_constrained_whole_number(&Self::TIMING_GRANULARITY)? as u8)
        } else {
            None
        };
        Ok(NrMultiRttReportConfig {
            max_dl_prs_rx_tx_time_diff_meas_per_trp,
            timing_reporting_granularity_factor,
        })
    }
}

/// NR-Multi-RTT-RequestLocationInformation-r16 ::= SEQUENCE {   -- EXTENSIBLE
///     nr-UE-RxTxTimeDiffMeasurementInfoRequest-r16 ENUMERATED{true} OPTIONAL, -- opt0
///     nr-RequestedMeasurements-r16 BIT STRING {
///         prsrsrpReq(0), firstPathRsrpReq-r17(1), dl-PRS-RSCP-Request-r18(2)
///       } (SIZE(1..8)),                                                       -- mandatory
///     nr-AssistanceAvailability-r16 BOOLEAN,                                 -- mandatory
///     nr-Multi-RTT-ReportConfig-r16 NR-Multi-RTT-ReportConfig-r16,           -- MANDATORY
///     additionalPaths-r16 ENUMERATED{requested} OPTIONAL,                    -- opt1
///     ..., [[ r17 ]], [[ r18 ]] }
///
/// NOTE `nr-Multi-RTT-ReportConfig` is MANDATORY here (no presence bit) and is
/// encoded after `nr-AssistanceAvailability`, before the optional
/// `additionalPaths`. The two single-value enums are modeled as presence
/// `bool`s (no content), as on the DL-TDOA request side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrMultiRttRequestLocationInformation {
    /// nr-UE-RxTxTimeDiffMeasurementInfoRequest presence (ENUMERATED{true}).
    pub rx_tx_time_diff_measurement_info_request: bool,
    /// nr-RequestedMeasurements bit map, SIZE(1..8): bit 0 = prsrsrpReq,
    /// bit 1 = firstPathRsrpReq-r17, bit 2 = dl-PRS-RSCP-Request-r18.
    pub requested_measurements: BitVec<u8, Msb0>,
    pub assistance_availability: bool,
    pub report_config: NrMultiRttReportConfig,
    /// additionalPaths presence (ENUMERATED{requested}).
    pub additional_paths: bool,
}

impl UperEncode for NrMultiRttRequestLocationInformation {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // 2 root optionals in declaration order: [rxTxMeasInfoRequest, additionalPaths].
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.rx_tx_time_diff_measurement_info_request,
                self.additional_paths,
            ],
        );
        // rxTxMeasInfoRequest: ENUMERATED{true} -> presence only, no content.
        encoder.encode_bit_string(&self.requested_measurements, Some(1), Some(8))?;
        encoder.write_bit(self.assistance_availability);
        self.report_config.encode_uper(encoder)?; // mandatory
        // additionalPaths: presence only, no content.
        Ok(())
    }
}

impl UperDecode for NrMultiRttRequestLocationInformation {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 2)?;
        // opts = [rxTxMeasInfoRequest, additionalPaths]
        let requested_measurements = decoder.decode_bit_string(Some(1), Some(8))?;
        let assistance_availability = decoder.read_bit()?;
        let report_config = NrMultiRttReportConfig::decode_uper(decoder)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(NrMultiRttRequestLocationInformation {
            rx_tx_time_diff_measurement_info_request: opts[0],
            requested_measurements,
            assistance_availability,
            report_config,
            additional_paths: opts[1],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpp::nr_dl_tdoa::NrSlot;

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

    fn sample_element() -> NrMultiRttMeasElement {
        NrMultiRttMeasElement {
            dl_prs_id: 1,
            nr_phys_cell_id: Some(42),
            nr_arfcn: Some(123_456),
            nr_ue_rx_tx_time_diff: NrUeRxTxTimeDiff::K3(200_000),
            nr_time_stamp: sample_time_stamp(),
            nr_timing_quality: NrTimingQuality {
                timing_quality_value: 7,
                timing_quality_resolution: 1,
            },
            nr_dl_prs_rsrp_result: Some(60),
        }
    }

    fn minimal_element() -> NrMultiRttMeasElement {
        NrMultiRttMeasElement {
            dl_prs_id: 0,
            nr_phys_cell_id: None,
            nr_arfcn: None,
            nr_ue_rx_tx_time_diff: NrUeRxTxTimeDiff::K0(0),
            nr_time_stamp: NrTimeStamp {
                dl_prs_id: 0,
                nr_phys_cell_id: None,
                nr_arfcn: None,
                nr_sfn: 0,
                nr_slot: NrSlot::Scs15(0),
            },
            nr_timing_quality: NrTimingQuality {
                timing_quality_value: 0,
                timing_quality_resolution: 0,
            },
            nr_dl_prs_rsrp_result: None,
        }
    }

    pub(crate) fn minimal_provide() -> NrMultiRttProvideLocationInformation {
        NrMultiRttProvideLocationInformation {
            signal_measurement_information: Some(NrMultiRttSignalMeasurementInformation {
                meas_list: NrMultiRttMeasList {
                    items: vec![minimal_element()],
                },
            }),
        }
    }

    #[test]
    fn rt_ue_rx_tx_time_diff_each_root() {
        roundtrip(&NrUeRxTxTimeDiff::K0(1_970_049));
        roundtrip(&NrUeRxTxTimeDiff::K1(985_025));
        roundtrip(&NrUeRxTxTimeDiff::K2(492_513));
        roundtrip(&NrUeRxTxTimeDiff::K3(246_257));
        roundtrip(&NrUeRxTxTimeDiff::K4(123_129));
        roundtrip(&NrUeRxTxTimeDiff::K5(61_565));
    }

    #[test]
    fn rt_meas_element() {
        roundtrip(&sample_element());
        roundtrip(&minimal_element());
    }

    #[test]
    fn rt_meas_list() {
        roundtrip(&NrMultiRttMeasList {
            items: vec![minimal_element()],
        });
        roundtrip(&NrMultiRttMeasList {
            items: vec![sample_element(), minimal_element(), sample_element()],
        });
    }

    #[test]
    fn rt_signal_measurement_information() {
        roundtrip(&NrMultiRttSignalMeasurementInformation {
            meas_list: NrMultiRttMeasList {
                items: vec![sample_element()],
            },
        });
    }

    #[test]
    fn rt_provide_location_information() {
        roundtrip(&minimal_provide());
        roundtrip(&NrMultiRttProvideLocationInformation {
            signal_measurement_information: Some(NrMultiRttSignalMeasurementInformation {
                meas_list: NrMultiRttMeasList {
                    items: vec![sample_element(), minimal_element()],
                },
            }),
        });
        // signal-measurement absent (an empty provide body).
        roundtrip(&NrMultiRttProvideLocationInformation {
            signal_measurement_information: None,
        });
    }

    #[test]
    fn err_nta_offset_present() {
        // SignalMeasurementInformation preamble ext 0 + nta-offset present `01`.
        // The deferred nr-NTA-Offset must be rejected.
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(Some(false), &[true]);
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert!(NrMultiRttSignalMeasurementInformation::decode_uper(&mut dec).is_err());
    }

    fn bits(values: &[bool]) -> BitVec<u8, Msb0> {
        let mut bv: BitVec<u8, Msb0> = BitVec::new();
        for &b in values {
            bv.push(b);
        }
        bv
    }

    #[test]
    fn rt_report_config() {
        roundtrip(&NrMultiRttReportConfig {
            max_dl_prs_rx_tx_time_diff_meas_per_trp: Some(4),
            timing_reporting_granularity_factor: Some(5),
        });
        roundtrip(&NrMultiRttReportConfig {
            max_dl_prs_rx_tx_time_diff_meas_per_trp: Some(1),
            timing_reporting_granularity_factor: None,
        });
        roundtrip(&NrMultiRttReportConfig {
            max_dl_prs_rx_tx_time_diff_meas_per_trp: None,
            timing_reporting_granularity_factor: None,
        });
    }

    pub(crate) fn minimal_request() -> NrMultiRttRequestLocationInformation {
        NrMultiRttRequestLocationInformation {
            rx_tx_time_diff_measurement_info_request: false,
            requested_measurements: bits(&[true]),
            assistance_availability: false,
            report_config: NrMultiRttReportConfig {
                max_dl_prs_rx_tx_time_diff_meas_per_trp: None,
                timing_reporting_granularity_factor: None,
            },
            additional_paths: false,
        }
    }

    #[test]
    fn rt_request_location_information() {
        // All optionals present + a populated report config.
        roundtrip(&NrMultiRttRequestLocationInformation {
            rx_tx_time_diff_measurement_info_request: true,
            requested_measurements: bits(&[true, false, true]),
            assistance_availability: true,
            report_config: NrMultiRttReportConfig {
                max_dl_prs_rx_tx_time_diff_meas_per_trp: Some(3),
                timing_reporting_granularity_factor: Some(2),
            },
            additional_paths: true,
        });
        // Minimal: mandatory fields only, empty report config.
        roundtrip(&minimal_request());
    }
}
