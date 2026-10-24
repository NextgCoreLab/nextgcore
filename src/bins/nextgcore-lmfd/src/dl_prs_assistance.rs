//! NR DL-PRS assistance data for Multi-RTT and DL-TDOA (#911).
//!
//! TS 38.305 §8.10.3.2 (Multi-RTT) and §8.12 (DL-TDOA) have the LMF give the UE
//! the DL-PRS configuration of the TRPs to measure before it asks for
//! measurements: an LPP `ProvideAssistanceData` carrying
//! `NR-DL-PRS-AssistanceData-r16` (TS 37.355 §6.4.3), in
//! `nr-Multi-RTT-ProvideAssistanceData-r16` and/or
//! `nr-DL-TDOA-ProvideAssistanceData-r16`. This module builds it from what the
//! gNBs reported in TRP Information Exchange (TS 38.455 §8.2.8: NR PCI, NR CGI,
//! ARFCN, PRS Configuration, SFN Initialisation Time, position).
//!
//! # The DL-PRS ID
//!
//! NRPPa's PRS Configuration carries no DL-PRS ID. TS 37.355 says the
//! `dl-PRS-ID` "is used along with a DL-PRS Resource Set ID and a DL-PRS Resource
//! ID to uniquely identify a DL-PRS Resource, and is associated with a single
//! TRP", and here the LMF assigns it (one per TRP, kept for the life of the
//! process). A UE measuring on this assistance data names each TRP by the
//! DL-PRS ID the LMF gave it, so the measurement is keyed by the TRP and not by
//! its PCI, which can name several TRPs.
//!
//! # Mapping (TS 38.455 §9.2.44 → TS 37.355 `NR-DL-PRS-*`)
//!
//! - A **positioning frequency layer** is the set of resource-set parameters that
//!   TS 37.355 requires to be equal across a layer: subcarrier spacing,
//!   bandwidth, start PRB, Point A, comb size and cyclic prefix. Resource sets
//!   are grouped by them, at most `nrMaxFreqLayers-r16` = 4 layers, at most
//!   `nrMaxTRPsPerFreq-r16` = 64 TRPs per layer and
//!   `nrMaxSetsPerTrpPerFreqLayer-r16` = 2 sets per TRP per layer.
//! - Periodicity and slot offset become the CHOICE for the layer's subcarrier
//!   spacing. A periodicity TS 37.355 does not allow for that spacing, or an
//!   offset not below it, drops the resource set.
//! - Repetition factor `rf1` and time gap are left out (`Need OP`: absent means
//!   one, and the time gap is present only with a repetition); other values map
//!   one to one.
//! - Muting options map one to one.
//! - The RE offset becomes the `dl-PRS-CombSizeN-AndReOffset` arm of the layer's
//!   comb size; an offset not below the comb size drops the resource.
//! - QCL from an SSB needs an SSB index and an `rs-Type` in LPP. NRPPa carries
//!   no type, so it is `typeC` in FR1 and `typeC-plus-typeD` in FR2 (TS 38.214:
//!   type D, the spatial Rx parameter, applies only in FR2). QCL from a PRS
//!   needs a resource ID. When neither can be formed, QCL is left out (`Need ON`).
//! - The extended symbol offset 13 (Rel-18) is not mapped; such a resource is
//!   dropped.
//!
//! # Timing
//!
//! - `nr-DL-PRS-SFN0-Offset` comes from the two TRPs' SFN Initialisation Times:
//!   frames, then subframes (rounded to the nearest, see [`sfn0_offset`]), from
//!   the reference TRP's SFN 0 to this TRP's. The remainder, within ±0.5 ms, goes
//!   into the expected RSTD. When either time is unknown, the TRPs are taken to be
//!   synchronised (offset 0).
//! - `nr-DL-PRS-ExpectedRSTD`, in units of 4·T_s, is the propagation difference
//!   from the a-priori UE position (the serving TRP, else the TRPs' centroid)
//!   plus that remainder. A TRP whose value falls outside ±3841 is left out.
//! - `nr-DL-PRS-ExpectedRSTD-Uncertainty` bounds the error of that
//!   propagation difference. That error is at most `min(2r, d(TRP, ref))`, for
//!   a UE within `r` of the a-priori position. It is in units of T_s when every
//!   layer is in FR2, else 4·T_s, and is capped at 246. Without the geometry it
//!   is 246.

use crate::positioning::{geodetic_to_enu, TrpCoord, SPEED_OF_LIGHT_M_S};
use nextgcore_lpp_gen::generated as lpp;
use nextgcore_nrppa_gen::generated as nrppa;

/// T_s = 1 / (15000 × 2048) s (TS 37.355 `nr-DL-PRS-ExpectedRSTD`), in seconds.
const TS_S: f64 = 1.0 / (15_000.0 * 2_048.0);
/// The `nr-DL-PRS-ExpectedRSTD` range, ±3841 × 4·T_s (about ±500 µs).
const EXPECTED_RSTD_MAX: i32 = 3841;
/// The largest `nr-DL-PRS-ExpectedRSTD-Uncertainty`.
const UNCERTAINTY_MAX: u32 = 246;
/// The first NR-ARFCN of the FR2 global raster (TS 38.104 §5.4.2.1: N_REF-Offs
/// 2 016 667 at 24 250.08 MHz).
const FR2_FIRST_ARFCN: u32 = 2_016_667;
/// TS 37.355 `nrMaxFreqLayers-r16`.
const MAX_FREQ_LAYERS: usize = 4;
/// TS 37.355 `nrMaxTRPsPerFreq-r16`.
const MAX_TRPS_PER_FREQ: usize = 64;
/// TS 37.355 `nrMaxSetsPerTrpPerFreqLayer-r16`.
const MAX_SETS_PER_TRP_PER_FREQ: usize = 2;

/// An NR CGI as LPP `NCGI-r15` wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ncgi {
    pub mcc: [u8; 3],
    /// Two or three digits.
    pub mnc: Vec<u8>,
    /// The 36-bit NR cell identity.
    pub cell: u64,
}

impl Ncgi {
    /// From an NRPPa `CGI-NR`: a TS 38.413 PLMN Identity (BCD, filler `F` for a
    /// two-digit MNC) and a 36-bit NR cell identity. `None` for a malformed PLMN.
    pub fn from_nrppa(c: &nrppa::CGI_NR) -> Option<Self> {
        let p = &c.plmn_identity.0;
        if p.len() != 3 {
            return None;
        }
        let digit = |d: u8| (d <= 9).then_some(d);
        let mcc = [digit(p[0] & 0x0f)?, digit(p[0] >> 4)?, digit(p[1] & 0x0f)?];
        let mut mnc = vec![digit(p[2] & 0x0f)?, digit(p[2] >> 4)?];
        match p[1] >> 4 {
            0x0f => {}
            d => mnc.push(digit(d)?),
        }
        let bits = &c.n_rcell_identifier.0;
        if bits.len() != 36 {
            return None;
        }
        let cell = bits.iter().fold(0u64, |acc, b| (acc << 1) | u64::from(*b));
        Some(Self { mcc, mnc, cell })
    }

    /// Whether this is the TS 29.571 `Ncgi` (`mcc`, `mnc` digit strings and a
    /// 9-hex-digit `nrCellId`) the AMF named.
    pub fn matches(&self, mcc: &str, mnc: &str, nr_cell_id: &str) -> bool {
        let digits = |s: &str| s.bytes().map(|b| b.wrapping_sub(b'0')).collect::<Vec<u8>>();
        digits(mcc) == self.mcc
            && digits(mnc) == self.mnc
            && u64::from_str_radix(nr_cell_id, 16).is_ok_and(|c| c == self.cell)
    }

    fn to_lpp(&self) -> lpp::NCGI_r15 {
        lpp::NCGI_r15 {
            mcc_r15: lpp::NCGI_r15Mcc_r15(
                self.mcc
                    .iter()
                    .map(|d| lpp::NCGI_r15Mcc_r15_Entry(*d))
                    .collect(),
            ),
            mnc_r15: lpp::NCGI_r15Mnc_r15(
                self.mnc
                    .iter()
                    .map(|d| lpp::NCGI_r15Mnc_r15_Entry(*d))
                    .collect(),
            ),
            nr_cellidentity_r15: lpp::NCGI_r15Nr_cellidentity_r15(
                (0..36).rev().map(|i| (self.cell >> i) & 1 == 1).collect(),
            ),
        }
    }
}

/// One TRP to describe to the UE.
#[derive(Debug, Clone)]
pub struct TrpPrs {
    /// The DL-PRS ID the LMF assigned to it.
    pub dl_prs_id: u8,
    pub pci: Option<u16>,
    pub ncgi: Option<Ncgi>,
    /// The NR-ARFCN of the TRP's CD-SSB.
    pub arfcn: Option<u32>,
    pub coord: Option<TrpCoord>,
    /// SFN Initialisation Time (TS 38.455 §9.2.36), 32.32 fixed-point seconds since 1900.
    pub sfn_init: Option<u64>,
    pub prs: nrppa::PRSConfiguration,
}

/// Where the UE is thought to be, and how far from there it can be.
#[derive(Debug, Clone, Copy)]
pub struct APriori {
    pub coord: TrpCoord,
    pub radius_m: f64,
}

/// The assistance data, and which DL-PRS IDs it describes.
#[derive(Debug, Clone)]
pub struct Built {
    pub data: lpp::NR_DL_PRS_AssistanceData_r16,
    /// The DL-PRS ID of the assistance data reference TRP.
    pub reference: u8,
    /// Every DL-PRS ID described, the reference included.
    pub dl_prs_ids: Vec<u8>,
}

/// The parameters TS 37.355 requires to be equal across a positioning
/// frequency layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layer {
    scs: u8,
    bandwidth: u8,
    start_prb: u16,
    point_a: u32,
    comb: u8,
    cp: u8,
}

impl Layer {
    fn of(s: &nrppa::PRSResourceSet_Item) -> Option<Self> {
        // Extension values of the NRPPa enumerations have no LPP counterpart.
        (s.subcarrier_spacing.0 <= 3 && s.comb_size.0 <= 3 && s.cp_type.0 <= 1).then_some(Self {
            scs: s.subcarrier_spacing.0,
            bandwidth: s.pr_sbandwidth.0,
            start_prb: s.start_prb.0,
            point_a: s.point_a.0,
            comb: s.comb_size.0,
            cp: s.cp_type.0,
        })
    }

    fn fr2(&self) -> bool {
        self.point_a >= FR2_FIRST_ARFCN
    }

    fn comb_n(&self) -> u8 {
        [2, 4, 6, 12][usize::from(self.comb)]
    }

    fn to_lpp(self) -> lpp::NR_DL_PRS_PositioningFrequencyLayer_r16 {
        lpp::NR_DL_PRS_PositioningFrequencyLayer_r16 {
            dl_prs_subcarrier_spacing_r16:
                lpp::NR_DL_PRS_PositioningFrequencyLayer_r16Dl_PRS_SubcarrierSpacing_r16(self.scs),
            dl_prs_resource_bandwidth_r16:
                lpp::NR_DL_PRS_PositioningFrequencyLayer_r16Dl_PRS_ResourceBandwidth_r16(
                    self.bandwidth,
                ),
            dl_prs_start_prb_r16: lpp::NR_DL_PRS_PositioningFrequencyLayer_r16Dl_PRS_StartPRB_r16(
                self.start_prb,
            ),
            dl_prs_point_a_r16: lpp::ARFCN_ValueNR_r15(self.point_a),
            dl_prs_comb_size_n_r16:
                lpp::NR_DL_PRS_PositioningFrequencyLayer_r16Dl_PRS_CombSizeN_r16(self.comb),
            dl_prs_cyclic_prefix_r16:
                lpp::NR_DL_PRS_PositioningFrequencyLayer_r16Dl_PRS_CyclicPrefix_r16(self.cp),
        }
    }
}

/// NRPPa `resourceSetPeriodicity` in slots.
fn period_slots(p: u8) -> Option<u32> {
    const ROOT: [u32; 20] = [
        4, 5, 8, 10, 16, 20, 32, 40, 64, 80, 160, 320, 640, 1280, 2560, 5120, 10240, 20480, 40960,
        81920,
    ];
    match p {
        0..=19 => Some(ROOT[usize::from(p)]),
        20 => Some(128),
        21 => Some(256),
        22 => Some(512),
        _ => None,
    }
}

fn muting_pattern(p: &nrppa::DL_PRSMutingPattern) -> Option<lpp::NR_MutingPattern_r16> {
    use lpp::NR_MutingPattern_r16 as L;
    use nrppa::DL_PRSMutingPattern as N;
    Some(match p {
        N::Two(b) => L::Po2_r16(lpp::NR_MutingPattern_r16_po2_r16(b.0.clone())),
        N::Four(b) => L::Po4_r16(lpp::NR_MutingPattern_r16_po4_r16(b.0.clone())),
        N::Six(b) => L::Po6_r16(lpp::NR_MutingPattern_r16_po6_r16(b.0.clone())),
        N::Eight(b) => L::Po8_r16(lpp::NR_MutingPattern_r16_po8_r16(b.0.clone())),
        N::Sixteen(b) => L::Po16_r16(lpp::NR_MutingPattern_r16_po16_r16(b.0.clone())),
        N::Thirty_two(b) => L::Po32_r16(lpp::NR_MutingPattern_r16_po32_r16(b.0.clone())),
        N::Choice_extension(_) => return None,
    })
}

fn qcl(q: &nrppa::PRSResource_QCLInfo, fr2: bool) -> Option<lpp::DL_PRS_QCL_Info_r16> {
    match q {
        nrppa::PRSResource_QCLInfo::QCLSourceSSB(s) => {
            let ssb = s.ssb_index.as_ref()?;
            Some(lpp::DL_PRS_QCL_Info_r16::Ssb_r16(
                lpp::DL_PRS_QCL_Info_r16_ssb_r16 {
                    pci_r16: lpp::NR_PhysCellID_r16(s.pci_nr.0),
                    ssb_index_r16: lpp::DL_PRS_QCL_Info_r16_ssb_r16Ssb_Index_r16(ssb.0),
                    rs_type_r16: lpp::DL_PRS_QCL_Info_r16_ssb_r16Rs_Type_r16(if fr2 {
                        lpp::DL_PRS_QCL_Info_r16_ssb_r16Rs_Type_r16::TYPE_C_PLUS_TYPE_D
                    } else {
                        lpp::DL_PRS_QCL_Info_r16_ssb_r16Rs_Type_r16::TYPE_C
                    }),
                },
            ))
        }
        nrppa::PRSResource_QCLInfo::QCLSourcePRS(p) => {
            let resource = p.qcl_source_prs_resource_id.as_ref()?;
            Some(lpp::DL_PRS_QCL_Info_r16::Dl_PRS_r16(
                lpp::DL_PRS_QCL_Info_r16_dl_PRS_r16 {
                    qcl_dl_prs_resource_id_r16: lpp::NR_DL_PRS_ResourceID_r16(resource.0),
                    qcl_dl_prs_resource_set_id_r16: lpp::NR_DL_PRS_ResourceSetID_r16(
                        p.qcl_source_prs_resource_set_id.0,
                    ),
                },
            ))
        }
        nrppa::PRSResource_QCLInfo::Choice_Extension(_) => None,
    }
}

fn resource(r: &nrppa::PRSResource_Item, layer: Layer) -> Option<lpp::NR_DL_PRS_Resource_r16> {
    use lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16 as C;
    if r.ie_extensions.is_some() {
        // The only extension is ExtendedResourceSymbolOffset (13), Rel-18.
        return None;
    }
    let re = r.re_offset.0;
    if re >= layer.comb_n() {
        return None;
    }
    let comb = match layer.comb {
        0 => C::N2_r16(lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16_n2_r16(re)),
        1 => C::N4_r16(lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16_n4_r16(re)),
        2 => C::N6_r16(lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16_n6_r16(re)),
        _ => C::N12_r16(lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16_n12_r16(re)),
    };
    Some(lpp::NR_DL_PRS_Resource_r16 {
        nr_dl_prs_resource_id_r16: lpp::NR_DL_PRS_ResourceID_r16(r.prs_resource_id.0),
        dl_prs_sequence_id_r16: lpp::NR_DL_PRS_Resource_r16Dl_PRS_SequenceID_r16(r.sequence_id.0),
        dl_prs_comb_size_n_and_re_offset_r16: comb,
        dl_prs_resource_slot_offset_r16: lpp::NR_DL_PRS_Resource_r16Dl_PRS_ResourceSlotOffset_r16(
            r.resource_slot_offset.0,
        ),
        dl_prs_resource_symbol_offset_r16:
            lpp::NR_DL_PRS_Resource_r16Dl_PRS_ResourceSymbolOffset_r16(r.resource_symbol_offset.0),
        dl_prs_qcl_info_r16: r.qcl_info.as_ref().and_then(|q| qcl(q, layer.fr2())),
        extensions: Default::default(),
    })
}

/// One NRPPa PRS resource set as an LPP one, with its layer. `Err` says why it
/// cannot be described.
fn resource_set(
    s: &nrppa::PRSResourceSet_Item,
) -> Result<(Layer, lpp::NR_DL_PRS_ResourceSet_r16), String> {
    let id = s.prs_resource_set_id.0;
    let layer = Layer::of(s).ok_or_else(|| format!("resource set {id}: an extension value"))?;
    let period = period_slots(s.resource_set_periodicity.0)
        .ok_or_else(|| format!("resource set {id}: an unknown periodicity"))?;
    let periodicity =
        periodicity(layer.scs, period, s.resource_set_slot_offset.0).ok_or_else(|| {
            format!(
                "resource set {id}: periodicity {period} slots, offset {} is not a TS 37.355 \
             value for its subcarrier spacing",
                s.resource_set_slot_offset.0
            )
        })?;
    // NRPPa rf1..rf32 (0..6), tg1..tg32 (0..5). LPP leaves rf1 out and has
    // n2..n32 (0..5), and the time gap only with a repetition.
    let rf = s.resource_repetition_factor.0;
    let tg = s.resource_time_gap.0;
    if rf > 6 || tg > 5 {
        return Err(format!(
            "resource set {id}: an extension repetition or time gap"
        ));
    }
    let (repetition, time_gap) = if rf == 0 {
        (None, None)
    } else {
        (
            Some(lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_ResourceRepetitionFactor_r16(rf - 1)),
            Some(lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_ResourceTimeGap_r16(tg)),
        )
    };
    // NRPPa n2, n4, n6, n12, ..., n1 (4); LPP n2, n4, n6, n12, ..., n1-v1800 (4).
    let symbols = s.resource_numberof_symbols.0;
    if symbols > 4 {
        return Err(format!("resource set {id}: an unknown number of symbols"));
    }
    let (option1, option2) = match &s.prs_muting {
        None => (None, None),
        Some(m) => {
            let o1 = match &m.prs_muting_option1 {
                None => None,
                Some(o) => Some(lpp::DL_PRS_MutingOption1_r16 {
                    dl_prs_muting_bit_repetition_factor_r16: Some(
                        lpp::DL_PRS_MutingOption1_r16Dl_prs_MutingBitRepetitionFactor_r16(
                            o.muting_bit_repetition_factor.0,
                        ),
                    ),
                    nr_option1_muting_r16: muting_pattern(&o.muting_pattern)
                        .ok_or_else(|| format!("resource set {id}: an extension muting pattern"))?,
                }),
            };
            let o2 = match &m.prs_muting_option2 {
                None => None,
                Some(o) => Some(lpp::DL_PRS_MutingOption2_r16 {
                    nr_option2_muting_r16: muting_pattern(&o.muting_pattern)
                        .ok_or_else(|| format!("resource set {id}: an extension muting pattern"))?,
                }),
            };
            (o1, o2)
        }
    };
    let resources: Vec<lpp::NR_DL_PRS_Resource_r16> = s
        .prs_resource_list
        .0
        .iter()
        .filter_map(|r| resource(r, layer))
        .collect();
    if resources.len() != s.prs_resource_list.0.len() {
        // A UE told of part of a set would misread the rest of its occasions.
        return Err(format!(
            "resource set {id}: {} of its {} resources cannot be described",
            s.prs_resource_list.0.len() - resources.len(),
            s.prs_resource_list.0.len()
        ));
    }
    Ok((
        layer,
        lpp::NR_DL_PRS_ResourceSet_r16 {
            nr_dl_prs_resource_set_id_r16: lpp::NR_DL_PRS_ResourceSetID_r16(id),
            dl_prs_periodicity_and_resource_set_slot_offset_r16: periodicity,
            dl_prs_resource_repetition_factor_r16: repetition,
            dl_prs_resource_time_gap_r16: time_gap,
            dl_prs_num_symbols_r16: lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_NumSymbols_r16(symbols),
            dl_prs_muting_option1_r16: option1,
            dl_prs_muting_option2_r16: option2,
            dl_prs_resource_power_r16: lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_ResourcePower_r16(
                s.prs_resource_transmit_power.0,
            ),
            dl_prs_resource_list_r16: lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_ResourceList_r16(
                resources,
            ),
        },
    ))
}

/// The SFN 0 of `trp` after that of `reference`, as `nr-DL-PRS-SFN0-Offset`
/// counts it: whole frames, then whole subframes, and the rest in seconds, which
/// goes into the expected RSTD. `None` when either SFN Initialisation Time is
/// unknown.
///
/// The subframe count is rounded to the nearest, so the rest is within ±0.5 ms.
/// TS 37.355 counts to the next subframe 0 and adds: "The location server sets
/// the value in accordance with the defined search window for the target device
/// using nr-DL-PRS-ExpectedRSTD and nr-DL-PRS-ExpectedRSTD-Uncertainty". The
/// window centre is the same either way, and a TRP whose SFN 0 is a hair before
/// the reference's then gets an expected RSTD near 0 rather than near 1 ms,
/// outside its ±500 µs range.
pub fn sfn0_offset(reference: Option<u64>, trp: Option<u64>) -> Option<(u16, u8, f64)> {
    // 32.32 fixed point. The SFN cycle, 10.24 s, is 1024/100 s, so the
    // difference is reduced modulo 1024·2^32 in units of 2^-32/100 s, exactly.
    let (r, t) = (reference?, trp?);
    let d = ((i128::from(t) - i128::from(r)) * 100).rem_euclid(1024 << 32);
    // 1 ms is 2^32/10 of those units, so 10·d is in units of 2^-32 ms.
    let tenfold = d * 10;
    let ms = (tenfold + (1 << 31)) >> 32; // nearest whole ms, 0..=10240
    let rest_s = (tenfold - (ms << 32)) as f64 / 4_294_967_296.0 * 1e-3;
    let ms = (ms % 10_240) as u32;
    Some(((ms / 10) as u16, (ms % 10) as u8, rest_s))
}

/// The assistance data for `trps`, referenced to `trps[reference]` when it can
/// be described (else to the first that can). `Err` when no TRP can be.
pub fn build(
    trps: &[TrpPrs],
    reference: usize,
    a_priori: Option<APriori>,
) -> Result<Built, String> {
    // Per layer, the TRPs (by index) with their resource sets.
    let mut layers: Vec<(Layer, Vec<(usize, Vec<lpp::NR_DL_PRS_ResourceSet_r16>)>)> = Vec::new();
    for (i, t) in trps.iter().enumerate() {
        for s in &t.prs.prs_resource_set_list.0 {
            let (layer, set) = match resource_set(s) {
                Ok(x) => x,
                Err(e) => {
                    log::warn!(
                        "DL-PRS assistance: DL-PRS ID {}: {e}; not described",
                        t.dl_prs_id
                    );
                    continue;
                }
            };
            let l = match layers.iter().position(|(l, _)| *l == layer) {
                Some(l) => l,
                None if layers.len() < MAX_FREQ_LAYERS => {
                    layers.push((layer, Vec::new()));
                    layers.len() - 1
                }
                None => {
                    log::warn!(
                        "DL-PRS assistance: DL-PRS ID {}: a fifth positioning frequency layer; \
                         not described",
                        t.dl_prs_id
                    );
                    continue;
                }
            };
            let entries = &mut layers[l].1;
            let full = entries.len() >= MAX_TRPS_PER_FREQ;
            match entries.iter_mut().find(|(j, _)| *j == i) {
                Some((_, sets)) if sets.len() < MAX_SETS_PER_TRP_PER_FREQ => sets.push(set),
                Some(_) => log::warn!(
                    "DL-PRS assistance: DL-PRS ID {}: more than two resource sets in one layer; \
                     the rest are not described",
                    t.dl_prs_id
                ),
                None if !full => entries.push((i, vec![set])),
                None => log::warn!(
                    "DL-PRS assistance: DL-PRS ID {}: a layer already holds 64 TRPs",
                    t.dl_prs_id
                ),
            }
        }
    }
    let described = |i: usize| layers.iter().any(|(_, e)| e.iter().any(|(j, _)| *j == i));
    let reference = if described(reference) {
        reference
    } else {
        (0..trps.len())
            .find(|&i| described(i))
            .ok_or("no TRP has a PRS configuration TS 37.355 can describe")?
    };
    let all_fr2 = layers.iter().all(|(l, _)| l.fr2());
    let resolution_s = if all_fr2 { TS_S } else { 4.0 * TS_S };
    let r = &trps[reference];

    let mut ids: Vec<u8> = Vec::new();
    let mut list = Vec::new();
    for (layer, entries) in &layers {
        let mut per_trp = Vec::new();
        for (i, sets) in entries {
            let t = &trps[*i];
            let (sfn, subframe, rest_s) =
                sfn0_offset(r.sfn_init, t.sfn_init).unwrap_or((0, 0, 0.0));
            let (expected, uncertainty) = if *i == reference {
                (0, 0)
            } else {
                match expected_rstd(r, t, a_priori, rest_s, resolution_s) {
                    Some(x) => x,
                    None => {
                        log::warn!(
                            "DL-PRS assistance: DL-PRS ID {}: the expected RSTD is outside \
                             ±500 µs of the reference; not described",
                            t.dl_prs_id
                        );
                        continue;
                    }
                }
            };
            per_trp.push(lpp::NR_DL_PRS_AssistanceDataPerTRP_r16 {
                dl_prs_id_r16: lpp::NR_DL_PRS_AssistanceDataPerTRP_r16Dl_PRS_ID_r16(t.dl_prs_id),
                nr_phys_cell_id_r16: t.pci.map(lpp::NR_PhysCellID_r16),
                nr_cell_global_id_r16: t.ncgi.as_ref().map(Ncgi::to_lpp),
                nr_arfcn_r16: t.arfcn.map(lpp::ARFCN_ValueNR_r15),
                nr_dl_prs_sfn0_offset_r16: lpp::NR_DL_PRS_SFN0_Offset_r16 {
                    sfn_offset_r16: lpp::NR_DL_PRS_SFN0_Offset_r16Sfn_Offset_r16(sfn),
                    integer_subframe_offset_r16:
                        lpp::NR_DL_PRS_SFN0_Offset_r16IntegerSubframeOffset_r16(subframe),
                },
                nr_dl_prs_expected_rstd_r16:
                    lpp::NR_DL_PRS_AssistanceDataPerTRP_r16Nr_DL_PRS_ExpectedRSTD_r16(expected),
                nr_dl_prs_expected_rstd_uncertainty_r16:
                    lpp::NR_DL_PRS_AssistanceDataPerTRP_r16Nr_DL_PRS_ExpectedRSTD_Uncertainty_r16(
                        uncertainty,
                    ),
                nr_dl_prs_info_r16: lpp::NR_DL_PRS_Info_r16 {
                    nr_dl_prs_resource_set_list_r16:
                        lpp::NR_DL_PRS_Info_r16Nr_DL_PRS_ResourceSetList_r16(sets.clone()),
                },
                extensions: Default::default(),
            });
            if !ids.contains(&t.dl_prs_id) {
                ids.push(t.dl_prs_id);
            }
        }
        if !per_trp.is_empty() {
            list.push(lpp::NR_DL_PRS_AssistanceDataPerFreq_r16 {
                nr_dl_prs_positioning_frequency_layer_r16: layer.to_lpp(),
                nr_dl_prs_assistance_data_per_freq_r16:
                    lpp::NR_DL_PRS_AssistanceDataPerFreq_r16Nr_DL_PRS_AssistanceDataPerFreq_r16(
                        per_trp,
                    ),
            });
        }
    }
    Ok(Built {
        data: lpp::NR_DL_PRS_AssistanceData_r16 {
            nr_dl_prs_reference_info_r16: lpp::DL_PRS_ID_Info_r16 {
                dl_prs_id_r16: lpp::DL_PRS_ID_Info_r16Dl_PRS_ID_r16(r.dl_prs_id),
                nr_dl_prs_resource_id_list_r16: None,
                nr_dl_prs_resource_set_id_r16: None,
            },
            nr_dl_prs_assistance_data_list_r16:
                lpp::NR_DL_PRS_AssistanceData_r16Nr_DL_PRS_AssistanceDataList_r16(list),
            nr_ssb_config_r16: None,
            extensions: Default::default(),
        },
        reference: r.dl_prs_id,
        dl_prs_ids: ids,
    })
}

/// `(nr-DL-PRS-ExpectedRSTD, nr-DL-PRS-ExpectedRSTD-Uncertainty)` of `t` against
/// the reference `r`. `None` when the expected RSTD is out of range.
fn expected_rstd(
    r: &TrpPrs,
    t: &TrpPrs,
    a_priori: Option<APriori>,
    tx_rest_s: f64,
    resolution_s: f64,
) -> Option<(i16, u8)> {
    let unit = 4.0 * TS_S;
    let geometry = match (a_priori, r.coord, t.coord) {
        (Some(a), Some(rc), Some(tc)) => {
            let p_r = geodetic_to_enu(rc, a.coord);
            let p_t = geodetic_to_enu(tc, a.coord);
            let norm = |e: f64, n: f64, u: f64| (e * e + n * n + u * u).sqrt();
            let d_r = norm(p_r.e, p_r.n, p_r.u);
            let d_t = norm(p_t.e, p_t.n, p_t.u);
            let baseline = norm(p_t.e - p_r.e, p_t.n - p_r.n, p_t.u - p_r.u);
            Some((
                (d_t - d_r) / SPEED_OF_LIGHT_M_S,
                (2.0 * a.radius_m).min(baseline) / SPEED_OF_LIGHT_M_S,
            ))
        }
        _ => None,
    };
    let (prop_s, spread_s) = match geometry {
        Some((p, s)) => (p, Some(s)),
        None => (0.0, None),
    };
    let expected = ((prop_s + tx_rest_s) / unit).round();
    if expected.abs() > f64::from(EXPECTED_RSTD_MAX) {
        return None;
    }
    let uncertainty = match spread_s {
        // One step of rounding margin on each side of the window.
        Some(s) => ((s / resolution_s).ceil() as u32 + 1).min(UNCERTAINTY_MAX),
        None => UNCERTAINTY_MAX,
    };
    Some((expected as i16, uncertainty as u8))
}

/// Encode an LMF-initiated LPP `ProvideAssistanceData` (TS 37.355 §5.2.2
/// Assistance Data Delivery: one message, endTransaction TRUE) carrying `data` in
/// `nr-Multi-RTT-ProvideAssistanceData-r16` and/or
/// `nr-DL-TDOA-ProvideAssistanceData-r16`, the Rel-16 extension group of
/// `ProvideAssistanceData-r9-IEs`.
pub fn provide_assistance_data(
    transaction_number: u8,
    data: &lpp::NR_DL_PRS_AssistanceData_r16,
    multi_rtt: bool,
    dl_tdoa: bool,
) -> Result<Vec<u8>, String> {
    let mut ies = lpp::ProvideAssistanceData_r9_IEs {
        common_i_es_provide_assistance_data: None,
        a_gnss_provide_assistance_data: None,
        otdoa_provide_assistance_data: None,
        epdu_provide_assistance_data: None,
        extensions: Default::default(),
    };
    if multi_rtt {
        ies.extensions.nr_multi_rtt_provide_assistance_data_r16 =
            Some(lpp::NR_Multi_RTT_ProvideAssistanceData_r16 {
                nr_dl_prs_assistance_data_r16: Some(data.clone()),
                nr_selected_dl_prs_index_list_r16: None,
                nr_multi_rtt_error_r16: None,
                extensions: Default::default(),
            });
    }
    if dl_tdoa {
        ies.extensions.nr_dl_tdoa_provide_assistance_data_r16 =
            Some(lpp::NR_DL_TDOA_ProvideAssistanceData_r16 {
                nr_dl_prs_assistance_data_r16: Some(data.clone()),
                nr_selected_dl_prs_index_list_r16: None,
                nr_position_calculation_assistance_r16: None,
                nr_dl_tdoa_error_r16: None,
                extensions: Default::default(),
            });
    }
    let msg = lpp::LPP_Message {
        transaction_id: Some(lpp::LPP_TransactionID {
            initiator: lpp::Initiator(lpp::Initiator::LOCATION_SERVER),
            transaction_number: lpp::TransactionNumber(transaction_number),
        }),
        end_transaction: lpp::LPP_MessageEndTransaction(true),
        sequence_number: None,
        acknowledgement: None,
        lpp_message_body: Some(lpp::LPP_MessageBody::C1(
            lpp::LPP_MessageBody_c1::ProvideAssistanceData(lpp::ProvideAssistanceData {
                critical_extensions: lpp::ProvideAssistanceDataCriticalExtensions::C1(
                    lpp::ProvideAssistanceDataCriticalExtensions_c1::ProvideAssistanceData_r9(ies),
                ),
            }),
        )),
    };
    nextgcore_lpp_gen::encode(&msg).map_err(|e| format!("LPP ProvideAssistanceData encode: {e:?}"))
}

/// The LPP `NR-DL-PRS-Periodicity-and-ResourceSetSlotOffset-r16` for a resource set
/// of subcarrier spacing `scs` (0..3 = 15..120 kHz), periodicity `period` slots
/// and slot offset `offset`. `None` when TS 37.355 has no such periodicity for
/// that spacing, or the offset is not below the periodicity.
fn periodicity(
    scs: u8,
    period: u32,
    offset: u32,
) -> Option<lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16> {
    use lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16 as P;
    if offset >= period {
        return None;
    }
    Some(match (scs, period) {
        (0, 4) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N4_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n4_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 5) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N5_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n5_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 8) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N8_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n8_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 10) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N10_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n10_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 16) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N16_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n16_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 20) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N20_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n20_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 32) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N32_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n32_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 40) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N40_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n40_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 64) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N64_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n64_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 80) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N80_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n80_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 160) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N160_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n160_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 320) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N320_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n320_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 640) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N640_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n640_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 1280) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N1280_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n1280_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 2560) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N2560_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n2560_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 5120) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N5120_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n5120_r16(
                    offset as _,
                ),
            ),
        ),
        (0, 10240) => P::Scs15_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16::N10240_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs15_r16_n10240_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 8) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N8_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n8_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 10) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N10_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n10_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 16) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N16_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n16_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 20) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N20_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n20_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 32) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N32_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n32_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 40) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N40_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n40_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 64) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N64_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n64_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 80) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N80_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n80_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 128) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N128_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n128_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 160) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N160_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n160_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 320) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N320_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n320_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 640) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N640_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n640_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 1280) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N1280_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n1280_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 2560) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N2560_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n2560_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 5120) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N5120_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n5120_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 10240) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N10240_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n10240_r16(
                    offset as _,
                ),
            ),
        ),
        (1, 20480) => P::Scs30_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16::N20480_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs30_r16_n20480_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 16) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N16_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n16_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 20) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N20_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n20_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 32) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N32_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n32_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 40) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N40_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n40_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 64) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N64_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n64_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 80) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N80_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n80_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 128) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N128_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n128_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 160) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N160_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n160_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 256) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N256_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n256_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 320) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N320_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n320_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 640) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N640_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n640_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 1280) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N1280_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n1280_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 2560) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N2560_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n2560_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 5120) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N5120_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n5120_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 10240) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N10240_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n10240_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 20480) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N20480_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n20480_r16(
                    offset as _,
                ),
            ),
        ),
        (2, 40960) => P::Scs60_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16::N40960_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs60_r16_n40960_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 32) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N32_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n32_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 40) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N40_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n40_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 64) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N64_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n64_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 80) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N80_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n80_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 128) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N128_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n128_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 160) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N160_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n160_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 256) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N256_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n256_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 320) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N320_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n320_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 512) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N512_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n512_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 640) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N640_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n640_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 1280) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N1280_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n1280_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 2560) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N2560_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n2560_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 5120) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N5120_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n5120_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 10240) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N10240_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n10240_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 20480) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N20480_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n20480_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 40960) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N40960_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n40960_r16(
                    offset as _,
                ),
            ),
        ),
        (3, 81920) => P::Scs120_r16(
            lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16::N81920_r16(
                lpp::NR_DL_PRS_Periodicity_and_ResourceSetSlotOffset_r16_scs120_r16_n81920_r16(
                    offset as _,
                ),
            ),
        ),
        _ => return None,
    })
}

#[cfg(test)]
pub(crate) mod tests;
