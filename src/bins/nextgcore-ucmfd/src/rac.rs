//! UE radio capability transcoding and paging derivation (TS 23.501 §5.4.4.1a, #585).
//!
//! The UCMF holds UE radio capability in one or both of two formats
//! (TS 29.673 §6.1.6.5):
//!
//! - **5GS**: the OCTET STRING of the NGAP UE Radio Capability IE (TS 38.413
//!   §9.3.1.74), i.e. a TS 38.331 `UERadioAccessCapabilityInformation`;
//! - **EPS**: the OCTET STRING of the S1AP UE Radio Capability IE (TS 36.413
//!   §9.2.1.27), i.e. a TS 36.331 `UERadioAccessCapabilityInformation`, whose
//!   contents are a TS 36.331 `UECapabilityInformation`.
//!
//! Both carry the same thing underneath: a `UE-CapabilityRAT-ContainerList` of
//! `(rat-Type, OCTET STRING)` pairs, and the per-RAT containers
//! (`UE-EUTRA-Capability`, `UE-NR-Capability`, `UE-MRDC-Capability`) are the same
//! ASN.1 types in both specifications. **Transcoding** therefore re-wraps the
//! containers, maps the `rat-Type` between the two enumerations, and leaves each
//! container's bytes untouched. RATs one side cannot carry are dropped, and so is
//! UTRAN, which TS 23.502 §5.2.18.2.1 keeps out of every UCMF dictionary entry.
//!
//! **UE radio capability for paging** is derived from the full capability, as
//! TS 23.501 §5.4.4.1a requires of a UCMF in Mode of operation B:
//!
//! - NR (TS 38.331 `UERadioPagingInformation`): `supportedBandListNRForPaging`
//!   is the `bandNR` of every `UE-NR-Capability.rf-Parameters.supportedBandListNR`
//!   entry;
//! - E-UTRA (TS 36.331 `UERadioPagingInformation`): `ue-RadioPagingInfo-r12` is
//!   the one the UE reported in `UECapabilityInformation-v1250-IEs` when the EPS
//!   form carries it, otherwise empty (no category 0, no CE mode). The empty form
//!   is what the 5GS form, which has no such field, always gives.
//!   `supportedBandListEUTRAForPaging-r13` is the `bandEUTRA` of every
//!   `UE-EUTRA-Capability.rf-Parameters.supportedBandListEUTRA` entry.
//!   `maxFBI` (64) is left out, because it only says the real band is in the
//!   v9e0 extension, which is not read.
//!
//! The 5GS paging form is the APER `UERadioCapabilityForPaging` SEQUENCE of NGAP
//! (TS 38.413 §9.3.1.68), the form the AMF puts in NGAP Paging. It carries the NR
//! part and, when the capability includes E-UTRA, the E-UTRA part as well
//! (TS 23.502 §5.2.18.3.1: E-UTRA paging for E-UTRA connected to 5GC). The EPS
//! paging form is the S1AP UE Radio Capability for Paging OCTET STRING (TS 36.413
//! §9.2.1.98): a TS 36.331 `UERadioPagingInformation`.
//!
//! Not derived: the NR paging fields after `supportedBandListNRForPaging` (the
//! v15e0 PDSCH scheduling offsets and the Rel-17 and later IEs). They are optional
//! and only serve the features they name.

use nextgcore_lte_rrc_gen as lte;
use nextgcore_ngap_gen as ngap;
use nextgcore_nr_rrc_gen as nr;

use lte::generated as l;
use ngap::generated as g;
use nr::generated as n;

/// Why a capability could not be transcoded or its paging capability derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RacError {
    /// The bytes are not a valid encoding of the expected TS 36.331 / 38.331 type.
    Undecodable(&'static str),
    /// Nothing was left to carry once the RATs the target cannot hold were dropped.
    NoTranscodableRat,
    /// The capability has no container the paging capability is derived from.
    NoPagingSource,
    /// Encoding the result failed.
    Encode(&'static str),
}

impl std::fmt::Display for RacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undecodable(what) => write!(f, "not a valid {what}"),
            Self::NoTranscodableRat => write!(f, "no RAT container the other format can carry"),
            Self::NoPagingSource => write!(f, "no RAT container to derive paging capability from"),
            Self::Encode(what) => write!(f, "could not encode {what}"),
        }
    }
}

/// A RAT container, with the RAT named independently of either enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rat {
    Eutra,
    Nr,
    EutraNr,
}

impl Rat {
    fn from_nr(t: u8) -> Option<Self> {
        match t {
            n::RAT_Type::NR => Some(Self::Nr),
            n::RAT_Type::EUTRA_NR => Some(Self::EutraNr),
            n::RAT_Type::EUTRA => Some(Self::Eutra),
            // utra-fdd: TS 23.502 §5.2.18.2.1 keeps UTRAN out of the dictionary.
            _ => None,
        }
    }

    fn from_lte(t: u8) -> Option<Self> {
        match t {
            l::RAT_Type::EUTRA => Some(Self::Eutra),
            l::RAT_Type::NR => Some(Self::Nr),
            l::RAT_Type::EUTRA_NR => Some(Self::EutraNr),
            // UTRA, GERAN and CDMA2000 have no TS 38.331 rat-Type, and UTRAN is kept
            // out of the dictionary anyway.
            _ => None,
        }
    }

    fn to_nr(self) -> u8 {
        match self {
            Self::Nr => n::RAT_Type::NR,
            Self::EutraNr => n::RAT_Type::EUTRA_NR,
            Self::Eutra => n::RAT_Type::EUTRA,
        }
    }

    fn to_lte(self) -> u8 {
        match self {
            Self::Eutra => l::RAT_Type::EUTRA,
            Self::Nr => l::RAT_Type::NR,
            Self::EutraNr => l::RAT_Type::EUTRA_NR,
        }
    }
}

/// The parts of a capability in either format that this module reads.
struct Parsed {
    containers: Vec<(Rat, Vec<u8>)>,
    /// `UECapabilityInformation-v1250-IEs.ue-RadioPagingInfo-r12` (EPS form only).
    eutra_paging_info: Option<l::UE_RadioPagingInfo_r12>,
}

fn parse_5gs(cap: &[u8]) -> Result<Parsed, RacError> {
    let info: n::UERadioAccessCapabilityInformation = nr::decode(cap)
        .map_err(|_| RacError::Undecodable("TS 38.331 UERadioAccessCapabilityInformation"))?;
    let n::UERadioAccessCapabilityInformationCriticalExtensions::C1(
        n::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation(ies),
    ) = info.critical_extensions
    else {
        return Err(RacError::Undecodable(
            "TS 38.331 UERadioAccessCapabilityInformation (unknown critical extension)",
        ));
    };
    let list: n::UE_CapabilityRAT_ContainerList =
        nr::decode(&ies.ue_radio_access_capability_info.0)
            .map_err(|_| RacError::Undecodable("TS 38.331 UE-CapabilityRAT-ContainerList"))?;
    Ok(Parsed {
        containers: list
            .0
            .into_iter()
            .filter_map(|c| {
                Rat::from_nr(c.rat_type.0).map(|r| (r, c.ue_capability_rat_container.0))
            })
            .collect(),
        eutra_paging_info: None,
    })
}

fn parse_eps(cap: &[u8]) -> Result<Parsed, RacError> {
    let info: l::UERadioAccessCapabilityInformation = lte::decode(cap)
        .map_err(|_| RacError::Undecodable("TS 36.331 UERadioAccessCapabilityInformation"))?;
    let l::UERadioAccessCapabilityInformationCriticalExtensions::C1(
        l::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation_r8(ies),
    ) = info.critical_extensions
    else {
        return Err(RacError::Undecodable(
            "TS 36.331 UERadioAccessCapabilityInformation (unknown critical extension)",
        ));
    };
    let msg: l::UECapabilityInformation = lte::decode(&ies.ue_radio_access_capability_info.0)
        .map_err(|_| RacError::Undecodable("TS 36.331 UECapabilityInformation"))?;
    let l::UECapabilityInformationCriticalExtensions::C1(
        l::UECapabilityInformationCriticalExtensions_c1::UeCapabilityInformation_r8(r8),
    ) = msg.critical_extensions
    else {
        return Err(RacError::Undecodable(
            "TS 36.331 UECapabilityInformation (unknown critical extension)",
        ));
    };
    let eutra_paging_info = r8
        .non_critical_extension
        .as_ref()
        .and_then(|v8a0| v8a0.non_critical_extension.as_ref())
        .and_then(|v1250| v1250.ue_radio_paging_info_r12.clone());
    Ok(Parsed {
        containers: r8
            .ue_capability_rat_container_list
            .0
            .into_iter()
            .filter_map(|c| {
                Rat::from_lte(c.rat_type.0).map(|r| (r, c.ue_capability_rat_container.0))
            })
            .collect(),
        eutra_paging_info,
    })
}

fn build_5gs(containers: &[(Rat, Vec<u8>)]) -> Result<Vec<u8>, RacError> {
    let list = n::UE_CapabilityRAT_ContainerList(
        containers
            .iter()
            .map(|(r, b)| n::UE_CapabilityRAT_Container {
                rat_type: n::RAT_Type(r.to_nr()),
                ue_capability_rat_container:
                    n::UE_CapabilityRAT_ContainerUe_CapabilityRAT_Container(b.clone()),
            })
            .collect(),
    );
    let inner =
        nr::encode(&list).map_err(|_| RacError::Encode("UE-CapabilityRAT-ContainerList"))?;
    let info = n::UERadioAccessCapabilityInformation {
        critical_extensions: n::UERadioAccessCapabilityInformationCriticalExtensions::C1(
            n::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation(
                n::UERadioAccessCapabilityInformation_IEs {
                    ue_radio_access_capability_info:
                        n::UERadioAccessCapabilityInformation_IEsUe_RadioAccessCapabilityInfo(inner),
                    non_critical_extension: None,
                },
            ),
        ),
    };
    nr::encode(&info).map_err(|_| RacError::Encode("TS 38.331 UERadioAccessCapabilityInformation"))
}

fn build_eps(containers: &[(Rat, Vec<u8>)]) -> Result<Vec<u8>, RacError> {
    let msg = l::UECapabilityInformation {
        // Not a live RRC transaction: the message is only the container of the
        // capability list here, as in an S1AP UE Radio Capability.
        rrc_transaction_identifier: l::RRC_TransactionIdentifier(0),
        critical_extensions: l::UECapabilityInformationCriticalExtensions::C1(
            l::UECapabilityInformationCriticalExtensions_c1::UeCapabilityInformation_r8(
                l::UECapabilityInformation_r8_IEs {
                    ue_capability_rat_container_list: l::UE_CapabilityRAT_ContainerList(
                        containers
                            .iter()
                            .map(|(r, b)| l::UE_CapabilityRAT_Container {
                                rat_type: l::RAT_Type(r.to_lte()),
                                ue_capability_rat_container:
                                    l::UE_CapabilityRAT_ContainerUeCapabilityRAT_Container(
                                        b.clone(),
                                    ),
                            })
                            .collect(),
                    ),
                    non_critical_extension: None,
                },
            ),
        ),
    };
    let inner = lte::encode(&msg).map_err(|_| RacError::Encode("UECapabilityInformation"))?;
    let info = l::UERadioAccessCapabilityInformation {
        critical_extensions: l::UERadioAccessCapabilityInformationCriticalExtensions::C1(
            l::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation_r8(
                l::UERadioAccessCapabilityInformation_r8_IEs {
                    ue_radio_access_capability_info:
                        l::UERadioAccessCapabilityInformation_r8_IEsUe_RadioAccessCapabilityInfo(inner),
                    non_critical_extension: None,
                },
            ),
        ),
    };
    lte::encode(&info).map_err(|_| RacError::Encode("TS 36.331 UERadioAccessCapabilityInformation"))
}

/// Transcode a 5GS-format capability (TS 38.331) to the EPS format (TS 36.331).
pub fn transcode_5gs_to_eps(cap_5gs: &[u8]) -> Result<Vec<u8>, RacError> {
    let parsed = parse_5gs(cap_5gs)?;
    if parsed.containers.is_empty() {
        return Err(RacError::NoTranscodableRat);
    }
    build_eps(&parsed.containers)
}

/// Transcode an EPS-format capability (TS 36.331) to the 5GS format (TS 38.331).
pub fn transcode_eps_to_5gs(cap_eps: &[u8]) -> Result<Vec<u8>, RacError> {
    let parsed = parse_eps(cap_eps)?;
    if parsed.containers.is_empty() {
        return Err(RacError::NoTranscodableRat);
    }
    build_5gs(&parsed.containers)
}

fn container(parsed: &Parsed, rat: Rat) -> Option<&[u8]> {
    parsed
        .containers
        .iter()
        .find(|(r, _)| *r == rat)
        .map(|(_, b)| b.as_slice())
}

/// TS 38.331 `UERadioPagingInformation` from a `UE-NR-Capability`.
fn nr_paging_information(ue_nr_capability: &[u8]) -> Result<Vec<u8>, RacError> {
    let cap: n::UE_NR_Capability =
        nr::decode(ue_nr_capability).map_err(|_| RacError::Undecodable("UE-NR-Capability"))?;
    let bands: Vec<n::FreqBandIndicatorNR> = cap
        .rf_parameters
        .supported_band_list_nr
        .0
        .iter()
        .map(|b| b.band_nr.clone())
        .collect();
    let info = n::UERadioPagingInformation {
        critical_extensions: n::UERadioPagingInformationCriticalExtensions::C1(
            n::UERadioPagingInformationCriticalExtensions_c1::UeRadioPagingInformation(
                n::UERadioPagingInformation_IEs {
                    // SIZE (1..maxBands) on both sides, and supportedBandListNR is
                    // never empty, so the list always fits.
                    supported_band_list_nr_for_paging: (!bands.is_empty()).then_some(
                        n::UERadioPagingInformation_IEsSupportedBandListNRForPaging(bands),
                    ),
                    non_critical_extension: None,
                },
            ),
        ),
    };
    nr::encode(&info).map_err(|_| RacError::Encode("TS 38.331 UERadioPagingInformation"))
}

/// TS 36.331 `maxFBI`: a `bandEUTRA` of this value defers to `bandEUTRA-v9e0`.
const MAX_FBI: u8 = 64;

/// TS 36.331 `UERadioPagingInformation` from a `UE-EUTRA-Capability`.
fn eutra_paging_information(
    ue_eutra_capability: &[u8],
    reported: Option<l::UE_RadioPagingInfo_r12>,
) -> Result<Vec<u8>, RacError> {
    let cap: l::UE_EUTRA_Capability = lte::decode(ue_eutra_capability)
        .map_err(|_| RacError::Undecodable("UE-EUTRA-Capability"))?;
    let bands: Vec<l::FreqBandIndicator_r11> = cap
        .rf_parameters
        .supported_band_list_eutra
        .0
        .iter()
        .filter(|b| b.band_eutra.0 != MAX_FBI)
        .map(|b| l::FreqBandIndicator_r11(u16::from(b.band_eutra.0)))
        .collect();
    let paging_info = reported.unwrap_or(l::UE_RadioPagingInfo_r12 {
        ue_category_v1250: None,
        extensions: Default::default(),
    });
    let paging_info_bytes =
        lte::encode(&paging_info).map_err(|_| RacError::Encode("UE-RadioPagingInfo-r12"))?;
    let info = l::UERadioPagingInformation {
        critical_extensions: l::UERadioPagingInformationCriticalExtensions::C1(
            l::UERadioPagingInformationCriticalExtensions_c1::UeRadioPagingInformation_r12(
                l::UERadioPagingInformation_r12_IEs {
                    ue_radio_paging_info_r12: l::UERadioPagingInformation_r12_IEsUe_RadioPagingInfo_r12(
                        paging_info_bytes,
                    ),
                    non_critical_extension: (!bands.is_empty()).then_some(
                        l::UERadioPagingInformation_v1310_IEs {
                            supported_band_list_eutra_for_paging_r13: Some(
                                l::UERadioPagingInformation_v1310_IEsSupportedBandListEUTRAForPaging_r13(
                                    bands,
                                ),
                            ),
                            non_critical_extension: None,
                        },
                    ),
                },
            ),
        ),
    };
    lte::encode(&info).map_err(|_| RacError::Encode("TS 36.331 UERadioPagingInformation"))
}

/// The 5GS UE Radio Capability for Paging (NGAP `UERadioCapabilityForPaging`, APER)
/// derived from a 5GS-format capability.
pub fn derive_paging_5gs(cap_5gs: &[u8]) -> Result<Vec<u8>, RacError> {
    let parsed = parse_5gs(cap_5gs)?;
    let of_nr = container(&parsed, Rat::Nr)
        .map(nr_paging_information)
        .transpose()?;
    let of_eutra = container(&parsed, Rat::Eutra)
        .map(|c| eutra_paging_information(c, None))
        .transpose()?;
    if of_nr.is_none() && of_eutra.is_none() {
        return Err(RacError::NoPagingSource);
    }
    let paging = g::UERadioCapabilityForPaging {
        ue_radio_capability_for_paging_of_nr: of_nr.map(g::UERadioCapabilityForPagingOfNR),
        ue_radio_capability_for_paging_of_eutra: of_eutra.map(g::UERadioCapabilityForPagingOfEUTRA),
        ie_extensions: None,
    };
    ngap::encode_contained(&paging).map_err(|_| RacError::Encode("NGAP UERadioCapabilityForPaging"))
}

/// The EPS UE Radio Capability for Paging (S1AP: a TS 36.331
/// `UERadioPagingInformation`) derived from an EPS-format capability.
pub fn derive_paging_eps(cap_eps: &[u8]) -> Result<Vec<u8>, RacError> {
    let parsed = parse_eps(cap_eps)?;
    let eutra = container(&parsed, Rat::Eutra).ok_or(RacError::NoPagingSource)?;
    eutra_paging_information(eutra, parsed.eutra_paging_info.clone())
}

#[cfg(test)]
pub(crate) mod tests;
