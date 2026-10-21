//! The N2 MBS SM transfers the MB-SMF builds and parses (TS 38.413 §9.3.5),
//! on the NGAP codec generated from the TS 38.413 ASN.1 (`nextgcore-ngap-gen`,
//! #417).
//!
//! The MB-SMF answers an AMF's ContextUpdate with an MBS Distribution Setup
//! Response Transfer (§9.3.5.8) or Setup Unsuccessful Transfer (§9.3.5.9), and
//! reads the TMGI out of the Setup Request (§9.3.5.7) and Release Request
//! (§9.3.5.10) Transfers it is sent. That is all of its NGAP, and no generated
//! type leaks past this module.
//!
//! Before #417 these went through `nextgcore-ngap`'s hand-written
//! `mbs_transfer` codec. The tests below pin every builder byte for byte, and
//! every parser, against octets derived by hand from TS 38.413 and X.691
//! (`golden`), not against either encoder.

use nextgcore_ngap_gen::generated as g;

/// A TMGI as its two halves: the PLMN identity (TS 24.008 BCD) and the MBS
/// Service ID.
pub(crate) type NgapTmgi = ([u8; 3], [u8; 3]);

/// A transfer that could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferError(String);

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransferError {}

fn encode<T: asn1_codecs::aper::AperCodec>(
    what: &str,
    transfer: &T,
) -> Result<Vec<u8>, TransferError> {
    nextgcore_ngap_gen::encode_contained(transfer)
        .map_err(|e| TransferError(format!("{what}: {e:?}")))
}

/// `Criticality` index of `reject`.
const CRITICALITY_REJECT: u8 = 0;

/// Decode a transfer, skipping protocol extensions the schema does not know.
/// An unknown extension marked `reject` refuses the transfer (TS 38.413
/// §10.3.4.1); `ignore` and `notify` are skipped. That is what the hand-written
/// decoder did with an extension it did not model.
fn decode<T: asn1_codecs::aper::AperCodec>(
    what: &str,
    bytes: &[u8],
) -> Result<T::Output, TransferError> {
    let (value, unknown) = nextgcore_ngap_gen::decode_contained_with_unknown_ies::<T>(bytes)
        .map_err(|e| TransferError(format!("{what}: {e:?}")))?;
    if let Some(u) = unknown
        .iter()
        .find(|u| u.criticality == Some(CRITICALITY_REJECT))
    {
        return Err(TransferError(format!(
            "{what}: protocol extension {} is not comprehended and its criticality is reject",
            u.id
        )));
    }
    if !unknown.is_empty() {
        log::debug!(
            "{what}: skipped {} protocol extension(s) this schema does not define (ids {:?})",
            unknown.len(),
            unknown.iter().map(|u| u.id).collect::<Vec<_>>()
        );
    }
    Ok(value)
}

fn session_id((plmn, service): NgapTmgi) -> g::MBS_SessionID {
    let mut tmgi = plmn.to_vec();
    tmgi.extend_from_slice(&service);
    g::MBS_SessionID {
        tmgi: g::TMGI(tmgi),
        nid: None,
        ie_extensions: None,
    }
}

fn tmgi_of(what: &str, id: &g::MBS_SessionID) -> Result<NgapTmgi, TransferError> {
    // TMGI ::= OCTET STRING (SIZE(6)), which the codec enforces on decode.
    let t = &id.tmgi.0;
    let (plmn, service) = (t.get(..3), t.get(3..6));
    match (plmn, service) {
        (Some(p), Some(s)) if t.len() == 6 => Ok((
            p.try_into().expect("3 octets"),
            s.try_into().expect("3 octets"),
        )),
        _ => Err(TransferError(format!("{what}: TMGI is not 6 octets"))),
    }
}

fn ipv4_address(address: [u8; 4]) -> g::TransportLayerAddress {
    g::TransportLayerAddress(
        (0..32)
            .map(|i| address[i / 8] & (0x80 >> (i % 8)) != 0)
            .collect(),
    )
}

/// Shared NG-U Multicast TNL Information (TS 38.413 §9.3.2.16): the LL SSM
/// (destination and source, IPv4) and the common GTP-TEID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SharedMulticastTunnel {
    pub multicast_address: [u8; 4],
    pub source_address: [u8; 4],
    pub teid: u32,
}

/// QFI is `INTEGER (0..63, ...)`; the codec would encode a larger value as an
/// extension, which no 5GS node can hold. The hand-written encoder refused it.
const MAX_QFI: u8 = 63;

/// `MBS-DistributionSetupResponseTransfer` (TS 38.413 §9.3.5.8): no MBS Area
/// Session ID, the shared multicast tunnel, one QoS flow with a standardized
/// 5QI and ARP 8 / shall-not-trigger / not-pre-emptable, status activated.
pub(crate) fn setup_response_transfer(
    tmgi: NgapTmgi,
    tunnel: SharedMulticastTunnel,
    qfi: u8,
    five_qi: u8,
) -> Result<Vec<u8>, TransferError> {
    const WHAT: &str = "MBS-DistributionSetupResponseTransfer";
    if qfi > MAX_QFI {
        return Err(TransferError(format!("{WHAT}: QFI {qfi} > {MAX_QFI}")));
    }
    let flow = g::MBS_QoSFlowsToBeSetupItem {
        mb_sqos_flow_identifier: g::QosFlowIdentifier(qfi),
        mb_sqos_flow_level_qos_parameters: g::QosFlowLevelQosParameters {
            qos_characteristics: g::QosCharacteristics::NonDynamic5QI(g::NonDynamic5QIDescriptor {
                five_qi: g::FiveQI(five_qi),
                priority_level_qos: None,
                averaging_window: None,
                maximum_data_burst_volume: None,
                ie_extensions: None,
            }),
            allocation_and_retention_priority: g::AllocationAndRetentionPriority {
                priority_level_arp: g::PriorityLevelARP(8),
                pre_emption_capability: g::Pre_emptionCapability(
                    g::Pre_emptionCapability::SHALL_NOT_TRIGGER_PRE_EMPTION,
                ),
                pre_emption_vulnerability: g::Pre_emptionVulnerability(
                    g::Pre_emptionVulnerability::NOT_PRE_EMPTABLE,
                ),
                ie_extensions: None,
            },
            gbr_qos_information: None,
            reflective_qos_attribute: None,
            additional_qos_flow_information: None,
            ie_extensions: None,
        },
        ie_extensions: None,
    };
    encode(
        WHAT,
        &g::MBS_DistributionSetupResponseTransfer {
            mbs_session_id: session_id(tmgi),
            mbs_area_session_id: None,
            shared_ngu_multicast_tnl_information: Some(g::SharedNGU_MulticastTNLInformation {
                ip_multicast_address: ipv4_address(tunnel.multicast_address),
                ip_source_address: ipv4_address(tunnel.source_address),
                gtp_teid: g::GTP_TEID(tunnel.teid.to_be_bytes().to_vec()),
                ie_extensions: None,
            }),
            mbs_qo_s_flows_to_be_setup_list: g::MBS_QoSFlowsToBeSetupList(vec![flow]),
            mbs_session_status: g::MBSSessionStatus(g::MBSSessionStatus::ACTIVATED),
            mbs_service_area: None,
            ie_extensions: None,
        },
    )
}

/// `MBS-DistributionSetupUnsuccessfulTransfer` (TS 38.413 §9.3.5.9) with Cause
/// transport / transport-resource-unavailable and no Criticality Diagnostics.
pub(crate) fn setup_unsuccessful_transfer(tmgi: NgapTmgi) -> Result<Vec<u8>, TransferError> {
    encode(
        "MBS-DistributionSetupUnsuccessfulTransfer",
        &g::MBS_DistributionSetupUnsuccessfulTransfer {
            mbs_session_id: session_id(tmgi),
            mbs_area_session_id: None,
            cause: g::Cause::Transport(g::CauseTransport(
                g::CauseTransport::TRANSPORT_RESOURCE_UNAVAILABLE,
            )),
            criticality_diagnostics: None,
            ie_extensions: None,
        },
    )
}

/// The TMGI of an `MBS-DistributionSetupRequestTransfer` (TS 38.413 §9.3.5.7).
pub(crate) fn parse_setup_request_tmgi(bytes: &[u8]) -> Result<NgapTmgi, TransferError> {
    const WHAT: &str = "MBS-DistributionSetupRequestTransfer";
    let t = decode::<g::MBS_DistributionSetupRequestTransfer>(WHAT, bytes)?;
    tmgi_of(WHAT, &t.mbs_session_id)
}

/// The TMGI of an `MBS-DistributionReleaseRequestTransfer` (TS 38.413
/// §9.3.5.10).
pub(crate) fn parse_release_request_tmgi(bytes: &[u8]) -> Result<NgapTmgi, TransferError> {
    const WHAT: &str = "MBS-DistributionReleaseRequestTransfer";
    let t = decode::<g::MBS_DistributionReleaseRequestTransfer>(WHAT, bytes)?;
    tmgi_of(WHAT, &t.mbs_session_id)
}

#[cfg(test)]
pub(crate) mod golden;

#[cfg(test)]
mod golden_tests;
