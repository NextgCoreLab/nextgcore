//! The N2 SM transfers the SMF builds and parses (TS 38.413 §9.3.4), on the
//! NGAP codec generated from the TS 38.413 ASN.1 (`nextgcore-ngap-gen`, #417).
//!
//! Every transfer travels as the contents of an `OCTET STRING (CONTAINING ...)`
//! inside an NGAP PDU the AMF builds; the SMF only ever sees the contents. So
//! this module is the whole of the SMF's NGAP surface: the builders take plain
//! values (tunnels as `(TEID, IPv4)`, QoS as numbers), the parsers return the
//! DL endpoint the SMF acts on, and no generated type leaks past it.
//!
//! Before #417 these went through `nextgcore-ngap`'s hand-written transfer
//! codec. The bytes are unchanged for every transfer but one -- the oracle
//! tests below pin each builder against the hand-written encoder, and each
//! parser against the hand-written decoder -- and the one is a fix: the
//! hand-written `PathSwitchRequestAcknowledgeTransfer` carried two presence
//! bits for members the Rel-17 SEQUENCE does not have, see
//! [`path_switch_request_acknowledge_transfer`].
//!
//! The parsers skip protocol extensions the schema does not know unless they
//! are marked `reject`, which refuses the transfer -- what the hand-written
//! decoder did with every extension -- so a gNB sending a later release's
//! extensions is still understood.

use nextgcore_ngap_gen::generated as g;

/// A transfer that could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferError(String);

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransferError {}

fn codec_error(what: &str, e: asn1_codecs::PerCodecError) -> TransferError {
    TransferError(format!("{what}: {e:?}"))
}

/// Encode `transfer` as the contents of its `OCTET STRING (CONTAINING ...)`.
fn encode<T: asn1_codecs::aper::AperCodec>(
    what: &str,
    transfer: &T,
) -> Result<Vec<u8>, TransferError> {
    nextgcore_ngap_gen::encode_contained(transfer).map_err(|e| codec_error(what, e))
}

/// `Criticality` index of `reject` (TS 38.413 §9.3.1.2 / the ASN.1 `Criticality`).
const CRITICALITY_REJECT: u8 = 0;

/// Decode a transfer, skipping protocol extensions the schema does not know.
///
/// An unknown extension marked `reject` refuses the transfer (TS 38.413
/// §10.3.4.1, "Reject IE"); one marked `ignore` or `notify` is skipped. That is
/// what the hand-written decoder did with every extension it met.
fn decode<T: asn1_codecs::aper::AperCodec>(
    what: &str,
    bytes: &[u8],
) -> Result<T::Output, TransferError> {
    let (value, unknown) = nextgcore_ngap_gen::decode_contained_with_unknown_ies::<T>(bytes)
        .map_err(|e| codec_error(what, e))?;
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

/// A QFI is six bits (TS 23.501 §5.7.1.1). `QosFlowIdentifier` is
/// `INTEGER (0..63, ...)`, so the generated codec would encode 64..255 as an
/// extension value rather than refuse it: conformant ASN.1, but no QFI any 5GS
/// node can hold. Refused here, as the hand-written encoder refused it.
const MAX_QFI: u8 = 63;

fn qfi(what: &str, value: u8) -> Result<g::QosFlowIdentifier, TransferError> {
    if value > MAX_QFI {
        return Err(TransferError(format!("{what}: QFI {value} > {MAX_QFI}")));
    }
    Ok(g::QosFlowIdentifier(value))
}

/// A GTP-U endpoint as `UPTransportLayerInformation` (TS 38.413 §9.3.2.2): an
/// IPv4 Transport Layer Address (32 bits, TS 38.414 §5.1) and the TEID.
pub(crate) fn gtp_tunnel((teid, address): (u32, [u8; 4])) -> g::UPTransportLayerInformation {
    let bits = (0..32)
        .map(|i| address[i / 8] & (0x80 >> (i % 8)) != 0)
        .collect();
    g::UPTransportLayerInformation::GTPTunnel(g::GTPTunnel {
        transport_layer_address: g::TransportLayerAddress(bits),
        gtp_teid: g::GTP_TEID(teid.to_be_bytes().to_vec()),
        ie_extensions: None,
    })
}

/// A GTP-U endpoint the NG-RAN reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DlEndpoint {
    /// The GTP-U TEID.
    pub teid: u32,
    /// The Transport Layer Address's bits as octets, MSB first, the last octet
    /// zero-padded.
    pub address: Vec<u8>,
    /// How many of those bits are significant: 32 for IPv4, 128 for IPv6, 160
    /// for both (TS 38.414 §5.1).
    pub bit_len: usize,
    /// The QoS flows the endpoint carries (or the NG-RAN accepted), in order.
    pub qfis: Vec<u8>,
}

impl DlEndpoint {
    /// The address as an IPv4 quad, when it is exactly one.
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        if self.bit_len == 32 {
            <[u8; 4]>::try_from(self.address.as_slice()).ok()
        } else {
            None
        }
    }
}

fn endpoint(
    what: &str,
    tunnel: g::UPTransportLayerInformation,
    qfis: Vec<u8>,
) -> Result<DlEndpoint, TransferError> {
    // UPTransportLayerInformation's choice-Extensions alternative is
    // uninhabited (empty object set), so a choice extension on the wire fails
    // the decode instead of reaching here; a schema that defines one makes this
    // pattern refutable and stops it compiling.
    let g::UPTransportLayerInformation::GTPTunnel(tunnel) = tunnel;
    let teid: [u8; 4] = tunnel
        .gtp_teid
        .0
        .as_slice()
        .try_into()
        .map_err(|_| TransferError(format!("{what}: GTP-TEID is not 4 octets")))?;
    let bits = &tunnel.transport_layer_address.0;
    Ok(DlEndpoint {
        teid: u32::from_be_bytes(teid),
        address: bits
            .chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |octet, (i, bit)| octet | (u8::from(*bit) << (7 - i)))
            })
            .collect(),
        bit_len: bits.len(),
        qfis,
    })
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Allocation and Retention Priority (TS 38.413 §9.3.1.19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Arp {
    /// Priority Level ARP, 1..15.
    pub priority_level: u8,
    /// Pre-emption Capability: `may-trigger-pre-emption` when true.
    pub may_trigger_pre_emption: bool,
    /// Pre-emption Vulnerability: `pre-emptable` when true.
    pub pre_emptable: bool,
}

/// GBR QoS Flow Information (TS 38.413 §9.3.1.18), in bit/s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gbr {
    pub mfbr_dl: u64,
    pub mfbr_ul: u64,
    pub gfbr_dl: u64,
    pub gfbr_ul: u64,
}

/// One QoS Flow Setup Request Item, with a standardized (non-dynamic) 5QI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QosFlowSetup {
    pub qfi: u8,
    pub five_qi: u16,
    pub arp: Arp,
    pub gbr: Option<Gbr>,
    /// The E-RAB ID an EPS→5GS handover maps the flow from.
    pub e_rab_id: Option<u8>,
}

/// The members of a `PDUSessionResourceSetupRequestTransfer` this SMF sends.
/// PDU Session Type is always IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupRequest {
    /// PDU Session Aggregate Maximum Bit Rate (DL, UL), bit/s.
    pub ambr: Option<(u64, u64)>,
    /// The UPF's N3 uplink endpoint `(TEID, IPv4)`.
    pub ul_tunnel: (u32, [u8; 4]),
    pub data_forwarding_not_possible: bool,
    pub direct_forwarding_path_availability: bool,
    pub flows: Vec<QosFlowSetup>,
}

fn ambr((dl, ul): (u64, u64)) -> g::PDUSessionAggregateMaximumBitRate {
    g::PDUSessionAggregateMaximumBitRate {
        pdu_session_aggregate_maximum_bit_rate_dl: g::BitRate(dl),
        pdu_session_aggregate_maximum_bit_rate_ul: g::BitRate(ul),
        ie_extensions: None,
    }
}

fn setup_item(
    what: &str,
    flow: &QosFlowSetup,
) -> Result<g::QosFlowSetupRequestItem, TransferError> {
    // FiveQI is INTEGER (0..255, ...) and the generated type a u8: a 5QI past
    // 255 cannot be carried.
    let five_qi = u8::try_from(flow.five_qi)
        .map_err(|_| TransferError(format!("{what}: 5QI {} > 255", flow.five_qi)))?;
    Ok(g::QosFlowSetupRequestItem {
        qos_flow_identifier: qfi(what, flow.qfi)?,
        qos_flow_level_qos_parameters: g::QosFlowLevelQosParameters {
            qos_characteristics: g::QosCharacteristics::NonDynamic5QI(g::NonDynamic5QIDescriptor {
                five_qi: g::FiveQI(five_qi),
                priority_level_qos: None,
                averaging_window: None,
                maximum_data_burst_volume: None,
                ie_extensions: None,
            }),
            allocation_and_retention_priority: g::AllocationAndRetentionPriority {
                // The codec refuses a Priority Level ARP outside 1..15.
                priority_level_arp: g::PriorityLevelARP(flow.arp.priority_level),
                pre_emption_capability: g::Pre_emptionCapability(
                    if flow.arp.may_trigger_pre_emption {
                        g::Pre_emptionCapability::MAY_TRIGGER_PRE_EMPTION
                    } else {
                        g::Pre_emptionCapability::SHALL_NOT_TRIGGER_PRE_EMPTION
                    },
                ),
                pre_emption_vulnerability: g::Pre_emptionVulnerability(if flow.arp.pre_emptable {
                    g::Pre_emptionVulnerability::PRE_EMPTABLE
                } else {
                    g::Pre_emptionVulnerability::NOT_PRE_EMPTABLE
                }),
                ie_extensions: None,
            },
            gbr_qos_information: flow.gbr.map(|gbr| g::GBR_QosInformation {
                maximum_flow_bit_rate_dl: g::BitRate(gbr.mfbr_dl),
                maximum_flow_bit_rate_ul: g::BitRate(gbr.mfbr_ul),
                guaranteed_flow_bit_rate_dl: g::BitRate(gbr.gfbr_dl),
                guaranteed_flow_bit_rate_ul: g::BitRate(gbr.gfbr_ul),
                notification_control: None,
                maximum_packet_loss_rate_dl: None,
                maximum_packet_loss_rate_ul: None,
                ie_extensions: None,
            }),
            reflective_qos_attribute: None,
            additional_qos_flow_information: None,
            ie_extensions: None,
        },
        e_rab_id: flow.e_rab_id.map(g::E_RAB_ID),
        ie_extensions: None,
    })
}

/// `PDUSessionResourceSetupRequestTransfer` (TS 38.413 §9.3.4.1).
///
/// The IEs go in object-set order, each with the criticality the object set
/// gives it: all `reject` but Direct Forwarding Path Availability, `ignore`.
pub(crate) fn setup_request_transfer(request: &SetupRequest) -> Result<Vec<u8>, TransferError> {
    use g::{
        PDUSessionResourceSetupRequestTransferProtocolIEs_Entry as Entry,
        PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };
    const WHAT: &str = "PDUSessionResourceSetupRequestTransfer";
    let reject = || g::Criticality(g::Criticality::REJECT);
    let entry = |id, criticality, value| Entry {
        id: ProtocolIE_ID(id),
        criticality,
        value,
    };

    let flows = request
        .flows
        .iter()
        .map(|f| setup_item(WHAT, f))
        .collect::<Result<Vec<_>, _>>()?;

    let mut ies = Vec::new();
    if let Some(a) = request.ambr {
        ies.push(entry(
            g::ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE,
            reject(),
            Ie::Id_PDUSessionAggregateMaximumBitRate(ambr(a)),
        ));
    }
    ies.push(entry(
        g::ID_UL_NGU_UP_TNL_INFORMATION,
        reject(),
        Ie::Id_UL_NGU_UP_TNLInformation(gtp_tunnel(request.ul_tunnel)),
    ));
    if request.data_forwarding_not_possible {
        ies.push(entry(
            g::ID_DATA_FORWARDING_NOT_POSSIBLE,
            reject(),
            Ie::Id_DataForwardingNotPossible(g::DataForwardingNotPossible(
                g::DataForwardingNotPossible::DATA_FORWARDING_NOT_POSSIBLE,
            )),
        ));
    }
    ies.push(entry(
        g::ID_PDU_SESSION_TYPE,
        reject(),
        Ie::Id_PDUSessionType(g::PDUSessionType(g::PDUSessionType::IPV4)),
    ));
    ies.push(entry(
        g::ID_QOS_FLOW_SETUP_REQUEST_LIST,
        reject(),
        Ie::Id_QosFlowSetupRequestList(g::QosFlowSetupRequestList(flows)),
    ));
    if request.direct_forwarding_path_availability {
        ies.push(entry(
            g::ID_DIRECT_FORWARDING_PATH_AVAILABILITY,
            g::Criticality(g::Criticality::IGNORE),
            Ie::Id_DirectForwardingPathAvailability(g::DirectForwardingPathAvailability(
                g::DirectForwardingPathAvailability::DIRECT_PATH_AVAILABLE,
            )),
        ));
    }
    encode(
        WHAT,
        &g::PDUSessionResourceSetupRequestTransfer {
            protocol_i_es: g::PDUSessionResourceSetupRequestTransferProtocolIEs(ies),
        },
    )
}

/// `PDUSessionResourceModifyRequestTransfer` (TS 38.413 §9.3.4.3): the
/// re-authorized Session-AMBR, when given, and the QoS flows to add or modify
/// (by QFI only), when any.
pub(crate) fn modify_request_transfer(
    session_ambr: Option<(u64, u64)>,
    qfis: &[u8],
) -> Result<Vec<u8>, TransferError> {
    use g::{
        PDUSessionResourceModifyRequestTransferProtocolIEs_Entry as Entry,
        PDUSessionResourceModifyRequestTransferProtocolIEs_EntryValue as Ie, ProtocolIE_ID,
    };
    const WHAT: &str = "PDUSessionResourceModifyRequestTransfer";
    let reject = || g::Criticality(g::Criticality::REJECT);
    let mut ies = Vec::new();
    if let Some(a) = session_ambr {
        ies.push(Entry {
            id: ProtocolIE_ID(g::ID_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE),
            criticality: reject(),
            value: Ie::Id_PDUSessionAggregateMaximumBitRate(ambr(a)),
        });
    }
    if !qfis.is_empty() {
        let items = qfis
            .iter()
            .map(|&q| {
                Ok(g::QosFlowAddOrModifyRequestItem {
                    qos_flow_identifier: qfi(WHAT, q)?,
                    qos_flow_level_qos_parameters: None,
                    e_rab_id: None,
                    ie_extensions: None,
                })
            })
            .collect::<Result<Vec<_>, TransferError>>()?;
        ies.push(Entry {
            id: ProtocolIE_ID(g::ID_QOS_FLOW_ADD_OR_MODIFY_REQUEST_LIST),
            criticality: reject(),
            value: Ie::Id_QosFlowAddOrModifyRequestList(g::QosFlowAddOrModifyRequestList(items)),
        });
    }
    encode(
        WHAT,
        &g::PDUSessionResourceModifyRequestTransfer {
            protocol_i_es: g::PDUSessionResourceModifyRequestTransferProtocolIEs(ies),
        },
    )
}

/// `PDUSessionResourceModifyConfirmTransfer` (TS 38.413 §9.3.4.19): the QoS
/// flows the core confirms and the UPF's UL N3 endpoint. No additional UL
/// tunnels (this SMF allocates none) and no failed flows.
pub(crate) fn modify_confirm_transfer(
    qfis: &[u8],
    ul_tunnel: (u32, [u8; 4]),
) -> Result<Vec<u8>, TransferError> {
    const WHAT: &str = "PDUSessionResourceModifyConfirmTransfer";
    let items = qfis
        .iter()
        .map(|&q| {
            Ok(g::QosFlowModifyConfirmItem {
                qos_flow_identifier: qfi(WHAT, q)?,
                ie_extensions: None,
            })
        })
        .collect::<Result<Vec<_>, TransferError>>()?;
    encode(
        WHAT,
        &g::PDUSessionResourceModifyConfirmTransfer {
            qos_flow_modify_confirm_list: g::QosFlowModifyConfirmList(items),
            ulngu_up_tnl_information: gtp_tunnel(ul_tunnel),
            additional_ng_uuptnl_information: None,
            qos_flow_failed_to_modify_list: None,
            ie_extensions: None,
        },
    )
}

/// The NGAP Causes this SMF sends (TS 38.413 §9.3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmfCause {
    /// nas / normal-release
    NasNormalRelease,
    /// transport / transport-resource-unavailable
    TransportResourceUnavailable,
    /// transport / unspecified
    TransportUnspecified,
    /// protocol / abstract-syntax-error-falsely-constructed-message
    ProtocolFalselyConstructedMessage,
    /// misc / unspecified
    MiscUnspecified,
}

impl SmfCause {
    fn generated(self) -> g::Cause {
        match self {
            Self::NasNormalRelease => g::Cause::Nas(g::CauseNas(g::CauseNas::NORMAL_RELEASE)),
            Self::TransportResourceUnavailable => g::Cause::Transport(g::CauseTransport(
                g::CauseTransport::TRANSPORT_RESOURCE_UNAVAILABLE,
            )),
            Self::TransportUnspecified => {
                g::Cause::Transport(g::CauseTransport(g::CauseTransport::UNSPECIFIED))
            }
            Self::ProtocolFalselyConstructedMessage => g::Cause::Protocol(g::CauseProtocol(
                g::CauseProtocol::ABSTRACT_SYNTAX_ERROR_FALSELY_CONSTRUCTED_MESSAGE,
            )),
            Self::MiscUnspecified => g::Cause::Misc(g::CauseMisc(g::CauseMisc::UNSPECIFIED)),
        }
    }
}

/// `PDUSessionResourceModifyIndicationUnsuccessfulTransfer` (TS 38.413
/// §9.3.4.21): why an AN-initiated modification could not be carried out.
pub(crate) fn modify_indication_unsuccessful_transfer(
    cause: SmfCause,
) -> Result<Vec<u8>, TransferError> {
    encode(
        "PDUSessionResourceModifyIndicationUnsuccessfulTransfer",
        &g::PDUSessionResourceModifyIndicationUnsuccessfulTransfer {
            cause: cause.generated(),
            ie_extensions: None,
        },
    )
}

/// `PDUSessionResourceReleaseCommandTransfer` (TS 38.413 §9.3.4.12) with
/// Cause nas / normal-release.
pub(crate) fn release_command_transfer() -> Result<Vec<u8>, TransferError> {
    encode(
        "PDUSessionResourceReleaseCommandTransfer",
        &g::PDUSessionResourceReleaseCommandTransfer {
            cause: SmfCause::NasNormalRelease.generated(),
            ie_extensions: None,
        },
    )
}

/// `PathSwitchRequestAcknowledgeTransfer` (TS 38.413 §9.3.4.9): the UPF's UL
/// N3 endpoint, or nothing at all -- every member is optional, and an empty
/// transfer means the UL path is unchanged.
///
/// The Rel-17 SEQUENCE has two optional root members (`uL-NGU-UP-TNLInformation`,
/// `securityIndication`) before `iE-Extensions`. The hand-written encoder this
/// replaced wrote presence bits for two more, `newSecurityResult` and
/// `qosFlowToReleaseList`, which the schema does not have, so every tunnel it
/// sent started two bits late and a conformant gNB read it from the wrong
/// offset. `path_switch_acknowledge_follows_the_schema_not_the_hand_written_layout`
/// pins the difference.
pub(crate) fn path_switch_request_acknowledge_transfer(
    ul_tunnel: Option<(u32, [u8; 4])>,
) -> Result<Vec<u8>, TransferError> {
    encode(
        "PathSwitchRequestAcknowledgeTransfer",
        &g::PathSwitchRequestAcknowledgeTransfer {
            ul_ngu_up_tnl_information: ul_tunnel.map(gtp_tunnel),
            security_indication: None,
            ie_extensions: None,
        },
    )
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// `PDUSessionResourceSetupResponseTransfer` (TS 38.413 §9.3.4.2): the gNB's
/// DL N3 endpoint and the QoS flows it carries.
pub(crate) fn parse_setup_response_transfer(bytes: &[u8]) -> Result<DlEndpoint, TransferError> {
    const WHAT: &str = "PDUSessionResourceSetupResponseTransfer";
    let t = decode::<g::PDUSessionResourceSetupResponseTransfer>(WHAT, bytes)?;
    let dl = t.dl_qos_flow_per_tnl_information;
    let qfis = dl
        .associated_qos_flow_list
        .0
        .iter()
        .map(|f| f.qos_flow_identifier.0)
        .collect();
    endpoint(WHAT, dl.up_transport_layer_information, qfis)
}

/// What the SMF reads from a `PDUSessionResourceModifyIndicationTransfer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModifyIndication {
    /// The NG-RAN's (new) DL N3 endpoint and the flows on it.
    pub dl: DlEndpoint,
    /// How many Additional DL QoS Flow per TNL Information items came too
    /// (dual connectivity, which this SMF does not install).
    pub additional_dl_tunnels: usize,
}

/// `PDUSessionResourceModifyIndicationTransfer` (TS 38.413 §9.3.4.20).
pub(crate) fn parse_modify_indication_transfer(
    bytes: &[u8],
) -> Result<ModifyIndication, TransferError> {
    const WHAT: &str = "PDUSessionResourceModifyIndicationTransfer";
    let t = decode::<g::PDUSessionResourceModifyIndicationTransfer>(WHAT, bytes)?;
    let dl = t.dl_qos_flow_per_tnl_information;
    let qfis = dl
        .associated_qos_flow_list
        .0
        .iter()
        .map(|f| f.qos_flow_identifier.0)
        .collect();
    Ok(ModifyIndication {
        dl: endpoint(WHAT, dl.up_transport_layer_information, qfis)?,
        additional_dl_tunnels: t
            .additional_dl_qos_flow_per_tnl_information
            .map_or(0, |l| l.0.len()),
    })
}

/// `PathSwitchRequestTransfer` (TS 38.413 §9.3.4.8): the target gNB's DL N3
/// endpoint and the QoS flows it accepted.
///
/// The hand-written decoder refused a transfer carrying DL NG-U TNL
/// Information Reused or User Plane Security Information, because it could not
/// skip them; both are optional members the SMF does not act on, and the
/// generated codec reads past them.
pub(crate) fn parse_path_switch_request_transfer(
    bytes: &[u8],
) -> Result<DlEndpoint, TransferError> {
    const WHAT: &str = "PathSwitchRequestTransfer";
    let t = decode::<g::PathSwitchRequestTransfer>(WHAT, bytes)?;
    let qfis = t
        .qos_flow_accepted_list
        .0
        .iter()
        .map(|f| f.qos_flow_identifier.0)
        .collect();
    endpoint(WHAT, t.dl_ngu_up_tnl_information, qfis)
}

/// What the SMF reads from a `HandoverRequestAcknowledgeTransfer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandoverAck {
    /// The target NG-RAN's DL N3 endpoint; `qfis` are the QoS flows it
    /// accepted (its QoS Flow Setup Response List), in order.
    pub dl: DlEndpoint,
    /// The accepted QoS flows whose `dataForwardingAccepted` is set.
    pub forwarding_accepted_qfis: Vec<u8>,
    /// DL Forwarding UP TNL Information: the one tunnel per PDU session the
    /// NG-RAN assigns for INDIRECT forwarding (TS 23.502 §4.11.1.2.2.2 step 10).
    pub dl_forwarding: Option<DlEndpoint>,
    /// Data Forwarding Response E-RAB List (TS 38.413 §9.3.1.121): one DL
    /// forwarding tunnel per E-RAB accepted for DIRECT forwarding, as
    /// `(E-RAB ID, tunnel)`.
    pub erab_forwarding: Vec<(u8, DlEndpoint)>,
}

/// `HandoverRequestAcknowledgeTransfer` (TS 38.413 §9.3.4.11): the target
/// NG-RAN's DL N3 endpoint, the QoS flows it accepted, and the data-forwarding
/// tunnels it assigned -- per PDU session for indirect forwarding, per E-RAB
/// for direct forwarding from E-UTRAN (step 10).
pub(crate) fn parse_handover_request_acknowledge_transfer(
    bytes: &[u8],
) -> Result<HandoverAck, TransferError> {
    const WHAT: &str = "HandoverRequestAcknowledgeTransfer";
    let t = decode::<g::HandoverRequestAcknowledgeTransfer>(WHAT, bytes)?;
    let flows = &t.qos_flow_setup_response_list.0;
    let qfis = flows.iter().map(|f| f.qos_flow_identifier.0).collect();
    let forwarding_accepted_qfis = flows
        .iter()
        .filter(|f| f.data_forwarding_accepted.is_some())
        .map(|f| f.qos_flow_identifier.0)
        .collect();
    let dl_forwarding = t
        .dl_forwarding_up_tnl_information
        .map(|tunnel| endpoint(WHAT, tunnel, Vec::new()))
        .transpose()?;
    let mut erab_forwarding = Vec::new();
    for ext in t.ie_extensions.map(|e| e.0).unwrap_or_default() {
        use g::HandoverRequestAcknowledgeTransferIE_Extensions_EntryExtensionValue as Ext;
        if let Ext::Id_DataForwardingResponseERABList(list) = ext.extension_value {
            for item in list.0 {
                erab_forwarding.push((
                    item.e_rab_id.0,
                    endpoint(WHAT, item.dl_forwarding_up_tnl_information, Vec::new())?,
                ));
            }
        }
    }
    Ok(HandoverAck {
        dl: endpoint(WHAT, t.dl_ngu_up_tnl_information, qfis)?,
        forwarding_accepted_qfis,
        dl_forwarding,
        erab_forwarding,
    })
}

#[cfg(test)]
mod oracle_tests;
