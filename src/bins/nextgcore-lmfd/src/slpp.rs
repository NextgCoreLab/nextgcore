//! SLPP sidelink positioning at the LMF (#557).
//!
//! The LMF is Endpoint B of TS 38.355 §5: it requests capabilities and
//! location information (§5.1.2, §5.3.2) and serves assistance data (§5.2.5).
//! The target UE is Endpoint A. SLPP travels in UL and DL NAS TRANSPORT as
//! payload container type 12, "SLPP message container" (TS 24.501 k00
//! §9.11.3.40). On the SBI it is carried with `n1MessageClass` "SLPP" (see
//! [`N1_MESSAGE_CLASS_SLPP`]).
//!
//! # Transport (TS 38.355 §4.3)
//!
//! - Every message with a body that the LMF sends carries a sequence number,
//!   counted per UE and location session (§4.3.2). A bare acknowledgement
//!   carries none: sequenceNumber "shall be omitted" without a body (§6.2).
//! - The last sequence number received is held per UE and location session.
//!   A repeat is discarded. The LMF deletes both numbers when its location
//!   session ends, as §4.3.2 asks of a server.
//! - A location session is named by its LCS correlation identifier. The LMF
//!   mints one per SL-RTT run and sends every DL message of that run under it.
//!   The AMF reports it back on the UE's uplink.
//! - Sequence state is bounded. A live session (a [`SessionGuard`]) is never
//!   evicted, and at most [`MAX_PENDING_EXCHANGES`] are live at once. Any other
//!   session, such as the one a UE's unsolicited message opens, is forgotten after
//!   [`SESSION_IDLE`] without activity, or evicted oldest first when the map is
//!   full.
//! - A UE message that asks for an acknowledgement gets a bare one (§4.3.3),
//!   duplicates and undecodable bodies included (§4.3.4.2 step 4).
//! - **Deviation: the LMF never asks for an acknowledgement and never
//!   retransmits (§4.3.4).** §4.3.1 puts reliable transport on the UE. Over NAS,
//!   delivery to the UE is reliable already, and each LMF exchange is bounded
//!   by the DetermineLocation response time instead.
//! - The answer to a UE's RequestAssistanceData carries the received sessionID
//!   and transactionID (§5.2.5). An Error carries a sessionID only "if PC5-U
//!   is used as transport layer" (§5.4.3), so over NAS it carries none.
//!
//! # Method: SL-RTT (TS 38.305 §4.3.16.1, §8.15.2)
//!
//! "The SL Rx-Tx time difference measurements performed by a pair of UEs
//! defines the RTT between the UEs." In single-sided RTT, UE A sends SL-PRS at
//! `tA` and UE B sends at `tB`. A then measures `RxTx_AB = tB + tof - tA`, and B
//! measures `RxTx_BA = tA + tof - tB`. Their sum is `2 * tof` whatever the
//! offset between `tA` and `tB`, so the range is `c * (RxTx_AB + RxTx_BA) / 2`.
//! A single UE's report is half a measurement. [`SlRttStore`] therefore holds
//! each half under (reporter, peer) application layer IDs and produces a range
//! once the reverse half exists.
//!
//! # Whose half it is (R45 M1 on #2254)
//!
//! A UE names itself by the applicationLayerID in its own SLPP-Message, and
//! nothing on the wire ties that to its SUPI. #2260: the binding comes from the
//! 5GC, not from the UE. Before an SL-RTT run, the LMF reads the Application
//! Layer IDs the UDR maps to the target's GPSI (TS 23.586 §4.3.5, TS 29.519
//! §6.2.26, [`crate::nudr_client`]) and binds those to the target
//! ([`AppIdBindings`], bounded, idle entries expire). Before #2260 the first UE
//! to claim an ID in a solicited answer kept it, and every later claim
//! refreshed it, so a UE ranged often enough held another UE's ID for good.
//! A half is held only when:
//! - it comes from a ProvideLocationInformation that answers an exchange this
//!   LMF started, and
//! - its reporter ID is bound to the UE it arrived from.
//!
//! A range is computed only when the target's reporter ID is the target's own.
//!
//! # Report mapping (TS 38.133 §10.4A.4.1.1)
//!
//! The reporting range is -985024 Tc to 985024 Tc, in steps of `2^k` Tc. Value 0
//! means "below the range" and the top value means "at or above it". Value `v`
//! in between covers `[-985024 + 2^k (v-1), -985024 + 2^k v)` Tc. The LMF reads
//! the midpoint of that bin. Tc is 1 / (480000 * 4096) s (TS 38.211 §4.1).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use nextgcore_slpp_gen::generated as g;
use nextgcore_slpp_gen::{decode, decode_ie, encode, encode_ie};

/// `n1MessageClass` for SLPP (#557).
///
/// TS 29.518 defines no SLPP value (TS29518_Namf_Communication.yaml:4511-4523
/// lists 5GMM, SM, LPP, SMS, UPDP, LCS, UPP-CM), while TS 24.501 k00
/// §5.4.5.2.5 c1 has the AMF "send the Payload container type and the content
/// ... to the LMF". The enum is `anyOf [enum, string]`, so the class can be
/// extended. amfd spells it the same way.
pub const N1_MESSAGE_CLASS_SLPP: &str = "SLPP";

/// Tc, the basic NR time unit (TS 38.211 §4.1): 1 / (480 kHz * 4096) s.
pub const TC_SECONDS: f64 = 1.0 / (480_000.0 * 4096.0);

/// Speed of light in vacuum, m/s.
const SPEED_OF_LIGHT_M_S: f64 = 299_792_458.0;

/// TS 38.133 §10.4A.4.1.1: the reporting range is +/-985024 Tc.
const RX_TX_RANGE_TC: i64 = 985_024;

/// `locationInformationType` rangeMeasurementsRequired: index 5 of the
/// enumeration in TS 38.355 CommonIEsRequestLocationInformation.
const RANGE_MEASUREMENTS_REQUIRED: u8 = 5;

/// `PositioningModes` bit 1, sl-TargetUE-Assisted (TS 38.355).
const SL_TARGET_UE_ASSISTED_BIT: usize = 1;

/// An SL-RTT half older than this is not paired. SL-RTT needs the two halves
/// of one exchange, and two UEs that moved apart between reports would
/// otherwise give a range that describes neither moment.
pub const SL_RTT_HALF_MAX_AGE: Duration = Duration::from_secs(30);

/// At most this many halves are held. The oldest is evicted first.
pub const SL_RTT_STORE_CAP: usize = 4096;

/// At most this many SLPP transactions wait for an answer at once.
pub const MAX_PENDING_EXCHANGES: usize = 1024;

// ---------------------------------------------------------------------------
// Downlink messages (LMF -> UE)
// ---------------------------------------------------------------------------

fn message(
    tid: Option<u8>,
    seq: Option<u8>,
    end: bool,
    body: g::SLPP_MessageBody_c1,
) -> g::SLPP_Message {
    g::SLPP_Message {
        application_layer_id: None,
        transaction_id: tid.map(g::SLPP_MessageTransactionID),
        end_transaction: g::SLPP_MessageEndTransaction(end),
        sequence_number: seq.map(g::SequenceNumber),
        session_id: None,
        acknowledgement: None,
        slpp_message_body: Some(g::SLPP_MessageBody::C1(body)),
        non_critical_extension: None,
    }
}

fn enc<T: asn1_codecs::uper::UperCodec>(v: &T) -> Result<Vec<u8>, String> {
    encode_ie(v).map_err(|e| format!("SLPP encode: {e:?}"))
}

/// RequestCapabilities for SL-RTT (TS 38.355 §5.1.1).
pub fn build_request_capabilities(tid: u8, seq: Option<u8>) -> Result<Vec<u8>, String> {
    let ies = g::RequestCapabilities_IEs {
        common_i_es_request_capabilities: None,
        common_sl_prs_methods_i_es_request_capabilities: None,
        sl_ao_a_request_capabilities: None,
        sl_rtt_request_capabilities: Some(g::RequestCapabilities_IEsSl_RTT_RequestCapabilities(
            enc(&g::SL_RTT_RequestCapabilities {})?,
        )),
        sl_tdoa_request_capabilities: None,
        sl_toa_request_capabilities: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    encode(&message(
        Some(tid),
        seq,
        false,
        g::SLPP_MessageBody_c1::RequestCapabilities(g::RequestCapabilities {
            critical_extensions: g::RequestCapabilitiesCriticalExtensions::RequestCapabilities(ies),
        }),
    ))
    .map_err(|e| format!("SLPP encode: {e:?}"))
}

/// RequestLocationInformation for SL-RTT range measurements (TS 38.355
/// §5.3.1). It asks for `rangeMeasurementsRequired` and the SL PRS-RSRP that
/// goes with each Rx-Tx measurement (TS 38.305 Table 8.15.2.2.3-1).
pub fn build_request_location_information(tid: u8, seq: Option<u8>) -> Result<Vec<u8>, String> {
    let common = g::CommonIEsRequestLocationInformation {
        location_information_type: g::LocationInformationType(RANGE_MEASUREMENTS_REQUIRED),
        periodical_reporting: None,
        additional_information: None,
        qos: None,
        environment: None,
        scheduled_location_time: None,
        location_coordinate_types: None,
        velocity_types: None,
    };
    let rtt = g::SL_RTT_RequestLocationInformation {
        sl_arp_info_request: None,
        sl_los_nlos_indicator_request: None,
        sl_prs_rsrp_request: Some(g::SL_RTT_RequestLocationInformationSl_PRS_RSRP_Request(0)),
        sl_rsrpp_request: None,
        sl_additional_paths_request: None,
        dummy: None,
        multiple_sl_prs_rx_tx_time_diff_request: None,
        measurements_for_multiple_arp_i_ds_rx: None,
        associated_sl_prs_tx_time_stamp_request: None,
    };
    let ies = g::RequestLocationInformation_IEs {
        common_i_es_request_location_information: Some(
            g::RequestLocationInformation_IEsCommonIEsRequestLocationInformation(enc(&common)?),
        ),
        common_sl_prs_methods_i_es_request_location_information: None,
        sl_ao_a_request_location_information: None,
        sl_rtt_request_location_information: Some(
            g::RequestLocationInformation_IEsSl_RTT_RequestLocationInformation(enc(&rtt)?),
        ),
        sl_tdoa_request_location_information: None,
        sl_toa_request_location_information: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    encode(&message(
        Some(tid),
        seq,
        false,
        g::SLPP_MessageBody_c1::RequestLocationInformation(g::RequestLocationInformation {
            critical_extensions:
                g::RequestLocationInformationCriticalExtensions::RequestLocationInformation(ies),
        }),
    ))
    .map_err(|e| format!("SLPP encode: {e:?}"))
}

/// ProvideAssistanceData answering a UE's RequestAssistanceData for SL-RTT
/// (TS 38.355 §5.2.5), on the UE's transaction and ending it. It carries the
/// received transactionID and sessionID, and none when none was received
/// (an invented transaction 0 could match a real one at the UE). `SL-RTT-
/// ProvideAssistanceData` is `SEQUENCE { ... }` in V19.2.0, with no root
/// member, so the SL-RTT part carries no data. The SL-PRS configuration a UE
/// would want sits in the common SL-PRS methods IEs, and this LMF holds none
/// (it schedules no SL-PRS), so it sends none rather than inventing one.
pub fn build_provide_assistance_data(
    tid: Option<u8>,
    session_id: Option<Vec<u8>>,
    seq: Option<u8>,
) -> Result<Vec<u8>, String> {
    let ies = g::ProvideAssistanceData_IEs {
        common_i_es_provide_assistance_data: None,
        common_sl_prs_methods_i_es_provide_assistance_data: None,
        sl_ao_a_provide_assistance_data: None,
        sl_rtt_provide_assistance_data: Some(
            g::ProvideAssistanceData_IEsSl_RTT_ProvideAssistanceData(enc(
                &g::SL_RTT_ProvideAssistanceData {},
            )?),
        ),
        sl_tdoa_provide_assistance_data: None,
        sl_toa_provide_assistance_data: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    let mut msg = message(
        tid,
        seq,
        true,
        g::SLPP_MessageBody_c1::ProvideAssistanceData(g::ProvideAssistanceData {
            critical_extensions: g::ProvideAssistanceDataCriticalExtensions::ProvideAssistanceData(
                ies,
            ),
        }),
    );
    msg.session_id = session_id.map(g::SessionID);
    encode(&msg).map_err(|e| format!("SLPP encode: {e:?}"))
}

/// Error (TS 38.355 §5.4.2) with `errorCause` slppMessageHeaderError (1) or
/// slppMessageBodyError (2). `tid` echoes the erroneous message's transaction
/// when it could be read.
pub fn build_error(tid: Option<u8>, seq: Option<u8>, cause: ErrorCause) -> Result<Vec<u8>, String> {
    let msg = g::SLPP_Message {
        application_layer_id: None,
        transaction_id: tid.map(g::SLPP_MessageTransactionID),
        end_transaction: g::SLPP_MessageEndTransaction(true),
        sequence_number: seq.map(g::SequenceNumber),
        session_id: None,
        acknowledgement: None,
        slpp_message_body: Some(g::SLPP_MessageBody::C1(g::SLPP_MessageBody_c1::Error(
            g::Error::CriticalExtensions(g::Error_criticalExtensions::Error(g::Error_IEs {
                common_i_es_error: Some(g::CommonIEsError {
                    error_cause: g::CommonIEsErrorErrorCause(cause as u8),
                }),
                late_non_critical_extension: None,
                non_critical_extension: None,
            })),
        ))),
        non_critical_extension: None,
    };
    encode(&msg).map_err(|e| format!("SLPP encode: {e:?}"))
}

/// A bare acknowledgement of the UE's message `acked` (TS 38.355 §4.3.3).
/// With no body it carries no transactionID and no sequenceNumber (§6.2
/// field descriptions), and endTransaction is FALSE.
pub fn build_ack(acked: u8) -> Result<Vec<u8>, String> {
    encode(&g::SLPP_Message {
        application_layer_id: None,
        transaction_id: None,
        end_transaction: g::SLPP_MessageEndTransaction(false),
        sequence_number: None,
        session_id: None,
        acknowledgement: Some(g::Acknowledgement {
            ack_requested: g::AcknowledgementAckRequested(false),
            ack_indicator: Some(g::SequenceNumber(acked)),
        }),
        slpp_message_body: None,
        non_critical_extension: None,
    })
    .map_err(|e| format!("SLPP encode: {e:?}"))
}

/// The header fields of an uplink SLPP message that the transport (§4.3) and
/// the answer (§5.2.5) act on, whatever its body holds.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UplinkHeader {
    /// sequenceNumber (§4.3.2).
    pub seq: Option<u8>,
    /// The sequence number to acknowledge, when the UE asked (§4.3.3).
    pub ack_for: Option<u8>,
    /// sessionID, echoed in the answer (§5.2.5).
    pub session_id: Option<Vec<u8>>,
}

/// The header of an uplink SLPP message, when the message decodes. A body
/// container that does not decode leaves the header readable (§4.3.4.2
/// step 4: acknowledged "regardless of whether the message body can be
/// correctly decoded").
pub fn uplink_header(bytes: &[u8]) -> Option<UplinkHeader> {
    let msg = decode(bytes).ok()?;
    let seq = msg.sequence_number.as_ref().map(|s| s.0);
    Some(UplinkHeader {
        seq,
        ack_for: msg
            .acknowledgement
            .as_ref()
            .filter(|a| a.ack_requested.0)
            .and(seq),
        session_id: msg.session_id.map(|s| s.0),
    })
}

/// `CommonIEsError.errorCause` (TS 38.355).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCause {
    /// `undefined`.
    Undefined = 0,
    /// `slppMessageHeaderError`.
    HeaderError = 1,
    /// `slppMessageBodyError`.
    BodyError = 2,
    /// `incorrectDataValue`.
    IncorrectDataValue = 3,
}

// ---------------------------------------------------------------------------
// Uplink messages (UE -> LMF)
// ---------------------------------------------------------------------------

/// One SL Rx-Tx time difference the reporting UE measured on a peer's SL-PRS.
#[derive(Debug, Clone, PartialEq)]
pub struct SlRttHalf {
    /// The peer UE's application layer ID (TS 23.287), as carried.
    pub peer: Vec<u8>,
    /// The measured SL Rx-Tx time difference, in Tc (bin midpoint).
    pub rx_tx_tc: f64,
}

/// What an uplink SLPP message asks of, or tells, the LMF.
#[derive(Debug, Clone, PartialEq)]
pub enum Uplink {
    /// ProvideCapabilities (TS 38.355 §5.1).
    Capabilities {
        tid: Option<u8>,
        app_id: Option<Vec<u8>>,
        /// SL-RTT in the sl-TargetUE-Assisted mode, which this LMF uses.
        sl_rtt_ue_assisted: bool,
    },
    /// ProvideLocationInformation (TS 38.355 §5.3).
    Location {
        tid: Option<u8>,
        app_id: Option<Vec<u8>>,
        halves: Vec<SlRttHalf>,
        /// `SL-RTT-LocationInformationError` index, when the UE reported one.
        sl_rtt_error: Option<u8>,
    },
    /// RequestAssistanceData from the UE (TS 38.355 §5.2).
    AssistanceRequest { tid: Option<u8> },
    /// Error (§5.4) or Abort (§5.5) from the UE. Either one ends the transaction.
    Ended { tid: Option<u8>, what: &'static str },
    /// A body this LMF does not act on as Endpoint B.
    Other { tid: Option<u8> },
}

impl Uplink {
    /// The transaction the message belongs to.
    pub fn transaction(&self) -> Option<u8> {
        match self {
            Self::Capabilities { tid, .. }
            | Self::Location { tid, .. }
            | Self::AssistanceRequest { tid }
            | Self::Ended { tid, .. }
            | Self::Other { tid } => *tid,
        }
    }
}

/// Why an uplink SLPP message could not be read, together with the Error cause
/// TS 38.355 §5.4.3 answers it with.
#[derive(Debug, Clone, PartialEq)]
pub struct UplinkError {
    pub tid: Option<u8>,
    pub cause: ErrorCause,
    pub detail: String,
}

/// The SL Rx-Tx time difference, in Tc, for a reported value `v` of the arm
/// `k` (TS 38.133 §10.4A.4.1.1). Returns `None` for the two open-ended edge
/// values, which bound the measurement on one side only, and for a value out of
/// the arm's range.
pub fn rx_tx_tc(k: u32, v: u32) -> Option<f64> {
    let step = 1i64 << k;
    let top = 2 * RX_TX_RANGE_TC / step + 1;
    let v = i64::from(v);
    if v == 0 || v >= top {
        return None;
    }
    let lower = -RX_TX_RANGE_TC + step * (v - 1);
    Some(lower as f64 + step as f64 / 2.0)
}

fn rx_tx_of(result: &g::SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult) -> Option<f64> {
    use g::SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult as K;
    match result {
        K::K0(v) => rx_tx_tc(0, v.0),
        K::K1(v) => rx_tx_tc(1, v.0),
        K::K2(v) => rx_tx_tc(2, v.0),
        K::K3(v) => rx_tx_tc(3, v.0),
        K::K4(v) => rx_tx_tc(4, v.0),
        K::K5(v) => rx_tx_tc(5, u32::from(v.0)),
    }
}

fn halves_in(info: &g::SL_RTT_ProvideLocationInformation) -> Vec<SlRttHalf> {
    let Some(meas) = info.sl_rtt_signal_measurement_information.as_ref() else {
        return vec![];
    };
    let mut out = Vec::new();
    for per_arp in &meas.sl_rtt_meas_list.0 {
        // Cond FirstElement: the peer's ID is in the first element of each list.
        let Some(peer) = per_arp
            .0
            .first()
            .and_then(|e| e.application_layer_id.as_ref())
            .map(|a| a.0.clone())
        else {
            log::warn!("SLPP: SL-RTT measurement list without the peer's applicationLayerID");
            continue;
        };
        for element in &per_arp.0 {
            let result = match &element.sl_prs_rx_tx_time_diff_meas_result {
                g::SL_PRS_RxTxTimeDiffMeasResult::Single_SL_PRS_RxTxTimeDiff(r) => r,
                // Several Rx-Tx results per pair need the SL-PRS occasion pairing
                // to combine. The first, single, measurement is what the range uses.
                g::SL_PRS_RxTxTimeDiffMeasResult::Multiple_SL_PRS_RxTxTimeDiff(_) => continue,
            };
            if let Some(rx_tx_tc) = result
                .sl_prs_rx_tx_time_diff_result
                .as_ref()
                .and_then(rx_tx_of)
            {
                out.push(SlRttHalf {
                    peer: peer.clone(),
                    rx_tx_tc,
                });
                break;
            }
        }
    }
    out
}

/// Decode one uplink SLPP message.
pub fn decode_uplink(bytes: &[u8]) -> Result<Uplink, UplinkError> {
    decode_uplink_with_sequence(bytes).map(|(u, _)| u)
}

/// [`decode_uplink`], also returning the message's sequenceNumber (TS 38.355
/// §4.3.2).
pub fn decode_uplink_with_sequence(bytes: &[u8]) -> Result<(Uplink, Option<u8>), UplinkError> {
    let (uplink, seq) = decode_uplink_inner(bytes)?;
    Ok((uplink, seq))
}

fn decode_uplink_inner(bytes: &[u8]) -> Result<(Uplink, Option<u8>), UplinkError> {
    let msg = decode(bytes).map_err(|e| UplinkError {
        tid: None,
        cause: ErrorCause::HeaderError,
        detail: format!("SLPP-Message does not decode: {e:?}"),
    })?;
    let tid = msg.transaction_id.as_ref().map(|t| t.0);
    let seq = msg.sequence_number.as_ref().map(|s| s.0);
    let app_id = msg.application_layer_id.as_ref().map(|a| a.0.clone());
    let body_error = |detail: String| UplinkError {
        tid,
        cause: ErrorCause::BodyError,
        detail,
    };
    let Some(g::SLPP_MessageBody::C1(body)) = msg.slpp_message_body else {
        return Ok((Uplink::Other { tid }, seq));
    };
    let uplink = match body {
        g::SLPP_MessageBody_c1::ProvideCapabilities(pc) => {
            let g::ProvideCapabilitiesCriticalExtensions::ProvideCapabilities(ies) =
                pc.critical_extensions
            else {
                return Ok((Uplink::Other { tid }, seq));
            };
            let sl_rtt_ue_assisted = match ies.sl_rtt_provide_capabilities {
                Some(c) => {
                    let caps: g::SL_RTT_ProvideCapabilities = decode_ie(&c.0)
                        .map_err(|e| body_error(format!("SL-RTT-ProvideCapabilities: {e:?}")))?;
                    caps.positioning_modes
                        .0
                        .get(SL_TARGET_UE_ASSISTED_BIT)
                        .is_some_and(|b| *b)
                }
                None => false,
            };
            Uplink::Capabilities {
                tid,
                app_id,
                sl_rtt_ue_assisted,
            }
        }
        g::SLPP_MessageBody_c1::ProvideLocationInformation(p) => {
            let g::ProvideLocationInformationCriticalExtensions::ProvideLocationInformation(ies) =
                p.critical_extensions
            else {
                return Ok((Uplink::Other { tid }, seq));
            };
            let (halves, sl_rtt_error) = match ies.sl_rtt_provide_location_information {
                Some(c) => {
                    let info: g::SL_RTT_ProvideLocationInformation =
                        decode_ie(&c.0).map_err(|e| {
                            body_error(format!("SL-RTT-ProvideLocationInformation: {e:?}"))
                        })?;
                    (halves_in(&info), info.sl_rtt_error.as_ref().map(|e| e.0))
                }
                None => (vec![], None),
            };
            Uplink::Location {
                tid,
                app_id,
                halves,
                sl_rtt_error,
            }
        }
        g::SLPP_MessageBody_c1::RequestAssistanceData(_) => Uplink::AssistanceRequest { tid },
        g::SLPP_MessageBody_c1::Error(_) => Uplink::Ended { tid, what: "Error" },
        g::SLPP_MessageBody_c1::Abort(_) => Uplink::Ended { tid, what: "Abort" },
        _ => Uplink::Other { tid },
    };
    Ok((uplink, seq))
}

// ---------------------------------------------------------------------------
// SL-RTT halves and the range
// ---------------------------------------------------------------------------

/// The range from the two halves of one SL-RTT exchange, in metres (TS 38.305
/// §8.15.2: c * RTT / 2, with RTT = RxTx_AB + RxTx_BA).
pub fn range_m(rx_tx_ab_tc: f64, rx_tx_ba_tc: f64) -> f64 {
    SPEED_OF_LIGHT_M_S * (rx_tx_ab_tc + rx_tx_ba_tc) * TC_SECONDS / 2.0
}

/// The largest range two halves can give: both at the top of the reporting
/// range, +985024 Tc each (TS 38.133 §10.4A.4.1.1), about 150 km.
pub fn max_range_m() -> f64 {
    range_m(RX_TX_RANGE_TC as f64, RX_TX_RANGE_TC as f64)
}

/// [`range_m`], when it is a distance (R45 M2 on #2254). The halves are signed,
/// so measurement error or a mismatched pair can sum below zero. TS 29.572's
/// distance is a magnitude, so a negative, non-finite or out-of-range value is
/// no range at all.
pub fn valid_range_m(rx_tx_ab_tc: f64, rx_tx_ba_tc: f64) -> Option<f64> {
    let r = range_m(rx_tx_ab_tc, rx_tx_ba_tc);
    if r.is_finite() && (0.0..=max_range_m()).contains(&r) {
        Some(r)
    } else {
        log::warn!(
            "SL-RTT halves {rx_tx_ab_tc} Tc and {rx_tx_ba_tc} Tc give {r} m, which is no \
             distance; no range is reported"
        );
        None
    }
}

/// SL-RTT halves, keyed by (reporter, peer) application layer ID.
#[derive(Debug, Default)]
pub struct SlRttStore {
    inner: Mutex<SlRttInner>,
}

#[derive(Debug, Default)]
struct SlRttInner {
    halves: HashMap<(Vec<u8>, Vec<u8>), (f64, Instant)>,
    /// Insertion order, for evicting the oldest.
    order: VecDeque<(Vec<u8>, Vec<u8>)>,
}

impl SlRttStore {
    /// Record what `reporter` measured. A newer half replaces the older one for
    /// the same peer.
    pub fn note(&self, reporter: &[u8], halves: &[SlRttHalf]) {
        self.note_at(reporter, halves, Instant::now());
    }

    fn note_at(&self, reporter: &[u8], halves: &[SlRttHalf], at: Instant) {
        let Ok(mut s) = self.inner.lock() else {
            return;
        };
        for h in halves {
            let key = (reporter.to_vec(), h.peer.clone());
            if s.halves.insert(key.clone(), (h.rx_tx_tc, at)).is_some() {
                s.order.retain(|k| k != &key);
            }
            s.order.push_back(key);
            while s.halves.len() > SL_RTT_STORE_CAP {
                let Some(oldest) = s.order.pop_front() else {
                    break;
                };
                s.halves.remove(&oldest);
            }
        }
    }

    /// The range between `a` and `b`, when both halves are held and neither is
    /// older than [`SL_RTT_HALF_MAX_AGE`].
    pub fn range_between(&self, a: &[u8], b: &[u8]) -> Option<f64> {
        self.range_between_at(a, b, Instant::now())
    }

    fn range_between_at(&self, a: &[u8], b: &[u8], now: Instant) -> Option<f64> {
        let s = self.inner.lock().ok()?;
        let fresh = |k: (Vec<u8>, Vec<u8>)| {
            s.halves
                .get(&k)
                .filter(|(_, at)| now.saturating_duration_since(*at) <= SL_RTT_HALF_MAX_AGE)
                .map(|(t, _)| *t)
        };
        let ab = fresh((a.to_vec(), b.to_vec()))?;
        let ba = fresh((b.to_vec(), a.to_vec()))?;
        valid_range_m(ab, ba)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map(|s| s.halves.len()).unwrap_or(0)
    }

    /// Forget every half (tests that use the process-global store).
    #[cfg(test)]
    pub(crate) fn clear(&self) {
        if let Ok(mut s) = self.inner.lock() {
            s.halves.clear();
            s.order.clear();
        }
    }
}

/// The range between the UE `target`, which reported as `reporter`, and `peer`
/// (R45 M1 on #2254): only when `reporter` is bound to `target`, so a UE that
/// names another UE's ID as its own is not given that UE's range.
pub fn range_for(target: &str, reporter: &[u8], peer: &[u8]) -> Option<f64> {
    if !app_id_bindings().is_bound_to(reporter, target) {
        log::warn!(
            "SLPP ranging for {target}: its report names an applicationLayerID the network \
             does not map to it; no range"
        );
        return None;
    }
    sl_rtt_store().range_between(reporter, peer)
}

/// The LMF's SL-RTT halves.
pub fn sl_rtt_store() -> &'static SlRttStore {
    static STORE: OnceLock<SlRttStore> = OnceLock::new();
    STORE.get_or_init(SlRttStore::default)
}

// ---------------------------------------------------------------------------
// Waiting for the UE's answer
// ---------------------------------------------------------------------------

type ExchangeKey = (String, u8);

/// SLPP transactions this LMF started and is waiting on, keyed by (UE, tid).
#[derive(Debug, Default)]
pub struct SlppExchanges {
    waiting: Mutex<HashMap<ExchangeKey, (u64, tokio::sync::oneshot::Sender<Uplink>)>>,
    next: std::sync::atomic::AtomicU64,
}

/// Removes its exchange when dropped, so a request that times out or whose
/// caller goes away leaves nothing waiting (cancellation safety). The sequence
/// number stops a late guard from removing a newer exchange on the same key.
pub struct ExchangeGuard {
    exchanges: &'static SlppExchanges,
    key: ExchangeKey,
    seq: u64,
}

impl Drop for ExchangeGuard {
    fn drop(&mut self) {
        if let Ok(mut w) = self.exchanges.waiting.lock() {
            if w.get(&self.key).is_some_and(|(s, _)| *s == self.seq) {
                w.remove(&self.key);
            }
        }
    }
}

impl SlppExchanges {
    /// Wait for the answer on (`ue`, `tid`). `None` when the cap is reached or
    /// the transaction is already in use.
    pub fn begin(
        &'static self,
        ue: &str,
        tid: u8,
    ) -> Option<(ExchangeGuard, tokio::sync::oneshot::Receiver<Uplink>)> {
        let mut w = self.waiting.lock().ok()?;
        let key = (ue.to_string(), tid);
        if w.len() >= MAX_PENDING_EXCHANGES || w.contains_key(&key) {
            return None;
        }
        let seq = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel();
        w.insert(key.clone(), (seq, tx));
        Some((
            ExchangeGuard {
                exchanges: self,
                key,
                seq,
            },
            rx,
        ))
    }

    /// Whether an exchange waits on (`ue`, `tid`).
    pub fn is_waiting(&self, ue: &str, tid: Option<u8>) -> bool {
        let Some(tid) = tid else {
            return false;
        };
        self.waiting
            .lock()
            .is_ok_and(|w| w.contains_key(&(ue.to_string(), tid)))
    }

    /// Hand `uplink` to the exchange waiting on it. Returns whether one was.
    pub fn complete(&self, ue: &str, uplink: Uplink) -> bool {
        let Some(tid) = uplink.transaction() else {
            return false;
        };
        let Some((_, tx)) = self
            .waiting
            .lock()
            .ok()
            .and_then(|mut w| w.remove(&(ue.to_string(), tid)))
        else {
            return false;
        };
        tx.send(uplink).is_ok()
    }

    #[cfg(test)]
    fn pending(&self) -> usize {
        self.waiting.lock().map(|w| w.len()).unwrap_or(0)
    }
}

/// The LMF's waiting SLPP exchanges.
pub fn exchanges() -> &'static SlppExchanges {
    static EXCHANGES: OnceLock<SlppExchanges> = OnceLock::new();
    EXCHANGES.get_or_init(SlppExchanges::default)
}

/// A location session with one UE (§4.3.2): the UE and the LCS correlation
/// identifier its SLPP messages travel under.
type SessionKey = (String, Option<String>);

fn session_key(ue: &str, session: Option<&str>) -> SessionKey {
    (ue.to_string(), session.map(str::to_string))
}

/// A session that no live [`SessionGuard`] holds, such as the one a UE's
/// unsolicited message opens, is forgotten after this long without activity
/// (R45 m2 on #2254). It matches the 10 minutes §4.3.2 gives the UE.
pub const SESSION_IDLE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Default)]
struct SequencesInner {
    /// Per session: the last number sent, and the last activity.
    sent: HashMap<SessionKey, (u8, Instant)>,
    /// Per session: the last number received, and the last activity.
    received: HashMap<SessionKey, (u8, Instant)>,
    /// Sessions a live [`SessionGuard`] holds: never evicted.
    live: std::collections::HashSet<SessionKey>,
}

/// Make room in `map` for `key`, at `now`: entries idle for [`SESSION_IDLE`]
/// go, and then, while the map is still full, the oldest entry no live session
/// holds (R45 M3 on #2254). A live session is never evicted.
fn make_room(
    map: &mut HashMap<SessionKey, (u8, Instant)>,
    live: &std::collections::HashSet<SessionKey>,
    key: &SessionKey,
    now: Instant,
) {
    if map.contains_key(key) || map.len() < MAX_PENDING_EXCHANGES {
        return;
    }
    map.retain(|k, (_, at)| live.contains(k) || now.saturating_duration_since(*at) < SESSION_IDLE);
    while map.len() >= MAX_PENDING_EXCHANGES {
        let Some(oldest) = map
            .iter()
            .filter(|(k, _)| !live.contains(*k))
            .min_by_key(|(_, (_, at))| *at)
            .map(|(k, _)| k.clone())
        else {
            // Only live sessions: they are capped at MAX_PENDING_EXCHANGES.
            break;
        };
        map.remove(&oldest);
    }
}

/// TS 38.355 §4.3.2 on both sides of the LMF's SLPP location sessions.
///
/// - Sending: the LMF "shall include a sequence number in all SLPP messages
///   sent for a particular location session", distinct per message, and
///   [`next_sequence`] increases it per UE and session.
/// - Receiving: a message whose sequence number equals the last one received
///   "for the same pair of endpoints and the associated location session ...
///   shall be discarded" ([`is_duplicate`]).
/// - Both "shall be deleted in a server when the associated location session
///   is terminated" ([`end_session`]).
///
/// A session is named by (UE, LCS correlation identifier). Each map holds at
/// most [`MAX_PENDING_EXCHANGES`] sessions besides live ones (see
/// [`make_room`]).
#[derive(Debug, Default)]
pub struct SlppSequences {
    inner: Mutex<SequencesInner>,
}

impl SlppSequences {
    /// The next sequence number to send to `ue` in location session `session`.
    pub fn next_sequence(&self, ue: &str, session: Option<&str>) -> Option<u8> {
        self.next_sequence_at(ue, session, Instant::now())
    }

    fn next_sequence_at(&self, ue: &str, session: Option<&str>, now: Instant) -> Option<u8> {
        let key = session_key(ue, session);
        let mut guard = self.inner.lock().ok()?;
        let s = &mut *guard;
        make_room(&mut s.sent, &s.live, &key, now);
        let e = s.sent.entry(key).or_insert((u8::MAX, now));
        e.0 = e.0.wrapping_add(1);
        e.1 = now;
        Some(e.0)
    }

    /// Whether a message from `ue` in `session` with sequence number `seq`
    /// repeats the last one received there, which marks it for discarding. A
    /// message without a sequence number cannot be checked and is not a
    /// duplicate.
    pub fn is_duplicate(&self, ue: &str, session: Option<&str>, seq: Option<u8>) -> bool {
        self.is_duplicate_at(ue, session, seq, Instant::now())
    }

    fn is_duplicate_at(
        &self,
        ue: &str,
        session: Option<&str>,
        seq: Option<u8>,
        now: Instant,
    ) -> bool {
        let Some(seq) = seq else {
            return false;
        };
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        let s = &mut *guard;
        let key = session_key(ue, session);
        if let Some(e) = s.received.get_mut(&key) {
            e.1 = now;
            if e.0 == seq {
                return true;
            }
            e.0 = seq;
            return false;
        }
        make_room(&mut s.received, &s.live, &key, now);
        s.received.insert(key, (seq, now));
        false
    }

    /// Mark `session` with `ue` live. `false` when [`MAX_PENDING_EXCHANGES`]
    /// sessions are live already.
    fn begin_live(&self, ue: &str, session: &str) -> bool {
        let Ok(mut s) = self.inner.lock() else {
            return false;
        };
        if s.live.len() >= MAX_PENDING_EXCHANGES {
            return false;
        }
        s.live.insert(session_key(ue, Some(session)));
        true
    }

    /// The LMF ended location session `session` with `ue`: both its sequence
    /// numbers are deleted (§4.3.2), and it is no longer live.
    pub fn end_session(&self, ue: &str, session: Option<&str>) {
        let key = session_key(ue, session);
        if let Ok(mut s) = self.inner.lock() {
            s.sent.remove(&key);
            s.received.remove(&key);
            s.live.remove(&key);
        }
    }

    #[cfg(test)]
    fn tracks(&self, ue: &str, session: Option<&str>) -> bool {
        let key = session_key(ue, session);
        self.inner
            .lock()
            .is_ok_and(|s| s.sent.contains_key(&key) || s.received.contains_key(&key))
    }
}

/// A live location session: its sequence numbers are never evicted while it
/// lasts, and are deleted when it is dropped, so a SL-RTT run that fails, times
/// out or is cancelled still deletes them (§4.3.2).
pub struct SessionGuard {
    ue: String,
    session: String,
}

impl SessionGuard {
    /// A new location session with `ue`, under a fresh LCS correlation
    /// identifier. `None` when [`MAX_PENDING_EXCHANGES`] sessions are live.
    pub fn begin(ue: &str) -> Option<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session = format!("slpp-{n}-{ue}");
        sequences().begin_live(ue, &session).then(|| Self {
            ue: ue.to_string(),
            session,
        })
    }

    /// The session's LCS correlation identifier.
    pub fn correlation_id(&self) -> &str {
        &self.session
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        sequences().end_session(&self.ue, Some(&self.session));
    }
}

/// An applicationLayerID binding is forgotten after this long unused.
pub const APP_ID_BINDING_IDLE: Duration = Duration::from_secs(10 * 60);

/// At most this many applicationLayerIDs are bound. Beyond that the binding
/// unused longest goes first.
pub const APP_ID_BINDING_CAP: usize = 4096;

/// Which UE (SUPI or other UE context id) each applicationLayerID belongs to:
/// the IDs the 5GC maps to that UE's GPSI (#2260, [`AppIdBindings::authorise`]).
/// A UE cannot then write halves, or be ranged, under an ID the network has not
/// given it, however often it answers.
#[derive(Debug, Default)]
pub struct AppIdBindings {
    inner: Mutex<HashMap<Vec<u8>, (String, Instant)>>,
}

impl AppIdBindings {
    /// #2260: `ue`'s authorised IDs are exactly `ids`, as the 5GC maps them now.
    /// An ID the network maps to `ue` is bound to it, even one bound to another
    /// UE before (the mapping moved). An ID bound to `ue` that the network no
    /// longer maps to it is unbound.
    pub fn authorise(&self, ue: &str, ids: &[Vec<u8>]) {
        self.authorise_at(ue, ids, Instant::now());
    }

    fn authorise_at(&self, ue: &str, ids: &[Vec<u8>], now: Instant) {
        let Ok(mut m) = self.inner.lock() else {
            return;
        };
        m.retain(|id, (owner, _)| owner != ue || ids.contains(id));
        for id in ids {
            if !m.contains_key(id) && m.len() >= APP_ID_BINDING_CAP {
                m.retain(|_, (_, at)| now.saturating_duration_since(*at) < APP_ID_BINDING_IDLE);
                if m.len() >= APP_ID_BINDING_CAP {
                    if let Some(oldest) = m
                        .iter()
                        .min_by_key(|(_, (_, at))| *at)
                        .map(|(k, _)| k.clone())
                    {
                        m.remove(&oldest);
                    }
                }
            }
            m.insert(id.clone(), (ue.to_string(), now));
        }
    }

    #[cfg(test)]
    fn is_bound_at(&self, app_id: &[u8], ue: &str, now: Instant) -> bool {
        self.inner.lock().is_ok_and(|m| {
            m.get(app_id).is_some_and(|(owner, at)| {
                owner == ue && now.saturating_duration_since(*at) < APP_ID_BINDING_IDLE
            })
        })
    }

    /// Whether `app_id` is bound to `ue` now.
    pub fn is_bound_to(&self, app_id: &[u8], ue: &str) -> bool {
        let now = Instant::now();
        self.inner.lock().is_ok_and(|m| {
            m.get(app_id).is_some_and(|(owner, at)| {
                owner == ue && now.saturating_duration_since(*at) < APP_ID_BINDING_IDLE
            })
        })
    }

    /// Forget `app_id`'s binding (tests that use the process-global bindings).
    #[cfg(test)]
    pub(crate) fn forget(&self, app_id: &[u8]) {
        if let Ok(mut m) = self.inner.lock() {
            m.remove(app_id);
        }
    }
}

/// The LMF's applicationLayerID bindings.
pub fn app_id_bindings() -> &'static AppIdBindings {
    static B: OnceLock<AppIdBindings> = OnceLock::new();
    B.get_or_init(AppIdBindings::default)
}

/// The LMF's SLPP sequence numbers.
pub fn sequences() -> &'static SlppSequences {
    static SEQ: OnceLock<SlppSequences> = OnceLock::new();
    SEQ.get_or_init(SlppSequences::default)
}

/// The SLPP transaction counter (TS 38.355 transactionID, 0..255).
pub fn next_transaction() -> u8 {
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Serialises tests that touch [`sl_rtt_store`], [`exchanges`], [`sequences`] or
/// [`app_id_bindings`], which are
/// process-global and would otherwise see each other's halves and exchanges.
#[cfg(test)]
pub static SLPP_GLOBALS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The hand-derived goldens of `nextgcore-slpp-gen`
/// (`src/libs/nextgcore-slpp-gen/src/tests.rs`), copied unchanged. nextgsim's
/// UE interop test drives its SLPP endpoint with the same LMF-side bytes, so
/// one set of vectors pins both ends of the exchange.
#[cfg(test)]
pub mod golden {
    /// nextgsim's UE reply to [`REQUEST_CAPABILITIES`] (nextgsim #592,
    /// `UE_PROVIDE_CAPABILITIES`, nextgsim-ue/src/nas/slpp/tests.rs at
    /// 1580bdc): sequenceNumber 0, band n1.
    pub const NEXTGSIM_UE_PROVIDE_CAPABILITIES: [u8; 14] = [
        0xE4, 0x07, 0x4B, 0x4B, 0x4A, 0x03, 0x00, 0x08, 0x40, 0x10, 0x02, 0x80, 0x08, 0x00,
    ];
    /// nextgsim's UE reply to [`REQUEST_LOCATION_INFORMATION`]
    /// (`UE_PROVIDE_LOCATION_INFORMATION`, #592): sequenceNumber 1, the SL-RTT
    /// half on 5A5A5A for a 50 m peer, no RSRP.
    pub const NEXTGSIM_UE_PROVIDE_LOCATION_INFORMATION: [u8; 21] = [
        0xE4, 0x07, 0x4B, 0x4B, 0x4A, 0x05, 0x01, 0x28, 0x40, 0x2D, 0x00, 0x04, 0x03, 0x5A, 0x5A,
        0x5A, 0x08, 0x09, 0xE1, 0x21, 0x00,
    ];
    /// `REQUEST_CAPABILITIES` of nextgcore-slpp-gen: SL-RTT, transaction 1.
    pub const REQUEST_CAPABILITIES: [u8; 6] = [0x44, 0x02, 0x00, 0x40, 0x04, 0x00];
    /// `REQUEST_LOCATION_INFORMATION` of nextgcore-slpp-gen: transaction 2,
    /// rangeMeasurementsRequired, with SL PRS-RSRP requested.
    pub const REQUEST_LOCATION_INFORMATION: [u8; 10] =
        [0x44, 0x04, 0x22, 0x40, 0x08, 0x00, 0xA0, 0x08, 0x40, 0x00];
    /// `PROVIDE_CAPABILITIES` of nextgcore-slpp-gen: from UE A5A5A5, SL-RTT,
    /// sl-TargetUE-Assisted only.
    pub const PROVIDE_CAPABILITIES: [u8; 13] = [
        0xC4, 0x07, 0x4B, 0x4B, 0x4A, 0x03, 0x08, 0x40, 0x10, 0x02, 0x80, 0x08, 0x80,
    ];
    /// `PROVIDE_LOCATION_INFORMATION` of nextgcore-slpp-gen: from UE A5A5A5, one
    /// SL-RTT measurement on peer 5A5A5A, k2 = 246338, RSRP 80.
    pub const PROVIDE_LOCATION_INFORMATION: [u8; 21] = [
        0xC4, 0x07, 0x4B, 0x4B, 0x4A, 0x05, 0x28, 0x40, 0x31, 0x00, 0x04, 0x03, 0x5A, 0x5A, 0x5A,
        0x0C, 0x09, 0xE1, 0x21, 0x50, 0x00,
    ];
}

#[cfg(test)]
mod tests;
