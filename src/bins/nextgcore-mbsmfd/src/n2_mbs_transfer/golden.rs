//! #417: the N2 MBS SM transfers as octets derived by hand from the TS 38.413
//! V17.9 schema and X.691 (ALIGNED PER), the reference the generated codec is
//! checked against now that the hand-written `nextgcore-ngap` codec is no
//! longer a dependency. Every octet below is worked out from the schema in the
//! comment beside it, not taken from either encoder.
//!
//! Shared layout facts (X.691):
//! - a SEQUENCE with `...` opens with its extension bit, then one presence bit
//!   per OPTIONAL member;
//! - TMGI `OCTET STRING (SIZE(6))` and GTP-TEID `OCTET STRING (SIZE(4))` are
//!   fixed-size and longer than two octets, so octet-aligned with no length
//!   (§17.6, §17.8);
//! - TransportLayerAddress `BIT STRING (SIZE(1..160, ...))`: extension bit,
//!   length-1 in 8 bits (range 160, a bit-field), then the bits octet-aligned
//!   (§16.11): `0 00011111` + padding for an IPv4 address;
//! - MBS-AreaSessionID `INTEGER (0..65535, ...)`: extension bit, then two
//!   aligned octets (range 65536, §11.5.7.3);
//! - NID `BIT STRING (SIZE(44))`: fixed, longer than 16 bits, so aligned with
//!   no length, and the next member starts mid-octet (§16.9).

use super::{NgapTmgi, SharedMulticastTunnel};
use nextgcore_ngap_gen::generated as g;

/// `MBS-DistributionSetupResponseTransfer` (§9.3.5.8) as mbsmfd builds it.
///
/// - `20`: ext `0`; presence area `0`, multicast TNL `1`, service area `0`,
///   iE-Extensions `0`; MBS-SessionID ext `0`, NID `0`, iE-Extensions `0`.
/// - TMGI, six octets.
/// - SharedNGU-MulticastTNLInformation: ext `0`, iE-Extensions `0`, then the
///   multicast address `0 00011111` -> `03 e0` and its four octets; the source
///   address `0 00011111` -> `0f 80` and its four octets; the TEID.
/// - MBS-QoSFlowsToBeSetupList: count-1 in 6 bits (1..64) `000000`, item ext
///   and iE-Extensions `00` -> `00`. QosFlowIdentifier `INTEGER (0..63, ...)`
///   ext `0` + six bits, QosFlowLevelQosParameters ext `0` -> `qfi << 1`.
///   Presence gBR/reflective/additional/iE-Ext `0000`, QosCharacteristics
///   CHOICE of three (not extensible) nonDynamic5QI `00`, NonDynamic5QI ext
///   `0`, presence `0000`, FiveQI `INTEGER (0..255, ...)` ext `0`, padded ->
///   `00 00`; then the 5QI in one aligned octet (range 256, §11.5.7.2).
/// - AllocationAndRetentionPriority ext `0`, iE-Ext `0`; PriorityLevelARP
///   `INTEGER (1..15)` 8 -> `0111`; Pre-emptionCapability ext `0`
///   shall-not-trigger `0`; Pre-emptionVulnerability ext `0` not-pre-emptable
///   `0`; MBSSessionStatus ext `0` activated `0` -> `0001 1100 0000` padded ->
///   `1c 00`.
pub(crate) fn setup_response_octets(
    (plmn, service): NgapTmgi,
    tunnel: SharedMulticastTunnel,
    qfi: u8,
    five_qi: u8,
) -> Vec<u8> {
    let mut o = vec![0x20];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o.extend_from_slice(&[0x03, 0xe0]);
    o.extend_from_slice(&tunnel.multicast_address);
    o.extend_from_slice(&[0x0f, 0x80]);
    o.extend_from_slice(&tunnel.source_address);
    o.extend_from_slice(&tunnel.teid.to_be_bytes());
    o.extend_from_slice(&[0x00, qfi << 1, 0x00, 0x00, five_qi, 0x1c, 0x00]);
    o
}

/// `MBS-DistributionSetupUnsuccessfulTransfer` (§9.3.5.9) with Cause
/// transport/transport-resource-unavailable.
///
/// - `00`: ext `0`; presence area `0`, criticality diagnostics `0`,
///   iE-Extensions `0`; MBS-SessionID `000`; padded.
/// - TMGI, six octets.
/// - Cause: CHOICE of six, not extensible, transport = index 1 `001`;
///   CauseTransport ext `0`, transport-resource-unavailable `0` -> `20`.
pub(crate) fn setup_unsuccessful_octets((plmn, service): NgapTmgi) -> Vec<u8> {
    let mut o = vec![0x00];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o.push(0x20);
    o
}

/// `MBS-DistributionSetupRequestTransfer` (§9.3.5.7), no optional members:
/// `00` (ext, three presence bits, MBS-SessionID `000`, padded), then the
/// TMGI.
pub(crate) fn setup_request_minimal_octets((plmn, service): NgapTmgi) -> Vec<u8> {
    let mut o = vec![0x00];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o
}

/// `MBS-DistributionSetupRequestTransfer` with an MBS Area Session ID and a
/// shared NG-U unicast GTP tunnel:
///
/// - `60`: ext `0`, area `1`, tunnel `1`, iE-Ext `0`; MBS-SessionID `000`;
///   padded.
/// - TMGI; MBS-AreaSessionID ext `0`, padded -> `00`, then the area ID in two
///   aligned octets.
/// - UPTransportLayerInformation CHOICE of two (not extensible) gTPTunnel
///   `0`, GTPTunnel ext `0` iE-Ext `0`, address `0 00011111`, padded ->
///   `01 f0`; the address; the TEID.
pub(crate) fn setup_request_area_tunnel_octets(
    (plmn, service): NgapTmgi,
    area: u16,
    address: [u8; 4],
    teid: u32,
) -> Vec<u8> {
    let mut o = vec![0x60];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o.push(0x00);
    o.extend_from_slice(&area.to_be_bytes());
    o.extend_from_slice(&[0x01, 0xf0]);
    o.extend_from_slice(&address);
    o.extend_from_slice(&teid.to_be_bytes());
    o
}

/// `MBS-DistributionSetupRequestTransfer` whose MBS-SessionID carries a NID,
/// with an area ID 1 and the tunnel 10.1.2.3 / 0x3039:
///
/// - `64`: ext `0`, area `1`, tunnel `1`, iE-Ext `0`; MBS-SessionID ext `0`,
///   NID `1`, iE-Ext `0`; padded.
/// - TMGI; NID `0x123456789ab`, 44 bits aligned: `12 34 56 78 9a b`, then
///   MBS-AreaSessionID ext `0` in the same octet, padded -> `b0`; area `00 01`.
/// - The tunnel as in [`setup_request_area_tunnel_octets`].
pub(crate) const NID: u64 = 0x123_4567_89ab;
pub(crate) fn setup_request_with_nid_octets((plmn, service): NgapTmgi) -> Vec<u8> {
    let mut o = vec![0x64];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xb0, 0x00, 0x01]);
    o.extend_from_slice(&[0x01, 0xf0, 0x0a, 0x01, 0x02, 0x03, 0x00, 0x00, 0x30, 0x39]);
    o
}

/// `MBS-DistributionSetupRequestTransfer` with one protocol extension, id
/// `id` and criticality `criticality` (0 reject, 1 ignore, 2 notify), whose
/// value is the one octet `00`:
///
/// - `10`: ext `0`, area `0`, tunnel `0`, iE-Ext `1`; MBS-SessionID `000`;
///   padded. TMGI.
/// - ProtocolExtensionContainer `SEQUENCE (SIZE(1..65535))`: count-1 in two
///   aligned octets `00 00`; the field's id `INTEGER (0..65535)` in two
///   aligned octets; criticality, two bits, padded; the open type: length
///   `01`, value `00`.
///
/// V17.9 defines no extension for this transfer (its ExtIEs set is empty), so
/// every id is unknown to it -- including 441, the Rel-19 TAI MBS Support
/// List.
pub(crate) fn setup_request_with_extension_octets(
    (plmn, service): NgapTmgi,
    id: u16,
    criticality: u8,
) -> Vec<u8> {
    let mut o = vec![0x10];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o.extend_from_slice(&[0x00, 0x00]);
    o.extend_from_slice(&id.to_be_bytes());
    o.extend_from_slice(&[criticality << 6, 0x01, 0x00]);
    o
}

/// The Cause octet of a release request whose Cause is the last member and
/// starts on an octet boundary: CHOICE of six (not extensible) index in three
/// bits, then the ENUMERATED's extension bit and its root index, padded.
///
/// - nas/normal-release: `010 0 00` -> `40`; nas/unspecified (3 of 4):
///   `010 0 11` -> `4c`;
/// - transport/transport-resource-unavailable: `001 0 0` -> `20`;
///   transport/unspecified: `001 0 1` -> `28`;
/// - misc/unspecified (5 of 6): `100 0 101` -> `8a`.
pub(crate) const RELEASE_CAUSE_OCTETS: [u8; 5] = [0x40, 0x4c, 0x20, 0x28, 0x8a];

/// `MBS-DistributionReleaseRequestTransfer` (§9.3.5.10) with no area and no
/// tunnel: `00` (ext, three presence bits, MBS-SessionID `000`, padded), the
/// TMGI, then the Cause octet.
pub(crate) fn release_request_minimal_octets(
    (plmn, service): NgapTmgi,
    cause_octet: u8,
) -> Vec<u8> {
    let mut o = vec![0x00];
    o.extend_from_slice(&plmn);
    o.extend_from_slice(&service);
    o.push(cause_octet);
    o
}

/// `MBS-DistributionReleaseRequestTransfer` with an area ID and a tunnel:
/// `60` as in [`setup_request_area_tunnel_octets`] (the presence bits
/// line up: area, tunnel, iE-Ext), TMGI, `00` area, `01 f0`, address, TEID -- which
/// ends on an octet boundary -- then the Cause octet.
pub(crate) fn release_request_area_tunnel_octets(
    tmgi: NgapTmgi,
    area: u16,
    address: [u8; 4],
    teid: u32,
    cause_octet: u8,
) -> Vec<u8> {
    let mut o = setup_request_area_tunnel_octets(tmgi, area, address, teid);
    o.push(cause_octet);
    o
}

/// What a test reads back out of an MBS-DistributionSetupResponseTransfer, by
/// the generated codec's strict decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupResponse {
    pub tmgi: NgapTmgi,
    pub tunnel: Option<SharedMulticastTunnel>,
    pub qfis: Vec<u8>,
    pub activated: bool,
}

fn ipv4(address: &g::TransportLayerAddress) -> [u8; 4] {
    address
        .0
        .as_raw_slice()
        .try_into()
        .expect("a 32-bit IPv4 address")
}

/// Decode a Setup Response Transfer with the generated codec (strict: no
/// unknown extension is skipped).
pub(crate) fn decode_setup_response(bytes: &[u8]) -> Result<SetupResponse, String> {
    let t = nextgcore_ngap_gen::decode_contained::<g::MBS_DistributionSetupResponseTransfer>(bytes)
        .map_err(|e| format!("{e:?}"))?;
    let tmgi = super::tmgi_of("MBS-DistributionSetupResponseTransfer", &t.mbs_session_id)
        .map_err(|e| e.to_string())?;
    Ok(SetupResponse {
        tmgi,
        tunnel: t
            .shared_ngu_multicast_tnl_information
            .as_ref()
            .map(|m| SharedMulticastTunnel {
                multicast_address: ipv4(&m.ip_multicast_address),
                source_address: ipv4(&m.ip_source_address),
                teid: u32::from_be_bytes(m.gtp_teid.0[..].try_into().expect("4 octets")),
            }),
        qfis: t
            .mbs_qo_s_flows_to_be_setup_list
            .0
            .iter()
            .map(|f| f.mb_sqos_flow_identifier.0)
            .collect(),
        activated: t.mbs_session_status.0 == g::MBSSessionStatus::ACTIVATED,
    })
}
