//! G1-3 — Strict-peer round-trip: conformant AMF-side client harness vs the
//! live mbsmfd ContextUpdate handler (TS 29.532 §5.3.2.5, figure 5.3.2.5.1-1,
//! AMF as NF Service Consumer; TS 38.413 §9.3.5.7/§9.3.5.8/§9.3.5.10).
//!
//! The conformant peer here is an INDEPENDENT AMF-side client: it builds the
//! `Nmbsmf_MBSSession` ContextUpdate request purely from raw serde_json (field
//! names typed from `specs/TS29532_Nmbsmf_MBSSession.yaml`) plus hand-derived
//! golden NGAP transfer-container bytes, assembled/decoded via the shared
//! `nextgcore_sbi::multipart` wire codec — it NEVER reuses `crate::types` (the
//! mbsmfd SBI wire types) to encode or decode the request. amfd has no Nmbsmf
//! client in-tree (verified: zero `nmbsmf` hits in amfd), so this yaml-driven
//! test client is the conformant peer, avoiding the lenient-mock trap.
//!
//! The response is decoded with the shared `nextgcore_ngap` NGAP codec AND its
//! first bytes are independently asserted against a hand-derived golden prefix,
//! so an encoder+decoder pair sharing the same bug cannot pass. Flipping one
//! byte in the golden request container makes mbsmfd fail-closed (4xx), proving
//! real APER decoding rather than pass-through.
//!
//! mbsmfd is a bin-only crate, so its real handler `mbsmf_sbi_request_handler`
//! is reachable only from within the crate; this in-crate `#[cfg(test)]` module
//! drives that real handler in-process while keeping request construction fully
//! independent of `crate::types`.

use bytes::Bytes;
use nextgcore_ngap::mbs_transfer::{MbsDistributionSetupResponseTransfer, MbsSessionStatus};
use nextgcore_sbi::constants::content_type::APPLICATION_NGAP;
use nextgcore_sbi::message::{SbiPart, SbiRequest, SbiResponse};
use nextgcore_sbi::multipart;

// The single Nmbsmf_MBSSession ContextUpdate route under test.
const ROUTE: &str = "/nmbsmf-mbssession/v1/mbs-sessions/contexts/update";

// Every golden container below carries TMGI PLMN 208/93 (BCD `02 F8 39` per
// TS 24.008 §10.5.1.3) so the shared prefix is reviewer-rederivable; each test
// uses a distinct 3-octet MBS Service ID to isolate its session in the global
// context (`session_add` keys on the full TMGI).

/// §9.3.5.7 MBS-DistributionSetupRequestTransfer, minimal (no area, no
/// unicast-TNL, no iE-Extensions). Hand-derived per X.691 aligned PER:
///   bit0    SEQUENCE ext            = 0
///   bit1    mBS-AreaSessionID pres  = 0
///   bit2    sharedNGU-UnicastTNL    = 0
///   bit3    iE-Extensions present   = 0
///   bits4-6 MBS-SessionID preamble (ext,nid,iE-ext) = 000
///   bit7    TMGI OCTET STRING(6) align pad          = 0   => byte0 = 0x00
///   bytes1-6 TMGI = 02 F8 39 <svc0> <svc1> <svc2>
fn golden_setup_req(svc: [u8; 3]) -> [u8; 7] {
    [0x00, 0x02, 0xF8, 0x39, svc[0], svc[1], svc[2]]
}

/// §9.3.5.10 MBS-DistributionReleaseRequestTransfer, no area, no TNL, cause =
/// nas:normal-release(0). Same MBS-SessionID prefix as the setup vector:
///   byte0    = 0x00 (all-absent preamble + MBS-SessionID preamble + pad)
///   bytes1-6 = TMGI 02 F8 39 <svc0> <svc1> <svc2>
///   byte7    = Cause: CHOICE nas = index 2 of 6 (3 bits) = 010; CauseNas ENUM
///              ext=0 (1 bit); value normal-release(0) in 2 bits = 00; align
///              pad 00 => 0100 0000 = 0x40
fn golden_rel_req(svc: [u8; 3]) -> [u8; 8] {
    [0x00, 0x02, 0xF8, 0x39, svc[0], svc[1], svc[2], 0x40]
}

/// §9.3.5.8 MBS-DistributionSetupResponseTransfer SEQUENCE preamble + TMGI
/// (the leading bytes that do NOT depend on the session's dynamic N4mb
/// transport), hand-derived per X.691:
///   bit0 ext=0, bit1 area=0, bit2 multicast-TNL present=1, bit3 svcArea=0,
///   bit4 iE-Ext=0; bits5-7 MBS-SessionID preamble 000 => byte0 = 0x20
///   bytes1-6 TMGI = 02 F8 39 <svc0> <svc1> <svc2>
fn golden_rsp_prefix(svc: [u8; 3]) -> [u8; 7] {
    [0x20, 0x02, 0xF8, 0x39, svc[0], svc[1], svc[2]]
}

/// Pre-create a multicast MBS session in the global context keyed by TMGI
/// PLMN 208/93 + `svc`. Session fixture setup only — uses the crate's context
/// API (`crate::Tmgi`/`crate::PlmnId`/`crate::MbsSessionType`), NOT the
/// `crate::types` SBI wire types.
fn seed_session(svc: [u8; 3]) {
    crate::mbsmf_context_init(256);
    let tmgi = crate::Tmgi {
        mbs_service_id: svc,
        plmn_id: crate::PlmnId {
            mcc: "208".to_string(),
            mnc: "93".to_string(),
        },
    };
    let ctx = crate::mbsmf_self();
    let guard = ctx.read().expect("context read");
    guard
        .session_add(tmgi, crate::MbsSessionType::Multicast)
        .expect("session added");
}

/// The stored session's downlink C-TEID for a given MBS Service ID, or None if
/// no shared N4mb transport is established. Context API only.
fn session_c_teid(svc: [u8; 3]) -> Option<u32> {
    let tmgi = crate::Tmgi {
        mbs_service_id: svc,
        plmn_id: crate::PlmnId {
            mcc: "208".to_string(),
            mnc: "93".to_string(),
        },
    };
    let ctx = crate::mbsmf_self();
    let guard = ctx.read().expect("context read");
    let session = guard.session_find_by_tmgi(&tmgi)?;
    session.n4mb_session.as_ref().map(|n| n.dl_teid)
}

/// Whether the stored session still has an established shared N4mb transport.
fn session_transport_present(svc: [u8; 3]) -> bool {
    session_c_teid(svc).is_some()
}

/// Build a spec-shaped `ContextUpdateReqData` JSON body (field names typed
/// from TS29532_Nmbsmf_MBSSession.yaml) carrying an `n2MbsSmInfo` that
/// references `content_id`. No `crate::types` involved.
fn amf_ctx_update_json(svc_hex: &str, ngap_ie_type: &str, content_id: &str) -> String {
    format!(
        r#"{{"nfcInstanceId":"amf-strict-peer","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc_hex}","plmnId":{{"mcc":"208","mnc":"93"}}}}}},"ranNodeId":{{"gNbId":{{"bitLength":24,"gNBValue":"000001"}}}},"n2MbsSmInfo":{{"ngapIeType":"{ngap_ie_type}","ngapData":{{"contentId":"{content_id}"}}}}}}"#
    )
}

/// Conformant AMF peer → live mbsmfd, over the real multipart/related wire
/// codec: assemble the request via `multipart::encode` (what the AMF emits),
/// decode it via `multipart::decode` (what mbsmfd's SBI server does inbound,
/// server.rs:570-592), then drive the real handler.
async fn amf_post_multipart(json: &str, content_id: &str, ngap_bytes: &[u8]) -> SbiResponse {
    let part = SbiPart::with_content(
        content_id,
        APPLICATION_NGAP,
        Bytes::copy_from_slice(ngap_bytes),
    );
    let boundary = multipart::generate_boundary();
    // AMF client emits multipart/related on the wire.
    let wire = multipart::encode(Some(json), std::slice::from_ref(&part), &boundary);
    let ct = multipart::content_type_with_boundary(&boundary);
    // mbsmfd's SBI server decodes the inbound multipart into content + parts.
    let decoded = multipart::decode(&ct, &wire).expect("inbound multipart decodes");
    let mut req = SbiRequest::post(ROUTE);
    req.http.set_header("Content-Type", ct);
    req.http.content = decoded.json;
    for p in decoded.parts {
        req.http.add_part(p);
    }
    crate::mbsmf_sbi_request_handler(req).await
}

/// AMF peer decodes an mbsmfd 200 multipart/related response: re-encode the
/// handler's `content` + `parts` exactly as the SBI server egress would
/// (server.rs:685-695), then decode as the AMF client. Returns the JSON root
/// (as a generic `serde_json::Value`, never `crate::types`) and the parts.
fn amf_decode_response(rsp: &SbiResponse) -> (serde_json::Value, Vec<SbiPart>) {
    assert!(
        !rsp.http.parts.is_empty(),
        "a 200 ContextUpdate response must carry a binary N2 part"
    );
    let boundary = multipart::generate_boundary();
    let wire = multipart::encode(rsp.http.content.as_deref(), &rsp.http.parts, &boundary);
    let ct = multipart::content_type_with_boundary(&boundary);
    let decoded = multipart::decode(&ct, &wire).expect("response multipart decodes");
    let json_val: serde_json::Value =
        serde_json::from_str(&decoded.json.expect("response JSON root")).expect("valid JSON root");
    (json_val, decoded.parts)
}

// ---------------------------------------------------------------------------
// The strict-peer round-trip (falsifiable acceptance name:
// `mbs_context_update_strict_peer`).
// ---------------------------------------------------------------------------

/// Inbound multipart MBS_DIS_SETUP_REQ (independent golden §9.3.5.7 bytes)
/// → 200 multipart whose part is a §9.3.5.8 Setup Response Transfer with the
/// session's real N4mb transport, and whose JSON says MBS_DIS_SETUP_RSP.
#[tokio::test]
async fn mbs_context_update_strict_peer_setup_roundtrip() {
    const SVC: [u8; 3] = [0x00, 0x00, 0xA3];
    seed_session(SVC);

    // Conformant AMF peer request: raw JSON + hand-derived golden §9.3.5.7.
    let json = amf_ctx_update_json("0000a3", "MBS_DIS_SETUP_REQ", "binaryDataN2Information");
    let rsp = amf_post_multipart(&json, "binaryDataN2Information", &golden_setup_req(SVC)).await;
    assert_eq!(rsp.status, 200, "strict-peer setup leg → 200 multipart");

    // AMF peer decodes the response multipart/related.
    let (json_val, parts) = amf_decode_response(&rsp);
    assert_eq!(
        json_val["n2MbsSmInfo"]["ngapIeType"].as_str(),
        Some("MBS_DIS_SETUP_RSP"),
        "response direction is MBS_DIS_SETUP_RSP (never *_REQ)"
    );
    let cid = json_val["n2MbsSmInfo"]["ngapData"]["contentId"]
        .as_str()
        .expect("response references a contentId");
    let part = parts
        .iter()
        .find(|p| p.content_id.as_deref() == Some(cid))
        .expect("contentId resolves to a body part (no dangling RefToBinaryData)");
    assert_eq!(
        part.content_type.as_deref(),
        Some(APPLICATION_NGAP),
        "N2 part is application/vnd.3gpp.ngap"
    );

    // (Independent guard) assert the golden §9.3.5.8 prefix on the raw bytes —
    // NOT via any encoder — so an encoder+decoder pair sharing a bug can't pass.
    assert_eq!(
        &part.data[..7],
        &golden_rsp_prefix(SVC),
        "§9.3.5.8 golden prefix (SEQUENCE preamble + TMGI)"
    );

    // Decode with the shared NGAP codec and cross-check the session's real
    // N4mb transport (the C-TEID the SMF/JSON path would report).
    let decoded = MbsDistributionSetupResponseTransfer::decode(&part.data)
        .expect("part decodes as §9.3.5.8 Setup Response Transfer");
    assert_eq!(decoded.mbs_session_id.plmn_identity, [0x02, 0xF8, 0x39]);
    assert_eq!(decoded.mbs_session_id.mbs_service_id, SVC);
    assert_eq!(decoded.mbs_session_status, MbsSessionStatus::Activated);
    let tnl = decoded
        .shared_ngu_multicast_tnl_information
        .expect("Shared NG-U Multicast TNL present");
    let c_teid = session_c_teid(SVC).expect("session established a shared N4mb transport");
    assert_eq!(
        u32::from_be_bytes(tnl.gtp_teid),
        c_teid,
        "decoded SharedNguMulticastTnl gtp_teid == the session's real cTeid"
    );
    assert_eq!(
        decoded.mbs_qos_flows_to_be_setup_list.len(),
        1,
        "single QoS flow derived from the session model"
    );
}

/// Falsifiability: flip ONE byte in the golden request container and the same
/// strict peer now gets 4xx (fail-closed) — proves real APER decoding rather
/// than pass-through of the JSON stub.
#[tokio::test]
async fn mbs_context_update_strict_peer_corrupt_container_4xx() {
    const SVC: [u8; 3] = [0x00, 0x00, 0xB4];
    seed_session(SVC);

    let mut container = golden_setup_req(SVC);
    // Flip bit3 of byte0: sets iE-Extensions-present on the SetupRequestTransfer
    // SEQUENCE, so the decoder expects a ProtocolExtensionContainer after the
    // TMGI that is not there → truncation → NgapError (never a default struct).
    container[0] ^= 0x10;

    let json = amf_ctx_update_json("0000b4", "MBS_DIS_SETUP_REQ", "binaryDataN2Information");
    let rsp = amf_post_multipart(&json, "binaryDataN2Information", &container).await;

    assert_ne!(
        rsp.status, 200,
        "corrupt container must NOT pass through as 200"
    );
    assert!(
        (400..600).contains(&rsp.status),
        "corrupt container is fail-closed (4xx/5xx), got {}",
        rsp.status
    );
    assert!(
        rsp.http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("INVALID_MSG_FORMAT"),
        "ProblemDetails carries an INVALID_MSG_FORMAT cause"
    );
}

/// Negative peer: a sloppy AMF consumer sends JSON-only (no multipart part)
/// but references a contentId → fail-closed 400 (never a silent JSON-only 200).
#[tokio::test]
async fn mbs_context_update_strict_peer_json_only_dangling_400() {
    const SVC: [u8; 3] = [0x00, 0x00, 0xD6];
    seed_session(SVC);

    let json = amf_ctx_update_json("0000d6", "MBS_DIS_SETUP_REQ", "binaryDataN2Information");
    // No `.with_part(...)`: the referenced contentId has no body part.
    let rsp = crate::mbsmf_sbi_request_handler(
        SbiRequest::post(ROUTE).with_body(json, "application/json"),
    )
    .await;

    assert_eq!(rsp.status, 400, "dangling contentId is fail-closed");
    assert!(
        rsp.http
            .content
            .as_deref()
            .unwrap_or("")
            .contains("MANDATORY_IE_INCORRECT"),
        "ProblemDetails carries a MANDATORY_IE_INCORRECT cause"
    );
}

/// Release leg: MBS_DIS_REL_REQ golden §9.3.5.10 bytes → 204 (spec step 2b:
/// nothing to return) and the session's shared transport is released.
#[tokio::test]
async fn mbs_context_update_strict_peer_release_204() {
    const SVC: [u8; 3] = [0x00, 0x00, 0xC5];
    seed_session(SVC);

    // Establish shared delivery first (setup leg) so there is a transport to
    // release.
    let setup_json = amf_ctx_update_json("0000c5", "MBS_DIS_SETUP_REQ", "binaryDataN2Information");
    let setup_rsp = amf_post_multipart(
        &setup_json,
        "binaryDataN2Information",
        &golden_setup_req(SVC),
    )
    .await;
    assert_eq!(setup_rsp.status, 200, "setup leg established");
    assert!(
        session_transport_present(SVC),
        "shared N4mb transport established by the setup leg"
    );

    // Release with the hand-derived §9.3.5.10 container.
    let rel_json = amf_ctx_update_json("0000c5", "MBS_DIS_REL_REQ", "binaryDataN2Information");
    let rel_rsp =
        amf_post_multipart(&rel_json, "binaryDataN2Information", &golden_rel_req(SVC)).await;
    assert_eq!(rel_rsp.status, 204, "release leg → 204 (nothing to return)");

    assert!(
        !session_transport_present(SVC),
        "shared transport released by MBS_DIS_REL_REQ"
    );
}
