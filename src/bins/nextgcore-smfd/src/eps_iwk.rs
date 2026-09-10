//! 5GS↔EPS interworking: EBI assignment over Namf_Communication (issue #117).
//!
//! TS 23.502 §4.11.1.4.1: a PDU session that may be moved to the EPC needs an EPS
//! Bearer Identity per QoS flow, and the **AMF** owns that identity space. The SMF
//! asks for one with `Namf_Communication_EBIAssignment`
//! (`POST /namf-comm/v1/ue-contexts/{ueContextId}/assign-ebi`, TS 29.518
//! §6.1.6.2.5), supplying the flow's ARP, and stores what comes back so the
//! Mapped EPS bearer contexts IE can name it to the UE.
//!
//! # Why this module exists
//!
//! Nothing in the workspace performed this operation: `grep` for `assign-ebi`
//! across `src/` returned nothing on either side, so `SmfBearer.ebi` was written
//! **only** by the EPC GTPv2 path (`gtp_handler.rs`) — i.e. only for a session
//! that had already been established from the EPC side. In the 5GC-first
//! interworking flow the two sides had no way to agree on bearer identities, so no
//! PDU session could be transferred to EPS.
//!
//! # A runtime switch, not a cargo feature
//!
//! #117 suggests `eps-interworking` as a cargo feature. This uses a runtime
//! switch (`SMF_EPS_INTERWORKING=1`, default **off** — this daemon has no clap
//! `Args` struct, so every switch is an env var) for the
//! reason recorded in this project and applied the same way by the EASDF leg
//! (#114): CI builds default features, so a cargo-feature-gated path is left
//! **uncompiled** and rots. A runtime switch is compiled always and exercised in
//! *both* states by one `cargo test` run — which is what makes #117's criterion 5
//! ("with interworking disabled, behaviour is unchanged") a thing a test can
//! assert rather than a claim about a build that CI never performs.
//!
//! Contrast #276, which *is* a cargo feature: that one binds a privileged port and
//! changes the process's network posture. This one changes which IEs an N1 message
//! carries. The distinction is the network posture, not the fact of being optional.
//!
//! # Failure posture
//!
//! Every failure here is **non-fatal to the session**. A session that could not
//! get an EBI is a working 5G session that cannot be moved to EPS; refusing it
//! would turn an interworking hiccup into a total service outage for the DNN.
//! Failures are logged with that consequence named.

use std::sync::atomic::{AtomicBool, Ordering};

/// Is the interworking leg enabled for this process?
static EPS_IWK_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable the leg (called once at startup).
pub fn enable() {
    EPS_IWK_ENABLED.store(true, Ordering::SeqCst);
    log::info!(
        "[SMF] 5GS↔EPS interworking ENABLED: PDU sessions will request an EBI from \
         the AMF and carry Mapped EPS bearer contexts (TS 23.502 §4.11.1.4.1)"
    );
}

/// Whether the leg is enabled.
pub fn enabled() -> bool {
    EPS_IWK_ENABLED.load(Ordering::SeqCst)
}

/// Serialises every test that touches the process-global switch.
///
/// Public within the crate because `main.rs`'s tests toggle the same variable; a
/// lock private to this module would be a second disjoint agreement about one
/// variable, which is the collision shape this repo keeps recording (and which
/// #276 hit as a hang rather than a flake).
#[cfg(test)]
pub static SWITCH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Test-only: set the switch without going through startup.
#[cfg(test)]
pub fn set_for_test(on: bool) {
    EPS_IWK_ENABLED.store(on, Ordering::SeqCst);
}

/// The ARP this SMF supplies for a session's default QoS flow.
///
/// `preemptCap` / `preemptVuln` are the conservative pair: a default flow that
/// cannot pre-empt others and can itself be pre-empted. Chosen rather than derived
/// because the policy decision this tree makes carries only an ARP **priority
/// level** (`decision.arp_priority_level`) and no pre-emption members, and the two
/// are `required` in TS 29.571's `Arp` — so they have to come from somewhere, and a
/// stated conservative default is better than a value invented per call.
pub fn default_flow_arp(priority_level: u8) -> serde_json::Value {
    serde_json::json!({
        // ArpPriorityLevel is 1..=15; clamp rather than send an out-of-range value
        // the AMF would (correctly) refuse with a 400.
        "priorityLevel": priority_level.clamp(1, 15),
        "preemptCap": "NOT_PREEMPT",
        "preemptVuln": "PREEMPTABLE",
    })
}

/// Request one EBI for a session's default QoS flow.
///
/// Returns the assigned EBI, or `None` when the leg is off, the AMF is unknown or
/// unreachable, it refused, or it had none left. `None` always means "this session
/// proceeds without EPS interworking", never "fail the session".
///
/// `amf_uri` is the AMF's callback root, which is the only address the SMF has for
/// it — the same source `send_n1_n2_message_transfer` uses. A create request that
/// carried no `smContextStatusUri` therefore cannot get an EBI, and says so.
pub async fn request_ebi(
    amf_uri: Option<&str>,
    supi: &str,
    pdu_session_id: u8,
    arp_priority_level: u8,
) -> Option<u8> {
    if !enabled() {
        return None;
    }
    let Some(amf_uri) = amf_uri else {
        log::warn!(
            "[{supi}] EPS interworking is on but the AMF supplied no callback URI: \
             no EBI can be requested for PSI {pdu_session_id}, so this session \
             cannot be moved to EPS"
        );
        return None;
    };
    let Some((host, port)) = crate::policy::split_host_port(amf_uri) else {
        log::warn!("[{supi}] AMF URI '{amf_uri}' is not a valid URI: no EBI requested");
        return None;
    };

    let body = serde_json::json!({
        "pduSessionId": pdu_session_id,
        // One ARP entry, so one EBI: this SMF authorises a single default QoS flow
        // per session on the live path, and asking for more than it has flows for
        // would burn identities out of an eleven-wide per-UE space.
        "arpList": [default_flow_arp(arp_priority_level)],
    });

    let path = format!("/namf-comm/v1/ue-contexts/{supi}/assign-ebi");
    let request = nextgcore_sbi::message::SbiRequest::post(&path).with_body(
        body.to_string(),
        nextgcore_sbi::constants::content_type::APPLICATION_JSON,
    );
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&host, port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );

    let response = match client.send_request(request).await {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!(
                "[{supi}] EBI assignment to {host}:{port} failed: {e}. The session \
                 proceeds without EPS interworking."
            );
            return None;
        }
    };
    if response.status != 200 {
        log::warn!(
            "[{supi}] AMF refused EBI assignment for PSI {pdu_session_id}: status={}. \
             The session proceeds without EPS interworking.",
            response.status
        );
        return None;
    }

    parse_assigned_ebi(response.http.content.as_deref().unwrap_or_default()).or_else(|| {
        log::warn!(
            "[{supi}] AMF answered 200 to EBI assignment for PSI {pdu_session_id} but \
             `assignedEbiList` named no usable EPS bearer identity"
        );
        None
    })
}

/// Pull the first usable EBI out of an `AssignedEbiData` body.
///
/// Separated from the request so the parse is testable against the shapes a
/// conformant AMF may send, including the empty `assignedEbiList` that
/// `minItems: 0` permits and that means "none was assigned".
///
/// An EBI outside 5..=15 is REFUSED rather than stored: TS 24.301 §9.3.2 reserves
/// 0..=4, and putting a reserved identity into a Mapped EPS bearer contexts IE
/// would tell the UE to build a bearer on it.
pub fn parse_assigned_ebi(body: &str) -> Option<u8> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    parsed
        .get("assignedEbiList")?
        .as_array()?
        .iter()
        .filter_map(|entry| entry.get("epsBearerId").and_then(serde_json::Value::as_u64))
        .find_map(|ebi| {
            let ebi = u8::try_from(ebi).ok()?;
            if (5..=15).contains(&ebi) {
                Some(ebi)
            } else {
                log::warn!(
                    "AMF assigned EPS bearer identity {ebi}, which TS 24.301 §9.3.2 \
                     reserves; ignoring it"
                );
                None
            }
        })
}

/// Record an assigned EBI on a QoS flow for `sess_id` (#117).
///
/// `SmfBearer.ebi` is where `gsm_build::encode_mapped_eps_bearer_context` reads the
/// identity from, and until #117 the ONLY writer of that field was the EPC GTPv2
/// path (`gtp_handler.rs`) — so an EBI could exist for a session established from
/// the EPC side and never for a 5GC-first one. This is the Namf writer the issue
/// asks for.
///
/// A QoS flow is created **only** when an EBI was assigned. `qos_flow_add` has no
/// other production caller (the live 5G path carries its QoS on the session and the
/// policy binding), so creating one unconditionally would populate a store nothing
/// reads and change what `max_num_of_bearer` means for every session in the process.
///
/// A separate function rather than an inline block because the SM-context create
/// path cannot be driven past its N4 leg by any test in this crate (no UPF
/// stand-in — issue #289), so an inline block would be unreachable from a test.
/// This seam is the reachable half; the call site itself is covered by inspection,
/// and that limitation is stated rather than implied.
pub fn record_mapped_eps_bearer(
    sess_id: u64,
    ebi: u8,
    qfi: u8,
    five_qi: u8,
    arp_priority_level: u8,
    supi: &str,
) -> Option<u64> {
    let ctx = crate::context::smf_self();
    let context = ctx.read().ok()?;
    match context.qos_flow_add(sess_id) {
        Some(mut flow) => {
            flow.ebi = ebi;
            flow.qfi = qfi;
            flow.qos.index = five_qi;
            flow.qos.arp_priority_level = arp_priority_level;
            let id = flow.id;
            context.bearer_update(&flow);
            log::info!(
                "[{supi}] EPS bearer {ebi} mapped onto QoS flow QFI {qfi} (5QI {five_qi}) for session {sess_id}"
            );
            Some(id)
        }
        None => {
            log::warn!(
                "[{supi}] EBI {ebi} was assigned but no QoS flow could be stored (bearer table full): the session cannot be moved to EPS"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leg_is_off_by_default() {
        // Not under the lock on purpose: this asserts the STATIC initialiser, and
        // taking the lock would not protect it from a sibling that has already
        // enabled the switch. Read as documentation of the default; the
        // behavioural guard is `request_ebi` returning None when disabled, below.
        assert!(!EPS_IWK_ENABLED.load(Ordering::SeqCst) || enabled());
    }

    #[tokio::test]
    async fn a_disabled_leg_dials_nothing() {
        let _g = SWITCH_LOCK.lock().await;
        set_for_test(false);
        // A URI that would fail loudly if it were dialled at all.
        assert_eq!(
            request_ebi(Some("http://127.0.0.1:1"), "imsi-1", 5, 8).await,
            None
        );
    }

    /// The parse accepts what a conformant AMF sends and refuses a reserved EBI.
    ///
    /// The reserved case is the one worth having: an AMF answering `epsBearerId: 0`
    /// is answering "none assigned" in the shape of an assignment, and storing it
    /// would put EBI 0 into a Mapped EPS bearer contexts IE.
    #[test]
    fn parse_assigned_ebi_takes_the_first_usable_identity() {
        assert_eq!(
            parse_assigned_ebi(
                r#"{"pduSessionId":5,"assignedEbiList":[{"epsBearerId":7,"arp":{"priorityLevel":8}}]}"#
            ),
            Some(7)
        );
        // minItems: 0 -- an empty list is legal and means none was assigned.
        assert_eq!(
            parse_assigned_ebi(r#"{"pduSessionId":5,"assignedEbiList":[]}"#),
            None
        );
        // Reserved identities are skipped, and a usable later entry still wins.
        assert_eq!(
            parse_assigned_ebi(
                r#"{"assignedEbiList":[{"epsBearerId":0},{"epsBearerId":4},{"epsBearerId":5}]}"#
            ),
            Some(5)
        );
        assert_eq!(
            parse_assigned_ebi(r#"{"assignedEbiList":[{"epsBearerId":16}]}"#),
            None,
            "16 is outside the EpsBearerId range and must not be stored"
        );
        assert_eq!(parse_assigned_ebi("not json"), None);
        assert_eq!(parse_assigned_ebi(r#"{"pduSessionId":5}"#), None);
    }

    /// The ARP this SMF sends carries all three members `Arp` declares required,
    /// and clamps the priority level into the range the schema allows.
    #[test]
    fn the_default_flow_arp_is_schema_complete_and_clamped() {
        let arp = default_flow_arp(8);
        for required in ["priorityLevel", "preemptCap", "preemptVuln"] {
            assert!(
                arp.get(required).is_some(),
                "Arp.{required} is required by TS 29.571"
            );
        }
        assert_eq!(arp["priorityLevel"], serde_json::json!(8));
        assert_eq!(
            default_flow_arp(0)["priorityLevel"],
            serde_json::json!(1),
            "0 is outside ArpPriorityLevel 1..=15 and must be clamped, not sent"
        );
        assert_eq!(
            default_flow_arp(200)["priorityLevel"],
            serde_json::json!(15)
        );
    }
    /// #117 criterion 2, the wire half: the SMF actually performs
    /// `Namf_Communication_EBIAssignment`, against a loopback AMF that records the
    /// request.
    ///
    /// The recorded `(path, body)` is the assertion, not just the returned EBI: a
    /// test that checked only the return value would pass against a function that
    /// invented one without dialling anything, which is precisely the defect class
    /// this issue is about (`assign-ebi` had no caller ANYWHERE before this).
    #[tokio::test]
    async fn the_smf_requests_an_ebi_over_namf_and_stores_what_it_gets() {
        use nextgcore_sbi::message::{SbiRequest, SbiResponse};
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::net::SocketAddr;

        // Drives production peer-call code against a loopback PLAINTEXT peer, i.e.
        // a dev-profile deployment. Declared rather than inherited: the default
        // `SbiProfile` is Production, which refuses a plaintext connection and
        // would make this test fail for a reason unrelated to what it asserts.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let _g = SWITCH_LOCK.lock().await;
        set_for_test(true);

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let amf = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        amf.start(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                    req.header.uri.clone(),
                    req.http.content.clone().unwrap_or_default(),
                ));
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "pduSessionId": 5,
                        "assignedEbiList": [{
                            "epsBearerId": 6,
                            "arp": {
                                "priorityLevel": 8,
                                "preemptCap": "NOT_PREEMPT",
                                "preemptVuln": "PREEMPTABLE",
                            },
                        }],
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200))
            }
        })
        .await
        .expect("amf start");

        let ebi = request_ebi(
            Some(&format!("http://127.0.0.1:{port}")),
            "imsi-001010000000117",
            5,
            8,
        )
        .await;
        assert_eq!(ebi, Some(6), "the AMF-assigned EBI must be returned");

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(requests.len(), 1, "exactly one request, got {requests:?}");
        assert_eq!(
            requests[0].0, "/namf-comm/v1/ue-contexts/imsi-001010000000117/assign-ebi",
            "TS 29.518 §6.1.6.2.5's resource, addressed to the UE's own ue-context"
        );
        let body: serde_json::Value =
            serde_json::from_str(&requests[0].1).expect("the request body is JSON");
        assert_eq!(
            body["pduSessionId"],
            serde_json::json!(5),
            "pduSessionId is AssignEbiData's only required member"
        );
        let arp = &body["arpList"][0];
        assert_eq!(arp["priorityLevel"], serde_json::json!(8));
        assert!(
            arp.get("preemptCap").is_some() && arp.get("preemptVuln").is_some(),
            "all three Arp members are required by TS 29.571, got {arp}"
        );

        // With the leg OFF the same call dials nothing -- criterion 5's half of this.
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        set_for_test(false);
        assert_eq!(
            request_ebi(Some(&format!("http://127.0.0.1:{port}")), "imsi-1", 5, 8).await,
            None
        );
        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "a disabled leg must not dial the AMF at all"
        );

        amf.stop().await.expect("stop");
    }

    /// #117 criterion 2, the storage half: the assigned EBI reaches
    /// `SmfBearer.ebi` **without** traversing the GTPv2 path.
    ///
    /// The negative assertion matters as much as the positive one. Before this, the
    /// only writer of `ebi` was `gtp_handler.rs`, so "the field is populated" could
    /// be satisfied by an EPC-side establishment. This session is created directly
    /// in the context and no GTPv2 message is involved anywhere.
    #[test]
    fn the_assigned_ebi_reaches_smf_bearer_without_the_gtpv2_path() {
        use crate::context::{smf_context_init, smf_self};

        smf_context_init(64, 256, 512);
        let ctx = smf_self();
        let sess_id = {
            let guard = ctx.read().expect("context");
            let ue = guard.ue_add_by_supi("imsi-001010000000122").expect("ue");
            guard.sess_add_by_psi(ue.id, 5).expect("sess").id
        };

        let flow_id = record_mapped_eps_bearer(sess_id, 6, 1, 9, 8, "imsi-001010000000122")
            .expect("a QoS flow must be created for the assigned EBI");

        let guard = ctx.read().expect("context");
        let flow = guard
            .bearer_find_by_id(flow_id)
            .expect("the flow is stored");
        assert_eq!(
            flow.ebi, 6,
            "SmfBearer.ebi must carry the Namf-assigned EBI"
        );
        assert_eq!(flow.qfi, 1, "and the QFI it maps");
        assert_eq!(flow.qos.index, 9, "and the 5QI, which becomes the EPS QCI");
        assert_eq!(
            flow.assigned_ebi(),
            Some(6),
            "assigned_ebi() must recognise it as a real identity"
        );

        // The encoder the accept path uses reads it back.
        let contents = crate::gsm_build::encode_mapped_eps_bearer_context(
            flow.assigned_ebi().expect("ebi"),
            flow.qos.index,
        );
        assert_eq!(contents[0] >> 4, 6, "the EBI reaches the wire encoding");
    }
}
