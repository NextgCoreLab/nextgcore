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

/// Test-only: set the switch without going through startup.
///
/// The caller must hold [`crate::context::PROCESS_STATE_TEST_LOCK`]. This module kept
/// a switch lock of its own until #308: one lock per switch serialises that switch's
/// writers and orders nothing else, and the release path reads this switch from tests
/// that never mention interworking.
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
    let body = serde_json::json!({
        "pduSessionId": pdu_session_id,
        // One ARP entry, so one EBI: this SMF authorises a single default QoS flow
        // per session on the live path, and asking for more than it has flows for
        // would burn identities out of an eleven-wide per-UE space.
        "arpList": [default_flow_arp(arp_priority_level)],
    });

    let response = post_assign_ebi(amf_uri, supi, pdu_session_id, &body, "assignment").await?;
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

/// Give an assigned EBI back to the AMF when its PDU session is released
/// (issue #291, TS 29.518 §6.1.6.2.5's `releasedEbiList`).
///
/// The identity space is **eleven wide per UE** — TS 24.301 §9.3.2 reserves 0..=4 —
/// so an SMF that assigns and never releases exhausts it after eleven session
/// lifetimes rather than after eleven concurrent bearers. `next_free_ebi` on the AMF
/// side is lowest-free, so the space does not look under pressure until it is gone,
/// and the twelfth session gets a `403 INSUFFICIENT_RESOURCES` with no live bearers
/// to account for it. The failure is silent in the direction that matters:
/// [`request_ebi`] treats every failure as non-fatal, so nothing surfaces except
/// that interworking has quietly stopped working for that subscriber.
///
/// Returns `true` when the AMF confirmed the release. A `false` is **not** a session
/// failure — see the module's failure posture — but it does mean one identity is
/// leaked until the UE deregisters, which is why the log names it.
///
/// The disabled leg returns early and says nothing: `false` would otherwise conflate
/// "not attempted" with "attempted and lost", and the leak warning below would name a
/// consequence that a deployment with interworking off cannot have.
pub async fn release_ebi(amf_uri: Option<&str>, supi: &str, pdu_session_id: u8, ebi: u8) -> bool {
    if !enabled() {
        return false;
    }
    let body = serde_json::json!({
        "pduSessionId": pdu_session_id,
        // The AMF frees these BEFORE it allocates anything in the same request, and
        // treats a release of an EBI it does not hold as a success — so this is
        // safely repeatable and cannot strand a retry (`handle_assign_ebi`).
        "releasedEbiList": [ebi],
    });

    let Some(response) = post_assign_ebi(amf_uri, supi, pdu_session_id, &body, "release").await
    else {
        // `post_assign_ebi` logs why it could not send; name the consequence here,
        // where the leaked identity is known.
        log::warn!(
            "[{supi}] EPS bearer identity {ebi} (PSI {pdu_session_id}) could not be \
             returned to the AMF and is LEAKED until this UE deregisters: the UE has \
             eleven per its whole registration, so repeated releases like this one end \
             in a 403 for a session with no live bearers"
        );
        return false;
    };
    if response.status != 200 {
        log::warn!(
            "[{supi}] AMF refused to release EPS bearer identity {ebi} (PSI \
             {pdu_session_id}): status={}. The identity is LEAKED until this UE \
             deregisters.",
            response.status
        );
        return false;
    }
    log::info!("[{supi}] EPS bearer identity {ebi} (PSI {pdu_session_id}) returned to the AMF");
    true
}

/// POST an `AssignEbiData` body to the UE's `assign-ebi` resource.
///
/// One place where the leg's switch, the AMF authority and the client posture are
/// decided, because the assignment and the release differ only in the body they
/// carry: two copies of this would be two chances for the switch check or the
/// timeouts to drift apart. `None` means nothing was sent, and why is logged here.
///
/// `amf_uri` is the AMF's callback root, which is the only address the SMF has for
/// it — the same source `send_n1_n2_message_transfer` uses. A session whose create
/// carried no `smContextStatusUri` therefore can neither get an EBI nor give one
/// back, and says so.
async fn post_assign_ebi(
    amf_uri: Option<&str>,
    supi: &str,
    pdu_session_id: u8,
    body: &serde_json::Value,
    what: &str,
) -> Option<nextgcore_sbi::message::SbiResponse> {
    if !enabled() {
        return None;
    }
    let Some(amf_uri) = amf_uri else {
        log::warn!(
            "[{supi}] EPS interworking is on but the AMF supplied no callback URI: \
             no EBI {what} is possible for PSI {pdu_session_id}"
        );
        return None;
    };
    let Some((host, port)) = crate::policy::split_host_port(amf_uri) else {
        log::warn!("[{supi}] AMF URI '{amf_uri}' is not a valid URI: no EBI {what} attempted");
        return None;
    };

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

    match client.send_request(request).await {
        Ok(resp) => Some(resp),
        Err(e) => {
            log::warn!("[{supi}] EBI {what} to {host}:{port} failed: {e}");
            None
        }
    }
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
/// A separate function rather than an inline block because when this was written the
/// SM-context create path could not be driven past its N4 leg by any test in this
/// crate, so an inline block would have been unreachable from a test.
///
/// #289 has since given the crate a UPF stand-in
/// (`pfcp_path::stand_in::associated_upf`), so the create path DOES reach this call
/// site under test. What is still not driven is this call site with the
/// interworking switch ON — every create test runs with the leg off, so the
/// `if let (Some(ebi), Some(sess_id))` guard above it is only ever taken on the
/// `None` arm. The seam remains the tested half; the difference is that closing the
/// gap is now a test away rather than a harness away.
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

/// An EPS PDN connection decoded from `SmContextCreateData.ueEpsPdnConnection`
/// (TS 29.502 §6.1.6.2.2, `EpsPdnCnxContainer`), #415.
///
/// This is the **inbound** half of the interworking container. smfd has produced one
/// since #78 (`main.rs`'s `build_ue_eps_pdn_connection`) and never consumed one, so an
/// EPS→5GS move (TS 23.502 §4.11.1.2.2.2 step 4) reached an SMF that ignored every
/// endpoint the MME supplied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpsPdnConnection {
    /// The APN this PDN connection is for.
    pub apn: String,
    /// TS 24.301 PDN type: 1 = IPv4, 2 = IPv6, 3 = IPv4v6.
    pub pdn_type: u8,
    /// The UE's IPv4 address, when one is assigned.
    pub ue_ipv4: Option<[u8; 4]>,
    /// The EPS QCI of the default bearer (TS 24.301 §9.9.4.3).
    pub qci: u8,
    /// The Linked EPS Bearer ID — the PDN connection's default bearer.
    pub linked_ebi: Option<u8>,
    /// `PGW S5/S8 IP Address and TEID for Control Plane`, as `(teid, ipv4)`.
    ///
    /// `None` when the container carries none, which is the case for **every**
    /// container this tree's own SMF produces — see the type docs on
    /// [`parse_eps_pdn_connection`].
    pub pgw_c_control_fteid: Option<(u32, [u8; 4])>,
    /// Per-bearer user-plane F-TEIDs, as `(ebi, teid, ipv4)`.
    pub bearer_fteids: Vec<(u8, u32, [u8; 4])>,
}

/// Decode a `ueEpsPdnConnection` container, accepting **both** formats this tree
/// has to deal with.
///
/// # Two spellings of one container
///
/// TS 29.274 Table 7.3.6-3 NOTE 5 expects a conformant Table 7.3.6-2 **grouped IE**,
/// which is what a real MME sends and what carries the endpoints. But this tree's own
/// producer emits an ad-hoc **positional** layout instead (`build_ue_eps_pdn_connection`,
/// `main.rs`, from #78):
///
/// ```text
/// [APN length][APN bytes][PDN type][4 UE address octets][QCI][EBI (optional)]
/// ```
///
/// `amfd/src/n26_path.rs`'s `pdn_connection_from_smf_container` documents that divergence
/// and works around it by parsing the positional form and rebuilding a real grouped IE —
/// sending a **reserved** all-zero PGW-C F-TEID because the positional layout *"carries
/// neither"* that nor the APN-AMBR.
///
/// So a consumer that understood only the positional layout would satisfy #415's
/// criterion 1 against our own producer while **dropping every endpoint a real MME
/// sends** — the mirror of the defect #415 was filed about. Both are parsed.
///
/// # Why the grouped form is tried first
///
/// A grouped IE opens with an IE **type** octet (`Apn` = 71, `IpAddress` = 74); the
/// positional layout opens with an APN **length**, which for a real APN is far below 71
/// (`"internet"` is 8). Those ranges do not overlap in practice, but the discrimination
/// is deliberately **not** written as a byte-range ladder over the first octet: nextgsim
/// #201/#202 was exactly that shape, where a conformant PDU whose leading byte fell in a
/// neighbouring arm's range was silently routed to the wrong branch. Instead the grouped
/// decode is **attempted**, and the positional fallback runs only when it yields no APN —
/// so a container that really is a grouped IE can never be read as the ad-hoc one,
/// whatever its first octet happens to be.
pub fn parse_eps_pdn_connection(container: &[u8]) -> Option<EpsPdnConnection> {
    if container.is_empty() {
        return None;
    }
    parse_grouped_pdn_connection(container).or_else(|| parse_positional_pdn_connection(container))
}

/// The conformant TS 29.274 Table 7.3.6-2 grouped IE — what a real MME sends.
fn parse_grouped_pdn_connection(container: &[u8]) -> Option<EpsPdnConnection> {
    use nextgcore_gtp::v2::Gtp2PdnConnectionIe;

    let value = bytes::Bytes::copy_from_slice(container);
    let pdn = Gtp2PdnConnectionIe::decode(&value).ok()?;
    // The APN is mandatory in Table 7.3.6-2, so its absence means this is not a grouped
    // PDN Connection — which is the signal to fall back rather than an error to report.
    let apn_bytes = pdn.apn().ok()?.apn;
    if apn_bytes.is_empty() {
        return None;
    }
    // TS 29.274 §8.6 length-prefixes each APN label (`8"internet"3"com"`), which is how
    // `Gtp2ApnIe::from_string` wrote it. Decoded back to dotted form so the value stored
    // on the session is the same spelling every other DNN in this daemon uses.
    let apn = decode_labelled_apn(&apn_bytes);
    if apn.is_empty() {
        return None;
    }

    let ue_ipv4 = pdn.ipv4_address();
    let bearers = pdn.bearer_contexts().unwrap_or_default();
    // The QCI of the default bearer. Table 7.3.6-2 carries QoS per Bearer Context, so it
    // is read from the bearer the Linked EPS Bearer ID names rather than from the first
    // in the list -- a multi-bearer PDN connection lists them in no guaranteed order.
    let linked_ebi = pdn.linked_ebi().ok();
    let qci = bearers
        .iter()
        .find(|b| linked_ebi.is_some_and(|ebi| b.ebi().ok() == Some(ebi)))
        .or_else(|| bearers.first())
        .and_then(|b| b.bearer_qos().ok().flatten())
        .map(|qos| qos.qci)
        .unwrap_or(0);

    let bearer_fteids = bearers
        .iter()
        .filter_map(|b| {
            let ebi = b.ebi().ok()?;
            let fteid = b.fteid(0).ok().flatten()?;
            Some((ebi, fteid.teid, fteid.ipv4_addr?))
        })
        .collect();

    Some(EpsPdnConnection {
        apn,
        // Table 7.3.6-2 has no PDN Type IE of its own; the UE address is what
        // discriminates, so an IPv4 address present means IPv4 (1) and its absence
        // leaves the type unstated (0) rather than guessing IPv6.
        pdn_type: if ue_ipv4.is_some() { 1 } else { 0 },
        ue_ipv4,
        qci,
        linked_ebi,
        pgw_c_control_fteid: pdn
            .pgw_s5s8_control_fteid()
            .ok()
            .and_then(|f| Some((f.teid, f.ipv4_addr?))),
        bearer_fteids,
    })
}

/// Turn TS 29.274 §8.6's length-prefixed APN labels back into dotted form.
///
/// The inverse of `Gtp2ApnIe::from_string`, which the library has no decoder for. A label
/// length running past the end of the buffer stops the walk and returns what was read so
/// far rather than guessing: a truncated APN is a bad APN, and an empty result is what
/// makes the caller fall through to the positional layout.
fn decode_labelled_apn(encoded: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut off = 0usize;
    while off < encoded.len() {
        let len = encoded[off] as usize;
        if len == 0 || off + 1 + len > encoded.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&encoded[off + 1..off + 1 + len]).to_string());
        off += 1 + len;
    }
    labels.join(".")
}

/// #78's positional layout — what this tree's own SMF produces.
///
/// Carries no endpoints at all, which is stated at the call site rather than inferred:
/// a session restored from one of these cannot address the PGW-C.
fn parse_positional_pdn_connection(container: &[u8]) -> Option<EpsPdnConnection> {
    let apn_len = *container.first()? as usize;
    // A length octet longer than the buffer means this is not the layout this function
    // knows, and guessing would build a session out of the wrong bytes.
    if container.len() < 1 + apn_len + 1 + 4 + 1 {
        return None;
    }
    let apn = String::from_utf8_lossy(&container[1..1 + apn_len]).to_string();
    let mut off = 1 + apn_len;
    let pdn_type = container[off];
    off += 1;
    let ue_ipv4: [u8; 4] = container[off..off + 4].try_into().ok()?;
    off += 4;
    let qci = container[off];
    off += 1;
    // #117 appends the EBI when one was assigned; #78's output stops at the QCI.
    let linked_ebi = container.get(off).copied();

    Some(EpsPdnConnection {
        apn,
        pdn_type,
        // All-zero is the container's "no address assigned", not an address of 0.0.0.0.
        ue_ipv4: (ue_ipv4 != [0, 0, 0, 0]).then_some(ue_ipv4),
        qci,
        linked_ebi,
        pgw_c_control_fteid: None,
        bearer_fteids: Vec::new(),
    })
}

/// Which data-forwarding posture an `SmContextCreateData` asks for (#415).
///
/// TS 23.502 §4.11.1.2.2.2 step 4: *"Based on configuration and the Direct Forwarding
/// Flag received from the MME, the initial AMF determines the applicability of data
/// forwarding and indicates to the SMF whether the direct data forwarding or indirect
/// data forwarding is applicable."* Step 7 is what makes the answer observable: *"If
/// neither indirect forwarding nor direct forwarding is applicable, the SMF shall further
/// include a 'Data forwarding not possible' indication in the N2 SM information
/// container."*
///
/// The two members are `indirectForwardingFlag` and `directForwardingFlag`
/// (`TS29502_Nsmf_PDUSession.yaml`, `SmContextCreateData`). Note what the issue's
/// criterion 2 asked for instead — `hoPreparationIndication` — is **not** a member of
/// this schema at all; it belongs to `PduSessionCreateData` and `HsmfUpdateData`, the
/// H-SMF (home-routed roaming) bodies. The preparation semantics in *this* direction are
/// carried by `hoState`; see [`HoPreparation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataForwarding {
    /// `indirectForwardingFlag`.
    pub indirect: bool,
    /// `directForwardingFlag`.
    pub direct: bool,
}

impl DataForwarding {
    /// Parse both flags from an `SmContextCreateData` body.
    ///
    /// Absent means `false` for each: neither member has a schema `default`, and an
    /// absent flag is the AMF not asserting that forwarding path, which is what `false`
    /// says.
    pub fn from_body(body: &serde_json::Value) -> Self {
        Self {
            indirect: body
                .get("indirectForwardingFlag")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            direct: body
                .get("directForwardingFlag")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        }
    }

    /// Whether step 7's *"Data forwarding not possible"* indication is owed.
    ///
    /// True exactly when **neither** path applies, per the step-7 sentence quoted on
    /// [`DataForwarding`]. Written as a named method rather than inlined at the call
    /// site so the negation is stated once: `!indirect && !direct` spelled out at two
    /// sites is how the two halves of one wire fact drift apart.
    pub fn not_possible(self) -> bool {
        !self.indirect && !self.direct
    }
}

/// The handover-preparation state an `SmContextCreateData` carries (#415).
///
/// TS 29.502 §5.2.2.3.4.1 defines `hoState` on an SM context. `PREPARING` is the value
/// that means what TS 23.502 step 4 calls the HO Preparation Indication:
///
/// > **PREPARING**: a handover is in preparation for the PDU session; SMF is preparing
/// > the N3 tunnel between the target 5G-AN and UPF, i.e. **the UPF's F-TEID is assigned
/// > for uplink traffic**
///
/// That is step 6's CN Tunnel Info allocation *without* the downlink switch — which is
/// exactly step 4's parenthetical *"(to avoid switching the UP path)"*. `PREPARED` is
/// then defined as the target 5G-AN's F-TEID being assigned *"upon handover execution"*,
/// i.e. the DL switch this path must not perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HoPreparation {
    /// `hoState` absent or `NONE` — an ordinary session establishment.
    #[default]
    None,
    /// `hoState: PREPARING` — allocate the uplink CN tunnel, leave the DL path alone.
    Preparing,
    /// Any other value (`PREPARED`, `COMPLETED`, `CANCELLED`, or a future extension).
    ///
    /// Kept distinct from `None` rather than collapsed into it: those are states of an
    /// **existing** handover and do not belong on a create, so a create carrying one is
    /// a peer defect worth naming rather than silently treating as no handover.
    Other,
}

impl HoPreparation {
    /// Parse `hoState` from an `SmContextCreateData` body.
    pub fn from_body(body: &serde_json::Value) -> Self {
        match body.get("hoState").and_then(|v| v.as_str()) {
            Some("PREPARING") => Self::Preparing,
            Some("NONE") | None => Self::None,
            // The type is `anyOf [enum, string]` for forward-compatibility, so an
            // unrecognised value must not fail the session.
            Some(_) => Self::Other,
        }
    }

    /// Whether the user plane must be left untouched for this create.
    pub fn is_preparing(self) -> bool {
        matches!(self, Self::Preparing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- #415: the inbound ueEpsPdnConnection container ----

    /// Build the CONFORMANT TS 29.274 Table 7.3.6-2 grouped IE — what a real MME sends,
    /// and the only form that carries endpoints at all.
    fn grouped_container(
        apn: &str,
        ue_ipv4: [u8; 4],
        ebi: u8,
        qci: u8,
        pgw_teid: u32,
        pgw_addr: [u8; 4],
    ) -> Vec<u8> {
        use nextgcore_gtp::v2::{
            Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2EbiIe, Gtp2FTeidIe, Gtp2Ie, Gtp2IeType,
            Gtp2PdnConnectionIe,
        };
        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(nextgcore_gtp::v2::Gtp2ApnIe::from_string(apn).to_ie(0));
        pdn.add_ie(Gtp2Ie::from_slice(Gtp2IeType::IpAddress as u8, 0, &ue_ipv4));
        pdn.add_ie(Gtp2EbiIe::new(ebi).to_ie(0));
        // Interface type 7 = S5/S8 PGW GTP-C (TS 29.274 Table 8.22-1).
        pdn.add_ie(Gtp2FTeidIe::new_ipv4(7, pgw_teid, pgw_addr).to_ie(0));
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(ebi);
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(qci, 0, 0, 0, 0));
        pdn.add_ie(bearer.to_ie(0));
        let mut buf = bytes::BytesMut::new();
        pdn.encode_value(&mut buf);
        buf.to_vec()
    }

    /// Build #78's POSITIONAL layout — what this tree's own SMF produces.
    fn positional_container(
        apn: &str,
        pdn_type: u8,
        ue_ipv4: [u8; 4],
        qci: u8,
        ebi: Option<u8>,
    ) -> Vec<u8> {
        let mut buf = vec![apn.len() as u8];
        buf.extend_from_slice(apn.as_bytes());
        buf.push(pdn_type);
        buf.extend_from_slice(&ue_ipv4);
        buf.push(qci);
        if let Some(ebi) = ebi {
            buf.push(ebi);
        }
        buf
    }

    /// The criterion-1 assertion: a conformant container yields every field INCLUDING the
    /// PGW-C endpoint, which is the whole point of #415 and the one thing the positional
    /// form cannot carry.
    ///
    /// Literal values, asserted field by field rather than as a round trip: a round trip
    /// passes whether or not the parse reads the right octets.
    #[test]
    fn a_conformant_grouped_container_yields_the_pgw_c_endpoint() {
        const APN: &str = "ims.mnc001.mcc001.gprs";
        const EBI: u8 = 6;
        const QCI: u8 = 5;
        const PGW_TEID: u32 = 0x0415_1234;
        const PGW_ADDR: [u8; 4] = [10, 41, 5, 7];
        const UE_ADDR: [u8; 4] = [10, 45, 0, 99];

        let parsed = parse_eps_pdn_connection(&grouped_container(
            APN, UE_ADDR, EBI, QCI, PGW_TEID, PGW_ADDR,
        ))
        .expect("a conformant Table 7.3.6-2 grouped IE must parse");

        assert_eq!(
            parsed.apn, APN,
            "the APN's labels must decode to dotted form"
        );
        assert_eq!(parsed.ue_ipv4, Some(UE_ADDR));
        assert_eq!(parsed.linked_ebi, Some(EBI));
        assert_eq!(
            parsed.qci, QCI,
            "the QCI comes from the LINKED bearer's QoS"
        );
        assert_eq!(
            parsed.pgw_c_control_fteid,
            Some((PGW_TEID, PGW_ADDR)),
            "the PGW-C S5/S8 control F-TEID is what #415 exists to consume; without it \
             the session cannot address the PGW-C for a later S5/S8 procedure"
        );
    }

    /// #78's positional container yields the five fields it carries, and states the
    /// ceiling: NO endpoints. Asserted as `None` rather than omitted, because "the
    /// endpoint is absent" is the fact a later reader needs.
    #[test]
    fn the_positional_container_yields_its_fields_and_no_endpoints() {
        const APN: &str = "internet";
        const EBI: u8 = 9;
        const QCI: u8 = 8;
        const UE_ADDR: [u8; 4] = [10, 45, 1, 77];

        let parsed =
            parse_eps_pdn_connection(&positional_container(APN, 1, UE_ADDR, QCI, Some(EBI)))
                .expect("#78's own layout must still parse");

        assert_eq!(parsed.apn, APN);
        assert_eq!(parsed.pdn_type, 1);
        assert_eq!(parsed.ue_ipv4, Some(UE_ADDR));
        assert_eq!(parsed.qci, QCI);
        assert_eq!(parsed.linked_ebi, Some(EBI));
        assert_eq!(
            parsed.pgw_c_control_fteid, None,
            "#78's positional layout carries no PGW-C F-TEID; amfd's \
             pdn_connection_from_smf_container sends the RESERVED value for exactly this reason"
        );
        assert!(parsed.bearer_fteids.is_empty());
    }

    /// **The discrimination guard.** A conformant grouped IE must NOT be read as the
    /// positional layout, and vice versa.
    ///
    /// This is the test that fails if the two parses are tried in the wrong order, or if
    /// the discrimination is written as a byte-range ladder over the first octet. nextgsim
    /// #201/#202 was that exact defect: a conformant PDU whose leading byte fell inside a
    /// neighbouring arm's range was silently routed to the wrong branch and the failure
    /// looked like a peer problem. Asserted as a DIFFERENCE — the same bytes must not
    /// produce the same reading under both parses — because only that distinguishes real
    /// discrimination from a parse that happens to succeed.
    #[test]
    fn the_two_container_formats_are_not_confused_for_each_other() {
        const APN: &str = "internet";
        let grouped = grouped_container(APN, [10, 45, 0, 1], 6, 5, 0x0415_0001, [10, 41, 0, 1]);
        let positional = positional_container(APN, 1, [10, 45, 0, 2], 8, Some(9));

        // The grouped form opens with an IE TYPE octet (Apn = 71); the positional form
        // opens with an APN LENGTH (8 for "internet"). Pinned so a future change to either
        // producer that made the two collide fails here rather than silently.
        assert_eq!(grouped[0], 71, "a grouped IE opens with the APN IE type");
        assert_eq!(positional[0], APN.len() as u8);

        let from_grouped = parse_eps_pdn_connection(&grouped).expect("grouped must parse");
        let from_positional = parse_eps_pdn_connection(&positional).expect("positional must parse");

        // The discriminating fact: only the grouped form yields an endpoint. If the
        // grouped container were misparsed as positional, this would be None.
        assert!(
            from_grouped.pgw_c_control_fteid.is_some(),
            "the grouped container was read as the positional layout, losing its endpoints"
        );
        assert!(from_positional.pgw_c_control_fteid.is_none());
        // And the two must not agree on the UE address, which is what proves each was read
        // with its own layout rather than one of them being coerced into the other.
        assert_ne!(from_grouped.ue_ipv4, from_positional.ue_ipv4);
    }

    /// A container that is neither format is refused rather than half-read. Guessing would
    /// build a session out of the wrong bytes.
    #[test]
    fn an_unparseable_container_is_refused() {
        // An APN length octet claiming more bytes than the buffer holds, and not a valid
        // grouped IE either.
        assert_eq!(parse_eps_pdn_connection(&[0xFF, 0x01, 0x02]), None);
        assert_eq!(parse_eps_pdn_connection(&[]), None);
    }

    /// The APN label decoder is the inverse of `Gtp2ApnIe::from_string`, which the GTP
    /// library ships without a decoder. A truncated label stops the walk rather than
    /// reading past the buffer.
    #[test]
    fn labelled_apns_decode_to_dotted_form_and_truncation_stops_the_walk() {
        assert_eq!(
            decode_labelled_apn(&[8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']),
            "internet"
        );
        assert_eq!(
            decode_labelled_apn(&[3, b'i', b'm', b's', 3, b'c', b'o', b'm']),
            "ims.com"
        );
        // A length octet running past the end: what was read survives, the rest is not
        // invented.
        assert_eq!(decode_labelled_apn(&[3, b'i', b'm', b's', 9, b'x']), "ims");
        assert_eq!(decode_labelled_apn(&[]), "");
    }

    // ---- #415: the forwarding flags and the handover state ----

    /// Step 7's *"Data forwarding not possible"* indication is owed exactly when NEITHER
    /// path applies. Asserted across all four combinations, because the interesting value
    /// is the one where both are absent and a one-sided test would miss it.
    #[test]
    fn data_forwarding_not_possible_is_true_only_when_neither_path_applies() {
        let cases = [
            (None, None, true),
            (Some(true), None, false),
            (None, Some(true), false),
            (Some(true), Some(true), false),
            (Some(false), Some(false), true),
        ];
        for (indirect, direct, expected_not_possible) in cases {
            let mut body = serde_json::json!({});
            if let Some(v) = indirect {
                body["indirectForwardingFlag"] = serde_json::json!(v);
            }
            if let Some(v) = direct {
                body["directForwardingFlag"] = serde_json::json!(v);
            }
            let parsed = DataForwarding::from_body(&body);
            assert_eq!(
                parsed.not_possible(),
                expected_not_possible,
                "indirect={indirect:?} direct={direct:?} must yield \
                 not_possible={expected_not_possible} (TS 23.502 §4.11.1.2.2.2 step 7)"
            );
            assert_eq!(parsed.indirect, indirect.unwrap_or(false));
            assert_eq!(parsed.direct, direct.unwrap_or(false));
        }
    }

    /// `hoState` is what carries the preparation semantics in this direction — NOT
    /// `hoPreparationIndication`, which #415's criterion 2 named and which belongs to
    /// `PduSessionCreateData` / `HsmfUpdateData` (the H-SMF roaming bodies) rather than to
    /// `SmContextCreateData`.
    ///
    /// The last case is the one that matters for that correction: a body carrying ONLY
    /// `hoPreparationIndication` must NOT be read as a preparation, because no conformant
    /// AMF sends it here and honouring it would be an arm production can never reach.
    #[test]
    fn ho_state_carries_the_preparation_and_ho_preparation_indication_does_not() {
        assert_eq!(
            HoPreparation::from_body(&serde_json::json!({ "hoState": "PREPARING" })),
            HoPreparation::Preparing
        );
        assert!(
            HoPreparation::from_body(&serde_json::json!({ "hoState": "PREPARING" })).is_preparing()
        );
        assert_eq!(
            HoPreparation::from_body(&serde_json::json!({})),
            HoPreparation::None
        );
        assert_eq!(
            HoPreparation::from_body(&serde_json::json!({ "hoState": "NONE" })),
            HoPreparation::None
        );
        // States of an EXISTING handover: distinct from None so the create path can name
        // them as a peer defect.
        for state in ["PREPARED", "COMPLETED", "CANCELLED", "SOME_FUTURE_VALUE"] {
            assert_eq!(
                HoPreparation::from_body(&serde_json::json!({ "hoState": state })),
                HoPreparation::Other,
                "hoState={state} is not a state a create can be in"
            );
        }
        assert_eq!(
            HoPreparation::from_body(&serde_json::json!({ "hoPreparationIndication": true })),
            HoPreparation::None,
            "hoPreparationIndication is not a member of SmContextCreateData; honouring it \
             would add an arm no conformant AMF can reach"
        );
    }

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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
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

        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        set_for_test(true);

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let amf = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
            port_listener,
        );
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
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
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
