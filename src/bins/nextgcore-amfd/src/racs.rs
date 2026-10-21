//! RACS on the AMF: UE radio capability signalling optimisation (nextgcore #570).
//!
//! The AMF side of TS 23.501 §5.4.4.1a, wired to the UCMF of #569:
//!
//! - **Nucmf_UECapabilityManagement consumer** (TS 29.673): Resolve an ID to the
//!   UE radio capability, Assign an ID for a capability, Subscribe to the UCMF's
//!   dictionary notifications. The UCMF is discovered through the NRF.
//! - **NGAP** (TS 38.413 §8.14): answer UE RADIO CAPABILITY ID MAPPING
//!   (procedure 60) and act on UE RADIO CAPABILITY INFO INDICATION (procedure 44);
//!   carry the UE Radio Capability ID (IE 264) in Initial Context Setup Request,
//!   Handover Request and Path Switch Request Acknowledge.
//! - **NAS** (TS 24.501 §5.4.4.1, §5.4.4.2, §5.5.1.2.4, §9.11.3.68/69): give a
//!   UE that set the 5GMM capability RACS bit its network-assigned ID in a
//!   CONFIGURATION UPDATE COMMAND or REGISTRATION ACCEPT, and the deletion
//!   indication when the UCMF deleted the ID it holds.
//!
//! **Byte contract** (nextg `specs/gnb-racs-other-messages-254.md`): NGAP carries
//! the TS 24.501 §9.11.3.68 *value* octets; the Nucmf `PlmnAssiUeRadioCapId` /
//! `ManAssiUeRadioCapId` (TS 29.571 `Bytes`) is base64 of the whole IE, IEI
//! `0x67` and length included. The AMF strips or prepends those two octets and
//! never re-encodes from the digit string. Every ID held in this module is in the
//! value-octet form.

use base64::Engine;
use nextgcore_ngap_gen::generated as ngap_gen;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};

/// IEI of the UE radio capability ID IE (TS 24.501 §9.11.3.68), in the REGISTRATION
/// REQUEST, REGISTRATION ACCEPT and CONFIGURATION UPDATE COMMAND.
pub const IEI_UE_RADIO_CAPABILITY_ID: u8 = 0x67;
/// Half-octet IEI of the UE radio capability ID deletion indication
/// (TS 24.501 §9.11.3.69), with the value in the low nibble.
pub const IEI_UE_RADIO_CAPABILITY_ID_DELETION: u8 = 0xE0;
/// "Network-assigned UE radio capability IDs deletion requested" (§9.11.3.69).
pub const DELETION_REQUESTED: u8 = 0x01;
/// The RACS bit of the 5GMM capability IE: octet 4, bit 8 (TS 24.501 §9.11.3.1),
/// i.e. bit 8 of the second contents octet.
const GMM_CAPABILITY_RACS_BIT: u8 = 0x80;

/// The UCMF's Nucmf_UECapabilityManagement API root (TS 29.673 §6.1.1).
const UECM_API: &str = "/nucmf-uecm/v1";
/// `application/vnd.3gpp.ngap` binary part (TS 29.673 §6.1.2.4).
const CONTENT_NGAP: &str = "application/vnd.3gpp.ngap";
/// Bound of the AMF's ID → capability cache. The UCMF is the authority; the cache
/// only saves a round trip per mapping request, so a modest bound is enough.
const CACHE_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// ID forms
// ---------------------------------------------------------------------------

/// Value octets → the Nucmf (TS 29.571) form: base64 of `0x67`, length, value.
pub fn to_nucmf(value: &[u8]) -> Option<String> {
    if value.is_empty() || value.len() > 255 {
        return None;
    }
    let mut ie = Vec::with_capacity(value.len() + 2);
    ie.push(IEI_UE_RADIO_CAPABILITY_ID);
    ie.push(value.len() as u8);
    ie.extend_from_slice(value);
    Some(base64::engine::general_purpose::STANDARD.encode(ie))
}

/// The Nucmf form → value octets, after checking the IEI and the length octet.
pub fn from_nucmf(nucmf: &str) -> Option<Vec<u8>> {
    let ie = base64::engine::general_purpose::STANDARD
        .decode(nucmf.trim())
        .ok()?;
    match ie.as_slice() {
        [IEI_UE_RADIO_CAPABILITY_ID, len, value @ ..]
            if !value.is_empty() && *len as usize == value.len() =>
        {
            Some(value.to_vec())
        }
        _ => None,
    }
}

/// Whether the ID is PLMN-assigned: its Type Field digit, the first digit and so
/// the low nibble of the first value octet, is 1 (TS 23.003 §29.2).
pub fn is_plmn_assigned(value: &[u8]) -> bool {
    value.first().is_some_and(|o| o & 0x0F == 1)
}

/// The Version ID of a PLMN-assigned ID: digits 2 and 3 (TS 23.003 §29.2), which
/// sit in the high nibble of octet 1 and the low nibble of octet 2.
pub fn version_id(value: &[u8]) -> Option<u8> {
    if !is_plmn_assigned(value) || value.len() < 2 {
        return None;
    }
    Some((value[0] & 0xF0) | (value[1] & 0x0F))
}

/// The Type Allocation Code of a PEI (`imei-<15>` / `imeisv-<16>`): its first 8
/// digits (TS 23.003 §6.2), which Assign keys the capability on (TS 29.673 §5.2.2.3).
pub fn tac_from_pei(pei: &str) -> Option<String> {
    let digits = pei
        .strip_prefix("imeisv-")
        .or_else(|| pei.strip_prefix("imei-"))?;
    let tac: String = digits.chars().take(8).collect();
    (tac.len() == 8 && tac.chars().all(|c| c.is_ascii_digit())).then_some(tac)
}

/// Whether a 5GMM capability IE's contents (TS 24.501 §9.11.3.1, after IEI and
/// length) set the RACS bit, octet 4 bit 8.
pub fn gmm_capability_supports_racs(contents: &[u8]) -> bool {
    contents
        .get(1)
        .is_some_and(|o| o & GMM_CAPABILITY_RACS_BIT != 0)
}

// ---------------------------------------------------------------------------
// The AMF's dictionary cache and the UCMF's deletions
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Cache {
    entries: HashMap<Vec<u8>, Vec<u8>>,
    order: VecDeque<Vec<u8>>,
    /// IDs the UCMF deleted (DELETION_OF_PLMN_ASSIGNED_IDS) or retired with a Version
    /// ID change: a UE still holding one gets the deletion indication, and the ID is
    /// no longer put in NGAP.
    deleted: HashSet<Vec<u8>>,
    /// The UCMF's current Version ID, when a NEW_VERSION_ID notification told us.
    current_version: Option<u8>,
}

/// The AMF's RACS state. Process-global, with its lock declared beside it.
static RACS: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::default()));

fn with_cache<T>(f: impl FnOnce(&mut Cache) -> T) -> T {
    let mut guard = RACS.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// The cached UE radio capability for an ID, if any.
pub fn cache_get(id: &[u8]) -> Option<Vec<u8>> {
    with_cache(|c| c.entries.get(id).cloned())
}

/// Cache a mapping learnt from the UCMF (Resolve or Assign).
pub fn cache_put(id: &[u8], capability: &[u8]) {
    with_cache(|c| {
        if c.entries.insert(id.to_vec(), capability.to_vec()).is_none() {
            c.order.push_back(id.to_vec());
            while c.order.len() > CACHE_CAPACITY {
                if let Some(old) = c.order.pop_front() {
                    c.entries.remove(&old);
                }
            }
        }
        c.deleted.remove(id);
    });
}

/// Whether the AMF must no longer use `id` (deleted at the UCMF, or a PLMN-assigned
/// ID under a Version ID other than the current one).
pub fn is_retired(id: &[u8]) -> bool {
    with_cache(|c| {
        c.deleted.contains(id)
            || matches!(
                (c.current_version, version_id(id)),
                (Some(current), Some(v)) if v != current
            )
    })
}

/// Apply a UCMF notification (TS 29.673 §5.2.2.4, `UcmfNotification`).
/// Returns the IDs it retired, for the log.
pub fn apply_notification(body: &serde_json::Value) -> Vec<Vec<u8>> {
    let event = body.get("eventType").and_then(|e| e.as_str()).unwrap_or("");
    match event {
        "DELETION_OF_PLMN_ASSIGNED_IDS" => {
            let ids: Vec<Vec<u8>> = body
                .pointer("/manAssOpRequestlist/plmnAssiUeRadioCapId")
                .and_then(|l| l.as_array())
                .map(|l| {
                    l.iter()
                        .filter_map(|v| v.as_str().and_then(from_nucmf))
                        .collect()
                })
                .unwrap_or_default();
            with_cache(|c| {
                for id in &ids {
                    c.entries.remove(id);
                    c.order.retain(|o| o != id);
                    c.deleted.insert(id.clone());
                }
            });
            ids
        }
        "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs" => {
            let Some(v) = body.get("versionId").and_then(|v| v.as_u64()) else {
                return Vec::new();
            };
            let v = v as u8;
            // TS 23.501 §5.4.4.1a: purge the old Version ID's entries first.
            with_cache(|c| {
                c.current_version = Some(v);
                let stale: Vec<Vec<u8>> = c
                    .entries
                    .keys()
                    .filter(|id| version_id(id).is_some_and(|x| x != v))
                    .cloned()
                    .collect();
                for id in &stale {
                    c.entries.remove(id);
                    c.order.retain(|o| o != id);
                }
                stale
            })
        }
        // A new entry needs no action: the next Resolve finds it.
        _ => Vec::new(),
    }
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    with_cache(|c| *c = Cache::default());
}

// ---------------------------------------------------------------------------
// NAS
// ---------------------------------------------------------------------------

/// The RACS IEs to append to a REGISTRATION ACCEPT or CONFIGURATION UPDATE COMMAND
/// for a UE (TS 24.501 §5.5.1.2.4, §5.4.4.2), and what they change on the UE.
///
/// Only for a UE that set the RACS bit. A retired ID gets the deletion indication
/// (§9.11.3.69) and is dropped from the context; an ID the UE did not present this
/// time (one the AMF learnt from the UCMF) is sent (§9.11.3.68).
pub fn nas_ies_for(ue: &mut crate::context::AmfUe) -> Vec<u8> {
    if !ue.racs_supported {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(id) = ue.ue_radio_capability_id.clone() {
        if is_retired(&id) {
            ue.ue_radio_capability_id = None;
            ue.ue_radio_capability_id_known_to_ue = false;
            out.push(IEI_UE_RADIO_CAPABILITY_ID_DELETION | DELETION_REQUESTED);
        } else if !ue.ue_radio_capability_id_known_to_ue && id.len() <= 255 {
            out.push(IEI_UE_RADIO_CAPABILITY_ID);
            out.push(id.len() as u8);
            out.extend_from_slice(&id);
            ue.ue_radio_capability_id_known_to_ue = true;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// NGAP
// ---------------------------------------------------------------------------

/// The UE Radio Capability ID of a UE RADIO CAPABILITY ID MAPPING REQUEST
/// (TS 38.413 §9.2.13.4), or `None` when it is not one or carries none.
pub fn decode_mapping_request(pdu: &[u8]) -> Option<Vec<u8>> {
    let ngap_gen::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
        return None;
    };
    let ngap_gen::InitiatingMessageValue::Id_UERadioCapabilityIDMapping(req) = m.value else {
        return None;
    };
    req.protocol_i_es.0.into_iter().find_map(|e| match e.value {
        ngap_gen::UERadioCapabilityIDMappingRequestProtocolIEs_EntryValue::Id_UERadioCapabilityID(
            id,
        ) => Some(id.0),
    })
}

/// UE RADIO CAPABILITY ID MAPPING RESPONSE (TS 38.413 §9.2.13.5): the ID (reject)
/// and the UE radio capability mapped to it (ignore), both mandatory.
pub fn build_mapping_response(id: &[u8], capability: &[u8]) -> Option<Vec<u8>> {
    use ngap_gen::{
        UERadioCapabilityIDMappingResponseProtocolIEs_Entry as Entry,
        UERadioCapabilityIDMappingResponseProtocolIEs_EntryValue as Ie,
    };
    let ies = vec![
        Entry {
            id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_UE_RADIO_CAPABILITY_ID),
            criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
            value: Ie::Id_UERadioCapabilityID(ngap_gen::UERadioCapabilityID(id.to_vec())),
        },
        Entry {
            id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_UE_RADIO_CAPABILITY),
            criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
            value: Ie::Id_UERadioCapability(ngap_gen::UERadioCapability(capability.to_vec())),
        },
    ];
    let pdu = ngap_gen::NGAP_PDU::SuccessfulOutcome(ngap_gen::SuccessfulOutcome {
        procedure_code: ngap_gen::ProcedureCode(ngap_gen::ID_UE_RADIO_CAPABILITY_ID_MAPPING),
        criticality: ngap_gen::Criticality(ngap_gen::Criticality::REJECT),
        value: ngap_gen::SuccessfulOutcomeValue::Id_UERadioCapabilityIDMapping(
            ngap_gen::UERadioCapabilityIDMappingResponse {
                protocol_i_es: ngap_gen::UERadioCapabilityIDMappingResponseProtocolIEs(ies),
            },
        ),
    });
    nextgcore_ngap_gen::encode(&pdu)
        .map_err(|e| log::error!("Failed to encode UE Radio Capability ID Mapping Response: {e:?}"))
        .ok()
}

/// What a UE RADIO CAPABILITY INFO INDICATION (TS 38.413 §9.2.13.1) carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoIndication {
    pub amf_ue_ngap_id: u64,
    pub ran_ue_ngap_id: u32,
    /// UE Radio Capability (IE 117), the TS 38.331 UERadioAccessCapabilityInformation.
    pub capability: Vec<u8>,
}

/// Decode a UE RADIO CAPABILITY INFO INDICATION. `None` when it is not one or a
/// mandatory IE (both UE NGAP IDs and the capability, §9.2.13.1) is missing.
pub fn decode_info_indication(pdu: &[u8]) -> Option<InfoIndication> {
    use ngap_gen::UERadioCapabilityInfoIndicationProtocolIEs_EntryValue as Ie;
    let ngap_gen::NGAP_PDU::InitiatingMessage(m) = nextgcore_ngap_gen::decode(pdu).ok()? else {
        return None;
    };
    let ngap_gen::InitiatingMessageValue::Id_UERadioCapabilityInfoIndication(ind) = m.value else {
        return None;
    };
    let (mut amf, mut ran, mut cap) = (None, None, None);
    for e in ind.protocol_i_es.0 {
        match e.value {
            Ie::Id_AMF_UE_NGAP_ID(v) => amf = Some(v.0),
            Ie::Id_RAN_UE_NGAP_ID(v) => ran = Some(v.0),
            Ie::Id_UERadioCapability(v) => cap = Some(v.0),
            _ => {}
        }
    }
    Some(InfoIndication {
        amf_ue_ngap_id: amf?,
        ran_ue_ngap_id: ran?,
        capability: cap?,
    })
}

/// Add the UE Radio Capability ID (IE 264, criticality reject) to an encoded
/// Initial Context Setup Request, Handover Request or Path Switch Request
/// Acknowledge, and — to an Initial Context Setup Request only, when the AMF holds
/// no usable ID — the UE Radio Capability (IE 117, ignore), so the NG-RAN need not
/// ask the UE (TS 23.501 §5.4.4.1).
///
/// IE 264 is appended: in all three object sets it follows every IE the AMF emits.
/// IE 117 is inserted before the first ICS IE that follows it in the object set
/// (`IndexToRFSP`, `MaskedIMEISV`, `NAS-PDU`, …). Returns `pdu` unchanged when
/// there is nothing to add or it is none of the three messages.
pub fn add_capability_ies(pdu: Vec<u8>, id: Option<&[u8]>, capability: Option<&[u8]>) -> Vec<u8> {
    let id = id.filter(|i| !i.is_empty() && !is_retired(i));
    let capability = if id.is_some() {
        None
    } else {
        capability.filter(|c| !c.is_empty())
    };
    if id.is_none() && capability.is_none() {
        return pdu;
    }
    let Ok(mut decoded) = nextgcore_ngap_gen::decode(&pdu) else {
        return pdu;
    };
    let reject = || ngap_gen::Criticality(ngap_gen::Criticality::REJECT);
    let changed = match &mut decoded {
        ngap_gen::NGAP_PDU::InitiatingMessage(m) => match &mut m.value {
            ngap_gen::InitiatingMessageValue::Id_InitialContextSetup(req) => {
                use ngap_gen::{
                    InitialContextSetupRequestProtocolIEs_Entry as Entry,
                    InitialContextSetupRequestProtocolIEs_EntryValue as Ie,
                };
                let ies = &mut req.protocol_i_es.0;
                if let Some(cap) = capability {
                    // The ICS IEs after id-UERadioCapability (117) in the object set
                    // that the AMF can emit.
                    const AFTER: [u16; 3] = [
                        ngap_gen::ID_INDEX_TO_RFSP,
                        ngap_gen::ID_MASKED_IMEISV,
                        ngap_gen::ID_NAS_PDU,
                    ];
                    let at = ies
                        .iter()
                        .position(|e| AFTER.contains(&e.id.0))
                        .unwrap_or(ies.len());
                    ies.insert(
                        at,
                        Entry {
                            id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_UE_RADIO_CAPABILITY),
                            criticality: ngap_gen::Criticality(ngap_gen::Criticality::IGNORE),
                            value: Ie::Id_UERadioCapability(ngap_gen::UERadioCapability(
                                cap.to_vec(),
                            )),
                        },
                    );
                }
                if let Some(id) = id {
                    ies.push(Entry {
                        id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_UE_RADIO_CAPABILITY_ID),
                        criticality: reject(),
                        value: Ie::Id_UERadioCapabilityID(ngap_gen::UERadioCapabilityID(
                            id.to_vec(),
                        )),
                    });
                }
                true
            }
            ngap_gen::InitiatingMessageValue::Id_HandoverResourceAllocation(req) => match id {
                Some(id) => {
                    req.protocol_i_es
                        .0
                        .push(ngap_gen::HandoverRequestProtocolIEs_Entry {
                            id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_UE_RADIO_CAPABILITY_ID),
                            criticality: reject(),
                            value: ngap_gen::HandoverRequestProtocolIEs_EntryValue::Id_UERadioCapabilityID(
                                ngap_gen::UERadioCapabilityID(id.to_vec()),
                            ),
                        });
                    true
                }
                None => false,
            },
            _ => false,
        },
        ngap_gen::NGAP_PDU::SuccessfulOutcome(m) => match (&mut m.value, id) {
            (ngap_gen::SuccessfulOutcomeValue::Id_PathSwitchRequest(ack), Some(id)) => {
                ack.protocol_i_es
                    .0
                    .push(ngap_gen::PathSwitchRequestAcknowledgeProtocolIEs_Entry {
                        id: ngap_gen::ProtocolIE_ID(ngap_gen::ID_UE_RADIO_CAPABILITY_ID),
                        criticality: reject(),
                        value: ngap_gen::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_UERadioCapabilityID(
                            ngap_gen::UERadioCapabilityID(id.to_vec()),
                        ),
                    });
                true
            }
            _ => false,
        },
        _ => false,
    };
    if !changed {
        return pdu;
    }
    match nextgcore_ngap_gen::encode(&decoded) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to add UE radio capability IEs: {e:?}; sending without them");
            pdu
        }
    }
}

// ---------------------------------------------------------------------------
// Nucmf_UECapabilityManagement consumer
// ---------------------------------------------------------------------------

/// The UCMF's endpoint: NRF discovery (NFType UCMF, `nucmf-uecapabilitymanagement`),
/// then `UCMF_SBI_ADDR` / `UCMF_SBI_PORT` for a bring-up without an NRF, logged when
/// used so it cannot silently stand in for discovery.
async fn resolve_ucmf_endpoint() -> Option<(String, u16)> {
    use nextgcore_sbi::context::{global_context, NfInstance};
    let service = nextgcore_sbi::types::SbiServiceType::NucmfUecapabilitymanagement;
    let from = |instances: Vec<NfInstance>| {
        let inst = instances.first()?;
        let svc = inst.find_service(service)?;
        let host = svc
            .ip_addresses
            .first()
            .or(inst.ipv4_addresses.first())
            .or(svc.fqdn.as_ref())
            .or(inst.fqdn.as_ref())?;
        Some((host.clone(), svc.port))
    };
    let ctx = global_context();
    if let Some(ep) = from(ctx.find_nf_instances_by_service(service).await) {
        return Some(ep);
    }
    if crate::sbi_path::amf_nrf_discover("UCMF", "nucmf-uecapabilitymanagement")
        .await
        .is_ok()
    {
        if let Some(ep) = from(ctx.find_nf_instances_by_service(service).await) {
            return Some(ep);
        }
    }
    let host = std::env::var("UCMF_SBI_ADDR").ok()?;
    let port = std::env::var("UCMF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    log::info!("No UCMF discoverable via the NRF; using UCMF_SBI_ADDR={host}:{port}");
    Some((host, port))
}

async fn ucmf_client() -> Result<nextgcore_sbi::client::SbiClient, String> {
    let (host, port) = resolve_ucmf_endpoint()
        .await
        .ok_or_else(|| "no UCMF endpoint (NRF discovery found none, UCMF_SBI_ADDR unset)".to_string())?;
    Ok(crate::attach_oauth2(
        nextgcore_sbi::client::SbiClient::for_peer(&host, port),
        nextgcore_sbi::types::NfType::Ucmf,
    ))
}

/// The `ueRadioCapability5GS` binary part of a `DicEntryData` answer.
fn capability_5gs_part(response: &nextgcore_sbi::message::SbiResponse) -> Option<Vec<u8>> {
    let json: serde_json::Value = serde_json::from_str(response.http.content.as_deref()?).ok()?;
    let cid = json.pointer("/ueRadioCapability5GS/contentId")?.as_str()?;
    response
        .http
        .parts
        .iter()
        .find(|p| {
            p.content_id
                .as_deref()
                .map(|c| c.trim_matches(|ch| ch == '<' || ch == '>'))
                == Some(cid)
        })
        .map(|p| p.data.to_vec())
}

/// Resolve (TS 29.673 §5.2.2.2.1): the TS 38.331 UE radio capability mapped to `id`.
/// `Ok(None)` when the UCMF has no entry (404 `NO_DICTIONARY_ENTRY_FOUND` or
/// `OUT_DATED_VERSION_ID_IN_RAC_ID`), which retires the ID locally.
pub async fn ucmf_resolve(id: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let nucmf = to_nucmf(id).ok_or("an empty or over-long UE radio capability ID")?;
    let member = if is_plmn_assigned(id) {
        "plmnAssiUeRadioCapId"
    } else {
        "manAssiUeRadioCapId"
    };
    let request = nextgcore_sbi::message::SbiRequest::get(format!("{UECM_API}/dic-entries"))
        .with_param(
            "ue-radio-capa-id",
            serde_json::json!({ member: nucmf }).to_string(),
        )
        .with_param("rac-format", "5GS");
    let response = ucmf_client()
        .await?
        .send_request(request)
        .await
        .map_err(|e| format!("Resolve at the UCMF failed: {e}"))?;
    match response.status {
        200 => {
            let cap = capability_5gs_part(&response)
                .ok_or("Resolve answer carries no ueRadioCapability5GS part")?;
            cache_put(id, &cap);
            Ok(Some(cap))
        }
        404 => {
            with_cache(|c| {
                c.deleted.insert(id.to_vec());
            });
            Ok(None)
        }
        s => Err(format!("Resolve at the UCMF returned {s}")),
    }
}

/// Assign (TS 29.673 §5.2.2.3): the PLMN-assigned ID for this TAC and TS 38.331
/// capability, in value-octet form. Caches the mapping.
pub async fn ucmf_assign(tac: &str, capability: &[u8]) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({
        "typeAllocationCode": tac,
        "ueRadioCapability5GS": { "contentId": "ueRadioCapability5GS" },
    });
    let request = nextgcore_sbi::message::SbiRequest::post(format!("{UECM_API}/dic-entries"))
        .with_json_body(&body)
        .map_err(|e| format!("encoding DicEntryCreateData: {e}"))?
        .with_part(nextgcore_sbi::message::SbiPart::with_content(
            "ueRadioCapability5GS",
            CONTENT_NGAP,
            bytes::Bytes::from(capability.to_vec()),
        ));
    let response = ucmf_client()
        .await?
        .send_request(request)
        .await
        .map_err(|e| format!("Assign at the UCMF failed: {e}"))?;
    if !matches!(response.status, 200 | 201) {
        return Err(format!("Assign at the UCMF returned {}", response.status));
    }
    let json: serde_json::Value = response
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .ok_or("Assign answer is not JSON")?;
    let id = json
        .get("plmnAssiUeRadioCapId")
        .and_then(|v| v.as_str())
        .and_then(from_nucmf)
        .ok_or("Assign answer carries no valid plmnAssiUeRadioCapId")?;
    cache_put(&id, capability);
    Ok(id)
}

/// The callback the UCMF notifies (TS 29.673 §5.2.2.4). Routed by `namf_server`.
pub fn notification_uri() -> String {
    format!(
        "{}/namf-callback/v1/ucmf-notify",
        crate::sbi_path::advertised_sbi_base()
    )
}

/// Subscribe (TS 29.673 §5.2.2.4) to the UCMF's dictionary notifications.
pub async fn ucmf_subscribe(nf_id: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "ucmfNotificationUri": notification_uri(),
        "nfId": nf_id,
    });
    let response = ucmf_client()
        .await?
        .post_json(&format!("{UECM_API}/subscriptions"), &body)
        .await
        .map_err(|e| format!("Subscribe at the UCMF failed: {e}"))?;
    if response.status != 201 {
        return Err(format!("Subscribe at the UCMF returned {}", response.status));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
