//! #686: UE contexts survive an AMF restart.
//!
//! # What 3GPP specifies, and what it leaves open
//!
//! TS 23.501 §5.21.2.3 (AMF auto-recovery): "AMF can either back up the UE contexts in
//! UDSF, or per GUAMI granularity in other AMFs". §4.2.5 and Annex C let any NF keep its
//! *unstructured* data, such as UE contexts, in a storage entity, as primary or secondary
//! storage. Annex C item 5 says AMF auto-recovery assumes exactly that.
//!
//! The rest is the implementation's choice:
//! - the record format: the data is "unstructured" (Annex C NOTE 1);
//! - when to write: §5.21.2.3 NOTE 1 says "frequency of backup is left to
//!   implementation", and Annex C item 2 calls storing *stable* state good practice;
//! - which store: the UDSF is optional (§6.2.12), and NOTE 2 lets it be collocated with
//!   the UDR.
//!
//! # What this module does
//!
//! - The storage entity is a MongoDB collection, [`COLLECTION`], used as secondary
//!   storage. It sits in the same database (and driver) the UDR's subscriber data uses.
//! - Each registered UE in a stable state (registered, no NAS procedure in flight, with a
//!   security context) is a [`StoredUeContext`] keyed by SUPI.
//! - [`NgapServer::persist_ue_contexts`] compares every stable UE with what it last
//!   wrote, about once a second ([`PERSIST_INTERVAL`]). It hands only the changes to a
//!   writer thread, so no database round trip ever runs on the NGAP task.
//! - A UE that is no longer held at all (deregistered, or released as unregistered)
//!   has its record deleted.
//! - At startup, [`NgapServer::restore_ue_contexts`] turns this AMF's records back into
//!   registered UEs before any NG association is accepted:
//!   - they are CM-IDLE, with their 5G-GUTI, NSSAI, NAS security context and PDU
//!     sessions;
//!   - a UE that was CM-CONNECTED at the crash has its N2 connection released as an NG
//!     Reset would release it (TS 23.502 §4.2.6): its sessions' user planes are
//!     DEACTIVATED at their SMFs, so downlink data pages the UE instead of going to a
//!     tunnel no gNB serves any more.
//!
//! # NAS COUNTs (TS 24.501 §4.4.3.1)
//!
//! The counts are written with the rest of the record, so after a crash they can be
//! behind the UE's by the messages exchanged since the last write.
//! - **Uplink:** the AMF estimates the received COUNT as the smallest above its stored one
//!   with the message's SN. That stays right while fewer than 256 uplink messages went
//!   unrecorded.
//!   - A SERVICE REQUEST that still fails the check is answered SERVICE REJECT #9, with
//!     the contexts kept (§4.4.4.3).
//!   - A mobility or periodic REGISTRATION REQUEST that fails gets authentication and SMC.
//! - **Downlink:** the stored value is the next COUNT to use, and the UE accepts the
//!   smallest COUNT above the largest it has verified that has the received SN. So on
//!   restore the AMF moves forward by [`DL_COUNT_RESTORE_MARGIN`] (255):
//!   - no COUNT is ever used twice with K_AMF, as long as fewer than 256 downlink
//!     messages went unrecorded;
//!   - the UE estimates the new COUNT correctly however many of those (0..=255) it
//!     received.
//!   - A margin of 256 would fail the UE's estimate exactly when nothing went unrecorded.
//!
//! # Scope
//!
//! Only records written under this AMF's own `nfInstanceId` are restored. Its UECM
//! registration at the UDM still names this AMF (TS 29.503; #753 pins the id), so the
//! restored context is the one the core expects.
//!
//! A record of another AMF instance belongs to the AMF Set takeover of §5.21.2.3, which
//! has to update the UDM and the peers first. It is left in the store.
//!
//! Off unless [`DB_URI_ENV`] names a MongoDB. Without it nothing is written or restored.

use super::{NgapServer, UeNasContext};
use crate::context::{
    AssignedEbi, Bitrate, GmmCapability, Guti5gs, NrCgi, PlmnId, PolicyAssociation, SNssai, Tai5gs,
    UeNetworkCapability, UeSecurityCapability,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// The environment variable naming the MongoDB the UE contexts are stored in, e.g.
/// `mongodb://mongo/nextgcore`. Unset (or empty): no storage, today's behaviour.
pub const DB_URI_ENV: &str = "AMF_UE_CONTEXT_DB_URI";

/// The MongoDB collection of stored UE contexts.
pub const COLLECTION: &str = "amf_ue_contexts";

/// The record format version. A record of another version is not restored.
pub const RECORD_VERSION: u32 = 1;

/// How often the stable UE contexts are compared with what was last written.
pub const PERSIST_INTERVAL: Duration = Duration::from_secs(1);

/// How far the downlink NAS COUNT moves on restore (see the module docs).
pub const DL_COUNT_RESTORE_MARGIN: u32 = 255;

/// How long the shutdown waits for the final flush to reach the store.
pub const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(3);

/// One PDU session of a stored UE: what the AMF needs to address it at its SMF again.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredSession {
    pub psi: u8,
    pub sm_context_ref: String,
    /// The SMF holding the SM context (#669), as `(host, port)`.
    pub smf: Option<(String, u16)>,
    pub s_nssai: SNssai,
    pub dnn: Option<String>,
}

/// The 5G NAS security context of a stored UE (TS 33.501 §6.3, TS 24.501 §4.4.2).
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredSecurity {
    pub nas_ksi: u8,
    pub nas_tsc: u8,
    pub nas_ue_ksi: u8,
    pub nas_ue_tsc: u8,
    pub kamf: Vec<u8>,
    pub knas_int: Vec<u8>,
    pub knas_enc: Vec<u8>,
    pub kgnb: Vec<u8>,
    pub nh: Vec<u8>,
    pub nhcc: u8,
    pub selected_int_algorithm: u8,
    pub selected_enc_algorithm: u8,
    /// The largest uplink NAS COUNT verified (TS 24.501 §4.4.3.1).
    pub ul_count: u32,
    pub ul_count_established: bool,
    /// The next downlink NAS COUNT to use.
    pub dl_count: u32,
}

/// A registered UE's context as the storage entity holds it.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredUeContext {
    pub version: u32,
    /// The `nfInstanceId` of the AMF that wrote it.
    pub amf_instance_id: String,
    pub supi: String,
    pub suci: String,
    pub gpsi: Option<String>,
    pub pei: Option<String>,
    pub imeisv: Option<String>,
    pub msisdn: Vec<String>,
    pub home_plmn_id: PlmnId,
    pub guti: Guti5gs,
    pub tai: Tai5gs,
    pub cgi: NrCgi,
    pub access_type: u8,
    pub registration_type: u8,
    pub requested_nssai: Vec<SNssai>,
    pub allowed_nssai: Vec<SNssai>,
    pub rejected_nssai: Vec<SNssai>,
    pub ue_ambr: Bitrate,
    pub gmm_capability: GmmCapability,
    pub ue_security_capability: UeSecurityCapability,
    pub ue_network_capability: UeNetworkCapability,
    pub redcap_indication: bool,
    pub slice_admission_granted: bool,
    pub racs_supported: bool,
    pub ue_radio_capability_id: Option<Vec<u8>>,
    pub ue_radio_capability_id_known_to_ue: bool,
    pub assigned_ebis: Vec<AssignedEbi>,
    /// The token of the UE's current UECM registration's `deregCallbackUri` (#753).
    pub uecm_dereg_token: Option<String>,
    pub sdm_subscription_id: Option<String>,
    pub policy_association: PolicyAssociation,
    pub ue_policy_association: PolicyAssociation,
    pub security: StoredSecurity,
    pub sessions: Vec<StoredSession>,
    /// CM-CONNECTED when written: its N2 connection is released on restore.
    pub cm_connected: bool,
}

/// Manual `Debug` (#861): no key, COUNT or token in a log line.
impl std::fmt::Debug for StoredUeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredUeContext")
            .field("version", &self.version)
            .field("supi", &self.supi)
            .field("guti_tmsi", &format_args!("{:#010x}", self.guti.tmsi))
            .field("sessions", &self.sessions.len())
            .field("cm_connected", &self.cm_connected)
            .finish_non_exhaustive()
    }
}

/// Where the records live.
pub trait UeContextBackend: Send + Sync + 'static {
    /// Write (insert or replace) the record of `rec.supi`.
    fn put(&self, rec: &StoredUeContext) -> Result<(), String>;
    /// Delete the record of `supi`, if any.
    fn delete(&self, supi: &str) -> Result<(), String>;
    /// Every record written by the AMF instance `amf_instance_id`.
    fn load(&self, amf_instance_id: &str) -> Result<Vec<StoredUeContext>, String>;
}

/// The MongoDB storage entity: one document per SUPI in [`COLLECTION`], `_id` = SUPI,
/// with the writer's instance id beside the record so a restart loads only its own.
pub struct MongoBackend {
    collection: mongodb::sync::Collection<mongodb::bson::Document>,
}

impl MongoBackend {
    /// Connect to `uri`. The database is the URI's (`mongodb://host/<db>`), else
    /// `nextgcore`, the UDR's. Blocking: run it off the async runtime.
    pub fn connect(uri: &str) -> Result<Self, String> {
        let client = mongodb::sync::Client::with_uri_str(uri).map_err(|e| e.to_string())?;
        let db = client
            .default_database()
            .unwrap_or_else(|| client.database("nextgcore"));
        db.run_command(mongodb::bson::doc! { "ping": 1 }, None)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            collection: db.collection(COLLECTION),
        })
    }
}

impl UeContextBackend for MongoBackend {
    fn put(&self, rec: &StoredUeContext) -> Result<(), String> {
        use mongodb::bson::doc;
        let record = mongodb::bson::to_bson(rec).map_err(|e| e.to_string())?;
        self.collection
            .replace_one(
                doc! { "_id": &rec.supi },
                doc! {
                    "_id": &rec.supi,
                    "amf_instance_id": &rec.amf_instance_id,
                    "record": record,
                },
                mongodb::options::ReplaceOptions::builder()
                    .upsert(true)
                    .build(),
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn delete(&self, supi: &str) -> Result<(), String> {
        self.collection
            .delete_one(mongodb::bson::doc! { "_id": supi }, None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn load(&self, amf_instance_id: &str) -> Result<Vec<StoredUeContext>, String> {
        let cursor = self
            .collection
            .find(
                mongodb::bson::doc! { "amf_instance_id": amf_instance_id },
                None,
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for doc in cursor {
            let doc = doc.map_err(|e| e.to_string())?;
            let id = doc.get_str("_id").unwrap_or("?").to_string();
            match doc
                .get("record")
                .cloned()
                .map(mongodb::bson::from_bson::<StoredUeContext>)
            {
                Some(Ok(rec)) => out.push(rec),
                Some(Err(e)) => log::warn!("Stored UE context {id} is unreadable: {e}"),
                None => log::warn!("Stored UE context {id} has no record"),
            }
        }
        Ok(out)
    }
}

/// An in-process backend, for tests and for a deployment that wants none persisted
/// across processes.
#[derive(Default)]
pub struct MemoryBackend {
    records: std::sync::Mutex<HashMap<String, StoredUeContext>>,
}

impl MemoryBackend {
    /// The record of `supi`, if stored.
    pub fn get(&self, supi: &str) -> Option<StoredUeContext> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(supi)
            .cloned()
    }
}

impl UeContextBackend for MemoryBackend {
    fn put(&self, rec: &StoredUeContext) -> Result<(), String> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(rec.supi.clone(), rec.clone());
        Ok(())
    }

    fn delete(&self, supi: &str) -> Result<(), String> {
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(supi);
        Ok(())
    }

    fn load(&self, amf_instance_id: &str) -> Result<Vec<StoredUeContext>, String> {
        Ok(self
            .records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|r| r.amf_instance_id == amf_instance_id)
            .cloned()
            .collect())
    }
}

enum WriterOp {
    Put(Box<StoredUeContext>),
    Delete(String),
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// The writer: a thread of its own doing the blocking store calls in order, so the
/// NGAP task only ever enqueues.
pub struct UeContextWriter {
    tx: std::sync::mpsc::Sender<WriterOp>,
}

impl UeContextWriter {
    pub fn spawn(backend: Arc<dyn UeContextBackend>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<WriterOp>();
        let spawned = std::thread::Builder::new()
            .name("amf-ue-store".into())
            .spawn(move || {
                for op in rx {
                    match op {
                        WriterOp::Put(rec) => {
                            if let Err(e) = backend.put(&rec) {
                                log::warn!("UE context of {} not stored: {e}", rec.supi);
                            }
                        }
                        WriterOp::Delete(supi) => {
                            if let Err(e) = backend.delete(&supi) {
                                log::warn!("Stored UE context of {supi} not deleted: {e}");
                            }
                        }
                        WriterOp::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            log::error!("The UE context writer thread did not start: {e}");
        }
        Self { tx }
    }

    fn put(&self, rec: StoredUeContext) {
        let _ = self.tx.send(WriterOp::Put(Box::new(rec)));
    }

    fn delete(&self, supi: &str) {
        let _ = self.tx.send(WriterOp::Delete(supi.to_string()));
    }

    /// Resolves once everything enqueued before it reached the store.
    fn flush(&self) -> tokio::sync::oneshot::Receiver<()> {
        let (done, wait) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(WriterOp::Flush(done));
        wait
    }
}

/// The storage state an [`NgapServer`] keeps.
pub(super) struct UeContextStore {
    writer: UeContextWriter,
    /// What was last written per SUPI (or restored), compared on each sweep.
    persisted: HashMap<String, StoredUeContext>,
    last_sweep: std::time::Instant,
}

impl UeContextStore {
    pub(super) fn new(writer: UeContextWriter) -> Self {
        Self {
            writer,
            persisted: HashMap::new(),
            last_sweep: std::time::Instant::now(),
        }
    }
}

/// What [`NgapServer::persist_ue_contexts`] did, for tests and the log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PersistSummary {
    pub written: usize,
    pub deleted: usize,
}

/// What [`NgapServer::restore_ue_contexts`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoreSummary {
    /// The restored UEs, by their new AMF UE NGAP IDs.
    pub restored: Vec<u64>,
    /// Of those, the ones CM-CONNECTED when written, whose N2 connection was released.
    pub released: usize,
    pub skipped: usize,
}

fn key<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    <[u8; N]>::try_from(bytes).ok()
}

impl NgapServer {
    /// Arm the UE context storage (#686): records are written from now on. `persisted`
    /// is what the store already holds for the UEs being restored, so they are not
    /// written again until they change.
    pub(super) fn attach_ue_context_store(&mut self, writer: UeContextWriter) {
        self.ue_context_store = Some(UeContextStore::new(writer));
    }

    /// The record of the UE `amf_ue_ngap_id` holds, if it is in a stable state worth
    /// storing: registered, with a SUPI and a NAS security context, no NAS procedure
    /// waiting on the UE, and not an unauthenticated emergency registration (TS 33.501
    /// §10.2.2, which has no key hierarchy to restore).
    fn stored_ue_context(
        &self,
        amf_ue_ngap_id: u64,
        state: &UeNasContext,
        amf_instance_id: &str,
    ) -> Option<StoredUeContext> {
        let ue = &state.amf_ue;
        if !state.registered
            || state.retx.is_some()
            || state.registration_session_ies.is_some()
            || !ue.security_context_available
            || ue.unauthenticated_emergency
        {
            return None;
        }
        let supi = ue.supi.clone()?;
        let sessions = {
            let ctx = crate::context::amf_self();
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            let mut sessions: Vec<StoredSession> = self
                .sm_context_refs
                .iter()
                .filter(|((ue_id, _), _)| *ue_id == amf_ue_ngap_id)
                .map(|((_, psi), sm_ref)| {
                    let sess = guard.sess_find_by_psi(amf_ue_ngap_id, *psi);
                    StoredSession {
                        psi: *psi,
                        sm_context_ref: sm_ref.clone(),
                        smf: self.sm_context_smfs.get(&(amf_ue_ngap_id, *psi)).cloned(),
                        s_nssai: sess.as_ref().map(|s| s.s_nssai.clone()).unwrap_or_default(),
                        dnn: sess.and_then(|s| s.dnn),
                    }
                })
                .collect();
            sessions.sort_by_key(|s| s.psi);
            sessions
        };
        Some(StoredUeContext {
            version: RECORD_VERSION,
            amf_instance_id: amf_instance_id.to_string(),
            supi,
            suci: state.suci.clone(),
            gpsi: ue.gpsi.clone(),
            pei: ue.pei.clone(),
            imeisv: ue.imeisv.clone(),
            msisdn: ue.msisdn.clone(),
            home_plmn_id: ue.home_plmn_id.clone(),
            guti: ue.current_guti.clone(),
            tai: ue.nr_tai.clone(),
            cgi: ue.nr_cgi.clone(),
            access_type: ue.access_type,
            registration_type: ue.registration_type,
            requested_nssai: ue.requested_nssai.clone(),
            allowed_nssai: ue.allowed_nssai.clone(),
            rejected_nssai: ue.rejected_nssai.clone(),
            ue_ambr: ue.ue_ambr.clone(),
            gmm_capability: ue.gmm_capability.clone(),
            ue_security_capability: ue.ue_security_capability.clone(),
            ue_network_capability: ue.ue_network_capability.clone(),
            redcap_indication: ue.redcap_indication,
            slice_admission_granted: ue.slice_admission_granted,
            racs_supported: ue.racs_supported,
            ue_radio_capability_id: ue.ue_radio_capability_id.clone(),
            ue_radio_capability_id_known_to_ue: ue.ue_radio_capability_id_known_to_ue,
            assigned_ebis: ue.assigned_ebis.clone(),
            uecm_dereg_token: ue.uecm_dereg_token.clone(),
            sdm_subscription_id: state.sdm_subscription_id.clone(),
            policy_association: ue.policy_association.clone(),
            ue_policy_association: ue.ue_policy_association.clone(),
            security: StoredSecurity {
                nas_ksi: ue.nas_ksi,
                nas_tsc: ue.nas_tsc,
                nas_ue_ksi: ue.nas_ue_ksi,
                nas_ue_tsc: ue.nas_ue_tsc,
                kamf: ue.kamf.to_vec(),
                knas_int: ue.knas_int.to_vec(),
                knas_enc: ue.knas_enc.to_vec(),
                kgnb: ue.kgnb.to_vec(),
                nh: ue.nh.to_vec(),
                nhcc: ue.nhcc,
                selected_int_algorithm: ue.selected_int_algorithm,
                selected_enc_algorithm: ue.selected_enc_algorithm,
                ul_count: ue.ul_count,
                ul_count_established: ue.ul_count_established,
                dl_count: ue.dl_count,
            },
            sessions,
            cm_connected: !state.cm_idle,
        })
    }

    /// Write what changed since the last sweep (#686): every stable UE whose record
    /// differs from the one last written, and a delete for every stored SUPI no UE is
    /// held under any more. A UE in the middle of a procedure keeps its last stable
    /// record. Runs at most every [`PERSIST_INTERVAL`] unless `force`.
    pub(super) fn persist_ue_contexts(&mut self, force: bool) -> PersistSummary {
        let mut summary = PersistSummary::default();
        let due = self
            .ue_context_store
            .as_ref()
            .is_some_and(|s| force || s.last_sweep.elapsed() >= PERSIST_INTERVAL);
        if !due {
            return summary;
        }
        let instance =
            nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Amf);
        let mut current: HashMap<String, StoredUeContext> = HashMap::new();
        let mut held: HashSet<String> = HashSet::new();
        for (id, state) in self.ue_auth_state.snapshot() {
            if let Some(rec) = self.stored_ue_context(id, &state, instance) {
                held.insert(rec.supi.clone());
                current.insert(rec.supi.clone(), rec);
            } else if state.registered {
                // Mid-procedure: its last stable record stays.
                if let Some(supi) = &state.amf_ue.supi {
                    held.insert(supi.clone());
                }
            }
        }
        let Some(store) = self.ue_context_store.as_mut() else {
            return summary;
        };
        store.last_sweep = std::time::Instant::now();
        for (supi, rec) in current {
            if store.persisted.get(&supi) != Some(&rec) {
                store.writer.put(rec.clone());
                store.persisted.insert(supi, rec);
                summary.written += 1;
            }
        }
        let gone: Vec<String> = store
            .persisted
            .keys()
            .filter(|s| !held.contains(*s))
            .cloned()
            .collect();
        for supi in gone {
            store.writer.delete(&supi);
            store.persisted.remove(&supi);
            summary.deleted += 1;
        }
        if summary != PersistSummary::default() {
            log::debug!(
                "UE contexts: {} written, {} deleted",
                summary.written,
                summary.deleted
            );
        }
        summary
    }

    /// A last sweep, then wait (bounded) until the writer has stored it: the shutdown's
    /// flush (#686).
    pub(super) async fn flush_ue_contexts(&mut self, timeout: Duration) {
        self.persist_ue_contexts(true);
        let Some(store) = self.ue_context_store.as_ref() else {
            return;
        };
        let wait = store.writer.flush();
        if tokio::time::timeout(timeout, wait).await.is_err() {
            log::warn!("UE contexts: the shutdown flush did not complete within {timeout:?}");
        } else {
            log::info!("UE contexts: {} stored at shutdown", store.persisted.len());
        }
    }

    /// Restore stored UE contexts as registered UEs (#686), before any NG association is
    /// accepted. Each becomes a CM-IDLE registered UE under a new AMF UE NGAP ID:
    /// - its sessions are addressable at their SMFs again;
    /// - its mobile reachable timer starts;
    /// - its downlink NAS COUNT moves on by [`DL_COUNT_RESTORE_MARGIN`].
    ///
    /// A UE that was CM-CONNECTED has its N2 connection released as an NG Reset would
    /// release it, with its user planes DEACTIVATED at the SMFs (TS 23.502 §4.2.6).
    ///
    /// Skipped (left in the store): a record of another version or another AMF instance,
    /// one whose 5G-GUTI this AMF does not serve, one with malformed keys, or a SUPI
    /// already held.
    pub(super) async fn restore_ue_contexts(
        &mut self,
        records: Vec<StoredUeContext>,
    ) -> RestoreSummary {
        let instance =
            nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Amf);
        let served = self.served_guamis();
        let mut summary = RestoreSummary::default();
        let mut connected = Vec::new();
        let mut held: HashSet<String> = self
            .ue_auth_state
            .snapshot()
            .into_iter()
            .filter_map(|(_, s)| s.amf_ue.supi.clone())
            .collect();
        for rec in records {
            let serves = guti_served(&served, &rec.guti);
            let already = held.contains(&rec.supi);
            if rec.version != RECORD_VERSION
                || rec.amf_instance_id != instance
                || !serves
                || already
            {
                log::info!(
                    "Stored UE context of {} not restored (version {}, another AMF instance: \
                     {}, GUTI served: {serves}, already held: {already})",
                    rec.supi,
                    rec.version,
                    rec.amf_instance_id != instance
                );
                summary.skipped += 1;
                continue;
            }
            let id = self.allocate_amf_ue_ngap_id();
            let Some(state) = restored_ue(id, &rec) else {
                log::warn!(
                    "Stored UE context of {} has malformed keys; not restored",
                    rec.supi
                );
                summary.skipped += 1;
                continue;
            };
            self.ue_auth_state.insert(id, state);
            held.insert(rec.supi.clone());
            for s in &rec.sessions {
                self.sm_context_refs
                    .insert((id, s.psi), s.sm_context_ref.clone());
                if let Some(smf) = &s.smf {
                    self.sm_context_smfs.insert((id, s.psi), smf.clone());
                }
                let ctx = crate::context::amf_self();
                let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
                if let Some(mut sess) = guard.sess_add(id, s.psi) {
                    sess.sm_context_ref = Some(s.sm_context_ref.clone());
                    sess.s_nssai = s.s_nssai.clone();
                    sess.dnn = s.dnn.clone();
                    guard.sess_update(&sess);
                }
            }
            log::info!(
                "UE context of {} restored as UE {id}: {} PDU session(s), CM-{} when stored",
                rec.supi,
                rec.sessions.len(),
                if rec.cm_connected {
                    "CONNECTED"
                } else {
                    "IDLE"
                }
            );
            if let Some(store) = self.ue_context_store.as_mut() {
                store.persisted.insert(rec.supi.clone(), rec.clone());
            }
            if rec.cm_connected {
                connected.push(id);
            } else {
                self.start_reachability_supervision(id).await;
            }
            summary.restored.push(id);
        }
        if !connected.is_empty() {
            let (released, smf_work) = self.release_ng_connections(connected).await;
            summary.released = released;
            for call in smf_work {
                self.offload_ng_reset_smf_call(call);
            }
        }
        summary
    }
}

/// A served GUAMI as `(PLMN, AMF Region ID, AMF Set ID, AMF Pointer)`.
pub(super) type ServedGuami = (PlmnId, u8, u16, u8);

/// Whether `guti` names one of the `served` GUAMIs (TS 23.003 §2.10.1): only then can a
/// UE holding it reach this AMF. No GUAMI configured serves every GUTI.
pub(super) fn guti_served(served: &[ServedGuami], guti: &Guti5gs) -> bool {
    served.is_empty()
        || served.iter().any(|(plmn, region, set, pointer)| {
            *plmn == guti.plmn_id
                && *region == guti.amf_region_id
                && *set == guti.amf_set_id
                && *pointer == guti.amf_pointer
        })
}

impl NgapServer {
    /// This AMF's served GUAMIs. Tests fix them with `served_guami_override`, because the
    /// configured ones are process-global and other tests set them.
    fn served_guamis(&self) -> Vec<ServedGuami> {
        #[cfg(test)]
        if let Some(fixed) = &self.served_guami_override {
            return fixed.clone();
        }
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        guard
            .served_guami
            .iter()
            .map(|g| {
                (
                    g.plmn_id.clone(),
                    g.amf_id.region,
                    g.amf_id.set,
                    g.amf_id.pointer,
                )
            })
            .collect()
    }
}

/// A registered UE rebuilt from its record, under `amf_ue_ngap_id`, with no NG
/// connection. `None` when a stored key has the wrong length.
fn restored_ue(amf_ue_ngap_id: u64, rec: &StoredUeContext) -> Option<UeNasContext> {
    let sec = &rec.security;
    let mut state = UeNasContext::new(amf_ue_ngap_id, 0, 0, crate::context::nas_security_canary());
    let ue = &mut state.amf_ue;
    ue.kamf = key(&sec.kamf)?;
    ue.knas_int = key(&sec.knas_int)?;
    ue.knas_enc = key(&sec.knas_enc)?;
    ue.kgnb = key(&sec.kgnb)?;
    ue.nh = key(&sec.nh)?;
    ue.nhcc = sec.nhcc;
    ue.nas_ksi = sec.nas_ksi;
    ue.nas_tsc = sec.nas_tsc;
    ue.nas_ue_ksi = sec.nas_ue_ksi;
    ue.nas_ue_tsc = sec.nas_ue_tsc;
    ue.selected_int_algorithm = sec.selected_int_algorithm;
    ue.selected_enc_algorithm = sec.selected_enc_algorithm;
    ue.ul_count = sec.ul_count;
    ue.ul_count_established = sec.ul_count_established;
    ue.dl_count = (sec.dl_count + DL_COUNT_RESTORE_MARGIN) & 0x00ff_ffff;
    ue.security_context_available = true;
    ue.supi = Some(rec.supi.clone());
    ue.suci = (!rec.suci.is_empty()).then(|| rec.suci.clone());
    ue.gpsi = rec.gpsi.clone();
    ue.pei = rec.pei.clone();
    ue.imeisv = rec.imeisv.clone();
    ue.msisdn = rec.msisdn.clone();
    ue.num_of_msisdn = rec.msisdn.len();
    ue.home_plmn_id = rec.home_plmn_id.clone();
    ue.current_guti = rec.guti.clone();
    ue.next_guti = rec.guti.clone();
    ue.current_m_tmsi = Some(rec.guti.tmsi);
    ue.nr_tai = rec.tai.clone();
    ue.nr_cgi = rec.cgi.clone();
    ue.access_type = rec.access_type;
    ue.registration_type = rec.registration_type;
    ue.requested_nssai = rec.requested_nssai.clone();
    ue.allowed_nssai = rec.allowed_nssai.clone();
    ue.rejected_nssai = rec.rejected_nssai.clone();
    ue.ue_ambr = rec.ue_ambr.clone();
    ue.gmm_capability = rec.gmm_capability.clone();
    ue.ue_security_capability = rec.ue_security_capability.clone();
    ue.ue_network_capability = rec.ue_network_capability.clone();
    ue.redcap_indication = rec.redcap_indication;
    ue.slice_admission_granted = rec.slice_admission_granted;
    ue.racs_supported = rec.racs_supported;
    ue.ue_radio_capability_id = rec.ue_radio_capability_id.clone();
    ue.ue_radio_capability_id_known_to_ue = rec.ue_radio_capability_id_known_to_ue;
    ue.assigned_ebis = rec.assigned_ebis.clone();
    ue.uecm_dereg_token = rec.uecm_dereg_token.clone();
    ue.policy_association = rec.policy_association.clone();
    ue.ue_policy_association = rec.ue_policy_association.clone();
    state.suci = rec.suci.clone();
    state.registered = true;
    state.restored = true;
    state.registration_accept_sent = true;
    state.cm_idle = !rec.cm_connected;
    state.sdm_subscription_id = rec.sdm_subscription_id.clone();
    state.policy_association_id = rec.policy_association.id.clone();
    state.ue_policy_association_id = rec.ue_policy_association.id.clone();
    state.gmm_fsm.transition_to_registered();
    Some(state)
}

/// Arm the storage from [`DB_URI_ENV`] and restore this AMF's stored UEs into `server`
/// (#686). A no-op when the variable is unset. A store that cannot be reached is
/// logged and left unarmed: the AMF serves as it would without one.
pub(super) async fn open_from_env(server: &mut NgapServer) {
    let uri = std::env::var(DB_URI_ENV).unwrap_or_default();
    let pinned = [
        nextgcore_sbi::nf_instance_id::ANY_NF_INSTANCE_ID_ENV.to_string(),
        nextgcore_sbi::nf_instance_id::type_env_var(nextgcore_sbi::types::NfType::Amf),
    ]
    .iter()
    .any(|v| std::env::var(v).is_ok_and(|id| !id.trim().is_empty()));
    if !uri.trim().is_empty() && !pinned {
        log::warn!(
            "UE context storage is armed but this AMF's nfInstanceId is not pinned \
             (NEXTGCORE_AMF_INSTANCE_ID): a restart gets a new one, and only records of the \
             same instance are restored"
        );
    }
    if uri.trim().is_empty() {
        log::info!(
            "UE context storage off ({DB_URI_ENV} unset): an AMF restart loses the UE \
             contexts, and UEs re-register on their next uplink"
        );
        return;
    }
    let connected = tokio::task::spawn_blocking(move || MongoBackend::connect(&uri)).await;
    let backend = match connected {
        Ok(Ok(b)) => Arc::new(b),
        Ok(Err(e)) => {
            log::error!("UE context storage unavailable ({DB_URI_ENV}): {e}; running without");
            return;
        }
        Err(e) => {
            log::error!("UE context storage connect panicked: {e}; running without");
            return;
        }
    };
    open_with(server, backend).await;
}

/// Restore from `backend`, then arm it for writing (#686).
pub(super) async fn open_with(server: &mut NgapServer, backend: Arc<dyn UeContextBackend>) {
    let instance = nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Amf);
    let loader = Arc::clone(&backend);
    let records = tokio::task::spawn_blocking(move || loader.load(instance))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    server.attach_ue_context_store(UeContextWriter::spawn(backend));
    match records {
        Ok(records) => {
            let found = records.len();
            let summary = server.restore_ue_contexts(records).await;
            log::info!(
                "UE context storage armed: {} of {found} stored UE context(s) restored \
                 ({} released from CM-CONNECTED, {} skipped)",
                summary.restored.len(),
                summary.released,
                summary.skipped
            );
        }
        Err(e) => log::error!("Stored UE contexts could not be read: {e}; none restored"),
    }
}
