//! EMM Message Handling
//!
//! Port of src/mme/emm-handler.c - EMM message handling functions

use crate::context::{EnbUe, EpsTai, MmeUe, PlmnId, NEXTGCORE_AUTS_LEN};
use crate::emm_build::EmmCause;

// ============================================================================
// EMM Handler Result
// ============================================================================

/// Result type for EMM handlers
pub type EmmResult<T> = Result<T, EmmError>;

/// EMM error types
#[derive(Debug, Clone)]
pub enum EmmError {
    /// Invalid message format
    InvalidMessage(String),
    /// Security failure
    SecurityFailure(String),
    /// Protocol error
    ProtocolError(EmmCause),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for EmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmmError::InvalidMessage(msg) => write!(f, "Invalid message: {msg}"),
            EmmError::SecurityFailure(msg) => write!(f, "Security failure: {msg}"),
            EmmError::ProtocolError(cause) => write!(f, "Protocol error: {cause:?}"),
            EmmError::InternalError(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for EmmError {}

// ============================================================================
// Attach Request Handling
// ============================================================================

/// Parsed attach request data
#[derive(Debug, Clone, Default)]
pub struct AttachRequestData {
    /// EPS attach type
    pub attach_type: u8,
    /// NAS key set identifier
    pub nas_ksi: u8,
    /// TSC (Type of Security Context)
    pub tsc: u8,
    /// Mobile identity type
    pub identity_type: u8,
    /// IMSI (if provided)
    pub imsi: Option<String>,
    /// GUTI (if provided)
    pub guti: Option<ParsedGuti>,
    /// UE network capability
    pub ue_network_capability: UeNetworkCapability,
    /// MS network capability (optional)
    pub ms_network_capability: Option<MsNetworkCapability>,
    /// ESM message container
    pub esm_message: Vec<u8>,
    /// Last visited TAI (optional)
    pub last_visited_tai: Option<EpsTai>,
    /// Additional security capability (optional)
    pub additional_security_capability: Option<UeAdditionalSecurityCapability>,
}

/// Parsed GUTI
#[derive(Debug, Clone, Default)]
pub struct ParsedGuti {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// MME Group ID
    pub mme_gid: u16,
    /// MME Code
    pub mme_code: u8,
    /// M-TMSI
    pub m_tmsi: u32,
}

/// UE network capability
#[derive(Debug, Clone, Default)]
pub struct UeNetworkCapability {
    /// EEA algorithms
    pub eea: u8,
    /// EIA algorithms
    pub eia: u8,
    /// UEA algorithms
    pub uea: u8,
    /// UIA algorithms
    pub uia: u8,
}

/// MS network capability
#[derive(Debug, Clone, Default)]
pub struct MsNetworkCapability {
    /// GEA1 support
    pub gea1: bool,
    /// Extended GEA
    pub extended_gea: u8,
}

/// UE additional security capability
#[derive(Debug, Clone, Default)]
pub struct UeAdditionalSecurityCapability {
    /// 5G-EA algorithms
    pub nea: u8,
    /// 5G-IA algorithms
    pub nia: u8,
}

/// Handle attach request
pub fn handle_attach_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<AttachRequestData> {
    if data.len() < 10 {
        return Err(EmmError::InvalidMessage("Attach request too short".into()));
    }

    let mut offset = 0;

    // Skip protocol discriminator and message type (already parsed)
    // Parse EPS attach type and NAS key set identifier
    let attach_type_byte = data[offset];
    offset += 1;

    let attach_type = attach_type_byte & 0x07;
    let nas_ksi = (attach_type_byte >> 4) & 0x07;
    let tsc = (attach_type_byte >> 7) & 0x01;

    // Parse EPS mobile identity
    let identity_len = data[offset] as usize;
    offset += 1;

    if offset + identity_len > data.len() {
        return Err(EmmError::InvalidMessage("Invalid identity length".into()));
    }

    let identity_data = &data[offset..offset + identity_len];
    offset += identity_len;

    let identity_type = identity_data[0] & 0x07;
    let (imsi, guti) = parse_mobile_identity(identity_data)?;

    // Parse UE network capability
    if offset >= data.len() {
        return Err(EmmError::InvalidMessage(
            "Missing UE network capability".into(),
        ));
    }

    let ue_cap_len = data[offset] as usize;
    offset += 1;

    if offset + ue_cap_len > data.len() {
        return Err(EmmError::InvalidMessage(
            "Invalid UE capability length".into(),
        ));
    }

    let ue_network_capability = parse_ue_network_capability(&data[offset..offset + ue_cap_len]);
    offset += ue_cap_len;

    // Parse ESM message container
    if offset + 2 > data.len() {
        return Err(EmmError::InvalidMessage(
            "Missing ESM message container".into(),
        ));
    }

    let esm_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;

    if offset + esm_len > data.len() {
        return Err(EmmError::InvalidMessage(
            "Invalid ESM message length".into(),
        ));
    }

    let esm_message = data[offset..offset + esm_len].to_vec();
    offset += esm_len;

    // Parse optional IEs
    let mut last_visited_tai = None;
    let mut ms_network_capability = None;
    let mut additional_security_capability = None;

    while offset < data.len() {
        let iei = data[offset];
        offset += 1;

        match iei {
            0x52 => {
                // Last visited registered TAI
                if offset + 5 <= data.len() {
                    last_visited_tai = Some(parse_tai(&data[offset..offset + 5]));
                    offset += 5;
                }
            }
            0x31 => {
                // MS network capability
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        ms_network_capability =
                            Some(parse_ms_network_capability(&data[offset..offset + len]));
                        offset += len;
                    }
                }
            }
            0x6f => {
                // UE additional security capability
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        additional_security_capability = Some(
                            parse_additional_security_capability(&data[offset..offset + len]),
                        );
                        offset += len;
                    }
                }
            }
            _ => {
                // Skip unknown IE
                if iei & 0x80 != 0 {
                    // Type 1 or Type 2 IE (1 byte)
                } else {
                    // Type 4 IE (TLV)
                    if offset < data.len() {
                        let len = data[offset] as usize;
                        offset += 1 + len;
                    }
                }
            }
        }
    }

    // Update MME UE context
    mme_ue.nas_eps.attach_type = attach_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    mme_ue.nas_eps.mme_ksi.tsc = tsc;
    mme_ue.ue_network_capability.eea = ue_network_capability.eea;
    mme_ue.ue_network_capability.eia = ue_network_capability.eia;
    mme_ue.ue_network_capability.uea = ue_network_capability.uea;
    mme_ue.ue_network_capability.uia = ue_network_capability.uia;

    if let Some(ref imsi_str) = imsi {
        mme_ue.imsi_bcd = imsi_str.clone();
    }

    // Copy TAI and E-CGI from eNB UE
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();

    Ok(AttachRequestData {
        attach_type,
        nas_ksi,
        tsc,
        identity_type,
        imsi,
        guti,
        ue_network_capability,
        ms_network_capability,
        esm_message,
        last_visited_tai,
        additional_security_capability,
    })
}

// ============================================================================
// Attach Complete Handling
// ============================================================================

/// Handle attach complete
pub fn handle_attach_complete(
    _enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<Vec<u8>> {
    // Parse ESM message container
    if data.len() < 2 {
        return Err(EmmError::InvalidMessage("Attach complete too short".into()));
    }

    let esm_len = ((data[0] as usize) << 8) | (data[1] as usize);

    if data.len() < 2 + esm_len {
        return Err(EmmError::InvalidMessage(
            "Invalid ESM message length".into(),
        ));
    }

    let esm_message = data[2..2 + esm_len].to_vec();

    log::info!("Attach complete received for IMSI[{}]", mme_ue.imsi_bcd);

    Ok(esm_message)
}

// ============================================================================
// Authentication Response Handling
// ============================================================================

/// Handle authentication response
pub fn handle_authentication_response(
    _enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<bool> {
    // Parse authentication response parameter
    if data.is_empty() {
        return Err(EmmError::InvalidMessage(
            "Authentication response empty".into(),
        ));
    }

    let res_len = data[0] as usize;

    if data.len() < 1 + res_len {
        return Err(EmmError::InvalidMessage("Invalid RES length".into()));
    }

    let res = &data[1..1 + res_len];

    // TS 24.301 §5.4.2.4 / TS 33.401 §6.1.1: the UE returns the *whole* RES and
    // the network compares it against the whole XRES. Accepting a shorter RES
    // and comparing only that many octets — which this did — authenticates a UE
    // that guessed a prefix, so a one-octet RES had a 1-in-256 chance per try.
    if res_len == 0 || res_len != mme_ue.xres_len as usize {
        log::warn!(
            "Authentication response length {res_len} does not match the expected {} octets",
            mme_ue.xres_len
        );
        return Ok(false);
    }

    let xres = &mme_ue.xres[..res_len];

    if !constant_time_eq(res, xres) {
        log::warn!("Authentication response mismatch");
        log::debug!("  RES: {res:02x?}");
        log::debug!("  XRES: {xres:02x?}");
        return Ok(false);
    }

    log::info!("Authentication successful for IMSI[{}]", mme_ue.imsi_bcd);

    Ok(true)
}

/// Compare two byte strings without an early exit on the first differing octet.
///
/// The length check does short-circuit, which is fine: the RES length travels in
/// the clear in the message. What must not leak is *where* the first difference
/// is, since that would let a peer recover XRES octet by octet.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

// ============================================================================
// Authentication Failure Handling
// ============================================================================

/// What the UE reported in an AUTHENTICATION FAILURE (TS 24.301 §5.4.2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationFailure {
    /// EMM cause #20: the UE could not verify the AUTN MAC.
    MacFailure,
    /// EMM cause #21: the USIM's SQN is out of range; re-synchronise with AUTS.
    SynchFailure(Box<[u8; NEXTGCORE_AUTS_LEN]>),
    /// EMM cause #26 or anything else the UE reported.
    Other(u8),
}

/// Handle authentication failure (TS 24.301 §5.4.2.7, §8.2.5).
///
/// The message carries a mandatory EMM cause and, for a synch failure, an
/// Authentication Failure Parameter IE (0x30) holding the 14-octet AUTS.
pub fn handle_authentication_failure(
    _enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<AuthenticationFailure> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage(
            "Authentication failure empty".into(),
        ));
    }

    let emm_cause = data[0];
    match emm_cause {
        emm_cause::MAC_FAILURE => {
            log::warn!("[{}] Authentication Failure: MAC failure", mme_ue.imsi_bcd);
            Ok(AuthenticationFailure::MacFailure)
        }
        emm_cause::SYNCH_FAILURE => {
            // Authentication Failure Parameter: IEI 0x30, length, AUTS.
            let mut offset = 1;
            while offset + 1 < data.len() {
                let iei = data[offset];
                let len = data[offset + 1] as usize;
                let value_start = offset + 2;
                if iei == AUTHENTICATION_FAILURE_PARAMETER_IEI {
                    if len != NEXTGCORE_AUTS_LEN || value_start + len > data.len() {
                        return Err(EmmError::InvalidMessage(format!(
                            "Authentication Failure Parameter is {len} octets, expected \
                             {NEXTGCORE_AUTS_LEN}"
                        )));
                    }
                    let mut auts = [0u8; NEXTGCORE_AUTS_LEN];
                    auts.copy_from_slice(&data[value_start..value_start + len]);
                    log::warn!(
                        "[{}] Authentication Failure: synch failure, AUTS received",
                        mme_ue.imsi_bcd
                    );
                    return Ok(AuthenticationFailure::SynchFailure(Box::new(auts)));
                }
                offset = value_start + len;
            }
            // TS 24.301 §5.4.2.7 d): the AUTS is mandatory for cause #21.
            Err(EmmError::InvalidMessage(
                "Synch failure without an Authentication Failure Parameter".into(),
            ))
        }
        other => {
            log::warn!(
                "[{}] Authentication Failure: EMM cause #{other}",
                mme_ue.imsi_bcd
            );
            Ok(AuthenticationFailure::Other(other))
        }
    }
}

/// IEI of the Authentication Failure Parameter (TS 24.301 §9.9.3.1).
const AUTHENTICATION_FAILURE_PARAMETER_IEI: u8 = 0x30;

/// EMM cause values used by the authentication abnormal cases.
mod emm_cause {
    /// #20 MAC failure
    pub const MAC_FAILURE: u8 = 20;
    /// #21 Synch failure
    pub const SYNCH_FAILURE: u8 = 21;
}

// ============================================================================
// Identity Response Handling
// ============================================================================

/// Handle identity response
pub fn handle_identity_response(
    _enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<Option<String>> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Identity response empty".into()));
    }

    let identity_len = data[0] as usize;

    if data.len() < 1 + identity_len {
        return Err(EmmError::InvalidMessage("Invalid identity length".into()));
    }

    let identity_data = &data[1..1 + identity_len];
    let identity_type = identity_data[0] & 0x07;

    match identity_type {
        1 => {
            // IMSI
            let imsi = decode_imsi(identity_data)?;
            mme_ue.imsi_bcd = imsi.clone();
            log::info!("Identity response: IMSI[{imsi}]");
            Ok(Some(imsi))
        }
        2 => {
            // IMEI
            let imei = decode_imei(identity_data)?;
            log::info!("Identity response: IMEI[{imei}]");
            Ok(Some(imei))
        }
        3 => {
            // IMEISV
            let imeisv = decode_imeisv(identity_data)?;
            mme_ue.imeisv_bcd = imeisv.clone();
            log::info!("Identity response: IMEISV[{imeisv}]");
            Ok(Some(imeisv))
        }
        _ => {
            log::warn!("Unknown identity type: {identity_type}");
            Ok(None)
        }
    }
}

// ============================================================================
// Security Mode Complete Handling
// ============================================================================

/// Handle security mode complete
pub fn handle_security_mode_complete(
    _enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<Option<String>> {
    let mut offset = 0;
    let mut imeisv = None;

    // Parse optional IEs
    while offset < data.len() {
        let iei = data[offset];
        offset += 1;

        match iei {
            0x23 => {
                // IMEISV
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        let imeisv_data = &data[offset..offset + len];
                        if let Ok(decoded) = decode_imeisv(imeisv_data) {
                            mme_ue.imeisv_bcd = decoded.clone();
                            imeisv = Some(decoded);
                        }
                        offset += len;
                    }
                }
            }
            _ => {
                // Skip unknown IE
                if iei & 0x80 != 0 {
                    // Type 1 or Type 2 IE
                } else if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1 + len;
                }
            }
        }
    }

    mme_ue.security_context_available = true;
    log::info!("Security mode complete for IMSI[{}]", mme_ue.imsi_bcd);

    Ok(imeisv)
}

// ============================================================================
// TAU Request Handling
// ============================================================================

/// IEI of the `UE status` IE in TRACKING AREA UPDATE REQUEST.
///
/// TS 24.301 Table 8.2.29.1 (`24301-k00.txt:36942`): IEI `6D`, optional, format TLV,
/// length 3.
pub const IEI_UE_STATUS: u8 = 0x6D;

/// `5GMM registration status` (`N1 mode reg`) — octet 3, **bit 2** of the UE status IE.
///
/// TS 24.501 Table 9.11.3.56.1
/// (`24501-k00_5_Main-Body_s09_s10.txt:11556-11560`): bit 2 set means *"UE is in
/// 5GMM-REGISTERED state"*. Bit **1** is `S1 mode reg` (EMM registration status), which
/// TS 24.301 NOTE 6 (`24301-k00.txt:17076-17077`) says *"is not used by the MME"* — so
/// masking the wrong bit reads a field the spec tells the MME to ignore, and the N26 leg
/// would never fire.
pub const UE_STATUS_N1_MODE_REG_BIT: u8 = 0x02;

/// IEI of the `Old GUTI type` IE in TRACKING AREA UPDATE REQUEST.
///
/// TS 24.301 Table 8.2.29.1 (`24301-k00.txt:36702`): IEI `E-`, optional, format TV,
/// length 1 — a type-1 IE, so the value rides in the low nibble of the same octet.
pub const IEI_OLD_GUTI_TYPE: u8 = 0xE0;

/// Parsed TAU request data
#[derive(Debug, Clone, Default)]
pub struct TauRequestData {
    /// EPS update type
    pub update_type: u8,
    /// Active flag
    pub active_flag: bool,
    /// NAS key set identifier
    pub nas_ksi: u8,
    /// TSC
    pub tsc: u8,
    /// Old GUTI
    pub old_guti: Option<ParsedGuti>,
    /// UE network capability (optional)
    pub ue_network_capability: Option<UeNetworkCapability>,
    /// Last visited TAI (optional)
    pub last_visited_tai: Option<EpsTai>,
    /// Did the UE say it is still registered in 5GMM? (`UE status` IE, `N1 mode reg`).
    ///
    /// # This, and NOT the GUTI type, is how the MME knows the TAU came from 5GS
    ///
    /// The intuitive discriminator — "the Old GUTI is a *mapped* GUTI" — is wrong, and
    /// TS 24.301 §5.5.3.2.2 **case z** (`24301-k00.txt:17068-17074`) says so in as many
    /// words. The UE moving from N1 mode to S1 mode
    ///
    /// > shall include a GUTI, mapped from 5G-GUTI [...] in the Old GUTI IE [...] In
    /// > addition, the UE shall include Old GUTI type IE with GUTI set to **"Native
    /// > GUTI"**, and the UE shall include a **UE status IE with a 5GMM registration
    /// > status set to "UE is in 5GMM-REGISTERED state"**.
    ///
    /// So an inter-system TAU arrives with `Old GUTI type = Native`, indistinguishable
    /// from an intra-EPS TAU on that field alone. An implementation keyed on "mapped
    /// GUTI" would compile, pass a round-trip test, and **never fire** — the
    /// "correct but unreachable" defect, reached through a wrong premise rather than
    /// through a missing caller.
    ///
    /// `false` when the IE is absent, which is fail-closed: sending a Context Request to
    /// an AMF for a UE that never claimed a 5GS registration asks a peer about a context
    /// that does not exist.
    pub five_gmm_registered: bool,
    /// The `Old GUTI type` value (`false` = Native, `true` = Mapped), when present.
    ///
    /// Recorded but **not** used to route; see [`Self::five_gmm_registered`]. Kept
    /// because TS 23.401 §4.3.19.3 makes it the discriminator for the *other* mapping —
    /// a GUTI mapped from a **P-TMSI/RAI**, i.e. an old SGSN — so a reader who finds
    /// only the UE status check can see this field was considered rather than missed.
    pub old_guti_type_mapped: Option<bool>,
}

/// Handle TAU request
pub fn handle_tau_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<TauRequestData> {
    if data.len() < 12 {
        return Err(EmmError::InvalidMessage("TAU request too short".into()));
    }

    let mut offset = 0;

    // Parse EPS update type and NAS key set identifier
    let update_type_byte = data[offset];
    offset += 1;

    let update_type = update_type_byte & 0x07;
    let active_flag = (update_type_byte & 0x08) != 0;
    let nas_ksi = (update_type_byte >> 4) & 0x07;
    let tsc = (update_type_byte >> 7) & 0x01;

    // Parse old GUTI
    let guti_len = data[offset] as usize;
    offset += 1;

    if offset + guti_len > data.len() {
        return Err(EmmError::InvalidMessage("Invalid GUTI length".into()));
    }

    let guti_data = &data[offset..offset + guti_len];
    let (_, old_guti) = parse_mobile_identity(guti_data)?;
    offset += guti_len;

    // Parse optional IEs
    let mut ue_network_capability = None;
    let mut last_visited_tai = None;
    let mut five_gmm_registered = false;
    let mut old_guti_type_mapped = None;

    while offset < data.len() {
        let iei = data[offset];
        offset += 1;

        match iei {
            0x31 => {
                // UE network capability
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        ue_network_capability =
                            Some(parse_ue_network_capability(&data[offset..offset + len]));
                        offset += len;
                    }
                }
            }
            0x52 => {
                // Last visited registered TAI
                if offset + 5 <= data.len() {
                    last_visited_tai = Some(parse_tai(&data[offset..offset + 5]));
                    offset += 5;
                }
            }
            IEI_UE_STATUS => {
                // UE status (TLV, length 3 => one contents octet). The IE the default
                // arm below used to walk past, and the one that makes the 5GS→EPS move
                // visible to the MME at all (#347). See `five_gmm_registered`.
                if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1;
                    if offset + len <= data.len() {
                        // Octet 3 is the first contents octet. A zero-length contents
                        // field is not legal (§9.11.3.56 fixes the IE at 3 octets), and
                        // reads as "not claimed" rather than as an error, for the same
                        // fail-closed reason the field's doc gives.
                        five_gmm_registered = data
                            .get(offset)
                            .is_some_and(|o| o & UE_STATUS_N1_MODE_REG_BIT != 0);
                        offset += len;
                    }
                }
            }
            _ if iei & 0xF0 == IEI_OLD_GUTI_TYPE => {
                // Old GUTI type: a TYPE 1 IE, so the IEI is the high nibble and the
                // value is bit 1 of the SAME octet -- there is no length and no
                // following value octet (TS 24.301 §9.9.3.45, `24301-k00.txt:44831`:
                // "The GUTI type is a type 1 information element", and Table 9.9.3.45.1
                // gives 0 = Native GUTI, 1 = Mapped GUTI).
                //
                // Matched on the high nibble because the default arm below would
                // otherwise treat `0xE1` as an unknown type-1 IE and skip it, which is
                // harmless but loses the value.
                old_guti_type_mapped = Some(iei & 0x01 != 0);
            }
            _ => {
                // Skip unknown IE
                if iei & 0x80 != 0 {
                    // Type 1 or Type 2 IE
                } else if offset < data.len() {
                    let len = data[offset] as usize;
                    offset += 1 + len;
                }
            }
        }
    }

    // Update MME UE context
    mme_ue.nas_eps.update_type = update_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    mme_ue.nas_eps.mme_ksi.tsc = tsc;
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();

    Ok(TauRequestData {
        update_type,
        active_flag,
        nas_ksi,
        tsc,
        old_guti,
        ue_network_capability,
        last_visited_tai,
        five_gmm_registered,
        old_guti_type_mapped,
    })
}

// ============================================================================
// Service Request Handling
// ============================================================================

/// Handle service request
pub fn handle_service_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<(u8, u8)> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Service request empty".into()));
    }

    // Parse KSI and sequence number
    let ksi_seq = data[0];
    let ksi = (ksi_seq >> 5) & 0x07;
    let sequence_number = ksi_seq & 0x1f;

    // Update context
    mme_ue.nas_eps.mme_ksi.ksi = ksi;
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();

    log::info!(
        "Service request from IMSI[{}] KSI[{}] SEQ[{}]",
        mme_ue.imsi_bcd,
        ksi,
        sequence_number
    );

    Ok((ksi, sequence_number))
}

// ============================================================================
// Extended Service Request Handling
// ============================================================================

/// Handle extended service request
pub fn handle_extended_service_request(
    enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<u8> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage(
            "Extended service request empty".into(),
        ));
    }

    // Parse service type and NAS key set identifier
    let service_type_byte = data[0];
    let service_type = service_type_byte & 0x0f;
    let nas_ksi = (service_type_byte >> 4) & 0x07;

    // Update context
    mme_ue.nas_eps.service_type = service_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;
    mme_ue.tai = enb_ue.saved.tai.clone();
    mme_ue.e_cgi = enb_ue.saved.e_cgi.clone();

    log::info!(
        "Extended service request from IMSI[{}] type[{}]",
        mme_ue.imsi_bcd,
        service_type
    );

    Ok(service_type)
}

// ============================================================================
// Detach Request Handling
// ============================================================================

/// Handle detach request (from UE)
pub fn handle_detach_request(
    _enb_ue: &EnbUe,
    mme_ue: &mut MmeUe,
    data: &[u8],
) -> EmmResult<(u8, bool)> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Detach request empty".into()));
    }

    // Parse detach type
    let detach_type_byte = data[0];
    let detach_type = detach_type_byte & 0x07;
    let switch_off = (detach_type_byte & 0x08) != 0;
    let nas_ksi = (detach_type_byte >> 4) & 0x07;

    // Update context
    mme_ue.nas_eps.detach_type = detach_type;
    mme_ue.nas_eps.mme_ksi.ksi = nas_ksi;

    log::info!(
        "Detach request from IMSI[{}] type[{}] switch_off[{}]",
        mme_ue.imsi_bcd,
        detach_type,
        switch_off
    );

    Ok((detach_type, switch_off))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse mobile identity
fn parse_mobile_identity(data: &[u8]) -> EmmResult<(Option<String>, Option<ParsedGuti>)> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Empty mobile identity".into()));
    }

    let identity_type = data[0] & 0x07;

    match identity_type {
        1 => {
            // IMSI
            let imsi = decode_imsi(data)?;
            Ok((Some(imsi), None))
        }
        6 => {
            // GUTI
            if data.len() < 11 {
                return Err(EmmError::InvalidMessage("GUTI too short".into()));
            }

            let guti = ParsedGuti {
                plmn_id: decode_plmn_id(&data[1..4]),
                mme_gid: ((data[4] as u16) << 8) | (data[5] as u16),
                mme_code: data[6],
                m_tmsi: ((data[7] as u32) << 24)
                    | ((data[8] as u32) << 16)
                    | ((data[9] as u32) << 8)
                    | (data[10] as u32),
            };
            Ok((None, Some(guti)))
        }
        _ => {
            log::warn!("Unknown mobile identity type: {identity_type}");
            Ok((None, None))
        }
    }
}

/// Decode IMSI from BCD format
fn decode_imsi(data: &[u8]) -> EmmResult<String> {
    if data.is_empty() {
        return Err(EmmError::InvalidMessage("Empty IMSI data".into()));
    }

    let mut imsi = String::with_capacity(15);

    // First digit is in the high nibble of first byte (after type)
    let first_digit = (data[0] >> 4) & 0x0f;
    if first_digit < 10 {
        imsi.push((b'0' + first_digit) as char);
    }

    // Remaining digits
    for &byte in &data[1..] {
        let low = byte & 0x0f;
        let high = (byte >> 4) & 0x0f;

        if low < 10 {
            imsi.push((b'0' + low) as char);
        }
        if high < 10 && high != 0x0f {
            imsi.push((b'0' + high) as char);
        }
    }

    Ok(imsi)
}

/// Decode IMEI from BCD format
fn decode_imei(data: &[u8]) -> EmmResult<String> {
    decode_imsi(data) // Same format as IMSI
}

/// Decode IMEISV from BCD format
fn decode_imeisv(data: &[u8]) -> EmmResult<String> {
    decode_imsi(data) // Same format as IMSI
}

/// Decode PLMN ID from 3 bytes
fn decode_plmn_id(data: &[u8]) -> PlmnId {
    if data.len() < 3 {
        return PlmnId::default();
    }

    PlmnId {
        mcc1: data[0] & 0x0f,
        mcc2: (data[0] >> 4) & 0x0f,
        mcc3: data[1] & 0x0f,
        mnc1: data[2] & 0x0f,
        mnc2: (data[2] >> 4) & 0x0f,
        mnc3: (data[1] >> 4) & 0x0f,
    }
}

/// Parse TAI from 5 bytes
fn parse_tai(data: &[u8]) -> EpsTai {
    if data.len() < 5 {
        return EpsTai::default();
    }

    EpsTai {
        plmn_id: decode_plmn_id(&data[0..3]),
        tac: ((data[3] as u16) << 8) | (data[4] as u16),
    }
}

/// Parse a UE network capability IE contents field (TS 24.301 §9.9.3.34).
///
/// `pub(crate)` for #347: the MM Context an AMF sends over N26 carries the same field
/// (TS 29.274 Figure 8.38-5, `Length of UE Network Capability` + contents), and decoding
/// it with a second implementation would be two spellings of one wire fact — the shape
/// that let #335 and #340 ship wrong tables.
pub(crate) fn parse_ue_network_capability(data: &[u8]) -> UeNetworkCapability {
    let mut cap = UeNetworkCapability::default();

    if !data.is_empty() {
        cap.eea = data[0];
    }
    if data.len() > 1 {
        cap.eia = data[1];
    }
    if data.len() > 2 {
        cap.uea = data[2];
    }
    if data.len() > 3 {
        cap.uia = data[3] & 0x7f;
    }

    cap
}

/// Parse MS network capability
fn parse_ms_network_capability(data: &[u8]) -> MsNetworkCapability {
    let mut cap = MsNetworkCapability::default();

    if !data.is_empty() {
        cap.gea1 = (data[0] & 0x80) != 0;
        cap.extended_gea = data[0] & 0x7f;
    }

    cap
}

/// Parse UE additional security capability
fn parse_additional_security_capability(data: &[u8]) -> UeAdditionalSecurityCapability {
    let mut cap = UeAdditionalSecurityCapability::default();

    if !data.is_empty() {
        cap.nea = data[0];
    }
    if data.len() > 1 {
        cap.nia = data[1];
    }

    cap
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_imsi() {
        // Test with a simple IMSI pattern
        // First byte: odd indicator (1) + type (1) + first digit in high nibble
        // For IMSI "123456789012345":
        // byte 0: 0x19 = odd(1) + type(1) + digit 1
        // byte 1: 0x32 = digit 2 (low) + digit 3 (high)
        // etc.
        let data = [0x19, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54];
        let imsi = decode_imsi(&data).unwrap();
        // The decoder extracts: 1 (from high nibble of byte 0)
        // then pairs: 2,3 4,5 6,7 8,9 0,1 2,3 4,5
        assert_eq!(imsi, "123456789012345");
    }

    #[test]
    fn test_decode_plmn_id() {
        // PLMN: MCC=310, MNC=410
        // Encoded: 0x13 0xf0 0x14
        let data = [0x13, 0xf0, 0x14];
        let plmn = decode_plmn_id(&data);
        assert_eq!(plmn.mcc1, 3);
        assert_eq!(plmn.mcc2, 1);
        assert_eq!(plmn.mcc3, 0);
        assert_eq!(plmn.mnc1, 4);
        assert_eq!(plmn.mnc2, 1);
        assert_eq!(plmn.mnc3, 0x0f); // 2-digit MNC
    }

    #[test]
    fn test_parse_tai() {
        // TAI: PLMN=310/410, TAC=0x1234
        let data = [0x13, 0xf0, 0x14, 0x12, 0x34];
        let tai = parse_tai(&data);
        assert_eq!(tai.tac, 0x1234);
    }

    #[test]
    fn test_parse_ue_network_capability() {
        let data = [0xff, 0x7f, 0x00, 0x00];
        let cap = parse_ue_network_capability(&data);
        assert_eq!(cap.eea, 0xff);
        assert_eq!(cap.eia, 0x7f);
        assert_eq!(cap.uea, 0x00);
        assert_eq!(cap.uia, 0x00);
    }

    #[test]
    fn test_parse_mobile_identity_imsi() {
        // IMSI type (1) with odd indicator
        let data = [0x19, 0x01, 0x14, 0x21, 0x43, 0x65, 0x87, 0xf9];
        let (imsi, guti) = parse_mobile_identity(&data).unwrap();
        assert!(imsi.is_some());
        assert!(guti.is_none());
    }

    #[test]
    fn test_parse_mobile_identity_guti() {
        // GUTI type (6)
        let data = [
            0xf6, // Type = GUTI
            0x13, 0xf0, 0x14, // PLMN
            0x00, 0x01, // MME GID
            0x02, // MME Code
            0x12, 0x34, 0x56, 0x78, // M-TMSI
        ];
        let (imsi, guti) = parse_mobile_identity(&data).unwrap();
        assert!(imsi.is_none());
        assert!(guti.is_some());

        let guti = guti.unwrap();
        assert_eq!(guti.mme_gid, 1);
        assert_eq!(guti.mme_code, 2);
        assert_eq!(guti.m_tmsi, 0x12345678);
    }

    #[test]
    fn test_emm_error_display() {
        let err = EmmError::InvalidMessage("test".into());
        assert!(err.to_string().contains("Invalid message"));

        let err = EmmError::ProtocolError(EmmCause::PlmnNotAllowed);
        assert!(err.to_string().contains("Protocol error"));
    }

    // ========================================================================
    // Authentication abnormal cases (issue #45)
    // ========================================================================

    /// A UE context holding an 8-octet XRES, as `mme_s6a_handle_aia` leaves it.
    fn ue_with_xres() -> MmeUe {
        let mut mme_ue = MmeUe {
            id: 1,
            ..Default::default()
        };
        mme_ue.xres[..8].copy_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);
        mme_ue.xres_len = 8;
        mme_ue
    }

    /// AUTHENTICATION RESPONSE body: RES length followed by the RES.
    fn authentication_response_body(res: &[u8]) -> Vec<u8> {
        let mut body = vec![res.len() as u8];
        body.extend_from_slice(res);
        body
    }

    #[test]
    fn test_full_length_res_is_accepted() {
        let mut mme_ue = ue_with_xres();
        let body = authentication_response_body(&[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);

        let accepted =
            handle_authentication_response(&EnbUe::default(), &mut mme_ue, &body).unwrap();

        assert!(accepted);
    }

    #[test]
    fn test_truncated_res_matching_the_xres_prefix_is_rejected() {
        let mut mme_ue = ue_with_xres();

        // TS 24.301 §5.4.2.4: the UE returns the whole RES. Comparing only the
        // octets it chose to send let a one-octet guess authenticate with
        // probability 1/256 per attempt.
        for prefix_len in 1..8usize {
            let prefix = mme_ue.xres[..prefix_len].to_vec();
            let body = authentication_response_body(&prefix);
            let accepted =
                handle_authentication_response(&EnbUe::default(), &mut mme_ue, &body).unwrap();
            assert!(
                !accepted,
                "a {prefix_len}-octet RES matching the XRES prefix must be rejected"
            );
        }
    }

    #[test]
    fn test_over_long_and_wrong_res_are_rejected() {
        let mut mme_ue = ue_with_xres();

        let too_long = authentication_response_body(&[0xa1; 9]);
        assert!(
            !handle_authentication_response(&EnbUe::default(), &mut mme_ue, &too_long).unwrap()
        );

        let mut wrong = mme_ue.xres[..8].to_vec();
        wrong[7] ^= 0xff;
        let wrong = authentication_response_body(&wrong);
        assert!(!handle_authentication_response(&EnbUe::default(), &mut mme_ue, &wrong).unwrap());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
        assert!(constant_time_eq(&[], &[]));
    }

    #[test]
    fn test_authentication_failure_synch_failure_carries_the_auts() {
        let mut mme_ue = MmeUe::default();
        let auts = [0x5a; NEXTGCORE_AUTS_LEN];
        let mut body = vec![21, AUTHENTICATION_FAILURE_PARAMETER_IEI, auts.len() as u8];
        body.extend_from_slice(&auts);

        let outcome = handle_authentication_failure(&EnbUe::default(), &mut mme_ue, &body).unwrap();

        assert_eq!(outcome, AuthenticationFailure::SynchFailure(Box::new(auts)));
    }

    #[test]
    fn test_authentication_failure_synch_failure_needs_the_auts() {
        let mut mme_ue = MmeUe::default();

        // Cause #21 with no Authentication Failure Parameter at all.
        assert!(handle_authentication_failure(&EnbUe::default(), &mut mme_ue, &[21]).is_err());

        // ...and with one of the wrong length.
        let body = vec![21, AUTHENTICATION_FAILURE_PARAMETER_IEI, 4, 1, 2, 3, 4];
        assert!(handle_authentication_failure(&EnbUe::default(), &mut mme_ue, &body).is_err());
    }

    #[test]
    fn test_authentication_failure_causes() {
        let mut mme_ue = MmeUe::default();

        assert_eq!(
            handle_authentication_failure(&EnbUe::default(), &mut mme_ue, &[20]).unwrap(),
            AuthenticationFailure::MacFailure
        );
        assert_eq!(
            handle_authentication_failure(&EnbUe::default(), &mut mme_ue, &[26]).unwrap(),
            AuthenticationFailure::Other(26)
        );
        assert!(handle_authentication_failure(&EnbUe::default(), &mut mme_ue, &[]).is_err());
    }

    /// A minimal TRACKING AREA UPDATE REQUEST body with the given trailing optional IEs.
    ///
    /// Layout per TS 24.301 §8.2.29: EPS update type + NAS KSI (1 octet), the Old GUTI as an
    /// LV EPS mobile identity, then optional IEs.
    fn tau_body(trailing: &[u8]) -> Vec<u8> {
        let mut body = vec![0x00]; // update type 0 (TA updating), KSI 0
        body.push(11); // Old GUTI length
        body.extend_from_slice(&[
            0xF6, 0x00, 0xF1, 0x10, 0xAB, 0x9B, 0x6A, 0x12, 0x34, 0x56, 0x78,
        ]);
        body.extend_from_slice(trailing);
        body
    }

    /// **#347**: a TAU from 5GS is recognised by the UE status IE's `N1 mode reg` bit —
    /// bit **2** — and NOT by the Old GUTI type.
    ///
    /// The assertion the whole N26 leg hangs on. There are two distinct ways to get it wrong,
    /// both of which compile and both of which leave the procedure permanently dead:
    ///
    /// 1. **Masking bit 1.** That is `S1 mode reg`, the EMM registration status, which
    ///    TS 24.301 NOTE 6 (`24301-k00.txt:17076-17077`) says *"is not used by the MME"*. A UE
    ///    arriving from 5GS has it CLEAR — it is not EMM-registered — so the branch never fires.
    /// 2. **Keying on a *mapped* Old GUTI type.** TS 24.301 §5.5.3.2.2 case z
    ///    (`24301-k00.txt:17068-17074`) has the UE send a GUTI mapped from its 5G-GUTI while
    ///    typing it *"Native GUTI"*, so the GUTI type is byte-identical to an intra-EPS TAU's
    ///    and cannot discriminate at all.
    ///
    /// Each is checked by asserting what the field does and does **not** imply.
    #[test]
    fn a_tau_from_5gs_is_recognised_by_the_ue_status_n1_mode_bit() {
        assert_eq!(
            IEI_UE_STATUS, 0x6D,
            "UE status is IEI 6D, TLV, length 3 (TS 24.301 Table 8.2.29.1, \
             24301-k00.txt:36942)"
        );
        assert_eq!(
            UE_STATUS_N1_MODE_REG_BIT, 0x02,
            "'5GMM registration status' (N1 mode reg) is octet 3 BIT 2 (TS 24.501 Table \
             9.11.3.56.1, 24501-k00_5_Main-Body_s09_s10.txt:11556). Bit 1 is 'S1 mode reg', \
             which TS 24.301 NOTE 6 says the MME does not use -- masking it would leave the \
             N26 branch permanently dead."
        );

        let enb_ue = EnbUe::default();

        // N1 mode reg SET => this TAU came from 5GS.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(
            &enb_ue,
            &mut ue,
            &tau_body(&[IEI_UE_STATUS, 0x01, UE_STATUS_N1_MODE_REG_BIT]),
        )
        .expect("a TAU with a UE status IE must parse");
        assert!(
            parsed.five_gmm_registered,
            "octet 3 bit 2 set means 'UE is in 5GMM-REGISTERED state', which is what tells \
             the MME to fetch the context over N26"
        );

        // Only bit 1 set (S1 mode reg) => NOT a 5GS move. This is the case a bit-1 mask would
        // wrongly treat as one.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(&enb_ue, &mut ue, &tau_body(&[IEI_UE_STATUS, 0x01, 0x01]))
            .expect("parses");
        assert!(
            !parsed.five_gmm_registered,
            "bit 1 is 'S1 mode reg' (EMM registration status), NOT the 5GMM one -- a UE that \
             is merely EMM-registered has not come from 5GS"
        );

        // Both bits => still a 5GS move; the two are independent.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(&enb_ue, &mut ue, &tau_body(&[IEI_UE_STATUS, 0x01, 0x03]))
            .expect("parses");
        assert!(
            parsed.five_gmm_registered,
            "bit 2 is read regardless of bit 1"
        );

        // No UE status IE => fail closed. Asking an AMF about a UE that never claimed a 5GS
        // registration would query a context that does not exist.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(&enb_ue, &mut ue, &tau_body(&[])).expect("parses");
        assert!(
            !parsed.five_gmm_registered,
            "an absent UE status IE reads as 'not 5GMM-registered', the fail-closed answer"
        );
        assert!(
            parsed.old_guti_type_mapped.is_none(),
            "and an absent Old GUTI type IE is None rather than a default"
        );

        // A NATIVE Old GUTI type with the 5GMM bit set is exactly §5.5.3.2.2 case z, and must
        // still route over N26.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(
            &enb_ue,
            &mut ue,
            &tau_body(&[
                IEI_OLD_GUTI_TYPE, // type-1 IE, value 0 = Native GUTI
                IEI_UE_STATUS,
                0x01,
                UE_STATUS_N1_MODE_REG_BIT,
            ]),
        )
        .expect("parses");
        assert_eq!(
            parsed.old_guti_type_mapped,
            Some(false),
            "Old GUTI type 0 is 'Native GUTI' (TS 24.301 Table 9.9.3.45.1)"
        );
        assert!(
            parsed.five_gmm_registered,
            "a NATIVE Old GUTI type must STILL route over N26 when the UE status says \
             5GMM-REGISTERED: §5.5.3.2.2 case z requires the UE to type its mapped GUTI as \
             'Native', so an implementation keyed on a MAPPED type would never fire"
        );

        // A mapped Old GUTI type without the UE status IE is the SGSN case (TS 23.401
        // §4.3.19.3) and must NOT route over N26.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(&enb_ue, &mut ue, &tau_body(&[IEI_OLD_GUTI_TYPE | 0x01]))
            .expect("parses");
        assert_eq!(parsed.old_guti_type_mapped, Some(true));
        assert!(
            !parsed.five_gmm_registered,
            "a MAPPED Old GUTI type means the old node was an SGSN (TS 23.401 §4.3.19.3), not \
             an AMF, so it must not trigger an N26 Context Request"
        );

        // And the Old GUTI still parses, because the Context Request carries it.
        let mut ue = MmeUe::default();
        let parsed = handle_tau_request(
            &enb_ue,
            &mut ue,
            &tau_body(&[IEI_UE_STATUS, 0x01, UE_STATUS_N1_MODE_REG_BIT]),
        )
        .expect("parses");
        let guti = parsed
            .old_guti
            .expect("the Old GUTI must parse: it is what the Context Request carries");
        assert_eq!(guti.mme_gid, 0xAB9B);
        assert_eq!(guti.mme_code, 0x6A);
        assert_eq!(guti.m_tmsi, 0x1234_5678);
    }
}
