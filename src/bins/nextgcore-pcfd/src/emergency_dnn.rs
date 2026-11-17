//! The operator setting `pcf.policy.emergency_dnns` (#1621 review B1): the
//! configurable list of Emergency DNs.
//!
//! TS 29.512 §4.2.2.2 (29512-k00.txt:3576-3583): "The PCF shall detect that a PDU
//! session is restricted to IMS Emergency services when the "dnn" attribute
//! included in the HTTP POST message received from the SMF includes a data network
//! identifier that matches one of the Emergency DNs from the configurable list.
//! The PCF does not perform in this case subscription check procedures with UDR;
//! it uses instead the locally configured operator policies". So an SM policy
//! create for an Emergency DN never reads the UDR, and a UDR outage cannot refuse
//! an emergency session.
//!
//! The same list decides when an AF session is an emergency one for AscRespData
//! (TS 29.514 §4.2.2.2, `asc_resp_required`).
//!
//! DNN labels compare case-insensitively (TS 23.003 §9.1).

use std::sync::{Mutex, RwLock};

/// The default list: `sos`, the Emergency DN this tree's SMF and AF use.
pub const DEFAULT: &[&str] = &["sos"];

/// The list in force. Written once at start-up ([`set`]), read on every create.
static EMERGENCY_DNNS: RwLock<Option<Vec<String>>> = RwLock::new(None);

/// Serialises tests that change [`EMERGENCY_DNNS`] or whose assertions depend on
/// it. Taken through [`crate::test_support::emergency_dnns`].
pub static EMERGENCY_DNNS_LOCK: Mutex<()> = Mutex::new(());

/// The list in force ([`DEFAULT`] until [`set`]).
pub fn get() -> Vec<String> {
    EMERGENCY_DNNS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| DEFAULT.iter().map(|d| d.to_string()).collect())
}

/// Put `dnns` in force.
pub fn set(dnns: Vec<String>) {
    *EMERGENCY_DNNS.write().unwrap_or_else(|e| e.into_inner()) = Some(dnns);
}

/// Whether `dnn` is one of the Emergency DNs in force, compared on its Network
/// Identifier (#1621 review round 2): the SMF may send the full DNN,
/// `sos.mnc001.mcc001.gprs`, as well as `sos` (TS 23.003 §9.1, §9A).
pub fn is_emergency(dnn: &str) -> bool {
    let ni = network_identifier(dnn);
    get()
        .iter()
        .any(|d| network_identifier(d).eq_ignore_ascii_case(ni))
}

/// The Network Identifier of a DNN (TS 23.003 §9.1): the DNN without a trailing
/// Operator Identifier `mnc<MNC>.mcc<MCC>.gprs` (three-digit MNC and MCC,
/// §9.1.2), or the whole DNN when it carries none.
pub fn network_identifier(dnn: &str) -> &str {
    let digits3 = |label: &str, prefix: &str| {
        label.len() == prefix.len() + 3
            && label[..prefix.len()].eq_ignore_ascii_case(prefix)
            && label[prefix.len()..].bytes().all(|b| b.is_ascii_digit())
    };
    let labels: Vec<&str> = dnn.rsplitn(4, '.').collect();
    match labels.as_slice() {
        [gprs, mcc, mnc, ni]
            if gprs.eq_ignore_ascii_case("gprs")
                && digits3(mcc, "mcc")
                && digits3(mnc, "mnc")
                && !ni.is_empty() =>
        {
            ni
        }
        _ => dnn,
    }
}

/// The list a config root states: `pcf.policy.emergency_dnns`, [`DEFAULT`] when
/// absent. Anything but a list of non-empty strings is an error, and start-up
/// fails on it. An empty list is allowed: no DN is then an emergency one.
pub fn from_config_root(root: &serde_yaml::Value) -> Result<Vec<String>, String> {
    let default = || DEFAULT.iter().map(|d| d.to_string()).collect();
    let Some(v) = root
        .get("pcf")
        .and_then(|p| p.get("policy"))
        .and_then(|p| p.get("emergency_dnns"))
    else {
        return Ok(default());
    };
    if v.is_null() {
        return Ok(default());
    }
    let Some(list) = v.as_sequence() else {
        return Err("pcf.policy.emergency_dnns must be a list of DNNs".to_string());
    };
    list.iter()
        .map(|d| match d.as_str().map(str::trim) {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err(format!(
                "pcf.policy.emergency_dnns: {d:?} is not a non-empty DNN string"
            )),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    /// #1621 review round 2: the full DNN form and any case match on the Network
    /// Identifier (TS 23.003 §9.1).
    #[test]
    fn an_emergency_dn_matches_on_its_network_identifier() {
        assert_eq!(network_identifier("sos.mnc001.mcc001.gprs"), "sos");
        assert_eq!(network_identifier("SOS.MNC001.MCC001.GPRS"), "SOS");
        assert_eq!(network_identifier("ims.sos.mnc123.mcc456.gprs"), "ims.sos");
        assert_eq!(network_identifier("sos"), "sos");
        assert_eq!(
            network_identifier("sos.mnc01.mcc001.gprs"),
            "sos.mnc01.mcc001.gprs"
        );
        assert_eq!(
            network_identifier(".mnc001.mcc001.gprs"),
            ".mnc001.mcc001.gprs"
        );
        assert_eq!(network_identifier("internet.example"), "internet.example");

        let _lock = EMERGENCY_DNNS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous = get();
        set(vec!["sos".to_string()]);
        let results = [
            is_emergency("sos"),
            is_emergency("SOS"),
            is_emergency("sos.mnc001.mcc001.gprs"),
            is_emergency("Sos.Mnc001.Mcc001.Gprs"),
            is_emergency("internet"),
            is_emergency("sos.example.org"),
        ];
        set(previous);
        assert_eq!(results, [true, true, true, true, false, false]);
    }

    #[test]
    fn the_list_is_read_from_pcf_policy() {
        assert_eq!(from_config_root(&serde_yaml::Value::Null).unwrap(), ["sos"]);
        assert_eq!(
            from_config_root(&root("pcf: { policy: { session_ambr_cap: none } }")).unwrap(),
            ["sos"]
        );
        assert_eq!(
            from_config_root(&root("pcf: { policy: { emergency_dnns: [sos, ims-sos] } }")).unwrap(),
            ["sos", "ims-sos"]
        );
        assert!(
            from_config_root(&root("pcf: { policy: { emergency_dnns: [] } }"))
                .unwrap()
                .is_empty()
        );
        assert!(from_config_root(&root("pcf: { policy: { emergency_dnns: sos } }")).is_err());
        assert!(from_config_root(&root("pcf: { policy: { emergency_dnns: [\"\"] } }")).is_err());
        assert!(from_config_root(&root("pcf: { policy: { emergency_dnns: [1] } }")).is_err());
    }
}
