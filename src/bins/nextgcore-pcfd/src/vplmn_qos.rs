//! #1541: the home-routed-roaming QoS constraints of the VPLMN
//! (VPLMN-QoS-Control, TS 29.512 Table 5.8-1 feature 49).
//!
//! In home-routed roaming the H-SMF provides the QoS the VPLMN supports in
//! `vplmnQos` (TS 29.512 §4.2.2.2, §4.2.2.5, §4.2.4.4, §4.2.4.5; TS 23.503
//! §6.1.3.6), and the H-PCF "ensures that the Authorized Session-AMBR value does
//! not exceed the Session-AMBR value provided by the VPLMN, that the Authorized
//! default 5QI/ARP contains a 5QI and ARP value supported by the VPLMN". With no
//! constraints provided "the H-PCF considers that no QoS constraints apply"
//! (TS 29.512 §4.2.2.5 NOTE 2).
//!
//! [`apply`] is that bound. It runs in `sbi_path::decision_session_data`, the one
//! step the create, the UpdateNotify and the GET build their decision through, and
//! in the `SE_AMBR_CH` / `VPLMN_QOS_CH` update arms, after the
//! `pcf.policy.session_ambr_cap` cap (#1402) and regardless of it.
//!
//! Not covered: `5qiPL` (needs VPLMN-5QIPrioLevel, feature 77, which this PCF
//! does not advertise) and the GFBR/MFBR members, which bound GBR flows this PCF
//! does not authorise from the SMF.

use crate::nudr_handler::SessionData;
use crate::sm_policy_build::parse_bitrate;

/// TS 29.512 Table 5.8-1 feature 49, VPLMN-QoS-Control: bit 48, since feature 1 is
/// the least significant bit (TS 29.571 §5.2.2 SupportedFeatures).
pub const SM_FEATURE_VPLMN_QOS_CONTROL: u64 = 1 << 48;

/// The parts of a TS 29.502 `VplmnQos` this PCF bounds its decision by.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VplmnQosBound {
    /// `sessionAmbr` as (uplink, downlink) bit/s; a 0 direction is no bound.
    pub session_ambr: Option<(u64, u64)>,
    /// `5qi`: the default 5QI the VPLMN supports.
    pub five_qi: Option<u8>,
    /// `add5QiList`: further 5QIs the VPLMN supports for the default QoS flow.
    #[serde(default)]
    pub add_5qi_list: Vec<u8>,
    /// `arp` as (priority level, may preempt, preemptable).
    pub arp: Option<(u8, bool, bool)>,
}

/// Parse a TS 29.502 `VplmnQos`. `Err` names the member that is not of its type
/// (TS 29.571: `5Qi` 0..255, `Arp.priorityLevel` 1..15, `BitRate` strings).
pub fn parse(v: &serde_json::Value) -> Result<VplmnQosBound, String> {
    let obj = v.as_object().ok_or("vplmnQos is not an object")?;
    let five_qi = |x: &serde_json::Value| x.as_u64().filter(|q| *q <= 255).map(|q| q as u8);
    let mut out = VplmnQosBound::default();
    if let Some(ambr) = obj.get("sessionAmbr") {
        let dir = |k: &str| ambr.get(k).and_then(|x| x.as_str()).and_then(parse_bitrate);
        match (dir("uplink"), dir("downlink")) {
            (Some(ul), Some(dl)) => out.session_ambr = Some((ul, dl)),
            _ => return Err("vplmnQos.sessionAmbr is not an Ambr".into()),
        }
    }
    if let Some(q) = obj.get("5qi") {
        out.five_qi = Some(five_qi(q).ok_or("vplmnQos.5qi is not a 5Qi")?);
    }
    if let Some(list) = obj.get("add5QiList") {
        let list = list
            .as_array()
            .ok_or("vplmnQos.add5QiList is not an array")?;
        for q in list {
            out.add_5qi_list
                .push(five_qi(q).ok_or("vplmnQos.add5QiList holds a non-5Qi")?);
        }
    }
    if let Some(arp) = obj.get("arp") {
        let level = arp
            .get("priorityLevel")
            .and_then(|x| x.as_u64())
            .filter(|l| (1..=15).contains(l))
            .ok_or("vplmnQos.arp.priorityLevel is not 1..15")?;
        let cap = match arp.get("preemptCap").and_then(|x| x.as_str()) {
            Some("MAY_PREEMPT") => true,
            Some("NOT_PREEMPT") => false,
            _ => return Err("vplmnQos.arp.preemptCap is not a PreemptionCapability".into()),
        };
        let vuln = match arp.get("preemptVuln").and_then(|x| x.as_str()) {
            Some("PREEMPTABLE") => true,
            Some("NOT_PREEMPTABLE") => false,
            _ => return Err("vplmnQos.arp.preemptVuln is not a PreemptionVulnerability".into()),
        };
        out.arp = Some((level as u8, cap, vuln));
    }
    Ok(out)
}

/// `sd` bounded by the VPLMN's QoS constraints (`None`: none apply, `sd`
/// unchanged).
///
/// - Session-AMBR: per direction `min(sd, vplmn)`; a 0 bps VPLMN direction is
///   not a bound (the reading `session_ambr_cap::apply` gives a 0 bps subscribed
///   value).
/// - Default 5QI: kept when the VPLMN supports it (`5qi` or `add5QiList`), else
///   the VPLMN's `5qi`.
/// - ARP: no more privileged than the VPLMN's: the priority level is the larger
///   number (lower priority), "may preempt" only if the VPLMN's may, and
///   "preemptable" if either is.
pub fn apply(sd: &SessionData, bound: Option<&VplmnQosBound>) -> SessionData {
    let mut out = sd.clone();
    let Some(bound) = bound else {
        return out;
    };
    if let Some((ul, dl)) = bound.session_ambr {
        if ul > 0 {
            out.ambr_uplink = out.ambr_uplink.min(ul);
        }
        if dl > 0 {
            out.ambr_downlink = out.ambr_downlink.min(dl);
        }
    }
    if let Some(q) = bound.five_qi {
        let supported = out.qos_index == q || bound.add_5qi_list.contains(&out.qos_index);
        if !supported {
            out.qos_index = q;
        }
    }
    if let Some((level, cap, vuln)) = bound.arp {
        out.arp_priority_level = out.arp_priority_level.max(level);
        out.arp_preempt_cap = out.arp_preempt_cap && cap;
        out.arp_preempt_vuln = out.arp_preempt_vuln || vuln;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sd() -> SessionData {
        SessionData {
            qos_index: 9,
            arp_priority_level: 2,
            arp_preempt_cap: true,
            arp_preempt_vuln: false,
            ambr_uplink: 200_000_000,
            ambr_downlink: 400_000_000,
            pcc_rules: vec![],
        }
    }

    #[test]
    fn no_constraints_change_nothing() {
        assert_eq!(apply(&sd(), None), sd());
        assert_eq!(apply(&sd(), Some(&VplmnQosBound::default())), sd());
    }

    /// REVERT-VERIFIED: with `apply` returning `sd` unchanged, every assertion on a
    /// bounded member fails.
    #[test]
    fn the_vplmn_bounds_ambr_5qi_and_arp() {
        let bound = parse(&serde_json::json!({
            "sessionAmbr": { "uplink": "100 Mbps", "downlink": "1 Gbps" },
            "5qi": 8,
            "arp": { "priorityLevel": 5, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE" }
        }))
        .unwrap();
        let got = apply(&sd(), Some(&bound));
        assert_eq!(
            (got.ambr_uplink, got.ambr_downlink),
            (100_000_000, 400_000_000)
        );
        assert_eq!(got.qos_index, 8, "9 is not supported in the VPLMN");
        assert_eq!(
            (
                got.arp_priority_level,
                got.arp_preempt_cap,
                got.arp_preempt_vuln
            ),
            (5, false, true)
        );
        // A 5QI in add5QiList is supported and kept; a less privileged ARP is kept.
        let bound = parse(&serde_json::json!({
            "5qi": 8, "add5QiList": [9],
            "arp": { "priorityLevel": 1, "preemptCap": "MAY_PREEMPT", "preemptVuln": "NOT_PREEMPTABLE" }
        }))
        .unwrap();
        let got = apply(&sd(), Some(&bound));
        assert_eq!(got.qos_index, 9);
        assert_eq!(
            (
                got.arp_priority_level,
                got.arp_preempt_cap,
                got.arp_preempt_vuln
            ),
            (2, true, false)
        );
    }

    #[test]
    fn a_zero_direction_is_not_a_bound_and_a_malformed_member_is_refused() {
        let bound = parse(&serde_json::json!({
            "sessionAmbr": { "uplink": "0 bps", "downlink": "10 Mbps" }
        }))
        .unwrap();
        let got = apply(&sd(), Some(&bound));
        assert_eq!(
            (got.ambr_uplink, got.ambr_downlink),
            (200_000_000, 10_000_000)
        );
        for bad in [
            serde_json::json!([]),
            serde_json::json!({ "sessionAmbr": { "uplink": "fast" } }),
            serde_json::json!({ "5qi": 300 }),
            serde_json::json!({ "add5QiList": ["x"] }),
            serde_json::json!({ "arp": { "priorityLevel": 0, "preemptCap": "NOT_PREEMPT", "preemptVuln": "PREEMPTABLE" } }),
            serde_json::json!({ "arp": { "priorityLevel": 3, "preemptCap": "x", "preemptVuln": "PREEMPTABLE" } }),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }
}
