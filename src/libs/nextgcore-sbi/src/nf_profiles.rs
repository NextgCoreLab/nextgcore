//! #2178: NFProfiles one NF registers and another NF's tests reason about,
//! built once so the two cannot drift (R41 on #2174: nrfd's grant test used a
//! hand-built copy of the NEF's profile).

/// The NF types that consume `nnef-eventexposure` (TS 23.502 §4.15.3.2): the
/// AF; the AMF and the UDM, peers of the monitoring-event exchanges; the SCP
/// that relays. #2160: not the UCMF, which only discovers the NEF.
///
/// #2178: not the NWDAF either. TS 23.288 §6.2.2 lets an NWDAF collect AF
/// data through the NEF (Nnef_EventExposure), but nextgcore's nwdafd has no
/// Nnef consumer path: the only producer service it calls is the AMF's
/// Namf_EventExposure (`/namf-evts/v1/subscriptions`), besides the NRF. Granting
/// it the service would be privilege nothing uses; an NWDAF that does consume
/// it is the change that adds NWDAF here, with its consumer path.
pub const NEF_EVENT_EXPOSURE_CONSUMERS: &[&str] = &["AF", "AMF", "UDM", "SCP"];

/// The NEF profile's `allowedNfTypes`: the service consumers, plus the UCMF,
/// which discovers the NEF to verify a NEF provisioner's type (#2141) and is
/// granted no NEF service ([`NEF_EVENT_EXPOSURE_CONSUMERS`]).
pub const NEF_PROFILE_ALLOWED_NF_TYPES: &[&str] = &["AF", "AMF", "UDM", "SCP", "UCMF"];

/// The NEF's NFProfile (TS 29.510 §6.1.6.2.2) as nefd registers it, without
/// its demo-only services: nfType NEF advertising `nnef-eventexposure`.
pub fn nef(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    scheme: crate::types::UriScheme,
) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "NEF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nnef-eventexposure"),
                "serviceName": "nnef-eventexposure",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": scheme.as_str(),
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
                // #2160: the NRF grants a service token only to a type both
                // levels allow (TS 29.510 §6.1.6.2.3).
                "allowedNfTypes": NEF_EVENT_EXPOSURE_CONSUMERS
            }
        ],
        "allowedNfTypes": NEF_PROFILE_ALLOWED_NF_TYPES,
        "heartBeatTimer": 10
    })
}
