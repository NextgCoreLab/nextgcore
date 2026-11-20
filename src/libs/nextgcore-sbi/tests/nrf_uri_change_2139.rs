//! #2139 (R40 on #2134): the NRF-URI-keyed cache end to end. The shared
//! verified-NF-type lookup (`owner_binding::verified_nf_type`) asks the NRF the
//! global context is configured with; once that URI changes, the new NRF is
//! asked, not the old one's cached answer reused. `the_cache_keeps_each_nrf_apart_2120`
//! pins this one layer down, with an explicit URI; this goes through the
//! configured one.
//!
//! An integration test, so its own process: it sets the process-wide NRF URI.
//!
//! REVERT-VERIFIED: with the NRF URI dropped from `nf_type_key`, the old NRF's
//! cached `Ok` is reused after the switch, the new NRF is never asked, and
//! "the new NRF is asked" fails.

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::owner_binding::verified_nf_type;
use nextgcore_sbi::types::NfType;
use std::sync::{Arc, Mutex};

const AMF: &str = "aaaaaaaa-2139-4000-8000-0000000000a9";

/// A stand-in NRF that lists AMF as an AMF when `lists`, and records each
/// lookup of it.
async fn nrf(lists: bool) -> (nextgcore_sbi::server::SbiServer, String, Arc<Mutex<usize>>) {
    let asked = Arc::new(Mutex::new(0usize));
    let seen = asked.clone();
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let seen = seen.clone();
            async move {
                let param = |k: &str| req.http.params.get(k).cloned().unwrap_or_default();
                let mine = param("target-nf-instance-id") == AMF;
                if mine {
                    *seen.lock().unwrap() += 1;
                }
                let list = if mine && lists && param("target-nf-type") == "AMF" {
                    vec![serde_json::json!({ "nfInstanceId": AMF, "nfType": "AMF" })]
                } else {
                    vec![]
                };
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({ "nfInstances": list }))
                    .expect("json")
            }
        })
        .await;
    (server, format!("http://127.0.0.1:{}", addr.port()), asked)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_nrf_uri_asks_the_new_nrf_2139() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    nextgcore_sbi::nf_instance_id::nf_instance_id(NfType::Smf);
    let (_old, old_uri, old_asked) = nrf(true).await;
    let (_new, new_uri, new_asked) = nrf(false).await;
    let mut caller = SbiRequest::post("/x");
    caller.oauth2_subject = Some(AMF.to_string());
    let ctx = nextgcore_sbi::context::global_context();

    ctx.set_nrf_uri(&old_uri).await;
    assert_eq!(
        verified_nf_type(&caller, NfType::Amf).await,
        Ok(()),
        "the old NRF lists it"
    );
    assert_eq!(verified_nf_type(&caller, NfType::Amf).await, Ok(()));
    assert_eq!(
        *old_asked.lock().unwrap(),
        1,
        "the old NRF's answer is cached"
    );

    ctx.set_nrf_uri(&new_uri).await;
    let after = verified_nf_type(&caller, NfType::Amf).await;
    assert_eq!(*new_asked.lock().unwrap(), 1, "the new NRF is asked");
    assert!(
        after.is_err(),
        "and its answer (not listed) decides: {after:?}"
    );
    assert_eq!(
        *old_asked.lock().unwrap(),
        1,
        "the old NRF is not asked again"
    );
}
