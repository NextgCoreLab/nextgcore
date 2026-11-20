//! #2141 (R41 on #2123): `nf_instance_id::own_nf_type`, the `requester-nf-type`
//! fallback of the shared verified-NF-type lookup when no self instance is set
//! (#2138), is the NF type this process first resolved its NF Instance ID as.
//!
//! An integration test, so its own process: the type is recorded in a
//! process-wide `OnceLock`, and in the unit-test binary whichever test resolves
//! the ID first decides it. ausfd and ucmfd resolve theirs as AUSF and UCMF at
//! startup, so this is the value their lookups fall back to.
//!
//! REVERT-VERIFIED: with `OWN_NF_TYPE.set` removed from `nf_instance_id`,
//! `own_nf_type()` stays `None` and the `recorded` assertion fails.

use nextgcore_sbi::nf_instance_id::{nf_instance_id, own_nf_type};
use nextgcore_sbi::types::NfType;

#[test]
fn the_own_nf_type_is_the_type_the_id_was_first_resolved_as_2141() {
    assert_eq!(own_nf_type(), None, "nothing resolved yet");
    let id = nf_instance_id(NfType::Ausf).to_string();
    assert_eq!(own_nf_type(), Some(NfType::Ausf), "recorded");
    // One identity per process: a later call naming another type changes neither.
    assert_eq!(nf_instance_id(NfType::Ucmf), id);
    assert_eq!(own_nf_type(), Some(NfType::Ausf), "the first type stays");
}
