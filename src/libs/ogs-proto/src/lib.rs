//! NextGCore Protocol Definitions Library
//!
//! This crate provides common protocol definitions, types, and utilities
//! used across the NextGCore 5G core network implementation.

mod types;
mod conv;
mod event;
mod timer;
pub mod ambient_iot;     // #212: Ambient IoT energy harvesting
pub mod ntn_constellation; // #213: NTN constellation planning

pub use types::*;
pub use conv::*;
pub use event::*;
pub use timer::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plmn_id_build() {
        let plmn = PlmnId::build(310, 410, 3);
        assert_eq!(plmn.mcc(), 310);
        assert_eq!(plmn.mnc(), 410);
        assert_eq!(plmn.mnc_len(), 3);
    }

    #[test]
    fn test_plmn_id_build_2digit_mnc() {
        let plmn = PlmnId::build(310, 26, 2);
        assert_eq!(plmn.mcc(), 310);
        assert_eq!(plmn.mnc(), 26);
        assert_eq!(plmn.mnc_len(), 2);
    }

    #[test]
    fn test_amf_id_build() {
        let amf = AmfId::build(0x01, 0x02, 0x03);
        assert_eq!(amf.region(), 0x01);
        assert_eq!(amf.set_id(), 0x02);
        assert_eq!(amf.pointer(), 0x03);
    }

    #[test]
    fn test_s_nssai() {
        let nssai = SNssai::new(1, Some(0x010203));
        assert_eq!(nssai.sst, 1);
        assert_eq!(nssai.sd, Some(0x010203));
    }

    #[test]
    fn test_event_new() {
        let event = Event::new(EventId::SbiServer);
        assert_eq!(event.id, EventId::SbiServer);
    }

    #[test]
    fn test_timer_name() {
        let name = timer_get_name(TimerId::NfInstanceRegistrationInterval);
        assert!(!name.is_empty());
    }
}
