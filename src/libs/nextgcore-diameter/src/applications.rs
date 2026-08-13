//! The set of Diameter applications a node supports, and the CER/CEA
//! negotiation built on it (RFC 6733 §5.3).
//!
//! # Why this exists
//!
//! `send_cer` used to emit only `Origin-Host`, `Origin-Realm` and
//! `Origin-State-Id`. Three AVPs the CER ABNF makes mandatory were missing
//! (`Host-IP-Address`, `Vendor-Id`, `Product-Name`), and **no application was
//! advertised at all**. `handle_cer` in turn validated only that Origin-Host and
//! Origin-Realm were present and then answered `2001 Success` unconditionally,
//! so it could never return `5010 DIAMETER_NO_COMMON_APPLICATION`.
//!
//! Two consequences. A conformant peer cannot discover which applications this
//! node speaks, so it has no basis for routing decisions. And a peer with
//! *nothing* in common is welcomed onto the connection, only to have every
//! subsequent request fail in a way that looks like an application bug rather
//! than a capability mismatch.
//!
//! # Vendor-specific applications
//!
//! Every application this tree implements except Gy is 3GPP vendor-specific, so
//! it is advertised inside a `Vendor-Specific-Application-Id` grouped AVP
//! (`Vendor-Id` + `Auth-Application-Id`) rather than a bare `Auth-Application-Id`
//! — TS 29.272 §7 for S6a, TS 29.212 §5.6 for Gx. Gy uses application id 4
//! (RFC 4006 Credit-Control), which is IETF-registered and therefore bare.
//!
//! # Scope
//!
//! Negotiation only: advertise, intersect, and reject when the intersection is
//! empty. Routing a request to an application, and the per-application dispatch
//! that would imply, is not part of this.

use std::collections::BTreeSet;

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;
use crate::NEXTGCORE_3GPP_VENDOR_ID;

/// A Diameter application identifier, plus the vendor that defines it.
///
/// Ordered (`BTreeSet`) rather than hashed so the AVP order in a CER is
/// deterministic: a stable wire image makes byte-comparison tests and packet
/// diffs meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApplicationId {
    /// The application id itself (e.g. 16777251 for S6a).
    pub id: u32,
    /// `Some(vendor)` for a vendor-specific application, `None` for an
    /// IETF-registered one. Determines whether it is advertised inside a
    /// `Vendor-Specific-Application-Id` group or as a bare `Auth-Application-Id`.
    pub vendor: Option<u32>,
}

impl ApplicationId {
    /// A 3GPP vendor-specific application (Vendor-Id 10415).
    pub const fn threegpp(id: u32) -> Self {
        Self {
            id,
            vendor: Some(NEXTGCORE_3GPP_VENDOR_ID),
        }
    }

    /// An IETF-registered application, advertised as a bare
    /// `Auth-Application-Id`.
    pub const fn ietf(id: u32) -> Self {
        Self { id, vendor: None }
    }
}

/// Well-known application ids, matching the per-application modules in this
/// crate. Kept here so a daemon names an interface rather than a magic number.
pub mod well_known {
    use super::ApplicationId;

    /// S6a: MME ↔ HSS (TS 29.272).
    pub const S6A: ApplicationId = ApplicationId::threegpp(16777251);
    /// S6b: PGW ↔ 3GPP AAA (TS 29.273).
    pub const S6B: ApplicationId = ApplicationId::threegpp(16777272);
    /// Cx: I-CSCF/S-CSCF ↔ HSS (TS 29.229).
    pub const CX: ApplicationId = ApplicationId::threegpp(16777216);
    /// SWx: 3GPP AAA ↔ HSS (TS 29.273).
    pub const SWX: ApplicationId = ApplicationId::threegpp(16777265);
    /// Gx: PCEF ↔ PCRF (TS 29.212).
    pub const GX: ApplicationId = ApplicationId::threegpp(16777238);
    /// Rx: AF ↔ PCRF (TS 29.214).
    pub const RX: ApplicationId = ApplicationId::threegpp(16777236);
    /// Gy: online charging, RFC 4006 Credit-Control. IETF-registered, so it is
    /// advertised as a bare Auth-Application-Id, not vendor-specific.
    pub const GY: ApplicationId = ApplicationId::ietf(4);
}

/// The applications a node advertises, and the vendors whose AVPs it understands.
///
/// Empty by default and populated by each daemon at startup: hssd declares
/// S6a + Cx + SWx, pcrfd declares Gx + Rx, mmed declares S6a. Declaring nothing
/// is legal and preserves the previous behaviour — see
/// [`Self::negotiate`] for what an empty set means during negotiation.
#[derive(Debug, Clone, Default)]
pub struct ApplicationRegistry {
    applications: BTreeSet<ApplicationId>,
    supported_vendors: BTreeSet<u32>,
    /// `Product-Name`, RFC 6733 §5.3.7.
    product_name: String,
    /// `Firmware-Revision`, RFC 6733 §5.3.4. Optional in CER/CEA.
    firmware_revision: Option<u32>,
}

impl ApplicationRegistry {
    /// An empty registry with the given product name.
    pub fn new(product_name: impl Into<String>) -> Self {
        Self {
            applications: BTreeSet::new(),
            supported_vendors: BTreeSet::new(),
            product_name: product_name.into(),
            firmware_revision: None,
        }
    }

    /// Declare support for an application.
    ///
    /// A vendor-specific application implicitly adds its vendor to
    /// `Supported-Vendor-Id`: claiming to speak S6a while not admitting to
    /// understanding 3GPP AVPs would be incoherent, and forgetting the separate
    /// call is an easy mistake with no upside.
    pub fn with_application(mut self, app: ApplicationId) -> Self {
        if let Some(vendor) = app.vendor {
            self.supported_vendors.insert(vendor);
        }
        self.applications.insert(app);
        self
    }

    /// Declare a supported vendor without an application (RFC 6733 §5.3.6).
    pub fn with_vendor(mut self, vendor_id: u32) -> Self {
        self.supported_vendors.insert(vendor_id);
        self
    }

    /// Set `Firmware-Revision` (RFC 6733 §5.3.4).
    pub fn with_firmware_revision(mut self, revision: u32) -> Self {
        self.firmware_revision = Some(revision);
        self
    }

    /// The declared applications.
    pub fn applications(&self) -> impl Iterator<Item = &ApplicationId> {
        self.applications.iter()
    }

    /// True when nothing has been declared.
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }

    pub fn product_name(&self) -> &str {
        &self.product_name
    }

    /// Append the capability AVPs to a CER or CEA.
    ///
    /// Covers the mandatory `Host-IP-Address` / `Vendor-Id` / `Product-Name`
    /// (RFC 6733 §5.3.1), the optional `Firmware-Revision`, every
    /// `Supported-Vendor-Id`, and one advertisement per application.
    ///
    /// `Vendor-Id` here is the vendor of *this node*, which RFC 6733 §5.3.3 says
    /// is 0 for a node that is not vendor-specific. It is distinct from the
    /// `Vendor-Id` nested inside each `Vendor-Specific-Application-Id`, which
    /// identifies who defined that application — conflating the two is an easy
    /// error, so they are set from different sources.
    pub fn append_capabilities(
        &self,
        msg: &mut DiameterMessage,
        host_addresses: &[std::net::IpAddr],
    ) {
        for addr in host_addresses {
            msg.add_avp(Avp::mandatory(
                avp_code::HOST_IP_ADDRESS,
                AvpData::Address(*addr),
            ));
        }

        // 0 = "not vendor-specific". This node is an implementation, not a
        // registered vendor; the 3GPP id belongs on the applications.
        msg.add_avp(Avp::mandatory(avp_code::VENDOR_ID, AvpData::Unsigned32(0)));

        msg.add_avp(Avp::mandatory(
            avp_code::PRODUCT_NAME,
            AvpData::Utf8String(self.product_name.clone()),
        ));

        if let Some(revision) = self.firmware_revision {
            // Firmware-Revision is NOT mandatory (RFC 6733 §5.3.4), so it
            // carries no M bit -- unlike every other capability AVP here.
            msg.add_avp(Avp::new(
                avp_code::FIRMWARE_REVISION,
                0,
                None,
                AvpData::Unsigned32(revision),
            ));
        }

        for vendor in &self.supported_vendors {
            msg.add_avp(Avp::mandatory(
                avp_code::SUPPORTED_VENDOR_ID,
                AvpData::Unsigned32(*vendor),
            ));
        }

        for app in &self.applications {
            match app.vendor {
                Some(vendor) => msg.add_avp(Avp::mandatory(
                    avp_code::VENDOR_SPECIFIC_APPLICATION_ID,
                    AvpData::Grouped(vec![
                        Avp::mandatory(avp_code::VENDOR_ID, AvpData::Unsigned32(vendor)),
                        Avp::mandatory(avp_code::AUTH_APPLICATION_ID, AvpData::Unsigned32(app.id)),
                    ]),
                )),
                None => msg.add_avp(Avp::mandatory(
                    avp_code::AUTH_APPLICATION_ID,
                    AvpData::Unsigned32(app.id),
                )),
            }
        }
    }

    /// Applications this node and the peer both support.
    ///
    /// Matching is on the application id alone, deliberately ignoring the vendor
    /// that carried it: the same id means the same application, and a peer may
    /// legitimately advertise S6a as a bare `Auth-Application-Id` (some stacks
    /// do) while we advertise it vendor-specifically. Requiring the vendor to
    /// match too would reject an interoperable peer over a presentation detail.
    pub fn common_with(&self, peer: &[ApplicationId]) -> Vec<ApplicationId> {
        let peer_ids: BTreeSet<u32> = peer.iter().map(|a| a.id).collect();
        self.applications
            .iter()
            .filter(|a| peer_ids.contains(&a.id))
            .copied()
            .collect()
    }

    /// Decide whether a peer advertising `peer_apps` may proceed.
    ///
    /// Returns the common set, or `None` when the connection must be refused
    /// with `DIAMETER_NO_COMMON_APPLICATION` (RFC 6733 §5.3).
    ///
    /// **Two cases deliberately accept rather than reject**, because rejecting
    /// them would break working deployments in the name of conformance:
    ///
    /// - *This node declares nothing.* A daemon that has not been taught to
    ///   populate a registry would otherwise refuse every peer the moment this
    ///   code landed. An empty local registry means "not participating in
    ///   negotiation", not "supports nothing".
    /// - *The peer advertises nothing.* Its CER is then non-conformant, but the
    ///   pre-existing behaviour accepted it, and turning that into a hard
    ///   rejection is a separate decision from implementing negotiation. It is
    ///   logged at warn so it is visible.
    ///
    /// An empty intersection between two non-empty sets is the case the RFC
    /// actually describes, and that is refused.
    pub fn negotiate(&self, peer_apps: &[ApplicationId]) -> Option<Vec<ApplicationId>> {
        if self.is_empty() {
            log::debug!("no local applications declared; skipping capability negotiation");
            return Some(Vec::new());
        }
        if peer_apps.is_empty() {
            log::warn!(
                "peer advertised no applications in its CER (RFC 6733 §5.3.1 requires at least \
                 one); accepting for backward compatibility"
            );
            return Some(Vec::new());
        }

        let common = self.common_with(peer_apps);
        if common.is_empty() {
            return None;
        }
        Some(common)
    }
}

/// Extract every application a CER/CEA advertises.
///
/// Reads bare `Auth-Application-Id` and `Acct-Application-Id`, plus the
/// `Auth-Application-Id` nested inside each `Vendor-Specific-Application-Id`
/// group. A group missing its inner `Auth-Application-Id` is skipped rather than
/// guessed at.
pub fn advertised_applications(msg: &DiameterMessage) -> Vec<ApplicationId> {
    let mut apps = Vec::new();

    for avp in &msg.avps {
        match avp.code {
            avp_code::AUTH_APPLICATION_ID | avp_code::ACCT_APPLICATION_ID => {
                if let Some(id) = avp.as_u32() {
                    apps.push(ApplicationId::ietf(id));
                }
            }
            avp_code::VENDOR_SPECIFIC_APPLICATION_ID => {
                // `parse_grouped`, NOT `if let AvpData::Grouped`. A decoded AVP
                // arrives as Raw/OctetString because the wire format carries no
                // type information, so matching only the in-memory Grouped
                // variant silently found nothing for every CER that had actually
                // been over a socket -- which is the only case that matters.
                let Ok(inner) = avp.parse_grouped() else {
                    log::warn!(
                        "Vendor-Specific-Application-Id is not decodable as grouped; ignored"
                    );
                    continue;
                };
                let vendor = inner
                    .iter()
                    .find(|a| a.code == avp_code::VENDOR_ID)
                    .and_then(|a| a.as_u32());
                let id = inner
                    .iter()
                    .find(|a| {
                        a.code == avp_code::AUTH_APPLICATION_ID
                            || a.code == avp_code::ACCT_APPLICATION_ID
                    })
                    .and_then(|a| a.as_u32());
                if let Some(id) = id {
                    apps.push(ApplicationId { id, vendor });
                }
            }
            _ => {}
        }
    }

    apps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{base_cmd, DiameterMessage, BASE_APPLICATION_ID};
    use std::net::{IpAddr, Ipv4Addr};

    fn cer() -> DiameterMessage {
        DiameterMessage::new_request(base_cmd::CAPABILITIES_EXCHANGE, BASE_APPLICATION_ID)
    }

    fn hss_registry() -> ApplicationRegistry {
        ApplicationRegistry::new("NextGCore HSS")
            .with_application(well_known::S6A)
            .with_application(well_known::CX)
            .with_application(well_known::SWX)
    }

    /// The three AVPs the CER ABNF makes mandatory and that were missing
    /// entirely (RFC 6733 §5.3.1).
    #[test]
    fn capabilities_include_the_mandatory_cer_avps() {
        let mut msg = cer();
        hss_registry().append_capabilities(&mut msg, &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]);

        assert!(
            msg.find_avp(avp_code::HOST_IP_ADDRESS).is_some(),
            "Host-IP-Address is mandatory"
        );
        assert!(
            msg.find_avp(avp_code::VENDOR_ID).is_some(),
            "Vendor-Id is mandatory"
        );
        assert!(
            msg.find_avp(avp_code::PRODUCT_NAME).is_some(),
            "Product-Name is mandatory"
        );
    }

    /// A node's own Vendor-Id is 0 (RFC 6733 §5.3.3) even though its
    /// applications are 3GPP vendor-specific. Conflating the two is the easy
    /// error, so it is pinned.
    #[test]
    fn node_vendor_id_is_zero_not_the_application_vendor() {
        let mut msg = cer();
        hss_registry().append_capabilities(&mut msg, &[]);
        assert_eq!(
            msg.find_avp(avp_code::VENDOR_ID).and_then(|a| a.as_u32()),
            Some(0)
        );
    }

    /// Every 3GPP application is advertised inside a
    /// Vendor-Specific-Application-Id group carrying Vendor-Id 10415.
    #[test]
    fn threegpp_applications_are_advertised_vendor_specifically() {
        let mut msg = cer();
        hss_registry().append_capabilities(&mut msg, &[]);

        let groups: Vec<_> = msg
            .avps
            .iter()
            .filter(|a| a.code == avp_code::VENDOR_SPECIFIC_APPLICATION_ID)
            .collect();
        assert_eq!(groups.len(), 3, "S6a, Cx and SWx");

        for g in groups {
            let AvpData::Grouped(inner) = &g.data else {
                panic!("Vendor-Specific-Application-Id must be grouped")
            };
            assert_eq!(
                inner
                    .iter()
                    .find(|a| a.code == avp_code::VENDOR_ID)
                    .and_then(|a| a.as_u32()),
                Some(NEXTGCORE_3GPP_VENDOR_ID)
            );
            assert!(inner
                .iter()
                .any(|a| a.code == avp_code::AUTH_APPLICATION_ID));
        }
    }

    /// Gy is RFC 4006, not 3GPP, so it must be a bare Auth-Application-Id.
    #[test]
    fn ietf_applications_are_advertised_bare() {
        let mut msg = cer();
        ApplicationRegistry::new("charging")
            .with_application(well_known::GY)
            .append_capabilities(&mut msg, &[]);

        assert_eq!(
            msg.find_avp(avp_code::AUTH_APPLICATION_ID)
                .and_then(|a| a.as_u32()),
            Some(4)
        );
        assert!(
            !msg.avps
                .iter()
                .any(|a| a.code == avp_code::VENDOR_SPECIFIC_APPLICATION_ID),
            "an IETF application must not be wrapped in a vendor group"
        );
    }

    /// Declaring a 3GPP application implies Supported-Vendor-Id 10415.
    #[test]
    fn declaring_a_vendor_application_adds_its_supported_vendor_id() {
        let mut msg = cer();
        ApplicationRegistry::new("mme")
            .with_application(well_known::S6A)
            .append_capabilities(&mut msg, &[]);

        assert_eq!(
            msg.find_avp(avp_code::SUPPORTED_VENDOR_ID)
                .and_then(|a| a.as_u32()),
            Some(NEXTGCORE_3GPP_VENDOR_ID)
        );
    }

    /// What one node writes, another must be able to read.
    #[test]
    fn advertised_applications_round_trips_through_a_cer() {
        let mut msg = cer();
        hss_registry().append_capabilities(&mut msg, &[]);

        let mut ids: Vec<u32> = advertised_applications(&msg).iter().map(|a| a.id).collect();
        ids.sort_unstable();
        let mut expected = vec![well_known::S6A.id, well_known::CX.id, well_known::SWX.id];
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    /// The case RFC 6733 §5.3 actually describes: two non-empty sets that do not
    /// intersect must be refused.
    #[test]
    fn no_common_application_is_refused() {
        // An MME (S6a) meeting a PCRF (Gx + Rx).
        let mme = ApplicationRegistry::new("mme").with_application(well_known::S6A);
        let peer = vec![well_known::GX, well_known::RX];
        assert!(
            mme.negotiate(&peer).is_none(),
            "no common application must be refused"
        );
    }

    #[test]
    fn overlapping_applications_are_accepted_and_reported() {
        let hss = hss_registry();
        // An MME advertising S6a only.
        let common = hss
            .negotiate(&[well_known::S6A])
            .expect("S6a is common to both");
        assert_eq!(common.len(), 1);
        assert_eq!(common[0].id, well_known::S6A.id);
    }

    /// A peer advertising S6a as a BARE Auth-Application-Id (some stacks do)
    /// must still match our vendor-specific advertisement: the id identifies the
    /// application, and rejecting over the presentation would break interop.
    #[test]
    fn matching_ignores_how_the_application_was_advertised() {
        let hss = hss_registry();
        let bare_s6a = ApplicationId::ietf(well_known::S6A.id);
        let common = hss
            .negotiate(&[bare_s6a])
            .expect("the same id must match regardless of vendor framing");
        assert_eq!(common.len(), 1);
    }

    /// A node that declares nothing must not start refusing peers: an empty
    /// registry means "not participating", which is how every daemon behaves
    /// until it is taught to populate one.
    #[test]
    fn empty_local_registry_accepts_any_peer() {
        let empty = ApplicationRegistry::new("unconfigured");
        assert!(empty.negotiate(&[well_known::S6A]).is_some());
        assert!(empty.negotiate(&[]).is_some());
    }

    /// A peer advertising nothing is non-conformant but was previously accepted;
    /// keep accepting it (with a warning) rather than bundling a behaviour
    /// change into this one.
    #[test]
    fn peer_advertising_nothing_is_accepted_for_compatibility() {
        assert!(hss_registry().negotiate(&[]).is_some());
    }

    /// A CER that has been ENCODED AND DECODED must still yield its
    /// applications.
    ///
    /// This is the case that matters and the one an in-memory test misses: the
    /// wire format carries no type information, so a decoded grouped AVP arrives
    /// as `Raw`, not `AvpData::Grouped`. The first version of
    /// `advertised_applications` matched only the `Grouped` variant and therefore
    /// found nothing for every CER that had actually crossed a socket, while
    /// passing every in-memory test.
    #[test]
    fn applications_survive_an_encode_decode_round_trip() {
        let mut msg = cer();
        hss_registry().append_capabilities(&mut msg, &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]);

        let mut encoded = msg.encode().freeze();
        let decoded = DiameterMessage::decode(&mut encoded).expect("a CER must decode");

        let mut ids: Vec<u32> = advertised_applications(&decoded)
            .iter()
            .map(|a| a.id)
            .collect();
        ids.sort_unstable();
        let mut expected = vec![well_known::S6A.id, well_known::CX.id, well_known::SWX.id];
        expected.sort_unstable();
        assert_eq!(
            ids, expected,
            "grouped AVPs must be read via parse_grouped, not by matching AvpData::Grouped"
        );

        // The vendor inside each group must survive too.
        for app in advertised_applications(&decoded) {
            assert_eq!(app.vendor, Some(NEXTGCORE_3GPP_VENDOR_ID));
        }
    }

    /// A Vendor-Specific-Application-Id with no inner Auth-Application-Id is
    /// skipped rather than being guessed at or panicking.
    #[test]
    fn malformed_vendor_group_is_ignored() {
        let mut msg = cer();
        msg.add_avp(Avp::mandatory(
            avp_code::VENDOR_SPECIFIC_APPLICATION_ID,
            AvpData::Grouped(vec![Avp::mandatory(
                avp_code::VENDOR_ID,
                AvpData::Unsigned32(NEXTGCORE_3GPP_VENDOR_ID),
            )]),
        ));
        assert!(advertised_applications(&msg).is_empty());
    }

    /// Advertisement order is deterministic, so a CER's wire image is stable
    /// across runs (BTreeSet, not HashSet).
    #[test]
    fn advertisement_order_is_deterministic() {
        let render = || {
            let mut msg = cer();
            hss_registry().append_capabilities(&mut msg, &[]);
            advertised_applications(&msg)
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(render(), render());
        // Cx (16777216) < Gx-range < S6a (16777251) < SWx (16777265).
        assert_eq!(
            render(),
            vec![well_known::CX.id, well_known::S6A.id, well_known::SWX.id]
        );
    }
}
