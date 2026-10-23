//! #726: X.691 golden bytes for the UCMF's TS 38.331 / TS 36.331 transcoding and
//! paging derivation, derived independently of the generated codecs.
//!
//! The tests in `rac/tests.rs` build their inputs with the generated codecs and
//! check outputs by decoding them with the same codecs. That proves round-trip
//! consistency, not X.691 conformance: a codec defect (a CHOICE index width, an
//! extension bit, an OCTET STRING length determinant) would move both sides at
//! once. Here every expected value is:
//!
//! 1. a **literal**, which no codec change can move;
//! 2. **derived field by field** from the ASN.1 with [`Bits`], a bit writer that
//!    shares no code with `asn1-codecs`. Each `put` is one field of the ASN.1,
//!    and its comment gives the field and the X.691 rule that sets its width;
//! 3. the **same bytes** the reviewer of #603 derived by hand (#726), for the
//!    three vectors that review gave.
//!
//! X.691 (02/2021) rules used. UPER (unaligned) unless noted:
//! - SEQUENCE (§19): an extension bit if the type has `...`, then one presence
//!   bit per OPTIONAL/DEFAULT component, then the components.
//! - CHOICE (§23): the alternative index as a constrained whole number of
//!   ⌈log2 n⌉ bits; no bit for an extension marker the type does not have.
//! - ENUMERATED (§14): an extension bit if the type has `...`, then the root
//!   index in ⌈log2 n_root⌉ bits.
//! - INTEGER (lb..ub) (§13, §11.5.7.1 unaligned): `value − lb` in ⌈log2 range⌉
//!   bits; INTEGER (0) has a range of 1 and takes no bits.
//! - BOOLEAN (§12): one bit.
//! - SEQUENCE (SIZE (lb..ub)) OF (§20): `count − lb` as above, then the items.
//! - OCTET STRING with no size constraint (§17.8, §11.9): a length determinant
//!   (one octet `0LLLLLLL` below 128), then the octets, not aligned under UPER.
//!   `OCTET STRING (CONTAINING T)` carries the complete encoding of `T`.
//! - A complete encoding is padded with zero bits to an octet, and is at least
//!   one octet (§11.1).
//! - APER (NGAP, TS 38.413): as UPER, except that an unconstrained OCTET STRING
//!   is octet-aligned, both its length determinant and its octets.

use super::*;

/// An X.691 bit field writer, independent of the generated codecs.
#[derive(Default)]
struct Bits {
    bits: Vec<bool>,
}

impl Bits {
    /// `value` in `width` bits, most significant first.
    fn put(&mut self, value: u64, width: u32) -> &mut Self {
        assert!(
            width == 64 || value < (1 << width),
            "{value} does not fit {width} bits"
        );
        for i in (0..width).rev() {
            self.bits.push((value >> i) & 1 == 1);
        }
        self
    }

    /// Octets, unaligned (UPER).
    fn octets(&mut self, bytes: &[u8]) -> &mut Self {
        for b in bytes {
            self.put(u64::from(*b), 8);
        }
        self
    }

    /// An unconstrained OCTET STRING under UPER (§17.8): length, then octets.
    fn octet_string(&mut self, bytes: &[u8]) -> &mut Self {
        assert!(bytes.len() < 128, "one-octet length determinant only");
        self.put(bytes.len() as u64, 8).octets(bytes)
    }

    /// Zero bits to the next octet boundary (APER alignment).
    fn align(&mut self) -> &mut Self {
        while !self.bits.len().is_multiple_of(8) {
            self.bits.push(false);
        }
        self
    }

    /// The complete encoding: padded to an octet, at least one octet (§11.1).
    fn finish(&mut self) -> Vec<u8> {
        self.align();
        if self.bits.is_empty() {
            self.put(0, 8);
        }
        self.bits
            .chunks(8)
            .map(|o| o.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b)))
            .collect()
    }
}

// --------------------------------------------------------------- TS 38.331

/// TS 38.331 `UE-NR-Capability`: Rel-15, PDCP without ROHC, and one minimal
/// `BandNR` per band, everything optional absent. This is what
/// [`ue_nr_capability`] builds.
fn hand_ue_nr_capability(bands: &[u16]) -> Vec<u8> {
    let mut w = Bits::default();
    // UE-NR-Capability: no extension marker; 11 OPTIONAL components, absent
    // (rlc, mac, measAndMob, fdd-Add, tdd-Add, fr1-Add, fr2-Add, featureSets,
    // featureSetCombinations, lateNonCriticalExtension, nonCriticalExtension).
    w.put(0, 11);
    // accessStratumRelease: ENUMERATED {rel15..spare1, ...}: extension bit,
    // then rel15 = root index 0 of 8 (3 bits).
    w.put(0, 1).put(0, 3);
    // pdcp-Parameters: extensible SEQUENCE: extension bit, then 6 OPTIONALs absent.
    w.put(0, 1).put(0, 6);
    // supportedROHC-Profiles: SEQUENCE of 10 BOOLEANs, all false.
    w.put(0, 10);
    // maxNumberROHC-ContextSessions: ENUMERATED, 16 values, no "...": cs2 = 0.
    w.put(0, 4);
    // phy-Parameters: 5 OPTIONALs, absent.
    w.put(0, 5);
    // rf-Parameters: extensible: extension bit, 2 OPTIONALs absent.
    w.put(0, 1).put(0, 2);
    // supportedBandListNR: SIZE (1..maxBands = 1024): count − 1 in 10 bits.
    w.put(bands.len() as u64 - 1, 10);
    for &b in bands {
        // BandNR: extension bit, 14 OPTIONALs absent, bandNR INTEGER (1..1024).
        w.put(0, 1).put(0, 14).put(u64::from(b) - 1, 10);
    }
    w.finish()
}

/// TS 38.331 `UE-CapabilityRAT-ContainerList` of `(rat-Type index, container)`.
fn hand_nr_container_list(containers: &[(u64, &[u8])]) -> Vec<u8> {
    let mut w = Bits::default();
    // SIZE (0..maxRAT-CapabilityContainers = 8): count in 4 bits.
    w.put(containers.len() as u64, 4);
    for (rat, c) in containers {
        // rat-Type: ENUMERATED {nr, eutra-nr, eutra, utra-fdd-v1610, ...}:
        // extension bit, root index in 2 bits. Then the OCTET STRING.
        w.put(0, 1).put(*rat, 2).octet_string(c);
    }
    w.finish()
}

/// TS 38.331 `UERadioAccessCapabilityInformation` around a container list.
fn hand_nr_racap_info(list: &[u8]) -> Vec<u8> {
    let mut w = Bits::default();
    // criticalExtensions CHOICE {c1, criticalExtensionsFuture}: c1 = 0 (1 bit).
    // c1 CHOICE of 8: ueRadioAccessCapabilityInformation = 0 (3 bits).
    // -IEs: nonCriticalExtension OPTIONAL absent (1 bit), then
    // ue-RadioAccessCapabilityInfo OCTET STRING (CONTAINING the list).
    w.put(0, 1).put(0, 3).put(0, 1).octet_string(list);
    w.finish()
}

/// TS 38.331 `UERadioPagingInformation` with `supportedBandListNRForPaging`.
fn hand_nr_paging_information(bands: &[u16]) -> Vec<u8> {
    let mut w = Bits::default();
    // c1 (1 bit), ueRadioPagingInformation (3 bits); -IEs: 2 OPTIONALs,
    // supportedBandListNRForPaging present, nonCriticalExtension absent.
    w.put(0, 1).put(0, 3).put(0b10, 2);
    // SIZE (1..maxBands = 1024), then FreqBandIndicatorNR INTEGER (1..1024).
    w.put(bands.len() as u64 - 1, 10);
    for &b in bands {
        w.put(u64::from(b) - 1, 10);
    }
    w.finish()
}

// --------------------------------------------------------------- TS 36.331

/// TS 36.331 `UE-EUTRA-Capability`, as [`ue_eutra_capability`] builds it:
/// Rel-15, category 4, no ROHC, each band full duplex, and a measParameters
/// entry per band whose interFreqBandList needs gaps for every band.
fn hand_ue_eutra_capability(bands: &[u8]) -> Vec<u8> {
    let n = bands.len() as u64;
    let mut w = Bits::default();
    // UE-EUTRA-Capability: no "..."; OPTIONALs featureGroupIndicators and
    // nonCriticalExtension absent.
    w.put(0, 2);
    // accessStratumRelease: ENUMERATED {rel8..rel15, ..., rel16..}: extension
    // bit, rel15 = root index 7 of 8.
    w.put(0, 1).put(7, 3);
    // ue-Category INTEGER (1..5): 4 − 1 in 3 bits.
    w.put(3, 3);
    // pdcp-Parameters: extension bit; maxNumberROHC-ContextSessions is DEFAULT
    // cs16 and absent (1 bit); supportedROHC-Profiles: 9 BOOLEANs, false.
    w.put(0, 1).put(0, 1).put(0, 9);
    // phyLayerParameters: 2 BOOLEANs, false.
    w.put(0, 2);
    // rf-Parameters.supportedBandListEUTRA: SIZE (1..maxBands = 64), then per
    // band bandEUTRA INTEGER (1..maxFBI = 64) and halfDuplex BOOLEAN.
    w.put(n - 1, 6);
    for &b in bands {
        w.put(u64::from(b) - 1, 6).put(0, 1);
    }
    // measParameters.bandListEUTRA: SIZE (1..64) of BandInfoEUTRA, each with
    // interRAT-BandList OPTIONAL absent and an interFreqBandList of SIZE (1..64)
    // whose interFreqNeedForGaps BOOLEANs are all true.
    w.put(n - 1, 6);
    for _ in bands {
        w.put(0, 1).put(n - 1, 6);
        for _ in bands {
            w.put(1, 1);
        }
    }
    // interRAT-Parameters: 7 OPTIONALs, absent.
    w.put(0, 7);
    w.finish()
}

/// TS 36.331 `UE-RadioPagingInfo-r12`. Extensible; the one root OPTIONAL is
/// `ue-Category-v1250 INTEGER (0)`, which takes no bits when present.
fn hand_ue_radio_paging_info_r12(category_0: bool) -> Vec<u8> {
    let mut w = Bits::default();
    w.put(0, 1).put(u64::from(category_0), 1);
    w.finish()
}

/// TS 36.331 `UECapabilityInformation` with a container list of
/// `(rat-Type index, container)`, and, with `paging_info`, a v8a0 → v1250
/// extension carrying `ue-RadioPagingInfo-r12` (category 0).
fn hand_lte_ue_capability_information(
    transaction: u64,
    containers: &[(u64, &[u8])],
    paging_info: bool,
) -> Vec<u8> {
    let mut w = Bits::default();
    // rrc-TransactionIdentifier INTEGER (0..3); criticalExtensions c1 (1 bit);
    // c1 CHOICE of 8: ueCapabilityInformation-r8 = 0 (3 bits); -r8-IEs:
    // nonCriticalExtension OPTIONAL (1 bit).
    w.put(transaction, 2)
        .put(0, 1)
        .put(0, 3)
        .put(u64::from(paging_info), 1);
    // ue-CapabilityRAT-ContainerList: SIZE (0..maxRAT-Capabilities = 8).
    w.put(containers.len() as u64, 4);
    for (rat, c) in containers {
        // rat-Type: ENUMERATED {eutra, utra, geran-cs, geran-ps, cdma2000-1XRTT,
        // nr, eutra-nr, spare1, ...}: extension bit, root index in 3 bits.
        w.put(0, 1).put(*rat, 3).octet_string(c);
    }
    if paging_info {
        // v8a0-IEs: lateNonCriticalExtension absent, nonCriticalExtension present.
        w.put(0b01, 2);
        // v1250-IEs: ue-RadioPagingInfo-r12 present, nonCriticalExtension absent.
        w.put(0b10, 2);
        // UE-RadioPagingInfo-r12 inline: extension bit, ue-Category-v1250 present.
        w.put(0, 1).put(1, 1);
    }
    w.finish()
}

/// TS 36.331 `UERadioAccessCapabilityInformation` around a
/// `UECapabilityInformation`.
fn hand_lte_racap_info(ue_capability_information: &[u8]) -> Vec<u8> {
    let mut w = Bits::default();
    // c1 (1 bit), ueRadioAccessCapabilityInformation-r8 (3 bits), -r8-IEs:
    // nonCriticalExtension absent (1 bit), then the OCTET STRING (CONTAINING).
    w.put(0, 1)
        .put(0, 3)
        .put(0, 1)
        .octet_string(ue_capability_information);
    w.finish()
}

/// TS 36.331 `UERadioPagingInformation` with `supportedBandListEUTRAForPaging-r13`.
fn hand_lte_paging_information(paging_info_r12: &[u8], bands: &[u8]) -> Vec<u8> {
    let mut w = Bits::default();
    // c1 (1 bit), ueRadioPagingInformation-r12 (3 bits); -r12-IEs:
    // nonCriticalExtension (v1310) present (1 bit); ue-RadioPagingInfo-r12
    // OCTET STRING (CONTAINING UE-RadioPagingInfo-r12).
    w.put(0, 1)
        .put(0, 3)
        .put(1, 1)
        .octet_string(paging_info_r12);
    // v1310-IEs: supportedBandListEUTRAForPaging-r13 present,
    // nonCriticalExtension absent; SIZE (1..maxBands = 64); each
    // FreqBandIndicator-r11 INTEGER (1..maxFBI2 = 256) in 8 bits.
    w.put(0b10, 2).put(bands.len() as u64 - 1, 6);
    for &b in bands {
        w.put(u64::from(b) - 1, 8);
    }
    w.finish()
}

// ----------------------------------------------------------------- NGAP APER

/// NGAP `UERadioCapabilityForPaging` (TS 38.413 §9.3.1.68), APER.
fn hand_ngap_ue_radio_capability_for_paging(of_nr: &[u8], of_eutra: &[u8]) -> Vec<u8> {
    let mut w = Bits::default();
    // Extensible SEQUENCE: extension bit; OPTIONALs ofNR present, ofEUTRA
    // present, iE-Extensions absent.
    w.put(0, 1).put(0b110, 3);
    // Each OCTET STRING (no size constraint): aligned length octet, aligned octets.
    w.align().put(of_nr.len() as u64, 8).octets(of_nr);
    w.align().put(of_eutra.len() as u64, 8).octets(of_eutra);
    w.finish()
}

// ------------------------------------------------------------- the vectors

/// `ue_nr_capability(&[78, 1])`: 104 bits. 41 zero bits of preamble and fixed
/// fields, `0 00` (RF-Parameters), count 1 (`0000000001`), BandNR 78
/// (`0 0…0 0001001101`, 77 in 10 bits), BandNR 1 (25 zero bits).
const UE_NR_CAPABILITY_78_1: [u8; 13] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x9A, 0x00, 0x00, 0x00,
];

/// `ue_eutra_capability(&[3, 7])`: 73 bits, `00 0111 011 0…` (preamble, rel15,
/// category 4, ...), bands `000001 000010 0 000110 0`, measParameters
/// `000001` and twice `0 000001 11`, then 7 zero bits.
const UE_EUTRA_CAPABILITY_3_7: [u8; 10] =
    [0x1D, 0x80, 0x00, 0x10, 0x83, 0x01, 0x03, 0x81, 0xC0, 0x00];

/// `ue_eutra_capability(&[20, 64, 3])`.
const UE_EUTRA_CAPABILITY_20_64_3: [u8; 12] = [
    0x1D, 0x80, 0x00, 0x24, 0xDF, 0x82, 0x04, 0x0B, 0x82, 0xE0, 0xB8, 0x00,
];

/// `cap_5gs()` and `tests/data/cap_5gs.bin`: the TS 38.331 wrapper
/// `0 000 0` + length 30 (`00011110`), then the list: count 3 (`0011`),
/// `0 00` nr + 13 octets, `0 10` eutra + 10 octets, `0 11` utra-fdd + `DE AD`.
/// The review of #603 (#726) derived the same header, `00 F1`.
const CAP_5GS: [u8; 32] = [
    0x00, 0xF1, 0x80, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x09, 0xA0, 0x00, 0x00,
    0x04, 0x14, 0x3B, 0x00, 0x00, 0x21, 0x06, 0x02, 0x07, 0x03, 0x80, 0x00, 0xC0, 0xB7, 0xAB, 0x40,
];

/// `transcode_5gs_to_eps(CAP_5GS)`: the TS 36.331 wrapper `0 000 0` + length
/// 28, around a `UECapabilityInformation` (transaction 0, c1, r8, no extension,
/// count 2): nr is index 5 here (`0 101`), eutra index 0 (`0 000`). UTRA-FDD is
/// dropped (TS 23.502 §5.2.18.2.1).
const EPS_OF_CAP_5GS: [u8; 30] = [
    0x00, 0xE0, 0x02, 0x50, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x09, 0xA0, 0x00,
    0x00, 0x00, 0x0A, 0x1D, 0x80, 0x00, 0x10, 0x83, 0x01, 0x03, 0x81, 0xC0, 0x00, 0x00,
];

/// `transcode_eps_to_5gs(EPS_OF_CAP_5GS)`: the TS 38.331 wrapper, length 27,
/// around count 2, `0 00` nr and `0 10` eutra: `CAP_5GS` without UTRA-FDD.
const FIVEGS_OF_EPS: [u8; 29] = [
    0x00, 0xD9, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x09, 0xA0, 0x00, 0x00,
    0x04, 0x14, 0x3B, 0x00, 0x00, 0x21, 0x06, 0x02, 0x07, 0x03, 0x80, 0x00, 0x00,
];

/// `derive_paging_eps(EPS_OF_CAP_5GS)`, as derived in the review of #603
/// (#726): `0 000 1`, length 1, `UE-RadioPagingInfo-r12` = `00` (extension bit,
/// no category, padded), `10`, count 1 (`000001`), bands 3 and 7 (`00000010`,
/// `00000110`), padding.
const PAGING_EPS_3_7: [u8; 6] = [0x08, 0x08, 0x04, 0x08, 0x10, 0x30];

/// `derive_paging_5gs(CAP_5GS)`, as derived in the review of #603 (#726):
/// `0110` (extension bit, NR and E-UTRA present, no iE-Extensions), aligned
/// length 5 and the NR `UERadioPagingInformation`
/// (`0 000 10 0000000001 0001001101 0000000000`), aligned length 6 and
/// `PAGING_EPS_3_7`.
const PAGING_5GS: [u8; 14] = [
    0x60, 0x05, 0x08, 0x01, 0x13, 0x40, 0x00, 0x06, 0x08, 0x08, 0x04, 0x08, 0x10, 0x30,
];

/// `cap_eps(true)`: transaction 2, E-UTRA (bands 20, 64, 3) and GERAN-PS
/// (`0 011`, one octet `01`), and the v8a0 → v1250 extension with
/// `ue-RadioPagingInfo-r12 { ue-Category-v1250 0 }` (`01 10 0 1`).
const CAP_EPS_CATEGORY_0: [u8; 21] = [
    0x00, 0x9C, 0x12, 0x00, 0xC1, 0xD8, 0x00, 0x02, 0x4D, 0xF8, 0x20, 0x40, 0xB8, 0x2E, 0x0B, 0x80,
    0x03, 0x01, 0x01, 0x64, 0x00,
];

/// `derive_paging_eps(CAP_EPS_CATEGORY_0)`: the UE's `ue-RadioPagingInfo-r12`
/// carried over (`01` padded: `40`), and bands 20 and 3. 64 is maxFBI, which
/// defers to bandEUTRA-v9e0 and is not a band (`00010011`, `00000010`).
const PAGING_EPS_CATEGORY_0: [u8; 6] = [0x08, 0x0A, 0x04, 0x08, 0x98, 0x10];

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Assert `actual` is the golden `expected`, with both in hex on failure.
#[track_caller]
fn golden(what: &str, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        actual,
        expected,
        "{what}\n   got {}\nwanted {}",
        hex(actual),
        hex(expected)
    );
}

// --------------------------------------------------------------- the tests

/// The derivations reproduce the literals: the literals are what X.691 gives,
/// not a snapshot of whatever the codec produced.
#[test]
fn the_hand_derivations_give_the_golden_bytes() {
    golden(
        "UE-NR-Capability",
        &hand_ue_nr_capability(&[78, 1]),
        &UE_NR_CAPABILITY_78_1,
    );
    golden(
        "UE-EUTRA-Capability",
        &hand_ue_eutra_capability(&[3, 7]),
        &UE_EUTRA_CAPABILITY_3_7,
    );
    golden(
        "UE-EUTRA-Capability (20, 64, 3)",
        &hand_ue_eutra_capability(&[20, 64, 3]),
        &UE_EUTRA_CAPABILITY_20_64_3,
    );
    let five_gs = hand_nr_racap_info(&hand_nr_container_list(&[
        (0, &UE_NR_CAPABILITY_78_1),
        (2, &UE_EUTRA_CAPABILITY_3_7),
        (3, &[0xDE, 0xAD]),
    ]));
    golden("cap_5gs", &five_gs, &CAP_5GS);
    let eps = hand_lte_racap_info(&hand_lte_ue_capability_information(
        0,
        &[(5, &UE_NR_CAPABILITY_78_1), (0, &UE_EUTRA_CAPABILITY_3_7)],
        false,
    ));
    golden("EPS of cap_5gs", &eps, &EPS_OF_CAP_5GS);
    let back = hand_nr_racap_info(&hand_nr_container_list(&[
        (0, &UE_NR_CAPABILITY_78_1),
        (2, &UE_EUTRA_CAPABILITY_3_7),
    ]));
    golden("5GS of the EPS form", &back, &FIVEGS_OF_EPS);
    golden(
        "EPS paging",
        &hand_lte_paging_information(&hand_ue_radio_paging_info_r12(false), &[3, 7]),
        &PAGING_EPS_3_7,
    );
    golden(
        "5GS paging",
        &hand_ngap_ue_radio_capability_for_paging(
            &hand_nr_paging_information(&[78, 1]),
            &PAGING_EPS_3_7,
        ),
        &PAGING_5GS,
    );
    golden(
        "cap_eps(true)",
        &hand_lte_racap_info(&hand_lte_ue_capability_information(
            2,
            &[(0, &UE_EUTRA_CAPABILITY_20_64_3), (3, &[0x01])],
            true,
        )),
        &CAP_EPS_CATEGORY_0,
    );
    golden(
        "EPS paging, category 0",
        &hand_lte_paging_information(&hand_ue_radio_paging_info_r12(true), &[20, 3]),
        &PAGING_EPS_CATEGORY_0,
    );
}

/// The inputs the other tests build with the codec are the golden encodings,
/// so the codec encodes these TS 38.331 / TS 36.331 values as X.691 says.
#[test]
fn the_test_capabilities_are_the_golden_encodings() {
    golden(
        "ue_nr_capability",
        &ue_nr_capability(&[78, 1]),
        &UE_NR_CAPABILITY_78_1,
    );
    golden(
        "ue_eutra_capability",
        &ue_eutra_capability(&[3, 7]),
        &UE_EUTRA_CAPABILITY_3_7,
    );
    golden(
        "ue_eutra_capability (20, 64, 3)",
        &ue_eutra_capability(&[20, 64, 3]),
        &UE_EUTRA_CAPABILITY_20_64_3,
    );
    golden("cap_5gs", &cap_5gs(), &CAP_5GS);
    golden("cap_eps(true)", &cap_eps(true), &CAP_EPS_CATEGORY_0);
    let file = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/cap_5gs.bin"
    ))
    .expect("tests/data/cap_5gs.bin");
    golden("tests/data/cap_5gs.bin", &file, &CAP_5GS);
}

/// TS 23.501 §5.4.4.1a mode B: the 5GS form transcoded to the EPS form, from
/// golden input to golden output.
#[test]
fn a_5gs_capability_transcodes_to_the_golden_eps_bytes() {
    golden(
        "transcode_5gs_to_eps",
        &transcode_5gs_to_eps(&CAP_5GS).unwrap(),
        &EPS_OF_CAP_5GS,
    );
}

#[test]
fn an_eps_capability_transcodes_to_the_golden_5gs_bytes() {
    golden(
        "transcode_eps_to_5gs",
        &transcode_eps_to_5gs(&EPS_OF_CAP_5GS).unwrap(),
        &FIVEGS_OF_EPS,
    );
}

#[test]
fn the_paging_capabilities_are_the_golden_bytes() {
    golden(
        "derive_paging_5gs",
        &derive_paging_5gs(&CAP_5GS).unwrap(),
        &PAGING_5GS,
    );
    golden(
        "derive_paging_eps",
        &derive_paging_eps(&EPS_OF_CAP_5GS).unwrap(),
        &PAGING_EPS_3_7,
    );
    golden(
        "derive_paging_eps, category 0",
        &derive_paging_eps(&CAP_EPS_CATEGORY_0).unwrap(),
        &PAGING_EPS_CATEGORY_0,
    );
}
