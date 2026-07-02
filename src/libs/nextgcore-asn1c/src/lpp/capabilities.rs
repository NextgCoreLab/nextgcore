//! LPP capability bodies (3GPP TS 37.355 §6.3), UNALIGNED PER.
//!
//! Implements the capability-transfer message bodies:
//!   * `RequestCapabilities` / `ProvideCapabilities` and their
//!     `criticalExtensions` → `c1` → `*-r9-IEs` nesting (identical wrapper to
//!     the location-information bodies in [`crate::lpp::ecid`]),
//!   * the per-method capability containers — `CommonIEs*Capabilities` and
//!     `ECID-*Capabilities`.
//!
//! v1 FOUNDATION scope: the `common` and `ecid` root methods are typed; the
//! other root methods (A-GNSS, OTDOA, EPDU) are modeled UNSUPPORTED-ABSENT
//! (never emitted; rejected on decode if a peer sets the presence bit). The
//! `CommonIEs*Capabilities` and `ECID-RequestCapabilities` SEQUENCEs have an
//! EMPTY root in the j20 ASN.1; their later-release capability flags (r13/r14/
//! r17/r18) live in extension-addition groups and are deferred to a follow-on
//! chunk — on decode those additions are read and discarded (forward-compat).

use bitvec::prelude::*;

use crate::per::{PerError, PerResult};
use crate::uper::{UperDecode, UperDecoder, UperEncode, UperEncoder};

// ---------------------------------------------------------------------------
// RequestCapabilities
// ---------------------------------------------------------------------------

/// RequestCapabilities ::= SEQUENCE {
///     criticalExtensions CHOICE {
///         c1 CHOICE {
///             requestCapabilities-r9 RequestCapabilities-r9-IEs,
///             spare3 NULL, spare2 NULL, spare1 NULL },
///         criticalExtensionsFuture SEQUENCE {} } }
///
/// Same non-extensible-outer-SEQUENCE wrapper as the location-information
/// bodies: no preamble bits, then the criticalExtensions/c1 CHOICE indices.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestCapabilities {
    pub ies: RequestCapabilitiesR9,
}

impl UperEncode for RequestCapabilities {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // criticalExtensions CHOICE: c1 (index 0 of 2, non-extensible).
        encoder.encode_choice_index(0, 2, false)?;
        // c1 CHOICE: requestCapabilities-r9 (index 0 of 4, non-extensible).
        encoder.encode_choice_index(0, 4, false)?;
        self.ies.encode_uper(encoder)
    }
}

impl UperDecode for RequestCapabilities {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let critical_extensions = decoder.decode_choice_index(2, false)?;
        if critical_extensions != 0 {
            return Err(PerError::DecodeError(
                "LPP RequestCapabilities criticalExtensionsFuture not supported".to_string(),
            ));
        }
        let c1 = decoder.decode_choice_index(4, false)?;
        if c1 != 0 {
            return Err(PerError::DecodeError(format!(
                "LPP RequestCapabilities c1 index {c1} (spare) not supported"
            )));
        }
        let ies = RequestCapabilitiesR9::decode_uper(decoder)?;
        Ok(RequestCapabilities { ies })
    }
}

/// RequestCapabilities-r9-IEs ::= SEQUENCE {  -- EXTENSIBLE
///     commonIEsRequestCapabilities CommonIEsRequestCapabilities OPTIONAL,
///     a-gnss-RequestCapabilities   OPTIONAL,
///     otdoa-RequestCapabilities    OPTIONAL,
///     ecid-RequestCapabilities     ECID-RequestCapabilities OPTIONAL,
///     epdu-RequestCapabilities     OPTIONAL,
///     ..., [[ ...later release groups... ]] }
///
/// v1 types the `common` and `ecid` root methods; a-gnss, otdoa and epdu are
/// UNSUPPORTED-ABSENT.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestCapabilitiesR9 {
    pub common: Option<CommonIEsRequestCapabilities>,
    pub ecid: Option<EcidRequestCapabilities>,
}

impl UperEncode for RequestCapabilitiesR9 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        // Root presence bits: [commonIEs, a-gnss, otdoa, ecid, epdu].
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.common.is_some(),
                false,
                false,
                self.ecid.is_some(),
                false,
            ],
        );
        if let Some(common) = &self.common {
            common.encode_uper(encoder)?;
        }
        if let Some(ecid) = &self.ecid {
            ecid.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for RequestCapabilitiesR9 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 5)?;
        // opts = [commonIEs, a-gnss, otdoa, ecid, epdu]
        if opts[1] || opts[2] || opts[4] {
            return Err(PerError::DecodeError(
                "unsupported LPP RequestCapabilities method present (v1 supports common + E-CID)"
                    .to_string(),
            ));
        }
        let common = if opts[0] {
            Some(CommonIEsRequestCapabilities::decode_uper(decoder)?)
        } else {
            None
        };
        let ecid = if opts[3] {
            Some(EcidRequestCapabilities::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(RequestCapabilitiesR9 { common, ecid })
    }
}

// ---------------------------------------------------------------------------
// ProvideCapabilities
// ---------------------------------------------------------------------------

/// ProvideCapabilities ::= SEQUENCE {
///     criticalExtensions CHOICE {
///         c1 CHOICE {
///             provideCapabilities-r9 ProvideCapabilities-r9-IEs,
///             spare3 NULL, spare2 NULL, spare1 NULL },
///         criticalExtensionsFuture SEQUENCE {} } }
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideCapabilities {
    pub ies: ProvideCapabilitiesR9,
}

impl UperEncode for ProvideCapabilities {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_choice_index(0, 2, false)?;
        encoder.encode_choice_index(0, 4, false)?;
        self.ies.encode_uper(encoder)
    }
}

impl UperDecode for ProvideCapabilities {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let critical_extensions = decoder.decode_choice_index(2, false)?;
        if critical_extensions != 0 {
            return Err(PerError::DecodeError(
                "LPP ProvideCapabilities criticalExtensionsFuture not supported".to_string(),
            ));
        }
        let c1 = decoder.decode_choice_index(4, false)?;
        if c1 != 0 {
            return Err(PerError::DecodeError(format!(
                "LPP ProvideCapabilities c1 index {c1} (spare) not supported"
            )));
        }
        let ies = ProvideCapabilitiesR9::decode_uper(decoder)?;
        Ok(ProvideCapabilities { ies })
    }
}

/// ProvideCapabilities-r9-IEs ::= SEQUENCE {  -- EXTENSIBLE
///     commonIEsProvideCapabilities CommonIEsProvideCapabilities OPTIONAL,
///     a-gnss-ProvideCapabilities   OPTIONAL,
///     otdoa-ProvideCapabilities    OPTIONAL,
///     ecid-ProvideCapabilities     ECID-ProvideCapabilities OPTIONAL,
///     epdu-ProvideCapabilities     OPTIONAL,
///     ..., [[ ...later release groups... ]] }
#[derive(Debug, Clone, PartialEq)]
pub struct ProvideCapabilitiesR9 {
    pub common: Option<CommonIEsProvideCapabilities>,
    pub ecid: Option<EcidProvideCapabilities>,
}

impl UperEncode for ProvideCapabilitiesR9 {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(
            Some(false),
            &[
                self.common.is_some(),
                false,
                false,
                self.ecid.is_some(),
                false,
            ],
        );
        if let Some(common) = &self.common {
            common.encode_uper(encoder)?;
        }
        if let Some(ecid) = &self.ecid {
            ecid.encode_uper(encoder)?;
        }
        Ok(())
    }
}

impl UperDecode for ProvideCapabilitiesR9 {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, opts) = decoder.decode_sequence_preamble(true, 5)?;
        if opts[1] || opts[2] || opts[4] {
            return Err(PerError::DecodeError(
                "unsupported LPP ProvideCapabilities method present (v1 supports common + E-CID)"
                    .to_string(),
            ));
        }
        let common = if opts[0] {
            Some(CommonIEsProvideCapabilities::decode_uper(decoder)?)
        } else {
            None
        };
        let ecid = if opts[3] {
            Some(EcidProvideCapabilities::decode_uper(decoder)?)
        } else {
            None
        };
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(ProvideCapabilitiesR9 { common, ecid })
    }
}

// ---------------------------------------------------------------------------
// Empty-root extensible capability containers
// ---------------------------------------------------------------------------

/// CommonIEsRequestCapabilities ::= SEQUENCE { ..., [[r14...]], [[r18...]] }
/// EMPTY ROOT, EXTENSIBLE. The root carries no fields, so the encoding is just
/// the SEQUENCE extension-marker bit. The later-release capability flags are
/// deferred to a follow-on chunk (read+discarded as extension additions here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonIEsRequestCapabilities;

impl UperEncode for CommonIEsRequestCapabilities {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        Ok(())
    }
}

impl UperDecode for CommonIEsRequestCapabilities {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(CommonIEsRequestCapabilities)
    }
}

/// CommonIEsProvideCapabilities ::= SEQUENCE { ..., [[r14...]], [[r18...]] }
/// EMPTY ROOT, EXTENSIBLE (see [`CommonIEsRequestCapabilities`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonIEsProvideCapabilities;

impl UperEncode for CommonIEsProvideCapabilities {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        Ok(())
    }
}

impl UperDecode for CommonIEsProvideCapabilities {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(CommonIEsProvideCapabilities)
    }
}

/// ECID-RequestCapabilities ::= SEQUENCE { ... }
/// EMPTY ROOT, EXTENSIBLE — the UE has no per-request E-CID capability fields to
/// signal in the root, so the encoding is just the SEQUENCE extension-marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcidRequestCapabilities;

impl UperEncode for EcidRequestCapabilities {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        Ok(())
    }
}

impl UperDecode for EcidRequestCapabilities {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidRequestCapabilities)
    }
}

// ---------------------------------------------------------------------------
// ECID-ProvideCapabilities
// ---------------------------------------------------------------------------

/// ECID-ProvideCapabilities ::= SEQUENCE {  -- EXTENSIBLE
///     ecid-MeasSupported BIT STRING {
///         rsrpSup(0), rsrqSup(1), ueRxTxSup(2),
///         nrsrpSup-r14(3), nrsrqSup-r14(4) } (SIZE(1..8)),
///     ..., [[ueRxTxSupTDD-r13]], [[periodical/triggered/idleState-r14]], [[r17]], [[r18]] }
///
/// Mirrors `ECID-RequestLocationInformation`: a single SIZE(1..8) measurement
/// bit map in the root. The r13/r14/r17/r18 capability flags are deferred to a
/// follow-on chunk (decoded extension additions are discarded).
#[derive(Debug, Clone, PartialEq)]
pub struct EcidProvideCapabilities {
    /// ecid-MeasSupported bit map, SIZE(1..8): bit 0 = rsrpSup, bit 1 = rsrqSup,
    /// bit 2 = ueRxTxSup, bit 3 = nrsrpSup-r14, bit 4 = nrsrqSup-r14.
    pub ecid_meas_supported: BitVec<u8, Msb0>,
}

impl UperEncode for EcidProvideCapabilities {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()> {
        encoder.encode_sequence_preamble(Some(false), &[]);
        encoder.encode_bit_string(&self.ecid_meas_supported, Some(1), Some(8))
    }
}

impl UperDecode for EcidProvideCapabilities {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self> {
        let (ext, _opts) = decoder.decode_sequence_preamble(true, 0)?;
        let ecid_meas_supported = decoder.decode_bit_string(Some(1), Some(8))?;
        if ext {
            decoder.decode_extension_additions()?;
        }
        Ok(EcidProvideCapabilities {
            ecid_meas_supported,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: UperEncode + UperDecode + PartialEq + std::fmt::Debug,
    {
        let mut enc = UperEncoder::new();
        value.encode_uper(&mut enc).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        let decoded = T::decode_uper(&mut dec).unwrap();
        assert_eq!(&decoded, value);
    }

    fn bits(values: &[bool]) -> BitVec<u8, Msb0> {
        let mut bv: BitVec<u8, Msb0> = BitVec::new();
        for &b in values {
            bv.push(b);
        }
        bv
    }

    #[test]
    fn rt_empty_root_containers() {
        roundtrip(&CommonIEsRequestCapabilities);
        roundtrip(&CommonIEsProvideCapabilities);
        roundtrip(&EcidRequestCapabilities);
    }

    #[test]
    fn rt_ecid_provide_capabilities() {
        let cases: [&[bool]; 3] = [
            &[true],
            &[true, true, false, false, false],
            &[true, true, true, true, true, true, true, true],
        ];
        for case in cases {
            roundtrip(&EcidProvideCapabilities {
                ecid_meas_supported: bits(case),
            });
        }
    }

    #[test]
    fn rt_request_capabilities_matrix() {
        // common + ecid present
        roundtrip(&RequestCapabilities {
            ies: RequestCapabilitiesR9 {
                common: Some(CommonIEsRequestCapabilities),
                ecid: Some(EcidRequestCapabilities),
            },
        });
        // ecid only
        roundtrip(&RequestCapabilities {
            ies: RequestCapabilitiesR9 {
                common: None,
                ecid: Some(EcidRequestCapabilities),
            },
        });
        // common only
        roundtrip(&RequestCapabilities {
            ies: RequestCapabilitiesR9 {
                common: Some(CommonIEsRequestCapabilities),
                ecid: None,
            },
        });
        // both absent
        roundtrip(&RequestCapabilities {
            ies: RequestCapabilitiesR9 {
                common: None,
                ecid: None,
            },
        });
    }

    #[test]
    fn rt_provide_capabilities_matrix() {
        // common + ecid present
        roundtrip(&ProvideCapabilities {
            ies: ProvideCapabilitiesR9 {
                common: Some(CommonIEsProvideCapabilities),
                ecid: Some(EcidProvideCapabilities {
                    ecid_meas_supported: bits(&[true, true, false, false, false]),
                }),
            },
        });
        // ecid only
        roundtrip(&ProvideCapabilities {
            ies: ProvideCapabilitiesR9 {
                common: None,
                ecid: Some(EcidProvideCapabilities {
                    ecid_meas_supported: bits(&[true]),
                }),
            },
        });
        // both absent
        roundtrip(&ProvideCapabilities {
            ies: ProvideCapabilitiesR9 {
                common: None,
                ecid: None,
            },
        });
    }

    #[test]
    fn err_request_capabilities_unsupported_method() {
        // Preamble: ext 0 + presence [commonIEs=0, a-gnss=1, otdoa=0, ecid=0,
        // epdu=0] = `0 0 1 0 0 0` -> 0010_0000 = 0x20. a-gnss is UNSUPPORTED.
        let mut dec = UperDecoder::new(&[0x20]);
        assert!(RequestCapabilitiesR9::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn err_provide_capabilities_unsupported_method() {
        let mut dec = UperDecoder::new(&[0x20]);
        assert!(ProvideCapabilitiesR9::decode_uper(&mut dec).is_err());
    }

    #[test]
    fn err_request_capabilities_future() {
        // criticalExtensions CHOICE index 1 (criticalExtensionsFuture).
        let mut dec = UperDecoder::new(&[0x80]);
        assert!(RequestCapabilities::decode_uper(&mut dec).is_err());
    }
}
