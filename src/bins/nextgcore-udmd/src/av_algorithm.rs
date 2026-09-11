//! Which f1-f5* algorithm generates a subscriber's authentication vectors (#115).
//!
//! TS 33.501 §6.1.3 runs "the subscriber's authentication algorithm", which TS 35.206
//! (MILENAGE) and TS 35.231 (TUAK) both standardise. Before #115 this build called
//! MILENAGE unconditionally, so a TUAK-provisioned subscriber could not authenticate at
//! all.
//!
//! # Why the mapping is configurable rather than an enum on the wire
//!
//! TS 29.505 §5.2.3 defines `AuthenticationSubscription.algorithmId` as a string that
//! "identifies a parameter set securely stored in the UDM (ARPF) that provides details on
//! the algorithm and parameters used to generate authentication vectors", and says
//! explicitly: "Values and their meaning are **HPLMN-operator specific**."
//!
//! So there is no standard value to match on, and #115's phrasing — "an f1-f5* algorithm
//! identifier" — is not quite what the field is. The UDR stores whatever was provisioned;
//! this module is the UDM-side parameter set the spec refers to. It recognises the two
//! obvious spellings out of the box and reads `UDM_TUAK_ALGORITHM_IDS` for any others an
//! operator uses, so a deployment whose identifiers are `"alg-7"` does not have to patch
//! the binary.

/// The authentication algorithm to run for a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AvAlgorithm {
    /// TS 35.206 MILENAGE. The default, and what every subscriber provisioned before
    /// #115 gets — an absent `algorithmId` must not change existing behaviour.
    #[default]
    Milenage,
    /// TS 35.231 TUAK.
    Tuak,
}

/// Environment variable naming additional `algorithmId` values that mean TUAK.
///
/// Comma-separated, case-insensitive. Exists because the spec makes the values
/// operator-specific: an operator whose parameter sets are numbered rather than named
/// needs to say which number is TUAK without a code change.
const TUAK_IDS_ENV: &str = "UDM_TUAK_ALGORITHM_IDS";

impl AvAlgorithm {
    /// Resolve a TS 29.505 `algorithmId` to an algorithm.
    ///
    /// `None` or an unrecognised value resolves to MILENAGE, which is deliberate and is
    /// the only safe default: an unknown identifier means the operator's parameter set is
    /// not configured here, and MILENAGE is what this build has always done. It is logged
    /// at warn so the mismatch is visible rather than silently producing vectors the UE
    /// cannot verify.
    pub fn from_algorithm_id(algorithm_id: Option<&str>) -> Self {
        let Some(id) = algorithm_id.map(str::trim).filter(|s| !s.is_empty()) else {
            return Self::Milenage;
        };
        let lower = id.to_ascii_lowercase();
        if lower == "tuak" || lower == "tuak1.0" {
            return Self::Tuak;
        }
        if lower == "milenage" {
            return Self::Milenage;
        }
        if Self::env_tuak_ids().contains(&lower) {
            return Self::Tuak;
        }
        log::warn!(
            "algorithmId '{id}' is not a parameter set this UDM knows, so MILENAGE is \
             used (TS 29.505 makes these values HPLMN-operator specific). Add it to \
             {TUAK_IDS_ENV} if it names a TUAK parameter set."
        );
        Self::Milenage
    }

    /// The operator-configured TUAK identifiers, lower-cased.
    fn env_tuak_ids() -> Vec<String> {
        std::env::var(TUAK_IDS_ENV)
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Why an authentication vector could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvError {
    /// The selected algorithm's operator field is not provisioned.
    MissingOperatorField {
        /// Which field, named as TS 29.505 spells it.
        field: &'static str,
    },
    /// The algorithm itself refused the inputs.
    Algorithm(String),
}

impl std::fmt::Display for AvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOperatorField { field } => {
                write!(f, "{field} is not provisioned for this subscriber")
            }
            Self::Algorithm(msg) => write!(f, "{msg}"),
        }
    }
}

/// The subscriber material an authentication vector is computed from.
pub struct AvInputs<'a> {
    /// Permanent key K.
    pub k: &'a [u8; 16],
    /// MILENAGE operator field OPc.
    pub opc: &'a [u8; 16],
    /// TUAK operator field TOPc, when provisioned.
    pub topc: Option<&'a [u8; 32]>,
    /// Authentication management field.
    pub amf: &'a [u8; 2],
    /// Sequence number.
    pub sqn: &'a [u8; 6],
    /// The challenge.
    pub rand: &'a [u8; 16],
}

/// Compute an authentication vector with the subscriber's own algorithm
/// (TS 33.501 §6.1.3), returning `(autn, ik, ck, ak, res)`.
///
/// The single decision point for which algorithm runs, called from exactly one place in
/// `app.rs`. A function rather than an inline `match` so the branch is testable without
/// standing up a UDR, an SBI server and a UE context — and so there is no second copy of
/// the rule for a test to agree with instead of the real one.
pub fn generate_av(
    algorithm: AvAlgorithm,
    inputs: &AvInputs<'_>,
) -> Result<([u8; 16], [u8; 16], [u8; 16], [u8; 6], [u8; 8]), AvError> {
    match algorithm {
        AvAlgorithm::Milenage => nextgcore_crypt::milenage::milenage_generate(
            inputs.opc,
            inputs.amf,
            inputs.k,
            inputs.sqn,
            inputs.rand,
        )
        .map_err(|e| AvError::Algorithm(format!("Milenage generate failed: {e:?}"))),
        AvAlgorithm::Tuak => {
            // TOPc is to TUAK what OPc is to MILENAGE, and there is no substitute: OPc is
            // 128-bit and TUAK's operator field is 256-bit, so falling back to it would
            // not merely be wrong, it would not fit. Refusing is the honest outcome —
            // producing a MILENAGE vector instead would hand the AMF an AV the UE can
            // never verify, which surfaces at the UE as an authentication failure and
            // tells the operator nothing about the provisioning gap that caused it.
            let topc = inputs.topc.ok_or(AvError::MissingOperatorField {
                field: "encTopcKey",
            })?;
            nextgcore_crypt::tuak::tuak_generate(
                topc,
                inputs.amf,
                inputs.k,
                inputs.sqn,
                inputs.rand,
                1,
            )
            .map_err(|e| AvError::Algorithm(format!("TUAK generate failed: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one behaviour that must not change: no `algorithmId` means MILENAGE, which is
    /// what every subscriber provisioned before #115 has.
    #[test]
    fn an_absent_or_empty_algorithm_id_is_milenage() {
        assert_eq!(AvAlgorithm::from_algorithm_id(None), AvAlgorithm::Milenage);
        assert_eq!(
            AvAlgorithm::from_algorithm_id(Some("")),
            AvAlgorithm::Milenage
        );
        assert_eq!(
            AvAlgorithm::from_algorithm_id(Some("   ")),
            AvAlgorithm::Milenage
        );
        assert_eq!(AvAlgorithm::default(), AvAlgorithm::Milenage);
    }

    #[test]
    fn the_well_known_spellings_resolve_without_configuration() {
        for id in ["tuak", "TUAK", "Tuak", "tuak1.0", "TUAK1.0"] {
            assert_eq!(
                AvAlgorithm::from_algorithm_id(Some(id)),
                AvAlgorithm::Tuak,
                "'{id}' must resolve to TUAK"
            );
        }
        for id in ["milenage", "MILENAGE", "Milenage"] {
            assert_eq!(
                AvAlgorithm::from_algorithm_id(Some(id)),
                AvAlgorithm::Milenage
            );
        }
    }

    /// An unknown identifier falls back to MILENAGE rather than failing the
    /// authentication: the identifier names an operator parameter set this UDM has not
    /// been told about, and refusing would turn a configuration gap into an outage for a
    /// subscriber whose keys are perfectly usable.
    #[test]
    fn an_unknown_algorithm_id_falls_back_to_milenage() {
        assert_eq!(
            AvAlgorithm::from_algorithm_id(Some("alg-7")),
            AvAlgorithm::Milenage
        );
    }
    // ------------------------------------------------------------------
    // The AV branch (#115)
    // ------------------------------------------------------------------

    fn inputs<'a>(topc: Option<&'a [u8; 32]>) -> AvInputs<'a> {
        // Leaked so the borrows outlive the helper; test-only, and bounded.
        static K: [u8; 16] = [0xab; 16];
        static OPC: [u8; 16] = [0x55; 16];
        static AMF: [u8; 2] = [0xff; 2];
        static SQN: [u8; 6] = [0x11; 6];
        static RAND: [u8; 16] = [0x42; 16];
        AvInputs {
            k: &K,
            opc: &OPC,
            topc,
            amf: &AMF,
            sqn: &SQN,
            rand: &RAND,
        }
    }

    /// A TUAK-provisioned subscriber gets a TUAK-derived vector, and a MILENAGE one gets a
    /// MILENAGE-derived vector — asserted by comparing against each algorithm's own output
    /// for the same inputs, so "it produced something" cannot pass for "it produced the
    /// right thing".
    #[test]
    fn the_branch_runs_the_algorithm_the_identifier_names() {
        let topc = nextgcore_crypt::tuak::tuak_topc(&[0x55u8; 32], &[0xabu8; 16], 1).unwrap();
        let inp = inputs(Some(&topc));

        let (mil_autn, mil_ik, mil_ck, _, mil_res) =
            generate_av(AvAlgorithm::Milenage, &inp).expect("milenage");
        let (tuak_autn, tuak_ik, tuak_ck, _, tuak_res) =
            generate_av(AvAlgorithm::Tuak, &inp).expect("tuak");

        let expected_mil = nextgcore_crypt::milenage::milenage_generate(
            inp.opc, inp.amf, inp.k, inp.sqn, inp.rand,
        )
        .unwrap();
        let expected_tuak =
            nextgcore_crypt::tuak::tuak_generate(&topc, inp.amf, inp.k, inp.sqn, inp.rand, 1)
                .unwrap();

        assert_eq!(
            (mil_autn, mil_ik, mil_ck, mil_res),
            (
                expected_mil.0,
                expected_mil.1,
                expected_mil.2,
                expected_mil.4
            ),
            "the MILENAGE arm must produce exactly milenage_generate's vector"
        );
        assert_eq!(
            (tuak_autn, tuak_ik, tuak_ck, tuak_res),
            (
                expected_tuak.0,
                expected_tuak.1,
                expected_tuak.2,
                expected_tuak.4
            ),
            "the TUAK arm must produce exactly tuak_generate's vector"
        );
        assert_ne!(
            mil_autn, tuak_autn,
            "the two arms must not coincide, or the branch could be wired either way \
             undetectably"
        );
    }

    /// Resolution and generation compose: an `algorithmId` of "tuak" reaches the TUAK arm.
    ///
    /// This is the wiring, expressed over the two functions the handler calls in sequence,
    /// so a change to either is caught.
    #[test]
    fn a_tuak_algorithm_id_reaches_the_tuak_arm() {
        let topc = nextgcore_crypt::tuak::tuak_topc(&[0x55u8; 32], &[0xabu8; 16], 1).unwrap();
        let inp = inputs(Some(&topc));

        let via_id = generate_av(AvAlgorithm::from_algorithm_id(Some("tuak")), &inp).unwrap();
        let direct =
            nextgcore_crypt::tuak::tuak_generate(&topc, inp.amf, inp.k, inp.sqn, inp.rand, 1)
                .unwrap();
        assert_eq!(via_id.0, direct.0);

        let no_id = generate_av(AvAlgorithm::from_algorithm_id(None), &inp).unwrap();
        let mil = nextgcore_crypt::milenage::milenage_generate(
            inp.opc, inp.amf, inp.k, inp.sqn, inp.rand,
        )
        .unwrap();
        assert_eq!(
            no_id.0, mil.0,
            "no algorithmId must still mean MILENAGE, so no existing subscriber changes"
        );
    }

    /// A TUAK subscriber with no TOPc is REFUSED, not silently served a MILENAGE vector.
    #[test]
    fn tuak_without_a_topc_is_refused_rather_than_falling_back() {
        let inp = inputs(None);
        assert_eq!(
            generate_av(AvAlgorithm::Tuak, &inp),
            Err(AvError::MissingOperatorField {
                field: "encTopcKey"
            }),
            "a TUAK subscriber with no operator field must fail loudly: a MILENAGE vector \
             here would be one the UE can never verify"
        );
        // And MILENAGE is unaffected by the absence of a TUAK field.
        assert!(generate_av(AvAlgorithm::Milenage, &inp).is_ok());
    }
}
