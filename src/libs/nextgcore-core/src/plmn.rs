//! PLMN ID digits as an NF's configuration file writes them (#2115).
//!
//! An MCC is 3 decimal digits and an MNC 2 or 3 (TS 23.003 §2.2; TS 29.571
//! `Mcc` `^\d{3}$`, `Mnc` `^\d{2,3}$`). The leading zeros are part of the
//! identity: TS 23.003 §2.2 itself contrasts "MNC 012 and MNC 12", which are
//! different networks.
//!
//! A config file must therefore write both as STRINGS. A value that reaches the
//! parser as a YAML number has already lost any leading zeros it had (a YAML 1.1
//! writer such as PyYAML re-dumps `mcc: "001"` as `mcc: 1`), so the parser
//! cannot know which PLMN was meant. It refuses the number rather than guess:
//! the guess the NFs used to make read the digits from the left and padded on
//! the right, so `mcc: 1` configured MCC 100. A number that lost nothing
//! (`mcc: 999`) is refused too, because the parser cannot tell where a number
//! came from.
//!
//! The wording follows the Helm chart's `nextgcore.plmnDigits` (#2069), which
//! refuses the same values on the deploy side, so an operator sees one rule
//! whichever end catches the mistake.

/// Which half of a PLMN ID a value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlmnPart {
    /// The Mobile Country Code: exactly 3 digits.
    Mcc,
    /// The Mobile Network Code: 2 or 3 digits.
    Mnc,
}

impl PlmnPart {
    /// The config key that carries this part.
    pub fn key(self) -> &'static str {
        match self {
            Self::Mcc => "mcc",
            Self::Mnc => "mnc",
        }
    }

    /// The TS 23.003 §2.2 rule, as the error states it.
    fn rule(self) -> &'static str {
        match self {
            Self::Mcc => "an MCC is 3 digits",
            Self::Mnc => "an MNC is 2 or 3 digits",
        }
    }

    /// A well-formed example, for the "quote it" hint.
    fn example(self) -> &'static str {
        match self {
            Self::Mcc => "001",
            Self::Mnc => "01",
        }
    }

    /// Whether `s` is a well-formed value of this part.
    fn accepts(self, s: &str) -> bool {
        let lengths = match self {
            Self::Mcc => 3..=3,
            Self::Mnc => 2..=3,
        };
        lengths.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Check a PLMN digit string. `field` names the value in the error (for
/// example `amf.guami[0].plmn_id.mcc`, or `--serving-plmn`).
pub fn check_digits(field: &str, part: PlmnPart, digits: &str) -> Result<(), String> {
    if part.accepts(digits) {
        Ok(())
    } else {
        Err(format!(
            "{field}={digits:?}: {} (TS 23.003 §2.2)",
            part.rule()
        ))
    }
}

/// The digits of a PLMN part as a config file wrote them: a YAML string of the
/// right length, returned as written. A number, or a string that is not 3 (MCC)
/// or 2-3 (MNC) digits, is refused with an error naming `field`; see the module
/// docs for why a number is never padded.
pub fn config_digits(
    field: &str,
    part: PlmnPart,
    value: &serde_yaml::Value,
) -> Result<String, String> {
    match value {
        serde_yaml::Value::String(s) => {
            check_digits(field, part, s)?;
            Ok(s.clone())
        }
        serde_yaml::Value::Number(n) => Err(format!(
            "{field}={n} reached the configuration as a number, not a string: its \
             leading zeros, if it had any, are already lost, and the NF will not guess \
             them, since MNC 70 and 070 are different PLMNs. Quote it in the config \
             file (for example {key}: \"{example}\") (TS 23.003 §2.2, #2115)",
            key = part.key(),
            example = part.example(),
        )),
        _ => Err(format!(
            "{field} is not a digit string: {} (TS 23.003 §2.2)",
            part.rule()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> serde_yaml::Value {
        serde_yaml::from_str(s).expect("yaml scalar")
    }

    /// Well-formed strings come back exactly as written, leading zeros and all.
    /// serde_yaml 0.9 (YAML 1.2) reads an unquoted `001` as a string, so that
    /// form is accepted too.
    #[test]
    fn a_digit_string_of_the_right_length_is_returned_as_written() {
        for (part, raw, want) in [
            (PlmnPart::Mcc, "\"001\"", "001"),
            (PlmnPart::Mcc, "001", "001"),
            (PlmnPart::Mcc, "\"999\"", "999"),
            (PlmnPart::Mnc, "\"01\"", "01"),
            (PlmnPart::Mnc, "\"070\"", "070"),
            (PlmnPart::Mnc, "070", "070"),
            (PlmnPart::Mnc, "\"70\"", "70"),
        ] {
            assert_eq!(
                config_digits("p", part, &yaml(raw)).as_deref(),
                Ok(want),
                "{part:?} {raw}"
            );
        }
    }

    /// Every number is refused, including one that lost nothing (999, 70), and
    /// the error says to quote the value, as the chart's does.
    #[test]
    fn a_number_is_refused_and_never_padded() {
        for (part, raw) in [
            (PlmnPart::Mcc, "1"),
            (PlmnPart::Mcc, "999"),
            (PlmnPart::Mnc, "1"),
            (PlmnPart::Mnc, "70"),
            (PlmnPart::Mnc, "1.5"),
        ] {
            let err = config_digits("amf.guami[0].plmn_id.x", part, &yaml(raw))
                .expect_err("a number must be refused");
            assert!(
                err.starts_with(&format!(
                    "amf.guami[0].plmn_id.x={raw} reached the configuration as a number"
                )),
                "{err}"
            );
            assert!(
                err.contains(&format!("{}: \"{}\"", part.key(), part.example())),
                "{err}"
            );
        }
    }

    /// A string of the wrong length or with a non-digit is refused with the
    /// TS 23.003 rule; so is a value that is not a scalar at all.
    #[test]
    fn a_malformed_string_or_a_non_scalar_is_refused() {
        for (part, raw, want) in [
            (PlmnPart::Mcc, "\"1\"", "f=\"1\": an MCC is 3 digits"),
            (PlmnPart::Mcc, "\"0011\"", "f=\"0011\": an MCC is 3 digits"),
            (PlmnPart::Mcc, "\"00a\"", "f=\"00a\": an MCC is 3 digits"),
            (PlmnPart::Mnc, "\"7\"", "f=\"7\": an MNC is 2 or 3 digits"),
            (
                PlmnPart::Mnc,
                "\"0700\"",
                "f=\"0700\": an MNC is 2 or 3 digits",
            ),
            (
                PlmnPart::Mnc,
                "\" 70\"",
                "f=\" 70\": an MNC is 2 or 3 digits",
            ),
            (PlmnPart::Mnc, "true", "f is not a digit string: an MNC"),
            (
                PlmnPart::Mcc,
                "[0, 0, 1]",
                "f is not a digit string: an MCC",
            ),
        ] {
            let err = config_digits("f", part, &yaml(raw)).expect_err(raw);
            assert!(err.starts_with(want), "{raw}: {err}");
        }
    }

    #[test]
    fn check_digits_accepts_exactly_the_ts_29_571_patterns() {
        assert_eq!(check_digits("f", PlmnPart::Mcc, "310"), Ok(()));
        assert_eq!(check_digits("f", PlmnPart::Mnc, "26"), Ok(()));
        assert_eq!(check_digits("f", PlmnPart::Mnc, "260"), Ok(()));
        assert!(check_digits("f", PlmnPart::Mcc, "31").is_err());
        assert!(check_digits("f", PlmnPart::Mcc, "").is_err());
        assert!(check_digits("f", PlmnPart::Mnc, "").is_err());
    }
}
