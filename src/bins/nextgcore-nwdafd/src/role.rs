//! Which NWDAF logical functions this instance contains (nextgsim#468).
//!
//! TS 23.288 §6.2A.0: an NWDAF may contain an MTLF (it trains models and
//! provisions them over `Nnwdaf_MLModelProvision`), an AnLF (it infers and
//! serves analytics), or both. `nwdaf.role` selects:
//!
//! - `both` (the default): today's NWDAF, unchanged;
//! - `mtlf`: the same as `both` for this build, named for deployments;
//! - `anlf`: no MTLF. `nnwdaf-mlmodelprovision` is neither advertised nor
//!   routed, so the NRF hands no consumer an NWDAF that does not train models
//!   (the issue #109 honesty rule). With the `d441e-model-retrain` demo on, an
//!   AnLF also subscribes to an MTLF for its model.
//!
//! A deployment setting, not a demo mode: an unknown value fails start-up.

use std::sync::OnceLock;

/// The `nwdaf.role` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    #[default]
    Both,
    Mtlf,
    Anlf,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Both => "both",
            Role::Mtlf => "mtlf",
            Role::Anlf => "anlf",
        }
    }

    /// Whether this instance contains an MTLF and so serves
    /// `Nnwdaf_MLModelProvision`.
    pub fn serves_mtlf(self) -> bool {
        !matches!(self, Role::Anlf)
    }
}

/// `nwdaf.role` from the config root: absent means [`Role::Both`]; anything
/// but `mtlf`, `anlf` or `both` is an error.
pub fn from_root(root: &serde_yaml::Value) -> Result<Role, String> {
    let Some(v) = root.get("nwdaf").and_then(|n| n.get("role")) else {
        return Ok(Role::Both);
    };
    match v.as_str() {
        Some("both") => Ok(Role::Both),
        Some("mtlf") => Ok(Role::Mtlf),
        Some("anlf") => Ok(Role::Anlf),
        _ => Err(format!(
            "nwdaf.role must be one of mtlf, anlf, both; got {v:?}"
        )),
    }
}

static ROLE: OnceLock<Role> = OnceLock::new();

/// Fix the role for the process (start-up, once). A second call is ignored.
pub fn install(role: Role) {
    let _ = ROLE.set(role);
}

/// The process's role; [`Role::Both`] until [`install`].
pub fn current() -> Role {
    ROLE.get().copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn roles_parse_and_default_to_both() {
        assert_eq!(from_root(&serde_yaml::Value::Null), Ok(Role::Both));
        assert_eq!(from_root(&root("nwdaf: {}")), Ok(Role::Both));
        for (s, r) in [
            ("mtlf", Role::Mtlf),
            ("anlf", Role::Anlf),
            ("both", Role::Both),
        ] {
            assert_eq!(from_root(&root(&format!("nwdaf:\n  role: {s}\n"))), Ok(r));
            assert_eq!(r.as_str(), s);
        }
        assert!(!Role::Anlf.serves_mtlf());
        assert!(Role::Mtlf.serves_mtlf() && Role::Both.serves_mtlf());
    }

    #[test]
    fn an_unknown_role_is_an_error() {
        for bad in ["role: bogus", "role: ANLF", "role: 1", "role: [anlf]"] {
            let err = from_root(&root(&format!("nwdaf:\n  {bad}\n"))).unwrap_err();
            assert!(err.contains("nwdaf.role"), "{err}");
        }
    }
}
