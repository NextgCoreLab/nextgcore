//! The NFStatusNotify sender rule and per-subscription callback tokens (#2172).
//!
//! An Nnrf_NFManagement NFStatusNotify (TS 29.510 §5.2.2.6) tells a subscriber
//! that an NF registered, deregistered or changed. A receiver acts on it: amfd
//! evicts the instance from its discovery cache, nwdafd feeds NF_LOAD. So a
//! forged NF_DEREGISTERED from any peer that can reach the callback could evict
//! a healthy NF. The NRF's notification carries no bearer (TS 33.501 §13.4.1),
//! so a receiver has two proofs, and under the `production` SBI profile needs
//! both:
//!
//! 1. the callback's own **token**: each NFStatusSubscribe names an
//!    unguessable token in its `nfStatusNotificationUri`, and only a held token
//!    is a subscription of this NF ([`TokenBook`], one token per
//!    subscription, #2093); and
//! 2. the **sender**: the verified client certificate is the NRF's, naming NF
//!    type NRF and nothing else (#2153: `[NRF, AMF]` is not the NRF's alone),
//!    or a relay's naming SCP (indirect communication, TS 23.501 §6.3.1.0;
//!    [`crate::owner_binding::is_relay_certificate`]: relay types only, so
//!    `[SCP, AMF]` is an AMF's, #2131). An SCP is admitted because of (1): the
//!    token is per subscription, so a relay that saw one subscription's token
//!    cannot use it for another.
//!
//! [`refuse_notifier`] is the check; every NFStatusNotify route calls it before
//! anything is read or changed. The source guard
//! `tests/nf_status_notify_receivers.rs` lists the receivers. Under `dev`
//! nothing is checked (plaintext lab, nothing to verify).

use crate::message::{SbiRequest, SbiResponse};

/// How long a replaced subscription's token still admits notifications when the
/// NRF gave no validity for it (the NRF may still deliver on the old
/// subscription until it lapses).
pub const RETIRED_TOKEN_GRACE: std::time::Duration = std::time::Duration::from_secs(300);

/// At most this many tokens are held (the current one, ones being subscribed,
/// and retired ones in their grace window); the oldest go first.
const MAX_TOKENS: usize = 4;

/// The callback tokens of one NFStatusSubscribe series, ONE PER SUBSCRIPTION
/// (each subscribe mints its own), not one per process: a token seen by a relay
/// on one subscription's notifications proves nothing about another's, and a
/// replaced subscription's token stops working once its grace window ends
/// (#2093; lifted from nwdafd by #2172).
#[derive(Debug, Default)]
pub struct TokenBook {
    /// The token of the subscription in force, once the NRF accepted it.
    current: Option<String>,
    /// Minted for a subscribe the NRF has not answered yet.
    pending: Vec<String>,
    /// Replaced subscriptions' tokens, with the instant each stops working.
    retired: Vec<(String, std::time::Instant)>,
}

impl TokenBook {
    /// An empty book (usable in a `static`).
    pub const fn new() -> Self {
        Self {
            current: None,
            pending: Vec::new(),
            retired: Vec::new(),
        }
    }

    /// Mint the token for a new NFStatusSubscribe.
    pub fn mint(&mut self) -> String {
        let token = uuid::Uuid::new_v4().simple().to_string();
        self.pending.push(token.clone());
        self.prune(std::time::Instant::now());
        token
    }

    /// The NRF accepted the subscription carrying `token`: it is now the current
    /// one, and the one it replaces keeps working until `retire_at`.
    pub fn activate(&mut self, token: &str, retire_at: std::time::Instant) {
        self.pending.retain(|t| t != token);
        if let Some(previous) = self.current.replace(token.to_string()) {
            if previous != token {
                self.retired.push((previous, retire_at));
            }
        }
        self.prune(std::time::Instant::now());
    }

    /// A subscribe carrying `token` failed, or was never sent: forget it.
    pub fn abandon(&mut self, token: &str) {
        self.pending.retain(|t| t != token);
    }

    /// Whether `token` names a subscription held at `now`: the current one, one
    /// being subscribed, or a replaced one in its grace window.
    pub fn holds(&self, token: &str, now: std::time::Instant) -> bool {
        let eq = |t: &str| crate::callback_auth::token_eq(t, token);
        self.current.as_deref().is_some_and(eq)
            || self.pending.iter().any(|t| eq(t))
            || self.retired.iter().any(|(t, until)| *until > now && eq(t))
    }

    /// The token of the subscription in force, if one was accepted.
    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    /// Whether `token` was minted for a subscribe not yet answered.
    pub fn is_pending(&self, token: &str) -> bool {
        self.pending.iter().any(|t| t == token)
    }

    /// How many subscribes are minted and not yet answered.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The current token, minting one as current when there is none (start-up,
    /// before the first subscribe answers; tests).
    pub fn current_or_mint(&mut self) -> String {
        if let Some(t) = &self.current {
            return t.clone();
        }
        let token = uuid::Uuid::new_v4().simple().to_string();
        self.current = Some(token.clone());
        token
    }

    fn prune(&mut self, now: std::time::Instant) {
        self.retired.retain(|(_, until)| *until > now);
        while self.pending.len() + self.retired.len() + 1 > MAX_TOKENS && !self.retired.is_empty() {
            self.retired.remove(0);
        }
        while self.pending.len() + 1 > MAX_TOKENS {
            self.pending.remove(0);
        }
    }
}

/// Whether `request`'s verified client certificate may deliver an
/// NFStatusNotify: the NRF's (NRF and no other type) or a relay's naming SCP.
pub fn is_nrf_or_relaying_scp(request: &SbiRequest) -> bool {
    let types = &request.peer_cert_nf_types;
    let nrf_only = !types.is_empty() && types.iter().all(|t| t.trim().eq_ignore_ascii_case("NRF"));
    let relay_scp = crate::owner_binding::is_relay_certificate(types)
        && types.iter().any(|t| t.trim().eq_ignore_ascii_case("SCP"));
    nrf_only || relay_scp
}

/// #2172: why an NFStatusNotify may not be acted on, as the 403 to answer, or
/// `None` to go on. Under `production` the callback must carry a token this NF
/// holds (`correlated`) and come from [`is_nrf_or_relaying_scp`]; under `dev`
/// everything is admitted. Call it before the body is read.
pub fn refuse_notifier(
    request: &SbiRequest,
    correlated: bool,
    production: bool,
) -> Option<SbiResponse> {
    if !production {
        return None;
    }
    let refuse = |why: &str| {
        // debug, not warn: a peer can send these at will.
        log::debug!("NFStatusNotify refused: {why}");
        Some(crate::server::send_forbidden(
            &format!("NFStatusNotify: {why}"),
            None,
        ))
    };
    if !correlated {
        return refuse(
            "the notification names no subscription of this NF (the callback carries no \
             correlation token)",
        );
    }
    if is_nrf_or_relaying_scp(request) {
        return None;
    }
    refuse(
        "only the NRF, directly or through an SCP, delivers NF status notifications; the \
         requester's verified certificate names neither",
    )
}

/// [`refuse_notifier`] under the process's SBI profile.
pub fn refuse_notifier_now(request: &SbiRequest, correlated: bool) -> Option<SbiResponse> {
    refuse_notifier(
        request,
        correlated,
        crate::security::SbiProfile::resolve().is_production(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from(types: &[&str]) -> SbiRequest {
        let mut r = SbiRequest::post("/x/nf-status-notify/t");
        r.peer_cert_present = true;
        r.peer_cert_nf_instance_id = Some("dddddddd-2172-4000-8000-00000000000d".into());
        r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        r
    }

    /// The sender rule: the NRF's NRF-only certificate, or a relay-only one
    /// naming SCP. A mixed `[NRF, AMF]` or `[SCP, AMF]`, another NF, a typeless
    /// certificate and an uncorrelated notification are refused under
    /// production; under dev nothing is checked.
    ///
    /// REVERT-VERIFIED: with the NRF arm on "names NRF", `[NRF, AMF]` is
    /// admitted; with the relay arm on "names SCP", `[SCP, AMF]` is.
    #[test]
    fn only_the_nrf_or_a_relaying_scp_may_notify_2172() {
        for ok in [&["NRF"][..], &["nrf"], &["SCP"], &["SCP", "SEPP"]] {
            assert!(refuse_notifier(&from(ok), true, true).is_none(), "{ok:?}");
        }
        for bad in [
            &["NRF", "AMF"][..],
            &["SCP", "AMF"],
            &["AMF"],
            &["SEPP"],
            &[],
        ] {
            let refused = refuse_notifier(&from(bad), true, true).expect("refused");
            assert_eq!(refused.status, 403, "{bad:?}");
        }
        assert_eq!(
            refuse_notifier(&from(&["NRF"]), false, true).map(|r| r.status),
            Some(403),
            "uncorrelated"
        );
        assert!(
            refuse_notifier(&from(&["AMF"]), false, false).is_none(),
            "dev"
        );
    }

    /// Each subscribe gets its own token; a replaced one is held through its
    /// grace window and then lapses (the lapse check itself, not pruning); an
    /// abandoned or never-minted token is never held.
    #[test]
    fn tokens_are_per_subscription_and_lapse_2172() {
        let mut book = TokenBook::new();
        let now = std::time::Instant::now();
        let first = book.mint();
        assert!(book.is_pending(&first) && book.holds(&first, now));
        book.activate(&first, now);
        assert_eq!(book.current(), Some(first.as_str()));
        let second = book.mint();
        assert_ne!(first, second);
        book.activate(&second, now + std::time::Duration::from_secs(60));
        assert!(book.holds(&first, now));
        assert!(!book.holds(&first, now + std::time::Duration::from_secs(61)));
        let failed = book.mint();
        book.abandon(&failed);
        assert!(!book.holds(&failed, now));
        assert_eq!(book.pending_len(), 0);
        assert!(!book.holds("0123456789abcdef0123456789abcdef", now));
    }
}
