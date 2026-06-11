//! Filter rule definitions and parsing.
//!
//! Ported from authsock-warden `src/filter/rule.rs`. A [`FilterRule`] is one
//! `[not-]<form>=<pattern>` token (e.g. `comment=github*`, `not-type=dsa`);
//! [`Filter`] is the underlying matcher it wraps.
//!
//! The upstream `github=<user>` form is **not** ported in this iteration: it
//! fetches `https://github.com/<user>.keys` over the network and would pull in a
//! heavy HTTP-client dependency (`reqwest`). It is recorded as deferred in the
//! authsock port plan (Iteration 3 allows postponing `github`). The
//! locally-evaluable forms — `comment` / `type` / `fingerprint` / `pubkey` /
//! `keyfile` — are all ported.

use crate::error::{Error, Result};
use crate::filter::{
    CommentMatcher, FingerprintMatcher, KeyTypeMatcher, KeyfileMatcher, PubkeyMatcher,
};
use crate::message::Identity;

/// A filter that can match against an SSH key identity.
#[derive(Debug, Clone)]
pub enum Filter {
    /// `fingerprint=SHA256:...` (or a bare `SHA256:` / `MD5:` auto-detected).
    Fingerprint(FingerprintMatcher),
    /// `pubkey=<openssh line>` (or a bare `ssh-...` line auto-detected).
    Pubkey(PubkeyMatcher),
    /// `keyfile=<authorized_keys path>`.
    Keyfile(KeyfileMatcher),
    /// `comment=<exact|glob|~regex>`.
    Comment(CommentMatcher),
    /// `type=<ed25519|rsa|...>`.
    KeyType(KeyTypeMatcher),
}

impl Filter {
    /// Whether `identity` matches this filter (before any negation).
    pub fn matches(&self, identity: &Identity) -> bool {
        match self {
            Filter::Fingerprint(m) => m.matches(identity),
            Filter::Pubkey(m) => m.matches(identity),
            Filter::Keyfile(m) => m.matches(identity),
            Filter::Comment(m) => m.matches(identity),
            Filter::KeyType(m) => m.matches(identity),
        }
    }

    /// Whether evaluating this filter requires the key's *comment*.
    ///
    /// Only [`Filter::Comment`] reads the comment; every other form is derived
    /// from the key blob alone (fingerprint / public key / type / authorized
    /// file membership). This drives the "can we judge this filter from a blob
    /// with no comment?" decision on the upstream sign path (see
    /// `cache-warden-cli`'s `sign_request`): a key forwarded to an upstream
    /// without a prior enumeration carries no comment, so a comment-dependent
    /// filter cannot be evaluated and must fail closed.
    pub fn needs_comment(&self) -> bool {
        matches!(self, Filter::Comment(_))
    }

    /// A short, secret-free description (for diagnostics).
    pub fn description(&self) -> String {
        match self {
            Filter::Fingerprint(m) => format!("fingerprint={}", m.pattern()),
            Filter::Pubkey(_) => "pubkey=<key>".to_string(),
            Filter::Keyfile(m) => format!("keyfile={}", m.path()),
            Filter::Comment(m) => format!("comment={}", m.pattern()),
            Filter::KeyType(m) => format!("type={}", m.key_type()),
        }
    }
}

/// A filter rule with optional negation (`not-` prefix).
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// The underlying matcher.
    pub filter: Filter,
    /// Whether the match result is inverted.
    pub negated: bool,
}

impl FilterRule {
    /// Wrap `filter` with an explicit `negated` flag.
    pub fn new(filter: Filter, negated: bool) -> Self {
        Self { filter, negated }
    }

    /// Whether `identity` passes this rule (matcher result, inverted if negated).
    pub fn matches(&self, identity: &Identity) -> bool {
        let result = self.filter.matches(identity);
        if self.negated { !result } else { result }
    }

    /// Parse a `[not-]<form>` token into a rule.
    pub fn parse(s: &str) -> Result<Self> {
        let (negated, s) = if let Some(rest) = s.strip_prefix("not-") {
            (true, rest)
        } else {
            (false, s)
        };

        let filter = Self::parse_filter(s)?;
        Ok(Self { filter, negated })
    }

    /// Parse the filter body (after any `not-` prefix) into a [`Filter`].
    fn parse_filter(s: &str) -> Result<Filter> {
        if let Some(filter) = Self::try_auto_detect(s) {
            return Ok(filter);
        }

        if let Some(rest) = s.strip_prefix("fingerprint=") {
            return Ok(Filter::Fingerprint(FingerprintMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("pubkey=") {
            return Ok(Filter::Pubkey(PubkeyMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("keyfile=") {
            return Ok(Filter::Keyfile(KeyfileMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("comment=") {
            return Ok(Filter::Comment(CommentMatcher::new(rest)?));
        }
        if let Some(rest) = s.strip_prefix("type=") {
            return Ok(Filter::KeyType(KeyTypeMatcher::new(rest)));
        }

        Err(Error::Filter(format!("unknown filter format: {s}")))
    }

    /// Detect a bare fingerprint / public-key token without an explicit `form=`.
    fn try_auto_detect(s: &str) -> Option<Filter> {
        if s.starts_with("SHA256:") {
            return FingerprintMatcher::new(s).ok().map(Filter::Fingerprint);
        }
        if s.starts_with("MD5:") {
            return FingerprintMatcher::new(s).ok().map(Filter::Fingerprint);
        }
        if s.starts_with("ssh-")
            || s.starts_with("ecdsa-sha2-")
            || s.starts_with("sk-ssh-")
            || s.starts_with("sk-ecdsa-")
        {
            return PubkeyMatcher::new(s).ok().map(Filter::Pubkey);
        }
        None
    }

    /// A short, secret-free description (negation rendered as a leading `-`).
    pub fn description(&self) -> String {
        if self.negated {
            format!("-{}", self.filter.description())
        } else {
            self.filter.description()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fingerprint() {
        let rule = FilterRule::parse("SHA256:abc123").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Fingerprint(_)));
    }

    #[test]
    fn test_parse_explicit_fingerprint() {
        let rule = FilterRule::parse("fingerprint=SHA256:abc123").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Fingerprint(_)));
    }

    #[test]
    fn test_parse_negated() {
        let rule = FilterRule::parse("not-type=dsa").unwrap();
        assert!(rule.negated);
        assert!(matches!(rule.filter, Filter::KeyType(_)));
    }

    #[test]
    fn test_parse_comment() {
        let rule = FilterRule::parse("comment=~@work").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Comment(_)));
    }

    #[test]
    fn test_parse_pubkey_auto() {
        let rule = FilterRule::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test",
        )
        .unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Pubkey(_)));
    }

    #[test]
    fn test_parse_unknown_form_is_error() {
        assert!(FilterRule::parse("github=kawaz").is_err());
        assert!(FilterRule::parse("bogus=x").is_err());
    }
}
