//! Filter rule definitions and parsing.
//!
//! Ported from authsock-warden `src/filter/rule.rs`. A [`FilterRule`] is one
//! `[not-]<form>=<pattern>` token (e.g. `comment=github*`, `not-type=dsa`);
//! [`Filter`] is the underlying matcher it wraps.
//!
//! All upstream forms are ported: the locally-evaluable `comment` / `type` /
//! `fingerprint` / `pubkey` / `keyfile`, plus `github=<user>`, which admits keys
//! published at `github.com/<user>.keys`. The github form needs a network fetch,
//! so its blob set is refreshed asynchronously while matching stays synchronous
//! (see [`GithubMatcher`]).

use crate::error::{Error, Result};
use crate::filter::{
    CommentMatcher, FingerprintMatcher, GithubMatcher, KeyTypeMatcher, KeyfileMatcher,
    PubkeyMatcher,
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
    /// `github=<user>`: keys published at `github.com/<user>.keys`.
    Github(GithubMatcher),
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
            Filter::Github(m) => m.matches(identity),
        }
    }

    /// Whether evaluating this filter requires the key's *comment*.
    ///
    /// Only [`Filter::Comment`] reads the comment; every other form is derived
    /// from the key blob alone (fingerprint / public key / type / authorized
    /// file membership / github published-blob set). This drives the "can we
    /// judge this filter from a blob with no comment?" decision on the upstream
    /// sign path (see
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
            Filter::Github(m) => format!("github={}", m.user()),
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
        if let Some(rest) = s.strip_prefix("github=") {
            validate_github_user(rest)?;
            return Ok(Filter::Github(GithubMatcher::new(rest)));
        }

        Err(Error::Filter(format!("unknown filter format: {s}")))
    }

    /// Detect a bare fingerprint / public-key token without an explicit `form=`.
    ///
    /// `github=` is **not** auto-detected — only the explicit `github=<user>`
    /// form is accepted (a bare username is indistinguishable from a comment).
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

/// Validate a `github=<user>` username before it is interpolated into the
/// `https://github.com/<user>.keys` URL.
///
/// Restricts to GitHub's username alphabet (ASCII alphanumeric and `-`, neither
/// leading nor trailing `-`, no consecutive `--`, 1..=39 chars). Beyond matching
/// GitHub's own rules this is a hard injection guard: a username can never carry
/// a `/`, `.`, `:`, whitespace, or a `-`-prefixed token that would add a URL
/// segment or a curl flag.
fn validate_github_user(user: &str) -> Result<()> {
    let ok = !user.is_empty()
        && user.len() <= 39
        && !user.starts_with('-')
        && !user.ends_with('-')
        && !user.contains("--")
        && user.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(Error::Filter(format!("invalid github username: {user:?}")))
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
        assert!(FilterRule::parse("bogus=x").is_err());
    }

    #[test]
    fn test_parse_github() {
        let rule = FilterRule::parse("github=kawaz").unwrap();
        assert!(!rule.negated);
        assert!(matches!(rule.filter, Filter::Github(_)));
        assert_eq!(rule.description(), "github=kawaz");
    }

    #[test]
    fn test_parse_github_negated() {
        let rule = FilterRule::parse("not-github=kawaz123").unwrap();
        assert!(rule.negated);
        assert!(matches!(rule.filter, Filter::Github(_)));
    }

    #[test]
    fn test_parse_github_with_hyphen() {
        // Hyphens are allowed inside a username (GitHub's own rule).
        assert!(FilterRule::parse("github=octo-cat").is_ok());
    }

    #[test]
    fn test_parse_github_rejects_invalid_usernames() {
        // Empty, injection-y, or out-of-alphabet usernames are rejected.
        assert!(FilterRule::parse("github=").is_err());
        assert!(FilterRule::parse("github=-bad").is_err());
        assert!(FilterRule::parse("github=bad-").is_err());
        assert!(FilterRule::parse("github=a--b").is_err());
        assert!(FilterRule::parse("github=a/b").is_err());
        assert!(FilterRule::parse("github=a.b").is_err());
        assert!(FilterRule::parse("github=a b").is_err());
        assert!(FilterRule::parse("github=foo;rm").is_err());
    }

    #[test]
    fn test_github_is_blob_only_not_comment_dependent() {
        // The github form judges by blob set membership, never by comment, so it
        // must not taint a socket's blob-only verdict.
        let rule = FilterRule::parse("github=kawaz").unwrap();
        assert!(!rule.filter.needs_comment());
    }
}
