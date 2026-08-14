//! The refresh claim: the mechanism that narrows a credential refresh to one
//! caller (DR-0034 §4).
//!
//! # Why a claim exists at all
//!
//! A compare-and-swap version alone decides who *wins the write*, not who
//! *makes the call*. Two processes that both notice an expiring OAuth token
//! will both hit the identity provider; CAS then rejects the loser's write —
//! after the damage is done, because a provider doing strict refresh-token
//! rotation has already invalidated the family. The claim is taken **before**
//! the provider call so only one is ever made.
//!
//! # Why the claim carries a token
//!
//! A claim expires so a caller that dies does not wedge the entry forever. But
//! expiry alone leaves a hole, and it is the one that matters:
//!
//! 1. A claims the entry and stalls.
//! 2. The claim lapses. B claims it and starts refreshing.
//! 3. A wakes up and writes.
//!
//! At step 3 nothing has written yet, so the version A remembers still
//! matches and its CAS check passes. Both A and B end up talking to the
//! provider and one of their writes lands unnoticed — exactly what the claim
//! was supposed to prevent.
//!
//! [`ClaimToken`] closes it. Taking a claim mints a fresh token, and a write
//! made while a claim is active must present the matching one. At step 3 the
//! active claim is B's, so A's token does not match and A's write is refused.
//!
//! The token is a **capability**, not an identity: it says "the holder took the
//! claim that is currently active", never "the holder is process X". That
//! distinction is what keeps it compatible with DR-0034 §4's reason for
//! choosing CAS in the first place — a pid or connection identity cannot tell
//! apart two threads of one client, and would not have been a usable
//! discriminator.
//!
//! A token is unguessable but not secret. Nothing decrypts with it; leaking one
//! lets the holder steal or release a claim, which is a liveness problem, not a
//! confidentiality one. It is still generated from the CSPRNG and compared in
//! constant time, because the cost of doing so is nil.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::crypto::fill_random;
use crate::error::VaultError;

/// Random bytes behind a claim token. 128 bits: a claim lives for minutes, and
/// guessing one only lets an attacker disrupt a refresh they could disrupt
/// more easily by other means.
const TOKEN_BYTES: usize = 16;

/// Encoded length of [`TOKEN_BYTES`] in unpadded base64url.
const TOKEN_CHARS: usize = 22;

/// An opaque capability proving its holder took the claim that is currently
/// active on an entry (DR-0034 §4).
///
/// Rendered as unpadded base64url so it travels through JSON, a shell argument
/// and an environment variable without escaping.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimToken(String);

impl ClaimToken {
    /// Mint a fresh token from the OS CSPRNG.
    ///
    /// Public because the daemon mints the token when it grants a claim: the
    /// vault is not the only holder of claim state (the in-memory store keeps
    /// one too, DR-0034 §4), and both must mint the same kind of token.
    pub fn generate() -> Self {
        let mut raw = [0u8; TOKEN_BYTES];
        fill_random(&mut raw);
        Self(base64url_encode(&raw))
    }

    /// Parse a token as supplied by a caller.
    ///
    /// Only the shape is checked — whether it is *the* active token is decided
    /// by [`ClaimToken::matches`] against the entry, which is the only place
    /// that can know.
    pub fn parse(s: &str) -> Result<Self, VaultError> {
        if s.len() != TOKEN_CHARS || !s.bytes().all(is_base64url_char) {
            return Err(VaultError::MalformedClaimToken);
        }
        Ok(Self(s.to_string()))
    }

    /// The encoded form, for the wire and for display.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `other` is this token.
    ///
    /// Constant-time in the token bytes. A claim token is not a secret, so a
    /// timing oracle here would only help an attacker forge a claim steal —
    /// but the comparison costs the same either way, and a variable-time
    /// `==` on a credential-adjacent value is the kind of detail that gets
    /// copied into a place where it does matter.
    pub fn matches(&self, other: &ClaimToken) -> bool {
        // Equal lengths by construction (both are TOKEN_CHARS), so the length
        // check leaks nothing a caller could not already see.
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

// Redacted not because the value is confidential (it is not — see the module
// doc) but because a token in a log invites replay from whoever reads the log,
// and the entry it guards is a credential.
impl std::fmt::Debug for ClaimToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimToken([REDACTED])")
    }
}

impl PartialEq for ClaimToken {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for ClaimToken {}

/// An in-progress refresh recorded on an entry.
///
/// Persisted with the entry, which is what makes it survive a daemon restart —
/// a claim that vanished on restart would let a `brew upgrade` mid-refresh
/// produce the double provider call the claim exists to prevent (DR-0034 §4).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Claim {
    /// The capability that must be presented to write while this claim holds.
    pub token: ClaimToken,
    /// When the claim was taken, in milliseconds since the Unix epoch.
    pub claimed_at_epoch_ms: u64,
    /// When the claim lapses, in milliseconds since the Unix epoch.
    ///
    /// Wall-clock rather than monotonic on purpose: the claim outlives the
    /// process that took it, and a monotonic reading means nothing to the next
    /// process to read the file. The cost is that a large clock adjustment can
    /// shorten or lengthen a claim; the expiry is a liveness backstop, not a
    /// safety boundary (the token is the safety boundary), so that is
    /// tolerable.
    pub expires_at_epoch_ms: u64,
}

impl Claim {
    /// Whether the claim still holds at `now_epoch_ms`.
    ///
    /// The boundary is exclusive: a claim whose expiry is exactly now has
    /// lapsed. Which side the boundary falls on does not matter much, but
    /// picking one and testing it keeps "expired" from meaning two things in
    /// two places.
    pub fn is_active_at(&self, now_epoch_ms: u64) -> bool {
        now_epoch_ms < self.expires_at_epoch_ms
    }

    /// Milliseconds until this claim lapses, saturating at zero.
    pub fn remaining_ms(&self, now_epoch_ms: u64) -> u64 {
        self.expires_at_epoch_ms.saturating_sub(now_epoch_ms)
    }
}

/// Unpadded base64url ("URL and filename safe" alphabet, RFC 4648 §5).
fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        // 3 input bytes make 4 output characters; a short final chunk makes
        // one character per 6 bits that carry real input, and no padding.
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn is_base64url_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_token_round_trips_through_parse() {
        let t = ClaimToken::generate();
        let back = ClaimToken::parse(t.as_str()).expect("its own output parses");
        assert!(t.matches(&back));
    }

    #[test]
    fn generated_tokens_are_22_base64url_characters() {
        let t = ClaimToken::generate();
        assert_eq!(t.as_str().len(), TOKEN_CHARS);
        assert!(t.as_str().bytes().all(is_base64url_char));
        // Unpadded: '=' would break the "safe in a URL, arg and env var" claim.
        assert!(!t.as_str().contains('='));
    }

    #[test]
    fn two_generated_tokens_differ() {
        assert_ne!(
            ClaimToken::generate().as_str(),
            ClaimToken::generate().as_str()
        );
    }

    #[test]
    fn parse_rejects_the_wrong_length_or_alphabet() {
        assert!(matches!(
            ClaimToken::parse(&"A".repeat(TOKEN_CHARS - 1)),
            Err(VaultError::MalformedClaimToken)
        ));
        assert!(matches!(
            ClaimToken::parse(&"A".repeat(TOKEN_CHARS + 1)),
            Err(VaultError::MalformedClaimToken)
        ));
        // '+' and '/' are standard base64, not base64url.
        let mut bad = "A".repeat(TOKEN_CHARS);
        bad.replace_range(0..1, "+");
        assert!(matches!(
            ClaimToken::parse(&bad),
            Err(VaultError::MalformedClaimToken)
        ));
        bad.replace_range(0..1, "=");
        assert!(matches!(
            ClaimToken::parse(&bad),
            Err(VaultError::MalformedClaimToken)
        ));
    }

    #[test]
    fn different_tokens_do_not_match() {
        let a = ClaimToken::generate();
        let b = ClaimToken::generate();
        assert!(!a.matches(&b));
        assert!(a.matches(&a.clone()));
    }

    #[test]
    fn debug_redacts_the_token() {
        let t = ClaimToken::generate();
        let shown = format!("{t:?}");
        assert!(shown.contains("REDACTED"));
        assert!(!shown.contains(t.as_str()));
    }

    /// Known-answer vectors from RFC 4648 §10, converted to the base64url
    /// alphabet and stripped of padding. Encoding is part of the persisted
    /// format, so a rewrite that changed it would invalidate live claims.
    #[test]
    fn base64url_encoding_matches_known_vectors() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
        // The two bytes that distinguish base64url from base64.
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
    }

    /// The expiry boundary, pinned with explicit timestamps rather than by
    /// waiting for real time to pass. Both branches of every claim decision
    /// come down to this comparison.
    #[test]
    fn a_claim_is_active_strictly_before_its_expiry() {
        let claim = Claim {
            token: ClaimToken::generate(),
            claimed_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 2_000,
        };
        assert!(claim.is_active_at(1_000), "at the moment it was taken");
        assert!(claim.is_active_at(1_999), "one millisecond before expiry");
        assert!(!claim.is_active_at(2_000), "exactly at expiry: lapsed");
        assert!(!claim.is_active_at(2_001));
    }

    #[test]
    fn remaining_time_saturates_at_zero_once_lapsed() {
        let claim = Claim {
            token: ClaimToken::generate(),
            claimed_at_epoch_ms: 1_000,
            expires_at_epoch_ms: 2_000,
        };
        assert_eq!(claim.remaining_ms(1_000), 1_000);
        assert_eq!(claim.remaining_ms(1_999), 1);
        assert_eq!(claim.remaining_ms(2_000), 0);
        assert_eq!(claim.remaining_ms(9_999), 0, "never wraps around");
    }

    /// A zero-length claim is already lapsed at the instant it is taken. The
    /// vault's tests lean on this to exercise the expired-claim path without
    /// sleeping.
    #[test]
    fn a_zero_length_claim_is_born_lapsed() {
        let claim = Claim {
            token: ClaimToken::generate(),
            claimed_at_epoch_ms: 5_000,
            expires_at_epoch_ms: 5_000,
        };
        assert!(!claim.is_active_at(5_000));
    }
}
