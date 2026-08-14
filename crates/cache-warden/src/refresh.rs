//! Per-entry refresh arbitration state: a monotonic version and an optional
//! in-progress claim (DR-0034 §4).
//!
//! # What the core does and does not decide
//!
//! The core **stores** these and carries them across a graceful restart. It
//! does not compare versions, match tokens, or judge whether a claim has
//! lapsed — that is policy, and policy lives in the adapter that owns the
//! protocol (DR-0004), exactly as it does for [`crate::GuardRecord`]: the core
//! keeps the record, the handler evaluates it.
//!
//! Consequently [`RefreshClaim::token`] is an opaque string here. The core
//! neither mints nor interprets it; it only has to survive a restart intact,
//! because a claim that lost its token on restart would be a claim nobody
//! could ever complete or release.

/// An in-progress refresh holding an entry (DR-0034 §4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RefreshClaim {
    /// The opaque capability the holder must present to write or release.
    /// Minted and compared by the adapter; stored verbatim here.
    token: String,
    /// When the claim was taken, in milliseconds since the Unix epoch.
    claimed_at_epoch_ms: u64,
    /// When the claim lapses, in milliseconds since the Unix epoch.
    ///
    /// Wall-clock rather than [`crate::Monotonic`], unlike every TTL in this
    /// crate. A claim outlives the process that took it (that is the point of
    /// persisting it), and a monotonic reading taken by a dead process means
    /// nothing to its successor.
    expires_at_epoch_ms: u64,
}

impl RefreshClaim {
    /// Record a claim.
    pub fn new(
        token: impl Into<String>,
        claimed_at_epoch_ms: u64,
        expires_at_epoch_ms: u64,
    ) -> Self {
        Self {
            token: token.into(),
            claimed_at_epoch_ms,
            expires_at_epoch_ms,
        }
    }

    /// The opaque token, for the adapter to compare against a caller's.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// When the claim was taken (epoch milliseconds).
    pub fn claimed_at_epoch_ms(&self) -> u64 {
        self.claimed_at_epoch_ms
    }

    /// When the claim lapses (epoch milliseconds).
    pub fn expires_at_epoch_ms(&self) -> u64 {
        self.expires_at_epoch_ms
    }

    /// Whether the claim still holds at `now_epoch_ms`.
    ///
    /// Exclusive at the boundary: a claim whose expiry is exactly now has
    /// lapsed. Provided here rather than left to each caller so "expired" does
    /// not come to mean two different things in two places.
    pub fn is_active_at(&self, now_epoch_ms: u64) -> bool {
        now_epoch_ms < self.expires_at_epoch_ms
    }

    /// Milliseconds until the claim lapses, saturating at zero.
    pub fn remaining_ms(&self, now_epoch_ms: u64) -> u64 {
        self.expires_at_epoch_ms.saturating_sub(now_epoch_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> RefreshClaim {
        RefreshClaim::new("tok", 1_000, 2_000)
    }

    #[test]
    fn a_claim_is_active_strictly_before_its_expiry() {
        let c = claim();
        assert!(c.is_active_at(1_000));
        assert!(c.is_active_at(1_999));
        assert!(!c.is_active_at(2_000), "exactly at expiry: lapsed");
        assert!(!c.is_active_at(2_001));
    }

    #[test]
    fn remaining_saturates_at_zero() {
        let c = claim();
        assert_eq!(c.remaining_ms(1_000), 1_000);
        assert_eq!(c.remaining_ms(2_000), 0);
        assert_eq!(c.remaining_ms(9_999), 0, "never wraps");
    }

    #[test]
    fn accessors_report_what_was_recorded() {
        let c = claim();
        assert_eq!(c.token(), "tok");
        assert_eq!(c.claimed_at_epoch_ms(), 1_000);
        assert_eq!(c.expires_at_epoch_ms(), 2_000);
    }

    /// A zero-length claim is born lapsed. The adapter's tests use this to
    /// reach the lapsed path without waiting for wall-clock time.
    #[test]
    fn a_zero_length_claim_is_born_lapsed() {
        assert!(!RefreshClaim::new("t", 5_000, 5_000).is_active_at(5_000));
    }
}
