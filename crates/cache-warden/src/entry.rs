//! The TTL two-stage lifecycle of a single cache entry.
//!
//! A [`CacheEntry`] holds one named secret and drives the two-stage TTL state
//! machine described in `docs/DESIGN-ja.md`:
//!
//! ```text
//! set ──> Active ──soft TTL──> SoftExpired ──re-auth(extend)──> Active
//!            │                      │
//!            └──────hard TTL────────┴──> HardExpired (value zeroized)
//! ```
//!
//! - **Active**: the value is fresh and may be returned directly.
//! - **SoftExpired**: the value is still in memory but stale; it must not be
//!   returned until re-authentication ([`CacheEntry::extend`]) refreshes it.
//! - **HardExpired**: the value has been zeroized and destroyed. A
//!   [`ValueSource::Command`] entry can be regenerated upstream; a
//!   [`ValueSource::Static`] entry cannot.

use std::time::Duration;

use crate::clock::{Clock, Monotonic};
use crate::secret::SecretBytes;
use crate::source::ValueSource;

/// TTL configuration for an entry.
///
/// `soft` is the duration after which the value becomes [`EntryState::SoftExpired`]
/// (stale, needs re-auth); `hard` is the duration after which it becomes
/// [`EntryState::HardExpired`] (zeroized and destroyed). Both are measured from
/// the moment the value last became [`EntryState::Active`].
///
/// # Unspecified TTLs
///
/// - `soft = None`: the entry never soft-expires. It stays Active until the hard
///   TTL (if any) hits. Use this for "cache as long as the value is allowed to
///   live, no periodic re-auth".
/// - `hard = None`: the entry never hard-expires; the value lives in memory
///   until explicitly deleted. A soft TTL (if set) still makes it require
///   re-auth periodically, but the value is never zeroized by time alone.
/// - both `None`: the entry is permanently Active.
///
/// # Invariant
///
/// When both are set, `soft <= hard` must hold. This is enforced at construction
/// time by [`Ttl::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl {
    soft: Option<Duration>,
    hard: Option<Duration>,
}

/// Error constructing a [`Ttl`] with a violated invariant.
#[derive(Debug, PartialEq, Eq)]
pub enum TtlError {
    /// `soft_ttl` was greater than `hard_ttl`.
    SoftExceedsHard {
        /// The offending soft TTL.
        soft: Duration,
        /// The hard TTL it exceeded.
        hard: Duration,
    },
}

impl std::fmt::Display for TtlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TtlError::SoftExceedsHard { soft, hard } => {
                write!(f, "soft_ttl ({soft:?}) must not exceed hard_ttl ({hard:?})")
            }
        }
    }
}

impl std::error::Error for TtlError {}

impl Ttl {
    /// Construct a TTL, enforcing `soft <= hard` when both are present.
    pub fn new(soft: Option<Duration>, hard: Option<Duration>) -> Result<Self, TtlError> {
        if let (Some(s), Some(h)) = (soft, hard)
            && s > h
        {
            return Err(TtlError::SoftExceedsHard { soft: s, hard: h });
        }
        Ok(Self { soft, hard })
    }

    /// A TTL that never expires (both stages unspecified).
    pub fn never() -> Self {
        Self {
            soft: None,
            hard: None,
        }
    }

    /// The soft TTL, if any.
    pub fn soft(&self) -> Option<Duration> {
        self.soft
    }

    /// The hard TTL, if any.
    pub fn hard(&self) -> Option<Duration> {
        self.hard
    }
}

/// The logical lifecycle state of a [`CacheEntry`] at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Fresh: the value may be returned directly.
    Active,
    /// Stale: the value is still in memory but requires re-authentication
    /// ([`CacheEntry::extend`]) before it may be returned again.
    SoftExpired,
    /// Destroyed: the value has been zeroized. Regenerable only for command sources.
    HardExpired,
}

/// A single named secret with its source, TTL, and lifecycle bookkeeping.
#[derive(Debug)]
pub struct CacheEntry {
    source: ValueSource,
    ttl: Ttl,
    /// Present while the value is alive (Active or SoftExpired); `None` once
    /// hard-expired and zeroized.
    value: Option<SecretBytes>,
    /// The monotonic instant the value last became Active.
    activated_at: Monotonic,
    /// Latched once the entry transitions to HardExpired, so the destroyed state
    /// is sticky even if `extend` resets timers afterwards on a command source.
    hard_expired: bool,
}

impl CacheEntry {
    /// Create a new Active entry holding `value`, activated at `clock.now()`.
    pub fn new(source: ValueSource, value: SecretBytes, ttl: Ttl, clock: &impl Clock) -> Self {
        Self {
            source,
            ttl,
            value: Some(value),
            activated_at: clock.now(),
            hard_expired: false,
        }
    }

    /// The value source for this entry.
    pub fn source(&self) -> &ValueSource {
        &self.source
    }

    /// The TTL configuration for this entry.
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Evaluate the current lifecycle state against `clock`.
    ///
    /// This is a pure read: it does **not** mutate the entry or zeroize the
    /// value. Use [`CacheEntry::evaluate`] when the hard-expiry side effect
    /// (zeroize) should actually happen.
    pub fn state(&self, clock: &impl Clock) -> EntryState {
        if self.hard_expired || self.value.is_none() {
            return EntryState::HardExpired;
        }
        let elapsed = clock.now().saturating_duration_since(self.activated_at);
        if let Some(hard) = self.ttl.hard
            && elapsed >= hard
        {
            return EntryState::HardExpired;
        }
        if let Some(soft) = self.ttl.soft
            && elapsed >= soft
        {
            return EntryState::SoftExpired;
        }
        EntryState::Active
    }

    /// Evaluate the state and apply the hard-expiry side effect.
    ///
    /// If the entry has reached its hard TTL, its value is zeroized and dropped
    /// here. Returns the (possibly newly transitioned) state.
    pub fn evaluate(&mut self, clock: &impl Clock) -> EntryState {
        let state = self.state(clock);
        if state == EntryState::HardExpired {
            self.zeroize_value();
        }
        state
    }

    /// Borrow the live secret if and only if the entry is currently Active.
    ///
    /// Returns `None` when the entry is SoftExpired (needs re-auth) or
    /// HardExpired (destroyed). Applies the hard-expiry zeroize side effect.
    pub fn get(&mut self, clock: &impl Clock) -> Option<&SecretBytes> {
        match self.evaluate(clock) {
            EntryState::Active => self.value.as_ref(),
            EntryState::SoftExpired | EntryState::HardExpired => None,
        }
    }

    /// Re-authenticate and refresh the entry back to Active.
    ///
    /// Valid from Active (a no-op refresh) and SoftExpired (the intended
    /// re-auth-extends path). Resets the activation instant to `clock.now()` so
    /// the TTL windows start over. Fails once the entry is HardExpired: the
    /// value is already destroyed and `extend` cannot resurrect it (regeneration
    /// of a command source is a separate operation handled by the store).
    pub fn extend(&mut self, clock: &impl Clock) -> Result<(), ExtendError> {
        match self.evaluate(clock) {
            EntryState::Active | EntryState::SoftExpired => {
                self.activated_at = clock.now();
                Ok(())
            }
            EntryState::HardExpired => Err(ExtendError::HardExpired),
        }
    }

    /// Whether this entry's source can regenerate the value after hard expiry.
    pub fn is_regenerable(&self) -> bool {
        self.source.is_regenerable()
    }

    /// Force the entry into the HardExpired state, zeroizing the value now.
    pub fn force_hard_expire(&mut self) {
        self.zeroize_value();
    }

    fn zeroize_value(&mut self) {
        if let Some(mut v) = self.value.take() {
            v.purge();
            // `v` is dropped here, which also zeroizes (defense in depth).
        }
        self.hard_expired = true;
    }
}

/// Error returned by [`CacheEntry::extend`].
#[derive(Debug, PartialEq, Eq)]
pub enum ExtendError {
    /// The entry has already hard-expired; its value is destroyed and cannot be
    /// extended. (A command source can be regenerated, but that is a separate
    /// operation, not an extension of the existing value.)
    HardExpired,
}

impl std::fmt::Display for ExtendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendError::HardExpired => {
                write!(
                    f,
                    "cannot extend a hard-expired entry; the value is destroyed"
                )
            }
        }
    }
}

impl std::error::Error for ExtendError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    const SOFT: Duration = Duration::from_secs(10);
    const HARD: Duration = Duration::from_secs(30);

    fn ttl() -> Ttl {
        Ttl::new(Some(SOFT), Some(HARD)).unwrap()
    }

    fn active_entry(clock: &FakeClock) -> CacheEntry {
        CacheEntry::new(ValueSource::Static, SecretBytes::from("v"), ttl(), clock)
    }

    // ---- Ttl invariant ----

    #[test]
    fn ttl_rejects_soft_greater_than_hard() {
        let err = Ttl::new(Some(Duration::from_secs(31)), Some(HARD)).unwrap_err();
        assert!(matches!(err, TtlError::SoftExceedsHard { .. }));
    }

    #[test]
    fn ttl_allows_soft_equal_hard() {
        let t = Ttl::new(Some(HARD), Some(HARD)).unwrap();
        assert_eq!(t.soft(), Some(HARD));
        assert_eq!(t.hard(), Some(HARD));
    }

    #[test]
    fn ttl_allows_partial_specs() {
        assert!(Ttl::new(Some(SOFT), None).is_ok());
        assert!(Ttl::new(None, Some(HARD)).is_ok());
        assert!(Ttl::new(None, None).is_ok());
    }

    // ---- state transitions over time ----

    #[test]
    fn fresh_entry_is_active() {
        let clock = FakeClock::new();
        let e = active_entry(&clock);
        assert_eq!(e.state(&clock), EntryState::Active);
    }

    #[test]
    fn stays_active_before_soft() {
        let clock = FakeClock::new();
        let e = active_entry(&clock);
        clock.advance(Duration::from_secs(9));
        assert_eq!(e.state(&clock), EntryState::Active);
    }

    #[test]
    fn soft_expires_at_exact_soft_boundary() {
        let clock = FakeClock::new();
        let e = active_entry(&clock);
        clock.advance(SOFT); // exactly at soft TTL -> SoftExpired
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
    }

    #[test]
    fn soft_expired_between_soft_and_hard() {
        let clock = FakeClock::new();
        let e = active_entry(&clock);
        clock.advance(Duration::from_secs(20));
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
    }

    #[test]
    fn hard_expires_at_exact_hard_boundary() {
        let clock = FakeClock::new();
        let e = active_entry(&clock);
        clock.advance(HARD); // exactly at hard TTL -> HardExpired
        assert_eq!(e.state(&clock), EntryState::HardExpired);
    }

    #[test]
    fn hard_takes_precedence_when_soft_equals_hard() {
        // Boundary: soft == hard. At the boundary, HardExpired wins.
        let clock = FakeClock::new();
        let t = Ttl::new(Some(HARD), Some(HARD)).unwrap();
        let e = CacheEntry::new(ValueSource::Static, SecretBytes::from("v"), t, &clock);
        clock.advance(HARD);
        assert_eq!(e.state(&clock), EntryState::HardExpired);
    }

    // ---- unspecified TTLs ----

    #[test]
    fn no_soft_ttl_never_soft_expires() {
        let clock = FakeClock::new();
        let t = Ttl::new(None, Some(HARD)).unwrap();
        let e = CacheEntry::new(ValueSource::Static, SecretBytes::from("v"), t, &clock);
        clock.advance(Duration::from_secs(29));
        assert_eq!(e.state(&clock), EntryState::Active);
        clock.advance(Duration::from_secs(1)); // hits hard
        assert_eq!(e.state(&clock), EntryState::HardExpired);
    }

    #[test]
    fn no_hard_ttl_never_hard_expires() {
        let clock = FakeClock::new();
        let t = Ttl::new(Some(SOFT), None).unwrap();
        let e = CacheEntry::new(ValueSource::Static, SecretBytes::from("v"), t, &clock);
        clock.advance(Duration::from_secs(10_000));
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
    }

    #[test]
    fn never_ttl_stays_active_forever() {
        let clock = FakeClock::new();
        let e = CacheEntry::new(
            ValueSource::Static,
            SecretBytes::from("v"),
            Ttl::never(),
            &clock,
        );
        clock.advance(Duration::from_secs(1_000_000));
        assert_eq!(e.state(&clock), EntryState::Active);
    }

    // ---- extend (re-auth) ----

    #[test]
    fn extend_from_soft_returns_to_active() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(Duration::from_secs(15)); // SoftExpired
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
        e.extend(&clock).unwrap();
        assert_eq!(e.state(&clock), EntryState::Active);
        // The window restarts: still active just before the next soft boundary.
        clock.advance(Duration::from_secs(9));
        assert_eq!(e.state(&clock), EntryState::Active);
    }

    #[test]
    fn extend_from_active_is_ok_and_resets_window() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(Duration::from_secs(5));
        e.extend(&clock).unwrap();
        // Window reset: 9s more from now is still active (would have been 14s total).
        clock.advance(Duration::from_secs(9));
        assert_eq!(e.state(&clock), EntryState::Active);
    }

    #[test]
    fn extend_fails_after_hard_expiry() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(HARD);
        let err = e.extend(&clock).unwrap_err();
        assert_eq!(err, ExtendError::HardExpired);
    }

    // ---- get gating ----

    #[test]
    fn get_returns_value_only_when_active() {
        let clock = FakeClock::new();
        let mut e = CacheEntry::new(
            ValueSource::Static,
            SecretBytes::from("secret"),
            ttl(),
            &clock,
        );
        assert_eq!(e.get(&clock).unwrap().expose_secret(), b"secret");
        clock.advance(SOFT);
        assert!(e.get(&clock).is_none()); // soft-expired: gated
    }

    // ---- zeroize side effect on hard expiry ----

    #[test]
    fn evaluate_zeroizes_on_hard_expiry() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        assert!(e.value.is_some());
        clock.advance(HARD);
        assert_eq!(e.evaluate(&clock), EntryState::HardExpired);
        assert!(
            e.value.is_none(),
            "value must be zeroized & dropped on hard expiry"
        );
    }

    #[test]
    fn force_hard_expire_destroys_value() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        e.force_hard_expire();
        assert_eq!(e.state(&clock), EntryState::HardExpired);
        assert!(e.value.is_none());
    }

    #[test]
    fn hard_expiry_is_sticky() {
        // Once hard-expired, advancing time / re-reading must not resurrect it.
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(HARD);
        e.evaluate(&clock);
        assert_eq!(e.state(&clock), EntryState::HardExpired);
    }

    // ---- regenerability propagation ----

    #[test]
    fn static_entry_is_not_regenerable() {
        let clock = FakeClock::new();
        let e = active_entry(&clock);
        assert!(!e.is_regenerable());
    }

    #[test]
    fn command_entry_is_regenerable() {
        let clock = FakeClock::new();
        let e = CacheEntry::new(
            ValueSource::command(["op".into(), "read".into()]),
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        assert!(e.is_regenerable());
    }
}
