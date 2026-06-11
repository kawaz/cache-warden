//! The TTL two-stage lifecycle of a single cache entry.
//!
//! A [`CacheEntry`] holds one named secret and drives the two-stage TTL state
//! machine described in `docs/DESIGN-ja.md`:
//!
//! ```text
//!          extend (idle refresh)
//!          ┌──────────────────┐
//!          ▼                  │
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
//!
//! # Two timing bases (soft vs hard)
//!
//! The soft and hard stages are measured from **independent** instants so that
//! "use it to keep it alive" never extends the value's absolute lifetime
//! (DR-0011):
//!
//! - **`loaded_at`** is fixed at `set` / `regenerate` time and is the basis for
//!   the **hard** TTL. It is the value's absolute clock: an extend never moves
//!   it, so a value cannot outlive its hard window by being used repeatedly.
//! - **`extended_at`** is the basis for the **soft** TTL. It starts equal to
//!   `loaded_at` and is pushed forward to `now` on every [`CacheEntry::extend`]
//!   (idle refresh): a frequently-used entry keeps refreshing its soft window
//!   while still hard-expiring on schedule.
//!
//! Only an explicit [`CacheEntry::pin_until`] can hold a value past its hard
//! deadline (a manual, re-auth-gated reprieve; see DR-0011 and the [`Store`]
//! layer's `pin_authenticated`).
//!
//! [`Store`]: crate::Store

use std::time::Duration;

use crate::clock::{Clock, Monotonic};
use crate::secret::SecretBytes;
use crate::source::ValueSource;

/// TTL configuration for an entry.
///
/// `soft` is the duration after which the value becomes [`EntryState::SoftExpired`]
/// (stale, needs re-auth); `hard` is the duration after which it becomes
/// [`EntryState::HardExpired`] (zeroized and destroyed). The two durations are
/// measured from **different** instants (DR-0011): the soft window from the last
/// extend (`extended_at`), the hard window from when the value was loaded
/// (`loaded_at`). See the module-level "Two timing bases" note.
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
/// time by [`Ttl::new`]. The check stays meaningful under the two-basis model:
/// at load time `extended_at == loaded_at`, so `soft <= hard` is exactly the
/// guarantee that a freshly loaded value reaches SoftExpired no later than
/// HardExpired (soft comes first). Once an extend moves `extended_at` forward,
/// the soft window simply restarts from there while the hard deadline stays put.
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
    /// The instant the value was loaded (`set` / `regenerate`). Basis for the
    /// **hard** TTL; an extend never moves it, so the value's absolute lifetime
    /// is fixed at load time (DR-0011).
    loaded_at: Monotonic,
    /// The instant the soft window last restarted (`set` / `regenerate` /
    /// `extend`). Basis for the **soft** TTL; pushed to `now` on every extend so
    /// that using the value keeps it fresh without touching `loaded_at`.
    extended_at: Monotonic,
    /// While `Some(deadline)`, expiry evaluation is suppressed until `deadline`
    /// (a manual reprieve set by [`CacheEntry::pin_until`], DR-0011). The value
    /// is treated as Active even past its soft/hard windows until the pin lapses.
    pin_deadline: Option<Monotonic>,
    /// Latched once the entry transitions to HardExpired, so the destroyed state
    /// is sticky even if `extend` resets timers afterwards on a command source.
    hard_expired: bool,
}

impl CacheEntry {
    /// Create a new Active entry holding `value`, loaded at `clock.now()`.
    pub fn new(source: ValueSource, value: SecretBytes, ttl: Ttl, clock: &impl Clock) -> Self {
        let now = clock.now();
        Self {
            source,
            ttl,
            value: Some(value),
            loaded_at: now,
            extended_at: now,
            pin_deadline: None,
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
    ///
    /// Evaluation order (DR-0011):
    ///
    /// 1. A still-destroyed value is always HardExpired (sticky).
    /// 2. An **active pin** (`now < pin_deadline`) forces Active: while pinned,
    ///    neither soft nor hard expiry fires, holding the value alive until the
    ///    deadline. Once the pin lapses, normal evaluation resumes — so a value
    ///    already past its real hard window goes straight to HardExpired.
    /// 3. The **hard** window is measured from `loaded_at` (absolute lifetime,
    ///    extend never moves it) and takes precedence over soft.
    /// 4. The **soft** window is measured from `extended_at` (restarts on every
    ///    extend).
    pub fn state(&self, clock: &impl Clock) -> EntryState {
        if self.hard_expired || self.value.is_none() {
            return EntryState::HardExpired;
        }
        let now = clock.now();
        // An active pin suppresses all expiry until its deadline.
        if let Some(deadline) = self.pin_deadline
            && now < deadline
        {
            return EntryState::Active;
        }
        if let Some(hard) = self.ttl.hard
            && now.saturating_duration_since(self.loaded_at) >= hard
        {
            return EntryState::HardExpired;
        }
        if let Some(soft) = self.ttl.soft
            && now.saturating_duration_since(self.extended_at) >= soft
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

    /// Re-authenticate and refresh the entry's **soft** window back to Active.
    ///
    /// Valid from Active (a no-op idle refresh) and SoftExpired (the intended
    /// re-auth-extends path). Moves only `extended_at` to `clock.now()`, so the
    /// soft window restarts while the **hard** deadline (`loaded_at`) is left
    /// untouched: using a value keeps it fresh but never lets it outlive its
    /// absolute lifetime (DR-0011). Pushing the hard deadline forward is a
    /// separate, explicit operation ([`CacheEntry::pin_until`]).
    ///
    /// Fails once the entry is HardExpired: the value is already destroyed and
    /// `extend` cannot resurrect it (regeneration of a command source is a
    /// separate operation handled by the store).
    pub fn extend(&mut self, clock: &impl Clock) -> Result<(), ExtendError> {
        match self.evaluate(clock) {
            EntryState::Active | EntryState::SoftExpired => {
                self.extended_at = clock.now();
                Ok(())
            }
            EntryState::HardExpired => Err(ExtendError::HardExpired),
        }
    }

    /// Pin the entry Active until `deadline`, suppressing soft/hard expiry.
    ///
    /// This is the manual reprieve of DR-0011: while `now < deadline`, the entry
    /// evaluates as Active regardless of its soft or hard windows, so a value
    /// whose hard deadline would otherwise fall (e.g. overnight) stays usable
    /// until `deadline`. When the pin lapses, normal evaluation resumes and a
    /// value already past its real hard window hard-expires immediately (and is
    /// zeroized on the next `evaluate`/`get`).
    ///
    /// Re-pinning (calling again with a new `deadline`) simply overwrites the
    /// pin; see [`CacheEntry::unpin`] to drop it early.
    ///
    /// Fails with [`PinError::HardExpired`] if the value is already destroyed:
    /// a pin holds a live value past expiry, it cannot resurrect a zeroized one.
    pub fn pin_until(&mut self, deadline: Monotonic, clock: &impl Clock) -> Result<(), PinError> {
        if self.evaluate(clock) == EntryState::HardExpired {
            return Err(PinError::HardExpired);
        }
        self.pin_deadline = Some(deadline);
        Ok(())
    }

    /// Drop any active pin, returning the entry to normal TTL evaluation.
    ///
    /// Safe to call when no pin is set (a no-op). Unlike [`CacheEntry::pin_until`]
    /// this never fails: removing a reprieve only moves toward expiry, so there
    /// is nothing to gate.
    pub fn unpin(&mut self) {
        self.pin_deadline = None;
    }

    /// The active pin deadline, if the entry is currently pinned.
    ///
    /// Value-free metadata for `status` / `list` reporting: it exposes *when*
    /// the reprieve lapses, never the secret. Note this returns the stored
    /// deadline even if it has already passed; the caller compares against the
    /// clock to compute remaining time (a lapsed pin reports a non-positive
    /// remainder).
    pub fn pin_deadline(&self) -> Option<Monotonic> {
        self.pin_deadline
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

/// Error returned by [`CacheEntry::pin_until`].
#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    /// The entry has already hard-expired; its value is destroyed and cannot be
    /// pinned. A pin holds a *live* value past expiry, not resurrect a dead one.
    HardExpired,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::HardExpired => {
                write!(f, "cannot pin a hard-expired entry; the value is destroyed")
            }
        }
    }
}

impl std::error::Error for PinError {}

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
    fn extend_from_active_is_ok_and_resets_soft_window() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(Duration::from_secs(5));
        e.extend(&clock).unwrap();
        // Soft window reset: 9s more from now is still active (would have been 14s
        // of soft elapsed total). The hard window is unaffected.
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

    // ---- two timing bases: extend refreshes soft only, hard is fixed ----

    #[test]
    fn idle_extend_refreshes_soft_but_not_hard() {
        // Repeatedly extending just-before-soft keeps the value Active for the
        // soft window each time, yet the value still hard-expires on its
        // original schedule (loaded_at + HARD), never later (DR-0011).
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        // t=9: still Active, extend -> soft window restarts from t=9.
        clock.advance(Duration::from_secs(9));
        e.extend(&clock).unwrap();
        // t=18: would be SoftExpired if soft were absolute, but the extend reset
        // it; still Active.
        clock.advance(Duration::from_secs(9));
        assert_eq!(e.state(&clock), EntryState::Active);
        e.extend(&clock).unwrap();
        // t=27: still Active (soft restarted at 18), hard window (30) not yet hit.
        clock.advance(Duration::from_secs(9));
        assert_eq!(e.state(&clock), EntryState::Active);
        // t=30: the hard deadline is loaded_at-based and was never moved by the
        // extends, so the value hard-expires exactly on its original schedule.
        clock.advance(Duration::from_secs(3));
        assert_eq!(e.state(&clock), EntryState::HardExpired);
    }

    #[test]
    fn extend_does_not_push_hard_deadline() {
        // Extend while Active right before hard: the hard deadline must not move.
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(Duration::from_secs(29)); // just before hard, soft-expired
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
        e.extend(&clock).unwrap(); // soft refreshed, but hard basis untouched
        assert_eq!(e.state(&clock), EntryState::Active);
        clock.advance(Duration::from_secs(1)); // t=30: original hard deadline
        assert_eq!(
            e.state(&clock),
            EntryState::HardExpired,
            "extend must not delay the hard deadline"
        );
    }

    // ---- pin (manual reprieve) ----

    #[test]
    fn pin_keeps_value_active_past_soft_expiry() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        // Pin to t=100 (well past both soft and hard windows).
        let deadline = Monotonic::from_offset(Duration::from_secs(100));
        e.pin_until(deadline, &clock).unwrap();
        clock.advance(Duration::from_secs(15)); // past soft (10)
        assert_eq!(e.state(&clock), EntryState::Active, "pin suppresses soft");
        clock.advance(Duration::from_secs(20)); // t=35, past hard (30)
        assert_eq!(e.state(&clock), EntryState::Active, "pin suppresses hard");
    }

    #[test]
    fn pin_at_exact_deadline_resumes_normal_evaluation() {
        // At exactly `now == deadline` the pin is no longer active (`now < deadline`
        // is false), so normal evaluation resumes. With the real hard window
        // already passed, the entry is HardExpired at the boundary.
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        let deadline = Monotonic::from_offset(HARD); // == 30
        e.pin_until(deadline, &clock).unwrap();
        clock.advance(Duration::from_secs(29));
        assert_eq!(
            e.state(&clock),
            EntryState::Active,
            "still pinned just before"
        );
        clock.advance(Duration::from_secs(1)); // now == deadline (30)
        assert_eq!(
            e.state(&clock),
            EntryState::HardExpired,
            "pin lapses exactly at its deadline; real hard window already passed"
        );
    }

    #[test]
    fn pin_lapse_into_real_hard_expiry_zeroizes() {
        // After the pin lapses past the real hard deadline, evaluate() must
        // actually destroy the value.
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        let deadline = Monotonic::from_offset(Duration::from_secs(50));
        e.pin_until(deadline, &clock).unwrap();
        clock.advance(Duration::from_secs(60)); // past pin and past hard
        assert_eq!(e.evaluate(&clock), EntryState::HardExpired);
        assert!(
            e.value.is_none(),
            "value zeroized once the pin lapses past hard"
        );
    }

    #[test]
    fn pin_within_hard_window_does_not_extend_hard() {
        // Pinning to a deadline *before* the real hard deadline is fine; once the
        // pin lapses, the value is still bound by its original hard window.
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        // Soft-expire, then pin to t=20 (before hard=30).
        clock.advance(Duration::from_secs(15));
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
        e.pin_until(Monotonic::from_offset(Duration::from_secs(20)), &clock)
            .unwrap();
        assert_eq!(e.state(&clock), EntryState::Active, "pinned -> Active");
        clock.advance(Duration::from_secs(7)); // t=22: pin lapsed, soft-expired again
        assert_eq!(e.state(&clock), EntryState::SoftExpired);
        clock.advance(Duration::from_secs(8)); // t=30: original hard deadline
        assert_eq!(e.state(&clock), EntryState::HardExpired);
    }

    #[test]
    fn re_pin_overwrites_the_deadline() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        e.pin_until(Monotonic::from_offset(Duration::from_secs(20)), &clock)
            .unwrap();
        // Extend the reprieve before it lapses.
        clock.advance(Duration::from_secs(5));
        e.pin_until(Monotonic::from_offset(Duration::from_secs(100)), &clock)
            .unwrap();
        clock.advance(Duration::from_secs(25)); // t=30: original pin would have lapsed
        assert_eq!(e.state(&clock), EntryState::Active, "re-pin keeps it alive");
        assert_eq!(
            e.pin_deadline(),
            Some(Monotonic::from_offset(Duration::from_secs(100)))
        );
    }

    #[test]
    fn unpin_returns_to_normal_evaluation() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        e.pin_until(Monotonic::from_offset(Duration::from_secs(100)), &clock)
            .unwrap();
        clock.advance(Duration::from_secs(15)); // past soft
        assert_eq!(e.state(&clock), EntryState::Active);
        e.unpin();
        assert_eq!(e.pin_deadline(), None);
        assert_eq!(
            e.state(&clock),
            EntryState::SoftExpired,
            "after unpin the soft window applies again"
        );
    }

    #[test]
    fn unpin_without_pin_is_a_noop() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        e.unpin(); // never pinned
        assert_eq!(e.pin_deadline(), None);
        assert_eq!(e.state(&clock), EntryState::Active);
    }

    #[test]
    fn pin_rejected_on_hard_expired_entry() {
        let clock = FakeClock::new();
        let mut e = active_entry(&clock);
        clock.advance(HARD); // hard-expired
        let err = e
            .pin_until(Monotonic::from_offset(Duration::from_secs(100)), &clock)
            .unwrap_err();
        assert_eq!(err, PinError::HardExpired);
        assert_eq!(e.pin_deadline(), None, "rejected pin must not be recorded");
    }

    #[test]
    fn pinned_entry_get_returns_value() {
        let clock = FakeClock::new();
        let mut e = CacheEntry::new(ValueSource::Static, SecretBytes::from("v"), ttl(), &clock);
        e.pin_until(Monotonic::from_offset(Duration::from_secs(100)), &clock)
            .unwrap();
        clock.advance(Duration::from_secs(40)); // past both soft and hard
        assert_eq!(
            e.get(&clock).unwrap().expose_secret(),
            b"v",
            "a pinned value is gettable past its TTL"
        );
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
