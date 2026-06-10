//! Time abstraction for testable, monotonic TTL evaluation.
//!
//! TTL expiry must be computed against a clock that **never moves backwards**.
//! Wall-clock time ([`std::time::SystemTime`]) can jump (NTP corrections, manual
//! clock changes, DST), which would let a secret's effective lifetime shrink or
//! grow unexpectedly. We therefore base TTL on a monotonic clock.
//!
//! Design rationale: the standard monotonic clock is [`std::time::Instant`], but
//! `Instant` values cannot be constructed at arbitrary points, which makes them
//! awkward to drive from tests. We expose time as [`Monotonic`] — an opaque
//! offset from an unspecified epoch — so production code uses a real monotonic
//! source while tests advance a [`FakeClock`] freely. The unit (`Duration` from
//! an epoch) is an internal detail; only differences between two `Monotonic`
//! values are meaningful.

use std::time::{Duration, Instant};

/// A point on a monotonic timeline.
///
/// Only the *difference* between two `Monotonic` values is meaningful; the
/// absolute value (offset from an unspecified epoch) carries no external
/// meaning. Monotonic time never decreases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Monotonic(Duration);

impl Monotonic {
    /// The zero point of the monotonic timeline.
    ///
    /// Useful as a base for tests and for [`FakeClock`].
    pub const ZERO: Monotonic = Monotonic(Duration::ZERO);

    /// Construct a `Monotonic` from an offset since the epoch.
    pub fn from_offset(offset: Duration) -> Self {
        Monotonic(offset)
    }

    /// The offset of this point since the epoch.
    pub fn offset(self) -> Duration {
        self.0
    }

    /// Saturating duration elapsed from `earlier` to `self`.
    ///
    /// Returns [`Duration::ZERO`] if `earlier` is after `self` (which should not
    /// happen on a monotonic clock, but we saturate rather than panic).
    pub fn saturating_duration_since(self, earlier: Monotonic) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// This point advanced by `delta`.
    pub fn saturating_add(self, delta: Duration) -> Monotonic {
        Monotonic(self.0.saturating_add(delta))
    }
}

/// Source of monotonic time.
///
/// Inject this into TTL-aware types so tests can control the passage of time.
pub trait Clock {
    /// The current monotonic time.
    fn now(&self) -> Monotonic;
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> Monotonic {
        (**self).now()
    }
}

/// Real monotonic clock backed by [`std::time::Instant`].
#[derive(Debug)]
pub struct SystemClock {
    base: Instant,
}

impl SystemClock {
    /// Create a clock whose epoch is the moment of construction.
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Monotonic {
        Monotonic(self.base.elapsed())
    }
}

/// Test clock whose time only changes when explicitly advanced.
#[derive(Debug)]
pub struct FakeClock {
    now: std::cell::Cell<Monotonic>,
}

impl FakeClock {
    /// Create a clock starting at [`Monotonic::ZERO`].
    pub fn new() -> Self {
        Self {
            now: std::cell::Cell::new(Monotonic::ZERO),
        }
    }

    /// Create a clock starting at the given point.
    pub fn starting_at(start: Monotonic) -> Self {
        Self {
            now: std::cell::Cell::new(start),
        }
    }

    /// Advance the clock by `delta`. Monotonic: never moves backwards.
    pub fn advance(&self, delta: Duration) {
        self.now.set(self.now.get().saturating_add(delta));
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Monotonic {
        self.now.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_starts_at_zero() {
        let c = FakeClock::new();
        assert_eq!(c.now(), Monotonic::ZERO);
    }

    #[test]
    fn fake_clock_advances() {
        let c = FakeClock::new();
        c.advance(Duration::from_secs(10));
        assert_eq!(c.now(), Monotonic::from_offset(Duration::from_secs(10)));
        c.advance(Duration::from_secs(5));
        assert_eq!(c.now(), Monotonic::from_offset(Duration::from_secs(15)));
    }

    #[test]
    fn fake_clock_starting_at_offset() {
        let start = Monotonic::from_offset(Duration::from_secs(100));
        let c = FakeClock::starting_at(start);
        assert_eq!(c.now(), start);
        c.advance(Duration::from_secs(1));
        assert_eq!(c.now(), Monotonic::from_offset(Duration::from_secs(101)));
    }

    #[test]
    fn duration_since_is_saturating() {
        let a = Monotonic::from_offset(Duration::from_secs(5));
        let b = Monotonic::from_offset(Duration::from_secs(8));
        assert_eq!(b.saturating_duration_since(a), Duration::from_secs(3));
        // Reversed: saturates to zero rather than underflowing.
        assert_eq!(a.saturating_duration_since(b), Duration::ZERO);
    }

    #[test]
    fn monotonic_ordering() {
        let a = Monotonic::from_offset(Duration::from_secs(1));
        let b = Monotonic::from_offset(Duration::from_secs(2));
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, a);
    }

    #[test]
    fn system_clock_is_monotonic_nondecreasing() {
        let c = SystemClock::new();
        let t1 = c.now();
        let t2 = c.now();
        assert!(t2 >= t1);
    }

    #[test]
    fn clock_works_through_reference() {
        // The blanket impl for &C lets a borrowed clock be used as a Clock.
        let c = FakeClock::new();
        fn read(clock: impl Clock) -> Monotonic {
            clock.now()
        }
        assert_eq!(read(&c), Monotonic::ZERO);
    }
}
