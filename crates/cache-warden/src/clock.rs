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

    /// This point moved backward by `delta`, saturating at [`Monotonic::ZERO`]
    /// rather than underflowing.
    ///
    /// Crate-internal: used by [`epoch_ms_to_monotonic`] (DR-0029 snapshot
    /// import) to reconstruct a point that lies *before* the importing
    /// process's current reading. See that function's doc for the headroom
    /// caveat this saturation implies.
    pub(crate) fn saturating_sub(self, delta: Duration) -> Monotonic {
        Monotonic(self.0.saturating_sub(delta))
    }
}

// ---- DR-0029 snapshot handoff: pure wall-clock <-> Monotonic conversion ----
//
// A [`Monotonic`] is only meaningful *within* one process's clock (an opaque
// offset from that clock's own, unspecified epoch — see the module doc). A
// graceful-restart snapshot crosses a process boundary, so entry timestamps
// (`loaded_at` / `extended_at` / a pin deadline / a failure record's
// `failed_at`) must travel as something process-independent: an absolute
// wall-clock instant. These two functions are that conversion, kept as pure
// functions (no hidden `SystemTime::now()` / `Clock` call) precisely so the
// conversion itself is deterministically unit-testable (DR-0029 "時刻ヘルパは
// pure 関数に切って単体テスト").

/// Convert a `Monotonic` point into an absolute wall-clock timestamp
/// (milliseconds since the Unix epoch), given the current monotonic time and
/// the current wall-clock time (both supplied explicitly by the caller).
///
/// The result is only meaningful when later fed back through
/// [`epoch_ms_to_monotonic`] with the *same* `now_wall_epoch_ms` convention
/// (milliseconds since the Unix epoch) — this is a snapshot-serialization
/// primitive, not a general-purpose wall-clock API.
pub(crate) fn monotonic_to_epoch_ms(
    now_mono: Monotonic,
    now_wall_epoch_ms: u64,
    point: Monotonic,
) -> u64 {
    if point >= now_mono {
        let ahead = point.saturating_duration_since(now_mono);
        now_wall_epoch_ms.saturating_add(ahead.as_millis() as u64)
    } else {
        let behind = now_mono.saturating_duration_since(point);
        now_wall_epoch_ms.saturating_sub(behind.as_millis() as u64)
    }
}

/// The inverse of [`monotonic_to_epoch_ms`]: reconstruct a `Monotonic` point
/// from a wall-clock timestamp, anchored against the *importing* process's own
/// current monotonic/wall-clock reading.
///
/// # Headroom caveat (known limitation, not fixed by this function)
///
/// [`Monotonic`] is a non-negative offset from its clock's own epoch (see the
/// module doc). If `epoch_ms` is further in the past than `now_mono`'s own
/// offset allows — e.g. the importing process's clock started only moments
/// ago (offset ≈ 0) but the snapshot entry is hours old — the reconstructed
/// point saturates at [`Monotonic::ZERO`] via [`Monotonic::saturating_sub`]
/// instead of underflowing, which makes the entry look *newer* than it really
/// is. A fresh process has no monotonic "runway" to place an old timestamp
/// before its own start; giving the importing [`Clock`] enough headroom (e.g.
/// anchoring its epoch to a fixed point such as the Unix epoch rather than
/// process start) is the responsibility of whoever constructs that clock —
/// tracked as a DR-0029 Phase 2 (fork/exec integration) concern. This function
/// cannot fix that locally; it only guarantees it degrades safely (saturates,
/// never panics, never goes negative).
pub(crate) fn epoch_ms_to_monotonic(
    now_mono: Monotonic,
    now_wall_epoch_ms: u64,
    epoch_ms: u64,
) -> Monotonic {
    if epoch_ms >= now_wall_epoch_ms {
        let ahead_ms = epoch_ms - now_wall_epoch_ms;
        now_mono.saturating_add(Duration::from_millis(ahead_ms))
    } else {
        let behind_ms = now_wall_epoch_ms - epoch_ms;
        now_mono.saturating_sub(Duration::from_millis(behind_ms))
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

    // ---- Monotonic::saturating_sub ----

    #[test]
    fn saturating_sub_moves_backward() {
        let m = Monotonic::from_offset(Duration::from_secs(10));
        assert_eq!(
            m.saturating_sub(Duration::from_secs(3)),
            Monotonic::from_offset(Duration::from_secs(7))
        );
    }

    #[test]
    fn saturating_sub_clamps_at_zero_instead_of_underflowing() {
        let m = Monotonic::from_offset(Duration::from_secs(2));
        assert_eq!(
            m.saturating_sub(Duration::from_secs(100)),
            Monotonic::ZERO,
            "must saturate, not panic on underflow"
        );
    }

    // ---- monotonic_to_epoch_ms / epoch_ms_to_monotonic (DR-0029 pure helpers) ----

    #[test]
    fn monotonic_to_epoch_ms_of_now_is_wall_now() {
        let now_mono = Monotonic::from_offset(Duration::from_secs(1_000));
        let now_wall_ms = 50_000u64;
        assert_eq!(
            monotonic_to_epoch_ms(now_mono, now_wall_ms, now_mono),
            now_wall_ms
        );
    }

    #[test]
    fn monotonic_to_epoch_ms_of_a_past_point_subtracts_the_gap() {
        // A point 30s before "now" maps to a wall-clock instant 30s earlier.
        let now_mono = Monotonic::from_offset(Duration::from_secs(1_000));
        let past = Monotonic::from_offset(Duration::from_secs(970));
        let now_wall_ms = 100_000u64;
        assert_eq!(
            monotonic_to_epoch_ms(now_mono, now_wall_ms, past),
            100_000 - 30_000
        );
    }

    #[test]
    fn monotonic_to_epoch_ms_of_a_future_point_adds_the_gap() {
        // A pin deadline 5s ahead of "now" maps to a wall-clock instant 5s later.
        let now_mono = Monotonic::from_offset(Duration::from_secs(1_000));
        let future = Monotonic::from_offset(Duration::from_secs(1_005));
        let now_wall_ms = 100_000u64;
        assert_eq!(
            monotonic_to_epoch_ms(now_mono, now_wall_ms, future),
            105_000
        );
    }

    #[test]
    fn epoch_ms_to_monotonic_round_trips_with_monotonic_to_epoch_ms() {
        // Round trip through both conversions using the *same* now/now_wall pair
        // (simulating same-process re-derivation) must be exact.
        let now_mono = Monotonic::from_offset(Duration::from_secs(500));
        let now_wall_ms = 999_000u64;
        for offset_secs in [0i64, 30, -30, 3600, -3600] {
            let point = if offset_secs >= 0 {
                now_mono.saturating_add(Duration::from_secs(offset_secs as u64))
            } else {
                now_mono.saturating_sub(Duration::from_secs((-offset_secs) as u64))
            };
            let epoch_ms = monotonic_to_epoch_ms(now_mono, now_wall_ms, point);
            let back = epoch_ms_to_monotonic(now_mono, now_wall_ms, epoch_ms);
            assert_eq!(back, point, "offset {offset_secs}s must round-trip exactly");
        }
    }

    #[test]
    fn epoch_ms_to_monotonic_preserves_relative_order_across_a_process_boundary() {
        // Simulate two different processes: the "old" clock used at export and
        // the "new" clock used at import each have their own, unrelated zero
        // point. As long as the *new* clock has enough headroom (its own
        // now_mono offset is comfortably larger than the oldest age being
        // reconstructed — see the headroom caveat on epoch_ms_to_monotonic),
        // the relative order of two points loaded at different times must
        // survive the round trip even though their absolute Monotonic values
        // differ between the two clocks.
        let old_now_mono = Monotonic::from_offset(Duration::from_secs(50_000)); // "old" process, been up a while
        let old_now_wall_ms = 1_700_000_000_000u64; // an arbitrary wall-clock instant
        let older_point = old_now_mono.saturating_sub(Duration::from_secs(7_200)); // loaded 2h ago
        let newer_point = old_now_mono.saturating_sub(Duration::from_secs(60)); // loaded 1m ago
        assert!(older_point < newer_point, "test setup sanity check");

        let older_epoch_ms = monotonic_to_epoch_ms(old_now_mono, old_now_wall_ms, older_point);
        let newer_epoch_ms = monotonic_to_epoch_ms(old_now_mono, old_now_wall_ms, newer_point);

        // The "new" process: unrelated zero point, but with enough headroom
        // (started, notionally, a full day of monotonic time "ago" in its own
        // numbering) to represent both ages without clamping.
        let new_now_mono = Monotonic::from_offset(Duration::from_secs(86_400));
        // A few seconds of real wall-clock time elapsed during the handoff.
        let new_now_wall_ms = old_now_wall_ms + 2_000;

        let reconstructed_older =
            epoch_ms_to_monotonic(new_now_mono, new_now_wall_ms, older_epoch_ms);
        let reconstructed_newer =
            epoch_ms_to_monotonic(new_now_mono, new_now_wall_ms, newer_epoch_ms);

        assert!(
            reconstructed_older < reconstructed_newer,
            "relative load order must be preserved across the process boundary"
        );
        // The absolute gap (± wall-clock/millisecond rounding slack) is also
        // preserved, not just the ordering.
        let expected_gap = Duration::from_secs(7_200 - 60);
        let actual_gap = reconstructed_newer.saturating_duration_since(reconstructed_older);
        let diff = actual_gap.abs_diff(expected_gap);
        assert!(
            diff <= Duration::from_millis(5),
            "elapsed-time gap must be preserved up to millisecond slack: expected {expected_gap:?}, got {actual_gap:?}"
        );
    }

    #[test]
    fn epoch_ms_to_monotonic_saturates_when_importing_clock_has_no_headroom() {
        // Documented limitation: if the *importing* clock's own numbering
        // starts too close to zero, an old timestamp cannot be represented
        // and clamps to Monotonic::ZERO instead of panicking. This is the
        // exact scenario epoch_ms_to_monotonic's doc warns about.
        let old_now_mono = Monotonic::from_offset(Duration::from_secs(10_000));
        let old_now_wall_ms = 1_700_000_000_000u64;
        let ancient_point = old_now_mono.saturating_sub(Duration::from_secs(9_999)); // 1s after old epoch
        let epoch_ms = monotonic_to_epoch_ms(old_now_mono, old_now_wall_ms, ancient_point);

        // The importing clock just started (offset ~0) with no headroom.
        let new_now_mono = Monotonic::from_offset(Duration::from_millis(5));
        let new_now_wall_ms = old_now_wall_ms; // no wall-clock gap for this test
        let reconstructed = epoch_ms_to_monotonic(new_now_mono, new_now_wall_ms, epoch_ms);

        assert_eq!(
            reconstructed,
            Monotonic::ZERO,
            "insufficient headroom clamps rather than underflows"
        );
    }
}
