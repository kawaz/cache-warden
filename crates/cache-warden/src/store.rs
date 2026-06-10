//! In-memory store mapping keys to cache entries.
//!
//! [`Store`] is the top-level container of the secure KV core: a map from a
//! string key to a [`CacheEntry`]. It evaluates TTL on read (gating stale /
//! destroyed values) and owns `set` / `get` / `delete` / `list`.
//!
//! Concurrency note: the store itself is not internally synchronized. Wrapping
//! it in a `Mutex` is left to the embedding layer because the daemon / socket
//! boundary that decides the locking granularity is still an open question
//! (see `docs/DESIGN-ja.md`). Keeping the core lock-free avoids baking in a
//! synchronization model before that boundary is settled.

use std::collections::BTreeMap;

use crate::clock::Clock;
use crate::entry::{CacheEntry, EntryState, ExtendError, Ttl};
use crate::secret::SecretBytes;
use crate::source::ValueSource;

/// In-memory secure key/value cache.
#[derive(Debug, Default)]
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
}

impl Store {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the entry under `key`, becoming Active now.
    ///
    /// Any previous entry under the same key is dropped (and thus its secret
    /// zeroized) before the new one takes its place.
    pub fn set(
        &mut self,
        key: impl Into<String>,
        source: ValueSource,
        value: SecretBytes,
        ttl: Ttl,
        clock: &impl Clock,
    ) {
        let entry = CacheEntry::new(source, value, ttl, clock);
        // Inserting overwrites the old entry; the displaced CacheEntry is dropped
        // here, zeroizing its secret.
        self.entries.insert(key.into(), entry);
    }

    /// Borrow the secret under `key` iff it exists and is currently Active.
    ///
    /// Evaluating may zeroize a hard-expired value as a side effect. Returns
    /// `None` if the key is absent, soft-expired, or hard-expired.
    pub fn get(&mut self, key: &str, clock: &impl Clock) -> Option<&SecretBytes> {
        self.entries.get_mut(key)?.get(clock)
    }

    /// The current lifecycle state of `key`, or `None` if the key is absent.
    ///
    /// Applies the hard-expiry zeroize side effect.
    pub fn state_of(&mut self, key: &str, clock: &impl Clock) -> Option<EntryState> {
        self.entries.get_mut(key).map(|e| e.evaluate(clock))
    }

    /// Re-authenticate and refresh `key` back to Active.
    ///
    /// Returns `Err(ExtendOutcome::NotFound)` if the key is absent, or
    /// `Err(ExtendOutcome::HardExpired)` if the value is already destroyed.
    pub fn extend(&mut self, key: &str, clock: &impl Clock) -> Result<(), ExtendOutcome> {
        match self.entries.get_mut(key) {
            None => Err(ExtendOutcome::NotFound),
            Some(entry) => entry
                .extend(clock)
                .map_err(|ExtendError::HardExpired| ExtendOutcome::HardExpired),
        }
    }

    /// Remove `key`, returning `true` if it was present.
    ///
    /// The removed entry is dropped (zeroizing its secret).
    pub fn delete(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// The keys currently in the store, sorted.
    ///
    /// Listing does not evaluate TTL or mutate entries; keys of hard-expired-
    /// but-not-yet-deleted entries are still listed until removed.
    pub fn list(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// Number of entries in the store (including not-yet-deleted expired ones).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Outcome of [`Store::extend`] when it cannot succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum ExtendOutcome {
    /// No entry exists under the given key.
    NotFound,
    /// The entry exists but its value is already hard-expired (destroyed).
    HardExpired,
}

impl std::fmt::Display for ExtendOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendOutcome::NotFound => write!(f, "no such key"),
            ExtendOutcome::HardExpired => write!(f, "entry is hard-expired (destroyed)"),
        }
    }
}

impl std::error::Error for ExtendOutcome {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use std::time::Duration;

    const SOFT: Duration = Duration::from_secs(10);
    const HARD: Duration = Duration::from_secs(30);

    fn ttl() -> Ttl {
        Ttl::new(Some(SOFT), Some(HARD)).unwrap()
    }

    #[test]
    fn empty_store() {
        let s = Store::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.list().is_empty());
    }

    #[test]
    fn set_then_get_active() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "DB",
            ValueSource::Static,
            SecretBytes::from("pw"),
            ttl(),
            &clock,
        );
        assert_eq!(s.get("DB", &clock).unwrap().expose_secret(), b"pw");
    }

    #[test]
    fn get_missing_key_is_none() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        assert!(s.get("nope", &clock).is_none());
    }

    #[test]
    fn get_gated_when_soft_expired() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        clock.advance(SOFT);
        assert!(s.get("K", &clock).is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
    }

    #[test]
    fn get_none_after_hard_expiry() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        clock.advance(HARD);
        assert!(s.get("K", &clock).is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    #[test]
    fn extend_refreshes_soft_expired_entry() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        clock.advance(Duration::from_secs(15));
        s.extend("K", &clock).unwrap();
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"v");
    }

    #[test]
    fn extend_missing_key_reports_not_found() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        assert_eq!(s.extend("ghost", &clock), Err(ExtendOutcome::NotFound));
    }

    #[test]
    fn extend_hard_expired_reports_hard_expired() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        clock.advance(HARD);
        assert_eq!(s.extend("K", &clock), Err(ExtendOutcome::HardExpired));
    }

    #[test]
    fn delete_removes_entry() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        assert!(s.delete("K"));
        assert!(!s.delete("K")); // already gone
        assert!(s.get("K", &clock).is_none());
    }

    #[test]
    fn list_returns_sorted_keys() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "b",
            ValueSource::Static,
            SecretBytes::from("1"),
            ttl(),
            &clock,
        );
        s.set(
            "a",
            ValueSource::Static,
            SecretBytes::from("2"),
            ttl(),
            &clock,
        );
        s.set(
            "c",
            ValueSource::Static,
            SecretBytes::from("3"),
            ttl(),
            &clock,
        );
        assert_eq!(s.list(), vec!["a", "b", "c"]);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn set_overwrites_existing_key() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("old"),
            ttl(),
            &clock,
        );
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("new"),
            ttl(),
            &clock,
        );
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"new");
    }

    #[test]
    fn re_set_revives_a_hard_expired_static_key() {
        // A static entry cannot be *extended* after hard expiry, but the caller
        // may always set it again (the documented recovery path).
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        clock.advance(HARD);
        assert!(s.get("K", &clock).is_none());
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("again"),
            ttl(),
            &clock,
        );
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"again");
    }
}
