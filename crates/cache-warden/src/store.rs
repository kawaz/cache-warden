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

use crate::auth::{AuthContext, AuthError, AuthOperation, Authenticator};
use crate::clock::Clock;
use crate::entry::{CacheEntry, EntryState, ExtendError, Ttl};
use crate::process::ProcessInfo;
use crate::secret::SecretBytes;
use crate::source::{RunError, SourceRunner, ValueSource};

/// Build an [`AuthContext`] for `key`/`op`, attaching `requester` if present.
///
/// Centralizes the "`None` requester ⇒ in-process / unattributed" convention so
/// every gated path expresses it the same way.
fn auth_context(key: &str, op: AuthOperation, requester: Option<&[ProcessInfo]>) -> AuthContext {
    let ctx = match op {
        AuthOperation::Extend => AuthContext::extend(key),
        AuthOperation::Regenerate => AuthContext::regenerate(key),
    };
    match requester {
        Some(chain) => ctx.with_requester(chain.to_vec()),
        None => ctx,
    }
}

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

    /// Re-authenticate the user, then extend `key` back to Active.
    ///
    /// This is the auth-gated counterpart to [`Store::extend`]. The [`Store`]
    /// layer is where re-authentication is enforced (see [`crate::auth`]); the
    /// low-level [`crate::CacheEntry::extend`] remains auth-free.
    ///
    /// The authenticator is consulted **only when the entry is soft-expired**
    /// (the transition the DESIGN figure gates with re-auth). When the entry is
    /// already Active, this is a no-op refresh and authentication is *not*
    /// requested — there is nothing to unlock. A denied or unavailable
    /// authenticator leaves the entry untouched.
    ///
    /// `requester` is the ancestry chain of the process asking for the unlock
    /// (from [`crate::ProcessInspector::ancestry`]), forwarded into the
    /// [`AuthContext`] so the [`Authenticator`] can name who is asking. Pass
    /// `None` for an in-process / unattributed call. The core does not interpret
    /// the chain as policy (DR-0004); it only carries it to the prompt.
    pub fn extend_authenticated(
        &mut self,
        key: &str,
        auth: &impl Authenticator,
        requester: Option<&[ProcessInfo]>,
        clock: &impl Clock,
    ) -> Result<(), ExtendAuthOutcome> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or(ExtendAuthOutcome::NotFound)?;
        match entry.evaluate(clock) {
            EntryState::Active => {
                // Already fresh: refresh the window without prompting.
                entry
                    .extend(clock)
                    .map_err(|ExtendError::HardExpired| ExtendAuthOutcome::HardExpired)
            }
            EntryState::SoftExpired => {
                auth.authenticate(&auth_context(key, AuthOperation::Extend, requester))
                    .map_err(ExtendAuthOutcome::AuthFailed)?;
                entry
                    .extend(clock)
                    .map_err(|ExtendError::HardExpired| ExtendAuthOutcome::HardExpired)
            }
            EntryState::HardExpired => Err(ExtendAuthOutcome::HardExpired),
        }
    }

    /// Regenerate a hard-expired, regenerable entry's value upstream.
    ///
    /// This implements the DESIGN-ja "command 型: コマンド再実行 → 再認証 →
    /// 再生成" path. The natural flow is: a caller `get`s a key, observes it is
    /// [`EntryState::HardExpired`], and then chooses to `regenerate` it.
    ///
    /// Steps, in order:
    ///
    /// 1. The entry must exist, be regenerable (a [`ValueSource::Command`]), and
    ///    currently be hard-expired. Otherwise the matching
    ///    [`RegenerateOutcome`] error is returned and nothing runs.
    /// 2. The source command is re-run via `runner` to fetch a fresh value.
    /// 3. The user re-authenticates via `auth`.
    /// 4. On success the entry is replaced by a fresh Active entry holding the
    ///    new value, with the same source and TTL, activated at `clock.now()`.
    ///
    /// # Order rationale (run before auth)
    ///
    /// The command runs *before* the auth prompt so that an upstream failure
    /// (network down, `op` not signed in) surfaces without bothering the user
    /// for biometrics that would be wasted. The freshly fetched value is held in
    /// a [`SecretBytes`] across the auth step and dropped (zeroized) if auth is
    /// denied, so a rejected regeneration leaves no plaintext behind and does
    /// not mutate the stored entry.
    /// `requester` is forwarded into the regeneration [`AuthContext`] exactly as
    /// in [`Store::extend_authenticated`]: the requesting process's ancestry
    /// chain, or `None` for an in-process / unattributed call.
    pub fn regenerate(
        &mut self,
        key: &str,
        runner: &impl SourceRunner,
        auth: &impl Authenticator,
        requester: Option<&[ProcessInfo]>,
        clock: &impl Clock,
    ) -> Result<(), RegenerateOutcome> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or(RegenerateOutcome::NotFound)?;

        let argv = match entry.source() {
            ValueSource::Command { argv } => argv.clone(),
            ValueSource::Static => return Err(RegenerateOutcome::NotRegenerable),
        };

        // Regeneration only applies once the value is actually destroyed.
        if entry.evaluate(clock) != EntryState::HardExpired {
            return Err(RegenerateOutcome::NotHardExpired);
        }

        let ttl = entry.ttl();
        let source = entry.source().clone();

        // 2. Re-run upstream. On failure nothing is mutated.
        let value = runner.run(&argv).map_err(RegenerateOutcome::RunFailed)?;

        // 3. Re-authenticate. `value` is dropped (zeroized) on the error path.
        auth.authenticate(&auth_context(key, AuthOperation::Regenerate, requester))
            .map_err(RegenerateOutcome::AuthFailed)?;

        // 4. Replace with a fresh Active entry (overwrite zeroizes the old one).
        self.entries
            .insert(key.to_string(), CacheEntry::new(source, value, ttl, clock));
        Ok(())
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

    /// Borrow the [`ValueSource`] of `key`, or `None` if the key is absent.
    ///
    /// This is value-free metadata (the source describes *how* a value is
    /// obtained, not the value itself), so it does not evaluate TTL or expose
    /// any secret. An adapter uses it to report whether an entry is
    /// regenerable without unlocking it.
    pub fn source_of(&self, key: &str) -> Option<&ValueSource> {
        self.entries.get(key).map(CacheEntry::source)
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

/// Outcome of [`Store::extend_authenticated`] when it cannot succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum ExtendAuthOutcome {
    /// No entry exists under the given key.
    NotFound,
    /// The entry's value is already hard-expired (destroyed); use regenerate.
    HardExpired,
    /// Re-authentication was denied or unavailable.
    AuthFailed(AuthError),
}

impl std::fmt::Display for ExtendAuthOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendAuthOutcome::NotFound => write!(f, "no such key"),
            ExtendAuthOutcome::HardExpired => {
                write!(f, "entry is hard-expired (destroyed); regenerate instead")
            }
            ExtendAuthOutcome::AuthFailed(e) => write!(f, "extend blocked: {e}"),
        }
    }
}

impl std::error::Error for ExtendAuthOutcome {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExtendAuthOutcome::AuthFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// Outcome of [`Store::regenerate`] when it cannot succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum RegenerateOutcome {
    /// No entry exists under the given key.
    NotFound,
    /// The entry's source is `static`; it cannot be regenerated (re-`set` needed).
    NotRegenerable,
    /// The entry is not hard-expired, so there is nothing to regenerate. Callers
    /// should `get` / `extend` instead while the value is still resident.
    NotHardExpired,
    /// The upstream source command failed; the stored entry is unchanged.
    RunFailed(RunError),
    /// Re-authentication was denied or unavailable; the fetched value was
    /// discarded (zeroized) and the stored entry is unchanged.
    AuthFailed(AuthError),
}

impl std::fmt::Display for RegenerateOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegenerateOutcome::NotFound => write!(f, "no such key"),
            RegenerateOutcome::NotRegenerable => {
                write!(f, "static source cannot be regenerated; re-set it instead")
            }
            RegenerateOutcome::NotHardExpired => {
                write!(f, "entry is not hard-expired; nothing to regenerate")
            }
            RegenerateOutcome::RunFailed(e) => write!(f, "regeneration command failed: {e}"),
            RegenerateOutcome::AuthFailed(e) => write!(f, "regeneration blocked: {e}"),
        }
    }
}

impl std::error::Error for RegenerateOutcome {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RegenerateOutcome::RunFailed(e) => Some(e),
            RegenerateOutcome::AuthFailed(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AllowAll, DenyAll, RecordingAuthenticator};
    use crate::clock::FakeClock;
    use std::time::Duration;

    const SOFT: Duration = Duration::from_secs(10);
    const HARD: Duration = Duration::from_secs(30);

    fn ttl() -> Ttl {
        Ttl::new(Some(SOFT), Some(HARD)).unwrap()
    }

    /// A test runner returning a fixed value, recording how many times it ran.
    struct CountingRunner {
        value: Vec<u8>,
        runs: std::cell::Cell<usize>,
    }
    impl CountingRunner {
        fn new(value: &[u8]) -> Self {
            Self {
                value: value.to_vec(),
                runs: std::cell::Cell::new(0),
            }
        }
        fn runs(&self) -> usize {
            self.runs.get()
        }
    }
    impl SourceRunner for CountingRunner {
        fn run(&self, _argv: &[String]) -> Result<SecretBytes, RunError> {
            self.runs.set(self.runs.get() + 1);
            Ok(SecretBytes::new(self.value.clone()))
        }
    }

    /// A test runner that always fails (without running anything externally).
    struct FailingRunner;
    impl SourceRunner for FailingRunner {
        fn run(&self, _argv: &[String]) -> Result<SecretBytes, RunError> {
            Err(RunError::EmptyOutput)
        }
    }

    fn cmd_entry(s: &mut Store, key: &str, clock: &FakeClock) {
        s.set(
            key,
            ValueSource::command(["echo".into(), "v".into()]),
            SecretBytes::from("original"),
            ttl(),
            clock,
        );
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
    fn source_of_reports_kind_without_exposing_value() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "stat",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        cmd_entry(&mut s, "cmd", &clock);
        assert_eq!(s.source_of("stat"), Some(&ValueSource::Static));
        assert!(s.source_of("cmd").unwrap().is_regenerable());
        assert_eq!(s.source_of("ghost"), None);
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

    // ---- extend_authenticated (auth-gated extend) ----

    #[test]
    fn extend_authenticated_prompts_only_when_soft_expired() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        let auth = RecordingAuthenticator::allowing();

        // Active: no prompt, just a window refresh.
        s.extend_authenticated("K", &auth, None, &clock).unwrap();
        assert_eq!(auth.call_count(), 0, "Active extend must not prompt");

        // Soft-expired: prompts exactly once.
        clock.advance(Duration::from_secs(15));
        s.extend_authenticated("K", &auth, None, &clock).unwrap();
        assert_eq!(auth.call_count(), 1);
        assert_eq!(auth.calls()[0], AuthContext::extend("K"));
        // Refreshed to Active and readable.
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"original");
    }

    #[test]
    fn extend_authenticated_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(Duration::from_secs(15));

        let chain = vec![ProcessInfo {
            pid: 7,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/usr/bin/ssh")),
            start_time: None,
        }];
        let auth = RecordingAuthenticator::allowing();
        s.extend_authenticated("K", &auth, Some(&chain), &clock)
            .unwrap();
        // The recorded context carries the requester so an Authenticator could
        // name who is asking.
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    #[test]
    fn regenerate_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(HARD);

        let chain = vec![ProcessInfo {
            pid: 9,
            ppid: None,
            path: Some(std::path::PathBuf::from("/bin/git")),
            start_time: None,
        }];
        let runner = CountingRunner::new(b"fresh");
        let auth = RecordingAuthenticator::allowing();
        s.regenerate("K", &runner, &auth, Some(&chain), &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    #[test]
    fn in_process_call_records_no_requester() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(Duration::from_secs(15));
        let auth = RecordingAuthenticator::allowing();
        // None requester == in-process / unattributed.
        s.extend_authenticated("K", &auth, None, &clock).unwrap();
        assert_eq!(auth.calls()[0].requester, None);
    }

    #[test]
    fn extend_authenticated_denied_leaves_entry_soft_expired() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(Duration::from_secs(15));
        let err = s
            .extend_authenticated("K", &DenyAll, None, &clock)
            .unwrap_err();
        assert_eq!(err, ExtendAuthOutcome::AuthFailed(AuthError::Denied));
        // Still gated (unchanged).
        assert!(s.get("K", &clock).is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
    }

    #[test]
    fn extend_authenticated_missing_key() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        assert_eq!(
            s.extend_authenticated("ghost", &AllowAll, None, &clock),
            Err(ExtendAuthOutcome::NotFound)
        );
    }

    #[test]
    fn extend_authenticated_hard_expired_reports_hard_expired_without_prompt() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(HARD);
        let auth = RecordingAuthenticator::allowing();
        assert_eq!(
            s.extend_authenticated("K", &auth, None, &clock),
            Err(ExtendAuthOutcome::HardExpired)
        );
        assert_eq!(auth.call_count(), 0, "no prompt for destroyed value");
    }

    // ---- regenerate: the get -> HardExpired -> regenerate flow ----

    #[test]
    fn regenerate_command_entry_after_hard_expiry_with_auth() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);

        // Natural flow: read, observe destruction, choose to regenerate.
        clock.advance(HARD);
        assert!(s.get("K", &clock).is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));

        let runner = CountingRunner::new(b"fresh-token");
        let auth = RecordingAuthenticator::allowing();
        s.regenerate("K", &runner, &auth, None, &clock).unwrap();

        assert_eq!(runner.runs(), 1);
        assert_eq!(auth.call_count(), 1);
        assert_eq!(auth.calls()[0], AuthContext::regenerate("K"));
        // Back to Active with the new value.
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"fresh-token");
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
    }

    #[test]
    fn regenerate_restarts_ttl_window() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(HARD);
        let runner = CountingRunner::new(b"fresh");
        s.regenerate("K", &runner, &AllowAll, None, &clock).unwrap();
        // The soft window restarts from regeneration time.
        clock.advance(Duration::from_secs(9));
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
        clock.advance(Duration::from_secs(1));
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
    }

    #[test]
    fn regenerate_static_source_is_rejected() {
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
        let runner = CountingRunner::new(b"x");
        let err = s
            .regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::NotRegenerable);
        assert_eq!(runner.runs(), 0, "must not run for a static source");
    }

    #[test]
    fn regenerate_not_hard_expired_is_rejected() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        // Active: nothing to regenerate.
        let runner = CountingRunner::new(b"x");
        assert_eq!(
            s.regenerate("K", &runner, &AllowAll, None, &clock),
            Err(RegenerateOutcome::NotHardExpired)
        );
        assert_eq!(runner.runs(), 0);
        // Soft-expired: also rejected (value still resident; extend instead).
        clock.advance(Duration::from_secs(15));
        assert_eq!(
            s.regenerate("K", &runner, &AllowAll, None, &clock),
            Err(RegenerateOutcome::NotHardExpired)
        );
        assert_eq!(runner.runs(), 0);
    }

    #[test]
    fn regenerate_missing_key() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        let runner = CountingRunner::new(b"x");
        assert_eq!(
            s.regenerate("ghost", &runner, &AllowAll, None, &clock),
            Err(RegenerateOutcome::NotFound)
        );
    }

    #[test]
    fn regenerate_auth_denied_leaves_entry_destroyed() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(HARD);
        let runner = CountingRunner::new(b"fresh");
        let err = s
            .regenerate("K", &runner, &DenyAll, None, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::AuthFailed(AuthError::Denied));
        // Command ran (fetch happens before auth), but the value was discarded.
        assert_eq!(runner.runs(), 1);
        assert!(s.get("K", &clock).is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    #[test]
    fn regenerate_run_failure_skips_auth_and_keeps_entry_destroyed() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        cmd_entry(&mut s, "K", &clock);
        clock.advance(HARD);
        let auth = RecordingAuthenticator::allowing();
        let err = s
            .regenerate("K", &FailingRunner, &auth, None, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::RunFailed(RunError::EmptyOutput));
        assert_eq!(auth.call_count(), 0, "auth must not run if fetch failed");
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }
}
