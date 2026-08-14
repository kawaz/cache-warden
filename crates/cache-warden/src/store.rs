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

use zeroize::Zeroizing;

use crate::auth::{AuthContext, AuthError, AuthOperation, Authenticator};
use crate::capability::{CapError, Capability};
use crate::clock::{
    Clock, Monotonic, epoch_ms_to_monotonic, epoch_ms_to_monotonic_for_failure,
    epoch_ms_to_monotonic_ttl_basis, monotonic_to_epoch_ms,
};
use crate::definition::{DefineError, Definition};
use crate::entry::{CacheEntry, EntryState, ExtendError, PinError, Ttl};
use crate::guard::GuardRecord;
use crate::key::{InvalidKey, validate_key_syntax};
use crate::meta::{SourceMeta, ValueMeta};
use crate::process::ProcessInfo;
use crate::refresh::RefreshClaim;
use crate::secret::SecretBytes;
use crate::snapshot::{
    self, ExportError, ImportError, SnapshotConstraint, SnapshotDeclaredAncestor,
    SnapshotDefinition, SnapshotEntry, SnapshotFailure, SnapshotGuard, SnapshotPinnedProcess,
    SnapshotSource, SnapshotValue, StoreSnapshot,
};
use crate::source::{RunError, SourceRunner, ValueSource};

/// Build an [`AuthContext`] for `key`/`op`, attaching `requester` if present.
///
/// Centralizes the "`None` requester ⇒ in-process / unattributed" convention so
/// every gated path expresses it the same way.
fn auth_context(key: &str, op: AuthOperation, requester: Option<&[ProcessInfo]>) -> AuthContext {
    let ctx = match op {
        AuthOperation::Extend => AuthContext::extend(key),
        AuthOperation::Regenerate => AuthContext::regenerate(key),
        AuthOperation::Pin => AuthContext::pin(key),
    };
    match requester {
        Some(chain) => ctx.with_requester(chain.to_vec()),
        None => ctx,
    }
}

/// A record of a fetch failure for a given key (DR-0022).
///
/// Stored in [`Store::failure_backoffs`]; consulted at the start of every
/// `regenerate` / `get_or_regenerate` call to suppress redundant upstream
/// fetch attempts while a short-term backoff window is active.
#[derive(Debug, Clone, Copy)]
pub struct FailureRecord {
    /// Monotonic time at which the failure occurred.
    pub failed_at: crate::clock::Monotonic,
    /// How long to suppress re-fetch after this failure. A zero value means
    /// the record is inert (backoff disabled — see [`Store::failure_backoff_duration`]).
    pub retry_after: std::time::Duration,
}

/// In-memory secure key/value cache.
///
/// Three maps, deliberately separate (DR-0014, DR-0022):
///
/// - `entries` holds live secret **values** (TTL-gated, zeroized on hard expiry).
/// - `definitions` holds the value-free **definitions** (how to regenerate).
/// - `failure_backoffs` holds per-key failure records (DR-0022): when a fetch
///   fails, the record blocks re-fetch until `retry_after` elapses. Lifetime
///   mirrors `definitions`: cleared by [`Store::delete_with_definition`]; survives
///   value-only [`Store::delete`] and hard-TTL expiry.
///
/// A key may appear in any combination of `entries` / `definitions`:
///
/// - value only → a `set` entry with no definition (e.g. a static value).
/// - definition only → defined but never yet produced (lazy), or its value was
///   `delete`d (the definition survives so the next get can regenerate it).
/// - both → a defined key whose value has been produced and is resident.
///
/// Capability gate (DR-0024): all secret-handling methods require a [`Capability`]
/// token obtained from the [`StoreBuilder`] that created this store. Callers
/// holding a different token (or no token) receive [`CapError::KeyMismatch`].
/// Use [`Store::builder`] to construct a store and obtain matching capabilities.
#[derive(Debug)]
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
    /// Per-key short-term failure backoff records (DR-0022).
    ///
    /// An entry is inserted when `runner.run` fails in `regenerate` /
    /// `get_or_regenerate`, and removed when the same path succeeds. The
    /// lifetime of a record follows `definitions`: it is dropped by
    /// `delete_with_definition` but survives `delete` (value-only) and
    /// hard-TTL expiry — because the definition is still present and the
    /// next lazy load would retry the same failing source.
    ///
    /// [`Store::set`] never touches this map (DR-0022 §C1): a static value
    /// injection is not the same event as a lazy-fetch success.
    failure_backoffs: BTreeMap<String, FailureRecord>,
    /// Per-entry access guard records (DR-0030).
    ///
    /// Populated by [`Store::set_guard`] alongside a [`Store::set`] whose CLI
    /// invocation declared `--require-*` constraints; cleared by
    /// [`Store::clear_guard`] when a subsequent unguarded set replaces the
    /// entry.
    ///
    /// # Lifetime — differs from [`Store::failure_backoffs`]
    ///
    /// `failure_backoffs` mirrors `definitions` (a fetch failure only makes
    /// sense while a definition is present); a value-only `delete` leaves the
    /// backoff record alive. An `access_guards` entry mirrors the **value
    /// set instance** instead: the record is "the setter's declaration for
    /// *this particular* injected value", and once the value is gone the
    /// declaration is meaningless. So every path that removes the value
    /// (value-only [`Store::delete`], [`Store::delete_with_definition`]) also
    /// removes the guard, and [`Store::undefine`] clears it too — a definition
    /// change is a lifecycle event the guard should not silently survive
    /// (DR-0030 §5).
    ///
    /// [`Store::set`] itself deliberately does **not** touch this map: the
    /// CLI/daemon layer decides whether a set carries new constraints (call
    /// `set_guard`) or none (call `clear_guard`), so the core stays oblivious
    /// to per-adapter default policy (`default-require-same-user` etc.).
    access_guards: BTreeMap<String, GuardRecord>,
    /// Per-key monotonic CAS versions (DR-0034 §4).
    ///
    /// A key absent from this map is at version 0, which the arbitration
    /// protocol reads as "does not exist yet" — so a create can be expressed
    /// as a compare-and-swap against 0 rather than needing a separate
    /// operation.
    ///
    /// # Lifetime — deliberately the longest of the four side maps
    ///
    /// A version **survives a value-only [`Store::delete`]** and hard-TTL
    /// expiry, and is dropped only when the key is removed outright
    /// ([`Store::delete_with_definition`]). Resetting it on a value delete
    /// would let a caller holding a stale version win a compare-and-swap
    /// against a *re-created* key — the "a consumed refresh token still looks
    /// current" failure DR-0034 §4 relies on monotonicity to prevent. The cost
    /// is a `u64` per deleted-but-still-defined key, which is bounded by the
    /// key count.
    ///
    /// The core only stores and advances this. Whether a caller's expected
    /// version matches is the adapter's judgement (DR-0004), the same split
    /// [`Store::access_guards`] uses.
    versions: BTreeMap<String, u64>,
    /// Per-key in-progress refresh claims (DR-0034 §4).
    ///
    /// Lifetime mirrors [`Store::access_guards`], not [`Store::versions`]: a
    /// claim describes a refresh of *this* value, so removing the value ends
    /// it. Keeping a claim past its value would leave an entry nobody can
    /// claim and nobody can release.
    ///
    /// Expiry and token matching are the adapter's to evaluate; the core does
    /// not read the clock on this map's behalf.
    refresh_claims: BTreeMap<String, RefreshClaim>,
    /// How long to suppress re-fetch after a `runner.run` failure (DR-0022).
    ///
    /// Configured via [`StoreBuilder::failure_backoff`]. The default is
    /// [`Duration::ZERO`], which disables the feature (no records are written,
    /// no backoff is applied). The daemon reads this from
    /// `[daemon].fetch-failure-backoff` and passes it through the builder.
    failure_backoff_duration: std::time::Duration,
    /// Process-local capability token for this store (DR-0024).
    ///
    /// Every secret-handling method checks the caller's [`Capability`] token
    /// against this value. A mismatch returns [`CapError::KeyMismatch`]
    /// immediately, before any backoff, lifecycle, runner, or auth logic runs.
    access_token: u128,
}

/// Outcome of constructing a [`Store`] via [`StoreBuilder::build`].
///
/// Bundles the store with three separate [`Capability`] tokens — one per
/// adapter role (control, authsock, otp). All three tokens are identical in
/// this implementation (they share the same per-process random token); separate
/// fields anticipate future role-based differentiation without breaking callers.
pub struct StoreBundle {
    /// The constructed store.
    pub store: Store,
    /// Capability for the control adapter (kv set/get/delete, list, define…).
    pub control_cap: Capability,
    /// Capability for the authsock adapter (get, extend, regenerate).
    pub authsock_cap: Capability,
    /// Capability for the OTP adapter (get, set).
    pub otp_cap: Capability,
}

/// Builder for [`Store`], producing a [`StoreBundle`] that includes the
/// matching [`Capability`] tokens (DR-0024).
///
/// Prefer [`Store::builder`] as the entry point.
pub struct StoreBuilder {
    failure_backoff_duration: std::time::Duration,
}

impl StoreBuilder {
    /// Create a builder with default settings (backoff disabled).
    pub fn new() -> Self {
        Self {
            failure_backoff_duration: std::time::Duration::ZERO,
        }
    }

    /// Set the per-failure backoff duration (DR-0022).
    ///
    /// After a `runner.run` failure in `regenerate` / `get_or_regenerate`, the
    /// store suppresses re-fetch attempts for this long. A [`Duration::ZERO`]
    /// (the default) disables the feature. The daemon reads this from
    /// `[daemon].fetch-failure-backoff` in config.
    pub fn failure_backoff(mut self, d: std::time::Duration) -> Self {
        self.failure_backoff_duration = d;
        self
    }

    /// Build the store and generate a fresh per-process capability token.
    ///
    /// Returns a [`StoreBundle`] containing the store and three [`Capability`]
    /// tokens (control, authsock, otp). Pass the appropriate token to each
    /// secret-handling method of the store.
    pub fn build(self) -> StoreBundle {
        let token = crate::capability::fresh_process_local_token();
        let cap = Capability { token };
        StoreBundle {
            store: Store::new_with_token(token, self.failure_backoff_duration),
            control_cap: cap.clone(),
            authsock_cap: cap.clone(),
            otp_cap: cap,
        }
    }
}

impl Default for StoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// Create a new [`StoreBuilder`] — the canonical entry point for constructing
    /// a store and obtaining its matching [`Capability`] tokens (DR-0024).
    pub fn builder() -> StoreBuilder {
        StoreBuilder::new()
    }

    /// Construct a store with a pre-issued token and backoff duration.
    ///
    /// This is called exclusively by [`StoreBuilder::build`]; it is not
    /// `pub` to prevent a caller from supplying an arbitrary token and
    /// bypassing the capability gate.
    pub(crate) fn new_with_token(
        token: u128,
        failure_backoff_duration: std::time::Duration,
    ) -> Self {
        Self {
            entries: BTreeMap::new(),
            definitions: BTreeMap::new(),
            failure_backoffs: BTreeMap::new(),
            access_guards: BTreeMap::new(),
            versions: BTreeMap::new(),
            refresh_claims: BTreeMap::new(),
            failure_backoff_duration,
            access_token: token,
        }
    }

    /// Check that `cap` matches this store's access token (DR-0024).
    ///
    /// Cap check runs before backoff, lifecycle, runner, and auth so that an
    /// unauthorized caller cannot probe any observable state of the store.
    fn check_cap(&self, cap: &Capability) -> Result<(), CapError> {
        if cap.token == self.access_token {
            Ok(())
        } else {
            Err(CapError::KeyMismatch)
        }
    }

    /// Remaining backoff duration for `key`, or `None` if no active backoff.
    ///
    /// Returns `Some(remaining)` iff a failure record exists *and* the backoff
    /// window has not yet elapsed. Returns `None` if the key has no failure
    /// record or the window has already passed. This is value-free metadata
    /// for `status` / `kv list` and test introspection.
    pub fn failure_backoff_remaining(
        &self,
        key: &str,
        clock: &impl Clock,
    ) -> Option<std::time::Duration> {
        let record = self.failure_backoffs.get(key)?;
        if record.retry_after == std::time::Duration::ZERO {
            return None;
        }
        let now = clock.now();
        let elapsed = now.saturating_duration_since(record.failed_at);
        if elapsed < record.retry_after {
            Some(record.retry_after - elapsed)
        } else {
            None
        }
    }

    /// Insert or replace the entry under `key`, becoming Active now.
    ///
    /// Any previous entry under the same key is dropped (and thus its secret
    /// zeroized) before the new one takes its place. The value is opaque bytes;
    /// a value *type* (e.g. otp) lives on the key's definition (DR-0016), so a
    /// preloaded typed value is `set` here while its type rides on the
    /// definition registered separately.
    ///
    /// Cap check (DR-0024) runs first: returns [`SetError::CapMismatch`] if
    /// `cap` does not match this store's token. The key is then validated for the
    /// composed-key syntax (DR-0017 §1.5); a malformed key is rejected with
    /// [`SetError::InvalidKey`] and the store is left untouched.
    pub fn set(
        &mut self,
        key: impl Into<String>,
        source: ValueSource,
        value: SecretBytes,
        ttl: Ttl,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<(), SetError> {
        // Cap first (DR-0024): an unauthorized caller learns nothing and mutates
        // nothing. Key syntax is checked only after authorization succeeds.
        self.check_cap(cap).map_err(|_| SetError::CapMismatch)?;
        let key = key.into();
        validate_key_syntax(&key)?;
        let entry = CacheEntry::new(source, value, ttl, clock);
        // Inserting overwrites the old entry; the displaced CacheEntry is dropped
        // here, zeroizing its secret.
        self.entries.insert(key, entry);
        Ok(())
    }

    /// Borrow the secret under `key` iff it exists and is currently Active.
    ///
    /// Evaluating may zeroize a hard-expired value as a side effect. Returns
    /// `None` if the key is absent, soft-expired, or hard-expired.
    ///
    /// Cap check (DR-0024) runs first: returns `Err(CapError::KeyMismatch)` if
    /// `cap` does not match. On success returns `Ok(None)` or `Ok(Some(&secret))`.
    pub fn get(
        &mut self,
        key: &str,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<Option<&SecretBytes>, CapError> {
        self.check_cap(cap)?;
        Ok(self.entries.get_mut(key).and_then(|e| e.get(clock)))
    }

    /// The current lifecycle state of `key`, or `None` if the key is absent.
    ///
    /// Applies the hard-expiry zeroize side effect.
    pub fn state_of(&mut self, key: &str, clock: &impl Clock) -> Option<EntryState> {
        self.entries.get_mut(key).map(|e| e.evaluate(clock))
    }

    /// The current lifecycle state of `key` without triggering zeroize (DR-0025).
    ///
    /// Uses [`CacheEntry::state`] (pure read), the same method [`ItemRef::state`]
    /// calls in filter callbacks. Hard-expired entries are reported as
    /// [`EntryState::HardExpired`] but their value is **not** zeroized.
    ///
    /// Use this for observation-only paths (e.g. `status` display) where
    /// zeroize timing is handled by the normal `get` / `state_of` path.
    pub fn entry_state_pure(&self, key: &str, clock: &impl Clock) -> Option<EntryState> {
        self.entries.get(key).map(|e| e.state(clock))
    }

    /// Re-authenticate and refresh `key` back to Active.
    ///
    /// Returns `Err(ExtendOutcome::NotFound)` if the key is absent, or
    /// `Err(ExtendOutcome::HardExpired)` if the value is already destroyed.
    /// Returns `Err(ExtendOutcome::CapMismatch)` if the capability does not
    /// match this store (DR-0024 cap check runs first).
    pub fn extend(
        &mut self,
        key: &str,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<(), ExtendOutcome> {
        self.check_cap(cap)
            .map_err(|_| ExtendOutcome::CapMismatch)?;
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
        auth: &(impl Authenticator + ?Sized),
        requester: Option<&[ProcessInfo]>,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<(), ExtendAuthOutcome> {
        self.check_cap(cap)
            .map_err(|_| ExtendAuthOutcome::CapMismatch)?;
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
        auth: &(impl Authenticator + ?Sized),
        requester: Option<&[ProcessInfo]>,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<(), RegenerateOutcome> {
        // DR-0024: cap check runs before backoff, entry lookup, runner, and auth.
        self.check_cap(cap)
            .map_err(|_| RegenerateOutcome::CapMismatch)?;
        // DR-0022: check backoff before touching the entry.
        // A backoff window from a previous RunFailed suppresses re-fetch.
        if let Some(remaining) = self.failure_backoff_remaining(key, clock) {
            tracing::warn!(
                key,
                retry_after_secs = remaining.as_secs_f64(),
                "regenerate: backoff active, suppressing re-fetch"
            );
            return Err(RegenerateOutcome::Backoff {
                retry_after: remaining,
            });
        }

        let entry = self
            .entries
            .get_mut(key)
            .ok_or(RegenerateOutcome::NotFound)?;

        let (argv, cwd, env) = match entry.source() {
            ValueSource::Command { argv, cwd, env } => (argv.clone(), cwd.clone(), env.clone()),
            ValueSource::Static => return Err(RegenerateOutcome::NotRegenerable),
        };

        // Regeneration only applies once the value is actually destroyed.
        if entry.evaluate(clock) != EntryState::HardExpired {
            return Err(RegenerateOutcome::NotHardExpired);
        }

        let ttl = entry.ttl();
        let source = entry.source().clone();

        // 2. Re-run upstream. On failure record backoff if duration > 0.
        let value = runner.run(&argv, cwd.as_deref(), &env).map_err(|e| {
            if self.failure_backoff_duration > std::time::Duration::ZERO {
                tracing::warn!(
                    key,
                    backoff_secs = self.failure_backoff_duration.as_secs_f64(),
                    "regenerate: runner failed, inserting failure backoff"
                );
                self.failure_backoffs.insert(
                    key.to_string(),
                    FailureRecord {
                        failed_at: clock.now(),
                        retry_after: self.failure_backoff_duration,
                    },
                );
            }
            RegenerateOutcome::RunFailed(e)
        })?;

        // 3. Re-authenticate. `value` is dropped (zeroized) on the error path.
        // TODO(Q7): auth failures are not currently backoff-tracked; see DR-0022 Open Question Q7.
        auth.authenticate(&auth_context(key, AuthOperation::Regenerate, requester))
            .map_err(RegenerateOutcome::AuthFailed)?;

        // 4. Replace with a fresh Active entry (overwrite zeroizes the old one).
        // On success, clear any existing backoff record (DR-0022).
        self.failure_backoffs.remove(key);
        // DR-0030 §5: a guard record is bound to one set instance. The new
        // value here is a fresh set instance (the old one was hard-expired
        // and the value we install is upstream-regenerated, not a
        // continuation of the setter's declaration), so a stale guard from
        // the previous instance must not silently gate reads of the new
        // value. v1 only attaches guards via `kv set` (Static), so this
        // branch is defensive against future definition-side guards; the
        // cleanup is uniform across every path that replaces the value.
        self.access_guards.remove(key);
        // A claim describes a refresh of the value that just went away.
        self.refresh_claims.remove(key);
        self.entries
            .insert(key.to_string(), CacheEntry::new(source, value, ttl, clock));
        Ok(())
    }

    /// Re-authenticate the user, then pin `key` Active until `deadline`.
    ///
    /// This is the manual reprieve of DR-0011: it holds a live value alive past
    /// its soft *and* hard windows until `deadline` (e.g. "keep this usable for
    /// the next 8 hours so an overnight hard expiry can't interrupt work").
    ///
    /// # Why pin always re-authenticates (even from Active)
    ///
    /// Unlike [`Store::extend_authenticated`], which skips the prompt while the
    /// entry is already Active (there is nothing to unlock), pin **always**
    /// demands authentication. Pinning is a security-relaxing operation — it
    /// suppresses the very expiry that would otherwise zeroize the secret — so
    /// the human must consciously authorize extending the value's exposure. The
    /// asymmetry is deliberate: extend merely re-confirms a window that the TTL
    /// already permits, whereas pin overrides it.
    ///
    /// The authenticator is consulted *before* the pin is applied; a denied or
    /// unavailable authenticator leaves the entry untouched. A hard-expired
    /// entry cannot be pinned (its value is destroyed); use regenerate / re-set.
    ///
    /// `requester` is forwarded into the [`AuthContext`] exactly as in
    /// [`Store::extend_authenticated`].
    pub fn pin_authenticated(
        &mut self,
        key: &str,
        deadline: Monotonic,
        auth: &(impl Authenticator + ?Sized),
        requester: Option<&[ProcessInfo]>,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<(), PinAuthOutcome> {
        self.check_cap(cap)
            .map_err(|_| PinAuthOutcome::CapMismatch)?;
        let entry = self.entries.get_mut(key).ok_or(PinAuthOutcome::NotFound)?;
        // Reject a destroyed value before bothering the user for biometrics.
        if entry.state(clock) == EntryState::HardExpired {
            return Err(PinAuthOutcome::HardExpired);
        }
        auth.authenticate(&auth_context(key, AuthOperation::Pin, requester))
            .map_err(PinAuthOutcome::AuthFailed)?;
        entry
            .pin_until(deadline, clock)
            .map_err(|PinError::HardExpired| PinAuthOutcome::HardExpired)
    }

    /// Drop any active pin on `key`, returning it to normal TTL evaluation.
    ///
    /// Returns `Ok(false)` if the key is absent, `Ok(true)` if unpinned.
    /// Returns `Err(CapError::KeyMismatch)` if `cap` does not match.
    ///
    /// Unlike [`Store::pin_authenticated`] this needs no *user* authentication
    /// (removing a reprieve only moves the entry back toward expiry, the safe
    /// direction), but it still requires a valid [`Capability`] so that an
    /// unauthorized caller cannot disturb pin state (DR-0024).
    pub fn unpin(&mut self, key: &str, cap: &Capability) -> Result<bool, CapError> {
        self.check_cap(cap)?;
        Ok(match self.entries.get_mut(key) {
            Some(entry) => {
                entry.unpin();
                true
            }
            None => false,
        })
    }

    /// The active pin deadline for `key`, or `None` if absent or not pinned.
    ///
    /// Value-free metadata for `status` / `list`: it reveals *when* a reprieve
    /// lapses, never the secret. A caller computes remaining seconds against the
    /// clock (a deadline already in the past reports a non-positive remainder).
    pub fn pin_deadline_of(&self, key: &str) -> Option<Monotonic> {
        self.entries.get(key).and_then(CacheEntry::pin_deadline)
    }

    /// Remove `key`, returning `Ok(true)` if it was present, `Ok(false)` if absent.
    ///
    /// The removed entry is dropped (zeroizing its secret).
    /// Returns `Err(CapError::KeyMismatch)` if `cap` does not match (DR-0024).
    pub fn delete(&mut self, key: &str, cap: &Capability) -> Result<bool, CapError> {
        self.check_cap(cap)?;
        // DR-0030 §5: guard record is bound to the value set instance. Even a
        // value-only delete (which leaves `failure_backoffs` alive because a
        // definition is still there to regenerate through) drops the guard —
        // the setter's declaration only ever applied to *this* injected value.
        self.access_guards.remove(key);
        // A claim describes a refresh of the value that just went away.
        self.refresh_claims.remove(key);
        Ok(self.entries.remove(key).is_some())
    }

    /// The keys currently in the store, sorted.
    ///
    /// Listing does not evaluate TTL or mutate entries; keys of hard-expired-
    /// but-not-yet-deleted entries are still listed until removed.
    ///
    /// # Deprecated
    /// Use `list_filtered(|r| r.entry().is_some())` instead (DR-0025).
    #[deprecated(note = "use list_filtered(|r| r.entry().is_some()) instead")]
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

    /// Number of value entries in the store (including not-yet-deleted expired
    /// ones). Definition-only keys (no produced value) are **not** counted here;
    /// use [`Store::keys`] for the union.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no value entries (ignoring definition-only keys).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ---- definition registry (DR-0014) ----

    /// Register the value-source definition for `key`, idempotently.
    ///
    /// A definition binds a key to *how* its value is regenerated (a command
    /// source + the TTL freshly produced values carry), held separately from the
    /// value store (DR-0014 §2): defining a key does **not** run the command or
    /// produce a value — production is deferred to the first [`Store::get_or_regenerate`].
    ///
    /// Idempotency is an **exact-match** rule (DR-0014 §1):
    ///
    /// - no existing definition → register it.
    /// - existing definition identical (same argv *and* TTL) → no-op `Ok(())`.
    /// - existing definition differs → [`DefineError::Conflict`] (the caller must
    ///   `delete_with_definition` then re-define; we never silently overwrite, so
    ///   two scripts clashing on a key surface the clash instead of clobbering).
    ///
    /// A [`ValueSource::Static`] source is rejected with
    /// [`DefineError::StaticNotDefinable`]: only command sources can lazily
    /// regenerate a value. This is independent of the value store — a static
    /// *value* may coexist under the same key (via [`Store::set`]); the
    /// definition is simply about regeneration, and [`Store::get_or_regenerate`]
    /// only falls back to it when the value is absent or destroyed.
    pub fn define(
        &mut self,
        key: impl Into<String>,
        source: ValueSource,
        ttl: Ttl,
    ) -> Result<(), DefineError> {
        self.define_with_meta(key, source, ttl, ValueMeta::new(), SourceMeta::new())
    }

    /// Register a definition with opaque type metadata (DR-0016) and an opaque
    /// typed-source-origin slot (DR-0018 §2).
    ///
    /// Same idempotency rule as [`Store::define`], but both the [`ValueMeta`] and
    /// the [`SourceMeta`] are part of the definition's identity: a redefine that
    /// differs only in its value-type metadata *or* in its typed source origin is
    /// a [`DefineError::Conflict`] (a key cannot quietly change type or source).
    /// The value metadata is copied onto each value produced from this definition;
    /// the source metadata is preserved for `status` / persistence.
    pub fn define_with_meta(
        &mut self,
        key: impl Into<String>,
        source: ValueSource,
        ttl: Ttl,
        meta: ValueMeta,
        source_meta: SourceMeta,
    ) -> Result<(), DefineError> {
        // Validate the composed-key syntax before anything else (DR-0017 §1.5):
        // `define` is not cap-gated (a definition is value-free metadata, DR-0024),
        // so the key grammar is the first and only gate on the key here.
        let key = key.into();
        validate_key_syntax(&key)?;
        let candidate = Definition::new(source, ttl)?
            .with_meta(meta)
            .with_source_meta(source_meta);
        match self.definitions.get(&key) {
            Some(existing) if *existing == candidate => Ok(()), // idempotent no-op
            Some(_) => Err(DefineError::Conflict),
            None => {
                self.definitions.insert(key, candidate);
                Ok(())
            }
        }
    }

    /// Borrow the [`Definition`] registered for `key`, or `None` if undefined.
    ///
    /// Value-free metadata for `status` / `list`: it reveals *how* a value would
    /// be regenerated (command argv + TTL), never the secret value. Works for a
    /// definition-only key (one whose value has not been produced yet).
    pub fn definition_of(&self, key: &str) -> Option<&Definition> {
        self.definitions.get(key)
    }

    /// Whether `key` has a registered definition (regardless of value presence).
    pub fn is_defined(&self, key: &str) -> bool {
        self.definitions.contains_key(key)
    }

    /// Whether `key` currently has a value entry (Active, soft- or hard-expired
    /// but not yet removed). A definition-only key reports `false`.
    pub fn has_value(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// All keys known to the store — the union of value entries and definitions
    /// — sorted and de-duplicated.
    ///
    /// Unlike [`Store::list`] (value entries only), this also surfaces
    /// definition-only keys (defined but not yet produced, or whose value was
    /// deleted) so `status` / `list` can report them. Listing evaluates no TTL
    /// and exposes no secret.
    ///
    /// # Deprecated
    /// Use `list_filtered(|_| true)` instead (DR-0025).
    #[deprecated(note = "use list_filtered(|_| true) instead")]
    pub fn keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = self
            .entries
            .keys()
            .chain(self.definitions.keys())
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    /// Filter the union of value entries and definitions by an [`ItemRef`] predicate (DR-0025).
    ///
    /// The callback receives an [`ItemRef<'_>`] for each key in the union of
    /// `entries` and `definitions`, and returns `true` to include that key.
    ///
    /// - `list_filtered(|_| true)` is equivalent to the deprecated `keys()`.
    /// - `list_filtered(|r| r.entry().is_some())` is equivalent to the deprecated `list()`.
    ///
    /// The callback holds an immutable borrow (`&Store`), so side effects such as
    /// hard-expiry zeroize are impossible inside a filter. Use `store.get` or
    /// `store.state_of` to trigger zeroize on specific keys.
    pub fn list_filtered<F>(&self, filter: F) -> Vec<&str>
    where
        F: Fn(&ItemRef<'_>) -> bool,
    {
        let mut keys: Vec<&str> = self
            .entries
            .keys()
            .chain(self.definitions.keys())
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys.dedup();

        keys.into_iter()
            .filter(|key| {
                let item = ItemRef { key, store: self };
                filter(&item)
            })
            .collect()
    }
}

// ---- ItemRef: lazy accessor handle (DR-0025) ----

/// Lazy accessor handle to a single key in a [`Store`] (DR-0025).
///
/// `ItemRef` bundles an immutable borrow of the store with a key name,
/// providing lazy per-accessor lookup across the three internal maps
/// (`entries` / `definitions` / `failure_backoffs`). An accessor is only
/// called if the filter needs it; accessors that are not called incur no
/// lookup cost.
///
/// The borrow is immutable (`&Store`), so a filter callback that holds an
/// `ItemRef` cannot trigger side effects such as hard-expiry zeroize. Pure
/// observation only.
pub struct ItemRef<'a> {
    key: &'a str,
    store: &'a Store,
}

impl<'a> ItemRef<'a> {
    /// The key this handle refers to.
    pub fn key(&self) -> &str {
        self.key
    }

    /// The current lifecycle state of the entry, computed with
    /// [`CacheEntry::state`] (pure read). Returns `None` if the key has no
    /// value entry.
    ///
    /// Does **not** trigger zeroize (`&self` borrow). Use `Store::state_of`
    /// (`&mut`) or `Store::get` to trigger hard-expiry zeroize.
    pub fn state(&self, clock: &impl Clock) -> Option<EntryState> {
        self.store.entries.get(self.key).map(|e| e.state(clock))
    }

    /// Borrow the [`CacheEntry`] for this key, or `None` if absent.
    pub fn entry(&self) -> Option<&CacheEntry> {
        self.store.entries.get(self.key)
    }

    /// Borrow the [`Definition`] for this key, or `None` if undefined.
    pub fn definition(&self) -> Option<&Definition> {
        self.store.definitions.get(self.key)
    }

    /// Borrow the [`FailureRecord`] for this key, or `None` if absent.
    pub fn failure(&self) -> Option<&FailureRecord> {
        self.store.failure_backoffs.get(self.key)
    }

    /// Remaining backoff duration for this key, or `None` if no active backoff.
    pub fn failure_remaining(&self, clock: &impl Clock) -> Option<std::time::Duration> {
        self.store.failure_backoff_remaining(self.key, clock)
    }

    /// Borrow the [`ValueMeta`] from this key's definition, or `None` if undefined.
    pub fn value_meta(&self) -> Option<&ValueMeta> {
        self.store.definitions.get(self.key).map(|d| d.meta())
    }

    /// Borrow the [`SourceMeta`] from this key's definition, or `None` if undefined.
    pub fn source_meta(&self) -> Option<&SourceMeta> {
        self.store
            .definitions
            .get(self.key)
            .map(|d| d.source_meta())
    }
}

// Reopen `impl Store` for the rest of the public API.
impl Store {
    /// Produce (or reproduce) `key`'s value from its registered definition.
    ///
    /// This is the lazy-generation path of DR-0014 §1: when a defined key's value
    /// is **absent** (never produced, or `delete`d) or **hard-expired**
    /// (destroyed), re-run the definition's command (re-auth included) to load a
    /// fresh value, resetting `loaded_at`. It reuses the same run-then-auth
    /// ordering and zeroize-on-deny guarantees as [`Store::regenerate`]; the only
    /// difference is the source of truth is the definition registry, so it works
    /// even when no value entry exists at all.
    ///
    /// Outcomes:
    ///
    /// - no definition for `key` → [`RegenerateDefOutcome::Undefined`].
    /// - a value entry exists and is **Active** or **SoftExpired** → there is a
    ///   resident value; this returns [`RegenerateDefOutcome::ValueResident`] and
    ///   runs nothing. Callers should `get` (Active) or `extend` (SoftExpired)
    ///   that value instead of regenerating it.
    /// - value absent or hard-expired → run the command, re-authenticate, and
    ///   install a fresh Active entry. Run/auth failures
    ///   ([`RegenerateDefOutcome::RunFailed`] / [`RegenerateDefOutcome::AuthFailed`])
    ///   leave the store unchanged (a hard-expired value stays destroyed; an
    ///   absent value stays absent), and the freshly fetched value is zeroized on
    ///   the auth-denied path.
    ///
    /// `requester` is forwarded into the [`AuthContext`] exactly as in
    /// [`Store::regenerate`].
    pub fn get_or_regenerate(
        &mut self,
        key: &str,
        runner: &impl SourceRunner,
        auth: &(impl Authenticator + ?Sized),
        requester: Option<&[ProcessInfo]>,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<(), RegenerateDefOutcome> {
        // DR-0024: cap check runs before definition lookup, backoff, runner, and auth.
        self.check_cap(cap)
            .map_err(|_| RegenerateDefOutcome::CapMismatch)?;
        let definition = self
            .definitions
            .get(key)
            .ok_or(RegenerateDefOutcome::Undefined)?;

        // A resident (Active or SoftExpired) value must not be silently
        // regenerated: that would burn an upstream call and re-auth while a
        // perfectly usable value sits in memory. Only an absent or destroyed
        // value falls through to regeneration.
        if let Some(entry) = self.entries.get_mut(key)
            && entry.evaluate(clock) != EntryState::HardExpired
        {
            return Err(RegenerateDefOutcome::ValueResident);
        }

        // DR-0022: check backoff before making an upstream call.
        if let Some(remaining) = self.failure_backoff_remaining(key, clock) {
            tracing::warn!(
                key,
                retry_after_secs = remaining.as_secs_f64(),
                "get_or_regenerate: backoff active, suppressing re-fetch"
            );
            return Err(RegenerateDefOutcome::Backoff {
                retry_after: remaining,
            });
        }

        let (argv, cwd, env) = match definition.source() {
            ValueSource::Command { argv, cwd, env } => (argv.clone(), cwd.clone(), env.clone()),
            // Definitions are command-only by construction (`define` rejects
            // static), so this is unreachable; treated defensively.
            ValueSource::Static => return Err(RegenerateDefOutcome::Undefined),
        };
        let source = definition.source().clone();
        let ttl = definition.ttl();

        // 1. Re-run upstream. On failure record backoff if duration > 0.
        let value = runner.run(&argv, cwd.as_deref(), &env).map_err(|e| {
            if self.failure_backoff_duration > std::time::Duration::ZERO {
                tracing::warn!(
                    key,
                    backoff_secs = self.failure_backoff_duration.as_secs_f64(),
                    "get_or_regenerate: runner failed, inserting failure backoff"
                );
                self.failure_backoffs.insert(
                    key.to_string(),
                    FailureRecord {
                        failed_at: clock.now(),
                        retry_after: self.failure_backoff_duration,
                    },
                );
            }
            RegenerateDefOutcome::RunFailed(e)
        })?;

        // 2. Re-authenticate. `value` is dropped (zeroized) on the error path.
        // TODO(Q7): auth failures are not currently backoff-tracked; see DR-0022 Open Question Q7.
        auth.authenticate(&auth_context(key, AuthOperation::Regenerate, requester))
            .map_err(RegenerateDefOutcome::AuthFailed)?;

        // 3. Install a fresh Active entry (overwriting any destroyed husk).
        // On success, clear any existing backoff record (DR-0022).
        self.failure_backoffs.remove(key);
        // DR-0030 §7: definition-derived entries are outside the guard's
        // scope (the guard was declared against the setter's *set instance*,
        // not against future upstream regeneration). Installing a fresh
        // definition-produced value here retires the old set instance, so
        // its guard record — if a caller of `set_guard` left one attached —
        // must be dropped rather than left to gate reads of a value the
        // setter never approved.
        self.access_guards.remove(key);
        // A claim describes a refresh of the value that just went away.
        self.refresh_claims.remove(key);
        self.entries
            .insert(key.to_string(), CacheEntry::new(source, value, ttl, clock));
        Ok(())
    }

    /// Remove both `key`'s value **and** its definition, returning `Ok(true)` if
    /// either was present, `Ok(false)` if the key was unknown entirely.
    ///
    /// This is the `--with-define` variant of DR-0014 §2: plain [`Store::delete`]
    /// drops only the value (the definition survives so the next get
    /// regenerates), whereas this forgets the key entirely so it will *not*
    /// regenerate. The removed value entry is dropped (zeroizing its secret).
    ///
    /// Also removes the failure-backoff record for `key` (DR-0022): the
    /// backoff lifetime mirrors the definition lifetime — if there is no
    /// definition, there is no lazy-fetch path, so the backoff is meaningless.
    ///
    /// Returns `Err(CapError::KeyMismatch)` if `cap` does not match (DR-0024).
    pub fn delete_with_definition(
        &mut self,
        key: &str,
        cap: &Capability,
    ) -> Result<bool, CapError> {
        self.check_cap(cap)?;
        let had_value = self.entries.remove(key).is_some();
        let had_def = self.definitions.remove(key).is_some();
        // DR-0022: failure backoff lifetime = definition lifetime.
        self.failure_backoffs.remove(key);
        // DR-0030 §5: guard follows the value; forgetting the key entirely
        // subsumes value-only delete's guard cleanup.
        self.access_guards.remove(key);
        // DR-0034 §4: the key is going away entirely, so its version goes
        // with it. Every other removal path keeps the version (see the
        // `versions` field doc) — only a full removal may reset it.
        self.versions.remove(key);
        // A claim describes a refresh of the value that just went away.
        self.refresh_claims.remove(key);
        Ok(had_value || had_def)
    }

    /// Remove only `key`'s definition, leaving any resident value entry and
    /// failure-backoff record untouched.
    ///
    /// Unlike [`Store::delete_with_definition`] (which forgets the key
    /// entirely, value included), this exists for callers that must replace
    /// *how* a key regenerates without disturbing value continuity — e.g.
    /// DR-0029 bundle 2's graceful-restart startup reconciliation, which
    /// clears an import-origin definition so the current config's
    /// `define_with_meta` can win cleanly, while the cached secret carried
    /// over by the handoff keeps serving until it naturally expires.
    ///
    /// Not cap-gated (DR-0024): like [`Store::define`]/[`Store::define_with_meta`],
    /// a definition is value-free metadata.
    ///
    /// Returns `true` if a definition was present and removed, `false` if
    /// `key` had none.
    pub fn undefine(&mut self, key: &str) -> bool {
        // DR-0030 §5: undefine is a lifecycle event; a guard record declared
        // against the previous generation of this key must not silently survive
        // a definition rebind. (v1 only attaches guards to `kv set` static
        // entries, but the cleanup is uniform across paths so a future
        // definition-side guard would inherit the same rule.)
        self.access_guards.remove(key);
        // A claim describes a refresh of the value that just went away.
        self.refresh_claims.remove(key);
        self.definitions.remove(key).is_some()
    }

    // ---- per-entry access guards (DR-0030) ----

    /// Attach (or replace) the [`GuardRecord`] for `key` (DR-0030 §1).
    ///
    /// Called by the CLI/daemon layer immediately after the matching
    /// [`Store::set`], with the constraint list decoded from the wire and the
    /// setter identity resolved from the connection's peer audit token. The
    /// full replacement semantics reflect DR-0030 §5 "set is record's whole
    /// declaration": a set with a fresh (or empty!) constraint list is
    /// authoritative — the CLI layer decides between calling this or
    /// [`Store::clear_guard`].
    ///
    /// # Why the core stays out of set()
    ///
    /// [`Store::set`] does not know whether the caller "meant" to guard the
    /// entry (there is no CLI-side default policy visible to the core, e.g.
    /// `default-require-same-user`). Making guard attachment a separate
    /// method lets the adapter apply its policy once, then hand the core two
    /// primitive operations (`set` + `set_guard`/`clear_guard`) with no
    /// hidden coupling.
    ///
    /// Cap check (DR-0024) runs first: returns [`CapError::KeyMismatch`] if
    /// `cap` does not match this store's token; nothing is mutated. Key
    /// syntax is not re-checked here — a guard can only be attached to a key
    /// that already survived `set`'s validation.
    pub fn set_guard(
        &mut self,
        key: impl Into<String>,
        record: GuardRecord,
        cap: &Capability,
    ) -> Result<(), CapError> {
        self.check_cap(cap)?;
        self.access_guards.insert(key.into(), record);
        Ok(())
    }

    /// Drop `key`'s guard record, returning whether one was present.
    ///
    /// Cap check runs first (DR-0024). Called by the CLI/daemon layer when a
    /// subsequent unguarded set replaces the previous entry.
    pub fn clear_guard(&mut self, key: &str, cap: &Capability) -> Result<bool, CapError> {
        self.check_cap(cap)?;
        Ok(self.access_guards.remove(key).is_some())
    }

    /// Borrow the [`GuardRecord`] attached to `key`, or `None` if unguarded.
    ///
    /// Value-free read: does not touch entries / definitions / TTL. Not
    /// cap-gated, matching `definition_of` / `source_of` — a guard record
    /// carries no secret plaintext (the setter chain is a fact, not a
    /// secret; DR-0030 §Security). The evaluator uses this on every `kv get`.
    pub fn guard_of(&self, key: &str) -> Option<&GuardRecord> {
        self.access_guards.get(key)
    }

    // ---- refresh arbitration (DR-0034 §4) ----

    /// `key`'s current CAS version, or `0` when it has none.
    ///
    /// Value-free and not cap-gated, matching [`Store::guard_of`]: a version
    /// is a change counter, never plaintext.
    pub fn version_of(&self, key: &str) -> u64 {
        self.versions.get(key).copied().unwrap_or(0)
    }

    /// Advance `key`'s version by one and return the new value.
    ///
    /// The only way a version moves, so monotonicity is a property of this
    /// function rather than of every caller remembering to increment.
    /// Saturating rather than wrapping: a `u64` counter cannot realistically
    /// be exhausted, and wrapping to zero would silently turn "exists" into
    /// "does not exist".
    ///
    /// Cap check (DR-0024) runs first; nothing is mutated on mismatch.
    pub fn bump_version(
        &mut self,
        key: impl Into<String>,
        cap: &Capability,
    ) -> Result<u64, CapError> {
        self.check_cap(cap)?;
        let key = key.into();
        let next = self.version_of(&key).saturating_add(1);
        self.versions.insert(key, next);
        Ok(next)
    }

    /// Record an in-progress refresh claim on `key`, replacing any existing
    /// one.
    ///
    /// Replacement is unconditional here on purpose: deciding whether the
    /// existing claim has lapsed, and whether this caller may take it over, is
    /// the adapter's call (DR-0004). The core would have to read the clock to
    /// judge, and it has no business doing so.
    ///
    /// Cap check (DR-0024) runs first.
    pub fn set_refresh_claim(
        &mut self,
        key: impl Into<String>,
        claim: RefreshClaim,
        cap: &Capability,
    ) -> Result<(), CapError> {
        self.check_cap(cap)?;
        self.refresh_claims.insert(key.into(), claim);
        Ok(())
    }

    /// Borrow `key`'s refresh claim, if one is recorded.
    ///
    /// Returns a recorded claim whether or not it has lapsed — expiry is the
    /// caller's to evaluate via [`RefreshClaim::is_active_at`].
    pub fn refresh_claim_of(&self, key: &str) -> Option<&RefreshClaim> {
        self.refresh_claims.get(key)
    }

    /// Drop `key`'s refresh claim, returning whether one was present.
    ///
    /// Cap check (DR-0024) runs first.
    pub fn clear_refresh_claim(&mut self, key: &str, cap: &Capability) -> Result<bool, CapError> {
        self.check_cap(cap)?;
        Ok(self.refresh_claims.remove(key).is_some())
    }

    // ---- graceful-restart snapshot (DR-0029 §2, Phase 1 / bundle 1) ----

    /// Serialize this store's full state into a [`StoreSnapshot`] for
    /// graceful-restart handoff to a fresh process.
    ///
    /// Only keys carrying *something* meaningful are included: a key whose
    /// value is logically hard-expired (a "husk" not yet physically
    /// zeroized — see [`CacheEntry::peek_value`]'s doc) contributes no value
    /// entry, and a key with no value, no definition, and no failure record
    /// at all is skipped entirely.
    ///
    /// `cap` is checked first (DR-0024): an unauthorized caller learns
    /// nothing about the store's contents. `clock` supplies "now" for the
    /// [`crate::clock::monotonic_to_epoch_ms`] wall-clock re-anchoring of
    /// every timestamp; the wall-clock side of that conversion reads the real
    /// [`std::time::SystemTime`] directly (this is a one-shot operation, not
    /// a per-tick TTL check, so — unlike every other `Store` method — there
    /// is no injectable wall-clock parameter; see the `snapshot` module doc
    /// for why the *pure* conversion functions this builds on stay
    /// independently testable regardless).
    ///
    /// Capability tokens (DR-0024) are adapter-role tokens, not tied to any
    /// entry (DR-0029 Q2), so none travel in the snapshot; the receiving
    /// process re-issues its own via [`Store::import_snapshot`]'s `builder`.
    pub fn export_snapshot(
        &self,
        cap: &Capability,
        clock: &impl Clock,
    ) -> Result<StoreSnapshot, ExportError> {
        self.check_cap(cap).map_err(|_| ExportError::CapMismatch)?;

        let now_mono = clock.now();
        let now_wall_ms = snapshot::wall_now_epoch_ms();
        let to_epoch_ms = |point: Monotonic| monotonic_to_epoch_ms(now_mono, now_wall_ms, point);

        let mut keys: Vec<&String> = self
            .entries
            .keys()
            .chain(self.definitions.keys())
            .chain(self.failure_backoffs.keys())
            .collect();
        keys.sort();
        keys.dedup();

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let value = self.entries.get(key).and_then(|entry| {
                // A logically hard-expired entry must never be exported as if
                // it were live plaintext, even if this method (which only
                // borrows `&self`) has not yet triggered the physical zeroize.
                if entry.state(clock) == EntryState::HardExpired {
                    return None;
                }
                let secret = entry.peek_value()?;
                Some(SnapshotValue {
                    source: SnapshotSource::from_value_source(entry.source()),
                    secret: Zeroizing::new(secret.with_exposed(|b| b.to_vec())),
                    soft_ttl_ms: entry.ttl().soft().map(|d| d.as_millis() as u64),
                    hard_ttl_ms: entry.ttl().hard().map(|d| d.as_millis() as u64),
                    loaded_at_epoch_ms: to_epoch_ms(entry.loaded_at()),
                    extended_at_epoch_ms: to_epoch_ms(entry.extended_at()),
                    pin_deadline_epoch_ms: entry.pin_deadline().map(to_epoch_ms),
                })
            });

            let definition = self.definitions.get(key).map(|def| {
                let (value_meta_type, value_meta_params) = def.meta().clone().into_parts();
                let (source_meta_kind, source_meta_fields) = def.source_meta().clone().into_parts();
                SnapshotDefinition {
                    source: SnapshotSource::from_value_source(def.source()),
                    soft_ttl_ms: def.ttl().soft().map(|d| d.as_millis() as u64),
                    hard_ttl_ms: def.ttl().hard().map(|d| d.as_millis() as u64),
                    value_meta_type,
                    value_meta_params,
                    source_meta_kind,
                    source_meta_fields,
                }
            });

            let failure = self
                .failure_backoffs
                .get(key)
                .map(|record| SnapshotFailure {
                    failed_at_epoch_ms: to_epoch_ms(record.failed_at),
                    retry_after_ms: record.retry_after.as_millis() as u64,
                });

            // DR-0030 §5: a guard record is bound to the setter's *value set
            // instance*, not to the key's definition. Only export the guard
            // when a live value survives this snapshot: a definition-only
            // key has no set instance for the guard to describe (the
            // definition's future regeneration is outside the guard's
            // scope, DR-0030 §7), and a hard-expired husk contributes no
            // value entry above and so must not drag a guard-only frame
            // across the handoff — which would gratuitously force
            // FORMAT_VERSION=2 on a downgrade path that carries no live
            // guarded secret at all.
            let guard = if value.is_some() {
                self.access_guards.get(key).map(guard_record_to_snapshot)
            } else {
                None
            };

            // DR-0034 §4. The claim follows the value (a claim on nothing is
            // meaningless); the version does not, because resetting it across
            // a restart is exactly the stale-writer hazard it guards against.
            let refresh_claim = if value.is_some() {
                self.refresh_claims.get(key).map(refresh_claim_to_snapshot)
            } else {
                None
            };
            let version = match self.versions.get(key) {
                Some(&v) if v > 0 => Some(v),
                _ => None,
            };

            if value.is_none()
                && definition.is_none()
                && failure.is_none()
                && guard.is_none()
                && version.is_none()
            {
                // Nothing meaningful survives for this key (e.g. a stale
                // hard-expired husk with no definition and no failure record).
                continue;
            }

            out.push(SnapshotEntry {
                key: key.clone(),
                value,
                definition,
                failure,
                guard,
                version,
                refresh_claim,
            });
        }

        // DR-0030 §3 ダウングレード方向: FORMAT_VERSION は snapshot.rs 側で
        // guard の有無から動的に選択される。ここでは選択そのものを snapshot.rs
        // に委ねる (Store から version をハードコードしない)。
        Ok(StoreSnapshot::from_entries(out))
    }

    /// Rebuild a store from a [`StoreSnapshot`]: the graceful-restart
    /// counterpart of [`Store::export_snapshot`], run by the freshly exec'd
    /// process.
    ///
    /// `builder` supplies the *new* process's own settings (e.g. the
    /// configured failure-backoff duration) and issues fresh [`Capability`]
    /// tokens. `clock` anchors the wall-clock-to-`Monotonic` re-anchoring for
    /// every timestamp the snapshot carries — see
    /// [`crate::clock::epoch_ms_to_monotonic`]'s doc for the headroom this
    /// clock needs to provide for old entries to reconstruct their correct
    /// relative age (a bundle-2 / fork-exec-integration concern; this method
    /// cannot fix an under-provisioned clock, only degrade safely if given
    /// one).
    ///
    /// Rejects the whole snapshot up front if its format version is not one
    /// this build understands ([`ImportError::UnsupportedVersion`]) — no
    /// entries are installed in that case. A malformed individual entry (an
    /// invalid TTL, a reconstructed `extended_at` preceding `loaded_at`, a
    /// definition claiming a non-command source, a key that fails the
    /// composed-key syntax check, or a key repeated across entries — all
    /// only reachable via corrupted or maliciously crafted snapshot bytes,
    /// never via [`Store::export_snapshot`]'s own output) aborts the whole
    /// import with the corresponding [`ImportError`] rather than installing a
    /// partial store. "Aborts the whole import" is enforced by construction,
    /// not by manual rollback: every early return happens before the
    /// function returns `bundle`, so on any `Err` path `bundle` (and whatever
    /// entries were installed into it so far) is simply dropped here —
    /// zeroizing any [`SecretBytes`] already inserted via
    /// [`crate::secret::SecretBytes`]'s zeroize-on-drop guarantee, same as
    /// any other discarded `Store`.
    pub fn import_snapshot(
        builder: StoreBuilder,
        snapshot: StoreSnapshot,
        clock: &impl Clock,
    ) -> Result<StoreBundle, ImportError> {
        if !snapshot.is_supported_version() {
            return Err(ImportError::UnsupportedVersion {
                got: snapshot.format_version(),
                supported: crate::snapshot::FORMAT_VERSION,
            });
        }

        let mut bundle = builder.build();
        let now_mono = clock.now();
        let now_wall_ms = snapshot::wall_now_epoch_ms();
        // Three specialized reconstructions, not one shared closure (DR-0029
        // review HIGH-1 / HIGH-2): a TTL basis (loaded_at/extended_at) and a
        // failure-backoff's failed_at each need their own conservative
        // clamp direction when the wall clock regressed or the importing
        // clock lacks headroom — see the doc on each `clock` function for
        // why. `pin_deadline` alone uses the general conversion: a pin
        // deadline is legitimately ahead of "now" (that is the entire point
        // of a pin), so it must not be clamped like a TTL basis would be.
        let to_ttl_basis =
            |epoch_ms: u64| epoch_ms_to_monotonic_ttl_basis(now_mono, now_wall_ms, epoch_ms);
        let to_pin_deadline =
            |epoch_ms: u64| epoch_ms_to_monotonic(now_mono, now_wall_ms, epoch_ms);
        let to_failed_at =
            |epoch_ms: u64| epoch_ms_to_monotonic_for_failure(now_mono, now_wall_ms, epoch_ms);

        // DR-0029 review LOW-3: a key repeated across `SnapshotEntry`s is
        // only reachable via corrupted/crafted bytes (`Store::export_snapshot`
        // de-duplicates by construction) — reject outright rather than let
        // the later entry silently win.
        let mut seen_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for entry in snapshot.into_entries() {
            let SnapshotEntry {
                key,
                value,
                definition,
                failure,
                version,
                refresh_claim,
                guard,
            } = entry;

            // DR-0029 review HIGH-5: `Store::set` / `Store::define` always
            // validate key syntax (DR-0017 §1.5); import must not be a way to
            // smuggle a syntactically invalid key past that gate.
            validate_key_syntax(&key).map_err(|_| ImportError::InvalidKey { key: key.clone() })?;
            if !seen_keys.insert(key.clone()) {
                return Err(ImportError::DuplicateKey { key });
            }

            if let Some(mut v) = value {
                let soft = v.soft_ttl_ms.map(std::time::Duration::from_millis);
                let hard = v.hard_ttl_ms.map(std::time::Duration::from_millis);
                let ttl = Ttl::new(soft, hard)
                    .map_err(|_| ImportError::MalformedTtl { key: key.clone() })?;
                let loaded_at = to_ttl_basis(v.loaded_at_epoch_ms);
                let extended_at = to_ttl_basis(v.extended_at_epoch_ms);
                // DR-0029 review MEDIUM-2: CacheEntry::from_parts does not
                // itself check extended_at >= loaded_at (its signature is
                // unchanged; the invariant is enforced here, at the one
                // caller that reconstructs both from untrusted wire data).
                if extended_at < loaded_at {
                    return Err(ImportError::MalformedTtl { key: key.clone() });
                }
                let pin_deadline = v.pin_deadline_epoch_ms.map(to_pin_deadline);
                // Move the plaintext into `SecretBytes` without copying: the
                // Zeroizing<Vec<u8>> buffer is swapped for an empty Vec via
                // `mem::take` (through Zeroizing's DerefMut<Target=Vec<u8>>),
                // so the same allocation changes owner from `v.secret` to
                // `secret_bytes` rather than existing as two live copies —
                // the DR-0028 "no owned copy" pattern applied to import.
                let raw = std::mem::take(&mut *v.secret);
                let secret_bytes = SecretBytes::new(raw);
                let cache_entry = CacheEntry::from_parts(
                    v.source.into_value_source(),
                    ttl,
                    secret_bytes,
                    loaded_at,
                    extended_at,
                    pin_deadline,
                );
                bundle.store.entries.insert(key.clone(), cache_entry);
            }

            if let Some(d) = definition {
                let soft = d.soft_ttl_ms.map(std::time::Duration::from_millis);
                let hard = d.hard_ttl_ms.map(std::time::Duration::from_millis);
                let ttl = Ttl::new(soft, hard)
                    .map_err(|_| ImportError::MalformedTtl { key: key.clone() })?;
                let value_meta = ValueMeta::from_parts(d.value_meta_type, d.value_meta_params);
                let source_meta = SourceMeta::from_parts(d.source_meta_kind, d.source_meta_fields);
                let def = Definition::new(d.source.into_value_source(), ttl)
                    .map_err(|_| ImportError::MalformedDefinition { key: key.clone() })?
                    .with_meta(value_meta)
                    .with_source_meta(source_meta);
                bundle.store.definitions.insert(key.clone(), def);
            }

            if let Some(f) = failure {
                let failed_at = to_failed_at(f.failed_at_epoch_ms);
                bundle.store.failure_backoffs.insert(
                    key.clone(),
                    FailureRecord {
                        failed_at,
                        retry_after: std::time::Duration::from_millis(f.retry_after_ms),
                    },
                );
            }

            // DR-0030 §5: a guard record is bound to the setter's *value set
            // instance*. Install only when a live value survived import;
            // definition-only or empty entries are stripped even if the wire
            // carried a guard (a maliciously crafted stream could; the
            // honest exporter already prunes them per the symmetric check
            // in `export_snapshot`).
            if let Some(g) = guard
                && bundle.store.entries.contains_key(&key)
            {
                bundle
                    .store
                    .access_guards
                    .insert(key.clone(), snapshot_to_guard_record(g));
            }

            // DR-0034 §4: the version is installed unconditionally (it is not
            // tied to a live value), the claim only alongside one — the same
            // asymmetry `export_snapshot` applies, so a round trip is stable.
            if let Some(v) = version.filter(|v| *v > 0) {
                bundle.store.versions.insert(key.clone(), v);
            }
            if let Some(c) = refresh_claim
                && bundle.store.entries.contains_key(&key)
            {
                bundle
                    .store
                    .refresh_claims
                    .insert(key.clone(), snapshot_to_refresh_claim(c));
            }
        }

        Ok(bundle)
    }
}

/// [`RefreshClaim`] -> wire mirror (DR-0034 §4).
fn refresh_claim_to_snapshot(c: &RefreshClaim) -> crate::snapshot::SnapshotRefreshClaim {
    crate::snapshot::SnapshotRefreshClaim {
        token: c.token().to_string(),
        claimed_at_epoch_ms: c.claimed_at_epoch_ms(),
        expires_at_epoch_ms: c.expires_at_epoch_ms(),
    }
}

/// Wire mirror -> [`RefreshClaim`].
fn snapshot_to_refresh_claim(c: crate::snapshot::SnapshotRefreshClaim) -> RefreshClaim {
    RefreshClaim::new(c.token, c.claimed_at_epoch_ms, c.expires_at_epoch_ms)
}

// ---- guard <-> snapshot converters ----
//
// Kept as free functions (rather than `From`/`Into` impls between the wire
// mirror and the domain type) for the same reason `SnapshotSource` has plain
// converters: the mirror lives in `snapshot.rs` behind a `pub(crate)` API and
// the mapping is a one-file concern of `Store::{export,import}_snapshot`.

fn guard_record_to_snapshot(record: &crate::guard::GuardRecord) -> SnapshotGuard {
    use crate::guard::{DeclaredAncestor, GuardConstraint};
    let constraints = record
        .constraints
        .iter()
        .map(|c| match c {
            GuardConstraint::SameUser => SnapshotConstraint::SameUser,
            GuardConstraint::SameAncestor { declared, pinned } => {
                let declared = match declared {
                    DeclaredAncestor::SameShell { shell_name } => {
                        SnapshotDeclaredAncestor::SameShell {
                            shell_name: shell_name.clone(),
                        }
                    }
                    DeclaredAncestor::Named { name } => {
                        SnapshotDeclaredAncestor::Named { name: name.clone() }
                    }
                };
                SnapshotConstraint::SameAncestor {
                    declared,
                    pinned: SnapshotPinnedProcess {
                        pid: pinned.pid,
                        // DR-0030 §Security: the entity pin is checked by
                        // `PinnedProcess::start_time == getter.start_time`.
                        // macOS reports process start times at µs precision;
                        // ms truncation here would round two "same instant"
                        // reads to different values across a snapshot
                        // round-trip and turn every same-ancestor guard into
                        // a fail-closed denial after restart.
                        start_time_us: pinned.start_time.map(|d| d.as_micros() as u64),
                        unique_id: pinned.unique_id,
                        path: pinned.path.clone(),
                        name: pinned.name.clone(),
                    },
                }
            }
            GuardConstraint::Command { name } => SnapshotConstraint::Command { name: name.clone() },
        })
        .collect();
    SnapshotGuard {
        constraints,
        setter_euid: record.setter.euid,
        setter_ruid: record.setter.ruid,
    }
}

fn snapshot_to_guard_record(s: SnapshotGuard) -> crate::guard::GuardRecord {
    use crate::guard::{
        DeclaredAncestor, GuardConstraint, GuardRecord, GuardSetter, PinnedProcess,
    };
    let constraints = s
        .constraints
        .into_iter()
        .map(|c| match c {
            SnapshotConstraint::SameUser => GuardConstraint::SameUser,
            SnapshotConstraint::SameAncestor { declared, pinned } => {
                let declared = match declared {
                    SnapshotDeclaredAncestor::SameShell { shell_name } => {
                        DeclaredAncestor::SameShell { shell_name }
                    }
                    SnapshotDeclaredAncestor::Named { name } => DeclaredAncestor::Named { name },
                };
                GuardConstraint::SameAncestor {
                    declared,
                    pinned: PinnedProcess {
                        pid: pinned.pid,
                        // Symmetric with the exporter's `as_micros()`; see the
                        // note there for why ms would break the entity pin.
                        start_time: pinned.start_time_us.map(std::time::Duration::from_micros),
                        unique_id: pinned.unique_id,
                        path: pinned.path,
                        name: pinned.name,
                    },
                }
            }
            SnapshotConstraint::Command { name } => GuardConstraint::Command { name },
        })
        .collect();
    GuardRecord::new(
        constraints,
        GuardSetter {
            euid: s.setter_euid,
            ruid: s.setter_ruid,
        },
    )
}

/// Error from [`Store::set`] when it cannot inject a value.
#[derive(Debug, PartialEq, Eq)]
pub enum SetError {
    /// The key is not a syntactically valid composed key (DR-0017 §1.5). The
    /// store was not mutated.
    InvalidKey(InvalidKey),
    /// The capability token does not match this store (DR-0024). No key syntax
    /// check ran and the store was not mutated.
    CapMismatch,
}

impl From<InvalidKey> for SetError {
    fn from(e: InvalidKey) -> Self {
        SetError::InvalidKey(e)
    }
}

impl std::fmt::Display for SetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetError::InvalidKey(e) => write!(f, "{e}"),
            SetError::CapMismatch => write!(f, "capability does not match this store"),
        }
    }
}

impl std::error::Error for SetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SetError::InvalidKey(e) => Some(e),
            SetError::CapMismatch => None,
        }
    }
}

/// Outcome of [`Store::extend`] when it cannot succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum ExtendOutcome {
    /// No entry exists under the given key.
    NotFound,
    /// The entry exists but its value is already hard-expired (destroyed).
    HardExpired,
    /// The capability token does not match this store (DR-0024).
    CapMismatch,
}

impl std::fmt::Display for ExtendOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendOutcome::NotFound => write!(f, "no such key"),
            ExtendOutcome::HardExpired => write!(f, "entry is hard-expired (destroyed)"),
            ExtendOutcome::CapMismatch => write!(f, "capability does not match this store"),
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
    /// The capability token does not match this store (DR-0024).
    CapMismatch,
}

impl std::fmt::Display for ExtendAuthOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendAuthOutcome::NotFound => write!(f, "no such key"),
            ExtendAuthOutcome::HardExpired => {
                write!(f, "entry is hard-expired (destroyed); regenerate instead")
            }
            ExtendAuthOutcome::AuthFailed(e) => write!(f, "extend blocked: {e}"),
            ExtendAuthOutcome::CapMismatch => write!(f, "capability does not match this store"),
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
    /// A previous fetch failure is within its backoff window; no upstream call
    /// was made. Callers should wait at least `retry_after` before retrying
    /// (DR-0022). The caller is told the *remaining* window, not the original.
    Backoff {
        /// Remaining duration of the backoff window.
        retry_after: std::time::Duration,
    },
    /// The capability token does not match this store (DR-0024). No backoff,
    /// entry, runner, or auth state was consulted.
    CapMismatch,
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
            RegenerateOutcome::Backoff { retry_after } => write!(
                f,
                "backoff active; retry after {:.1}s",
                retry_after.as_secs_f64()
            ),
            RegenerateOutcome::CapMismatch => write!(f, "capability does not match this store"),
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

impl RegenerateOutcome {
    /// Whether this outcome represents a backoff (no upstream call was made).
    pub fn is_backoff(&self) -> bool {
        matches!(self, RegenerateOutcome::Backoff { .. })
    }
}

/// Outcome of [`Store::pin_authenticated`] when it cannot succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum PinAuthOutcome {
    /// No entry exists under the given key.
    NotFound,
    /// The entry's value is already hard-expired (destroyed); it cannot be
    /// pinned. Regenerate (command source) or re-set (static) instead.
    HardExpired,
    /// Re-authentication was denied or unavailable; the entry was not pinned.
    AuthFailed(AuthError),
    /// The capability token does not match this store (DR-0024).
    CapMismatch,
}

impl std::fmt::Display for PinAuthOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinAuthOutcome::NotFound => write!(f, "no such key"),
            PinAuthOutcome::HardExpired => {
                write!(f, "entry is hard-expired (destroyed); cannot pin")
            }
            PinAuthOutcome::AuthFailed(e) => write!(f, "pin blocked: {e}"),
            PinAuthOutcome::CapMismatch => write!(f, "capability does not match this store"),
        }
    }
}

impl std::error::Error for PinAuthOutcome {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PinAuthOutcome::AuthFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// Outcome of [`Store::get_or_regenerate`] when it cannot install a value.
#[derive(Debug, PartialEq, Eq)]
pub enum RegenerateDefOutcome {
    /// No definition is registered for the key; there is nothing to regenerate
    /// from. (Distinct from [`RegenerateOutcome::NotFound`], which is about a
    /// missing *value* entry.)
    Undefined,
    /// A usable value (Active or SoftExpired) is already resident, so no
    /// regeneration ran. Callers should `get` (Active) or `extend` (SoftExpired)
    /// the existing value instead.
    ValueResident,
    /// The upstream definition command failed; the store is unchanged.
    RunFailed(RunError),
    /// Re-authentication was denied or unavailable; the fetched value was
    /// discarded (zeroized) and the store is unchanged.
    AuthFailed(AuthError),
    /// A previous fetch failure is within its backoff window; no upstream call
    /// was made. The caller should wait at least `retry_after` before retrying
    /// (DR-0022). Mirrors [`RegenerateOutcome::Backoff`].
    Backoff {
        /// Remaining duration of the backoff window.
        retry_after: std::time::Duration,
    },
    /// The capability token does not match this store (DR-0024). No definition,
    /// backoff, runner, or auth state was consulted.
    CapMismatch,
}

impl std::fmt::Display for RegenerateDefOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegenerateDefOutcome::Undefined => write!(f, "no definition registered for this key"),
            RegenerateDefOutcome::ValueResident => {
                write!(
                    f,
                    "a usable value is already resident; get or extend it instead"
                )
            }
            RegenerateDefOutcome::RunFailed(e) => {
                write!(f, "definition command failed: {e}")
            }
            RegenerateDefOutcome::AuthFailed(e) => write!(f, "regeneration blocked: {e}"),
            RegenerateDefOutcome::Backoff { retry_after } => write!(
                f,
                "backoff active; retry after {:.1}s",
                retry_after.as_secs_f64()
            ),
            RegenerateDefOutcome::CapMismatch => {
                write!(f, "capability does not match this store")
            }
        }
    }
}

impl std::error::Error for RegenerateDefOutcome {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RegenerateDefOutcome::RunFailed(e) => Some(e),
            RegenerateDefOutcome::AuthFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl RegenerateDefOutcome {
    /// Whether this outcome represents a backoff (no upstream call was made).
    pub fn is_backoff(&self) -> bool {
        matches!(self, RegenerateDefOutcome::Backoff { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AllowAll, DenyAll, RecordingAuthenticator};
    use crate::capability::Capability;
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
        fn run(
            &self,
            _argv: &[String],
            _cwd: Option<&std::path::Path>,
            _env: &std::collections::BTreeMap<String, String>,
        ) -> Result<SecretBytes, RunError> {
            self.runs.set(self.runs.get() + 1);
            Ok(SecretBytes::new(self.value.clone()))
        }
    }

    /// A test runner that always fails (without running anything externally).
    struct FailingRunner;
    impl SourceRunner for FailingRunner {
        fn run(
            &self,
            _argv: &[String],
            _cwd: Option<&std::path::Path>,
            _env: &std::collections::BTreeMap<String, String>,
        ) -> Result<SecretBytes, RunError> {
            Err(RunError::EmptyOutput)
        }
    }

    fn cmd_entry(s: &mut Store, key: &str, cap: &Capability, clock: &FakeClock) {
        s.set(
            key,
            ValueSource::command(["echo".into(), "v".into()]),
            SecretBytes::from("original"),
            ttl(),
            cap,
            clock,
        )
        .expect("test cap valid");
    }

    #[test]
    fn empty_store() {
        let (s, _cap) = crate::test_helpers::store_with_cap();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        #[allow(deprecated)]
        let list = s.list();
        assert!(list.is_empty());
    }

    #[test]
    fn set_then_get_active() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "DB",
            ValueSource::Static,
            SecretBytes::from("pw"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        assert_eq!(
            s.get("DB", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"pw"
        );
    }

    #[test]
    fn get_missing_key_is_none() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        assert!(s.get("nope", &cap, &clock).unwrap().is_none());
    }

    #[test]
    fn get_gated_when_soft_expired() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(SOFT);
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
    }

    #[test]
    fn get_none_after_hard_expiry() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    #[test]
    fn extend_refreshes_soft_expired_entry() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(Duration::from_secs(15));
        s.extend("K", &cap, &clock).unwrap();
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"v"
        );
    }

    #[test]
    fn extend_missing_key_reports_not_found() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        assert_eq!(
            s.extend("ghost", &cap, &clock),
            Err(ExtendOutcome::NotFound)
        );
    }

    #[test]
    fn extend_hard_expired_reports_hard_expired() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        assert_eq!(s.extend("K", &cap, &clock), Err(ExtendOutcome::HardExpired));
    }

    #[test]
    fn delete_removes_entry() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        assert!(s.delete("K", &cap).unwrap());
        assert!(!s.delete("K", &cap).unwrap()); // already gone
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
    }

    #[test]
    fn list_returns_sorted_keys() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "b",
            ValueSource::Static,
            SecretBytes::from("1"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.set(
            "a",
            ValueSource::Static,
            SecretBytes::from("2"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.set(
            "c",
            ValueSource::Static,
            SecretBytes::from("3"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        #[allow(deprecated)]
        let result = s.list();
        assert_eq!(result, vec!["a", "b", "c"]);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn source_of_reports_kind_without_exposing_value() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "stat",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        cmd_entry(&mut s, "cmd", &cap, &clock);
        assert_eq!(s.source_of("stat"), Some(&ValueSource::Static));
        assert!(s.source_of("cmd").unwrap().is_regenerable());
        assert_eq!(s.source_of("ghost"), None);
    }

    #[test]
    fn set_overwrites_existing_key() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("old"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("new"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"new"
        );
    }

    #[test]
    fn re_set_revives_a_hard_expired_static_key() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("again"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"again"
        );
    }

    // ---- extend_authenticated (auth-gated extend) ----

    #[test]
    fn extend_authenticated_prompts_only_when_soft_expired() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        let auth = RecordingAuthenticator::allowing();

        // Active: no prompt, just a window refresh.
        s.extend_authenticated("K", &auth, None, &cap, &clock)
            .unwrap();
        assert_eq!(auth.call_count(), 0, "Active extend must not prompt");

        // Soft-expired: prompts exactly once.
        clock.advance(Duration::from_secs(15));
        s.extend_authenticated("K", &auth, None, &cap, &clock)
            .unwrap();
        assert_eq!(auth.call_count(), 1);
        assert_eq!(auth.calls()[0], AuthContext::extend("K"));
        // Refreshed to Active and readable.
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"original"
        );
    }

    #[test]
    fn extend_authenticated_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(Duration::from_secs(15));

        let chain = vec![ProcessInfo {
            pid: 7,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/usr/bin/ssh")),
            start_time: None,
        }];
        let auth = RecordingAuthenticator::allowing();
        s.extend_authenticated("K", &auth, Some(&chain), &cap, &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    #[test]
    fn regenerate_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);

        let chain = vec![ProcessInfo {
            pid: 9,
            ppid: None,
            path: Some(std::path::PathBuf::from("/bin/git")),
            start_time: None,
        }];
        let runner = CountingRunner::new(b"fresh");
        let auth = RecordingAuthenticator::allowing();
        s.regenerate("K", &runner, &auth, Some(&chain), &cap, &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    #[test]
    fn in_process_call_records_no_requester() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(Duration::from_secs(15));
        let auth = RecordingAuthenticator::allowing();
        // None requester == in-process / unattributed.
        s.extend_authenticated("K", &auth, None, &cap, &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester, None);
    }

    #[test]
    fn extend_authenticated_denied_leaves_entry_soft_expired() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(Duration::from_secs(15));
        let err = s
            .extend_authenticated("K", &DenyAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, ExtendAuthOutcome::AuthFailed(AuthError::Denied));
        // Still gated (unchanged).
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
    }

    #[test]
    fn extend_authenticated_missing_key() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        assert_eq!(
            s.extend_authenticated("ghost", &AllowAll, None, &cap, &clock),
            Err(ExtendAuthOutcome::NotFound)
        );
    }

    #[test]
    fn extend_authenticated_hard_expired_reports_hard_expired_without_prompt() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);
        let auth = RecordingAuthenticator::allowing();
        assert_eq!(
            s.extend_authenticated("K", &auth, None, &cap, &clock),
            Err(ExtendAuthOutcome::HardExpired)
        );
        assert_eq!(auth.call_count(), 0, "no prompt for destroyed value");
    }

    // ---- regenerate: the get -> HardExpired -> regenerate flow ----

    #[test]
    fn regenerate_command_entry_after_hard_expiry_with_auth() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);

        // Natural flow: read, observe destruction, choose to regenerate.
        clock.advance(HARD);
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));

        let runner = CountingRunner::new(b"fresh-token");
        let auth = RecordingAuthenticator::allowing();
        s.regenerate("K", &runner, &auth, None, &cap, &clock)
            .unwrap();

        assert_eq!(runner.runs(), 1);
        assert_eq!(auth.call_count(), 1);
        assert_eq!(auth.calls()[0], AuthContext::regenerate("K"));
        // Back to Active with the new value.
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"fresh-token"
        );
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
    }

    #[test]
    fn regenerate_restarts_ttl_window() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);
        let runner = CountingRunner::new(b"fresh");
        s.regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        // The soft window restarts from regeneration time.
        clock.advance(Duration::from_secs(9));
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
        clock.advance(Duration::from_secs(1));
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
    }

    #[test]
    fn regenerate_static_source_is_rejected() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        let runner = CountingRunner::new(b"x");
        let err = s
            .regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::NotRegenerable);
        assert_eq!(runner.runs(), 0, "must not run for a static source");
    }

    #[test]
    fn regenerate_not_hard_expired_is_rejected() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        // Active: nothing to regenerate.
        let runner = CountingRunner::new(b"x");
        assert_eq!(
            s.regenerate("K", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateOutcome::NotHardExpired)
        );
        assert_eq!(runner.runs(), 0);
        // Soft-expired: also rejected (value still resident; extend instead).
        clock.advance(Duration::from_secs(15));
        assert_eq!(
            s.regenerate("K", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateOutcome::NotHardExpired)
        );
        assert_eq!(runner.runs(), 0);
    }

    #[test]
    fn regenerate_missing_key() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        assert_eq!(
            s.regenerate("ghost", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateOutcome::NotFound)
        );
    }

    #[test]
    fn regenerate_auth_denied_leaves_entry_destroyed() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);
        let runner = CountingRunner::new(b"fresh");
        let err = s
            .regenerate("K", &runner, &DenyAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::AuthFailed(AuthError::Denied));
        // Command ran (fetch happens before auth), but the value was discarded.
        assert_eq!(runner.runs(), 1);
        assert!(s.get("K", &cap, &clock).unwrap().is_none());
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    #[test]
    fn regenerate_run_failure_skips_auth_and_keeps_entry_destroyed() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);
        let auth = RecordingAuthenticator::allowing();
        let err = s
            .regenerate("K", &FailingRunner, &auth, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::RunFailed(RunError::EmptyOutput));
        assert_eq!(auth.call_count(), 0, "auth must not run if fetch failed");
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    // ---- pin_authenticated / unpin (DR-0011) ----

    use crate::clock::Monotonic;

    fn deadline_secs(secs: u64) -> Monotonic {
        Monotonic::from_offset(Duration::from_secs(secs))
    }

    #[test]
    fn pin_authenticated_always_prompts_even_when_active() {
        // Unlike extend, pin demands auth from Active too (security-relaxing).
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        let auth = RecordingAuthenticator::allowing();
        s.pin_authenticated("K", deadline_secs(100), &auth, None, &cap, &clock)
            .unwrap();
        assert_eq!(auth.call_count(), 1, "pin prompts even from Active");
        assert_eq!(auth.calls()[0], AuthContext::pin("K"));
    }

    #[test]
    fn pin_authenticated_keeps_value_gettable_past_ttl() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.pin_authenticated("K", deadline_secs(1000), &AllowAll, None, &cap, &clock)
            .unwrap();
        clock.advance(Duration::from_secs(500)); // past soft and hard windows
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"v",
            "pinned value survives its TTL"
        );
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
    }

    #[test]
    fn pin_authenticated_denied_leaves_entry_unpinned() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        let err = s
            .pin_authenticated("K", deadline_secs(1000), &DenyAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, PinAuthOutcome::AuthFailed(AuthError::Denied));
        assert_eq!(s.pin_deadline_of("K"), None, "denied pin must not apply");
    }

    #[test]
    fn pin_authenticated_missing_key() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        assert_eq!(
            s.pin_authenticated("ghost", deadline_secs(100), &AllowAll, None, &cap, &clock),
            Err(PinAuthOutcome::NotFound)
        );
    }

    #[test]
    fn pin_authenticated_hard_expired_is_rejected_without_prompt() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD); // hard-expired
        let auth = RecordingAuthenticator::allowing();
        assert_eq!(
            s.pin_authenticated("K", deadline_secs(1000), &auth, None, &cap, &clock),
            Err(PinAuthOutcome::HardExpired)
        );
        assert_eq!(auth.call_count(), 0, "no prompt for a destroyed value");
    }

    #[test]
    fn pin_authenticated_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        let chain = vec![ProcessInfo {
            pid: 11,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/usr/bin/ssh")),
            start_time: None,
        }];
        let auth = RecordingAuthenticator::allowing();
        s.pin_authenticated("K", deadline_secs(100), &auth, Some(&chain), &cap, &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    #[test]
    fn re_pin_overwrites_deadline_via_store() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.pin_authenticated("K", deadline_secs(20), &AllowAll, None, &cap, &clock)
            .unwrap();
        s.pin_authenticated("K", deadline_secs(1000), &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(s.pin_deadline_of("K"), Some(deadline_secs(1000)));
    }

    #[test]
    fn unpin_returns_entry_to_normal_evaluation() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.pin_authenticated("K", deadline_secs(1000), &AllowAll, None, &cap, &clock)
            .unwrap();
        clock.advance(Duration::from_secs(15)); // past soft
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active), "pinned");
        assert!(s.unpin("K", &cap).unwrap());
        assert_eq!(s.pin_deadline_of("K"), None);
        assert_eq!(
            s.state_of("K", &clock),
            Some(EntryState::SoftExpired),
            "after unpin the soft window applies again"
        );
    }

    #[test]
    fn unpin_missing_key_is_false() {
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        assert!(!s.unpin("ghost", &cap).unwrap());
    }

    // ---- definition registry (DR-0014) ----

    fn cmd_source() -> ValueSource {
        ValueSource::command(["op".into(), "read".into(), "op://v/i/f".into()])
    }

    #[test]
    fn define_registers_without_producing_a_value() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(s.is_defined("K"));
        assert!(!s.has_value("K"), "define must not produce a value");
        assert_eq!(s.len(), 0, "no value entry yet");
        assert_eq!(s.definition_of("K").unwrap().source(), &cmd_source());
    }

    #[test]
    fn define_is_idempotent_for_exact_match() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(s.is_defined("K"));
    }

    #[test]
    fn define_conflicting_argv_is_rejected() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let other = ValueSource::command(["op".into(), "read".into(), "op://other".into()]);
        assert_eq!(s.define("K", other, ttl()), Err(DefineError::Conflict));
        assert_eq!(s.definition_of("K").unwrap().source(), &cmd_source());
    }

    #[test]
    fn define_conflicting_ttl_is_rejected() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let other_ttl = Ttl::new(Some(Duration::from_secs(5)), Some(HARD)).unwrap();
        assert_eq!(
            s.define("K", cmd_source(), other_ttl),
            Err(DefineError::Conflict)
        );
    }

    #[test]
    fn define_rejects_static_source() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        assert_eq!(
            s.define("K", ValueSource::Static, ttl()),
            Err(DefineError::StaticNotDefinable)
        );
        assert!(!s.is_defined("K"));
    }

    #[test]
    fn get_or_regenerate_lazily_produces_for_a_definition_only_key() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(
            s.get("K", &cap, &clock).unwrap().is_none(),
            "no value before lazy gen"
        );

        let runner = CountingRunner::new(b"lazy-token");
        let auth = RecordingAuthenticator::allowing();
        s.get_or_regenerate("K", &runner, &auth, None, &cap, &clock)
            .unwrap();

        assert_eq!(runner.runs(), 1);
        assert_eq!(auth.call_count(), 1);
        assert_eq!(auth.calls()[0], AuthContext::regenerate("K"));
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"lazy-token"
        );
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
    }

    #[test]
    fn get_or_regenerate_resets_loaded_at_for_a_fresh_hard_window() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        clock.advance(Duration::from_secs(100));
        let runner = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
        clock.advance(HARD);
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    #[test]
    fn get_or_regenerate_undefined_key_is_rejected() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        let runner = CountingRunner::new(b"x");
        assert_eq!(
            s.get_or_regenerate("ghost", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateDefOutcome::Undefined)
        );
        assert_eq!(runner.runs(), 0);
    }

    #[test]
    fn get_or_regenerate_skips_when_value_is_active() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"first");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(runner.runs(), 1);
        assert_eq!(
            s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateDefOutcome::ValueResident)
        );
        assert_eq!(runner.runs(), 1, "must not re-run for a resident value");
    }

    #[test]
    fn get_or_regenerate_skips_when_value_is_soft_expired() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        clock.advance(Duration::from_secs(15)); // SoftExpired
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
        assert_eq!(
            s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateDefOutcome::ValueResident)
        );
        assert_eq!(runner.runs(), 1);
    }

    #[test]
    fn get_or_regenerate_reproduces_after_hard_expiry() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        clock.advance(HARD);
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(runner.runs(), 2);
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"v"
        );
    }

    #[test]
    fn get_or_regenerate_run_failure_skips_auth_and_leaves_value_absent() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let auth = RecordingAuthenticator::allowing();
        let err = s
            .get_or_regenerate("K", &FailingRunner, &auth, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateDefOutcome::RunFailed(RunError::EmptyOutput));
        assert_eq!(auth.call_count(), 0, "auth must not run if fetch failed");
        assert!(!s.has_value("K"), "value stays absent");
        assert!(s.is_defined("K"), "definition survives a failed run");
    }

    #[test]
    fn get_or_regenerate_auth_denied_discards_value() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"fresh");
        let err = s
            .get_or_regenerate("K", &runner, &DenyAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateDefOutcome::AuthFailed(AuthError::Denied));
        assert_eq!(runner.runs(), 1, "fetch happens before auth");
        assert!(!s.has_value("K"), "denied value is discarded, not stored");
    }

    #[test]
    fn get_or_regenerate_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        let chain = vec![ProcessInfo {
            pid: 13,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/bin/git")),
            start_time: None,
        }];
        let auth = RecordingAuthenticator::allowing();
        s.get_or_regenerate(
            "K",
            &CountingRunner::new(b"v"),
            &auth,
            Some(&chain),
            &cap,
            &clock,
        )
        .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    // ---- opaque value-type metadata lives on the definition (DR-0016) ----

    fn otp_meta() -> ValueMeta {
        ValueMeta::with_type(
            "otp",
            [
                ("digits".to_string(), "6".to_string()),
                ("period".to_string(), "30".to_string()),
            ],
        )
    }

    #[test]
    fn definition_carries_the_type_metadata() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define_with_meta("OTP", cmd_source(), ttl(), otp_meta(), SourceMeta::new())
            .unwrap();
        assert_eq!(s.definition_of("OTP").unwrap().meta(), &otp_meta());
        assert_eq!(
            s.definition_of("OTP").unwrap().meta().type_label(),
            Some("otp")
        );
        assert_eq!(
            s.definition_of("OTP").unwrap().meta().param("digits"),
            Some("6")
        );
    }

    #[test]
    fn lazily_produced_value_keeps_its_type_on_the_definition() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define_with_meta("K", cmd_source(), ttl(), otp_meta(), SourceMeta::new())
            .unwrap();
        let runner = CountingRunner::new(b"seed-bytes");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert!(s.has_value("K"));
        assert_eq!(
            s.definition_of("K").unwrap().meta(),
            &otp_meta(),
            "type still read from the definition after production"
        );
    }

    #[test]
    fn regenerated_value_type_still_read_from_definition() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define_with_meta("K", cmd_source(), ttl(), otp_meta(), SourceMeta::new())
            .unwrap();
        s.get_or_regenerate(
            "K",
            &CountingRunner::new(b"orig"),
            &AllowAll,
            None,
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        s.get_or_regenerate(
            "K",
            &CountingRunner::new(b"fresh"),
            &AllowAll,
            None,
            &cap,
            &clock,
        )
        .unwrap();
        assert_eq!(
            s.definition_of("K").unwrap().meta(),
            &otp_meta(),
            "type survives regenerate (it lives on the definition)"
        );
    }

    #[test]
    fn define_meta_participates_in_idempotency_conflict() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define_with_meta("K", cmd_source(), ttl(), otp_meta(), SourceMeta::new())
            .unwrap();
        s.define_with_meta("K", cmd_source(), ttl(), otp_meta(), SourceMeta::new())
            .unwrap();
        assert_eq!(
            s.define("K", cmd_source(), ttl()),
            Err(DefineError::Conflict)
        );
    }

    // ---- delete: value-only vs value+definition (DR-0014 §2) ----

    #[test]
    fn delete_drops_value_but_keeps_definition() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        s.get_or_regenerate(
            "K",
            &CountingRunner::new(b"v"),
            &AllowAll,
            None,
            &cap,
            &clock,
        )
        .unwrap();
        assert!(s.has_value("K"));

        assert!(s.delete("K", &cap).unwrap(), "value removed");
        assert!(!s.has_value("K"), "value gone");
        assert!(s.is_defined("K"), "definition survives a value-only delete");

        let runner = CountingRunner::new(b"again");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"again"
        );
    }

    #[test]
    fn delete_with_definition_forgets_the_key_entirely() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        s.get_or_regenerate(
            "K",
            &CountingRunner::new(b"v"),
            &AllowAll,
            None,
            &cap,
            &clock,
        )
        .unwrap();

        assert!(s.delete_with_definition("K", &cap).unwrap());
        assert!(!s.has_value("K"));
        assert!(!s.is_defined("K"), "definition removed too");
        assert_eq!(
            s.get_or_regenerate(
                "K",
                &CountingRunner::new(b"x"),
                &AllowAll,
                None,
                &cap,
                &clock
            ),
            Err(RegenerateDefOutcome::Undefined)
        );
    }

    #[test]
    fn delete_with_definition_works_on_definition_only_key() {
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(!s.has_value("K"));
        assert!(
            s.delete_with_definition("K", &cap).unwrap(),
            "removes a definition-only key"
        );
        assert!(!s.is_defined("K"));
    }

    #[test]
    fn delete_with_definition_absent_key_is_false() {
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        assert!(!s.delete_with_definition("ghost", &cap).unwrap());
    }

    #[test]
    fn plain_delete_of_static_entry_is_unchanged() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "S",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        assert!(s.delete("S", &cap).unwrap());
        assert!(!s.has_value("S"));
        assert!(!s.is_defined("S"));
        assert!(s.get("S", &cap, &clock).unwrap().is_none());
    }

    // ---- enumeration: definition-only keys are listed (DR-0014 §5) ----

    #[test]
    fn keys_unions_values_and_definitions() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "val",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.define("def", cmd_source(), ttl()).unwrap();
        s.define("both", cmd_source(), ttl()).unwrap();
        s.get_or_regenerate(
            "both",
            &CountingRunner::new(b"v"),
            &AllowAll,
            None,
            &cap,
            &clock,
        )
        .unwrap();

        #[allow(deprecated)]
        let list_result = s.list();
        #[allow(deprecated)]
        let keys_result = s.keys();
        assert_eq!(list_result, vec!["both", "val"]);
        assert_eq!(keys_result, vec!["both", "def", "val"]);
    }

    #[test]
    fn definition_only_key_reports_metadata_without_a_value() {
        let (mut s, _cap) = crate::test_helpers::store_with_cap();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(s.is_defined("K"));
        assert!(!s.has_value("K"));
        assert_eq!(
            s.state_of("K", &FakeClock::new()),
            None,
            "no value -> no state"
        );
        assert!(s.definition_of("K").unwrap().source().is_regenerable());
    }

    // ---- static value + definition coexistence (DR-0014 §2 design call) ----

    #[test]
    fn defining_a_key_with_a_resident_static_value_is_independent() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("static-val"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"static-val"
        );
        let runner = CountingRunner::new(b"regenerated");
        assert_eq!(
            s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock),
            Err(RegenerateDefOutcome::ValueResident)
        );
        assert_eq!(runner.runs(), 0);
        clock.advance(HARD);
        s.get_or_regenerate("K", &runner, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(runner.runs(), 1);
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"regenerated"
        );
    }

    // ---- fetch failure backoff (DR-0022 A-3b) ----

    const BACKOFF: Duration = Duration::from_secs(5);

    /// 1. failure_backoff_duration = 0 のとき従来通り RunFailed が返る (backoff 機能なし)
    #[test]
    fn backoff_zero_duration_gives_run_failed_regression() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap(); // default = zero backoff
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);
        let auth = RecordingAuthenticator::allowing();
        let err = s
            .regenerate("K", &FailingRunner, &auth, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::RunFailed(RunError::EmptyOutput));
        assert_eq!(auth.call_count(), 0);
    }

    /// 2. fake op exit 1 直後 (clock 進めず) の regenerate は Backoff を返し、
    ///    fake op は再実行されない
    #[test]
    fn backoff_active_after_first_failure_blocks_rerun() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);

        let err = s
            .regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::RunFailed(RunError::EmptyOutput));

        let counting = CountingRunner::new(b"v");
        let err2 = s
            .regenerate("K", &counting, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        match err2 {
            RegenerateOutcome::Backoff { retry_after } => {
                assert!(
                    retry_after > Duration::ZERO,
                    "retry_after should be positive"
                );
                assert!(
                    retry_after <= BACKOFF,
                    "retry_after should not exceed backoff period"
                );
            }
            other => panic!("expected Backoff, got {other:?}"),
        }
        assert_eq!(
            counting.runs(),
            0,
            "runner must NOT be called during backoff"
        );
    }

    /// 3. backoff 期間経過後に再呼び出すと fake op が再実行される
    #[test]
    fn backoff_expires_after_duration_allows_rerun() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);

        let _ = s.regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);
        clock.advance(BACKOFF + Duration::from_millis(1));

        let counting = CountingRunner::new(b"fresh");
        s.regenerate("K", &counting, &AllowAll, None, &cap, &clock)
            .unwrap();
        assert_eq!(
            counting.runs(),
            1,
            "runner must be called after backoff expires"
        );
        assert_eq!(
            s.get("K", &cap, &clock).unwrap().unwrap().expose_secret(),
            b"fresh"
        );
    }

    /// 4. backoff 中に store.set を直接呼び出しても failure_backoffs は残る
    #[test]
    fn store_set_does_not_clear_failure_backoffs() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);

        let _ = s.regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);

        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("injected"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        let remaining = s.failure_backoff_remaining("K", &clock);
        assert!(
            remaining.is_some(),
            "failure_backoffs must survive a store.set"
        );
    }

    /// 5. failure_backoff_duration = 0s で従来動作 (= backoff 機能なし)
    #[test]
    fn set_failure_backoff_zero_disables_feature() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap(); // default = zero backoff
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);

        let err = s
            .regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::RunFailed(RunError::EmptyOutput));

        let err2 = s
            .regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        match err2 {
            RegenerateOutcome::Backoff { .. } => {
                panic!("Backoff must not be returned when failure_backoff_duration = 0")
            }
            RegenerateOutcome::RunFailed(_) => {}
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    /// 6. 同一 key に対する 2 回の連続 regenerate で 1 個目が失敗した後、2 個目は backoff を返す
    #[test]
    fn sequential_regenerate_second_sees_backoff_after_first_fails() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        cmd_entry(&mut s, "K", &cap, &clock);
        clock.advance(HARD);

        let _ = s.regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);

        let counting = CountingRunner::new(b"v");
        let err2 = s
            .regenerate("K", &counting, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert!(
            matches!(err2, RegenerateOutcome::Backoff { .. }),
            "second call must see backoff, got {err2:?}"
        );
        assert_eq!(counting.runs(), 0);
    }

    /// 7. get_or_regenerate (lazy 経路) でも Backoff が返る
    #[test]
    fn get_or_regenerate_returns_backoff_after_failure() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        s.define("K", cmd_source(), ttl()).unwrap();

        let err = s
            .get_or_regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateDefOutcome::RunFailed(RunError::EmptyOutput));

        let counting = CountingRunner::new(b"v");
        let err2 = s
            .get_or_regenerate("K", &counting, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert!(
            matches!(err2, RegenerateDefOutcome::Backoff { .. }),
            "lazy path must also return Backoff, got {err2:?}"
        );
        assert_eq!(counting.runs(), 0);
    }

    /// 8a. kv.del --with-define (delete_with_definition) で failure_backoffs も消える
    #[test]
    fn delete_with_definition_clears_failure_backoffs() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        s.define("K", cmd_source(), ttl()).unwrap();

        let _ = s.get_or_regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);

        assert!(s.delete_with_definition("K", &cap).unwrap());
        assert!(!s.is_defined("K"));

        let remaining = s.failure_backoff_remaining("K", &clock);
        assert!(
            remaining.is_none(),
            "failure_backoffs must be cleared by delete_with_definition"
        );
    }

    /// 8b. kv.del (値のみ削除) では failure_backoffs は残る
    #[test]
    fn value_only_delete_keeps_failure_backoffs() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        s.define("K", cmd_source(), ttl()).unwrap();

        let _ = s.get_or_regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);

        s.delete("K", &cap).unwrap();
        assert!(!s.has_value("K"), "value removed");
        assert!(s.is_defined("K"), "definition survives");

        let remaining = s.failure_backoff_remaining("K", &clock);
        assert!(
            remaining.is_some(),
            "failure_backoffs must survive a value-only delete"
        );
    }

    /// 8c. hard-ttl 切れで entry drop しても failure_backoffs は残る
    #[test]
    fn hard_expiry_drop_keeps_failure_backoffs() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        s.define("K", cmd_source(), ttl()).unwrap();

        let counting = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &counting, &AllowAll, None, &cap, &clock)
            .unwrap();

        clock.advance(HARD);
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
        let _ = s.get_or_regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);

        assert!(s.failure_backoff_remaining("K", &clock).is_some());

        let counting2 = CountingRunner::new(b"v2");
        let err = s
            .get_or_regenerate("K", &counting2, &AllowAll, None, &cap, &clock)
            .unwrap_err();
        assert!(
            matches!(err, RegenerateDefOutcome::Backoff { .. }),
            "backoff must survive hard-expiry drop, got {err:?}"
        );
        assert_eq!(counting2.runs(), 0);
    }

    // ---- capability gate (DR-0024) ----

    #[test]
    fn set_with_wrong_cap_returns_cap_mismatch() {
        let clock = FakeClock::new();
        let (mut store, _cap) = crate::test_helpers::store_with_cap();
        let wrong_bundle = StoreBuilder::new().build();
        let wrong_cap = wrong_bundle.control_cap;
        let err = store
            .set(
                "K",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &wrong_cap,
                &clock,
            )
            .unwrap_err();
        // Cap check runs before key syntax (DR-0024): a valid key + wrong cap is
        // a CapMismatch, and the store is untouched.
        assert_eq!(err, SetError::CapMismatch);
        assert!(
            !store.has_value("K"),
            "set must not mutate store on cap mismatch"
        );
    }

    // ---- composed-key syntax gate (DR-0017 §1.5, enforced in the core) ----

    #[test]
    fn set_rejects_a_syntactically_invalid_key() {
        // The core write gate refuses a key outside the composed-key grammar
        // (here the `:`-bearing pseudo-prefix the old `__authsock_op:` path used).
        // The store must be left untouched — a bad key never becomes an entry.
        let clock = FakeClock::new();
        let (mut store, cap) = crate::test_helpers::store_with_cap();
        let err = store
            .set(
                "__authsock_op:itemABC",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap_err();
        match err {
            SetError::InvalidKey(e) => assert_eq!(e.key(), "__authsock_op:itemABC"),
            other => panic!("expected InvalidKey, got {other:?}"),
        }
        assert!(!store.has_value("__authsock_op:itemABC"));
    }

    #[test]
    fn set_accepts_bare_and_namespaced_keys() {
        // Both a bare KEY and a composed NS/KEY are valid store keys (the core is
        // a generic KV; the daemon composes NS/KEY on top).
        let clock = FakeClock::new();
        let (mut store, cap) = crate::test_helpers::store_with_cap();
        for key in ["K", "default/K", "authsock/op_itemABC"] {
            store
                .set(
                    key,
                    ValueSource::Static,
                    SecretBytes::from("v"),
                    ttl(),
                    &cap,
                    &clock,
                )
                .unwrap_or_else(|e| panic!("{key:?} must be accepted: {e}"));
            assert!(store.has_value(key));
        }
    }

    #[test]
    fn define_rejects_a_syntactically_invalid_key() {
        // The definition registry shares the same core key gate: an adapter
        // calling `define` directly (the actual bypass this closes) cannot slip a
        // malformed key past it either.
        let (mut store, _cap) = crate::test_helpers::store_with_cap();
        let err = store
            .define(
                "__authsock_op:itemABC",
                ValueSource::command(["echo".into(), "x".into()]),
                ttl(),
            )
            .unwrap_err();
        match err {
            DefineError::InvalidKey(e) => assert_eq!(e.key(), "__authsock_op:itemABC"),
            other => panic!("expected InvalidKey, got {other:?}"),
        }
        assert!(!store.is_defined("__authsock_op:itemABC"));
    }

    #[test]
    fn define_accepts_a_namespaced_key() {
        // The composed form the authsock adapter now uses for op keys.
        let (mut store, _cap) = crate::test_helpers::store_with_cap();
        store
            .define(
                "authsock/op_itemABC",
                ValueSource::command(["op".into(), "read".into(), "op://v/i/f".into()]),
                ttl(),
            )
            .expect("a valid composed key must be definable");
        assert!(store.is_defined("authsock/op_itemABC"));
    }

    #[test]
    fn get_with_wrong_cap_returns_keymismatch() {
        let clock = FakeClock::new();
        let (mut store, cap) = crate::test_helpers::store_with_cap();
        store
            .set(
                "K",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
        let wrong_bundle = StoreBuilder::new().build();
        let wrong_cap = wrong_bundle.control_cap;
        let err = store.get("K", &wrong_cap, &clock).unwrap_err();
        assert_eq!(err, CapError::KeyMismatch);
    }

    #[test]
    fn cap_mismatch_does_not_touch_backoff_or_runner() {
        let clock = FakeClock::new();
        let (mut store, cap) = crate::test_helpers::store_with_cap();
        store
            .set(
                "K",
                ValueSource::command(["echo".into(), "v".into()]),
                SecretBytes::from("orig"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
        clock.advance(HARD);
        let wrong_bundle = StoreBuilder::new().build();
        let wrong_cap = wrong_bundle.control_cap;
        let runner = CountingRunner::new(b"fresh");
        let err = store
            .regenerate("K", &runner, &AllowAll, None, &wrong_cap, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateOutcome::CapMismatch);
        assert_eq!(runner.runs(), 0, "runner must not run on cap mismatch");
        assert!(store.failure_backoff_remaining("K", &clock).is_none());
    }

    #[test]
    fn cap_check_runs_before_backoff_check() {
        let clock = FakeClock::new();
        let (mut store, cap) = crate::test_helpers::store_with_cap_and_backoff(BACKOFF);
        store
            .set(
                "K",
                ValueSource::command(["echo".into(), "v".into()]),
                SecretBytes::from("orig"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
        clock.advance(HARD);
        let _ = store.regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);
        assert!(
            store.failure_backoff_remaining("K", &clock).is_some(),
            "backoff must be active"
        );
        let wrong_bundle = StoreBuilder::new().build();
        let wrong_cap = wrong_bundle.control_cap;
        let err = store
            .regenerate(
                "K",
                &CountingRunner::new(b"x"),
                &AllowAll,
                None,
                &wrong_cap,
                &clock,
            )
            .unwrap_err();
        assert_eq!(
            err,
            RegenerateOutcome::CapMismatch,
            "cap check must run before backoff check"
        );
    }

    // ---- list_filtered / ItemRef (DR-0025) ----

    #[test]
    fn list_filtered_true_matches_keys() {
        // list_filtered(|_| true) must return the same set as the deprecated keys().
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        // value only
        s.set(
            "value_only",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        // definition only (command source required)
        s.define("def_only", ValueSource::command(["echo".into()]), ttl())
            .unwrap();
        // both: a key can appear in both entries and definitions simultaneously.
        // set() inserts into entries, define() inserts into definitions — separate maps.
        s.define("both_key", ValueSource::command(["echo".into()]), ttl())
            .unwrap();
        s.set(
            "both_key",
            ValueSource::command(["echo".into()]),
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();

        #[allow(deprecated)]
        let expected = s.keys();
        let actual = s.list_filtered(|_| true);
        assert_eq!(actual, expected);
    }

    #[test]
    fn list_filtered_entry_matches_list() {
        // list_filtered(|r| r.entry().is_some()) must match the deprecated list().
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "a",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.set(
            "b",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.define("def_only", ValueSource::command(["echo".into()]), ttl())
            .unwrap();

        #[allow(deprecated)]
        let expected = s.list();
        let actual = s.list_filtered(|r| r.entry().is_some());
        assert_eq!(actual, expected);
    }

    #[test]
    fn list_filtered_empty_store_returns_empty() {
        let (s, _cap) = crate::test_helpers::store_with_cap();
        let result = s.list_filtered(|_| true);
        assert!(result.is_empty());
    }

    #[test]
    fn list_filtered_false_returns_empty() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "a",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        let result = s.list_filtered(|_| false);
        assert!(result.is_empty());
    }

    #[test]
    fn list_filtered_definition_only_filter() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "value_only",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.define("def_only", ValueSource::command(["echo".into()]), ttl())
            .unwrap();

        let result = s.list_filtered(|r| r.definition().is_some());
        assert_eq!(result, vec!["def_only"]);
    }

    #[test]
    fn list_filtered_failure_filter() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(Duration::from_secs(60));
        // Insert a value then expire it so regenerate can run.
        s.set(
            "K",
            ValueSource::command(["echo".into()]),
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        let _ = s.regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);
        // Now K has a failure record.
        let result = s.list_filtered(|r| r.failure().is_some());
        assert_eq!(result, vec!["K"]);
        // A key without failure should not appear.
        s.set(
            "clean",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        let result2 = s.list_filtered(|r| r.failure().is_some());
        assert_eq!(result2, vec!["K"]);
    }

    #[test]
    fn item_ref_state_is_pure_read_no_zeroize() {
        // DR-0025: ItemRef::state uses CacheEntry::state (pure read), not evaluate.
        // After hard expiry, the entry's value is still in entries map (not zeroized)
        // because ItemRef::state does not call evaluate/zeroize.
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("secret"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);

        // Access via list_filtered with state — pure read, no zeroize.
        let states: Vec<_> = s.list_filtered(|r| {
            // Inside the callback the value entry must still be present
            // (not zeroized), since ItemRef::state is pure read.
            assert!(r.entry().is_some(), "entry must be present before zeroize");
            r.state(&clock)
                .map(|st| st == EntryState::HardExpired)
                .unwrap_or(false)
        });
        assert_eq!(states, vec!["K"]);

        // The entry must still be there (not zeroized by the filter above).
        assert!(
            s.entries.contains_key("K"),
            "entry still present after pure-read filter"
        );
    }

    #[test]
    fn item_ref_value_meta_from_definition() {
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        let meta = ValueMeta::with_type("otp".to_string(), Vec::<(String, String)>::new());
        s.define_with_meta(
            "typed_key",
            ValueSource::command(["echo".into()]),
            ttl(),
            meta.clone(),
            crate::meta::SourceMeta::new(),
        )
        .unwrap();
        // Undefined key: value_meta returns None.
        s.set(
            "plain",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();

        let found_typed = s.list_filtered(|r| {
            r.value_meta()
                .and_then(|m| m.type_label())
                .map(|t| t == "otp")
                .unwrap_or(false)
        });
        assert_eq!(found_typed, vec!["typed_key"]);

        let found_plain = s.list_filtered(|r| r.value_meta().is_none());
        assert_eq!(found_plain, vec!["plain"]);
    }

    #[test]
    fn item_ref_failure_remaining_with_clock() {
        let clock = FakeClock::new();
        let backoff = Duration::from_secs(60);
        let (mut s, cap) = crate::test_helpers::store_with_cap_and_backoff(backoff);
        s.set(
            "K",
            ValueSource::command(["echo".into()]),
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        clock.advance(HARD);
        let _ = s.regenerate("K", &FailingRunner, &AllowAll, None, &cap, &clock);

        // failure_remaining via ItemRef should match failure_backoff_remaining.
        let expected_remaining = s.failure_backoff_remaining("K", &clock);
        let item_remaining = s.list_filtered(|r| r.failure_remaining(&clock).is_some());
        assert_eq!(item_remaining, vec!["K"]);
        // Check the actual remaining value matches.
        let via_filter: Vec<_> =
            s.list_filtered(|r| r.failure_remaining(&clock) == expected_remaining);
        assert_eq!(via_filter, vec!["K"]);
    }

    #[test]
    fn list_filtered_sorted_and_deduped() {
        // Keys that appear in both entries and definitions should not be duplicated.
        let clock = FakeClock::new();
        let (mut s, cap) = crate::test_helpers::store_with_cap();
        // "shared" appears in both maps.
        s.define("shared", ValueSource::command(["echo".into()]), ttl())
            .unwrap();
        // Produce a value (would need get_or_regenerate, but just set for simplicity):
        // Actually, we can't set a value AND keep the definition since define requires command.
        // We can set a command-sourced value directly using set().
        s.set(
            "shared",
            ValueSource::command(["echo".into()]),
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.set(
            "z",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &cap,
            &clock,
        )
        .unwrap();
        s.define("a", ValueSource::command(["echo".into()]), ttl())
            .unwrap();

        let result = s.list_filtered(|_| true);
        // "shared" appears in both entries and definitions, must be deduped.
        // Order: sorted alphabetically.
        assert_eq!(result, vec!["a", "shared", "z"]);
    }

    // ---- DR-0029 §2 graceful-restart snapshot (export_snapshot / import_snapshot) ----

    mod snapshot_tests {
        use super::*;

        /// Build a store exercising the three DR-0029-mandated snapshot shapes
        /// in one go: a plain static value ("STATIC"), a definition whose
        /// value was lazily regenerated via a mock command
        /// ("DEFINED", `CountingRunner`), and a key that is *both* pinned
        /// *and* carries an active fetch-failure backoff record ("PINNED").
        ///
        /// The pin+backoff combination on one key needs a specific sequence,
        /// since the two are individually exclusive with the states each
        /// other's setup passes through:
        /// [`Store::pin_authenticated`] refuses a hard-expired entry, and
        /// [`Store::regenerate`] only records a backoff for a *hard-expired*
        /// command-source entry that fails to regenerate. So: give "PINNED" a
        /// command-source value, hard-expire it, fail a `regenerate` (records
        /// the backoff, leaves the entry hard-expired with no value), then
        /// `set` a fresh value (this does **not** clear `failure_backoffs` —
        /// DR-0022 — so the record survives) and only *then* pin it.
        ///
        /// Returns the store, its control capability, and the clock driving
        /// it (so the caller can advance time further before exporting).
        fn three_shape_store() -> (Store, Capability, FakeClock) {
            let clock = FakeClock::new();
            let (mut s, cap) =
                crate::test_helpers::store_with_cap_and_backoff(Duration::from_secs(60));
            // STATIC and DEFINED use a TTL that never hard-expires: shape 3's
            // setup below deliberately advances the shared clock past the
            // short `ttl()` hard window (to hard-expire "PINNED" for its own
            // regenerate-failure flow), which would otherwise also destroy
            // STATIC/DEFINED's values before export — an artifact of sharing
            // one clock across all three shapes, not something this test is
            // trying to exercise.
            let durable_ttl = Ttl::never();

            // Shape 1: a plain static value.
            s.set(
                "STATIC",
                ValueSource::Static,
                SecretBytes::from("static-secret"),
                durable_ttl,
                &cap,
                &clock,
            )
            .unwrap();

            // Shape 2: a definition, lazily produced via a mock command runner
            // (DR-0014 get_or_regenerate path), so both `entries` and
            // `definitions` carry this key.
            s.define(
                "DEFINED",
                ValueSource::command(["op".into(), "read".into()]),
                durable_ttl,
            )
            .unwrap();
            let runner = CountingRunner::new(b"regenerated-secret");
            s.get_or_regenerate("DEFINED", &runner, &AllowAll, None, &cap, &clock)
                .unwrap();
            assert_eq!(runner.runs(), 1, "test setup: DEFINED must be produced");

            // Shape 3: pinned + an active backoff record on the same key.
            s.set(
                "PINNED",
                ValueSource::command(["will-fail".into()]),
                SecretBytes::from("v0"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            clock.advance(HARD); // hard-expire it
            let err = s
                .regenerate("PINNED", &FailingRunner, &AllowAll, None, &cap, &clock)
                .unwrap_err();
            assert_eq!(err, RegenerateOutcome::RunFailed(RunError::EmptyOutput));
            assert!(
                s.failure_backoff_remaining("PINNED", &clock).is_some(),
                "test setup: the failed regenerate must record a backoff"
            );
            // Re-set a fresh value (does not clear failure_backoffs, DR-0022),
            // then pin it — now possible since the entry is Active again.
            s.set(
                "PINNED",
                ValueSource::command(["will-fail".into()]),
                SecretBytes::from("pinned-secret"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            s.pin_authenticated(
                "PINNED",
                clock.now().saturating_add(Duration::from_secs(10_000)),
                &AllowAll,
                None,
                &cap,
                &clock,
            )
            .unwrap();
            assert!(
                s.failure_backoff_remaining("PINNED", &clock).is_some(),
                "test setup: backoff record must survive the re-set + pin"
            );

            (s, cap, clock)
        }

        #[test]
        fn roundtrip_preserves_values_definitions_and_meta_across_all_three_shapes() {
            let (s, cap, clock) = three_shape_store();
            let expected_pin_deadline = s.pin_deadline_of("PINNED");
            assert!(
                expected_pin_deadline.is_some(),
                "test setup: PINNED must be pinned"
            );
            let expected_backoff_remaining = s.failure_backoff_remaining("PINNED", &clock);

            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert_eq!(snap.len(), 3, "STATIC, DEFINED, PINNED");

            // Import into a brand-new store, using the *same* clock instance
            // (simulating no elapsed time) so this test isolates data-fidelity
            // from the separate time-re-anchoring concern (covered below and
            // in clock.rs).
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            let mut s2 = bundle.store;
            let cap2 = bundle.control_cap;

            // Shape 1: static value, byte-for-byte via with_exposed (DR-0028).
            let v = s2.get("STATIC", &cap2, &clock).unwrap().unwrap();
            v.with_exposed(|b| assert_eq!(b, b"static-secret"));
            assert_eq!(s2.source_of("STATIC"), Some(&ValueSource::Static));

            // Shape 2: definition + its produced value both survive, and the
            // definition is still regenerable (command source preserved).
            let v = s2.get("DEFINED", &cap2, &clock).unwrap().unwrap();
            v.with_exposed(|b| assert_eq!(b, b"regenerated-secret"));
            assert_eq!(
                s2.definition_of("DEFINED").map(Definition::source),
                Some(&ValueSource::command(["op".into(), "read".into()]))
            );

            // Shape 3: pin deadline and the active backoff record both survive.
            // Same clock instance for export and import (see the comment
            // above), so the reconstructed values must match *exactly*, not
            // just approximately.
            let v = s2.get("PINNED", &cap2, &clock).unwrap().unwrap();
            v.with_exposed(|b| assert_eq!(b, b"pinned-secret"));
            assert_eq!(s2.pin_deadline_of("PINNED"), expected_pin_deadline);
            assert_eq!(
                s2.failure_backoff_remaining("PINNED", &clock),
                expected_backoff_remaining,
                "PINNED's failure backoff record must survive the round trip"
            );
            // PINNED was built via set()/regenerate() directly (not
            // define()/get_or_regenerate()), so it legitimately has no
            // definition — this shape's distinguishing feature is pin +
            // backoff, not a definition.
            assert_eq!(s2.definition_of("PINNED"), None);
        }

        #[test]
        fn roundtrip_preserves_value_meta_and_source_meta() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.define_with_meta(
                "OTP",
                ValueSource::command(["op".into(), "read".into()]),
                ttl(),
                ValueMeta::with_type("otp", [("digits".to_string(), "6".to_string())]),
                SourceMeta::with_kind("op", [("uri".to_string(), "op://v/i/f".to_string())]),
            )
            .unwrap();
            let runner = CountingRunner::new(b"123456");
            s.get_or_regenerate("OTP", &runner, &AllowAll, None, &cap, &clock)
                .unwrap();

            let snap = s.export_snapshot(&cap, &clock).unwrap();
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            let s2 = bundle.store;

            let def = s2.definition_of("OTP").unwrap();
            assert_eq!(def.meta().type_label(), Some("otp"));
            assert_eq!(def.meta().param("digits"), Some("6"));
            assert_eq!(def.source_meta().kind(), Some("op"));
            assert_eq!(def.source_meta().field("uri"), Some("op://v/i/f"));
        }

        #[test]
        fn export_skips_a_key_with_no_value_definition_or_failure() {
            // delete() removes only the value; with no definition and no
            // failure record either, the key contributes nothing to export
            // once fully gone.
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "GONE",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            s.delete("GONE", &cap).unwrap();

            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert!(snap.is_empty());
        }

        #[test]
        fn export_skips_a_logically_hard_expired_value_even_if_not_yet_zeroized() {
            // export_snapshot only borrows &self, so it cannot trigger the
            // zeroize side effect itself — but it must still refuse to
            // export plaintext that is logically destroyed.
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "EXPIRED",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            clock.advance(HARD);
            // No get()/state_of() call here: the physical zeroize has not run.

            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert!(
                snap.is_empty(),
                "a logically hard-expired value must not be exported"
            );
        }

        #[test]
        fn export_rejects_a_capability_mismatch_before_reading_anything() {
            let clock = FakeClock::new();
            let (s, _cap) = crate::test_helpers::store_with_cap();
            let (_other_store, other_cap) = crate::test_helpers::store_with_cap();
            assert!(matches!(
                s.export_snapshot(&other_cap, &clock),
                Err(ExportError::CapMismatch)
            ));
        }

        #[test]
        fn time_reanchor_preserves_relative_load_order_across_a_process_boundary() {
            // Two independent clocks stand in for two processes: the "old"
            // clock the entries were loaded against, and a "new" clock (with
            // enough headroom — see epoch_ms_to_monotonic's doc) the importer
            // uses. loaded_at ordering between two keys must survive even
            // though the two clocks' Monotonic numbering is unrelated.
            let old_clock =
                FakeClock::starting_at(Monotonic::from_offset(Duration::from_secs(50_000)));
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            // A long (2h) hard TTL and no soft TTL, so the 1h gap between the
            // two loads below neither hard-expires OLDER before export nor
            // lets soft-expiry (a separate concern) interfere with the get()
            // assertions — this test is purely about hard-TTL ordering
            // surviving the process-boundary re-anchor.
            let long_ttl = Ttl::new(None, Some(Duration::from_secs(7_200))).unwrap();
            s.set(
                "OLDER",
                ValueSource::Static,
                SecretBytes::from("older-secret"),
                long_ttl,
                &cap,
                &old_clock,
            )
            .unwrap();
            old_clock.advance(Duration::from_secs(3600)); // 1h passes
            s.set(
                "NEWER",
                ValueSource::Static,
                SecretBytes::from("newer-secret"),
                long_ttl,
                &cap,
                &old_clock,
            )
            .unwrap();

            let snap = s.export_snapshot(&cap, &old_clock).unwrap();

            // The "new" process's clock: unrelated zero point, but started
            // with a full day of headroom in its own numbering.
            let new_clock =
                FakeClock::starting_at(Monotonic::from_offset(Duration::from_secs(86_400)));
            let bundle = Store::import_snapshot(Store::builder(), snap, &new_clock).unwrap();
            let mut s2 = bundle.store;
            let cap2 = bundle.control_cap;

            // Both values are still Active immediately after import (neither
            // TTL window has elapsed in the *new* process's frame) ...
            assert!(s2.get("OLDER", &cap2, &new_clock).unwrap().is_some());
            assert!(s2.get("NEWER", &cap2, &new_clock).unwrap().is_some());
            // ... but OLDER, having been loaded 1h before NEWER, hits its hard
            // TTL (2h from its own load) first: advancing by the remaining
            // 1h (2h hard - the 1h already "elapsed" during export, per the
            // re-anchored ages) must destroy OLDER while NEWER (loaded an
            // hour later, so only 1h into its own 2h window) survives.
            new_clock.advance(Duration::from_secs(3_600));
            assert!(
                s2.get("OLDER", &cap2, &new_clock).unwrap().is_none(),
                "OLDER must have hard-expired first"
            );
            assert!(
                s2.get("NEWER", &cap2, &new_clock).unwrap().is_some(),
                "NEWER, loaded an hour after OLDER, must still be alive"
            );
        }

        #[test]
        fn import_rejects_an_unsupported_format_version() {
            let (s, cap, clock) = three_shape_store();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            let mut bytes = snap.to_bytes().unwrap();
            // format_version occupies the 4 bytes right after the 8-byte magic.
            bytes[8..12].copy_from_slice(&999u32.to_be_bytes());

            // Realistic pipeline: a corrupted wire snapshot is caught by
            // `from_bytes` before `import_snapshot` ever runs.
            let err = StoreSnapshot::from_bytes(&bytes).unwrap_err();
            assert!(matches!(
                err,
                ImportError::UnsupportedVersion {
                    got: 999,
                    supported: _
                }
            ));
        }

        #[test]
        fn import_rejects_a_corrupted_length_prefix_without_panicking() {
            let (s, cap, clock) = three_shape_store();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            let mut bytes = snap.to_bytes().unwrap();
            // The first entry's length prefix is the 4 bytes right after the
            // 12-byte header (magic + version + entry_count).
            bytes[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());

            let err = StoreSnapshot::from_bytes(&bytes).unwrap_err();
            assert!(matches!(err, ImportError::Truncated));
        }

        // ---- DR-0029 review: HIGH-5 (key syntax), LOW-3 (duplicate key) ----

        #[test]
        fn import_rejects_invalid_key_syntax() {
            // Only reachable via corrupted/crafted snapshot bytes: Store::set
            // / Store::define already reject a `-`-containing key (DR-0017
            // §1.5) before export could ever see it.
            let clock = FakeClock::new();
            let snap = StoreSnapshot::new(vec![SnapshotEntry {
                key: "bad-key".to_string(),
                value: Some(SnapshotValue {
                    source: SnapshotSource::Static,
                    secret: Zeroizing::new(b"v".to_vec()),
                    soft_ttl_ms: None,
                    hard_ttl_ms: None,
                    loaded_at_epoch_ms: 0,
                    extended_at_epoch_ms: 0,
                    pin_deadline_epoch_ms: None,
                }),
                definition: None,
                failure: None,
                guard: None,
                version: None,
                refresh_claim: None,
            }]);

            // `StoreBundle` does not derive `Debug`, so `unwrap_err()` (which
            // needs `T: Debug` for its panic message) is not usable here.
            let err = match Store::import_snapshot(Store::builder(), snap, &clock) {
                Err(e) => e,
                Ok(_) => panic!("expected import_snapshot to reject this snapshot"),
            };
            assert!(matches!(err, ImportError::InvalidKey { key } if key == "bad-key"));
        }

        #[test]
        fn import_rejects_a_duplicate_key_across_entries() {
            // Only reachable via corrupted/crafted bytes: Store::export_snapshot
            // de-duplicates keys by construction (it iterates a sorted+deduped
            // key union). Import must reject outright rather than let the
            // later entry silently win over the earlier one.
            let clock = FakeClock::new();
            let make_entry = |secret: &str| SnapshotEntry {
                key: "DUP".to_string(),
                value: Some(SnapshotValue {
                    source: SnapshotSource::Static,
                    secret: Zeroizing::new(secret.as_bytes().to_vec()),
                    soft_ttl_ms: None,
                    hard_ttl_ms: None,
                    loaded_at_epoch_ms: 0,
                    extended_at_epoch_ms: 0,
                    pin_deadline_epoch_ms: None,
                }),
                definition: None,
                failure: None,
                guard: None,
                version: None,
                refresh_claim: None,
            };
            let snap = StoreSnapshot::new(vec![make_entry("first"), make_entry("second")]);

            // `StoreBundle` does not derive `Debug`, so `unwrap_err()` (which
            // needs `T: Debug` for its panic message) is not usable here.
            let err = match Store::import_snapshot(Store::builder(), snap, &clock) {
                Err(e) => e,
                Ok(_) => panic!("expected import_snapshot to reject this snapshot"),
            };
            assert!(matches!(err, ImportError::DuplicateKey { key } if key == "DUP"));
        }

        // ---- DR-0029 review MEDIUM-2: extended_at >= loaded_at invariant ----

        #[test]
        fn import_rejects_extended_at_preceding_loaded_at() {
            // Only reachable via corrupted/crafted bytes: CacheEntry::extend
            // only ever moves extended_at forward from loaded_at, so a
            // snapshot honestly produced by Store::export_snapshot always has
            // extended_at >= loaded_at. CacheEntry::from_parts does not
            // itself check this (its signature is unchanged); import_snapshot
            // is the one caller that reconstructs both from untrusted wire
            // data, so it is the one responsible for catching the violation.
            let clock = FakeClock::starting_at(Monotonic::from_offset(Duration::from_secs(1_000)));
            let now_wall_ms = crate::snapshot::wall_now_epoch_ms();
            let snap = StoreSnapshot::new(vec![SnapshotEntry {
                key: "BACKWARDS".to_string(),
                value: Some(SnapshotValue {
                    source: SnapshotSource::Static,
                    secret: Zeroizing::new(b"v".to_vec()),
                    soft_ttl_ms: None,
                    hard_ttl_ms: None,
                    loaded_at_epoch_ms: now_wall_ms - 5_000, // 5s before "now"
                    extended_at_epoch_ms: now_wall_ms - 10_000, // earlier than loaded_at: malformed
                    pin_deadline_epoch_ms: None,
                }),
                definition: None,
                failure: None,
                guard: None,
                version: None,
                refresh_claim: None,
            }]);

            // `StoreBundle` does not derive `Debug`, so `unwrap_err()` (which
            // needs `T: Debug` for its panic message) is not usable here.
            let err = match Store::import_snapshot(Store::builder(), snap, &clock) {
                Err(e) => e,
                Ok(_) => panic!("expected import_snapshot to reject this snapshot"),
            };
            assert!(matches!(err, ImportError::MalformedTtl { key } if key == "BACKWARDS"));
        }

        // ---- DR-0029 review HIGH-2: failed_at re-anchor under insufficient headroom ----

        #[test]
        fn import_preserves_full_backoff_window_when_importing_clock_lacks_headroom() {
            // Store-level regression: a failure record whose true age (per the
            // wall-clock delta baked into failed_at_epoch_ms) exceeds the
            // importing clock's own monotonic headroom must route through
            // epoch_ms_to_monotonic_for_failure and anchor to "now" (the full
            // retry_after window still applies), not clamp to Monotonic::ZERO.
            // A ZERO clamp would make the record look `clock`'s-own-uptime
            // older than it is — here, 90s older — which would read the 60s
            // backoff as already-expired the instant it is checked, silently
            // dropping the DR-0022 TouchID-storm suppression a graceful
            // restart is supposed to preserve.
            let clock = FakeClock::starting_at(Monotonic::from_offset(Duration::from_secs(90)));
            let now_wall_ms = crate::snapshot::wall_now_epoch_ms();
            // True age (relative to now_wall_ms) is 9999s — far more than the
            // importing clock's 90s of headroom, so reconstruction hits the
            // insufficient-headroom path.
            let failed_at_epoch_ms = now_wall_ms - 9_999_000;
            let snap = StoreSnapshot::new(vec![SnapshotEntry {
                key: "WILLFAIL".to_string(),
                value: None,
                definition: None,
                failure: Some(SnapshotFailure {
                    failed_at_epoch_ms,
                    retry_after_ms: 60_000, // 60s, well under the 90s of headroom
                }),
                guard: None,
                version: None,
                refresh_claim: None,
            }]);

            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            let s2 = bundle.store;

            assert_eq!(
                s2.failure_backoff_remaining("WILLFAIL", &clock),
                Some(Duration::from_secs(60)),
                "insufficient headroom must anchor failed_at to now (full 60s \
                 remaining), not clamp to Monotonic::ZERO (which would read as \
                 already-expired: 90s since the importing clock's own start \
                 already exceeds the 60s retry_after)"
            );
        }
    }

    // ---- DR-0030 access guards ----
    //
    // These tests fix the shape of the fourth `Store` map (`access_guards`)
    // and its lifecycle coupling to entries / definitions. Evaluation logic
    // lives in `cache-warden-cli::daemon::guard` (DR-0004: core stays out of
    // chain interpretation), so nothing here checks "does this getter chain
    // satisfy the record" — only "does the record land / clear at the right
    // moments".

    mod access_guards {
        use super::*;
        use crate::guard::{
            DeclaredAncestor, GuardConstraint, GuardRecord, GuardSetter, PinnedProcess,
        };

        fn sample_record() -> GuardRecord {
            GuardRecord::new(
                vec![
                    GuardConstraint::SameUser,
                    GuardConstraint::SameAncestor {
                        declared: DeclaredAncestor::SameShell {
                            shell_name: "zsh".into(),
                        },
                        pinned: PinnedProcess {
                            pid: 42,
                            start_time: Some(Duration::from_secs(1_700_000_000)),
                            unique_id: Some(999),
                            path: std::path::PathBuf::from("/bin/zsh"),
                            name: "zsh".into(),
                        },
                    },
                ],
                GuardSetter {
                    euid: 501,
                    ruid: 501,
                },
            )
        }

        /// set_guard 直後に guard_of で同じ record が引ける — 第 4 マップの
        /// 基本輪郭 (書いた通り読める、DR-0030 §2)。
        #[test]
        fn set_guard_then_guard_of_returns_the_record() {
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            assert_eq!(s.guard_of("default/K"), Some(&sample_record()));
        }

        /// clear_guard は既存 record を落として true を返し、無ければ false
        /// を返す (呼び出し側の「上書き set 時に前 record を消す」パスで
        /// 副作用有無を区別する必要があるため)。
        #[test]
        fn clear_guard_reports_presence() {
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            assert!(!s.clear_guard("default/K", &cap).unwrap());
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            assert!(s.clear_guard("default/K", &cap).unwrap());
            assert_eq!(s.guard_of("default/K"), None);
        }

        /// cap mismatch は set_guard / clear_guard 両方で拒否 (DR-0024 cap
        /// gate は mutation の統一入口)。 guard_of は value-free read なので
        /// cap 不要 (definition_of / source_of と同型)。
        #[test]
        fn set_and_clear_guard_are_cap_gated_but_guard_of_is_not() {
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            let (_other_store, other_cap) = crate::test_helpers::store_with_cap();
            assert_eq!(
                s.set_guard("default/K", sample_record(), &other_cap),
                Err(CapError::KeyMismatch)
            );
            // Store's own cap succeeds.
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            assert_eq!(
                s.clear_guard("default/K", &other_cap),
                Err(CapError::KeyMismatch)
            );
            // guard_of is cap-free.
            assert!(s.guard_of("default/K").is_some());
        }

        /// value-only delete でも guard は落ちる (DR-0030 §5): guard は
        /// 「その set instance への宣言」なので値が消えれば意味論を失う。
        /// failure_backoffs との差分をここで固定 (backoff は definition
        /// 生存に紐づくので value-only delete でも生き残る — 対称でない)。
        #[test]
        fn value_only_delete_removes_guard() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            cmd_entry(&mut s, "default/K", &cap, &clock);
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            s.delete("default/K", &cap).unwrap();
            assert_eq!(s.guard_of("default/K"), None);
        }

        /// delete_with_definition も guard を落とす (value-only delete の
        /// 上位互換)。
        #[test]
        fn delete_with_definition_removes_guard() {
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.define(
                "default/K",
                ValueSource::command(["echo".into(), "v".into()]),
                ttl(),
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            s.delete_with_definition("default/K", &cap).unwrap();
            assert_eq!(s.guard_of("default/K"), None);
        }

        /// undefine も guard を落とす (definition rebind 前に旧宣言が生き
        /// 残る事故を防ぐ、DR-0030 §5)。v1 は set のみに guard が付くので
        /// 実運用では稀だが、対称性のために固定。
        #[test]
        fn undefine_removes_guard() {
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.define(
                "default/K",
                ValueSource::command(["echo".into(), "v".into()]),
                ttl(),
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            s.undefine("default/K");
            assert_eq!(s.guard_of("default/K"), None);
        }

        /// `Store::set` 自体は guard を触らない (DR-0030 §5): CLI 層が
        /// set_guard / clear_guard を呼び分ける前提。core が set 中に guard
        /// を落とすと、CLI 層の「新 record を先に埋めてから set」順序が組
        /// めなくなるため、core は明示的な API しか提供しない。
        #[test]
        fn store_set_does_not_touch_guard() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("v1"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            // Second set with the same cap: guard stays intact — the CLI
            // layer, not `set`, is responsible for calling `clear_guard`.
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("v2"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            assert_eq!(s.guard_of("default/K"), Some(&sample_record()));
        }

        // ---- snapshot round-trip / orphan prune / version selection ----

        /// guard 付き entry の export→import 往復で record が保存される
        /// (DR-0029 handoff の必須要件、DR-0030 §3)。
        #[test]
        fn guard_survives_snapshot_round_trip() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("secret"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            assert_eq!(bundle.store.guard_of("default/K"), Some(&sample_record()));
        }

        /// value も definition も無い key に guard record が残っていた
        /// (bug 由来の orphan) 場合、export/import 時に prune される
        /// (DR-0030 §5)。live store でも guard_of 経由で見えたままだが、
        /// snapshot handoff を横切ると自動で片付く。
        #[test]
        fn orphan_guard_is_pruned_at_export() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            // Insert an orphan directly (no value, no definition).
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            assert_eq!(bundle.store.guard_of("default/K"), None);
        }

        /// guard を含まない export は format_version を 1 (VERSION_PRE_GUARD)
        /// に維持し、旧 daemon が読める互換を壊さない (DR-0030 §3 "ダウン
        /// グレード方向")。
        #[test]
        fn guardless_export_stays_on_pre_guard_version() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert_eq!(snap.format_version(), crate::snapshot::VERSION_PRE_GUARD);
        }

        /// definition-only key に guard record が残っていた場合、export は
        /// guard を同梱しない (DR-0030 §5: guard は set instance に紐づく)。
        /// 旧実装は「definition があるから live」と誤判定して guard を snapshot
        /// に載せ、無駄に FORMAT_VERSION=2 に押し上げていた。この test は
        /// 「definition しか無い key の guard は export されない」+ 「その
        /// 結果 export version が PRE_GUARD に留まる」の 2 段を pin する。
        #[test]
        fn guard_on_definition_only_key_is_not_exported() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.define(
                "default/K",
                ValueSource::command(["echo".into(), "v".into()]),
                ttl(),
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert_eq!(
                snap.format_version(),
                crate::snapshot::VERSION_PRE_GUARD,
                "definition-only guard must not force a version bump — the guard \
                 belongs to no live set instance and is dropped at export"
            );
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            assert_eq!(bundle.store.guard_of("default/K"), None);
        }

        /// hard-expired husk (value が実体としては hard-expired、まだ物理
        /// zeroize されていない) の key に guard record が残っていた場合、
        /// export は guard を同梱しない (§5 と同型: 現時点で live value が
        /// 存在しないから guard は意味論を失う)。旧実装ではこの husk が
        /// FORMAT_VERSION=2 を強制していた。
        #[test]
        fn guard_on_hard_expired_value_is_not_exported() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            // Push past the hard TTL boundary so the value is logically
            // destroyed (husk stage): export_snapshot borrows `&self` and
            // must not resurrect the guard for a value it is refusing to
            // emit as SnapshotValue.
            clock.advance(HARD + Duration::from_secs(1));
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert_eq!(
                snap.format_version(),
                crate::snapshot::VERSION_PRE_GUARD,
                "a hard-expired husk carries no live value, so its guard \
                 must not force FORMAT_VERSION=2"
            );
        }

        /// regenerate は「新しい set instance の value を install する」経路
        /// なので、旧 set instance の guard record が生き残ってはならない
        /// (DR-0030 §5)。 旧値の hard 失効 → regenerate → 新値 install の
        /// フローで、以前の宣言が新値の gate に流用されないことを固定する。
        /// v1 では kv set のみに guard が付くが、この cleanup は future の
        /// definition-side guard も守る目的で uniform に実装されている。
        #[test]
        fn regenerate_clears_stale_guard() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            // Command-source entry so regenerate is applicable; attach a
            // guard directly (simulating a future definition-side guard the
            // v1 CLI does not yet declare, but the core cleanup must cover).
            cmd_entry(&mut s, "default/K", &cap, &clock);
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            // Age the value past hard expiry so regenerate is legal.
            clock.advance(HARD + Duration::from_secs(1));
            let runner = CountingRunner::new(b"fresh");
            s.regenerate("default/K", &runner, &AllowAll, None, &cap, &clock)
                .expect("regenerate succeeds under AllowAll");
            assert_eq!(
                s.guard_of("default/K"),
                None,
                "regenerate installs a new set instance; the previous \
                 declaration must not silently gate the new value"
            );
        }

        /// get_or_regenerate 経路も同型: definition から新値が install される
        /// と、その key に残っていた guard record は落ちる (DR-0030 §7:
        /// definition-derived entry は guard の scope 外)。
        #[test]
        fn get_or_regenerate_clears_stale_guard() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.define(
                "default/K",
                ValueSource::command(["echo".into(), "v".into()]),
                ttl(),
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            let runner = CountingRunner::new(b"fresh");
            s.get_or_regenerate("default/K", &runner, &AllowAll, None, &cap, &clock)
                .expect("lazy generate succeeds under AllowAll");
            assert_eq!(
                s.guard_of("default/K"),
                None,
                "the definition-derived install retires the setter's \
                 declaration; the guard record must not survive"
            );
        }

        /// guard を 1 件でも含む export は FORMAT_VERSION に上がる。旧
        /// daemon はここで unsupported version として reject → cold start に
        /// 退化する (DR-0030 §3: "認可が黙って消える" より安全側)。
        #[test]
        fn guarded_export_bumps_to_current_format_version() {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            s.set_guard("default/K", sample_record(), &cap).unwrap();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            // One generation above pre-guard, not the newest: DR-0034 added a
            // further step for refresh state, and a guard-only export must
            // stay importable by a guards-but-no-claims build.
            assert_eq!(snap.format_version(), crate::snapshot::VERSION_PRE_REFRESH);
        }
    }

    // These fix the shape of the two DR-0034 §4 side maps (`versions`,
    // `refresh_claims`). The core only stores them — every comparison and
    // expiry judgement belongs to the adapter (DR-0004) — so what is tested
    // here is storage, lifetime, and snapshot carriage, never policy.
    mod refresh_state {
        use super::*;

        fn seeded() -> (Store, Capability, FakeClock) {
            let clock = FakeClock::new();
            let (mut s, cap) = crate::test_helpers::store_with_cap();
            s.set(
                "default/K",
                ValueSource::Static,
                SecretBytes::from("v"),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
            (s, cap, clock)
        }

        #[test]
        fn an_unknown_key_is_at_version_zero() {
            let (s, _cap, _clock) = seeded();
            assert_eq!(s.version_of("default/NOPE"), 0);
            assert_eq!(s.version_of("default/K"), 0, "set does not assign one");
        }

        #[test]
        fn bumping_advances_by_one_and_returns_the_new_value() {
            let (mut s, cap, _clock) = seeded();
            assert_eq!(s.bump_version("default/K", &cap).unwrap(), 1);
            assert_eq!(s.bump_version("default/K", &cap).unwrap(), 2);
            assert_eq!(s.version_of("default/K"), 2);
        }

        #[test]
        fn bumping_is_rejected_without_a_matching_capability() {
            let (mut s, _cap, _clock) = seeded();
            let (_other, wrong) = crate::test_helpers::store_with_cap();
            assert!(s.bump_version("default/K", &wrong).is_err());
            assert_eq!(s.version_of("default/K"), 0, "nothing mutated on refusal");
        }

        /// The lifetime that differs from every other side map: a value-only
        /// delete keeps the version. Resetting it would let a caller holding a
        /// stale version win a compare-and-swap against a re-created key.
        #[test]
        fn a_value_only_delete_keeps_the_version() {
            let (mut s, cap, _clock) = seeded();
            s.bump_version("default/K", &cap).unwrap();
            s.bump_version("default/K", &cap).unwrap();
            s.delete("default/K", &cap).unwrap();
            assert_eq!(s.version_of("default/K"), 2, "the counter must not reset");
        }

        #[test]
        fn removing_the_key_outright_drops_the_version() {
            let (mut s, cap, _clock) = seeded();
            s.bump_version("default/K", &cap).unwrap();
            s.delete_with_definition("default/K", &cap).unwrap();
            assert_eq!(s.version_of("default/K"), 0);
        }

        #[test]
        fn a_claim_is_stored_and_read_back_verbatim() {
            let (mut s, cap, _clock) = seeded();
            s.set_refresh_claim("default/K", RefreshClaim::new("tok", 10, 20), &cap)
                .unwrap();
            let c = s.refresh_claim_of("default/K").expect("stored");
            assert_eq!(c.token(), "tok");
            assert_eq!(c.claimed_at_epoch_ms(), 10);
            assert_eq!(c.expires_at_epoch_ms(), 20);
        }

        /// The core hands back a lapsed claim rather than hiding it: deciding
        /// whether it still holds needs a clock, and reading the clock on the
        /// caller's behalf is the policy call the core does not make.
        #[test]
        fn a_lapsed_claim_is_still_returned() {
            let (mut s, cap, _clock) = seeded();
            s.set_refresh_claim("default/K", RefreshClaim::new("tok", 10, 20), &cap)
                .unwrap();
            let c = s.refresh_claim_of("default/K").expect("still stored");
            assert!(!c.is_active_at(9_999), "the caller judges, not the store");
        }

        #[test]
        fn clearing_reports_whether_a_claim_was_present() {
            let (mut s, cap, _clock) = seeded();
            assert!(!s.clear_refresh_claim("default/K", &cap).unwrap());
            s.set_refresh_claim("default/K", RefreshClaim::new("t", 1, 2), &cap)
                .unwrap();
            assert!(s.clear_refresh_claim("default/K", &cap).unwrap());
            assert!(s.refresh_claim_of("default/K").is_none());
        }

        /// A claim describes a refresh of the value; when the value goes, so
        /// does the claim — otherwise the entry would be stuck holding a claim
        /// nobody can complete or release.
        #[test]
        fn deleting_the_value_drops_the_claim() {
            let (mut s, cap, _clock) = seeded();
            s.set_refresh_claim("default/K", RefreshClaim::new("t", 1, 2), &cap)
                .unwrap();
            s.delete("default/K", &cap).unwrap();
            assert!(s.refresh_claim_of("default/K").is_none());
        }

        #[test]
        fn version_and_claim_survive_a_snapshot_round_trip() {
            let (mut s, cap, clock) = seeded();
            s.bump_version("default/K", &cap).unwrap();
            s.bump_version("default/K", &cap).unwrap();
            s.set_refresh_claim(
                "default/K",
                RefreshClaim::new("abcdefghijklmnopqrstuv", 1_000, 61_000),
                &cap,
            )
            .unwrap();

            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert_eq!(
                snap.format_version(),
                crate::snapshot::FORMAT_VERSION,
                "refresh state forces the newest wire version"
            );
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            assert_eq!(bundle.store.version_of("default/K"), 2);
            let c = bundle
                .store
                .refresh_claim_of("default/K")
                .expect("the claim must outlive the restart");
            assert_eq!(c.token(), "abcdefghijklmnopqrstuv");
            assert_eq!(c.expires_at_epoch_ms(), 61_000);
        }

        /// The asymmetry between the two maps has to survive the round trip
        /// too: a version outlives its value, so a snapshot taken after a
        /// value-only delete still carries it.
        #[test]
        fn a_version_survives_the_snapshot_even_with_no_value_left() {
            let (mut s, cap, clock) = seeded();
            s.bump_version("default/K", &cap).unwrap();
            s.define(
                "default/K",
                ValueSource::command(vec!["true".to_string()]),
                ttl(),
            )
            .unwrap();
            s.delete("default/K", &cap).unwrap();

            let snap = s.export_snapshot(&cap, &clock).unwrap();
            let bundle = Store::import_snapshot(Store::builder(), snap, &clock).unwrap();
            assert_eq!(bundle.store.version_of("default/K"), 1);
            assert!(bundle.store.refresh_claim_of("default/K").is_none());
        }

        /// A store with neither versions nor claims must keep emitting the
        /// snapshot version an older build can import — the whole point of
        /// stepping up by content rather than unconditionally.
        #[test]
        fn a_store_with_no_refresh_state_does_not_bump_the_wire_version() {
            let (s, cap, clock) = seeded();
            let snap = s.export_snapshot(&cap, &clock).unwrap();
            assert_eq!(snap.format_version(), crate::snapshot::VERSION_PRE_GUARD);
        }
    }
}
