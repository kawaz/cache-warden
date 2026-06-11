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
use crate::clock::{Clock, Monotonic};
use crate::definition::{DefineError, Definition};
use crate::entry::{CacheEntry, EntryState, ExtendError, PinError, Ttl};
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
        AuthOperation::Pin => AuthContext::pin(key),
    };
    match requester {
        Some(chain) => ctx.with_requester(chain.to_vec()),
        None => ctx,
    }
}

/// In-memory secure key/value cache.
///
/// Two maps, deliberately separate (DR-0014): `entries` holds live secret
/// **values** (TTL-gated, zeroized on hard expiry), while `definitions` holds
/// the value-free **definitions** (how to regenerate a value: command + TTL).
/// A key may appear in either, neither, or both:
///
/// - value only → a `set` entry with no definition (e.g. a static value).
/// - definition only → defined but never yet produced (lazy), or its value was
///   `delete`d (the definition survives so the next get can regenerate it).
/// - both → a defined key whose value has been produced and is resident.
#[derive(Debug, Default)]
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
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
        auth: &(impl Authenticator + ?Sized),
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
        auth: &(impl Authenticator + ?Sized),
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
        clock: &impl Clock,
    ) -> Result<(), PinAuthOutcome> {
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
    /// Returns `false` if the key is absent. Unlike [`Store::pin_authenticated`]
    /// this needs **no** authentication: removing a reprieve only moves the entry
    /// back toward expiry (the safe direction), so there is nothing to gate.
    pub fn unpin(&mut self, key: &str) -> bool {
        match self.entries.get_mut(key) {
            Some(entry) => {
                entry.unpin();
                true
            }
            None => false,
        }
    }

    /// The active pin deadline for `key`, or `None` if absent or not pinned.
    ///
    /// Value-free metadata for `status` / `list`: it reveals *when* a reprieve
    /// lapses, never the secret. A caller computes remaining seconds against the
    /// clock (a deadline already in the past reports a non-positive remainder).
    pub fn pin_deadline_of(&self, key: &str) -> Option<Monotonic> {
        self.entries.get(key).and_then(CacheEntry::pin_deadline)
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
        let candidate = Definition::new(source, ttl)?;
        let key = key.into();
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
        clock: &impl Clock,
    ) -> Result<(), RegenerateDefOutcome> {
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

        let argv = match definition.source() {
            ValueSource::Command { argv } => argv.clone(),
            // Definitions are command-only by construction (`define` rejects
            // static), so this is unreachable; treated defensively.
            ValueSource::Static => return Err(RegenerateDefOutcome::Undefined),
        };
        let source = definition.source().clone();
        let ttl = definition.ttl();

        // 1. Re-run upstream. On failure nothing is mutated.
        let value = runner.run(&argv).map_err(RegenerateDefOutcome::RunFailed)?;

        // 2. Re-authenticate. `value` is dropped (zeroized) on the error path.
        auth.authenticate(&auth_context(key, AuthOperation::Regenerate, requester))
            .map_err(RegenerateDefOutcome::AuthFailed)?;

        // 3. Install a fresh Active entry (overwriting any destroyed husk).
        self.entries
            .insert(key.to_string(), CacheEntry::new(source, value, ttl, clock));
        Ok(())
    }

    /// Remove both `key`'s value **and** its definition, returning `true` if
    /// either was present.
    ///
    /// This is the `--with-define` variant of DR-0014 §2: plain [`Store::delete`]
    /// drops only the value (the definition survives so the next get
    /// regenerates), whereas this forgets the key entirely so it will *not*
    /// regenerate. The removed value entry is dropped (zeroizing its secret).
    pub fn delete_with_definition(&mut self, key: &str) -> bool {
        let had_value = self.entries.remove(key).is_some();
        let had_def = self.definitions.remove(key).is_some();
        had_value || had_def
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
}

impl std::fmt::Display for PinAuthOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinAuthOutcome::NotFound => write!(f, "no such key"),
            PinAuthOutcome::HardExpired => {
                write!(f, "entry is hard-expired (destroyed); cannot pin")
            }
            PinAuthOutcome::AuthFailed(e) => write!(f, "pin blocked: {e}"),
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

    // ---- pin_authenticated / unpin (DR-0011) ----

    use crate::clock::Monotonic;

    fn deadline_secs(secs: u64) -> Monotonic {
        Monotonic::from_offset(Duration::from_secs(secs))
    }

    #[test]
    fn pin_authenticated_always_prompts_even_when_active() {
        // Unlike extend, pin demands auth from Active too (security-relaxing).
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        let auth = RecordingAuthenticator::allowing();
        s.pin_authenticated("K", deadline_secs(100), &auth, None, &clock)
            .unwrap();
        assert_eq!(auth.call_count(), 1, "pin prompts even from Active");
        assert_eq!(auth.calls()[0], AuthContext::pin("K"));
    }

    #[test]
    fn pin_authenticated_keeps_value_gettable_past_ttl() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        s.pin_authenticated("K", deadline_secs(1000), &AllowAll, None, &clock)
            .unwrap();
        clock.advance(Duration::from_secs(500)); // past soft and hard windows
        assert_eq!(
            s.get("K", &clock).unwrap().expose_secret(),
            b"v",
            "pinned value survives its TTL"
        );
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
    }

    #[test]
    fn pin_authenticated_denied_leaves_entry_unpinned() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        let err = s
            .pin_authenticated("K", deadline_secs(1000), &DenyAll, None, &clock)
            .unwrap_err();
        assert_eq!(err, PinAuthOutcome::AuthFailed(AuthError::Denied));
        assert_eq!(s.pin_deadline_of("K"), None, "denied pin must not apply");
    }

    #[test]
    fn pin_authenticated_missing_key() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        assert_eq!(
            s.pin_authenticated("ghost", deadline_secs(100), &AllowAll, None, &clock),
            Err(PinAuthOutcome::NotFound)
        );
    }

    #[test]
    fn pin_authenticated_hard_expired_is_rejected_without_prompt() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        clock.advance(HARD); // hard-expired
        let auth = RecordingAuthenticator::allowing();
        assert_eq!(
            s.pin_authenticated("K", deadline_secs(1000), &auth, None, &clock),
            Err(PinAuthOutcome::HardExpired)
        );
        assert_eq!(auth.call_count(), 0, "no prompt for a destroyed value");
    }

    #[test]
    fn pin_authenticated_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        let chain = vec![ProcessInfo {
            pid: 11,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/usr/bin/ssh")),
            start_time: None,
        }];
        let auth = RecordingAuthenticator::allowing();
        s.pin_authenticated("K", deadline_secs(100), &auth, Some(&chain), &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    #[test]
    fn re_pin_overwrites_deadline_via_store() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        s.pin_authenticated("K", deadline_secs(20), &AllowAll, None, &clock)
            .unwrap();
        s.pin_authenticated("K", deadline_secs(1000), &AllowAll, None, &clock)
            .unwrap();
        assert_eq!(s.pin_deadline_of("K"), Some(deadline_secs(1000)));
    }

    #[test]
    fn unpin_returns_entry_to_normal_evaluation() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        s.pin_authenticated("K", deadline_secs(1000), &AllowAll, None, &clock)
            .unwrap();
        clock.advance(Duration::from_secs(15)); // past soft
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active), "pinned");
        assert!(s.unpin("K"));
        assert_eq!(s.pin_deadline_of("K"), None);
        assert_eq!(
            s.state_of("K", &clock),
            Some(EntryState::SoftExpired),
            "after unpin the soft window applies again"
        );
    }

    #[test]
    fn unpin_missing_key_is_false() {
        let mut s = Store::new();
        assert!(!s.unpin("ghost"));
    }

    // ---- definition registry (DR-0014) ----

    fn cmd_source() -> ValueSource {
        ValueSource::command(["op".into(), "read".into(), "op://v/i/f".into()])
    }

    #[test]
    fn define_registers_without_producing_a_value() {
        // define is lazy: it stores the definition but runs no command and
        // produces no value entry (DR-0014 §1).
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(s.is_defined("K"));
        assert!(!s.has_value("K"), "define must not produce a value");
        assert_eq!(s.len(), 0, "no value entry yet");
        assert_eq!(s.definition_of("K").unwrap().source(), &cmd_source());
    }

    #[test]
    fn define_is_idempotent_for_exact_match() {
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        // Same argv + TTL again: a silent no-op.
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(s.is_defined("K"));
    }

    #[test]
    fn define_conflicting_argv_is_rejected() {
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let other = ValueSource::command(["op".into(), "read".into(), "op://other".into()]);
        assert_eq!(s.define("K", other, ttl()), Err(DefineError::Conflict));
        // The original definition is untouched.
        assert_eq!(s.definition_of("K").unwrap().source(), &cmd_source());
    }

    #[test]
    fn define_conflicting_ttl_is_rejected() {
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let other_ttl = Ttl::new(Some(Duration::from_secs(5)), Some(HARD)).unwrap();
        assert_eq!(
            s.define("K", cmd_source(), other_ttl),
            Err(DefineError::Conflict)
        );
    }

    #[test]
    fn define_rejects_static_source() {
        let mut s = Store::new();
        assert_eq!(
            s.define("K", ValueSource::Static, ttl()),
            Err(DefineError::StaticNotDefinable)
        );
        assert!(!s.is_defined("K"));
    }

    #[test]
    fn get_or_regenerate_lazily_produces_for_a_definition_only_key() {
        // The canonical lazy path: a key has a definition but no value yet.
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(s.get("K", &clock).is_none(), "no value before lazy gen");

        let runner = CountingRunner::new(b"lazy-token");
        let auth = RecordingAuthenticator::allowing();
        s.get_or_regenerate("K", &runner, &auth, None, &clock)
            .unwrap();

        assert_eq!(runner.runs(), 1);
        assert_eq!(auth.call_count(), 1);
        assert_eq!(auth.calls()[0], AuthContext::regenerate("K"));
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"lazy-token");
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
    }

    #[test]
    fn get_or_regenerate_resets_loaded_at_for_a_fresh_hard_window() {
        // Lazy production resets loaded_at: the hard window starts from now.
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        clock.advance(Duration::from_secs(100)); // long after define
        let runner = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        // Active immediately after production, soft-expires HARD-relative to now.
        assert_eq!(s.state_of("K", &clock), Some(EntryState::Active));
        clock.advance(HARD);
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
    }

    #[test]
    fn get_or_regenerate_undefined_key_is_rejected() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        let runner = CountingRunner::new(b"x");
        assert_eq!(
            s.get_or_regenerate("ghost", &runner, &AllowAll, None, &clock),
            Err(RegenerateDefOutcome::Undefined)
        );
        assert_eq!(runner.runs(), 0);
    }

    #[test]
    fn get_or_regenerate_skips_when_value_is_active() {
        // A resident Active value must not be silently regenerated.
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"first");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        assert_eq!(runner.runs(), 1);
        // Active now: a second call regenerates nothing.
        assert_eq!(
            s.get_or_regenerate("K", &runner, &AllowAll, None, &clock),
            Err(RegenerateDefOutcome::ValueResident)
        );
        assert_eq!(runner.runs(), 1, "must not re-run for a resident value");
    }

    #[test]
    fn get_or_regenerate_skips_when_value_is_soft_expired() {
        // SoftExpired means the value is still resident (extend, not regenerate).
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        clock.advance(Duration::from_secs(15)); // SoftExpired
        assert_eq!(s.state_of("K", &clock), Some(EntryState::SoftExpired));
        assert_eq!(
            s.get_or_regenerate("K", &runner, &AllowAll, None, &clock),
            Err(RegenerateDefOutcome::ValueResident)
        );
        assert_eq!(runner.runs(), 1);
    }

    #[test]
    fn get_or_regenerate_reproduces_after_hard_expiry() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"v");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        clock.advance(HARD); // value destroyed
        assert_eq!(s.state_of("K", &clock), Some(EntryState::HardExpired));
        // Lazy path reproduces it.
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        assert_eq!(runner.runs(), 2);
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"v");
    }

    #[test]
    fn get_or_regenerate_run_failure_skips_auth_and_leaves_value_absent() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let auth = RecordingAuthenticator::allowing();
        let err = s
            .get_or_regenerate("K", &FailingRunner, &auth, None, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateDefOutcome::RunFailed(RunError::EmptyOutput));
        assert_eq!(auth.call_count(), 0, "auth must not run if fetch failed");
        assert!(!s.has_value("K"), "value stays absent");
        assert!(s.is_defined("K"), "definition survives a failed run");
    }

    #[test]
    fn get_or_regenerate_auth_denied_discards_value() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let runner = CountingRunner::new(b"fresh");
        let err = s
            .get_or_regenerate("K", &runner, &DenyAll, None, &clock)
            .unwrap_err();
        assert_eq!(err, RegenerateDefOutcome::AuthFailed(AuthError::Denied));
        assert_eq!(runner.runs(), 1, "fetch happens before auth");
        assert!(!s.has_value("K"), "denied value is discarded, not stored");
    }

    #[test]
    fn get_or_regenerate_forwards_requester_into_context() {
        use crate::process::ProcessInfo;
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        let chain = vec![ProcessInfo {
            pid: 13,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from("/bin/git")),
            start_time: None,
        }];
        let auth = RecordingAuthenticator::allowing();
        s.get_or_regenerate("K", &CountingRunner::new(b"v"), &auth, Some(&chain), &clock)
            .unwrap();
        assert_eq!(auth.calls()[0].requester.as_deref(), Some(chain.as_slice()));
    }

    // ---- delete: value-only vs value+definition (DR-0014 §2) ----

    #[test]
    fn delete_drops_value_but_keeps_definition() {
        // delete invalidates: the value is gone, but the definition survives so
        // the next get regenerates it.
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        s.get_or_regenerate("K", &CountingRunner::new(b"v"), &AllowAll, None, &clock)
            .unwrap();
        assert!(s.has_value("K"));

        assert!(s.delete("K"), "value removed");
        assert!(!s.has_value("K"), "value gone");
        assert!(s.is_defined("K"), "definition survives a value-only delete");

        // The next lazy get regenerates from the surviving definition.
        let runner = CountingRunner::new(b"again");
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"again");
    }

    #[test]
    fn delete_with_definition_forgets_the_key_entirely() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        s.get_or_regenerate("K", &CountingRunner::new(b"v"), &AllowAll, None, &clock)
            .unwrap();

        assert!(s.delete_with_definition("K"));
        assert!(!s.has_value("K"));
        assert!(!s.is_defined("K"), "definition removed too");
        // No regeneration is possible anymore.
        assert_eq!(
            s.get_or_regenerate("K", &CountingRunner::new(b"x"), &AllowAll, None, &clock),
            Err(RegenerateDefOutcome::Undefined)
        );
    }

    #[test]
    fn delete_with_definition_works_on_definition_only_key() {
        let mut s = Store::new();
        s.define("K", cmd_source(), ttl()).unwrap();
        assert!(!s.has_value("K"));
        assert!(
            s.delete_with_definition("K"),
            "removes a definition-only key"
        );
        assert!(!s.is_defined("K"));
    }

    #[test]
    fn delete_with_definition_absent_key_is_false() {
        let mut s = Store::new();
        assert!(!s.delete_with_definition("ghost"));
    }

    #[test]
    fn plain_delete_of_static_entry_is_unchanged() {
        // A static value (no definition) keeps the legacy delete semantics:
        // deleting removes it for good (nothing to regenerate from).
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "S",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        assert!(s.delete("S"));
        assert!(!s.has_value("S"));
        assert!(!s.is_defined("S"));
        assert!(s.get("S", &clock).is_none());
    }

    // ---- enumeration: definition-only keys are listed (DR-0014 §5) ----

    #[test]
    fn keys_unions_values_and_definitions() {
        let clock = FakeClock::new();
        let mut s = Store::new();
        // value-only (static)
        s.set(
            "val",
            ValueSource::Static,
            SecretBytes::from("v"),
            ttl(),
            &clock,
        );
        // definition-only (lazy, not produced)
        s.define("def", cmd_source(), ttl()).unwrap();
        // both (defined + produced)
        s.define("both", cmd_source(), ttl()).unwrap();
        s.get_or_regenerate("both", &CountingRunner::new(b"v"), &AllowAll, None, &clock)
            .unwrap();

        // list() is value entries only.
        assert_eq!(s.list(), vec!["both", "val"]);
        // keys() is the union, sorted and de-duplicated.
        assert_eq!(s.keys(), vec!["both", "def", "val"]);
    }

    #[test]
    fn definition_only_key_reports_metadata_without_a_value() {
        // status/list can introspect a defined-but-unproduced key.
        let mut s = Store::new();
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
        // DR-0014 §2: the definition registry and value store are orthogonal.
        // A static value may already sit under a key; defining (a command source)
        // for the same key is allowed and does not touch the value. get_or_regenerate
        // then defers to the live static value rather than regenerating, because a
        // resident value wins (we don't burn an upstream call while a usable value
        // is in memory).
        let clock = FakeClock::new();
        let mut s = Store::new();
        s.set(
            "K",
            ValueSource::Static,
            SecretBytes::from("static-val"),
            ttl(),
            &clock,
        );
        s.define("K", cmd_source(), ttl()).unwrap();
        // The static value is still readable and untouched by define.
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"static-val");
        // While that value is Active, get_or_regenerate defers to it.
        let runner = CountingRunner::new(b"regenerated");
        assert_eq!(
            s.get_or_regenerate("K", &runner, &AllowAll, None, &clock),
            Err(RegenerateDefOutcome::ValueResident)
        );
        assert_eq!(runner.runs(), 0);
        // Once the static value hard-expires (and cannot itself regenerate), the
        // definition takes over and lazily produces a fresh value.
        clock.advance(HARD);
        s.get_or_regenerate("K", &runner, &AllowAll, None, &clock)
            .unwrap();
        assert_eq!(runner.runs(), 1);
        assert_eq!(s.get("K", &clock).unwrap().expose_secret(), b"regenerated");
    }
}
