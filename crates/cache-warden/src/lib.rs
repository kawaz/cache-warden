//! Secure secret cache core.
//!
//! cache-warden is a secure key/value cache for secret values (API tokens, DB
//! passwords, SSH keys, ...). It resolves the tension between *keeping secrets
//! safe* (zeroize-backed in-memory protection, secure upstream sources) and
//! *using them fast* (avoid paying an upstream fetch — e.g. `op read` — on every
//! access) by caching values with a two-stage TTL lifecycle and process
//! authentication.
//!
//! This crate is the pure domain core. It is deliberately free of process /
//! socket / daemon concerns so that protocol adapters (an SSH agent adapter, a
//! KV CLI/socket adapter) can be layered on top. See `docs/DESIGN-ja.md` and
//! the decision records under `docs/decisions/`.
//!
//! # Core concepts
//!
//! - [`SecretBytes`]: an in-memory secret value, zeroized on drop and redacted
//!   in `Debug` / `Display`, and pinned in memory with `mlock` (fail-open;
//!   query [`SecretBytes::is_locked`]) to keep plaintext off swap.
//! - [`Clock`] / [`SystemClock`] / [`FakeClock`]: a monotonic time source used
//!   for TTL evaluation (injectable for tests).
//! - [`ValueSource`]: where a value comes from — [`ValueSource::Static`] (not
//!   regenerable after hard expiry) or [`ValueSource::Command`] (regenerable via
//!   a [`SourceRunner`]).
//! - [`CommandRunner`]: the [`SourceRunner`] that runs a `command` source with
//!   [`std::process::Command`] and captures stdout (honoring a
//!   [`TrailingNewline`] policy, with an opt-in
//!   [`CommandRunner::with_timeout`]).
//! - [`CacheEntry`] / [`EntryState`] / [`Ttl`]: the two-stage TTL state machine
//!   (Active → SoftExpired → HardExpired) with re-authentication
//!   ([`CacheEntry::extend`]).
//! - [`Authenticator`] / [`AuthContext`]: the re-authentication boundary.
//!   [`CommandAuthenticator`] is the production mechanism — it delegates the
//!   prompt to an external command (DR-0010, mirroring authsock-warden's
//!   "re-auth command first"); a built-in TouchID authenticator is a later
//!   iteration. Fakes ([`AllowAll`], [`DenyAll`], [`RecordingAuthenticator`])
//!   drive tests.
//! - [`ProcessInspector`] / [`ProcessInfo`]: generic process authentication —
//!   inspecting a pid and walking its ancestry toward init/launchd.
//!   [`SystemInspector`] is OS-backed; [`FakeInspector`] builds arbitrary trees
//!   for tests. Policy interpretation (which chain may touch what) is left to an
//!   adapter (DR-0004).
//! - [`Store`]: a key → [`CacheEntry`] in-memory store with TTL-gated reads.
//!   The auth gates ([`Store::extend_authenticated`], [`Store::regenerate`])
//!   live here, not on [`CacheEntry`].
//!
//! # Layering: where authentication lives
//!
//! [`CacheEntry::extend`] is intentionally **auth-free** — it only advances the
//! state machine. The [`Store`] layer is the single place that demands
//! re-authentication: [`Store::extend_authenticated`] gates soft-expiry
//! extension and [`Store::regenerate`] gates command re-generation after hard
//! expiry. This keeps the state machine independently testable and concentrates
//! re-auth policy in one place.
//!
//! # Scope of this iteration
//!
//! The real re-authentication mechanism (TouchID — turning an [`AuthContext`]
//! and its requester chain into an actual biometric prompt), the daemon/socket
//! boundary, and the CLI are intentionally out of scope here and live in later
//! iterations / the CLI crate. Swap-protection (`mlock`) and command timeouts
//! are implemented (see [`SecretBytes`] and [`CommandRunner::with_timeout`]).

mod auth;
mod child_process;
mod clock;
mod definition;
mod entry;
mod meta;
mod process;
mod secret;
mod source;
mod store;

pub use auth::{
    AllowAll, AuthContext, AuthError, AuthOperation, Authenticator, CommandAuthenticator, DenyAll,
    RecordingAuthenticator,
};
pub use child_process::spawn_with_clean_signal_mask;
pub use clock::{Clock, FakeClock, Monotonic, SystemClock};
pub use definition::{DefineError, Definition};
pub use entry::{CacheEntry, EntryState, ExtendError, PinError, Ttl, TtlError};
pub use meta::{SourceMeta, ValueMeta};
pub use process::{FakeInspector, InspectError, ProcessInfo, ProcessInspector, SystemInspector};
pub use secret::SecretBytes;
pub use source::{CommandRunner, RunError, SourceRunner, TrailingNewline, ValueSource};
pub use store::{
    ExtendAuthOutcome, ExtendOutcome, FailureRecord, PinAuthOutcome, RegenerateDefOutcome,
    RegenerateOutcome, Store,
};
