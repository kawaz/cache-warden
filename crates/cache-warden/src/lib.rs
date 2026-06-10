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
//!   in `Debug` / `Display`.
//! - [`Clock`] / [`SystemClock`] / [`FakeClock`]: a monotonic time source used
//!   for TTL evaluation (injectable for tests).
//! - [`ValueSource`]: where a value comes from — [`ValueSource::Static`] (not
//!   regenerable after hard expiry) or [`ValueSource::Command`] (regenerable via
//!   a [`SourceRunner`]).
//! - [`CacheEntry`] / [`EntryState`] / [`Ttl`]: the two-stage TTL state machine
//!   (Active → SoftExpired → HardExpired) with re-authentication
//!   ([`CacheEntry::extend`]).
//! - [`Store`]: a key → [`CacheEntry`] in-memory store with TTL-gated reads.
//!
//! # Scope of this iteration
//!
//! Process authentication, re-authentication (TouchID), `mlock`, the
//! daemon/socket boundary, and the CLI are intentionally out of scope here and
//! live in later iterations / the CLI crate.

mod clock;
mod entry;
mod secret;
mod source;
mod store;

pub use clock::{Clock, FakeClock, Monotonic, SystemClock};
pub use entry::{CacheEntry, EntryState, ExtendError, Ttl, TtlError};
pub use secret::SecretBytes;
pub use source::{RunError, SourceRunner, ValueSource};
pub use store::{ExtendOutcome, Store};
