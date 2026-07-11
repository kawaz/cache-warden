//! macOS process inspection: pid facts, ancestry walking, and Unix-domain-socket
//! peer credentials.
//!
//! # Design principles
//!
//! - **Data retrieval only.** This crate answers "what does the kernel say about
//!   pid N / this socket's peer?" and stops there. It does not interpret the
//!   answer — no "is this pid allowed", no policy matching, no ancestry-chain
//!   evaluation. That judgment belongs to the caller: this crate's responsibility
//!   boundary is data retrieval, policy is the consumer's.
//! - **Minimal, system-level dependencies only.** [`libc`] carries the kernel
//!   FFI surface (`proc_pidinfo` / `proc_pidpath` / `getsockopt`), and — on
//!   macOS targets only — `security-framework` / `core-foundation` carry the
//!   [`codesign`] module's `Security.framework` calls. No `sysinfo`-style
//!   aggregator crate, no build script. This crate is intentionally
//!   self-contained (no dependency on `cache-warden`'s own types) so it can be
//!   extracted to its own repository without carrying this workspace along.
//! - **Non-macOS is a shim, not a cfg wall.** Every public function compiles and
//!   runs on any Unix target; off-macOS builds return
//!   [`InspectError::Unavailable`] or `None` rather than failing to compile.
//!   Callers do not need `#[cfg]` guards of their own to use this crate on
//!   Linux/CI. (Unix only: the peer API is keyed by a Unix `RawFd`, so Windows
//!   targets are out of scope by construction.)

pub mod codesign;
mod inspect;
mod peer;

pub use inspect::{InspectError, ProcessInfo, ProcessUniqueId, ancestry, inspect, unique_id};
pub use peer::{AuditToken, peer_audit_token, peer_effective_pid, peer_pid};
