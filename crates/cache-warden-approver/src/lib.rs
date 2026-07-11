//! Library surface for `cache-warden-approver`.
//!
//! Currently just the IPC wire schema ([`wire`], draft-DR-0031 §4), shared
//! between this crate's helper bin (`src/main.rs`, macOS-only) and
//! `cache-warden-cli`'s daemon-side `daemon::approver` module. The wire types
//! are plain data (`serde` derive only) and build on every platform; the
//! dialog/AppKit code stays confined to the bin target's
//! `#[cfg(target_os = "macos")]` module.

pub mod wire;

/// draft-DR-0031 §Security: the signing Identifier prefix every process in
/// the cache-warden family carries (daemon `com.github.kawaz.cache-warden`,
/// helper `com.github.kawaz.cache-warden.approver`, future siblings). Both
/// ends of the approver IPC refuse a Team-ID-matching peer whose signing
/// Identifier does not start with this string. Lives here — next to the wire
/// schema both ends already share — so the daemon and the helper cannot
/// drift apart on what "cache-warden family" means.
pub const CACHE_WARDEN_IDENTIFIER_PREFIX: &str = "com.github.kawaz.cache-warden";
