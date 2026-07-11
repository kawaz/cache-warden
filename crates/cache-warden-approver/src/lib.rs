//! Library surface for `cache-warden-approver`.
//!
//! Currently just the IPC wire schema ([`wire`], draft-DR-0031 §4), shared
//! between this crate's helper bin (`src/main.rs`, macOS-only) and
//! `cache-warden-cli`'s daemon-side `daemon::approver` module. The wire types
//! are plain data (`serde` derive only) and build on every platform; the
//! dialog/AppKit code stays confined to the bin target's
//! `#[cfg(target_os = "macos")]` module.

pub mod wire;
