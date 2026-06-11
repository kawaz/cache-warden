//! The `cache-warden run` daemon (DR-0008 single-process host).
//!
//! Layout:
//! - [`handler`]: pure, synchronous request → response logic over the core
//!   [`cache_warden::Store`]. No I/O, unit-tested against the core.
//! - [`peer`]: peer-credential lookup (LOCAL_PEERPID / SO_PEERCRED) for the
//!   accepted connection, feeding the requester ancestry chain.
//! - [`server`]: the tokio control-socket listener — bind, accept loop, per-
//!   connection task, watch-channel shutdown, SIGINT/SIGTERM.
//! - [`authsock`]: the SSH agent listener(s) — one per `[authsock.sockets.*]`,
//!   speaking the SSH agent protocol over the core Store (port Iteration 1).

pub mod authsock;
pub mod handler;
pub mod peer;
pub mod server;
