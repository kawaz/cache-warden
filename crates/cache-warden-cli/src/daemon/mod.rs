//! The `cache-warden run` daemon (DR-0008 single-process host).
//!
//! Layout:
//! - [`handler`]: pure, synchronous request → response logic over the core
//!   [`cache_warden::Store`]. No I/O, unit-tested against the core.
//! - [`peer`]: peer-credential lookup (LOCAL_PEERPID / SO_PEERCRED) for the
//!   accepted connection, feeding the requester ancestry chain.
//! - [`server`]: the tokio control-socket listener — bind, accept loop, per-
//!   connection task, watch-channel shutdown, SIGINT/SIGTERM.
//! - [`approver`]: draft-DR-0031 Phase 1.4 IPC — the daemon-side unix-socket
//!   `serde_json` client for the `cache-warden-approver` GUI helper. Socket
//!   lifecycle only (bind / spawn / accept / exchange with a response
//!   timeout); not yet wired into [`handler`] / `kv.get` (Phase 1.5 guard
//!   integration).
//! - [`authsock`]: the SSH agent listener(s) — one per `[authsock.sockets.*]`,
//!   speaking the SSH agent protocol over the core Store, with local KV keys and
//!   forwarded upstream agents (port Iterations 1–2).
//! - [`upstream_path`]: resolve an upstream agent socket path around the macOS
//!   TCC privacy prompt (state-dir symlink for Group Container sockets).
//! - [`hardening`]: process-wide startup hardening — suppress core dumps so a
//!   crash cannot leak in-memory secrets to disk (5a) and refuse debugger
//!   attachment so a live inspector cannot read them (5b, opt-out via
//!   `[daemon].allow-debug-attach`); design §3 judgement 5.
//! - [`graceful_restart`]: DR-0029 Phase 1 — serialize the kv store, verify
//!   this process's own binary, and hand the state to a freshly exec'd copy
//!   of itself over a private socketpair (no re-fetch storm across a
//!   restart). `server::run` is the only caller.

pub mod approver;
pub mod approver_wire;
pub mod authsock;
pub mod ceremony;
mod graceful_restart;
pub mod guard;
pub mod handler;
pub mod hardening;
pub mod otp_adapter;
pub mod peer;
pub mod server;
pub mod upstream_path;
pub mod vault_state;
