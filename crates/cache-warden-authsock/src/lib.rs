//! SSH agent protocol adapter for cache-warden.
//!
//! This crate is the **authsock adapter** layered on top of the cache-warden
//! secure-secret-cache core (`cache-warden`). The core treats an SSH private key
//! as one kind of cached secret value; this crate speaks the SSH agent protocol
//! (key blob wire format, REQUEST_IDENTITIES / SIGN_REQUEST framing) that sits on
//! top of that core. See `docs/decisions/DR-0003-secure-kv-core-and-adapters.md`
//! (core vs adapter split) and `docs/decisions/DR-0004-authsock-warden-succession.md`
//! (authsock-warden succession / port plan).
//!
//! It carries forward the SSH agent protocol message and codec assets from
//! authsock-warden. Key sourcing, filters, 1Password local signing and the
//! in-process listener wiring (DR-0008) are added in later port iterations.
//!
//! # This iteration (codec)
//!
//! - [`MessageType`]: SSH agent message-type byte ⇔ enum.
//! - [`AgentMessage`]: a typed message ([`MessageType`] + payload bytes) with
//!   encode / decode and the REQUEST_IDENTITIES / SIGN_REQUEST builders/parsers.
//! - [`Identity`]: a public key blob + comment, with `ssh-key`-backed parsing.
//! - [`SignRequestFields`]: the parsed SIGN_REQUEST payload (key blob, data, flags).
//! - [`AgentCodec`]: length-prefixed async framing over a connection.

mod codec;
mod error;
mod message;

pub use codec::AgentCodec;
pub use error::{Error, Result};
pub use message::{AgentMessage, Identity, MessageType, SignRequestFields};
