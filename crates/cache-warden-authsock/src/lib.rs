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
//! It carries forward the SSH agent protocol message / codec, the local signer,
//! and the public-key registry from authsock-warden. Key sourcing (op discovery),
//! filters, policy, and the in-process listener wiring (DR-0008, which lives in
//! the CLI crate) are added in later port iterations.
//!
//! # Currently ported
//!
//! - [`MessageType`]: SSH agent message-type byte ⇔ enum.
//! - [`AgentMessage`]: a typed message ([`MessageType`] + payload bytes) with
//!   encode / decode and the REQUEST_IDENTITIES / SIGN_REQUEST builders/parsers.
//! - [`Identity`]: a public key blob + comment, with `ssh-key`-backed parsing.
//! - [`SignRequestFields`]: the parsed SIGN_REQUEST payload (key blob, data, flags).
//! - [`AgentCodec`]: length-prefixed async framing over a connection.
//! - [`sign`]: stateless local signing (Ed25519 / RSA) from a borrowed PEM,
//!   producing an SSH wire signature blob.
//! - [`PublicKeyRegistry`]: value-free map from a wire public-key blob to the
//!   core KV key holding the private PEM (the REQUEST_IDENTITIES source).
//! - [`Upstream`]: a connection to another agent socket whose keys are merged in
//!   and whose signatures are forwarded (the agent-proxy KeySource, DR-0004
//!   decision 8 / port plan Iteration 2).

mod codec;
mod error;
mod message;
mod registry;
mod signer;
mod upstream;

pub use codec::AgentCodec;
pub use error::{Error, Result};
pub use message::{AgentMessage, Identity, MessageType, SignRequestFields};
pub use registry::{PublicKeyRegistry, RegisteredKey};
pub use signer::sign;
pub use upstream::{Upstream, UpstreamConnection};
