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
//! - [`FilterEvaluator`] (+ [`Filter`] / [`FilterRule`] / the matchers): per-socket
//!   key filters that restrict which public keys a socket exposes and signs with
//!   (port plan Iteration 3). The `github=<user>` filter admits keys published at
//!   `github.com/<user>.keys`; its blob set is refreshed asynchronously by a
//!   [`GithubFetcher`] (production: `curl`) while [`GithubMatcher::matches`] reads
//!   the cache synchronously on the hot path.
//! - [`FilterEvaluator`] and the filter matchers: per-socket key visibility
//!   (port plan Iteration 3). They restrict which public keys a socket enumerates
//!   and can sign with, reading only the public side of a key.
//! - [`OpClient`] / [`discover_keys`] / [`OpKeyCache`]: 1Password (`op`) SSH-key
//!   discovery (port plan Iteration 4 / DR-011). Enumerates `op://` vault keys,
//!   resolves public keys (disk-cached), and yields a `public-key → item id` map.
//!   The private PEM is fetched lazily at sign time through the core KV
//!   ([`private_key_argv`] as a [`cache_warden::ValueSource::Command`]); the
//!   registry's [`KeySource::Op`] carries that fetch spec. The op CLI sits behind
//!   the [`OpClient`] trait so discovery is tested with a fake (no `op` in CI).
//! - [`chain_allowed`] / [`chain_gate_passes`]: process access policy, shared by
//!   the socket layer (port plan Iteration 5) and the key layer (DR-0012). Decide
//!   whether a requester's process ancestry is admitted by an `allowed_processes`
//!   list (empty = unrestricted; otherwise an OR over the chain on exact
//!   executable basename). [`chain_gate_passes`] adds the fail-closed handling for
//!   an unidentifiable requester. The generic ancestry walk lives in the core;
//!   this is the policy interpretation half (DR-0004).

mod codec;
mod error;
mod filter;
mod message;
mod op;
mod op_cache;
mod op_discovery;
mod process_policy;
mod registry;
mod signer;
mod upstream;

pub use codec::AgentCodec;
pub use error::{Error, Result};
pub use filter::{
    CommentMatcher, Filter, FilterEvaluator, FilterGroup, FilterRule, FingerprintMatcher,
    GithubFetcher, GithubMatcher, KeyTypeMatcher, KeyfileMatcher, PubkeyMatcher, RealGithubFetcher,
    parse_keys,
};
pub use message::{AgentMessage, Identity, MessageType, SignRequestFields};
pub use op::{OpClient, OpKeyInfo, OpSource, RealOpClient, private_key_argv, validate_item_id};
pub use op_cache::{CachedKey, OpKeyCache, default_cache_path};
pub use op_discovery::{DiscoveredKey, discover_keys};
pub use process_policy::{chain_allowed, chain_gate_passes};
pub use registry::{KeySource, PublicKeyRegistry, RegisteredKey};
pub use signer::sign;
pub use upstream::{Upstream, UpstreamConnection};
