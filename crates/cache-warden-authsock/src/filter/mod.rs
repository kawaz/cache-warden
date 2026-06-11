//! Per-socket key filters (port plan Iteration 3).
//!
//! Ported from authsock-warden `src/filter/`. A filter restricts *which* public
//! keys a socket exposes (in REQUEST_IDENTITIES) and can sign with (in
//! SIGN_REQUEST), so one socket can carry, say, only GitHub keys while another
//! carries everything. Filtering reads only the public side of a key (blob /
//! comment / type / fingerprint) — it never touches private material.
//!
//! - Matchers: [`CommentMatcher`], [`FingerprintMatcher`], [`KeyTypeMatcher`],
//!   [`PubkeyMatcher`], [`KeyfileMatcher`].
//! - [`FilterRule`] wraps one matcher with optional `not-` negation; [`Filter`]
//!   is the matcher enum it holds.
//! - [`FilterEvaluator`] combines rules as OR-of-AND (groups ANDed within, ORed
//!   across); an empty evaluator matches every key (an unfiltered socket).
//!
//! The upstream `github=<user>` filter is **not** ported in this iteration: it
//! fetches keys over HTTP and would add a heavy network-client dependency. It is
//! recorded as deferred (see `rule.rs`). `keyfile` (local file, no network) *is*
//! ported.

mod comment;
mod evaluator;
mod fingerprint;
mod keyfile;
mod keytype;
mod pubkey;
mod rule;

pub use comment::CommentMatcher;
pub use evaluator::{FilterEvaluator, FilterGroup};
pub use fingerprint::FingerprintMatcher;
pub use keyfile::KeyfileMatcher;
pub use keytype::KeyTypeMatcher;
pub use pubkey::PubkeyMatcher;
pub use rule::{Filter, FilterRule};
