//! GitHub user public-key matching filter (`github=<user>`).
//!
//! Ported from authsock-warden `src/filter/github.rs`, but with the network
//! fetch redesigned for cache-warden's synchronous match path.
//!
//! A `github=<user>` filter admits exactly the keys published at
//! `https://github.com/<user>.keys`. Each line of that endpoint is an OpenSSH
//! public key; the filter compares the *wire-format public-key blob* of every
//! presented identity against the set of published blobs. Only public material
//! is ever handled — the private side is never touched.
//!
//! # Why fetch and match are split (the load-bearing design constraint)
//!
//! [`crate::filter::FilterEvaluator::matches`] is **synchronous** and is called
//! from the daemon's async hot path ([`request_identities`] / `sign_request`).
//! Running a blocking `curl` inside [`GithubMatcher::matches`] would stall the
//! tokio runtime, so the two halves are separated:
//!
//! - [`GithubMatcher::matches`] only takes a `RwLock` read and checks set
//!   membership — no network, no `await`, microseconds.
//! - Fetching is done by an async caller (the daemon's startup fetch and its
//!   background refresh task) which then writes the result back into the shared
//!   [`GithubCache`] via [`GithubMatcher::set_keys`] / [`GithubMatcher::mark_failed`].
//!
//! # Fail-closed (differs from authsock-warden)
//!
//! When the published key set is unavailable (never fetched, or the last fetch
//! failed — network down, timeout, non-2xx, parse error) the cache is **invalid**
//! and [`GithubMatcher::matches`] returns `false` for every key. This is the
//! safe side: an unverifiable key is *not* exposed. authsock-warden's matcher is
//! effectively fail-closed too (an empty matcher list matches nothing), and
//! cache-warden makes that explicit with the `valid` flag so a stale-but-failed
//! refresh cannot keep admitting keys past its window without a successful
//! re-fetch confirming them.

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ssh_encoding::Encode;
use ssh_key::PublicKey;

use crate::error::{Error, Result};
use crate::message::Identity;

/// The shared, mutable key cache behind a [`GithubMatcher`].
///
/// Holds the set of published wire-format public-key blobs, when it was last
/// (re)fetched, and whether the last fetch succeeded. [`GithubMatcher::matches`]
/// only admits a key when `valid` is `true` **and** the key's blob is in `keys`.
#[derive(Debug, Default)]
pub struct GithubCache {
    /// Wire-format public-key blobs published for the user (empty until fetched).
    keys: HashSet<Vec<u8>>,
    /// When the cache was last written (by a successful fetch or a failure),
    /// or `None` if never fetched. Drives [`GithubMatcher::needs_refresh`].
    fetched_at: Option<Instant>,
    /// Whether the cached `keys` set reflects a successful fetch. `false` means
    /// fail-closed: [`GithubMatcher::matches`] admits nothing.
    valid: bool,
}

/// A `github=<user>` filter: admits keys published at `github.com/<user>.keys`.
///
/// Cheaply cloneable — clones share the same [`GithubCache`] (an [`Arc`]), so a
/// background refresh through one clone is visible to every other clone (and to
/// the synchronous [`GithubMatcher::matches`] on the hot path).
#[derive(Debug, Clone)]
pub struct GithubMatcher {
    user: String,
    cache: Arc<RwLock<GithubCache>>,
}

impl GithubMatcher {
    /// Create a matcher for `user` with an empty (invalid) cache.
    ///
    /// The cache is fail-closed until a successful fetch calls [`Self::set_keys`];
    /// [`Self::matches`] returns `false` for every key until then.
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            cache: Arc::new(RwLock::new(GithubCache::default())),
        }
    }

    /// The GitHub username this matcher fetches keys for.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Whether `identity`'s public-key blob is one of the user's published keys.
    ///
    /// Synchronous and lock-only (no network): the hot path calls this. Returns
    /// `false` when the cache is invalid (never fetched / last fetch failed),
    /// when the read lock is poisoned, or when the blob is not in the set —
    /// fail-closed in every uncertain case.
    pub fn matches(&self, identity: &Identity) -> bool {
        match self.cache.read() {
            Ok(cache) => cache.valid && cache.keys.contains(identity.key_blob.as_ref()),
            Err(_) => false,
        }
    }

    /// Install a freshly-fetched key set, marking the cache valid as of `now`.
    pub fn set_keys(&self, keys: HashSet<Vec<u8>>, now: Instant) {
        if let Ok(mut cache) = self.cache.write() {
            cache.keys = keys;
            cache.fetched_at = Some(now);
            cache.valid = true;
        }
    }

    /// Record a failed fetch: keep the cache invalid (fail-closed) but stamp
    /// `fetched_at` so [`Self::needs_refresh`] backs off until the next window
    /// rather than hammering a down endpoint on every request.
    pub fn mark_failed(&self, now: Instant) {
        if let Ok(mut cache) = self.cache.write() {
            cache.valid = false;
            cache.fetched_at = Some(now);
        }
    }

    /// Whether the cache is due for a (re)fetch at `now` given `ttl`.
    ///
    /// `true` when never fetched, or when `ttl` has elapsed since the last
    /// fetch attempt (success or failure). A poisoned lock reports `true` so the
    /// caller attempts a refresh (which fail-closes rather than serves stale).
    pub fn needs_refresh(&self, ttl: Duration, now: Instant) -> bool {
        match self.cache.read() {
            Ok(cache) => match cache.fetched_at {
                None => true,
                Some(at) => now.duration_since(at) >= ttl,
            },
            Err(_) => true,
        }
    }
}

/// Abstraction over fetching a GitHub user's published keys, behind a trait so
/// the daemon's fetch/refresh logic is tested against a fake (no real network /
/// `curl` in CI). The production implementation is [`RealGithubFetcher`].
pub trait GithubFetcher {
    /// Fetch the wire-format public-key blobs published for `user`, giving up
    /// after `timeout`. An error (network down, timeout, non-2xx, spawn failure)
    /// must be surfaced so the caller can [`GithubMatcher::mark_failed`].
    fn fetch_keys(&self, user: &str, timeout: Duration) -> Result<HashSet<Vec<u8>>>;
}

/// Production [`GithubFetcher`]: shells out to `curl` (no in-process HTTP client).
///
/// Mirrors `op.rs`'s "drive an external CLI" approach so cache-warden adds no
/// HTTP-client dependency. Runs
/// `curl -fsSL --max-time <secs> https://github.com/<user>.keys` and parses the
/// body into wire blobs via [`parse_keys`].
#[derive(Debug, Clone, Default)]
pub struct RealGithubFetcher;

impl RealGithubFetcher {
    /// A fetcher using the system `curl`.
    pub fn new() -> Self {
        Self
    }
}

impl GithubFetcher for RealGithubFetcher {
    fn fetch_keys(&self, user: &str, timeout: Duration) -> Result<HashSet<Vec<u8>>> {
        // `user` is validated alphanumeric+hyphen at parse time (see rule.rs), so
        // it cannot inject a curl flag or extra URL segment here. The `--` before
        // the URL is belt-and-suspenders: even a hypothetical `-`-leading value
        // could never be read as a flag.
        let url = format!("https://github.com/{user}.keys");
        let secs = timeout.as_secs().max(1).to_string();
        let output = Command::new("curl")
            .args(["-fsSL", "--max-time", &secs, "--", &url])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| Error::Filter(format!("failed to execute curl for github keys: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Filter(format!(
                "curl failed fetching github keys for {user}: {}",
                stderr.trim()
            )));
        }
        let body = String::from_utf8_lossy(&output.stdout);
        Ok(parse_keys(&body, user))
    }
}

/// Parse a `.keys` endpoint body into the set of wire-format public-key blobs.
///
/// Each non-empty line is one OpenSSH public key; a line that fails to parse is
/// skipped with a warning (so one malformed line cannot drop the whole set).
/// `user` is only used to label the warning. Blank lines are ignored.
pub fn parse_keys(body: &str, user: &str) -> HashSet<Vec<u8>> {
    let mut blobs = HashSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match blob_from_openssh(line) {
            Ok(blob) => {
                blobs.insert(blob);
            }
            Err(e) => {
                eprintln!("cache-warden: github filter: skipping unparseable key for {user}: {e}");
            }
        }
    }
    blobs
}

/// Derive a wire-format public-key blob from one OpenSSH public-key line.
///
/// Uses the same `key_data().encode()` encoding the registry and [`Identity`]
/// use, so equality with an enumerated identity's blob is exact.
fn blob_from_openssh(line: &str) -> Result<Vec<u8>> {
    let key = PublicKey::from_openssh(line)
        .map_err(|e| Error::Filter(format!("invalid public key: {e}")))?;
    let mut blob = Vec::new();
    key.key_data()
        .encode(&mut blob)
        .map_err(|e| Error::Filter(format!("failed to encode key: {e}")))?;
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    // Two distinct, valid ed25519 public keys (different 32-byte bodies).
    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a@host";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINJTQuhKj5p8u3wQpx0Kk1jKBgJ4z9z+5pXg8mWw0aBc b@host";

    fn blob_of(openssh: &str) -> Vec<u8> {
        blob_from_openssh(openssh).unwrap()
    }

    fn identity_of(openssh: &str) -> Identity {
        Identity::new(Bytes::from(blob_of(openssh)), String::new())
    }

    #[test]
    fn user_is_recorded() {
        assert_eq!(GithubMatcher::new("kawaz").user(), "kawaz");
    }

    #[test]
    fn fresh_matcher_is_fail_closed() {
        // Never fetched => cache invalid => admits nothing, even a real key.
        let m = GithubMatcher::new("kawaz");
        assert!(!m.matches(&identity_of(KEY_A)));
    }

    #[test]
    fn set_keys_admits_only_the_published_blobs() {
        let m = GithubMatcher::new("kawaz");
        let mut keys = HashSet::new();
        keys.insert(blob_of(KEY_A));
        m.set_keys(keys, Instant::now());

        assert!(m.matches(&identity_of(KEY_A)));
        assert!(!m.matches(&identity_of(KEY_B))); // not published
    }

    #[test]
    fn mark_failed_keeps_it_fail_closed() {
        // Even if a prior success had populated keys, a subsequent failure must
        // not keep admitting them — valid flips to false.
        let m = GithubMatcher::new("kawaz");
        let mut keys = HashSet::new();
        keys.insert(blob_of(KEY_A));
        m.set_keys(keys, Instant::now());
        assert!(m.matches(&identity_of(KEY_A)));

        m.mark_failed(Instant::now());
        assert!(!m.matches(&identity_of(KEY_A)));
    }

    #[test]
    fn needs_refresh_is_true_before_any_fetch() {
        let m = GithubMatcher::new("kawaz");
        assert!(m.needs_refresh(Duration::from_secs(3600), Instant::now()));
    }

    #[test]
    fn needs_refresh_is_false_within_ttl_after_fetch() {
        let m = GithubMatcher::new("kawaz");
        let now = Instant::now();
        m.set_keys(HashSet::new(), now);
        // A moment later, still well within a 1h TTL.
        assert!(!m.needs_refresh(Duration::from_secs(3600), now));
    }

    #[test]
    fn needs_refresh_is_true_once_ttl_elapsed() {
        let m = GithubMatcher::new("kawaz");
        let fetched = Instant::now();
        m.set_keys(HashSet::new(), fetched);
        // `now` is ttl past the fetch instant.
        let later = fetched + Duration::from_secs(7200);
        assert!(m.needs_refresh(Duration::from_secs(3600), later));
    }

    #[test]
    fn mark_failed_also_stamps_fetched_at_for_backoff() {
        // After a failure, a refresh within TTL is not due (we backed off).
        let m = GithubMatcher::new("kawaz");
        let now = Instant::now();
        m.mark_failed(now);
        assert!(!m.needs_refresh(Duration::from_secs(3600), now));
    }

    #[test]
    fn clones_share_one_cache() {
        let m = GithubMatcher::new("kawaz");
        let clone = m.clone();
        let mut keys = HashSet::new();
        keys.insert(blob_of(KEY_A));
        // Writing through one clone is visible through the other.
        clone.set_keys(keys, Instant::now());
        assert!(m.matches(&identity_of(KEY_A)));
    }

    // ---- parse_keys ----

    #[test]
    fn parse_keys_collects_valid_lines() {
        let body = format!("{KEY_A}\n{KEY_B}\n");
        let blobs = parse_keys(&body, "kawaz");
        assert_eq!(blobs.len(), 2);
        assert!(blobs.contains(&blob_of(KEY_A)));
        assert!(blobs.contains(&blob_of(KEY_B)));
    }

    #[test]
    fn parse_keys_skips_blank_and_unparseable_lines() {
        let body = format!("\n{KEY_A}\nnot a valid key line\n   \n");
        let blobs = parse_keys(&body, "kawaz");
        // Only the one valid key survives; blanks and the junk line are dropped.
        assert_eq!(blobs.len(), 1);
        assert!(blobs.contains(&blob_of(KEY_A)));
    }

    #[test]
    fn parse_keys_empty_body_is_empty_set() {
        assert!(parse_keys("", "kawaz").is_empty());
    }

    /// A fake [`GithubFetcher`] for the cli daemon tests' benefit, exercised here
    /// to prove the trait shape is usable without real network.
    struct FakeFetcher {
        body: String,
    }

    impl GithubFetcher for FakeFetcher {
        fn fetch_keys(&self, user: &str, _timeout: Duration) -> Result<HashSet<Vec<u8>>> {
            Ok(parse_keys(&self.body, user))
        }
    }

    #[test]
    fn fetcher_feeds_set_keys_end_to_end() {
        let fetcher = FakeFetcher {
            body: format!("{KEY_A}\n"),
        };
        let m = GithubMatcher::new("kawaz");
        let keys = fetcher
            .fetch_keys("kawaz", Duration::from_secs(10))
            .unwrap();
        m.set_keys(keys, Instant::now());
        assert!(m.matches(&identity_of(KEY_A)));
        assert!(!m.matches(&identity_of(KEY_B)));
    }
}
