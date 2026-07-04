//! op key discovery: enumerate 1Password SSH keys and resolve their public keys
//! (DR-011 staged cache). Produces the `public-key → item id` mapping the daemon
//! turns into core KV command entries + a public-key registry (port plan §1.4).
//!
//! # Strategy (minimal DR-011 — disk cache + `op item get`)
//!
//! For each [`OpSource`]:
//!
//! 1. `op item list` enumerates the source's SSH-key items (fingerprint → item).
//! 2. For each item, if the disk cache holds that fingerprint, reuse the cached
//!    public key (no `op item get`, no TouchID).
//! 3. Otherwise `op item get --fields public_key` resolves the public key.
//! 4. The refreshed cache is written back.
//!
//! ## Discovery-failure fallback (`op item list` failed)
//!
//! When `op item list` fails outright — op not signed in, a launchd-context
//! daemon whose biometric path never reaches the GUI session, a hung op killed
//! by the wall-clock cap — discovery does **not** drop to zero keys. Instead it
//! falls back to the disk cache: every cached key whose recorded provenance
//! matches this source (the `op --account` it was discovered under, plus the
//! source's `op://VAULT` members) is offered as a [`DiscoveryOutcome::Stale`]
//! result. The public key is not a secret and signing still forces a live `op`
//! fetch + TouchID, so serving a stale public key changes availability only, not
//! confidentiality (see the DR). Provenance bounds the fallback so one account's
//! cached key is never offered for another account's source; a legacy cache
//! entry with no recorded provenance is conservatively excluded. The disk cache
//! is left untouched on this path — a transient op outage must never discard the
//! known-good mapping.
//!
//! ## Deferred: the 1Password agent-socket fast path (DR-011 steps 3–4)
//!
//! DR-011 also probes the 1Password *agent socket* (REQUEST_IDENTITIES) to
//! resolve still-unknown fingerprints before falling back to `op item get`,
//! avoiding extra `op` calls on a cold cache. cache-warden already has an
//! [`crate::Upstream`] agent client, so the wiring is feasible — but it adds a
//! second async resolution path (fingerprint match against the agent's
//! identities) on top of the core-KV plumbing this iteration introduces. The
//! disk cache covers the steady state (warm restarts resolve with no `op item
//! get`); only the *first ever* discovery of a key pays one `op item get`. The
//! agent fast path is therefore left to a follow-up (recorded in the port plan)
//! to keep this iteration's surface focused on the core-KV / TTL wiring, which is
//! the part with no prior art in cache-warden.

use crate::error::{Error, Result};
use crate::op::{OpClient, OpKeyInfo, OpSource, parse_field_value, parse_item_list};
use crate::op_cache::{CacheProvenance, CachedKey, OpKeyCache};

/// One discovered key: its public key (OpenSSH) and how to fetch its private key.
///
/// Holds no secret — only the public key and the 1Password item id (the daemon
/// turns the id into a core-KV command source that fetches the PEM lazily).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredKey {
    /// 1Password item id (the private-key fetch handle).
    pub item_id: String,
    /// Public key in OpenSSH format (`ssh-ed25519 AAAA... comment`).
    pub public_key: String,
    /// Item title — used as the `ssh-add -l` comment.
    pub title: String,
    /// Fingerprint (`SHA256:...`); the cache key and a stable identity label.
    pub fingerprint: String,
    /// Vault name (display only).
    pub vault: String,
}

/// The outcome of discovering one source's keys.
#[derive(Debug)]
pub enum DiscoveryOutcome {
    /// `op item list` succeeded. `keys` are freshly enumerated; `cache` is the
    /// refreshed disk cache the caller should persist.
    Fresh {
        /// The freshly discovered keys.
        keys: Vec<DiscoveredKey>,
        /// The refreshed disk cache to write back.
        cache: OpKeyCache,
    },
    /// `op item list` failed. `keys` were recovered from the stale disk cache,
    /// bounded to this source's account + `op://` members. The disk cache is
    /// intentionally **not** returned: the caller must not re-save on this path
    /// (a transient op outage must never discard the known-good mapping).
    Stale {
        /// The keys recovered from the (stale) disk cache.
        keys: Vec<DiscoveredKey>,
        /// The `op item list` failure, for logging.
        error: Error,
    },
}

/// Discover every key across `sources` under the op account `account`, using and
/// refreshing `cache`.
///
/// `account` is the `op --account` these sources are discovered under (`None` =
/// the op CLI default account). It is recorded on each freshly cached key as its
/// [`CacheProvenance`] and is the boundary the discovery-failure fallback honours
/// (a cached key is only ever offered for a source whose account matches).
///
/// Returns [`DiscoveryOutcome::Fresh`] on success (with the refreshed cache to
/// persist). If `op item list` fails, returns [`DiscoveryOutcome::Stale`] with
/// the keys recovered from `cache` (bounded to `account` + the sources'
/// `op://VAULT` members) so startup keeps serving the last-known keys instead of
/// dropping to zero. A `parse` / `op item get` failure is still an `Err` (the op
/// call returned but its payload was unusable — a different failure mode from a
/// list that never returned).
///
/// Keys are de-duplicated by fingerprint across sources (the same physical key
/// listed in two overlapping sources appears once).
pub fn discover_keys(
    client: &impl OpClient,
    sources: &[OpSource],
    account: Option<&str>,
    cache: OpKeyCache,
) -> Result<DiscoveryOutcome> {
    let cache_by_fp: std::collections::HashMap<String, CachedKey> = cache
        .by_fingerprint()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();

    let mut discovered: Vec<DiscoveredKey> = Vec::new();
    let mut seen_fp: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut fresh_cache = OpKeyCache::new();

    for source in sources {
        let json = match client.item_list_json(source.vault.as_deref()) {
            Ok(json) => json,
            // `op item list` failed: fall back to the disk cache (P2 hotfix).
            // Every remaining source would fail the same way (one op process,
            // one integration channel), so recover the cache subset belonging to
            // this account + members now and stop, without touching the cache.
            Err(error) => {
                let keys = fallback_from_cache(&cache, sources, account);
                return Ok(DiscoveryOutcome::Stale { keys, error });
            }
        };
        let infos = parse_item_list(&json, source.item.as_deref())?;
        for info in infos {
            if !seen_fp.insert(info.fingerprint.clone()) {
                continue; // already discovered via an earlier source
            }
            let key = resolve_one(client, &info, &cache_by_fp)?;
            fresh_cache.keys.push(CachedKey {
                item_id: key.item_id.clone(),
                fingerprint: key.fingerprint.clone(),
                public_key: key.public_key.clone(),
                title: key.title.clone(),
                vault: key.vault.clone(),
                // Record the account this key was discovered under so a later
                // discovery-failure fallback can bound this key to its source.
                provenance: Some(CacheProvenance {
                    account: account.map(str::to_string),
                }),
            });
            discovered.push(key);
        }
    }

    Ok(DiscoveryOutcome::Fresh {
        keys: discovered,
        cache: fresh_cache,
    })
}

/// Recover a source's keys from the disk `cache` when `op item list` failed.
///
/// Only entries that (1) carry a recorded [`CacheProvenance`] whose `account`
/// equals `account`, (2) match at least one of `sources`' vault/item filters,
/// and (3) hold a non-empty public key are offered. A legacy entry (no
/// provenance) is excluded — we cannot prove which source it belongs to, so the
/// conservative choice is to never let it cross a source boundary. De-duplicated
/// by fingerprint (a key listed by two overlapping members appears once).
fn fallback_from_cache(
    cache: &OpKeyCache,
    sources: &[OpSource],
    account: Option<&str>,
) -> Vec<DiscoveredKey> {
    let mut out: Vec<DiscoveredKey> = Vec::new();
    let mut seen_fp: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &cache.keys {
        // (1) Provenance must be known and its account must match this source's.
        // A legacy entry (`provenance == None`) is never fallback-eligible.
        let Some(provenance) = &entry.provenance else {
            continue;
        };
        if provenance.account.as_deref() != account {
            continue;
        }
        // (2) The entry must fall inside at least one of this source's members
        // (vault / item), so a fallback never crosses a vault boundary either.
        if !sources.iter().any(|s| source_matches(s, entry)) {
            continue;
        }
        // (3) An entry with no usable public key would only be dropped later by
        // the registry; skip it here so the reported key count reflects real
        // signing capacity.
        if entry.public_key.is_empty() {
            continue;
        }
        if !seen_fp.insert(entry.fingerprint.clone()) {
            continue;
        }
        out.push(DiscoveredKey {
            item_id: entry.item_id.clone(),
            public_key: entry.public_key.clone(),
            title: entry.title.clone(),
            fingerprint: entry.fingerprint.clone(),
            vault: entry.vault.clone(),
        });
    }
    out
}

/// Whether a cached `entry` falls inside `source`'s vault/item filter.
///
/// Mirrors [`parse_item_list`]'s live filtering: a `None` vault/item matches any
/// value; a `Some` vault matches the entry's vault name exactly; a `Some` item
/// matches the entry's title or item id exactly. This keeps the fallback bounded
/// to exactly the members the source would have enumerated live.
fn source_matches(source: &OpSource, entry: &CachedKey) -> bool {
    if let Some(vault) = &source.vault
        && &entry.vault != vault
    {
        return false;
    }
    if let Some(item) = &source.item
        && &entry.title != item
        && &entry.item_id != item
    {
        return false;
    }
    true
}

/// Resolve one listed item's public key: disk cache hit, else `op item get`.
fn resolve_one(
    client: &impl OpClient,
    info: &OpKeyInfo,
    cache_by_fp: &std::collections::HashMap<String, CachedKey>,
) -> Result<DiscoveredKey> {
    if let Some(cached) = cache_by_fp.get(&info.fingerprint) {
        // Trust the cached public key, but keep the fresh list's item id / title
        // / vault (an item could have been renamed or moved between runs).
        return Ok(DiscoveredKey {
            item_id: info.item_id.clone(),
            public_key: cached.public_key.clone(),
            title: info.title.clone(),
            fingerprint: info.fingerprint.clone(),
            vault: info.vault_name.clone(),
        });
    }
    let json = client.item_get_public_key_json(&info.item_id)?;
    let public_key = parse_field_value(&json)?;
    Ok(DiscoveredKey {
        item_id: info.item_id.clone(),
        public_key,
        title: info.title.clone(),
        fingerprint: info.fingerprint.clone(),
        vault: info.vault_name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::cell::RefCell;

    /// A fake `op` CLI: serves canned `item list` JSON and counts/records
    /// `item get` calls so tests can assert the cache fast path avoids them.
    struct FakeOp {
        list_json: String,
        /// item_id → public-key field JSON returned by `item get`.
        public_keys: std::collections::HashMap<String, String>,
        /// item ids that `item get` was asked to resolve (in order).
        get_calls: RefCell<Vec<String>>,
        /// If set, `item_list_json` fails with this message.
        list_error: Option<String>,
    }

    impl FakeOp {
        fn new(list_json: &str) -> Self {
            Self {
                list_json: list_json.into(),
                public_keys: std::collections::HashMap::new(),
                get_calls: RefCell::new(Vec::new()),
                list_error: None,
            }
        }
        fn with_public_key(mut self, item_id: &str, openssh: &str) -> Self {
            self.public_keys.insert(
                item_id.into(),
                format!(r#"{{"id":"public_key","value":"{openssh}"}}"#),
            );
            self
        }
        fn failing_list(msg: &str) -> Self {
            let mut f = Self::new("[]");
            f.list_error = Some(msg.into());
            f
        }
        fn get_count(&self) -> usize {
            self.get_calls.borrow().len()
        }
    }

    impl OpClient for FakeOp {
        fn item_list_json(&self, _vault: Option<&str>) -> Result<Vec<u8>> {
            match &self.list_error {
                Some(m) => Err(Error::KeyStore(m.clone())),
                None => Ok(self.list_json.clone().into_bytes()),
            }
        }
        fn item_get_public_key_json(&self, item_id: &str) -> Result<Vec<u8>> {
            self.get_calls.borrow_mut().push(item_id.to_string());
            self.public_keys
                .get(item_id)
                .cloned()
                .map(String::into_bytes)
                .ok_or_else(|| Error::KeyStore(format!("no public key for {item_id}")))
        }
        fn item_get_private_key_json(&self, item_id: &str) -> Result<Vec<u8>> {
            // Discovery never fetches the private key; fail loudly if it does.
            Err(Error::KeyStore(format!(
                "private key fetch is not part of discovery: {item_id}"
            )))
        }
    }

    const LIST_TWO: &str = r#"[
        {"id":"id1","title":"Key One","vault":{"id":"v","name":"Private"},
         "additional_information":"SHA256:fp1"},
        {"id":"id2","title":"Key Two","vault":{"id":"v","name":"Work"},
         "additional_information":"SHA256:fp2"}
    ]"#;

    /// Build a cached entry for fallback tests. `provenance`: `None` = legacy
    /// entry (pre-provenance schema, unknown origin — never fallback-eligible);
    /// `Some(account)` = discovered under that `op --account` (`Some(None)` =
    /// the op CLI default account, which is a *known* provenance).
    fn cached(id: &str, fp: &str, vault: &str, provenance: Option<Option<&str>>) -> CachedKey {
        CachedKey {
            item_id: id.into(),
            fingerprint: fp.into(),
            public_key: format!("ssh-ed25519 AAAA{id}"),
            title: format!("title-{id}"),
            vault: vault.into(),
            provenance: provenance.map(|account| CacheProvenance {
                account: account.map(str::to_string),
            }),
        }
    }

    /// Unwrap a Fresh outcome (panics on Stale — the test expected a live list).
    fn expect_fresh(outcome: DiscoveryOutcome) -> (Vec<DiscoveredKey>, OpKeyCache) {
        match outcome {
            DiscoveryOutcome::Fresh { keys, cache } => (keys, cache),
            DiscoveryOutcome::Stale { .. } => panic!("expected Fresh, got Stale"),
        }
    }

    /// Unwrap a Stale outcome (panics on Fresh — the test expected a list failure).
    /// Note Stale carries no cache: the type itself prevents the caller from
    /// re-saving on this path (a transient op outage must not clobber the file).
    fn expect_stale(outcome: DiscoveryOutcome) -> (Vec<DiscoveredKey>, Error) {
        match outcome {
            DiscoveryOutcome::Stale { keys, error } => (keys, error),
            DiscoveryOutcome::Fresh { .. } => panic!("expected Stale, got Fresh"),
        }
    }

    #[test]
    fn cold_cache_resolves_every_key_via_item_get() {
        let op = FakeOp::new(LIST_TWO)
            .with_public_key("id1", "ssh-ed25519 AAAAONE")
            .with_public_key("id2", "ssh-ed25519 AAAATWO");
        let (keys, new_cache) = expect_fresh(
            discover_keys(
                &op,
                &[OpSource::default()],
                Some("acct-a"),
                OpKeyCache::new(),
            )
            .unwrap(),
        );
        assert_eq!(op.get_count(), 2, "both keys resolved via op item get");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].item_id, "id1");
        assert_eq!(keys[0].public_key, "ssh-ed25519 AAAAONE");
        assert_eq!(keys[0].title, "Key One");
        // The cache is rebuilt from the discovered keys, and every fresh entry
        // records the account it was discovered under — the provenance the
        // discovery-failure fallback later uses as its source boundary.
        assert_eq!(new_cache.keys.len(), 2);
        for entry in &new_cache.keys {
            assert_eq!(
                entry.provenance,
                Some(CacheProvenance {
                    account: Some("acct-a".into())
                }),
                "fresh discovery must stamp provenance on every cached entry"
            );
        }
    }

    #[test]
    fn warm_cache_skips_item_get() {
        // Pre-seed the cache with both fingerprints; no op item get should run.
        // The entries are deliberately legacy (provenance: None): a legacy entry
        // is excluded from the *failure fallback*, but remains a perfectly good
        // warm-cache hint for a *successful* discovery — the fingerprint fast
        // path does not care about provenance.
        let mut cache = OpKeyCache::new();
        let mut one = cached("id1", "SHA256:fp1", "Private", None);
        one.public_key = "ssh-ed25519 CACHEDONE".into();
        let mut two = cached("id2", "SHA256:fp2", "Work", None);
        two.public_key = "ssh-ed25519 CACHEDTWO".into();
        cache.keys.push(one);
        cache.keys.push(two);
        // No public keys registered: if discovery tried op item get it would error.
        let op = FakeOp::new(LIST_TWO);
        let (keys, _) =
            expect_fresh(discover_keys(&op, &[OpSource::default()], None, cache).unwrap());
        assert_eq!(op.get_count(), 0, "warm cache avoids op item get");
        assert_eq!(keys.len(), 2);
        // The cached public key is reused, but the fresh title from item list wins.
        assert_eq!(keys[0].public_key, "ssh-ed25519 CACHEDONE");
        assert_eq!(keys[0].title, "Key One");
    }

    #[test]
    fn partial_cache_resolves_only_missing_keys() {
        let mut cache = OpKeyCache::new();
        let mut one = cached("id1", "SHA256:fp1", "Private", None);
        one.public_key = "ssh-ed25519 CACHEDONE".into();
        cache.keys.push(one);
        let op = FakeOp::new(LIST_TWO).with_public_key("id2", "ssh-ed25519 AAAATWO");
        let (keys, _) =
            expect_fresh(discover_keys(&op, &[OpSource::default()], None, cache).unwrap());
        // Only the uncached id2 hit op item get.
        assert_eq!(op.get_count(), 1);
        assert_eq!(op.get_calls.borrow()[0], "id2");
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn duplicate_fingerprint_across_sources_appears_once() {
        // Two sources both list fp1; the key is discovered once (no double get).
        let op = FakeOp::new(LIST_TWO)
            .with_public_key("id1", "ssh-ed25519 AAAAONE")
            .with_public_key("id2", "ssh-ed25519 AAAATWO");
        let sources = vec![OpSource::default(), OpSource::default()];
        let (keys, _) =
            expect_fresh(discover_keys(&op, &sources, None, OpKeyCache::new()).unwrap());
        assert_eq!(keys.len(), 2, "deduplicated by fingerprint");
        assert_eq!(op.get_count(), 2);
    }

    #[test]
    fn no_sources_discovers_nothing() {
        let op = FakeOp::new(LIST_TWO);
        let (keys, cache) = expect_fresh(discover_keys(&op, &[], None, OpKeyCache::new()).unwrap());
        assert!(keys.is_empty());
        assert!(cache.keys.is_empty());
        assert_eq!(op.get_count(), 0);
    }

    // ---- discovery-failure fallback (`op item list` failed) ----
    //
    // Spec change note: `op item list` failure used to propagate as `Err` (the
    // caller flattened it to zero keys — the dogfood-critical "0-key serving"
    // symptom of issue 2026-06-13-op-discovery-blocks-startup). It now returns
    // `Ok(Stale { .. })` with the keys recovered from the disk cache, bounded by
    // recorded provenance. A parse / `op item get` failure still propagates as
    // `Err` — the op call *returned* but its payload was unusable, a different
    // failure mode from a list that never came back.

    #[test]
    fn list_failure_with_empty_cache_yields_stale_zero_keys() {
        // No cache to fall back on: the outcome is still Stale (not Err), with
        // zero keys — the caller serves an empty socket exactly as before the
        // fallback existed, and logs the preserved list error.
        let op = FakeOp::failing_list("op item list failed: not signed in");
        let (keys, error) = expect_stale(
            discover_keys(&op, &[OpSource::default()], None, OpKeyCache::new()).unwrap(),
        );
        assert!(keys.is_empty());
        assert!(
            error.to_string().contains("not signed in"),
            "list error preserved for logging"
        );
    }

    #[test]
    fn list_failure_falls_back_to_provenance_matching_cache() {
        // The P2 hotfix itself: list fails (launchd-context op hang / timeout),
        // but the cache holds keys previously discovered under the SAME account
        // → they are served (signing degrades to "stale enumeration", not to a
        // dead socket). A key cached under a DIFFERENT account is never offered:
        // provenance is the source boundary.
        let mut cache = OpKeyCache::new();
        cache.keys.push(cached(
            "mine",
            "SHA256:fpA",
            "Private",
            Some(Some("acct-a")),
        ));
        cache.keys.push(cached(
            "theirs",
            "SHA256:fpB",
            "Private",
            Some(Some("acct-b")),
        ));
        let op = FakeOp::failing_list("timed out after 30s");
        let (keys, _) = expect_stale(
            discover_keys(&op, &[OpSource::default()], Some("acct-a"), cache).unwrap(),
        );
        assert_eq!(keys.len(), 1, "only the same-account key is offered");
        assert_eq!(keys[0].item_id, "mine");
        assert_eq!(op.get_count(), 0, "fallback never invokes op item get");
    }

    #[test]
    fn fallback_excludes_legacy_entries_without_provenance() {
        // A legacy entry (pre-provenance schema) proves nothing about which
        // source it belongs to. The conservative rule: it is NEVER offered by
        // the fallback, even if every other field looks plausible.
        let mut cache = OpKeyCache::new();
        cache
            .keys
            .push(cached("legacy", "SHA256:fpL", "Private", None));
        let op = FakeOp::failing_list("boom");
        let (keys, _) =
            expect_stale(discover_keys(&op, &[OpSource::default()], None, cache).unwrap());
        assert!(keys.is_empty(), "legacy entries are not fallback-eligible");
    }

    #[test]
    fn fallback_default_account_is_a_known_provenance() {
        // `Some(CacheProvenance { account: None })` = discovered under the op
        // CLI default account — a KNOWN provenance, distinct from a legacy
        // entry. It matches a default-account discovery (account = None) and
        // does not match a named account.
        let mut cache = OpKeyCache::new();
        cache
            .keys
            .push(cached("dflt", "SHA256:fpD", "Private", Some(None)));
        let op = FakeOp::failing_list("boom");
        let (keys, _) =
            expect_stale(discover_keys(&op, &[OpSource::default()], None, cache.clone()).unwrap());
        assert_eq!(
            keys.len(),
            1,
            "default-account entry serves a default-account source"
        );
        let (keys, _) = expect_stale(
            discover_keys(&op, &[OpSource::default()], Some("acct-a"), cache).unwrap(),
        );
        assert!(
            keys.is_empty(),
            "default-account entry never serves a named account"
        );
    }

    #[test]
    fn fallback_respects_source_vault_and_item_filters() {
        // The fallback mirrors the live `op item list` filters: a source bound
        // to one vault (or one item) only recovers cache entries that fall
        // inside it — a fallback never widens what the source would have
        // enumerated live.
        let mut cache = OpKeyCache::new();
        cache
            .keys
            .push(cached("priv", "SHA256:fpP", "Private", Some(None)));
        cache
            .keys
            .push(cached("work", "SHA256:fpW", "Work", Some(None)));
        let op = FakeOp::failing_list("boom");
        let vault_source = OpSource {
            vault: Some("Private".into()),
            item: None,
        };
        let (keys, _) =
            expect_stale(discover_keys(&op, &[vault_source], None, cache.clone()).unwrap());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].item_id, "priv", "vault filter bounds the fallback");
        // Item filter matches title or item id (same as live post-filtering).
        let item_source = OpSource {
            vault: None,
            item: Some("title-work".into()),
        };
        let (keys, _) = expect_stale(discover_keys(&op, &[item_source], None, cache).unwrap());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].item_id, "work", "item filter bounds the fallback");
    }

    #[test]
    fn fallback_excludes_entries_with_empty_public_key() {
        // An entry with no usable public key cannot serve REQUEST_IDENTITIES;
        // offering it would inflate the reported key count without adding any
        // signing capacity, so the fallback skips it.
        let mut cache = OpKeyCache::new();
        let mut empty = cached("empty", "SHA256:fpE", "Private", Some(None));
        empty.public_key = String::new();
        cache.keys.push(empty);
        let op = FakeOp::failing_list("boom");
        let (keys, _) =
            expect_stale(discover_keys(&op, &[OpSource::default()], None, cache).unwrap());
        assert!(
            keys.is_empty(),
            "empty-pubkey entries add no signing capacity"
        );
    }

    #[test]
    fn fallback_dedups_by_fingerprint() {
        // The same physical key cached twice (e.g. via overlapping members in a
        // past discovery) is offered once — mirrors the live dedup rule.
        let mut cache = OpKeyCache::new();
        cache
            .keys
            .push(cached("dup1", "SHA256:same", "Private", Some(None)));
        cache
            .keys
            .push(cached("dup2", "SHA256:same", "Private", Some(None)));
        let op = FakeOp::failing_list("boom");
        let (keys, _) =
            expect_stale(discover_keys(&op, &[OpSource::default()], None, cache).unwrap());
        assert_eq!(keys.len(), 1, "fallback deduplicates by fingerprint");
    }
}
