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

use crate::error::Result;
use crate::op::{OpClient, OpKeyInfo, OpSource, parse_field_value, parse_item_list};
use crate::op_cache::{CachedKey, OpKeyCache};

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

/// Discover every key across `sources`, using and refreshing `cache`.
///
/// `cache` is taken by value and the updated cache is returned alongside the
/// discovered keys so the caller decides where/whether to persist it (the daemon
/// writes it back; tests inspect it). A per-source `op item list` failure aborts
/// that source's discovery and is propagated — the daemon downgrades a discovery
/// error to "this source has no keys" so startup is never blocked.
///
/// Keys are de-duplicated by fingerprint across sources (the same physical key
/// listed in two overlapping sources appears once).
pub fn discover_keys(
    client: &impl OpClient,
    sources: &[OpSource],
    cache: OpKeyCache,
) -> Result<(Vec<DiscoveredKey>, OpKeyCache)> {
    let cache_by_fp: std::collections::HashMap<String, CachedKey> = cache
        .by_fingerprint()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();

    let mut discovered: Vec<DiscoveredKey> = Vec::new();
    let mut seen_fp: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut fresh_cache = OpKeyCache::new();

    for source in sources {
        let json = client.item_list_json(source.vault.as_deref())?;
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
            });
            discovered.push(key);
        }
    }

    Ok((discovered, fresh_cache))
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

    #[test]
    fn cold_cache_resolves_every_key_via_item_get() {
        let op = FakeOp::new(LIST_TWO)
            .with_public_key("id1", "ssh-ed25519 AAAAONE")
            .with_public_key("id2", "ssh-ed25519 AAAATWO");
        let (keys, new_cache) =
            discover_keys(&op, &[OpSource::default()], OpKeyCache::new()).unwrap();
        assert_eq!(op.get_count(), 2, "both keys resolved via op item get");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].item_id, "id1");
        assert_eq!(keys[0].public_key, "ssh-ed25519 AAAAONE");
        assert_eq!(keys[0].title, "Key One");
        // The cache is rebuilt from the discovered keys.
        assert_eq!(new_cache.keys.len(), 2);
    }

    #[test]
    fn warm_cache_skips_item_get() {
        // Pre-seed the cache with both fingerprints; no op item get should run.
        let mut cache = OpKeyCache::new();
        cache.keys.push(CachedKey {
            item_id: "id1".into(),
            fingerprint: "SHA256:fp1".into(),
            public_key: "ssh-ed25519 CACHEDONE".into(),
            title: "old".into(),
            vault: "Private".into(),
        });
        cache.keys.push(CachedKey {
            item_id: "id2".into(),
            fingerprint: "SHA256:fp2".into(),
            public_key: "ssh-ed25519 CACHEDTWO".into(),
            title: "old".into(),
            vault: "Work".into(),
        });
        // No public keys registered: if discovery tried op item get it would error.
        let op = FakeOp::new(LIST_TWO);
        let (keys, _) = discover_keys(&op, &[OpSource::default()], cache).unwrap();
        assert_eq!(op.get_count(), 0, "warm cache avoids op item get");
        assert_eq!(keys.len(), 2);
        // The cached public key is reused, but the fresh title from item list wins.
        assert_eq!(keys[0].public_key, "ssh-ed25519 CACHEDONE");
        assert_eq!(keys[0].title, "Key One");
    }

    #[test]
    fn partial_cache_resolves_only_missing_keys() {
        let mut cache = OpKeyCache::new();
        cache.keys.push(CachedKey {
            item_id: "id1".into(),
            fingerprint: "SHA256:fp1".into(),
            public_key: "ssh-ed25519 CACHEDONE".into(),
            title: "old".into(),
            vault: "Private".into(),
        });
        let op = FakeOp::new(LIST_TWO).with_public_key("id2", "ssh-ed25519 AAAATWO");
        let (keys, _) = discover_keys(&op, &[OpSource::default()], cache).unwrap();
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
        let (keys, _) = discover_keys(&op, &sources, OpKeyCache::new()).unwrap();
        assert_eq!(keys.len(), 2, "deduplicated by fingerprint");
        assert_eq!(op.get_count(), 2);
    }

    #[test]
    fn item_list_failure_propagates() {
        let op = FakeOp::failing_list("op item list failed: not signed in");
        let err = discover_keys(&op, &[OpSource::default()], OpKeyCache::new()).unwrap_err();
        match err {
            Error::KeyStore(m) => assert!(m.contains("not signed in")),
            other => panic!("expected KeyStore, got {other:?}"),
        }
    }

    #[test]
    fn no_sources_discovers_nothing() {
        let op = FakeOp::new(LIST_TWO);
        let (keys, cache) = discover_keys(&op, &[], OpKeyCache::new()).unwrap();
        assert!(keys.is_empty());
        assert!(cache.keys.is_empty());
        assert_eq!(op.get_count(), 0);
    }
}
