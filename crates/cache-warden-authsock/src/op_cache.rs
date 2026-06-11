//! Public-key disk cache for the `op://` source (DR-011 fast path).
//!
//! Caches the `fingerprint → public-key` mapping (plus item id / title / vault
//! for display) in `$XDG_CACHE_HOME/cache-warden/op_map.json` so a restart can
//! resolve known keys without re-running `op item get` for each one. The data is
//! **not** sensitive: it holds public keys and fingerprints only, never private
//! material — so it is plain JSON (0600 for tidiness, not secrecy).
//!
//! The cache is a *hint*: a miss simply falls through to `op item get`, and any
//! read/parse/version error yields an empty cache (fail-open). The cache path is
//! injectable so tests use a temp dir instead of the user's real cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// On-disk cache format version. Bumped when the schema changes; a mismatched
/// file is ignored (treated as empty) rather than mis-parsed.
const CACHE_VERSION: u32 = 1;
const CACHE_FILENAME: &str = "op_map.json";
const APP_DIR: &str = "cache-warden";

/// One cached public key, keyed in the file by its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedKey {
    /// 1Password item id (re-validated before use; the file is user-writable).
    pub item_id: String,
    /// Key fingerprint (`SHA256:...`), the lookup key.
    pub fingerprint: String,
    /// Public key in OpenSSH format (`ssh-ed25519 AAAA...`).
    pub public_key: String,
    /// Item title (the key's comment).
    pub title: String,
    /// Vault name (display only).
    pub vault: String,
}

/// The whole cache file: a version tag plus a flat list of cached keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpKeyCache {
    /// Schema version (see [`CACHE_VERSION`]).
    pub version: u32,
    /// All cached public keys.
    pub keys: Vec<CachedKey>,
}

impl Default for OpKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OpKeyCache {
    /// An empty cache at the current version.
    pub fn new() -> Self {
        Self {
            version: CACHE_VERSION,
            keys: Vec::new(),
        }
    }

    /// Index the cache by fingerprint for O(1) lookups during discovery.
    pub fn by_fingerprint(&self) -> HashMap<&str, &CachedKey> {
        self.keys
            .iter()
            .map(|k| (k.fingerprint.as_str(), k))
            .collect()
    }

    /// Load the cache from `path`, returning an empty cache on **any** problem
    /// (missing file, unreadable, malformed JSON, version mismatch). The cache
    /// is only ever a hint, so a corrupt file must never break discovery.
    pub fn load_from(path: &Path) -> Self {
        let Ok(content) = std::fs::read_to_string(path) else {
            return Self::new();
        };
        match serde_json::from_str::<OpKeyCache>(&content) {
            Ok(cache) if cache.version == CACHE_VERSION => cache,
            _ => Self::new(),
        }
    }

    /// Load the cache from the default path ([`default_cache_path`]), or empty.
    pub fn load() -> Self {
        match default_cache_path() {
            Some(p) => Self::load_from(&p),
            None => Self::new(),
        }
    }

    /// Write the cache to `path` (creating parent dirs), best effort.
    ///
    /// A write failure is swallowed (the cache is a hint; the daemon must keep
    /// running). On unix the file is set to 0600 for tidiness — not because the
    /// contents are secret, but to avoid leaving world-readable clutter.
    pub fn save_to(&self, path: &Path) {
        if let Some(parent) = path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            return;
        }
        let Ok(content) = serde_json::to_string_pretty(self) else {
            return;
        };
        if std::fs::write(path, &content).is_err() {
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    }

    /// Write the cache to the default path ([`default_cache_path`]), best effort.
    pub fn save(&self) {
        if let Some(p) = default_cache_path() {
            self.save_to(&p);
        }
    }
}

/// The default cache file path: `$XDG_CACHE_HOME/cache-warden/op_map.json`,
/// falling back to `$HOME/.cache/cache-warden/op_map.json`.
///
/// Returns `None` when neither `XDG_CACHE_HOME` nor `HOME` is set (the cache is
/// then simply unavailable — discovery still works via `op item get`).
pub fn default_cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join(APP_DIR).join(CACHE_FILENAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fp: &str, id: &str) -> CachedKey {
        CachedKey {
            item_id: id.into(),
            fingerprint: fp.into(),
            public_key: format!("ssh-ed25519 AAAA{id}"),
            title: format!("key-{id}"),
            vault: "Private".into(),
        }
    }

    #[test]
    fn new_cache_is_empty_at_current_version() {
        let c = OpKeyCache::new();
        assert_eq!(c.version, CACHE_VERSION);
        assert!(c.keys.is_empty());
    }

    #[test]
    fn by_fingerprint_indexes_each_key() {
        let mut c = OpKeyCache::new();
        c.keys.push(key("SHA256:aaa", "abc"));
        c.keys.push(key("SHA256:bbb", "def"));
        let map = c.by_fingerprint();
        assert_eq!(map["SHA256:aaa"].item_id, "abc");
        assert_eq!(map["SHA256:bbb"].item_id, "def");
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("op_map.json");
        let mut c = OpKeyCache::new();
        c.keys.push(key("SHA256:x", "itemx"));
        c.save_to(&path);
        let loaded = OpKeyCache::load_from(&path);
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].item_id, "itemx");
    }

    #[test]
    fn save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op_map.json");
        OpKeyCache::new().save_to(&path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let c = OpKeyCache::load_from(&dir.path().join("absent.json"));
        assert!(c.keys.is_empty());
    }

    #[test]
    fn load_malformed_json_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(OpKeyCache::load_from(&path).keys.is_empty());
    }

    #[test]
    fn load_version_mismatch_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.json");
        std::fs::write(&path, r#"{"version":999,"keys":[]}"#).unwrap();
        assert!(OpKeyCache::load_from(&path).keys.is_empty());
    }
}
