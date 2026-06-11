//! Keyfile matching filter (authorized_keys format).
//!
//! Ported from authsock-warden `src/filter/keyfile.rs`. Matches an [`Identity`]
//! against the public keys listed in an `authorized_keys`-style file: comment /
//! blank lines are skipped, leading SSH options are stripped, and each key line
//! becomes a [`PubkeyMatcher`]. The file is read once at construction and can be
//! re-read with [`KeyfileMatcher::reload`].
//!
//! Two changes from upstream keep this crate's conventions: a malformed key line
//! is reported with `eprintln!` (the crate does not depend on `tracing`), and a
//! leading `~/` in the path is expanded in-crate (no `shellexpand` dependency).

use crate::error::{Error, Result};
use crate::filter::PubkeyMatcher;
use crate::message::Identity;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Matcher for keys from an `authorized_keys`-style file.
#[derive(Debug, Clone)]
pub struct KeyfileMatcher {
    path: PathBuf,
    matchers: Arc<RwLock<Vec<PubkeyMatcher>>>,
}

impl KeyfileMatcher {
    /// Create a matcher backed by the authorized_keys file at `path`.
    ///
    /// A leading `~/` is expanded to `$HOME/`. The file is read immediately;
    /// construction fails if it cannot be read.
    pub fn new(path: &str) -> Result<Self> {
        let path = expand_tilde(path);

        let matcher = Self {
            path,
            matchers: Arc::new(RwLock::new(Vec::new())),
        };

        matcher.reload()?;

        Ok(matcher)
    }

    /// The configured keyfile path (for diagnostics / descriptions).
    pub fn path(&self) -> String {
        self.path.display().to_string()
    }

    /// Re-read the keyfile, replacing the in-memory key set.
    pub fn reload(&self) -> Result<()> {
        let keys = Self::load_keys(&self.path)?;
        let mut matchers = self
            .matchers
            .write()
            .map_err(|e| Error::Filter(format!("failed to acquire lock: {e}")))?;
        *matchers = keys;
        Ok(())
    }

    /// Load every parseable key line from `path` into a list of matchers.
    fn load_keys(path: &Path) -> Result<Vec<PubkeyMatcher>> {
        let content = fs::read_to_string(path).map_err(|e| {
            Error::Filter(format!("failed to read keyfile '{}': {e}", path.display()))
        })?;

        let mut matchers = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(key_part) = Self::extract_key_part(line) {
                match PubkeyMatcher::new(key_part) {
                    Ok(m) => matchers.push(m),
                    Err(e) => {
                        eprintln!(
                            "cache-warden: keyfile filter: skipping invalid key in {}: {e}",
                            path.display()
                        );
                    }
                }
            }
        }

        Ok(matchers)
    }

    /// Strip leading SSH options, returning the substring starting at the key
    /// type token (or the whole line if no known prefix is found).
    fn extract_key_part(line: &str) -> Option<&str> {
        let key_prefixes = [
            "ssh-ed25519",
            "ssh-rsa",
            "ssh-dss",
            "ecdsa-sha2-",
            "sk-ssh-ed25519",
            "sk-ecdsa-sha2-",
        ];

        for prefix in &key_prefixes {
            if let Some(pos) = line.find(prefix) {
                return Some(&line[pos..]);
            }
        }

        Some(line)
    }

    /// Whether `identity` matches any key in the file.
    pub fn matches(&self, identity: &Identity) -> bool {
        if let Ok(matchers) = self.matchers.read() {
            matchers.iter().any(|m| m.matches(identity))
        } else {
            false
        }
    }
}

/// Expand a leading `~/` to `$HOME/`; leave everything else verbatim.
fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_extract_key_part() {
        let line = "ssh-ed25519 AAAAC3 comment";
        assert_eq!(KeyfileMatcher::extract_key_part(line), Some(line));

        let line_with_options = "no-agent-forwarding ssh-ed25519 AAAAC3 comment";
        assert_eq!(
            KeyfileMatcher::extract_key_part(line_with_options),
            Some("ssh-ed25519 AAAAC3 comment")
        );
    }

    #[test]
    fn test_load_keys() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Comment line").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com").unwrap();

        let matcher = KeyfileMatcher::new(file.path().to_str().unwrap()).unwrap();
        let matchers = matcher.matchers.read().unwrap();
        assert_eq!(matchers.len(), 1);
    }

    #[test]
    fn test_missing_file_is_error() {
        let result = KeyfileMatcher::new("/nonexistent/path/authorized_keys");
        assert!(result.is_err());
    }
}
