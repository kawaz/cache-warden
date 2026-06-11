//! 1Password CLI (`op`) integration for SSH key discovery (port plan §1.4).
//!
//! This is the adapter side of the `op://` key source: it enumerates SSH keys
//! stored in 1Password vaults and resolves each key's *public* half, building a
//! `public-key blob → 1Password item id` map. The private-key PEM is **never**
//! fetched here — that is deferred to sign time and goes through the core
//! [`cache_warden::Store`] as a [`cache_warden::ValueSource::Command`] (the core
//! gets the TTL / re-auth / regenerate / mlock; see the daemon wiring).
//!
//! # Why the op CLI is behind a trait
//!
//! Every `op` invocation may trigger TouchID and depends on the user being
//! logged in — neither is available in CI. The actual process spawning lives
//! behind [`OpClient`] so the discovery logic (and its DR-011 caching) is tested
//! against a fake. The production client is [`RealOpClient`].
//!
//! # Source members (`op://`, `op://VAULT`, `op://VAULT/ITEM`)
//!
//! An `op://` source member is parsed into an [`OpSource`] vault/item filter,
//! exactly as authsock-warden did, so the same `op://` strings carry over.

use std::process::Command;

use serde::Deserialize;

use crate::error::{Error, Result};

/// A vault/item filter parsed from an `op://...` source member.
///
/// - `op://` → `{ vault: None, item: None }` (all SSH keys),
/// - `op://VAULT` → `{ vault: Some, item: None }`,
/// - `op://VAULT/ITEM` → `{ vault: Some, item: Some }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpSource {
    /// Restrict discovery to this vault name/id (passed to `op item list --vault`).
    pub vault: Option<String>,
    /// Restrict discovery to this item title/id (post-filtered after listing).
    pub item: Option<String>,
}

impl OpSource {
    /// Parse an `op://...` member string into a vault/item filter.
    ///
    /// Returns `None` for any string that is not an `op://` member (an agent /
    /// file path), so the caller can route non-op members elsewhere. Mirrors
    /// authsock-warden's `SourceMember::parse` op branch: a single-segment rest
    /// is the vault, a `VAULT/ITEM` rest splits into both (each non-empty).
    pub fn parse(member: &str) -> Option<Self> {
        let rest = member.strip_prefix("op://")?;
        let (vault, item) = match rest.split_once('/') {
            Some((v, i)) if !v.is_empty() && !i.is_empty() => {
                (Some(v.to_string()), Some(i.to_string()))
            }
            _ if !rest.is_empty() => (Some(rest.to_string()), None),
            _ => (None, None),
        };
        Some(OpSource { vault, item })
    }
}

/// An SSH key item discovered from 1Password (public metadata only — no secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpKeyInfo {
    /// 1Password item id (used to fetch the public/private key).
    pub item_id: String,
    /// Human-readable item title (used as the key's comment in `ssh-add -l`).
    pub title: String,
    /// Vault id the item lives in.
    pub vault_id: String,
    /// Vault name the item lives in.
    pub vault_name: String,
    /// Key fingerprint, e.g. `SHA256:aKmT...` (the disk-cache lookup key, DR-011).
    pub fingerprint: String,
}

/// One entry of the `op item list --format json` array (extra fields ignored).
#[derive(Debug, Deserialize)]
struct OpItemListEntry {
    id: String,
    title: String,
    vault: OpVault,
    additional_information: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpVault {
    id: String,
    name: String,
}

/// One `op item get --fields ... --format json` field object (`{ "value": ... }`).
#[derive(Debug, Deserialize)]
struct OpFieldValue {
    value: String,
}

/// The `op` operations the discovery layer needs, behind a trait for testing.
///
/// Each method may block on TouchID and the network; the daemon calls them on
/// the blocking pool. A fake implementation in tests returns canned bytes so the
/// discovery / cache logic runs without `op` installed.
pub trait OpClient {
    /// Run `op item list --categories "SSH Key" --format json` (optionally
    /// `--vault VAULT`) and return its raw stdout JSON bytes.
    fn item_list_json(&self, vault: Option<&str>) -> Result<Vec<u8>>;

    /// Run `op item get ITEM --fields public_key --format json` and return its
    /// raw stdout JSON bytes.
    fn item_get_public_key_json(&self, item_id: &str) -> Result<Vec<u8>>;
}

/// The production [`OpClient`]: spawns the `op` CLI synchronously.
///
/// An optional account (`op_account`, e.g. `"kawaz.1password.com"`) is passed as
/// `--account` on every call so a multi-account 1Password setup targets the
/// right account (kawaz's `op_account` setting).
#[derive(Debug, Clone, Default)]
pub struct RealOpClient {
    account: Option<String>,
}

impl RealOpClient {
    /// A client using the default `op` account.
    pub fn new() -> Self {
        Self::default()
    }

    /// A client that passes `--account ACCOUNT` to every `op` call.
    pub fn with_account(account: impl Into<String>) -> Self {
        Self {
            account: Some(account.into()),
        }
    }

    /// Start an `op` command with the account flag applied if configured.
    fn command(&self) -> Command {
        let mut cmd = Command::new("op");
        if let Some(account) = &self.account {
            cmd.args(["--account", account]);
        }
        cmd
    }

    /// Run an `op` subcommand and return stdout, mapping failures to `KeyStore`
    /// errors whose message never includes secret material (only stderr, which
    /// `op` does not write secrets to, trimmed).
    fn run(&self, args: &[&str], what: &str) -> Result<Vec<u8>> {
        let output = self.command().args(args).output().map_err(|e| {
            Error::KeyStore(format!(
                "failed to execute op CLI: {e}. Is the 1Password CLI installed?"
            ))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::KeyStore(format!("{what} failed: {}", stderr.trim())));
        }
        Ok(output.stdout)
    }
}

impl OpClient for RealOpClient {
    fn item_list_json(&self, vault: Option<&str>) -> Result<Vec<u8>> {
        let mut args = vec![
            "item",
            "list",
            "--categories",
            "SSH Key",
            "--format",
            "json",
        ];
        if let Some(v) = vault {
            args.push("--vault");
            args.push(v);
        }
        self.run(&args, "op item list")
    }

    fn item_get_public_key_json(&self, item_id: &str) -> Result<Vec<u8>> {
        validate_item_id(item_id)?;
        self.run(
            &[
                "item",
                "get",
                item_id,
                "--fields",
                "public_key",
                "--format",
                "json",
            ],
            "op item get (public key)",
        )
    }
}

/// Validate that an item id is safe to pass to the `op` CLI as a bare argument.
///
/// 1Password item ids are alphanumeric. Rejecting anything else prevents a
/// discovered (or cached) id from injecting a CLI flag (`--vault`) or shell-ish
/// metacharacters into the argv the core later runs as a command source.
pub fn validate_item_id(item_id: &str) -> Result<()> {
    if !item_id.is_empty() && item_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(Error::KeyStore(format!("invalid item id: {item_id}")))
    }
}

/// Parse `op item list --format json` stdout into [`OpKeyInfo`]s, keeping only
/// entries whose `additional_information` is a `SHA256:` fingerprint.
///
/// `item` post-filters by exact title or id match (the `op://VAULT/ITEM` item
/// segment). An entry without a SHA256 fingerprint is dropped (it is not a
/// usable SSH key for the agent), matching authsock-warden.
pub fn parse_item_list(json: &[u8], item: Option<&str>) -> Result<Vec<OpKeyInfo>> {
    let entries: Vec<OpItemListEntry> = serde_json::from_slice(json)
        .map_err(|e| Error::KeyStore(format!("failed to parse op item list output: {e}")))?;
    let mut keys: Vec<OpKeyInfo> = entries
        .into_iter()
        .filter_map(|entry| {
            let fingerprint = entry.additional_information?;
            if !fingerprint.starts_with("SHA256:") {
                return None;
            }
            Some(OpKeyInfo {
                item_id: entry.id,
                title: entry.title,
                vault_id: entry.vault.id,
                vault_name: entry.vault.name,
                fingerprint,
            })
        })
        .collect();
    if let Some(item) = item {
        keys.retain(|k| k.title == item || k.item_id == item);
    }
    Ok(keys)
}

/// Extract the `value` of an `op item get --fields ... --format json` object.
///
/// Used for the **public** key field only; the private key is never fetched in
/// this module (it flows through the core command source at sign time).
pub fn parse_field_value(json: &[u8]) -> Result<String> {
    let field: OpFieldValue = serde_json::from_slice(json)
        .map_err(|e| Error::KeyStore(format!("failed to parse op field value: {e}")))?;
    Ok(field.value)
}

/// Build the argv the **core** runs (as a [`cache_warden::ValueSource::Command`])
/// to fetch one key's private-key PEM at sign time.
///
/// # Why no `--format json` (plain output) — port plan §1.4 / §3-11
///
/// authsock-warden fetched the private key as JSON and extracted `.value`. The
/// cache-warden core's `CommandRunner` captures **raw stdout** as the secret, so
/// a JSON wrapper would store `{"value":"<PEM>"}` instead of the PEM. We instead
/// run `op item get ITEM --fields private_key --reveal` *without* `--format
/// json`, which prints the field value (the PEM) plainly. The core's default
/// `TrailingNewline::TrimOne` then strips op's single trailing newline, leaving
/// the exact PEM the signer parses. `--reveal` is required so the concealed SSH
/// key field is returned (DR-011).
///
/// An optional `account` is threaded through as `--account ACCOUNT` so the core
/// command targets the same 1Password account discovery used.
pub fn private_key_argv(item_id: &str, account: Option<&str>) -> Vec<String> {
    let mut argv: Vec<String> = vec!["op".to_string()];
    if let Some(a) = account {
        argv.push("--account".to_string());
        argv.push(a.to_string());
    }
    argv.extend(
        [
            "item",
            "get",
            item_id,
            "--fields",
            "private_key",
            "--reveal",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- OpSource::parse ----

    #[test]
    fn parse_op_bare_has_no_filter() {
        assert_eq!(OpSource::parse("op://"), Some(OpSource::default()));
    }

    #[test]
    fn parse_op_vault_only() {
        assert_eq!(
            OpSource::parse("op://Private"),
            Some(OpSource {
                vault: Some("Private".into()),
                item: None,
            })
        );
    }

    #[test]
    fn parse_op_vault_and_item() {
        assert_eq!(
            OpSource::parse("op://Private/kawaz-key"),
            Some(OpSource {
                vault: Some("Private".into()),
                item: Some("kawaz-key".into()),
            })
        );
    }

    #[test]
    fn parse_non_op_member_is_none() {
        assert_eq!(OpSource::parse("agent:/tmp/agent.sock"), None);
        assert_eq!(OpSource::parse("/tmp/bare.sock"), None);
        assert_eq!(OpSource::parse("file:~/.ssh/id"), None);
    }

    // ---- validate_item_id ----

    #[test]
    fn item_id_accepts_alphanumeric() {
        assert!(validate_item_id("zl4nsgmrs73isw6mlc464tpecy").is_ok());
        assert!(validate_item_id("A1b2C3").is_ok());
    }

    #[test]
    fn item_id_rejects_empty_and_flags_and_metachars() {
        assert!(validate_item_id("").is_err());
        assert!(validate_item_id("--vault").is_err());
        assert!(validate_item_id("a b").is_err());
        assert!(validate_item_id("a;rm -rf /").is_err());
        assert!(validate_item_id("a/b").is_err());
    }

    // ---- parse_item_list ----

    fn list_json() -> &'static str {
        r#"[
            {
                "id": "zl4nsgmrs73isw6mlc464tpecy",
                "title": "SSH: kawaz@host",
                "vault": { "id": "v1", "name": "Private" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:aKmTBeL9vdtjrDYIq65Fv3GMc3UeVYEq+cFDs//Hwoo"
            },
            {
                "id": "id2",
                "title": "Work Key",
                "vault": { "id": "v2", "name": "Work" },
                "category": "SSH_KEY",
                "additional_information": "SHA256:bbbb"
            },
            {
                "id": "noinfo",
                "title": "Not a key",
                "vault": { "id": "v3", "name": "Private" },
                "category": "SSH_KEY",
                "additional_information": null
            },
            {
                "id": "md5key",
                "title": "Old key",
                "vault": { "id": "v4", "name": "Private" },
                "category": "SSH_KEY",
                "additional_information": "MD5:ab:cd"
            }
        ]"#
    }

    #[test]
    fn item_list_keeps_only_sha256_fingerprints() {
        let keys = parse_item_list(list_json().as_bytes(), None).unwrap();
        // The null-info and MD5-fingerprint entries are dropped.
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].item_id, "zl4nsgmrs73isw6mlc464tpecy");
        assert_eq!(keys[0].vault_name, "Private");
        assert_eq!(
            keys[0].fingerprint,
            "SHA256:aKmTBeL9vdtjrDYIq65Fv3GMc3UeVYEq+cFDs//Hwoo"
        );
        assert_eq!(keys[1].item_id, "id2");
    }

    #[test]
    fn item_list_post_filters_by_item_title_or_id() {
        let by_title = parse_item_list(list_json().as_bytes(), Some("Work Key")).unwrap();
        assert_eq!(by_title.len(), 1);
        assert_eq!(by_title[0].item_id, "id2");

        let by_id = parse_item_list(list_json().as_bytes(), Some("id2")).unwrap();
        assert_eq!(by_id.len(), 1);
        assert_eq!(by_id[0].title, "Work Key");

        let none = parse_item_list(list_json().as_bytes(), Some("nope")).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn item_list_empty_array_is_empty() {
        assert!(parse_item_list(b"[]", None).unwrap().is_empty());
    }

    #[test]
    fn item_list_invalid_json_is_keystore_error() {
        let err = parse_item_list(b"not json", None).unwrap_err();
        assert!(matches!(err, Error::KeyStore(_)));
    }

    // ---- parse_field_value ----

    #[test]
    fn field_value_extracts_value_ignoring_extra_keys() {
        let json = r#"{"id":"public_key","type":"STRING","reference":"op://v/i/public_key","value":"ssh-ed25519 AAAA..."}"#;
        assert_eq!(
            parse_field_value(json.as_bytes()).unwrap(),
            "ssh-ed25519 AAAA..."
        );
    }

    #[test]
    fn field_value_invalid_json_is_keystore_error() {
        assert!(matches!(
            parse_field_value(b"{").unwrap_err(),
            Error::KeyStore(_)
        ));
    }

    // ---- private_key_argv ----

    #[test]
    fn private_key_argv_is_plain_reveal_without_json() {
        // Plain output (no --format json) so the core CommandRunner captures the
        // PEM directly; --reveal so the concealed key field is returned.
        let argv = private_key_argv("itemABC", None);
        assert_eq!(
            argv,
            vec![
                "op",
                "item",
                "get",
                "itemABC",
                "--fields",
                "private_key",
                "--reveal"
            ]
        );
        assert!(!argv.iter().any(|a| a == "json"));
    }

    #[test]
    fn private_key_argv_threads_account() {
        let argv = private_key_argv("itemABC", Some("kawaz.1password.com"));
        assert_eq!(
            argv,
            vec![
                "op",
                "--account",
                "kawaz.1password.com",
                "item",
                "get",
                "itemABC",
                "--fields",
                "private_key",
                "--reveal",
            ]
        );
    }
}
