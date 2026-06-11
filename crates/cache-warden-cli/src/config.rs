//! TOML configuration for the daemon (DR-0010).
//!
//! cache-warden runs fine with **no** configuration at all (every field has a
//! default). A config file lets the user pin the control socket path, wire a
//! re-authentication command, and declare entries to preload at daemon start.
//!
//! # Schema (v1)
//!
//! ```toml
//! [daemon]
//! socket = "~/.local/state/cache-warden/control.sock"  # overridable; CLI --socket wins
//!
//! [auth]
//! command = ["/path/to/reauth-prompt"]   # omitted => no re-auth (AllowAll)
//!
//! [kv.DB_PASSWORD]                        # an entry to preload at startup
//! command = ["op", "read", "op://vault/item/password"]
//! soft-ttl = "1h"
//! hard-ttl = "24h"
//! ```
//!
//! # Why a `command`-only `[kv.*]` (no inline value)
//!
//! A `[kv.*]` entry may only declare a `command` source — there is **no** way to
//! write a literal secret value into the config file. This is deliberate: a
//! plaintext secret committed to a config file (and thus to dotfiles repos,
//! backups, `cat`-able paths) is exactly the leak the cache exists to avoid.
//! Static values must be injected at runtime via `cache-warden kv set
//! --value-stdin`, never persisted in config. A `value` / `value-stdin` /
//! `static` key in `[kv.*]` is rejected as a configuration error.
//!
//! # `[auth]` omitted => no re-authentication
//!
//! If `[auth].command` is absent, the daemon wires [`cache_warden::AllowAll`]:
//! soft-expired entries extend (and command entries regenerate) without
//! prompting. This is the "I trust this host, just cache fast" setup. Configure
//! `[auth].command` to demand re-authentication on every TTL-gated unlock.
//!
//! # Strictness
//!
//! Every table uses `#[serde(deny_unknown_fields)]` (authsock-warden precedent):
//! a typo'd key is an error, not a silently ignored field.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::protocol::parse_duration;

/// The whole configuration file, parsed from TOML.
///
/// All sections are optional; an empty file (or no file) yields
/// [`Config::default`], which runs the daemon with built-in defaults.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Daemon-level settings (socket path).
    #[serde(default)]
    pub daemon: DaemonConfig,
    /// Re-authentication settings.
    #[serde(default)]
    pub auth: AuthConfig,
    /// Entries to preload at startup, keyed by entry name. A `BTreeMap` keeps a
    /// deterministic (sorted) preload order for predictable startup logging.
    #[serde(default)]
    pub kv: BTreeMap<String, KvEntryConfig>,
    /// SSH agent adapter settings (the authsock adapter; port plan Iteration 1).
    #[serde(default)]
    pub authsock: AuthsockConfig,
}

/// `[authsock]` section: SSH agent sockets the daemon serves.
///
/// Each `[authsock.sockets.NAME]` declares one agent socket and the core KV
/// keys whose private-key PEMs answer its SIGN_REQUESTs. The private keys
/// themselves live in `[kv.*]` (command-preloaded) or are injected at runtime
/// with `cache-warden kv set` — they are never written here.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthsockConfig {
    /// Agent sockets keyed by name. `BTreeMap` keeps a deterministic bind order.
    #[serde(default)]
    pub sockets: BTreeMap<String, AuthsockSocketConfig>,
}

/// One `[authsock.sockets.NAME]` agent socket.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthsockSocketConfig {
    /// Filesystem path of the SSH agent socket (a leading `~/` is expanded).
    pub path: String,
    /// Core KV key names whose private-key PEMs this socket can sign with. Each
    /// is enumerated (public key) in REQUEST_IDENTITIES and looked up on a
    /// matching SIGN_REQUEST.
    #[serde(default)]
    pub keys: Vec<String>,
}

/// One validated agent socket ready to bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthsockSocket {
    /// The socket name (the `[authsock.sockets.NAME]` key).
    pub name: String,
    /// The resolved socket path (leading `~/` expanded).
    pub path: PathBuf,
    /// Core KV key names this socket signs with.
    pub keys: Vec<String>,
}

/// `[daemon]` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Control socket path. Tilde and `$VAR` are **not** expanded except a
    /// leading `~/` (see [`expand_tilde`]); omit to use the built-in default.
    #[serde(default)]
    pub socket: Option<String>,
}

/// `[auth]` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// The re-authentication command argv (program first). Absent => no re-auth
    /// (the daemon wires `AllowAll`).
    #[serde(default)]
    pub command: Option<Vec<String>>,
}

/// One `[kv.NAME]` preload entry.
///
/// Only a `command` source is permitted (see the module note on why inline
/// values are forbidden). The `value` / `value-stdin` / `static` keys exist in
/// the schema *only* so a friendly error can be raised when a user tries to
/// write a literal secret; they are otherwise unused.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvEntryConfig {
    /// The upstream command argv (program first) whose stdout is the value.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Soft TTL string (e.g. `"1h"`). Parsed via [`parse_duration`].
    #[serde(default, rename = "soft-ttl")]
    pub soft_ttl: Option<String>,
    /// Hard TTL string (e.g. `"24h"`). Parsed via [`parse_duration`].
    #[serde(default, rename = "hard-ttl")]
    pub hard_ttl: Option<String>,

    // --- Forbidden-on-purpose keys (see KvEntryConfig::validate) ---
    /// Present only to reject inline literal values with a clear error.
    #[serde(default)]
    value: Option<toml::Value>,
    /// Present only to reject inline literal values with a clear error.
    #[serde(default, rename = "value-stdin")]
    value_stdin: Option<toml::Value>,
    /// Present only to reject a `static` source declaration with a clear error.
    #[serde(default)]
    r#static: Option<toml::Value>,
}

/// A preload entry validated into a ready-to-run shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreloadEntry {
    /// The entry name (the `[kv.NAME]` key).
    pub name: String,
    /// The command argv to run at startup (program first).
    pub command: Vec<String>,
    /// Parsed soft TTL in seconds, or `None`.
    pub soft_ttl_secs: Option<u64>,
    /// Parsed hard TTL in seconds, or `None`.
    pub hard_ttl_secs: Option<u64>,
}

/// An error in the configuration file's *content* (distinct from I/O / TOML
/// syntax errors, which are reported separately by [`load`]).
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// Human-readable description (no secret material — config holds none).
    pub message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ConfigError {}

impl KvEntryConfig {
    /// Validate this entry against the schema rules and produce a [`PreloadEntry`].
    ///
    /// Rejects inline literal values (`value` / `value-stdin` / `static`), a
    /// missing `command`, and unparseable TTL strings.
    fn validate(&self, name: &str) -> Result<PreloadEntry, ConfigError> {
        if self.value.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: inline `value` is not allowed — secrets must not be stored in config; use a `command` source or inject the value at runtime with `cache-warden kv set --value-stdin`"
            )));
        }
        if self.value_stdin.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: `value-stdin` is not a config key — inject literal values at runtime with `cache-warden kv set --value-stdin`"
            )));
        }
        if self.r#static.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: a `static` source cannot be preloaded from config — only `command` entries may be preloaded"
            )));
        }

        let command = match &self.command {
            Some(argv) if !argv.is_empty() => argv.clone(),
            Some(_) => {
                return Err(ConfigError::new(format!(
                    "[kv.{name}]: `command` must not be empty"
                )));
            }
            None => {
                return Err(ConfigError::new(format!(
                    "[kv.{name}]: a preload entry requires a `command` source"
                )));
            }
        };

        let parse = |label: &str, s: &Option<String>| -> Result<Option<u64>, ConfigError> {
            match s {
                None => Ok(None),
                Some(v) => parse_duration(v)
                    .map(|d| Some(d.as_secs()))
                    .map_err(|e| ConfigError::new(format!("[kv.{name}]: {label}: {e}"))),
            }
        };
        let soft_ttl_secs = parse("soft-ttl", &self.soft_ttl)?;
        let hard_ttl_secs = parse("hard-ttl", &self.hard_ttl)?;

        Ok(PreloadEntry {
            name: name.to_string(),
            command,
            soft_ttl_secs,
            hard_ttl_secs,
        })
    }
}

impl AuthsockSocketConfig {
    /// Validate this socket against the schema rules and produce an
    /// [`AuthsockSocket`].
    ///
    /// Rejects an empty `path` and an empty `keys` list (a socket with no keys
    /// would answer REQUEST_IDENTITIES with nothing and could never sign).
    fn validate(&self, name: &str) -> Result<AuthsockSocket, ConfigError> {
        if self.path.trim().is_empty() {
            return Err(ConfigError::new(format!(
                "[authsock.sockets.{name}]: `path` must not be empty"
            )));
        }
        if self.keys.is_empty() {
            return Err(ConfigError::new(format!(
                "[authsock.sockets.{name}]: `keys` must list at least one KV key name"
            )));
        }
        Ok(AuthsockSocket {
            name: name.to_string(),
            path: expand_tilde(&self.path),
            keys: self.keys.clone(),
        })
    }
}

impl Config {
    /// Parse a config from TOML text and validate its content.
    ///
    /// Returns a content [`ConfigError`] for schema violations (forbidden keys,
    /// missing `command`, bad TTL). TOML *syntax* errors are surfaced as the
    /// `toml::de::Error` arm.
    pub fn parse(text: &str) -> Result<Config, ConfigParseError> {
        let cfg: Config = toml::from_str(text).map_err(ConfigParseError::Toml)?;
        // Eagerly validate every preload entry so a bad entry fails fast at
        // startup rather than at first `get`.
        for (name, entry) in &cfg.kv {
            entry.validate(name).map_err(ConfigParseError::Content)?;
        }
        // Validate authsock sockets too (empty path / keys fail fast at startup).
        for (name, sock) in &cfg.authsock.sockets {
            sock.validate(name).map_err(ConfigParseError::Content)?;
        }
        // An empty (or omitted) auth command is treated as "no command", not as
        // a configured-but-empty command; reject the misleading empty form.
        if let Some(argv) = &cfg.auth.command
            && argv.is_empty()
        {
            return Err(ConfigParseError::Content(ConfigError::new(
                "[auth]: `command` must not be empty (omit the key for no re-authentication)",
            )));
        }
        Ok(cfg)
    }

    /// The resolved re-authentication command argv, if any.
    pub fn auth_command(&self) -> Option<&[String]> {
        self.auth.command.as_deref()
    }

    /// The validated preload entries, in deterministic (name-sorted) order.
    ///
    /// Pre-validated by [`Config::parse`], so this cannot fail; it re-runs the
    /// (cheap, infallible-at-this-point) conversion.
    pub fn preload_entries(&self) -> Vec<PreloadEntry> {
        self.kv
            .iter()
            .filter_map(|(name, entry)| entry.validate(name).ok())
            .collect()
    }

    /// The configured socket path with a leading `~/` expanded, if set.
    pub fn socket_path(&self) -> Option<PathBuf> {
        self.daemon.socket.as_deref().map(expand_tilde)
    }

    /// The validated authsock agent sockets, in deterministic (name-sorted)
    /// order. Pre-validated by [`Config::parse`], so this cannot fail.
    pub fn authsock_sockets(&self) -> Vec<AuthsockSocket> {
        self.authsock
            .sockets
            .iter()
            .filter_map(|(name, sock)| sock.validate(name).ok())
            .collect()
    }
}

/// The two failure modes of [`Config::parse`]: TOML syntax vs. content rules.
#[derive(Debug)]
pub enum ConfigParseError {
    /// The text was not valid TOML.
    Toml(toml::de::Error),
    /// The text parsed but violated a schema rule.
    Content(ConfigError),
}

impl std::fmt::Display for ConfigParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigParseError::Toml(e) => write!(f, "invalid TOML: {e}"),
            ConfigParseError::Content(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigParseError {}

/// Expand a leading `~/` to `$HOME/`; leave everything else verbatim.
///
/// Intentionally minimal (no `$VAR` interpolation, no `~user`): the config only
/// needs the common home-relative socket path, and a smaller surface is easier
/// to reason about.
pub fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(s)
}

/// The config file search order (highest priority first):
///
/// 1. `$CACHE_WARDEN_CONFIG` (explicit override; used verbatim if set).
/// 2. `$XDG_CONFIG_HOME/cache-warden/config.toml` (if `XDG_CONFIG_HOME` set).
/// 3. `~/.config/cache-warden/config.toml`.
///
/// Returns every candidate path in order, regardless of existence; the caller
/// picks the first that exists.
pub fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(explicit) = std::env::var_os("CACHE_WARDEN_CONFIG")
        && !explicit.is_empty()
    {
        paths.push(PathBuf::from(explicit));
    }

    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        paths.push(PathBuf::from(xdg).join("cache-warden").join("config.toml"));
    }

    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".config")
                .join("cache-warden")
                .join("config.toml"),
        );
    }

    // Drop duplicates while preserving priority order: when XDG_CONFIG_HOME is
    // (the common) `~/.config`, the XDG and HOME candidates collapse to the same
    // path, and listing it twice is just noise.
    paths.dedup();
    paths
}

/// Find the first existing config file in [`config_search_paths`], if any.
pub fn find_config_file() -> Option<PathBuf> {
    config_search_paths().into_iter().find(|p| p.is_file())
}

/// The outcome of [`load`]: where the config came from and what it holds.
#[derive(Debug)]
pub struct LoadedConfig {
    /// The path the config was read from, or `None` if defaults were used.
    pub path: Option<PathBuf>,
    /// The parsed (and validated) configuration.
    pub config: Config,
}

/// Errors from [`load`] / [`load_from`].
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The OS error rendered as a string.
        source: String,
    },
    /// The file was read but failed to parse / validate.
    Parse {
        /// The path that failed.
        path: PathBuf,
        /// The parse failure.
        source: ConfigParseError,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io { path, source } => {
                write!(f, "cannot read config {}: {source}", path.display())
            }
            LoadError::Parse { path, source } => {
                write!(f, "invalid config {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Read and parse the config file at `path`.
pub fn load_from(path: &Path) -> Result<Config, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|e| LoadError::Io {
        path: path.to_path_buf(),
        source: e.to_string(),
    })?;
    Config::parse(&text).map_err(|e| LoadError::Parse {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Load the config from the first existing search path, or defaults if none.
pub fn load() -> Result<LoadedConfig, LoadError> {
    match find_config_file() {
        Some(path) => {
            let config = load_from(&path)?;
            Ok(LoadedConfig {
                path: Some(path),
                config,
            })
        }
        None => Ok(LoadedConfig {
            path: None,
            config: Config::default(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_all_defaults() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg, Config::default());
        assert!(cfg.auth_command().is_none());
        assert!(cfg.preload_entries().is_empty());
        assert!(cfg.socket_path().is_none());
    }

    #[test]
    fn daemon_socket_is_read_and_tilde_expanded() {
        let cfg = Config::parse(
            r#"[daemon]
socket = "~/.local/state/cache-warden/control.sock"
"#,
        )
        .unwrap();
        // SAFETY: single-threaded test.
        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", "/home/tester") };
        assert_eq!(
            cfg.socket_path().unwrap(),
            PathBuf::from("/home/tester/.local/state/cache-warden/control.sock")
        );
        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn auth_command_is_read_as_argv() {
        let cfg = Config::parse(
            r#"[auth]
command = ["/usr/local/bin/reauth", "--prompt"]
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.auth_command(),
            Some(["/usr/local/bin/reauth".to_string(), "--prompt".to_string()].as_slice())
        );
    }

    #[test]
    fn empty_auth_command_is_rejected() {
        let err = Config::parse(
            r#"[auth]
command = []
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("must not be empty")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn kv_command_entry_with_ttls_validates() {
        let cfg = Config::parse(
            r#"[kv.DB_PASSWORD]
command = ["op", "read", "op://vault/item/password"]
soft-ttl = "1h"
hard-ttl = "24h"
"#,
        )
        .unwrap();
        let entries = cfg.preload_entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "DB_PASSWORD");
        assert_eq!(e.command, vec!["op", "read", "op://vault/item/password"]);
        assert_eq!(e.soft_ttl_secs, Some(3600));
        assert_eq!(e.hard_ttl_secs, Some(86400));
    }

    #[test]
    fn kv_entries_are_sorted_by_name() {
        let cfg = Config::parse(
            r#"[kv.B]
command = ["echo", "b"]

[kv.A]
command = ["echo", "a"]
"#,
        )
        .unwrap();
        let names: Vec<_> = cfg.preload_entries().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn kv_inline_value_is_rejected() {
        let err = Config::parse(
            r#"[kv.SOME_STATIC]
value = "hunter2"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => {
                assert!(e.message.contains("not allowed"), "msg: {}", e.message);
                assert!(!e.message.contains("hunter2"), "must not echo the secret");
            }
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn kv_value_stdin_key_is_rejected() {
        let err = Config::parse(
            r#"[kv.X]
value-stdin = true
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Content(_)));
    }

    #[test]
    fn kv_static_key_is_rejected() {
        let err = Config::parse(
            r#"[kv.X]
static = "v"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Content(_)));
    }

    #[test]
    fn kv_entry_without_command_is_rejected() {
        let err = Config::parse(
            r#"[kv.X]
soft-ttl = "1h"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("requires a `command`")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn kv_entry_with_empty_command_is_rejected() {
        let err = Config::parse(
            r#"[kv.X]
command = []
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Content(_)));
    }

    #[test]
    fn kv_entry_with_bad_ttl_is_rejected() {
        let err = Config::parse(
            r#"[kv.X]
command = ["echo", "x"]
soft-ttl = "1d"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("soft-ttl")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let err = Config::parse(
            r#"bogus = "value"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn unknown_field_in_daemon_is_rejected() {
        let err = Config::parse(
            r#"[daemon]
bogus = 1
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn syntax_error_is_toml_error() {
        let err = Config::parse("not = valid = toml").unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn expand_tilde_leaves_absolute_paths() {
        assert_eq!(expand_tilde("/tmp/x.sock"), PathBuf::from("/tmp/x.sock"));
    }

    // ---- authsock sockets ----

    #[test]
    fn empty_config_has_no_authsock_sockets() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.authsock_sockets().is_empty());
    }

    #[test]
    fn authsock_socket_is_read_and_validated() {
        let cfg = Config::parse(
            r#"[authsock.sockets.default]
path = "/tmp/cache-warden.sock"
keys = ["GITHUB_KEY", "OTHER_KEY"]
"#,
        )
        .unwrap();
        let socks = cfg.authsock_sockets();
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].name, "default");
        assert_eq!(socks[0].path, PathBuf::from("/tmp/cache-warden.sock"));
        assert_eq!(socks[0].keys, vec!["GITHUB_KEY", "OTHER_KEY"]);
    }

    #[test]
    fn authsock_socket_path_tilde_is_expanded() {
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "~/.ssh/cache-warden.sock"
keys = ["K"]
"#,
        )
        .unwrap();
        // SAFETY: single-threaded test.
        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", "/home/tester") };
        let socks = cfg.authsock_sockets();
        assert_eq!(
            socks[0].path,
            PathBuf::from("/home/tester/.ssh/cache-warden.sock")
        );
        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn authsock_sockets_are_sorted_by_name() {
        let cfg = Config::parse(
            r#"[authsock.sockets.bbb]
path = "/tmp/b.sock"
keys = ["K"]

[authsock.sockets.aaa]
path = "/tmp/a.sock"
keys = ["K"]
"#,
        )
        .unwrap();
        let names: Vec<_> = cfg.authsock_sockets().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["aaa", "bbb"]);
    }

    #[test]
    fn authsock_socket_without_path_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = ""
keys = ["K"]
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("`path` must not be empty")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn authsock_socket_with_empty_keys_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = []
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("at least one KV key")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn authsock_socket_missing_path_field_is_toml_error() {
        // `path` has no default, so omitting it is a TOML deserialization error.
        let err = Config::parse(
            r#"[authsock.sockets.s]
keys = ["K"]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn unknown_field_in_authsock_socket_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
bogus = 1
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }
}
