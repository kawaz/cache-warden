//! TOML configuration for the daemon (DR-0010).
//!
//! cache-warden runs fine with **no** configuration at all (every field has a
//! default). A config file lets the user pin the control socket path, wire a
//! re-authentication command, and declare command-source definitions
//! registered at daemon start (DR-0014).
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
//! [kv.DB_PASSWORD]                        # a command-source definition
//! command = ["op", "read", "op://vault/item/password"]
//! soft-ttl = "1h"
//! hard-ttl = "24h"
//! preload = true                          # run at startup (default: lazy)
//! ```
//!
//! # Definitions are lazy by default (DR-0014 §4)
//!
//! A `[kv.*]` entry registers a *definition* (KEY ↔ command + TTL) at startup
//! but does **not** run the command then — the value is produced lazily on the
//! first `kv get`. Set `preload = true` to opt back into the old behaviour
//! (run the command at startup so the first get is a cache hit). A failed
//! preload is a warning, never fatal: the definition stays registered and the
//! value regenerates on the next get.
//!
//! Exception: a key referenced by any `[authsock.sockets.*].keys` list is
//! preloaded automatically, regardless of its `preload` flag — the agent
//! registry derives the public key from the resident PEM at startup
//! (REQUEST_IDENTITIES needs it), and the socket declaration already expresses
//! that intent. Requiring a second `preload = true` on the same key would be a
//! silent footgun: a forgotten flag would drop the key from the agent.
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
    /// Command-source definitions registered at startup, keyed by entry name. A
    /// `BTreeMap` keeps a deterministic (sorted) registration order for
    /// predictable startup logging.
    #[serde(default)]
    pub kv: BTreeMap<String, KvEntryConfig>,
    /// SSH agent adapter settings (the authsock adapter; port plan Iteration 1).
    #[serde(default)]
    pub authsock: AuthsockConfig,
    /// Client-side defaults (DR-0015): the reveal/dry-run polarity for the
    /// value-emitting verbs (`kv get` / `run` / `inject`).
    #[serde(default)]
    pub cli: CliConfig,
}

/// `[cli]` section: client-side defaults (DR-0015 §4).
///
/// `default-mode` sets the polarity used when neither a `--reveal` / `--dry-run`
/// flag nor `CACHE_WARDEN_DRY_RUN` is given. The built-in default is `"reveal"`
/// (real values); an operator can flip a whole context to `"dry-run"` here.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliConfig {
    /// `"reveal"` (default) or `"dry-run"`. Absent means "not set" (the resolver
    /// falls through to the built-in reveal default).
    #[serde(default, rename = "default-mode")]
    pub default_mode: Option<String>,
}

impl CliConfig {
    /// The configured default [`Mode`](crate::mode::Mode), or `None` if unset.
    ///
    /// Validated by [`Config::parse`] (an unknown string is rejected there), so
    /// this re-parse is infallible at call time.
    pub fn default_mode(&self) -> Option<crate::mode::Mode> {
        match self.default_mode.as_deref() {
            Some("dry-run") => Some(crate::mode::Mode::DryRun),
            Some("reveal") => Some(crate::mode::Mode::Reveal),
            _ => None,
        }
    }
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
    /// Key sources keyed by name (port plan Iteration 4). A source enumerates
    /// keys from an upstream key store (currently only `kind = "op"`, 1Password
    /// vault discovery) and a `[authsock.sockets.*]` references it via `source`.
    #[serde(default)]
    pub sources: BTreeMap<String, AuthsockSourceConfig>,
    /// Agent sockets keyed by name. `BTreeMap` keeps a deterministic bind order.
    #[serde(default)]
    pub sockets: BTreeMap<String, AuthsockSocketConfig>,
    /// `github=<user>` filter settings (cache TTL / fetch timeout), shared by
    /// every socket that uses a `github` filter.
    #[serde(default)]
    pub github: GithubConfig,
}

/// `[authsock.github]` section: settings for `github=<user>` filters.
///
/// A `github` filter fetches `github.com/<user>.keys` over the network. These
/// settings cap how often the published key set is refreshed (`cache_ttl`) and
/// how long a single fetch may take (`timeout`). They apply to every `github`
/// filter the daemon serves.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// How long a fetched key set is reused before a background refresh
    /// re-fetches it. Parsed via [`parse_duration`]; defaults to `"1h"`.
    #[serde(default = "default_github_cache_ttl")]
    pub cache_ttl: String,
    /// Maximum wall-clock time for one `.keys` fetch (passed to `curl
    /// --max-time`). Parsed via [`parse_duration`]; defaults to `"10s"`.
    #[serde(default = "default_github_timeout")]
    pub timeout: String,
}

fn default_github_cache_ttl() -> String {
    "1h".to_string()
}

fn default_github_timeout() -> String {
    "10s".to_string()
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            cache_ttl: default_github_cache_ttl(),
            timeout: default_github_timeout(),
        }
    }
}

impl GithubConfig {
    /// Parse `cache_ttl` into a [`std::time::Duration`].
    pub fn cache_ttl_duration(&self) -> Result<std::time::Duration, ConfigError> {
        parse_duration(&self.cache_ttl)
            .map_err(|e| ConfigError::new(format!("[authsock.github]: cache_ttl: {e}")))
    }

    /// Parse `timeout` into a [`std::time::Duration`].
    pub fn timeout_duration(&self) -> Result<std::time::Duration, ConfigError> {
        parse_duration(&self.timeout)
            .map_err(|e| ConfigError::new(format!("[authsock.github]: timeout: {e}")))
    }
}

/// One `[authsock.sources.NAME]`: a key source (op vault discovery).
///
/// The only `kind` today is `"op"` (port plan Iteration 4 / DR-011): it lists SSH
/// keys from 1Password vaults named by `members` (`op://`, `op://VAULT`,
/// `op://VAULT/ITEM`) and serves their private keys by fetching each lazily at
/// sign time through the core KV. The TTLs become the lazily-created core entry's
/// soft / hard windows (a socket cannot override them in this iteration).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthsockSourceConfig {
    /// Source kind. Must be `"op"`.
    pub kind: String,
    /// 1Password account (`op --account ...`), e.g. `"kawaz.1password.com"`.
    /// Omit to use the `op` CLI's default account.
    #[serde(default)]
    pub op_account: Option<String>,
    /// `op://` source members enumerating which vaults/items to discover. An
    /// empty / omitted list defaults to a single bare `op://` (all SSH keys).
    #[serde(default)]
    pub members: Vec<String>,
    /// Soft TTL string (e.g. `"1h"`) for each discovered key's core entry.
    #[serde(default, rename = "soft-ttl")]
    pub soft_ttl: Option<String>,
    /// Hard TTL string (e.g. `"24h"`) for each discovered key's core entry.
    #[serde(default, rename = "hard-ttl")]
    pub hard_ttl: Option<String>,
}

/// A validated key source ready for discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthsockSource {
    /// The source name (the `[authsock.sources.NAME]` key).
    pub name: String,
    /// 1Password account, or `None` for the `op` default.
    pub op_account: Option<String>,
    /// `op://` member strings (at least one; defaults to `["op://"]`).
    pub members: Vec<String>,
    /// Soft TTL in seconds for discovered keys' core entries, or `None`.
    pub soft_ttl_secs: Option<u64>,
    /// Hard TTL in seconds for discovered keys' core entries, or `None`.
    pub hard_ttl_secs: Option<u64>,
}

/// One `[authsock.sockets.NAME]` agent socket.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthsockSocketConfig {
    /// Filesystem path of the SSH agent socket (a leading `~/` is expanded).
    pub path: String,
    /// Core KV key names whose private-key PEMs this socket can sign with. Each
    /// is enumerated (public key) in REQUEST_IDENTITIES and looked up on a
    /// matching SIGN_REQUEST. These are signed **locally** (the adapter holds
    /// the PEM through the core).
    #[serde(default)]
    pub keys: Vec<String>,
    /// Upstream agent socket paths (each a leading `~/` is expanded). Their keys
    /// are merged into REQUEST_IDENTITIES and their SIGN_REQUESTs are
    /// **forwarded** (we never hold the upstream's private material). Optional.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Name of an `[authsock.sources.*]` whose discovered keys this socket serves
    /// (port plan Iteration 4). The source's keys are enumerated (REQUEST_IDENTITIES)
    /// and signed by fetching each private key lazily through the core KV. Optional;
    /// combines with `keys` / `upstreams` (one socket may bundle several routes).
    #[serde(default)]
    pub source: Option<String>,
    /// Key filters restricting which public keys this socket exposes and can sign
    /// with (port plan Iteration 3). Each TOML element is one **OR term**: a
    /// string is a single-rule term (`"comment=github*"`), an array is an AND
    /// group (`["comment=*@work*", "type=ed25519"]`). The terms are ORed, the
    /// rules within a group ANDed. An empty / omitted list means no filtering
    /// (all keys are exposed). See [`deserialize_filters`].
    #[serde(default, deserialize_with = "deserialize_filters")]
    pub filters: Vec<Vec<String>>,
    /// Process names (executable basenames) allowed to use this socket (port plan
    /// Iteration 5). When non-empty, a connecting client is admitted only if some
    /// process in its ancestry chain has a matching executable basename; otherwise
    /// every REQUEST_IDENTITIES / SIGN_REQUEST on that connection is refused
    /// (SSH_AGENT_FAILURE). An empty / omitted list means **no restriction** (all
    /// processes are allowed). Matching is exact (no globs / regexes). See
    /// [`cache_warden_authsock::chain_allowed`].
    #[serde(default)]
    pub allowed_processes: Vec<String>,
}

/// Deserialize `filters` from a TOML array of strings and/or arrays of strings.
///
/// Mirrors authsock-warden's filter syntax so an operator's mental model carries
/// over (port plan §3): each element becomes one OR term —
/// - `"comment=github*"` → a single-rule term (`["comment=github*"]`),
/// - `["comment=*@work*", "type=ed25519"]` → an AND group.
///
/// The resulting `Vec<Vec<String>>` is OR-of-AND: the outer vec is ORed, each
/// inner vec is ANDed. The *rule tokens* themselves are validated later (at
/// socket construction) so a parse error names the socket.
fn deserialize_filters<'de, D>(deserializer: D) -> Result<Vec<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct FiltersVisitor;

    impl<'de> Visitor<'de> for FiltersVisitor {
        type Value = Vec<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a sequence of strings or arrays of strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some(value) = seq.next_element::<toml::Value>()? {
                match value {
                    // A single string is a one-rule OR term.
                    toml::Value::String(s) => result.push(vec![s]),
                    // An array is an AND group (every element must be a string).
                    toml::Value::Array(arr) => {
                        let group: Vec<String> = arr
                            .into_iter()
                            .map(|v| {
                                v.as_str().map(str::to_string).ok_or_else(|| {
                                    de::Error::custom("expected string in filter group")
                                })
                            })
                            .collect::<Result<_, _>>()?;
                        result.push(group);
                    }
                    _ => return Err(de::Error::custom("expected string or array of strings")),
                }
            }
            Ok(result)
        }
    }

    deserializer.deserialize_seq(FiltersVisitor)
}

/// One validated agent socket ready to bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthsockSocket {
    /// The socket name (the `[authsock.sockets.NAME]` key).
    pub name: String,
    /// The resolved socket path (leading `~/` expanded).
    pub path: PathBuf,
    /// Core KV key names this socket signs with locally.
    pub keys: Vec<String>,
    /// Upstream agent socket paths (leading `~/` expanded) whose keys are merged
    /// and whose signatures are forwarded.
    pub upstreams: Vec<PathBuf>,
    /// Name of the `[authsock.sources.*]` this socket serves, if any.
    pub source: Option<String>,
    /// Key-filter terms (OR of AND) restricting which keys this socket exposes
    /// and can sign with. Empty means no filtering. The tokens are validated at
    /// parse time (so a bad token fails startup, naming the socket); the daemon
    /// builds a `FilterEvaluator` from them.
    pub filters: Vec<Vec<String>>,
    /// Executable basenames allowed to use this socket (port plan Iteration 5).
    /// Empty means no restriction; otherwise a connection is admitted only when
    /// some process in the peer's ancestry chain has a matching basename.
    pub allowed_processes: Vec<String>,
}

/// `[daemon]` section.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Control socket path. Tilde and `$VAR` are **not** expanded except a
    /// leading `~/` (see [`expand_tilde`]); omit to use the built-in default.
    #[serde(default)]
    pub socket: Option<String>,
    /// Persist online (`kv define` / `kv del --with-define`) definitions to a
    /// state file so they survive a daemon restart (DR-0014 §4). Default
    /// `false`. When `true` the daemon writes the definition registry (KEY /
    /// argv / TTL — **never** values) to `$XDG_STATE_HOME/cache-warden/definitions.toml`
    /// (0600, atomic) on every definition change and restores it at startup
    /// (config-priority merge). When `false` the state file is never read or
    /// written, even if one already exists.
    ///
    /// Note: if a user embeds a literal token directly in a definition's argv,
    /// that argv is written to disk (shell-history-equivalent risk; the file is
    /// 0600). The persisted file holds definitions only, never secret values.
    #[serde(default, rename = "persist-definitions")]
    pub persist_definitions: bool,
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

/// One `[kv.NAME]` command-source definition entry.
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
    /// Run the command at startup (eager) rather than lazily on first get
    /// (DR-0014 §4). Defaults to `false`: the definition is registered but the
    /// value is produced on the first `kv get`. A key referenced by an
    /// `[authsock.sockets.*].keys` list is preloaded automatically regardless of
    /// this flag (the agent registry needs the PEM resident at startup).
    #[serde(default)]
    pub preload: bool,

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

/// A `[kv.*]` command-source definition validated into a ready-to-register
/// shape (DR-0014 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvDefinition {
    /// The entry name (the `[kv.NAME]` key).
    pub name: String,
    /// The command argv (program first) whose stdout is the value.
    pub command: Vec<String>,
    /// Parsed soft TTL in seconds, or `None`.
    pub soft_ttl_secs: Option<u64>,
    /// Parsed hard TTL in seconds, or `None`.
    pub hard_ttl_secs: Option<u64>,
    /// Whether to run the command at startup (eager) instead of lazily on first
    /// get. Defaults to `false` (lazy).
    pub preload: bool,
}

/// An error in the configuration file's *content* (distinct from I/O / TOML
/// syntax errors, which are reported separately by [`load`]).
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// Human-readable description (no secret material — config holds none).
    pub message: String,
}

impl ConfigError {
    /// Build a content error from a human-readable (secret-free) message. Used
    /// by the config parser and the defs-file parser (`defs.rs`), which share
    /// the `[kv.*]` grammar.
    pub fn new(message: impl Into<String>) -> Self {
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
    /// Validate this entry against the schema rules and produce a [`KvDefinition`].
    ///
    /// Rejects inline literal values (`value` / `value-stdin` / `static`), a
    /// missing `command`, and unparseable TTL strings.
    fn validate(&self, name: &str) -> Result<KvDefinition, ConfigError> {
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
                "[kv.{name}]: a `static` source cannot be defined from config — only `command` entries may be defined"
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
                    "[kv.{name}]: a definition entry requires a `command` source"
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

        Ok(KvDefinition {
            name: name.to_string(),
            command,
            soft_ttl_secs,
            hard_ttl_secs,
            preload: self.preload,
        })
    }
}

impl AuthsockSocketConfig {
    /// Validate this socket against the schema rules and produce an
    /// [`AuthsockSocket`].
    ///
    /// Rejects an empty `path`, and a socket with neither `keys` nor `upstreams`
    /// (it would answer REQUEST_IDENTITIES with nothing and could never sign).
    fn validate(&self, name: &str) -> Result<AuthsockSocket, ConfigError> {
        if self.path.trim().is_empty() {
            return Err(ConfigError::new(format!(
                "[authsock.sockets.{name}]: `path` must not be empty"
            )));
        }
        if self.keys.is_empty() && self.upstreams.is_empty() && self.source.is_none() {
            return Err(ConfigError::new(format!(
                "[authsock.sockets.{name}]: needs at least one of `keys` (local KV keys), \
                 `upstreams` (forwarded agent sockets), or `source` (a discovered key source)"
            )));
        }
        // Validate the filter tokens at startup so a bad pattern fails fast and
        // names the socket. A successful parse is discarded — the daemon rebuilds
        // the evaluator from the stored tokens. (A `keyfile=` filter reads its
        // file here, surfacing a missing/unreadable keyfile at startup too.)
        cache_warden_authsock::FilterEvaluator::parse(&self.filters).map_err(|e| {
            ConfigError::new(format!("[authsock.sockets.{name}]: invalid `filters`: {e}"))
        })?;
        Ok(AuthsockSocket {
            name: name.to_string(),
            path: expand_tilde(&self.path),
            keys: self.keys.clone(),
            upstreams: self.upstreams.iter().map(|p| expand_tilde(p)).collect(),
            source: self.source.clone(),
            filters: self.filters.clone(),
            allowed_processes: self.allowed_processes.clone(),
        })
    }
}

impl AuthsockSourceConfig {
    /// Validate this source and produce an [`AuthsockSource`].
    ///
    /// Rejects an unknown `kind` (only `"op"` today) and unparseable TTLs. An
    /// empty `members` defaults to `["op://"]` (all SSH keys), and each member is
    /// checked to be a valid `op://` reference so a typo fails at startup.
    fn validate(&self, name: &str) -> Result<AuthsockSource, ConfigError> {
        if self.kind != "op" {
            return Err(ConfigError::new(format!(
                "[authsock.sources.{name}]: unsupported `kind` {:?} (only \"op\" is supported)",
                self.kind
            )));
        }
        let members = if self.members.is_empty() {
            vec!["op://".to_string()]
        } else {
            self.members.clone()
        };
        for m in &members {
            if cache_warden_authsock::OpSource::parse(m).is_none() {
                return Err(ConfigError::new(format!(
                    "[authsock.sources.{name}]: member {m:?} is not an `op://` reference"
                )));
            }
        }
        let parse = |label: &str, s: &Option<String>| -> Result<Option<u64>, ConfigError> {
            match s {
                None => Ok(None),
                Some(v) => parse_duration(v).map(|d| Some(d.as_secs())).map_err(|e| {
                    ConfigError::new(format!("[authsock.sources.{name}]: {label}: {e}"))
                }),
            }
        };
        Ok(AuthsockSource {
            name: name.to_string(),
            op_account: self.op_account.clone(),
            members,
            soft_ttl_secs: parse("soft-ttl", &self.soft_ttl)?,
            hard_ttl_secs: parse("hard-ttl", &self.hard_ttl)?,
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
        // Eagerly validate every definition entry so a bad entry fails fast at
        // startup rather than at first `get`.
        for (name, entry) in &cfg.kv {
            entry.validate(name).map_err(ConfigParseError::Content)?;
        }
        // Validate authsock sources (bad kind / member / TTL fail fast).
        for (name, src) in &cfg.authsock.sources {
            src.validate(name).map_err(ConfigParseError::Content)?;
        }
        // Validate authsock sockets too (empty path / keys fail fast at startup),
        // and cross-check that any `source` reference names a declared source.
        for (name, sock) in &cfg.authsock.sockets {
            sock.validate(name).map_err(ConfigParseError::Content)?;
            if let Some(src) = &sock.source
                && !cfg.authsock.sources.contains_key(src)
            {
                return Err(ConfigParseError::Content(ConfigError::new(format!(
                    "[authsock.sockets.{name}]: `source` {src:?} is not a declared \
                     [authsock.sources.*]"
                ))));
            }
        }
        // Validate the github filter durations eagerly so a bad TTL / timeout
        // fails at startup rather than at first fetch.
        cfg.authsock
            .github
            .cache_ttl_duration()
            .map_err(ConfigParseError::Content)?;
        cfg.authsock
            .github
            .timeout_duration()
            .map_err(ConfigParseError::Content)?;
        // Validate `[cli].default-mode` eagerly: only "reveal" / "dry-run" are
        // accepted, so a typo (`default-mode = "dryrun"`) fails at startup.
        if let Some(m) = &cfg.cli.default_mode
            && m != "reveal"
            && m != "dry-run"
        {
            return Err(ConfigParseError::Content(ConfigError::new(format!(
                "[cli]: `default-mode` must be \"reveal\" or \"dry-run\", got {m:?}"
            ))));
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

    /// The validated `[kv.*]` definitions, in deterministic (name-sorted) order.
    ///
    /// Pre-validated by [`Config::parse`], so this cannot fail; it re-runs the
    /// (cheap, infallible-at-this-point) conversion.
    pub fn kv_definitions(&self) -> Vec<KvDefinition> {
        self.kv
            .iter()
            .filter_map(|(name, entry)| entry.validate(name).ok())
            .collect()
    }

    /// The configured socket path with a leading `~/` expanded, if set.
    pub fn socket_path(&self) -> Option<PathBuf> {
        self.daemon.socket.as_deref().map(expand_tilde)
    }

    /// Whether online definitions are persisted across restarts (DR-0014 §4).
    pub fn persist_definitions(&self) -> bool {
        self.daemon.persist_definitions
    }

    /// The configured default reveal/dry-run [`Mode`](crate::mode::Mode), or
    /// `None` when `[cli].default-mode` is unset (DR-0015 §4).
    pub fn cli_default_mode(&self) -> Option<crate::mode::Mode> {
        self.cli.default_mode()
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

    /// The `github` filter settings (cache TTL / fetch timeout).
    pub fn authsock_github(&self) -> &GithubConfig {
        &self.authsock.github
    }

    /// The validated authsock key sources, in deterministic (name-sorted) order.
    /// Pre-validated by [`Config::parse`], so this cannot fail.
    pub fn authsock_sources(&self) -> Vec<AuthsockSource> {
        self.authsock
            .sources
            .iter()
            .filter_map(|(name, src)| src.validate(name).ok())
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
        assert!(cfg.kv_definitions().is_empty());
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
    fn cli_default_mode_absent_is_none() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.cli_default_mode(), None);
    }

    #[test]
    fn cli_default_mode_reveal_and_dry_run_parse() {
        let cfg = Config::parse("[cli]\ndefault-mode = \"reveal\"\n").unwrap();
        assert_eq!(cfg.cli_default_mode(), Some(crate::mode::Mode::Reveal));
        let cfg = Config::parse("[cli]\ndefault-mode = \"dry-run\"\n").unwrap();
        assert_eq!(cfg.cli_default_mode(), Some(crate::mode::Mode::DryRun));
    }

    #[test]
    fn cli_default_mode_invalid_is_rejected() {
        let err = Config::parse("[cli]\ndefault-mode = \"dryrun\"\n").unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("default-mode")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn cli_unknown_field_is_rejected() {
        let err = Config::parse("[cli]\nbogus = 1\n").unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn persist_definitions_defaults_to_false() {
        let cfg = Config::parse("").unwrap();
        assert!(!cfg.persist_definitions());
        // Also when [daemon] is present but the flag is omitted.
        let cfg = Config::parse("[daemon]\nsocket = \"/tmp/x.sock\"\n").unwrap();
        assert!(!cfg.persist_definitions());
    }

    #[test]
    fn persist_definitions_is_read_when_true() {
        let cfg = Config::parse("[daemon]\npersist-definitions = true\n").unwrap();
        assert!(cfg.persist_definitions());
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
        let entries = cfg.kv_definitions();
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
        let names: Vec<_> = cfg.kv_definitions().into_iter().map(|e| e.name).collect();
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
    fn authsock_socket_with_empty_keys_and_no_upstreams_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = []
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => {
                assert!(e.message.contains("`keys`") && e.message.contains("`upstreams`"))
            }
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn authsock_socket_upstreams_are_read_and_tilde_expanded() {
        let cfg = Config::parse(
            r#"[authsock.sockets.default]
path = "/tmp/cache-warden.sock"
keys = ["GITHUB_KEY"]
upstreams = ["~/.1password/agent.sock", "/tmp/other.sock"]
"#,
        )
        .unwrap();
        // SAFETY: single-threaded test.
        let saved = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", "/home/tester") };
        let socks = cfg.authsock_sockets();
        match saved {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(
            socks[0].upstreams,
            vec![
                PathBuf::from("/home/tester/.1password/agent.sock"),
                PathBuf::from("/tmp/other.sock"),
            ]
        );
    }

    #[test]
    fn authsock_socket_with_only_upstreams_is_allowed() {
        // An upstream-only socket (no local KV keys) is valid: it just forwards.
        let cfg = Config::parse(
            r#"[authsock.sockets.proxy]
path = "/tmp/p.sock"
upstreams = ["/tmp/agent.sock"]
"#,
        )
        .unwrap();
        let socks = cfg.authsock_sockets();
        assert_eq!(socks.len(), 1);
        assert!(socks[0].keys.is_empty());
        assert_eq!(socks[0].upstreams, vec![PathBuf::from("/tmp/agent.sock")]);
    }

    #[test]
    fn authsock_socket_omitting_upstreams_defaults_to_empty() {
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
"#,
        )
        .unwrap();
        assert!(cfg.authsock_sockets()[0].upstreams.is_empty());
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

    // ---- authsock allowed_processes (port plan Iteration 5) ----

    #[test]
    fn authsock_socket_omitting_allowed_processes_defaults_to_empty() {
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
"#,
        )
        .unwrap();
        // The common case (kawaz's real config): no restriction.
        assert!(cfg.authsock_sockets()[0].allowed_processes.is_empty());
    }

    #[test]
    fn authsock_socket_allowed_processes_are_read() {
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
allowed_processes = ["ssh", "git"]
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.authsock_sockets()[0].allowed_processes,
            vec!["ssh".to_string(), "git".to_string()]
        );
    }

    #[test]
    fn authsock_socket_empty_allowed_processes_list_is_no_restriction() {
        // An explicit empty list is valid and means "no restriction" (same as
        // omitting the key) — it does not turn the socket into a deny-all.
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
allowed_processes = []
"#,
        )
        .unwrap();
        assert!(cfg.authsock_sockets()[0].allowed_processes.is_empty());
    }

    // ---- authsock filters ----

    #[test]
    fn authsock_socket_omitting_filters_defaults_to_empty() {
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
"#,
        )
        .unwrap();
        assert!(cfg.authsock_sockets()[0].filters.is_empty());
    }

    #[test]
    fn authsock_socket_string_filter_is_a_single_rule_or_term() {
        let cfg = Config::parse(
            r#"[authsock.sockets.github]
path = "/tmp/g.sock"
keys = ["K"]
filters = ["comment=github*"]
"#,
        )
        .unwrap();
        let socks = cfg.authsock_sockets();
        assert_eq!(socks[0].filters, vec![vec!["comment=github*".to_string()]]);
    }

    #[test]
    fn authsock_socket_mixed_string_and_array_filters_parse_as_or_of_and() {
        // "f1", "f2", ["f3", "f4"] => f1 || f2 || (f3 && f4)
        let cfg = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
filters = ["comment=a*", "type=ed25519", ["comment=*work*", "type=rsa"]]
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.authsock_sockets()[0].filters,
            vec![
                vec!["comment=a*".to_string()],
                vec!["type=ed25519".to_string()],
                vec!["comment=*work*".to_string(), "type=rsa".to_string()],
            ]
        );
    }

    #[test]
    fn authsock_socket_invalid_filter_token_is_rejected_naming_socket() {
        let err = Config::parse(
            r#"[authsock.sockets.broken]
path = "/tmp/s.sock"
keys = ["K"]
filters = ["bogus=x"]
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => {
                assert!(
                    e.message.contains("broken"),
                    "must name the socket: {}",
                    e.message
                );
                assert!(e.message.contains("filters"), "msg: {}", e.message);
            }
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn authsock_socket_invalid_filter_regex_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
filters = ["comment=~[invalid"]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Content(_)));
    }

    #[test]
    fn authsock_socket_non_string_filter_element_is_toml_error() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
keys = ["K"]
filters = [42]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    // ---- authsock github filter settings ----

    #[test]
    fn github_settings_default_to_1h_and_10s() {
        let cfg = Config::parse("").unwrap();
        let g = cfg.authsock_github();
        assert_eq!(g.cache_ttl, "1h");
        assert_eq!(g.timeout, "10s");
        assert_eq!(g.cache_ttl_duration().unwrap().as_secs(), 3600);
        assert_eq!(g.timeout_duration().unwrap().as_secs(), 10);
    }

    #[test]
    fn github_settings_are_read_and_parsed() {
        let cfg = Config::parse(
            r#"[authsock.github]
cache_ttl = "30m"
timeout = "5s"
"#,
        )
        .unwrap();
        let g = cfg.authsock_github();
        assert_eq!(g.cache_ttl_duration().unwrap().as_secs(), 1800);
        assert_eq!(g.timeout_duration().unwrap().as_secs(), 5);
    }

    #[test]
    fn github_bad_cache_ttl_is_rejected() {
        let err = Config::parse(
            r#"[authsock.github]
cache_ttl = "1day"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("cache_ttl")),
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn github_bad_timeout_is_rejected() {
        let err = Config::parse(
            r#"[authsock.github]
timeout = "soon"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Content(_)));
    }

    #[test]
    fn github_unknown_field_is_rejected() {
        let err = Config::parse(
            r#"[authsock.github]
bogus = 1
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn socket_can_combine_op_source_and_github_filter() {
        // kawaz's real setup: an op-backed source socket also filtered by github.
        let cfg = Config::parse(
            r#"[authsock.sources.default]
kind = "op"

[authsock.sockets.kawaz]
path = "/tmp/kawaz.sock"
source = "default"
filters = ["github=kawaz"]
"#,
        )
        .unwrap();
        let socks = cfg.authsock_sockets();
        assert_eq!(socks[0].source.as_deref(), Some("default"));
        assert_eq!(socks[0].filters, vec![vec!["github=kawaz".to_string()]]);
    }

    // ---- authsock sources (op discovery; port plan Iteration 4) ----

    #[test]
    fn empty_config_has_no_authsock_sources() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.authsock_sources().is_empty());
    }

    #[test]
    fn op_source_with_account_and_ttls_validates() {
        let cfg = Config::parse(
            r#"[authsock.sources.default]
kind = "op"
op_account = "kawaz.1password.com"
members = ["op://", "op://Private/key"]
soft-ttl = "1h"
hard-ttl = "24h"
"#,
        )
        .unwrap();
        let sources = cfg.authsock_sources();
        assert_eq!(sources.len(), 1);
        let s = &sources[0];
        assert_eq!(s.name, "default");
        assert_eq!(s.op_account.as_deref(), Some("kawaz.1password.com"));
        assert_eq!(s.members, vec!["op://", "op://Private/key"]);
        assert_eq!(s.soft_ttl_secs, Some(3600));
        assert_eq!(s.hard_ttl_secs, Some(86400));
    }

    #[test]
    fn op_source_empty_members_default_to_bare_op() {
        let cfg = Config::parse(
            r#"[authsock.sources.default]
kind = "op"
"#,
        )
        .unwrap();
        assert_eq!(cfg.authsock_sources()[0].members, vec!["op://"]);
    }

    #[test]
    fn op_source_unknown_kind_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sources.x]
kind = "vault"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => {
                assert!(e.message.contains("kind"), "msg: {}", e.message)
            }
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn op_source_non_op_member_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sources.x]
kind = "op"
members = ["agent:/tmp/agent.sock"]
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => {
                assert!(e.message.contains("op://"), "msg: {}", e.message)
            }
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn op_source_bad_ttl_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sources.x]
kind = "op"
soft-ttl = "1day"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Content(_)));
    }

    #[test]
    fn op_source_missing_kind_is_toml_error() {
        // `kind` has no default, so omitting it is a deserialization error.
        let err = Config::parse(
            r#"[authsock.sources.x]
members = ["op://"]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn op_source_unknown_field_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sources.x]
kind = "op"
bogus = 1
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigParseError::Toml(_)));
    }

    #[test]
    fn sources_are_sorted_by_name() {
        let cfg = Config::parse(
            r#"[authsock.sources.bbb]
kind = "op"

[authsock.sources.aaa]
kind = "op"
"#,
        )
        .unwrap();
        let names: Vec<_> = cfg.authsock_sources().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["aaa", "bbb"]);
    }

    // ---- socket `source` reference ----

    #[test]
    fn socket_referencing_a_source_validates() {
        let cfg = Config::parse(
            r#"[authsock.sources.default]
kind = "op"

[authsock.sockets.kawaz]
path = "/tmp/kawaz.sock"
source = "default"
filters = ["comment=*kawaz*"]
"#,
        )
        .unwrap();
        let socks = cfg.authsock_sockets();
        assert_eq!(socks[0].source.as_deref(), Some("default"));
        assert!(socks[0].keys.is_empty());
    }

    #[test]
    fn socket_with_only_a_source_is_allowed() {
        // A source-only socket (no local keys, no upstreams) is valid.
        let cfg = Config::parse(
            r#"[authsock.sources.default]
kind = "op"

[authsock.sockets.s]
path = "/tmp/s.sock"
source = "default"
"#,
        )
        .unwrap();
        assert_eq!(cfg.authsock_sockets().len(), 1);
    }

    #[test]
    fn socket_referencing_unknown_source_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
source = "ghost"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => {
                assert!(e.message.contains("ghost"), "msg: {}", e.message);
                assert!(e.message.contains("source"), "msg: {}", e.message);
            }
            other => panic!("expected content error, got {other:?}"),
        }
    }

    #[test]
    fn socket_with_no_keys_upstreams_or_source_is_rejected() {
        let err = Config::parse(
            r#"[authsock.sockets.s]
path = "/tmp/s.sock"
"#,
        )
        .unwrap_err();
        match err {
            ConfigParseError::Content(e) => assert!(e.message.contains("source")),
            other => panic!("expected content error, got {other:?}"),
        }
    }
}
