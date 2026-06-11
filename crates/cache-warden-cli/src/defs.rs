//! Definition files (`--defs FILE`) and the persisted-definition state file.
//!
//! Both speak the **same TOML grammar** as the daemon config's `[kv.*]` section
//! (DR-0014 §4) — a subset: each `[kv.NAME]` table carries a `command` argv plus
//! optional `soft-ttl` / `hard-ttl`. The static-value prohibition of the config
//! schema is inherited (a `value` / `value-stdin` / `static` key is rejected),
//! and `preload` — which only makes sense for the daemon's startup-eager config
//! entries — is **rejected** here so a stray flag is surfaced rather than
//! silently ignored (DR-0014 §4: "static values cannot be written" rule
//! inherited; an unusable key is an error, matching `deny_unknown_fields`).
//!
//! # Two callers, one grammar
//!
//! - `kv define --defs FILE` parses a user-authored defs file into a list of
//!   [`KvDefinition`]s, each of which the CLI registers via one `kv.define`
//!   request ([`parse_defs_file`]).
//! - The daemon, when `[daemon].persist-definitions = true`, writes its online
//!   definition registry to `$XDG_STATE_HOME/cache-warden/definitions.toml`
//!   ([`serialize_definitions`] / [`save_definitions`]) and restores it at
//!   startup ([`load_definitions`]). The persisted file holds **definitions
//!   only** — KEY / argv / TTL — never a secret value (DR-0014 §4).
//!
//! # No automatic discovery
//!
//! There is deliberately no implicit load of a `.cache-warden.toml` in the cwd:
//! an untrusted repo's file becoming a command definition is a data→code
//! boundary break (DR-0014 §4). `--defs` is always explicit; the conventional
//! name `.cache-warden.toml` is documentation only, with no special-casing in
//! code.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use cache_warden::Store;

use crate::config::{ConfigError, KvDefinition};
use crate::protocol::parse_duration;

/// Snapshot the store's definition registry as a list of [`KvDefinition`]s
/// (name-sorted), for persistence.
///
/// Reads only the **definition** registry (KEY / argv / TTL) — never a value
/// (DR-0014 §4). A definition is command-only by construction, so a static
/// source (which cannot happen for a registered definition) is skipped
/// defensively. The result feeds [`serialize_definitions`] / [`save_definitions`].
pub fn snapshot_definitions(store: &Store) -> Vec<KvDefinition> {
    let mut out = Vec::new();
    for key in store.keys() {
        let Some(def) = store.definition_of(key) else {
            continue; // value-only key: nothing to persist
        };
        let Some(argv) = def.source().command_argv() else {
            continue; // defensively skip a non-command definition
        };
        let ttl = def.ttl();
        out.push(KvDefinition {
            name: key.to_string(),
            command: argv.to_vec(),
            soft_ttl_secs: ttl.soft().map(|d| d.as_secs()),
            hard_ttl_secs: ttl.hard().map(|d| d.as_secs()),
            preload: false,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// One `[kv.NAME]` table in a defs / persisted-definitions file.
///
/// The same subset grammar as the config `[kv.*]` section, minus `preload`
/// (rejected here — see the module note). The forbidden-on-purpose keys
/// (`value` / `value-stdin` / `static` / `preload`) are typed as
/// `Option<toml::Value>` only so a clear error can be raised; they are otherwise
/// unused.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefEntry {
    /// The command argv (program first) whose stdout is the value.
    #[serde(default)]
    command: Option<Vec<String>>,
    /// Soft TTL string (e.g. `"1h"`).
    #[serde(default, rename = "soft-ttl")]
    soft_ttl: Option<String>,
    /// Hard TTL string (e.g. `"24h"`).
    #[serde(default, rename = "hard-ttl")]
    hard_ttl: Option<String>,

    // --- Forbidden-on-purpose keys (rejected with a clear error) ---
    /// `preload` is a config-only startup flag; meaningless in a defs file.
    #[serde(default)]
    preload: Option<toml::Value>,
    /// Present only to reject inline literal values.
    #[serde(default)]
    value: Option<toml::Value>,
    /// Present only to reject inline literal values.
    #[serde(default, rename = "value-stdin")]
    value_stdin: Option<toml::Value>,
    /// Present only to reject a `static` source declaration.
    #[serde(default)]
    r#static: Option<toml::Value>,
}

/// The whole defs / persisted-definitions file: a map of `[kv.NAME]` tables.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefsFile {
    /// Definitions keyed by entry name. A `BTreeMap` keeps deterministic
    /// (name-sorted) order for predictable processing and round-tripping.
    #[serde(default)]
    kv: BTreeMap<String, DefEntry>,
}

impl DefEntry {
    /// Validate this entry against the defs grammar and produce a
    /// [`KvDefinition`]. Rejects `preload`, inline literal values, a missing /
    /// empty `command`, and unparseable TTL strings.
    fn validate(&self, name: &str) -> Result<KvDefinition, ConfigError> {
        if self.preload.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: `preload` is not allowed in a defs file — it is a \
                 config-only startup flag; defs definitions are always lazy"
            )));
        }
        if self.value.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: inline `value` is not allowed — defs files declare \
                 regenerable command definitions only, never literal secrets"
            )));
        }
        if self.value_stdin.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: `value-stdin` is not a defs key — inject literal \
                 values at runtime with `cache-warden kv set --value-stdin`"
            )));
        }
        if self.r#static.is_some() {
            return Err(ConfigError::new(format!(
                "[kv.{name}]: a `static` source cannot be defined — only `command` \
                 entries may be defined"
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

        Ok(KvDefinition {
            name: name.to_string(),
            command,
            soft_ttl_secs: parse("soft-ttl", &self.soft_ttl)?,
            hard_ttl_secs: parse("hard-ttl", &self.hard_ttl)?,
            // Defs / persisted definitions are always lazy — `preload` is
            // rejected above, so this is unconditionally false.
            preload: false,
        })
    }
}

/// Parse defs-file TOML text into validated [`KvDefinition`]s (name-sorted).
///
/// Returns a content [`ConfigError`] for the first schema violation, or a TOML
/// syntax error rendered into a `ConfigError` (the caller only needs a message).
pub fn parse_defs(text: &str) -> Result<Vec<KvDefinition>, ConfigError> {
    let file: DefsFile =
        toml::from_str(text).map_err(|e| ConfigError::new(format!("invalid TOML: {e}")))?;
    file.kv
        .iter()
        .map(|(name, entry)| entry.validate(name))
        .collect()
}

/// Read and parse a defs file at `path` into validated [`KvDefinition`]s.
pub fn parse_defs_file(path: &Path) -> Result<Vec<KvDefinition>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read defs file {}: {e}", path.display()))?;
    parse_defs(&text).map_err(|e| format!("invalid defs file {}: {e}", path.display()))
}

/// Serialize a list of definitions into the defs-file TOML grammar.
///
/// The output is the same `[kv.NAME]` subset a human authors by hand, so the
/// persisted file is readable and editable. Only definition metadata is written
/// (KEY / argv / TTL); there is **no** field for a value, so a value can never
/// be serialized by construction (DR-0014 §4).
pub fn serialize_definitions(defs: &[KvDefinition]) -> String {
    // Build a deterministic (name-sorted) document by hand: `toml::to_string`
    // on a map is fine, but emitting it directly keeps the output minimal and
    // guarantees only the four allowed fields ever appear.
    let mut sorted: Vec<&KvDefinition> = defs.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = String::new();
    for (i, def) in sorted.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("[kv.{}]\n", toml_key(&def.name)));
        out.push_str(&format!("command = {}\n", toml_string_array(&def.command)));
        if let Some(secs) = def.soft_ttl_secs {
            out.push_str(&format!("soft-ttl = \"{secs}s\"\n"));
        }
        if let Some(secs) = def.hard_ttl_secs {
            out.push_str(&format!("hard-ttl = \"{secs}s\"\n"));
        }
    }
    out
}

/// Quote a table key if it is not a bare key (TOML bare keys allow
/// `A-Za-z0-9_-`). A name with other characters is rendered as a quoted key.
fn toml_key(name: &str) -> String {
    let bare = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        name.to_string()
    } else {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Render a string slice as a TOML array of basic (double-quoted) strings.
fn toml_string_array(items: &[String]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("[{}]", parts.join(", "))
}

/// The persisted-definitions state file path:
/// `$XDG_STATE_HOME/cache-warden/definitions.toml` (with the `~/.local/state`
/// fallback), the same state dir as the control socket (DR-0014 §4).
pub fn definitions_state_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(".local/state")
        });
    base.join("cache-warden").join("definitions.toml")
}

/// Load persisted definitions from `path`, returning `Ok(vec![])` if the file
/// does not exist (a first run, or persistence just turned on).
///
/// A malformed persisted file is reported as an error so the daemon can warn and
/// continue (the caller decides fatality — it is non-fatal at startup).
pub fn load_definitions(path: &Path) -> Result<Vec<KvDefinition>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_defs(&text)
            .map_err(|e| format!("invalid persisted definitions {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!(
            "cannot read persisted definitions {}: {e}",
            path.display()
        )),
    }
}

/// Atomically write `defs` to `path` (0600), creating the parent dir as needed.
///
/// Writes to a temporary file in the **same directory** (so the final `rename`
/// is atomic on the same filesystem), sets 0600 **before** the rename (no window
/// where the real path is world-readable), then renames over `path`.
pub fn save_definitions(path: &Path, defs: &[KvDefinition]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serialize_definitions(defs);

    // Temp file in the same dir as the target so `rename` stays on one
    // filesystem (atomic). A pid suffix avoids clobbering a concurrent writer's
    // temp (there is only one daemon, but cheap insurance).
    let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    // Create the temp 0600 from the start (no chmod-after window).
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let write = f
        .write_all(body.as_bytes())
        .and_then(|_| f.sync_all())
        .and_then(|_| std::fs::rename(&tmp, path));
    if write.is_err() {
        // Best-effort cleanup of the temp on failure.
        let _ = std::fs::remove_file(&tmp);
    }
    write
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(name: &str, argv: &[&str], soft: Option<u64>, hard: Option<u64>) -> KvDefinition {
        KvDefinition {
            name: name.to_string(),
            command: argv.iter().map(|s| s.to_string()).collect(),
            soft_ttl_secs: soft,
            hard_ttl_secs: hard,
            preload: false,
        }
    }

    // ---- parse_defs ----

    #[test]
    fn parses_a_single_command_entry_with_ttls() {
        let defs = parse_defs(
            r#"[kv.DB_PASSWORD]
command = ["op", "read", "op://vault/item/password"]
soft-ttl = "1h"
hard-ttl = "24h"
"#,
        )
        .unwrap();
        assert_eq!(defs.len(), 1);
        let d = &defs[0];
        assert_eq!(d.name, "DB_PASSWORD");
        assert_eq!(d.command, vec!["op", "read", "op://vault/item/password"]);
        assert_eq!(d.soft_ttl_secs, Some(3600));
        assert_eq!(d.hard_ttl_secs, Some(86400));
        assert!(!d.preload, "defs definitions are always lazy");
    }

    #[test]
    fn parses_multiple_entries_name_sorted() {
        let defs = parse_defs(
            r#"[kv.B]
command = ["echo", "b"]

[kv.A]
command = ["echo", "a"]
"#,
        )
        .unwrap();
        let names: Vec<_> = defs.iter().map(|d| d.name.clone()).collect();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn empty_file_parses_to_no_definitions() {
        assert!(parse_defs("").unwrap().is_empty());
    }

    #[test]
    fn preload_in_defs_is_rejected() {
        let err = parse_defs(
            r#"[kv.X]
command = ["echo", "x"]
preload = true
"#,
        )
        .unwrap_err();
        assert!(err.message.contains("preload"), "msg: {}", err.message);
    }

    #[test]
    fn inline_value_in_defs_is_rejected_and_not_echoed() {
        let err = parse_defs(
            r#"[kv.SECRET]
value = "hunter2"
"#,
        )
        .unwrap_err();
        assert!(err.message.contains("not allowed"), "msg: {}", err.message);
        assert!(
            !err.message.contains("hunter2"),
            "must not echo the secret: {}",
            err.message
        );
    }

    #[test]
    fn missing_command_is_rejected() {
        let err = parse_defs(
            r#"[kv.X]
soft-ttl = "1h"
"#,
        )
        .unwrap_err();
        assert!(err.message.contains("requires a `command`"));
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = parse_defs(
            r#"[kv.X]
command = []
"#,
        )
        .unwrap_err();
        assert!(err.message.contains("must not be empty"));
    }

    #[test]
    fn bad_ttl_is_rejected_naming_the_field() {
        let err = parse_defs(
            r#"[kv.X]
command = ["echo", "x"]
soft-ttl = "1day"
"#,
        )
        .unwrap_err();
        assert!(err.message.contains("soft-ttl"), "msg: {}", err.message);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = parse_defs(
            r#"[kv.X]
command = ["echo", "x"]
bogus = 1
"#,
        )
        .unwrap_err();
        assert!(err.message.contains("invalid TOML"), "msg: {}", err.message);
    }

    #[test]
    fn syntax_error_is_reported() {
        assert!(parse_defs("not = valid = toml").is_err());
    }

    // ---- serialize / round-trip ----

    #[test]
    fn serialize_then_parse_round_trips() {
        let defs = vec![
            def("A", &["op", "read", "op://a"], Some(3600), Some(86400)),
            def("B", &["printf", "x"], None, None),
        ];
        let text = serialize_definitions(&defs);
        let back = parse_defs(&text).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], defs[0]);
        assert_eq!(back[1], defs[1]);
    }

    #[test]
    fn serialize_is_name_sorted_and_value_free() {
        let defs = vec![
            def("ZED", &["echo", "z"], None, None),
            def("ABLE", &["echo", "a"], Some(60), None),
        ];
        let text = serialize_definitions(&defs);
        // Name-sorted: ABLE before ZED.
        assert!(text.find("[kv.ABLE]").unwrap() < text.find("[kv.ZED]").unwrap());
        // No value field can ever appear.
        assert!(!text.contains("value"));
    }

    #[test]
    fn serialize_quotes_non_bare_keys() {
        let defs = vec![def("a.b/c", &["echo"], None, None)];
        let text = serialize_definitions(&defs);
        assert!(text.contains("[kv.\"a.b/c\"]"), "text: {text}");
        // And it round-trips back to the same name.
        let back = parse_defs(&text).unwrap();
        assert_eq!(back[0].name, "a.b/c");
    }

    #[test]
    fn serialize_escapes_quotes_in_argv() {
        let defs = vec![def("K", &["echo", "a\"b"], None, None)];
        let text = serialize_definitions(&defs);
        let back = parse_defs(&text).unwrap();
        assert_eq!(back[0].command, vec!["echo", "a\"b"]);
    }

    // ---- load / save (atomic, 0600) ----

    #[test]
    fn load_missing_file_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("definitions.toml");
        assert!(load_definitions(&path).unwrap().is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("definitions.toml");
        let defs = vec![
            def("A", &["op", "read", "op://a"], Some(3600), Some(86400)),
            def("B", &["printf", "x"], None, None),
        ];
        save_definitions(&path, &defs).unwrap();
        let back = load_definitions(&path).unwrap();
        assert_eq!(back, defs);
    }

    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("definitions.toml");
        save_definitions(&path, &[def("K", &["echo"], None, None)]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "persisted file must be 0600");
    }

    #[test]
    fn save_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("definitions.toml");
        save_definitions(&path, &[def("K", &["echo"], None, None)]).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp left behind: {leftovers:?}");
    }

    #[test]
    fn save_empty_definitions_writes_empty_file() {
        // Persisting an empty registry (e.g. after the last `del --with-define`)
        // truncates the file to empty rather than leaving stale content.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("definitions.toml");
        save_definitions(&path, &[def("K", &["echo"], None, None)]).unwrap();
        save_definitions(&path, &[]).unwrap();
        assert!(load_definitions(&path).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("definitions.toml");
        save_definitions(&path, &[def("OLD", &["echo", "old"], None, None)]).unwrap();
        save_definitions(&path, &[def("NEW", &["echo", "new"], None, None)]).unwrap();
        let back = load_definitions(&path).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].name, "NEW");
    }

    // ---- snapshot_definitions ----

    #[test]
    fn snapshot_returns_only_definitions_name_sorted() {
        use cache_warden::{FakeClock, SecretBytes, Ttl, ValueSource};
        use std::time::Duration;
        let mut store = Store::new();
        let ttl = Ttl::new(
            Some(Duration::from_secs(3600)),
            Some(Duration::from_secs(86400)),
        )
        .unwrap();
        store
            .define(
                "ZED",
                ValueSource::command(vec!["op".into(), "read".into(), "op://z".into()]),
                ttl,
            )
            .unwrap();
        store
            .define(
                "ABLE",
                ValueSource::command(vec!["printf".into(), "x".into()]),
                Ttl::new(None, None).unwrap(),
            )
            .unwrap();
        // A static value-only entry must NOT appear in the snapshot.
        let clock = FakeClock::new();
        store.set(
            "STATIC",
            ValueSource::Static,
            SecretBytes::new(b"v".to_vec()),
            Ttl::new(None, None).unwrap(),
            &clock,
        );

        let snap = snapshot_definitions(&store);
        let names: Vec<_> = snap.iter().map(|d| d.name.clone()).collect();
        assert_eq!(names, vec!["ABLE", "ZED"], "only definitions, name-sorted");
        let zed = snap.iter().find(|d| d.name == "ZED").unwrap();
        assert_eq!(zed.command, vec!["op", "read", "op://z"]);
        assert_eq!(zed.soft_ttl_secs, Some(3600));
        assert_eq!(zed.hard_ttl_secs, Some(86400));
    }

    #[test]
    fn snapshot_round_trips_through_serialize() {
        use cache_warden::{Ttl, ValueSource};
        let mut store = Store::new();
        store
            .define(
                "K",
                ValueSource::command(vec!["echo".into(), "x".into()]),
                Ttl::new(None, None).unwrap(),
            )
            .unwrap();
        let snap = snapshot_definitions(&store);
        let back = parse_defs(&serialize_definitions(&snap)).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn state_path_uses_xdg_state_home() {
        // SAFETY: single-threaded test; saved/restored below.
        let saved = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", "/tmp/xdgstate") };
        assert_eq!(
            definitions_state_path(),
            PathBuf::from("/tmp/xdgstate/cache-warden/definitions.toml")
        );
        match saved {
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }
}
