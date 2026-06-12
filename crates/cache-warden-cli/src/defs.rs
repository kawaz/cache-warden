//! Definition files (`--defs FILE`) and the persisted-definition state file.
//!
//! Both carry the same per-entry fields as the daemon config's `[kv.*]` section
//! (DR-0014 §4) — a subset: a `command` argv plus optional `soft-ttl` /
//! `hard-ttl` (+ the value-type fields of DR-0016). The static-value
//! prohibition of the config schema is inherited (a `value` / `value-stdin` /
//! `static` key is rejected), and `preload` — which only makes sense for the
//! daemon's startup-eager config entries — is **rejected** here so a stray flag
//! is surfaced rather than silently ignored (DR-0014 §4: "static values cannot
//! be written" rule inherited; an unusable key is an error, matching
//! `deny_unknown_fields`).
//!
//! # Two callers, two table shapes (DR-0017 §5)
//!
//! - `kv define --defs FILE` parses a **user-authored** defs file: flat
//!   `[kv.NAME]` tables with an optional per-entry `namespace` field
//!   ([`parse_defs_file`], the same grammar as the daemon config).
//! - The daemon, when `[daemon].persist-definitions = true`, writes its online
//!   definition registry to `$XDG_STATE_HOME/cache-warden/definitions.toml`
//!   ([`serialize_definitions`] / [`save_definitions`]) and restores it at
//!   startup ([`load_definitions`]). The persisted format is the **uniform
//!   two-level dotted nesting `[kv.NS.KEY]`** (kv → namespace → key →
//!   definition): the file is machine-generated with every entry's namespace
//!   normalized, so the depth is uniform, and the identifier charset
//!   (`[A-Za-z0-9_]+`, no `.`) makes every segment a bare key — no quoting —
//!   with an unambiguous path-depth-to-meaning mapping. The mixed-shape
//!   ambiguity that rules dotted nesting out for the human config does not
//!   exist here. The persisted file holds **definitions only** — KEY / argv /
//!   TTL — never a secret value (DR-0014 §4).
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

use cache_warden::{Store, ValueMeta};

use crate::config::{ConfigError, KvDefinition};
use crate::protocol::parse_duration;
use crate::protocol::wire::ValueMetaWire;

/// Convert the core's opaque [`ValueMeta`] into the wire shape for persistence
/// (DR-0016). The reverse of `handler::meta_from_wire`.
fn meta_to_wire(meta: &ValueMeta) -> ValueMetaWire {
    ValueMetaWire {
        type_label: meta.type_label().map(|s| s.to_string()),
        params: meta
            .params()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

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
        // Store keys are composed `NS/KEY` (DR-0017 §1); split so the
        // persisted entry round-trips through the normalized KvDefinition
        // shape. A key that does not split (an internal daemon key) is never
        // a registered definition, but skip defensively if one appears.
        let Some((ns, key_name)) = crate::namespace::split_composed(key) else {
            continue;
        };
        out.push(KvDefinition {
            name: key_name.to_string(),
            namespace: Some(ns.to_string()),
            command: argv.to_vec(),
            soft_ttl_secs: ttl.soft().map(|d| d.as_secs()),
            hard_ttl_secs: ttl.hard().map(|d| d.as_secs()),
            preload: false,
            // Carry the opaque value-type metadata so the type round-trips
            // through the persisted-definitions file (DR-0016).
            meta: meta_to_wire(def.meta()),
        });
    }
    out.sort_by_key(|d| d.full_key(crate::namespace::DEFAULT_NAMESPACE));
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
    /// Value type (DR-0016): `"otp"` or absent (opaque).
    #[serde(default, rename = "type")]
    value_type: Option<String>,
    /// OTP digit count (only with `type = "otp"`).
    #[serde(default, rename = "otp-digits")]
    otp_digits: Option<u32>,
    /// OTP time step in seconds (only with `type = "otp"`).
    #[serde(default, rename = "otp-period")]
    otp_period: Option<u64>,
    /// OTP hash algorithm (only with `type = "otp"`).
    #[serde(default, rename = "otp-algorithm")]
    otp_algorithm: Option<String>,
    /// Pin this entry to an absolute namespace (DR-0017 §5). Absent = the
    /// context default (the `--namespace` value of the `kv define --defs`
    /// invocation, or `"default"` for the persisted-definitions file).
    #[serde(default)]
    namespace: Option<String>,

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
                "[kv.{name}]: `value-stdin` is not a defs key — pipe literal \
                 values in at runtime (`... | cache-warden kv set {name}`)"
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

        let meta = crate::config::build_kv_meta(
            name,
            &self.value_type,
            self.otp_digits,
            self.otp_period,
            &self.otp_algorithm,
        )?;
        let (key_name, namespace) = crate::config::split_kv_entry_name(name, &self.namespace)?;

        Ok(KvDefinition {
            name: key_name,
            namespace,
            command,
            soft_ttl_secs: parse("soft-ttl", &self.soft_ttl)?,
            hard_ttl_secs: parse("hard-ttl", &self.hard_ttl)?,
            // Defs / persisted definitions are always lazy — `preload` is
            // rejected above, so this is unconditionally false.
            preload: false,
            meta,
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

/// The persisted-definitions file: the uniform two-level dotted nesting
/// `kv → NS → KEY → definition` (DR-0017 §5). A flat `[kv.KEY]` table (the
/// user-defs shape) does not fit this type and is rejected by serde.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistFile {
    /// Definitions keyed by namespace, then key name. `BTreeMap`s keep a
    /// deterministic (sorted) order for predictable round-tripping.
    #[serde(default)]
    kv: BTreeMap<String, BTreeMap<String, DefEntry>>,
}

/// Parse persisted-definitions TOML text (`[kv.NS.KEY]` dotted nesting) into
/// validated [`KvDefinition`]s, each pinned to its absolute namespace.
///
/// Both path segments are charset-validated (`[A-Za-z0-9_]+`, DR-0017 §1.5):
/// TOML could express other segments via quoting, but such a file was not
/// written by us. A per-entry `namespace` field is rejected — in this format
/// the table path *is* the namespace.
fn parse_persisted(text: &str) -> Result<Vec<KvDefinition>, ConfigError> {
    let file: PersistFile =
        toml::from_str(text).map_err(|e| ConfigError::new(format!("invalid TOML: {e}")))?;
    let mut out = Vec::new();
    for (ns, entries) in &file.kv {
        crate::namespace::validate_identifier(ns, "namespace")
            .map_err(|e| ConfigError::new(format!("[kv.{ns}]: {e}")))?;
        for (key, entry) in entries {
            crate::namespace::validate_identifier(key, "KEY")
                .map_err(|e| ConfigError::new(format!("[kv.{ns}.{key}]: {e}")))?;
            if entry.namespace.is_some() {
                return Err(ConfigError::new(format!(
                    "[kv.{ns}.{key}]: a `namespace` field is not allowed in the                      persisted format — the table path is the namespace"
                )));
            }
            // `validate` sees the plain KEY (an identifier), so the entry's
            // (absent) namespace field yields None; pin the path namespace.
            let mut def = entry.validate(key)?;
            def.namespace = Some(ns.clone());
            out.push(def);
        }
    }
    Ok(out)
}

/// Serialize a list of definitions into the persisted-definitions TOML format:
/// the uniform two-level dotted nesting `[kv.NS.KEY]` (DR-0017 §5).
///
/// Two same-named keys in different namespaces are two distinct tables. Every
/// path segment is an identifier (`[A-Za-z0-9_]+`, guaranteed by the protocol
/// boundary for everything in the store), so segments are always TOML bare
/// keys — the narrowed charset exists precisely so no quoting is ever needed.
/// Only definition metadata is written (KEY / argv / TTL); there is **no**
/// field for a value, so a value can never be serialized by construction
/// (DR-0014 §4).
pub fn serialize_definitions(defs: &[KvDefinition]) -> String {
    // Build a deterministic (namespace-then-key sorted) document by hand:
    // emitting directly keeps the output minimal and guarantees only the
    // allowed fields ever appear.
    let mut sorted: Vec<&KvDefinition> = defs.iter().collect();
    sorted.sort_by_key(|d| d.full_key(crate::namespace::DEFAULT_NAMESPACE));

    let mut out = String::new();
    for (i, def) in sorted.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let ns = def
            .namespace
            .as_deref()
            .unwrap_or(crate::namespace::DEFAULT_NAMESPACE);
        out.push_str(&format!("[kv.{ns}.{}]\n", def.name));
        out.push_str(&format!("command = {}\n", toml_string_array(&def.command)));
        if let Some(secs) = def.soft_ttl_secs {
            out.push_str(&format!("soft-ttl = \"{secs}s\"\n"));
        }
        if let Some(secs) = def.hard_ttl_secs {
            out.push_str(&format!("hard-ttl = \"{secs}s\"\n"));
        }
        // Value-type metadata (DR-0016): write `type` + any otp-* params so the
        // type round-trips. Values are simple numbers / labels — no escaping
        // beyond the basic-string quoting used elsewhere.
        if let Some((ty, digits, period, algorithm)) = crate::config::meta_to_toml_fields(&def.meta)
        {
            out.push_str(&format!("type = \"{ty}\"\n"));
            if let Some(d) = digits {
                out.push_str(&format!("otp-digits = {d}\n"));
            }
            if let Some(p) = period {
                out.push_str(&format!("otp-period = {p}\n"));
            }
            if let Some(a) = algorithm {
                out.push_str(&format!("otp-algorithm = \"{a}\"\n"));
            }
        }
    }
    out
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
        Ok(text) => parse_persisted(&text)
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
            namespace: None,
            command: argv.iter().map(|s| s.to_string()).collect(),
            soft_ttl_secs: soft,
            hard_ttl_secs: hard,
            preload: false,
            meta: Default::default(),
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

    // ---- value type (DR-0016) ----

    #[test]
    fn parses_an_otp_typed_entry_with_params() {
        let defs = parse_defs(
            r#"[kv.OTP]
command = ["op", "read", "op://vault/item/field"]
type = "otp"
otp-digits = 8
otp-period = 60
otp-algorithm = "SHA256"
"#,
        )
        .unwrap();
        assert_eq!(defs.len(), 1);
        let d = &defs[0];
        assert_eq!(d.meta.type_label.as_deref(), Some("otp"));
        assert_eq!(d.meta.params.get("digits").map(String::as_str), Some("8"));
        assert_eq!(d.meta.params.get("period").map(String::as_str), Some("60"));
        // Algorithm normalized to lowercase.
        assert_eq!(
            d.meta.params.get("algorithm").map(String::as_str),
            Some("sha256")
        );
    }

    #[test]
    fn otp_params_without_type_are_rejected() {
        let err = parse_defs(
            r#"[kv.X]
command = ["echo", "x"]
otp-digits = 8
"#,
        )
        .unwrap_err();
        assert!(
            err.message.contains("type = \"otp\""),
            "msg: {}",
            err.message
        );
    }

    #[test]
    fn unknown_type_in_defs_is_rejected() {
        let err = parse_defs(
            r#"[kv.X]
command = ["echo", "x"]
type = "magic"
"#,
        )
        .unwrap_err();
        assert!(
            err.message.contains("unknown `type`"),
            "msg: {}",
            err.message
        );
    }

    #[test]
    fn otp_typed_definition_round_trips_through_serialize() {
        // A serialized otp definition parses back to the same meta (DR-0016).
        let mut d = def("OTP", &["op", "read", "op://v/i/f"], Some(3600), None);
        d.meta = crate::protocol::wire::ValueMetaWire {
            type_label: Some("otp".to_string()),
            params: [
                ("digits".to_string(), "8".to_string()),
                ("algorithm".to_string(), "sha512".to_string()),
            ]
            .into_iter()
            .collect(),
        };
        let text = serialize_definitions(std::slice::from_ref(&d));
        assert!(text.contains("type = \"otp\""), "text: {text}");
        assert!(text.contains("otp-digits = 8"), "text: {text}");
        let back = parse_persisted(&text).unwrap();
        // Persisted entries come back with an absolute namespace (the dotted
        // table path); the composed key round-trips exactly.
        assert_eq!(back[0].full_key("ignored"), d.full_key("default"));
        assert_eq!(back[0].meta, d.meta, "otp meta round-trips");
    }

    // ---- serialize / round-trip ----

    #[test]
    fn serialize_then_parse_round_trips() {
        let defs = vec![
            def("A", &["op", "read", "op://a"], Some(3600), Some(86400)),
            def("B", &["printf", "x"], None, None),
        ];
        let text = serialize_definitions(&defs);
        let back = parse_persisted(&text).unwrap();
        assert_eq!(back.len(), 2);
        // The persisted form pins the absolute namespace; the composed key,
        // argv, and TTLs round-trip exactly (DR-0017 §5).
        for (b, d) in back.iter().zip(defs.iter()) {
            assert_eq!(b.full_key("ignored"), d.full_key("default"));
            assert_eq!(b.command, d.command);
            assert_eq!(b.soft_ttl_secs, d.soft_ttl_secs);
            assert_eq!(b.hard_ttl_secs, d.hard_ttl_secs);
        }
    }

    #[test]
    fn serialize_is_name_sorted_and_value_free() {
        let defs = vec![
            def("ZED", &["echo", "z"], None, None),
            def("ABLE", &["echo", "a"], Some(60), None),
        ];
        let text = serialize_definitions(&defs);
        // Dotted nested tables (no quoting needed: the charset has no `.`),
        // name-sorted: ABLE before ZED.
        let able = text.find("[kv.default.ABLE]").expect("ABLE table");
        let zed = text.find("[kv.default.ZED]").expect("ZED table");
        assert!(able < zed, "name-sorted: {text}");
        // No value field can ever appear.
        assert!(!text.contains("value"));
        // And no quoted table names: the identifier charset (DR-0017 §1.5)
        // makes every segment a TOML bare key.
        assert!(!text.contains('"') || !text.contains("[kv.\""), "{text}");
    }

    #[test]
    fn serialize_writes_dotted_nested_tables() {
        // The persisted format is the uniform two-level dotted nesting
        // `[kv.NS.KEY]` (DR-0017 §5): the identifier charset has no `.`, so
        // every segment is a bare key (no quoting) and the path depth is
        // unambiguous. It parses back to the same key + absolute namespace.
        let mut d = def("c", &["echo"], None, None);
        d.namespace = Some("projA".into());
        let text = serialize_definitions(std::slice::from_ref(&d));
        assert!(text.contains("[kv.projA.c]"), "text: {text}");
        let back = parse_persisted(&text).unwrap();
        assert_eq!(back[0].name, "c");
        assert_eq!(back[0].namespace.as_deref(), Some("projA"));
    }

    #[test]
    fn serialize_same_key_in_two_namespaces_coexists() {
        // The whole point of the nesting: the same KEY under two namespaces is
        // two distinct tables (impossible as flat `[kv.KEY]`).
        let mut a = def("DB", &["echo", "a"], None, None);
        a.namespace = Some("projA".into());
        let mut b = def("DB", &["echo", "b"], None, None);
        b.namespace = Some("projB".into());
        let text = serialize_definitions(&[a, b]);
        assert!(text.contains("[kv.projA.DB]"), "{text}");
        assert!(text.contains("[kv.projB.DB]"), "{text}");
        let back = parse_persisted(&text).unwrap();
        assert_eq!(back.len(), 2);
        let keys: Vec<String> = back.iter().map(|d| d.full_key("ignored")).collect();
        assert_eq!(keys, vec!["projA/DB", "projB/DB"]);
    }

    #[test]
    fn persisted_parser_rejects_flat_entries() {
        // The persisted grammar is uniformly two-level; a flat `[kv.KEY]`
        // table (the user-defs shape) does not parse.
        let err = parse_persisted("[kv.K]\ncommand = [\"echo\"]\n").unwrap_err();
        assert!(err.message.contains("invalid TOML"), "msg: {}", err.message);
    }

    #[test]
    fn persisted_parser_rejects_namespace_field() {
        // In the persisted format the namespace IS the table path; a stray
        // per-entry `namespace` field is ambiguous and refused.
        let err = parse_persisted("[kv.projA.K]\nnamespace = \"projB\"\ncommand = [\"echo\"]\n")
            .unwrap_err();
        assert!(err.message.contains("namespace"), "msg: {}", err.message);
    }

    #[test]
    fn persisted_parser_validates_segment_charset() {
        // Quoted segments outside the identifier charset are rejected even
        // though TOML can express them.
        assert!(parse_persisted("[kv.\"a-b\".K]\ncommand = [\"echo\"]\n").is_err());
        assert!(parse_persisted("[kv.NS.\"a.b\"]\ncommand = [\"echo\"]\n").is_err());
    }

    #[test]
    fn user_defs_parser_rejects_quoted_composed_table_names() {
        // The old persisted shape (`[kv."NS/KEY"]`) is gone: a user-defs table
        // name is a plain identifier; the namespace travels in the per-entry
        // field only.
        let err = parse_defs("[kv.\"projA/c\"]\ncommand = [\"echo\"]\n").unwrap_err();
        assert!(err.message.contains("A-Za-z0-9_"), "msg: {}", err.message);
    }

    #[test]
    fn user_defs_parser_rejects_dotted_nesting() {
        // The user-facing defs grammar stays flat `[kv.NAME]` (+ optional
        // per-entry `namespace` field); the persisted nesting is not valid
        // there (the shapes stay distinct on purpose).
        assert!(parse_defs("[kv.NS.KEY]\ncommand = [\"echo\"]\n").is_err());
    }

    #[test]
    fn serialize_escapes_quotes_in_argv() {
        let defs = vec![def("K", &["echo", "a\"b"], None, None)];
        let text = serialize_definitions(&defs);
        let back = parse_persisted(&text).unwrap();
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
        assert_eq!(back.len(), defs.len());
        for (b, d) in back.iter().zip(defs.iter()) {
            assert_eq!(b.full_key("ignored"), d.full_key("default"));
            assert_eq!(b.command, d.command);
            assert_eq!(b.soft_ttl_secs, d.soft_ttl_secs);
            assert_eq!(b.hard_ttl_secs, d.hard_ttl_secs);
        }
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
                "default/ZED",
                ValueSource::command(vec!["op".into(), "read".into(), "op://z".into()]),
                ttl,
            )
            .unwrap();
        store
            .define(
                "default/ABLE",
                ValueSource::command(vec!["printf".into(), "x".into()]),
                Ttl::new(None, None).unwrap(),
            )
            .unwrap();
        // A static value-only entry must NOT appear in the snapshot.
        let clock = FakeClock::new();
        store.set(
            "default/STATIC",
            ValueSource::Static,
            SecretBytes::new(b"v".to_vec()),
            Ttl::new(None, None).unwrap(),
            &clock,
        );

        let snap = snapshot_definitions(&store);
        let names: Vec<_> = snap.iter().map(|d| d.name.clone()).collect();
        assert_eq!(names, vec!["ABLE", "ZED"], "only definitions, name-sorted");
        // The store's composed key splits into (namespace, name).
        assert!(
            snap.iter()
                .all(|d| d.namespace.as_deref() == Some("default"))
        );
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
                "default/K",
                ValueSource::command(vec!["echo".into(), "x".into()]),
                Ttl::new(None, None).unwrap(),
            )
            .unwrap();
        let snap = snapshot_definitions(&store);
        let back = parse_persisted(&serialize_definitions(&snap)).unwrap();
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
