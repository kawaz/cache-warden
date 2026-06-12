//! Help text for every CLI level (top / `daemon` / `kv` / `config` and each
//! leaf subcommand).
//!
//! Help is data, not hand-formatted prose: each level is a [`HelpSpec`] holding
//! its title, one-line summary, the subcommands it groups (if any), and the
//! options that are specific to that level. [`HelpSpec::render`] assembles the
//! shared section layout (subcommands → level options → global options →
//! environment) so a new level only has to describe its own rows — the global
//! and environment sections are defined once ([`GLOBAL_OPTIONS`], [`ENVIRONMENT`])
//! and never duplicated per level.
//!
//! This keeps the levels uniform: adding `kv define` / a top-level `run` later
//! is a matter of adding a row (and, for a new group, a new [`HelpSpec`]) — the
//! rendering and the global/environment sections come for free.

/// A single `name<pad>description` row in a help section (a subcommand or an
/// option). Multi-line descriptions are pre-wrapped with the continuation lines
/// already indented to match the column.
pub struct Row {
    pub name: &'static str,
    pub desc: &'static str,
}

/// A help page for one CLI level.
pub struct HelpSpec {
    /// First header line, e.g. `cache-warden kv` or `cache-warden kv set`.
    pub heading: &'static str,
    /// One-line summary printed under the heading.
    pub summary: &'static str,
    /// The `Usage:` line body (already prefixed with the program name).
    pub usage: &'static str,
    /// Subcommands grouped at this level (empty for a leaf command).
    pub subcommands: &'static [Row],
    /// Options specific to this level (empty if the level has none).
    pub options: &'static [Row],
    /// Extra prose printed after the options (e.g. the long `kv pin`
    /// explanation). Empty string = omitted.
    pub detail: &'static str,
    /// Whether to append the shared global-options + environment sections.
    /// Leaf commands and groups both include them; only the most minimal pages
    /// would opt out.
    pub show_global: bool,
}

/// Global options shared by every level (rendered once, defined once).
const GLOBAL_OPTIONS: &[Row] = &[
    Row {
        name: "--socket PATH",
        desc: "Control socket path. Precedence:\n\
               --socket > [daemon].socket in config >\n\
               $XDG_STATE_HOME/cache-warden/control.sock",
    },
    Row {
        name: "--help",
        desc: "Show this help message",
    },
    Row {
        name: "--version",
        desc: "Show version",
    },
];

/// Environment variables shared by every level.
const ENVIRONMENT: &[Row] = &[
    Row {
        name: "CACHE_WARDEN_CONFIG",
        desc: "Explicit config file path (highest config priority)",
    },
    Row {
        name: "XDG_CONFIG_HOME",
        desc: "Base dir for the config file\n\
               ($XDG_CONFIG_HOME/cache-warden/config.toml)",
    },
    Row {
        name: "XDG_STATE_HOME",
        desc: "Base dir for the default control socket path",
    },
    Row {
        name: "CACHE_WARDEN_DRY_RUN",
        desc: "Default to dry-run for kv get / run / inject when set\n\
               (1/true/yes/on); a --reveal flag still overrides it",
    },
    Row {
        name: "EDITOR / VISUAL",
        desc: "Editor launched by `config edit`",
    },
];

const INDENT: &str = "    ";
/// Gap between a name and its description (when the column auto-fits).
const NAME_GAP: usize = 2;
/// Cap on the auto-fit description column. A name at/above this width drops its
/// own description to the next line, but does not push the whole section right.
/// Sized so the longest real names (`--command ARGV...`, `CACHE_WARDEN_CONFIG`)
/// still align inline, matching the original help layout.
const MAX_DESC_COLUMN: usize = 25;

/// Render one `    name<pad>desc` block at the given description column,
/// indenting continuation lines of a multi-line `desc` to match.
fn render_row(out: &mut String, row: &Row, desc_column: usize) {
    let lead = format!("{INDENT}{}", row.name);
    let mut lines = row.desc.split('\n');
    let first = lines.next().unwrap_or("");
    if lead.len() < desc_column {
        let pad = " ".repeat(desc_column - lead.len());
        out.push_str(&format!("{lead}{pad}{first}\n"));
    } else {
        // Name reaches/overflows the column: description starts on the next line.
        out.push_str(&format!("{lead}\n"));
        let pad = " ".repeat(desc_column);
        out.push_str(&format!("{pad}{first}\n"));
    }
    let cont_pad = " ".repeat(desc_column);
    for line in lines {
        out.push_str(&format!("{cont_pad}{line}\n"));
    }
}

/// Render a section, auto-fitting the description column to the section's own
/// rows (so each section's names align without forcing one global width).
fn render_section(out: &mut String, title: &str, rows: &[Row]) {
    if rows.is_empty() {
        return;
    }
    let desc_column = rows
        .iter()
        .map(|r| INDENT.len() + r.name.len() + NAME_GAP)
        .filter(|w| *w <= MAX_DESC_COLUMN)
        .max()
        .unwrap_or(MAX_DESC_COLUMN);
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    for row in rows {
        render_row(out, row, desc_column);
    }
}

impl HelpSpec {
    /// Assemble the full help page for this level.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(self.heading);
        out.push('\n');
        // The top level folds its summary into `heading`; other levels carry a
        // one-line `summary`. Emit it only when present so there is exactly one
        // blank line before `Usage:`.
        if !self.summary.is_empty() {
            out.push_str(self.summary);
            out.push('\n');
        }
        out.push('\n');
        out.push_str("Usage:\n");
        out.push_str(&format!("{INDENT}{}\n", self.usage));

        render_section(&mut out, "Commands:", self.subcommands);
        render_section(&mut out, "Options:", self.options);

        if !self.detail.is_empty() {
            out.push('\n');
            out.push_str(self.detail);
            out.push('\n');
        }

        if self.show_global {
            render_section(&mut out, "Global options:", GLOBAL_OPTIONS);
            render_section(&mut out, "Environment:", ENVIRONMENT);
        }
        out
    }
}

// ---- Level specs --------------------------------------------------------

/// Top-level help: command list + global + environment only (the per-command
/// option detail lives on each leaf's own page).
pub fn top() -> HelpSpec {
    HelpSpec {
        heading: concat!(
            "cache-warden ",
            env!("CARGO_PKG_VERSION"),
            "\nSecure secret cache: a TTL-managed, zeroize-backed key/value cache for secrets."
        ),
        // heading carries the version+summary; keep summary empty to avoid a
        // blank duplicate line.
        summary: "",
        usage: concat!("cache-warden", " <COMMAND> [OPTIONS]"),
        subcommands: &[
            Row {
                name: "daemon run",
                desc: "Start the daemon in the foreground",
            },
            Row {
                name: "daemon register",
                desc: "Install the launchd/systemd user service (--print to preview)",
            },
            Row {
                name: "daemon unregister",
                desc: "Stop and remove the installed service",
            },
            Row {
                name: "daemon status",
                desc: "Show service registration / running state",
            },
            Row {
                name: "ping",
                desc: "Check that the daemon is alive",
            },
            Row {
                name: "status",
                desc: "Show daemon info and the (value-free) entry list",
            },
            Row {
                name: "kv define <KEY> ...",
                desc: "Register a regenerable definition (lazy)",
            },
            Row {
                name: "kv set <KEY> [VALUE]",
                desc: "Cache a static value (VALUE omitted = read stdin)",
            },
            Row {
                name: "kv get <KEY>",
                desc: "Fetch a cached value (regenerates if defined)",
            },
            Row {
                name: "kv del <KEY>",
                desc: "Delete a cached value (--with-define drops the definition)",
            },
            Row {
                name: "kv list",
                desc: "List cached key names",
            },
            Row {
                name: "kv pin <KEY> <DUR>",
                desc: "Hold a value Active for DUR, ignoring its TTL (re-auth)",
            },
            Row {
                name: "kv unpin <KEY>",
                desc: "Drop a pin, returning the value to normal TTL evaluation",
            },
            Row {
                name: "run -- CMD ...",
                desc: "Resolve env references then exec CMD (--dry-run to verify)",
            },
            Row {
                name: "inject",
                desc: "Substitute references in a template stream (--dry-run to verify)",
            },
            Row {
                name: "config show",
                desc: "Show the effective configuration",
            },
            Row {
                name: "config path",
                desc: "Show the config file path (or the search order)",
            },
            Row {
                name: "config edit",
                desc: "Open the config in $EDITOR",
            },
        ],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// The `daemon` group page.
pub fn daemon() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " daemon"),
        summary: "Manage the cache-warden daemon process and service registration.",
        usage: concat!("cache-warden", " daemon <COMMAND> [OPTIONS]"),
        subcommands: &[
            Row {
                name: "run",
                desc: "Start the daemon in the foreground",
            },
            Row {
                name: "register",
                desc: "Install the launchd/systemd user service (--print to preview)",
            },
            Row {
                name: "unregister",
                desc: "Stop and remove the installed service",
            },
            Row {
                name: "status",
                desc: "Show service registration / running state",
            },
        ],
        options: &[],
        detail: "\
register / unregister / status manage a per-user service (launchd LaunchAgent on
macOS, `systemd --user` on Linux). register writes the service definition and
starts it now + at login; it is idempotent (re-run to update the binary path or
config). The register-time config path is baked into the definition so the
service uses the same config that was in effect when you registered (DR-0019).",
        show_global: true,
    }
}

/// `daemon run` leaf page.
pub fn daemon_run() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " daemon run"),
        summary: "Start the daemon in the foreground.",
        usage: concat!("cache-warden", " daemon run [OPTIONS]"),
        subcommands: &[],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `daemon register` leaf page (DR-0019).
pub fn daemon_register() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " daemon register"),
        summary: "Install and start the per-user service (launchd / systemd --user).",
        usage: concat!(
            "cache-warden",
            " daemon register [--socket PATH] [--label NAME] [--print]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--socket PATH",
                desc: "Bake `--socket PATH` into the service start command\n\
                       (the service binds this control socket)",
            },
            Row {
                name: "--label NAME",
                desc: "Service label (default: com.github.kawaz.cache-warden on\n\
                       macOS, cache-warden on Linux). Use to run multiple\n\
                       instances side by side",
            },
            Row {
                name: "--print",
                desc: "Render the service definition to stdout and install\n\
                       nothing (audit / dry-run)",
            },
        ],
        detail: "\
register writes the service definition (launchd plist or systemd unit) and loads
it so the daemon starts now and at every login. It is idempotent: re-running
updates the definition (binary path, socket, baked config) and restarts the
service — this is the main way to point the service at a rebuilt binary.

The binary path is the absolute path of the running executable; the config path
is whatever the loader resolves at register time ($CACHE_WARDEN_CONFIG > XDG >
~/.config), baked in as CACHE_WARDEN_CONFIG so the service does not silently pick
up a different config. A minimal PATH is baked in so `op` is found.

Linux: `systemd --user` services stop at logout unless lingering is enabled;
register prints a hint to run `loginctl enable-linger` when it is off (it never
enables it for you — that may require admin). Logs: macOS writes
~/Library/Logs/cache-warden/daemon.log; Linux uses journald.",
        show_global: true,
    }
}

/// `daemon unregister` leaf page (DR-0019).
pub fn daemon_unregister() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " daemon unregister"),
        summary: "Stop, unload, and delete the installed service.",
        usage: concat!("cache-warden", " daemon unregister [--label NAME]"),
        subcommands: &[],
        options: &[Row {
            name: "--label NAME",
            desc: "Service label to remove (default: the per-OS default label)",
        }],
        detail: "\
Stops the service, unloads it from the service manager, and deletes its
definition file. A label that is not registered is a no-op (idempotent).",
        show_global: true,
    }
}

/// `daemon status` leaf page (DR-0019).
pub fn daemon_status() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " daemon status"),
        summary: "Show the service registration / running state.",
        usage: concat!("cache-warden", " daemon status [--label NAME]"),
        subcommands: &[],
        options: &[Row {
            name: "--label NAME",
            desc: "Service label to query (default: the per-OS default label)",
        }],
        detail: "\
Reports whether the service definition is installed, whether the service manager
reports it running, its pid, and the definition file path — a one-screen table,
the same shape on macOS and Linux. This is distinct from the top-level
`cache-warden status`, which lists cache entries (DR-0019).",
        show_global: true,
    }
}

/// The `kv` group page.
pub fn kv() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv"),
        summary: "Manage cached key/value secrets.",
        usage: concat!("cache-warden", " kv <COMMAND> [OPTIONS]"),
        subcommands: &[
            Row {
                name: "define",
                desc: "Register a regenerable definition (lazy)",
            },
            Row {
                name: "set",
                desc: "Cache a static value",
            },
            Row {
                name: "get",
                desc: "Fetch a cached value (regenerates if defined)",
            },
            Row {
                name: "del",
                desc: "Delete a cached value (--with-define drops the definition)",
            },
            Row {
                name: "list",
                desc: "List cached key names",
            },
            Row {
                name: "pin",
                desc: "Hold a value Active for DUR, ignoring its TTL (re-auth)",
            },
            Row {
                name: "unpin",
                desc: "Drop a pin, returning the value to normal TTL evaluation",
            },
        ],
        options: &[],
        detail: "\
Every kv subcommand accepts `--namespace NS` to select the KV namespace
(DR-0017). The default resolves as: --namespace > CACHE_WARDEN_NAMESPACE >
[cli].namespace > \"default\". KEY and NS are identifiers ([A-Za-z0-9_]+); a
`ns/key` form inside a KEY argument is rejected — the flag is the only path.

Every kv subcommand accepts a `--` separator: everything after it is taken as
positional arguments and never interpreted as an option, so option-looking key
names stay safe (`kv get -- --weird-key`, `kv del -- \"$key\"`). One
intersection: in `kv define`, a `--command` consumes the rest of the line, so
it cannot be combined with a key that itself needs `--`.",
        show_global: true,
    }
}

/// `kv define` leaf page (carries the per-flag option detail).
pub fn kv_define() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv define"),
        summary: "Register a regenerable definition for a key (lazy; DR-0014).",
        usage: concat!(
            "cache-warden",
            " kv define (<KEY> (--command ARGV... | --source URI) | --defs FILE...) [OPTIONS]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--command ARGV...",
                desc: "Run ARGV; its stdout is the value (regenerable).\n\
                       Consumes everything after it, so it must come last",
            },
            Row {
                name: "--command-cwd PATH",
                desc: "Working directory for --command (place before --command)",
            },
            Row {
                name: "--command-env N=V",
                desc: "Env overlay for --command (repeatable; before --command)",
            },
            Row {
                name: "--source URI",
                desc: "An op:// source URI (lowered to `op read <URI>`)",
            },
            Row {
                name: "--defs FILE",
                desc: "Register every [kv.NAME] in a TOML defs file at once\n\
                       (repeatable). Cannot be combined with KEY /\n\
                       --command / --source",
            },
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--soft-ttl DUR",
                desc: "Soft TTL (re-auth to extend). e.g. 1h, 30m, 45s, 86400",
            },
            Row {
                name: "--hard-ttl DUR",
                desc: "Hard TTL (value zeroized at expiry)",
            },
            Row {
                name: "--type otp",
                desc: "Mark the value as a TOTP seed: get derives a code\n\
                       (the seed is never returned; write-only)",
            },
            Row {
                name: "--otp-digits N",
                desc: "OTP code length (default 6; requires --type otp)",
            },
            Row {
                name: "--otp-period SEC",
                desc: "OTP time step in seconds (default 30)",
            },
            Row {
                name: "--otp-algorithm A",
                desc: "OTP hash: sha1 (default) / sha256 / sha512",
            },
        ],
        detail: "\
The command is NOT run at define time; the value is produced lazily on the
first `kv get`. Defining is idempotent under an exact match (same argv/URI +
TTL is a no-op); a conflicting redefinition is rejected — delete it first with
`kv del KEY --with-define`, then re-define.

With --type otp the stored value is a TOTP *seed* (raw base32 or an otpauth://
URI). `kv get` derives the current code from the seed and the wall clock; the
seed itself is never returned (write-only). Explicit --otp-* flags override any
parameters read from an otpauth:// URI. A `--type otp` source must point at the
seed field (plain op://vault/item/field), NOT `?attribute=otp` (which returns a
computed 30s code, not the seed) — that combination is rejected.

--defs FILE bulk-registers every [kv.NAME] in a TOML file (same grammar as the
config [kv.*] section: command + soft-ttl / hard-ttl; no inline values, no
preload). Each clashing key is reported on its own; one conflict does not stop
the others. There is no automatic discovery — only the files you pass are read
(a conventional name is .cache-warden.toml, but it is never loaded implicitly).
An entry may pin itself with `namespace = \"NS\"` (absolute); without the field
it follows this invocation's --namespace (DR-0017). Note: TOML table keys are
unique, so one file cannot define the same NAME twice in different namespaces.",
        show_global: true,
    }
}

/// `kv set` leaf page (carries the per-flag option detail).
pub fn kv_set() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv set"),
        summary: "Cache a static value.",
        usage: concat!("cache-warden", " kv set [OPTIONS] [--] KEY [VALUE]"),
        subcommands: &[],
        options: &[
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--soft-ttl DUR",
                desc: "Soft TTL (re-auth to extend). e.g. 1h, 30m, 45s, 86400",
            },
            Row {
                name: "--hard-ttl DUR",
                desc: "Hard TTL (value zeroized at expiry)",
            },
        ],
        detail: "\
`kv set` injects a literal, opaque value only. To register a regenerable
command source, use `kv define` instead.

VALUE is positional: `kv set DB hunter2`. When VALUE is omitted the bytes are
read from stdin (binary safe): `op read op://v/i/pw | kv set DB`. Reading from
a terminal is refused — if stdin is a TTY and no VALUE is given, the command
errors immediately instead of hanging.

A VALUE in argv is visible to `ps` and lands in your shell history, so prefer
piping stdin for real secrets. A value containing NUL bytes (full binary) can
only come via stdin (argv cannot carry NUL).

Everything after `--` is positional, never an option: `kv set -- --weird-key v`.

Value types (otp) live on definitions, not on set values: a typed key must be
regenerable, so register it with `kv define KEY --type otp ...`. `kv set`
rejects `--type` / `--otp-*` and points you there.",
        show_global: true,
    }
}

/// `kv get` leaf page.
pub fn kv_get() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv get"),
        summary: "Fetch a cached value (raw bytes to stdout).",
        usage: concat!(
            "cache-warden",
            " kv get [--namespace NS] <KEY> [--dry-run | --reveal]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--dry-run",
                desc: "Verify retrieval WITHOUT emitting the value: print a mask\n\
                       (<cache-warden:NS/KEY:masked>), running the full chain\n\
                       (lazy generate / extend / regenerate / re-auth)",
            },
            Row {
                name: "--reveal",
                desc: "Force real-value output (use when the default has been\n\
                       set to dry-run via config / CACHE_WARDEN_DRY_RUN)",
            },
        ],
        detail: "\
By default `kv get` REVEALS the real value (raw bytes to stdout). For a safe
check, use --dry-run: it runs the full retrieval chain (and so has side
effects — upstream execution, re-authentication / TouchID, cache warming) but
returns only a mask, never the value. On failure --dry-run prints
<cache-warden:NS/KEY:failed> and exits non-zero (masks always show the
resolved absolute NS/KEY).",
        show_global: true,
    }
}

/// Top-level `run` leaf page (DR-0013 / DR-0015).
pub fn run_cmd() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " run"),
        summary: "Resolve cache-warden://KEY env references, then exec a command.",
        usage: concat!(
            "cache-warden",
            " run [--namespace NS] [--env NAME=VALUE]... [--defs FILE]... [--dry-run | --reveal] -- CMD [ARGS...]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--env NAME=VALUE",
                desc: "Add/override a child env var (repeatable). A value that is\n\
                       exactly cache-warden://[NS/]KEY is resolved; --env wins\n\
                       over the inherited environment",
            },
            Row {
                name: "--defs FILE",
                desc: "Register a TOML defs file before resolving (repeatable)",
            },
            Row {
                name: "--dry-run",
                desc: "Verify WITHOUT real values: exec with MASKED env\n\
                       (<cache-warden:KEY:masked>); non-zero exit if any ref fails",
            },
            Row {
                name: "--reveal",
                desc: "Force real values (use when the default has been set to\n\
                       dry-run via config / CACHE_WARDEN_DRY_RUN)",
            },
        ],
        detail: "\
By default `run` REVEALS real values. For a safe check, use --dry-run: it runs
the full retrieval chain — with side effects (upstream execution,
re-authentication / TouchID, cache warming) — but injects only masks, never the
value, and exits non-zero if any reference fails.

Only env values that are ENTIRELY a reference are substituted (whole-value
rule). References are cache-warden://[NS/]KEY: an unqualified KEY resolves into
this invocation's namespace, a qualified NS/KEY is absolute (DR-0017). argv is
never an injection face: a reference-looking token after `--` is passed
verbatim with a warning (use --env NAME=cache-warden://KEY). On success `run`
execs the command (no parent lingers holding secrets).",
        show_global: true,
    }
}

/// Top-level `inject` leaf page (DR-0013 / DR-0015).
pub fn inject_cmd() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " inject"),
        summary: "Substitute cache-warden://KEY references in a template stream.",
        usage: concat!(
            "cache-warden",
            " inject [--namespace NS] [--in FILE] [--out FILE] [--defs FILE]... [--dry-run | --reveal]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--in FILE",
                desc: "Read the template from FILE (default: stdin)",
            },
            Row {
                name: "--out FILE",
                desc: "Write the result to FILE, created 0600 (default: stdout)",
            },
            Row {
                name: "--defs FILE",
                desc: "Register a TOML defs file before resolving (repeatable)",
            },
            Row {
                name: "--dry-run",
                desc: "Verify WITHOUT real values: emit MASKS\n\
                       (<cache-warden:KEY:masked>); non-zero exit if any ref fails",
            },
            Row {
                name: "--reveal",
                desc: "Force real values (use when the default has been set to\n\
                       dry-run via config / CACHE_WARDEN_DRY_RUN)",
            },
        ],
        detail: "\
By default `inject` REVEALS real values. For a safe check, use --dry-run: it
runs the full retrieval chain — with side effects (upstream execution,
re-authentication / TouchID, cache warming) — but emits only masks, never the
value, and exits non-zero if any reference fails.

References are cache-warden://[NS/]KEY, replaced as substrings (embedded
composition is allowed, unlike `run`'s whole-value env rule): an unqualified
KEY resolves into this invocation's namespace, a qualified NS/KEY is absolute
(DR-0017). Processing is byte-oriented and binary safe. In reveal mode it is
fail-closed: nothing is written if any reference fails.",
        show_global: true,
    }
}

/// `kv del` leaf page.
pub fn kv_del() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv del"),
        summary: "Delete a cached value (optionally its definition too).",
        usage: concat!(
            "cache-warden",
            " kv del [--namespace NS] <KEY> [--with-define]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--with-define",
                desc: "Also drop the registered definition so the key will not\n\
                       regenerate on a later get (default: value only)",
            },
        ],
        detail: "",
        show_global: true,
    }
}

/// `kv list` leaf page.
pub fn kv_list() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv list"),
        summary: "List cached key names (current namespace).",
        usage: concat!(
            "cache-warden",
            " kv list [--namespace NS] [--all-namespaces]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--namespace NS",
                desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
            },
            Row {
                name: "--all-namespaces",
                desc: "List every namespace's keys in their composed NS/KEY form",
            },
        ],
        detail: "\
By default only the current namespace's keys are listed (names shown without
the NS/ prefix). --all-namespaces lists everything as NS/KEY (DR-0017).",
        show_global: true,
    }
}

/// `kv pin` leaf page (carries the long pin explanation).
pub fn kv_pin() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv pin"),
        summary: "Hold a value Active for DUR, ignoring its TTL (re-auth).",
        usage: concat!("cache-warden", " kv pin [--namespace NS] <KEY> <DUR>"),
        subcommands: &[],
        options: &[Row {
            name: "--namespace NS",
            desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
        }],
        detail: "\
Hold the value Active for DUR (e.g. 8h), suppressing both soft and hard
expiry until then. Useful before a long unattended run so an overnight hard
expiry can't interrupt it. Re-authentication is always required (pinning
relaxes the TTL). `kv unpin <KEY>` removes the pin (no re-auth).
DUR uses the same grammar as the TTL flags: 1h, 30m, 45s, or bare seconds.",
        show_global: true,
    }
}

/// `kv unpin` leaf page.
pub fn kv_unpin() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv unpin"),
        summary: "Drop a pin, returning the value to normal TTL evaluation.",
        usage: concat!("cache-warden", " kv unpin [--namespace NS] <KEY>"),
        subcommands: &[],
        options: &[Row {
            name: "--namespace NS",
            desc: "KV namespace (default: CACHE_WARDEN_NAMESPACE >\n\
                       [cli].namespace > \"default\"; DR-0017)",
        }],
        detail: "",
        show_global: true,
    }
}

/// The `config` group page.
pub fn config() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " config"),
        summary: "Inspect and edit the configuration.",
        usage: concat!("cache-warden", " config <COMMAND> [OPTIONS]"),
        subcommands: &[
            Row {
                name: "show",
                desc: "Show the effective configuration",
            },
            Row {
                name: "path",
                desc: "Show the config file path (or the search order)",
            },
            Row {
                name: "edit",
                desc: "Open the config in $EDITOR",
            },
        ],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `config show` leaf page.
pub fn config_show() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " config show"),
        summary: "Show the effective configuration.",
        usage: concat!("cache-warden", " config show"),
        subcommands: &[],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `config path` leaf page.
pub fn config_path() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " config path"),
        summary: "Show the config file path (or the search order).",
        usage: concat!("cache-warden", " config path"),
        subcommands: &[],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `config edit` leaf page.
pub fn config_edit() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " config edit"),
        summary: "Open the config in $EDITOR.",
        usage: concat!("cache-warden", " config edit"),
        subcommands: &[],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `--help` / `-h` detection. `true` if any arg requests help.
pub fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_help_detects_flag_anywhere() {
        assert!(wants_help(&["--help".into()]));
        assert!(wants_help(&["set".into(), "--help".into()]));
        assert!(!wants_help(&["set".into(), "K".into()]));
        assert!(!wants_help(&[]));
    }

    #[test]
    fn top_help_has_sections_but_no_per_flag_detail() {
        let h = top().render();
        // Command list present.
        assert!(h.contains("Commands:"));
        assert!(h.contains("kv set <KEY> [VALUE]"));
        // Global + environment present.
        assert!(h.contains("Global options:"));
        assert!(h.contains("--socket PATH"));
        assert!(h.contains("Environment:"));
        assert!(h.contains("CACHE_WARDEN_CONFIG"));
        // The per-flag `kv set` detail must NOT be on the top page anymore.
        assert!(!h.contains("shell history"));
        assert!(!h.contains("Hold the value Active"));
    }

    #[test]
    fn kv_group_help_lists_subcommands_with_one_liners() {
        let h = kv().render();
        assert!(h.contains("cache-warden kv\n"));
        assert!(h.contains("Commands:"));
        assert!(h.contains("set"));
        assert!(h.contains("pin"));
        // group help shows the global section too.
        assert!(h.contains("Global options:"));
        // but not the per-flag detail of `kv set`.
        assert!(!h.contains("shell history"));
        // The shared `--` separator rule is documented at the group level.
        assert!(h.contains("`--` separator"));
    }

    #[test]
    fn kv_set_help_carries_option_detail() {
        let h = kv_set().render();
        assert!(h.contains("Options:"));
        // The value is positional now: usage shows it, no --value flags remain.
        assert!(h.contains("KEY [VALUE]"));
        assert!(!h.contains("--value-stdin"));
        assert!(!h.contains("--value V"));
        assert!(h.contains("--soft-ttl DUR"));
        assert!(h.contains("Global options:"));
        assert!(h.contains("Environment:"));
        // Secrets-in-argv warning + binary/NUL note + pipe guidance.
        assert!(h.contains("shell history"));
        assert!(h.contains("NUL"));
        assert!(h.contains("stdin"));
        // The `--` separator is shown for option-looking keys.
        assert!(h.contains("kv set -- --weird-key"));
        // Value types (otp) moved to `kv define`; `kv set` no longer lists them
        // but steers users there (DR-0016).
        assert!(!h.contains("--otp-digits"));
        assert!(h.contains("kv define KEY --type otp"));
        // Namespace flag (DR-0017).
        assert!(h.contains("--namespace NS"));
    }

    #[test]
    fn kv_list_and_value_verbs_document_namespaces() {
        // DR-0017: every kv leaf carries --namespace; list adds --all-namespaces.
        let list = kv_list().render();
        assert!(list.contains("--namespace NS"));
        assert!(list.contains("--all-namespaces"));
        assert!(list.contains("NS/KEY"));
        for spec in [kv_get(), kv_del(), kv_pin(), kv_unpin(), kv_define()] {
            let h = spec.render();
            assert!(h.contains("--namespace NS"), "missing in: {h}");
        }
        // run / inject carry the flag and the [NS/]KEY reference grammar.
        for spec in [run_cmd(), inject_cmd()] {
            let h = spec.render();
            assert!(h.contains("--namespace NS"), "missing in: {h}");
            assert!(h.contains("[NS/]KEY"), "reference grammar in: {h}");
        }
        // The kv group page explains the precedence chain.
        let group = kv().render();
        assert!(group.contains("CACHE_WARDEN_NAMESPACE"));
    }

    #[test]
    fn kv_define_help_carries_command_and_source_options() {
        let h = kv_define().render();
        assert!(h.contains("Options:"));
        assert!(h.contains("--command ARGV..."));
        assert!(h.contains("--source URI"));
        assert!(h.contains("--defs FILE"));
        assert!(h.contains("--soft-ttl DUR"));
        // The lazy + idempotency explanation lives here.
        assert!(h.contains("lazily"));
        assert!(h.contains("--with-define"));
        // The bulk-define note mentions no implicit discovery.
        assert!(h.contains(".cache-warden.toml"));
        // OTP value-type flags + the attribute=otp footgun note (DR-0016).
        assert!(h.contains("--type otp"));
        assert!(h.contains("--otp-algorithm"));
        assert!(h.contains("attribute=otp"));
    }

    #[test]
    fn kv_del_help_carries_with_define() {
        let h = kv_del().render();
        assert!(h.contains("--with-define"));
    }

    #[test]
    fn kv_pin_help_carries_long_explanation() {
        let h = kv_pin().render();
        assert!(h.contains("Hold the value Active"));
        assert!(h.contains("same grammar as the TTL flags"));
    }

    #[test]
    fn daemon_group_help_lists_run_and_service_subcommands() {
        let h = daemon().render();
        assert!(h.contains("cache-warden daemon\n"));
        assert!(h.contains("Commands:"));
        assert!(h.contains("run"));
        // DR-0019: register / unregister / status are now real subcommands.
        assert!(h.contains("register"));
        assert!(h.contains("unregister"));
        assert!(h.contains("status"));
    }

    #[test]
    fn daemon_register_help_carries_flags_and_notes() {
        let h = daemon_register().render();
        assert!(h.contains("--socket PATH"));
        assert!(h.contains("--label NAME"));
        assert!(h.contains("--print"));
        // The idempotency + baked-config rationale is documented.
        assert!(h.contains("idempotent"));
        assert!(h.contains("CACHE_WARDEN_CONFIG"));
        // The Linux linger hint is mentioned.
        assert!(h.contains("enable-linger"));
    }

    #[test]
    fn daemon_unregister_and_status_help_carry_label_flag() {
        for h in [daemon_unregister().render(), daemon_status().render()] {
            assert!(h.contains("--label NAME"), "missing --label in: {h}");
        }
        // status explains it differs from the top-level entry-listing status.
        assert!(daemon_status().render().contains("distinct from"));
    }

    #[test]
    fn top_help_lists_daemon_service_subcommands() {
        let h = top().render();
        assert!(h.contains("daemon register"));
        assert!(h.contains("daemon unregister"));
        assert!(h.contains("daemon status"));
    }

    #[test]
    fn config_group_help_lists_subcommands() {
        let h = config().render();
        assert!(h.contains("show"));
        assert!(h.contains("path"));
        assert!(h.contains("edit"));
    }

    #[test]
    fn rows_in_a_section_share_one_description_column() {
        let h = kv().render();
        // Within the Commands: section, all one-liner descriptions align to the
        // same column (auto-fit to the widest short name, here `define`).
        let set_col = h
            .lines()
            .find(|l| l.trim_start().starts_with("set"))
            .and_then(|l| l.find("Cache a static value"))
            .unwrap();
        let define_col = h
            .lines()
            .find(|l| l.trim_start().starts_with("define"))
            .and_then(|l| l.find("Register a regenerable"))
            .unwrap();
        assert_eq!(set_col, define_col);
        // `define` is the widest name here, so its description sits right after it.
        assert_eq!(define_col, INDENT.len() + "define".len() + NAME_GAP);
    }

    #[test]
    fn multiline_desc_continuation_is_indented() {
        let h = top().render();
        // The --socket option wraps; the last continuation line must be indented
        // (all-space prefix, no name in column 0).
        let idx = h.find("$XDG_STATE_HOME/cache-warden/control.sock").unwrap();
        let line_start = h[..idx].rfind('\n').map(|n| n + 1).unwrap_or(0);
        let prefix = &h[line_start..idx];
        assert!(prefix.chars().all(|c| c == ' '));
        assert!(prefix.len() >= INDENT.len());
    }

    #[test]
    fn long_name_drops_description_to_next_line() {
        // A name at/above MAX_DESC_COLUMN keeps its description on the next line
        // (indented to the column) instead of running long inline.
        let long = "x".repeat(MAX_DESC_COLUMN); // INDENT + name >> MAX_DESC_COLUMN
        let rows = [Row {
            name: Box::leak(long.into_boxed_str()),
            desc: "the description",
        }];
        let mut out = String::new();
        render_section(&mut out, "Section:", &rows);
        let lines: Vec<&str> = out.lines().collect();
        // ["", "Section:", "    xxxx...", "                         the description"]
        let name_line = lines.iter().find(|l| l.contains("xxx")).unwrap();
        assert!(
            !name_line.contains("the description"),
            "long name should not carry its description inline"
        );
        let desc_line = lines
            .iter()
            .find(|l| l.contains("the description"))
            .unwrap();
        assert!(desc_line.starts_with(&" ".repeat(MAX_DESC_COLUMN)));
    }
}
