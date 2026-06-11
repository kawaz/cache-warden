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
                name: "kv set <KEY> ...",
                desc: "Cache a static value",
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
        summary: "Manage the cache-warden daemon process.",
        usage: concat!("cache-warden", " daemon <COMMAND> [OPTIONS]"),
        subcommands: &[Row {
            name: "run",
            desc: "Start the daemon in the foreground",
        }],
        options: &[],
        detail: "",
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
        detail: "",
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
            " kv define <KEY> [OPTIONS] (--command ARGV... | --source URI)"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--command ARGV...",
                desc: "Run ARGV; its stdout is the value (regenerable).\n\
                       Consumes everything after it, so it must come last",
            },
            Row {
                name: "--source URI",
                desc: "A source URI; only op:// is built in\n\
                       (expands to `op read <URI>`)",
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
The command is NOT run at define time; the value is produced lazily on the
first `kv get`. Defining is idempotent under an exact match (same argv/URI +
TTL is a no-op); a conflicting redefinition is rejected — delete it first with
`kv del KEY --with-define`, then re-define.",
        show_global: true,
    }
}

/// `kv set` leaf page (carries the per-flag option detail).
pub fn kv_set() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv set"),
        summary: "Cache a static value.",
        usage: concat!(
            "cache-warden",
            " kv set <KEY> (--value V | --value-stdin) [OPTIONS]"
        ),
        subcommands: &[],
        options: &[
            Row {
                name: "--value V",
                desc: "Use the literal string V as the value",
            },
            Row {
                name: "--value-stdin",
                desc: "Read the value from stdin (binary safe)",
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
`kv set` injects a literal value only. To register a regenerable command
source, use `kv define` instead.",
        show_global: true,
    }
}

/// `kv get` leaf page.
pub fn kv_get() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv get"),
        summary: "Fetch a cached value (raw bytes to stdout).",
        usage: concat!("cache-warden", " kv get <KEY>"),
        subcommands: &[],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `kv del` leaf page.
pub fn kv_del() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv del"),
        summary: "Delete a cached value (optionally its definition too).",
        usage: concat!("cache-warden", " kv del <KEY> [--with-define]"),
        subcommands: &[],
        options: &[Row {
            name: "--with-define",
            desc: "Also drop the registered definition so the key will not\n\
                   regenerate on a later get (default: value only)",
        }],
        detail: "",
        show_global: true,
    }
}

/// `kv list` leaf page.
pub fn kv_list() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv list"),
        summary: "List cached key names.",
        usage: concat!("cache-warden", " kv list"),
        subcommands: &[],
        options: &[],
        detail: "",
        show_global: true,
    }
}

/// `kv pin` leaf page (carries the long pin explanation).
pub fn kv_pin() -> HelpSpec {
    HelpSpec {
        heading: concat!("cache-warden", " kv pin"),
        summary: "Hold a value Active for DUR, ignoring its TTL (re-auth).",
        usage: concat!("cache-warden", " kv pin <KEY> <DUR>"),
        subcommands: &[],
        options: &[],
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
        usage: concat!("cache-warden", " kv unpin <KEY>"),
        subcommands: &[],
        options: &[],
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
        assert!(h.contains("kv set <KEY> ..."));
        // Global + environment present.
        assert!(h.contains("Global options:"));
        assert!(h.contains("--socket PATH"));
        assert!(h.contains("Environment:"));
        assert!(h.contains("CACHE_WARDEN_CONFIG"));
        // The per-flag `kv set` detail must NOT be on the top page anymore.
        assert!(!h.contains("--value-stdin"));
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
        assert!(!h.contains("--value-stdin"));
    }

    #[test]
    fn kv_set_help_carries_option_detail() {
        let h = kv_set().render();
        assert!(h.contains("Options:"));
        assert!(h.contains("--value-stdin"));
        // `--command` moved to `kv define`; `kv set` is static-only now.
        assert!(!h.contains("--command"));
        assert!(h.contains("--soft-ttl DUR"));
        assert!(h.contains("Global options:"));
        assert!(h.contains("Environment:"));
    }

    #[test]
    fn kv_define_help_carries_command_and_source_options() {
        let h = kv_define().render();
        assert!(h.contains("Options:"));
        assert!(h.contains("--command ARGV..."));
        assert!(h.contains("--source URI"));
        assert!(h.contains("--soft-ttl DUR"));
        // The lazy + idempotency explanation lives here.
        assert!(h.contains("lazily"));
        assert!(h.contains("--with-define"));
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
    fn daemon_group_help_lists_run() {
        let h = daemon().render();
        assert!(h.contains("cache-warden daemon\n"));
        assert!(h.contains("Commands:"));
        assert!(h.contains("run"));
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
