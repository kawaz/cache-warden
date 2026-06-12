//! `cache-warden inject`: substitute secret references in a template stream
//! (DR-0013 inject + DR-0015 dry-run).
//!
//! Reads a template (stdin or `--in FILE`), replaces every `cache-warden://KEY`
//! substring with its resolved value (reveal) or a mask (dry-run), and writes
//! the result (stdout or `--out FILE`, the latter created 0600). Processing is
//! byte-oriented and binary safe. In reveal mode it is fail-closed: nothing is
//! written if any reference fails to resolve. In dry-run mode the whole output
//! is rendered with masks and the command exits non-zero if any reference
//! failed (DR-0015 §3).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::mode::Mode;
use crate::refs::{self, Resolver};

/// Parsed `inject` arguments (the `--defs` files are handled by the caller, so
/// they are not stored here).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InjectArgs {
    /// Input file, or `None` for stdin.
    pub in_file: Option<PathBuf>,
    /// Output file, or `None` for stdout.
    pub out_file: Option<PathBuf>,
    /// `--defs FILE` definition files to register before resolving.
    pub defs: Vec<PathBuf>,
}

/// Parse `inject`'s flags into [`InjectArgs`]. The mode flags (`--dry-run` /
/// `--reveal`) and `--socket` are removed by the caller before this runs.
pub fn parse_inject(args: &[String]) -> Result<InjectArgs, String> {
    let mut out = InjectArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                let v = args.get(i + 1).ok_or("--in requires a FILE argument")?;
                out.in_file = Some(PathBuf::from(v));
                i += 2;
            }
            s if s.starts_with("--in=") => {
                out.in_file = Some(PathBuf::from(s.strip_prefix("--in=").unwrap()));
                i += 1;
            }
            "--out" => {
                let v = args.get(i + 1).ok_or("--out requires a FILE argument")?;
                out.out_file = Some(PathBuf::from(v));
                i += 2;
            }
            s if s.starts_with("--out=") => {
                out.out_file = Some(PathBuf::from(s.strip_prefix("--out=").unwrap()));
                i += 1;
            }
            "--defs" => {
                let v = args.get(i + 1).ok_or("--defs requires a FILE argument")?;
                out.defs.push(PathBuf::from(v));
                i += 2;
            }
            s if s.starts_with("--defs=") => {
                out.defs
                    .push(PathBuf::from(s.strip_prefix("--defs=").unwrap()));
                i += 1;
            }
            s if s.starts_with("--") => {
                return Err(format!("unknown option for `inject`: {s}"));
            }
            other => {
                return Err(format!(
                    "`inject` takes no positional arguments (got {other:?})"
                ));
            }
        }
    }
    Ok(out)
}

/// Render a template's references into output bytes (pure, testable).
///
/// `template` is the raw input; `resolver` resolves keys (deduped). Unqualified
/// references resolve into `ctx_ns`, qualified ones are absolute (DR-0017 §3);
/// masks and failure lists show the resolved absolute key. Returns the rendered
/// bytes on success. In reveal mode a failed reference returns an `Err` naming
/// the failed keys (fail-closed). In dry-run mode it returns the masked bytes
/// plus the failed keys, so the caller can still write the output and then exit
/// non-zero.
pub fn render<R: Resolver>(
    template: &[u8],
    mode: Mode,
    ctx_ns: &str,
    resolver: &mut R,
) -> Result<refs::RenderedTemplate, String> {
    let keys: Vec<String> = refs::find_references_bytes(template)
        .into_iter()
        .map(|l| l.key)
        .collect();
    let resolved = refs::resolve_all(&keys, ctx_ns, resolver);
    match refs::render_template(template, &resolved, mode, ctx_ns) {
        Ok(rendered) => Ok(rendered),
        Err(failures) => Err(format!(
            "{} reference(s) failed to resolve: {}",
            failures.len(),
            failures.join(", ")
        )),
    }
}

/// Write `bytes` to `out_file` (0600) or stdout when `None`.
///
/// A `--out FILE` is created with mode 0600 from the start (no world-readable
/// window) so a rendered secret file is never group/other readable (DR-0013).
pub fn write_output(out_file: Option<&Path>, bytes: &[u8]) -> std::io::Result<()> {
    match out_file {
        None => {
            std::io::stdout().write_all(bytes)?;
            std::io::stdout().flush()
        }
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(bytes)?;
            f.sync_all()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::{ResolveResult, ResolvedValue};

    fn ok(bytes: &[u8]) -> ResolveResult {
        Ok(ResolvedValue::Value(bytes.to_vec()))
    }

    #[test]
    fn parse_defaults_to_stdin_stdout() {
        let a = parse_inject(&[]).unwrap();
        assert_eq!(a, InjectArgs::default());
    }

    #[test]
    fn parse_in_out_and_defs() {
        let a = parse_inject(&[
            "--in".into(),
            "tmpl".into(),
            "--out".into(),
            "result".into(),
            "--defs".into(),
            "d.toml".into(),
        ])
        .unwrap();
        assert_eq!(a.in_file, Some(PathBuf::from("tmpl")));
        assert_eq!(a.out_file, Some(PathBuf::from("result")));
        assert_eq!(a.defs, vec![PathBuf::from("d.toml")]);
    }

    #[test]
    fn parse_rejects_positional_and_unknown() {
        assert!(parse_inject(&["x".into()]).is_err());
        assert!(parse_inject(&["--bogus".into()]).is_err());
    }

    #[test]
    fn render_reveal_substitutes() {
        // The resolver sees the qualified key (DR-0017 §3).
        let mut resolver = |k: &str| ok(format!("val-{k}").as_bytes());
        let out = render(
            b"a=cache-warden://K",
            Mode::Reveal,
            "default",
            &mut resolver,
        )
        .unwrap();
        assert_eq!(out.bytes, b"a=val-default/K");
    }

    #[test]
    fn render_reveal_fails_closed() {
        let mut resolver = |_k: &str| -> ResolveResult { Err("nope".into()) };
        let err = render(b"cache-warden://K", Mode::Reveal, "default", &mut resolver).unwrap_err();
        assert!(err.contains("default/K"), "err: {err}");
    }

    #[test]
    fn render_dry_run_masks_and_reports_failures() {
        let mut resolver = |k: &str| -> ResolveResult {
            if k == "default/BAD" {
                Err("nope".into())
            } else {
                Ok(ResolvedValue::Verified)
            }
        };
        let out = render(
            b"cache-warden://OK cache-warden://BAD",
            Mode::DryRun,
            "default",
            &mut resolver,
        )
        .unwrap();
        // Masks display the resolved absolute key (DR-0017 §5).
        assert_eq!(
            out.bytes,
            b"<cache-warden:default/OK:masked> <cache-warden:default/BAD:failed>"
        );
        assert_eq!(out.failures, vec!["default/BAD".to_string()]);
    }

    #[test]
    fn write_output_to_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_output(Some(&path), b"secret-bytes").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret-bytes");
    }
}
