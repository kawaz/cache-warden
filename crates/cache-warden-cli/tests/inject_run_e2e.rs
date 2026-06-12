//! End-to-end tests for the top-level `run` and `inject` verbs and the dry-run
//! verification mode (DR-0013 / DR-0015).
//!
//! A real daemon is started over a temp control socket; the CLI binary is then
//! driven as a client. These exercise the whole path: reference detection →
//! `kv.get` (reveal or dry_run) → env injection + exec / template substitution →
//! masked dry-run output and non-zero exit, plus the `CACHE_WARDEN_DRY_RUN`
//! polarity switch.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

/// A spawned daemon killed on drop.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn connect_with_retry(socket: &Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(5);
    loop {
        match UnixStream::connect(socket) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("daemon never reachable at {}: {e}", socket.display());
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(200));
            }
        }
    }
}

/// Send one raw JSON line, read one JSON response.
fn request(socket: &Path, json_line: &str) -> serde_json::Value {
    let stream = connect_with_retry(socket);
    let mut writer = stream.try_clone().expect("clone");
    writer.write_all(json_line.as_bytes()).expect("write");
    writer.write_all(b"\n").expect("nl");
    writer.flush().expect("flush");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read");
    assert!(n > 0, "daemon closed without responding");
    serde_json::from_str(line.trim_end()).expect("parse json")
}

fn spawn_plain(dir: &Path) -> (Daemon, std::path::PathBuf) {
    let socket = dir.join("control.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn daemon");
    (Daemon { child }, socket)
}

fn wait_for_exit(daemon: &mut Daemon, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match daemon.child.try_wait().expect("try_wait") {
            Some(_) => return,
            None => {
                if Instant::now() >= deadline {
                    panic!("daemon did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn stop(mut daemon: Daemon) {
    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    wait_for_exit(&mut daemon, Duration::from_secs(10));
}

/// Run the CLI as a client with extra env, returning the captured output.
fn run_cli_env(socket: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cache-warden"));
    // `--socket` must precede any `--` separator: everything after `--` is
    // positional (for `run`, the command argv), so a trailing `--socket` would
    // belong to the child command, not to us. Insert it right after the
    // top-level command word instead.
    cmd.arg(args[0])
        .arg("--socket")
        .arg(socket)
        .args(&args[1..]);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run cli")
}

fn run_cli(socket: &Path, args: &[&str]) -> Output {
    run_cli_env(socket, args, &[])
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Define a key (in the default namespace) whose value is the given literal
/// (via `printf`). The wire key is the composed `default/KEY` (DR-0017).
fn define(socket: &Path, key: &str, value: &str) {
    let json =
        format!(r#"{{"cmd":"kv.define","key":"default/{key}","argv":["printf","{value}"]}}"#);
    let resp = request(socket, &json);
    assert_eq!(resp["ok"], true, "define {key}: {resp}");
}

// ---- run ----------------------------------------------------------------

#[test]
fn run_injects_whole_value_env_reference_and_execs() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "DB_PW", "s3cr3t-value");

    // `run --env DB=cache-warden://DB_PW -- sh -c 'printf %s "$DB"'` must print
    // the resolved value (exec'd child sees the injected env).
    let out = run_cli(
        &socket,
        &[
            "run",
            "--env",
            "DB=cache-warden://DB_PW",
            "--",
            "sh",
            "-c",
            "printf %s \"$DB\"",
        ],
    );
    assert!(out.status.success(), "run failed: {}", stderr(&out));
    assert_eq!(stdout(&out), "s3cr3t-value");

    stop(daemon);
}

#[test]
fn run_argv_reference_is_passed_verbatim_with_warning() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    // A reference-looking token in argv is NOT resolved; it reaches the child
    // verbatim, and a warning is printed to stderr (DR-0013).
    let out = run_cli(&socket, &["run", "--", "printf", "%s", "cache-warden://X"]);
    assert!(out.status.success(), "run failed: {}", stderr(&out));
    assert_eq!(stdout(&out), "cache-warden://X", "argv passed verbatim");
    assert!(
        stderr(&out).contains("argv is not an injection face"),
        "expected argv warning: {}",
        stderr(&out)
    );

    stop(daemon);
}

#[test]
fn run_reveal_fails_closed_on_missing_reference() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    // No such key: reveal mode must not exec; non-zero exit, no child output.
    let out = run_cli(
        &socket,
        &[
            "run",
            "--env",
            "X=cache-warden://NOPE",
            "--",
            "printf",
            "should-not-run",
        ],
    );
    assert!(!out.status.success(), "must fail closed");
    assert!(
        !stdout(&out).contains("should-not-run"),
        "child must not have run: {}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("NOPE"), "names the failed key");

    stop(daemon);
}

#[test]
fn run_dry_run_execs_with_masked_env() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "DB_PW", "super-secret");

    // dry-run: the child IS exec'd, but with a masked env value (the real value
    // never reaches the client / child) — DR-0015 §3.
    let out = run_cli(
        &socket,
        &[
            "run",
            "--dry-run",
            "--env",
            "DB=cache-warden://DB_PW",
            "--",
            "sh",
            "-c",
            "printf %s \"$DB\"",
        ],
    );
    assert!(
        out.status.success(),
        "dry-run should exec: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "<cache-warden:default/DB_PW:masked>");
    assert!(
        !stdout(&out).contains("super-secret"),
        "real value must never appear in dry-run"
    );

    stop(daemon);
}

#[test]
fn run_dry_run_nonzero_exit_when_reference_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    // dry-run with a missing key: do not exec, exit non-zero, summarize on stderr.
    let out = run_cli(
        &socket,
        &[
            "run",
            "--dry-run",
            "--env",
            "X=cache-warden://NOPE",
            "--",
            "printf",
            "should-not-run",
        ],
    );
    assert!(!out.status.success(), "dry-run with failure exits non-zero");
    assert!(
        !stdout(&out).contains("should-not-run"),
        "child must not run when a dry-run reference fails"
    );
    assert!(stderr(&out).contains("NOPE"), "names the failed key");

    stop(daemon);
}

// ---- inject -------------------------------------------------------------

#[test]
fn inject_substitutes_references_in_template() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "USER", "alice");
    define(&socket, "PW", "hunter2");

    let tmpl = dir.path().join("dsn.tmpl");
    std::fs::write(
        &tmpl,
        "dsn=postgres://cache-warden://USER:cache-warden://PW@db",
    )
    .unwrap();
    let out_file = dir.path().join("dsn.out");

    let out = run_cli(
        &socket,
        &[
            "inject",
            "--in",
            tmpl.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "inject failed: {}", stderr(&out));

    let rendered = std::fs::read_to_string(&out_file).unwrap();
    assert_eq!(rendered, "dsn=postgres://alice:hunter2@db");

    // The output file is 0600 (DR-0013).
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&out_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "--out file must be 0600");

    stop(daemon);
}

#[test]
fn inject_dry_run_masks_and_reports_failures() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "OK", "real-value");
    // BAD is never defined.

    let tmpl = dir.path().join("t.tmpl");
    std::fs::write(&tmpl, "a=cache-warden://OK b=cache-warden://BAD").unwrap();

    let out = run_cli(
        &socket,
        &["inject", "--dry-run", "--in", tmpl.to_str().unwrap()],
    );
    // Non-zero exit because BAD failed, but the masked output is still produced.
    assert!(
        !out.status.success(),
        "a failed reference makes dry-run exit non-zero"
    );
    assert_eq!(
        stdout(&out),
        "a=<cache-warden:default/OK:masked> b=<cache-warden:default/BAD:failed>"
    );
    assert!(
        !stdout(&out).contains("real-value"),
        "real value must never appear in dry-run"
    );
    assert!(stderr(&out).contains("BAD"), "summary names the failed key");

    stop(daemon);
}

#[test]
fn inject_reveal_fails_closed_no_partial_output() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "OK", "real-value");
    let tmpl = dir.path().join("t.tmpl");
    std::fs::write(&tmpl, "a=cache-warden://OK b=cache-warden://MISSING").unwrap();
    let out_file = dir.path().join("t.out");

    let out = run_cli(
        &socket,
        &[
            "inject",
            "--in",
            tmpl.to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "reveal must fail closed");
    // No output file written (fail-closed, no partial output).
    assert!(!out_file.exists(), "no output file on a fail-closed inject");
    assert!(stderr(&out).contains("MISSING"));

    stop(daemon);
}

// ---- CACHE_WARDEN_DRY_RUN polarity switch (DR-0015 §4) -------------------

#[test]
fn env_var_flips_default_to_dry_run_and_flag_overrides_back() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "K", "real-secret");
    let tmpl = dir.path().join("t.tmpl");
    std::fs::write(&tmpl, "v=cache-warden://K").unwrap();

    // With CACHE_WARDEN_DRY_RUN=1 the default flips to dry-run: masked output.
    let out = run_cli_env(
        &socket,
        &["inject", "--in", tmpl.to_str().unwrap()],
        &[("CACHE_WARDEN_DRY_RUN", "1")],
    );
    assert!(
        out.status.success(),
        "no failures, exit 0: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "v=<cache-warden:default/K:masked>");

    // An explicit --reveal overrides the env var back to real values.
    let out = run_cli_env(
        &socket,
        &["inject", "--reveal", "--in", tmpl.to_str().unwrap()],
        &[("CACHE_WARDEN_DRY_RUN", "1")],
    );
    assert!(out.status.success(), "reveal override: {}", stderr(&out));
    assert_eq!(stdout(&out), "v=real-secret");

    stop(daemon);
}

#[test]
fn kv_get_dry_run_prints_mask_and_real_get_prints_value() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    define(&socket, "TOK", "tok-value");

    // Reveal: raw value to stdout.
    let out = run_cli(&socket, &["kv", "get", "TOK"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out), "tok-value");

    // Dry-run: masked, value never emitted.
    let out = run_cli(&socket, &["kv", "get", "--dry-run", "TOK"]);
    assert!(out.status.success(), "dry-run get ok: {}", stderr(&out));
    assert_eq!(stdout(&out).trim_end(), "<cache-warden:default/TOK:masked>");
    assert!(!stdout(&out).contains("tok-value"));

    // Dry-run of a missing key: failed mask + non-zero exit.
    let out = run_cli(&socket, &["kv", "get", "--dry-run", "GHOST"]);
    assert!(!out.status.success(), "missing key dry-run exits non-zero");
    assert_eq!(
        stdout(&out).trim_end(),
        "<cache-warden:default/GHOST:failed>"
    );

    stop(daemon);
}

#[test]
fn run_defs_registers_then_injects() {
    // `run --defs FILE` registers definitions before resolving (DR-0013 / §--defs).
    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    let defs = dir.path().join("defs.toml");
    std::fs::write(
        &defs,
        "[kv.FROM_DEFS]\ncommand = [\"printf\", \"defs-value\"]\n",
    )
    .unwrap();

    let out = run_cli(
        &socket,
        &[
            "run",
            "--defs",
            defs.to_str().unwrap(),
            "--env",
            "V=cache-warden://FROM_DEFS",
            "--",
            "sh",
            "-c",
            "printf %s \"$V\"",
        ],
    );
    assert!(out.status.success(), "run --defs failed: {}", stderr(&out));
    assert_eq!(stdout(&out), "defs-value");

    stop(daemon);
}

// ---- OTP value type via the CLI (DR-0016) -------------------------------

/// `cache-warden kv define --type otp` then `kv get` prints a 6-digit CODE (not
/// the seed), and a `run --env X=cache-warden://OTP` injects the same shape of
/// code — the reference resolution naturally yields the derived code, never the
/// seed. Value types live on definitions now (DR-0016).
#[test]
fn otp_define_get_and_run_inject_the_code_not_the_seed() {
    // RFC 6238 SHA1 test seed (base32).
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    let dir = tempfile::tempdir().unwrap();
    let (daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    // Register an otp definition whose command emits the seed (the seed itself
    // is never stored as a set value). The first get produces it lazily.
    let out = run_cli(
        &socket,
        &[
            "kv",
            "define",
            "OTP",
            "--type",
            "otp",
            "--command",
            "printf",
            "%s",
            SEED,
        ],
    );
    assert!(
        out.status.success(),
        "kv define --type otp failed: {}",
        stderr(&out)
    );

    // `kv get` prints the derived code, never the seed.
    let out = run_cli(&socket, &["kv", "get", "OTP"]);
    assert!(out.status.success(), "kv get otp failed: {}", stderr(&out));
    let code = stdout(&out);
    assert_eq!(code.len(), 6, "default otp digits, got {code:?}");
    assert!(code.chars().all(|c| c.is_ascii_digit()), "code: {code:?}");
    assert_ne!(code, SEED, "must not print the seed");

    // dry-run prints the mask, not the code.
    let out = run_cli(&socket, &["kv", "get", "OTP", "--dry-run"]);
    assert!(out.status.success(), "dry-run failed: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "<cache-warden:default/OTP:masked>");

    // `run` injects the code into the child env (whole-value reference).
    let out = run_cli(
        &socket,
        &[
            "run",
            "--env",
            "TOKEN=cache-warden://OTP",
            "--",
            "sh",
            "-c",
            "printf %s \"$TOKEN\"",
        ],
    );
    assert!(
        out.status.success(),
        "run with otp ref failed: {}",
        stderr(&out)
    );
    let injected = stdout(&out);
    assert_eq!(injected.len(), 6, "injected a 6-digit code: {injected:?}");
    assert!(injected.chars().all(|c| c.is_ascii_digit()));
    assert_ne!(injected, SEED, "run must inject the code, not the seed");

    stop(daemon);
}
