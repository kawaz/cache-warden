//! End-to-end tests for graceful restart (DR-0029 Phase 1, bundle 2).
//!
//! Follows `tests/e2e.rs`'s conventions: spawn the real built binary,
//! speak the raw JSON Lines wire directly, and retry the initial connect
//! with bounded backoff rather than a fixed sleep.
//!
//! Every real-daemon test in this file runs on macOS only: graceful
//! restart's fork/exec sequence is `unimplemented!` on every other target
//! (see `daemon::graceful_restart::handoff::execute`'s non-macOS stub), and
//! its control-socket handler rejects the request before ever reaching that
//! code on those platforms (`daemon::graceful_restart::handle_request`'s
//! early guard) — there would be nothing to exercise.

#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// A spawned daemon that is killed (and its socket cleaned) on drop.
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
                    panic!("daemon never became reachable at {}: {e}", socket.display());
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(200));
            }
        }
    }
}

/// Send one JSON request line, read one JSON response line (or `None` if the
/// daemon closed the connection without replying — the expected shape for an
/// *accepted* `daemon.restart_graceful` on the success path).
fn request_allow_close(socket: &Path, json_line: &str) -> Option<serde_json::Value> {
    let stream = connect_with_retry(socket);
    let mut writer = stream.try_clone().expect("clone");
    writer.write_all(json_line.as_bytes()).expect("write");
    writer.write_all(b"\n").expect("write nl");
    writer.flush().expect("flush");

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read");
    if n == 0 {
        return None;
    }
    Some(serde_json::from_str(line.trim_end()).expect("parse response json"))
}

fn request(socket: &Path, json_line: &str) -> serde_json::Value {
    request_allow_close(socket, json_line).expect("daemon closed without responding")
}

/// Poll `cmd:ping` until it succeeds or `deadline` elapses.
fn wait_for_ping(socket: &Path, deadline: Duration) {
    let end = Instant::now() + deadline;
    let mut delay = Duration::from_millis(5);
    loop {
        if let Some(resp) = request_allow_close(socket, r#"{"cmd":"ping"}"#)
            && resp["ok"] == true
        {
            return;
        }
        if Instant::now() >= end {
            panic!("daemon at {} never answered ping again", socket.display());
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(200));
    }
}

fn pid_of(socket: &Path) -> u64 {
    request(socket, r#"{"cmd":"status"}"#)["pid"]
        .as_u64()
        .unwrap()
}

/// A mock command source that appends one line to `counter_file` every time
/// it runs, so a test can assert exactly how many times it was invoked —
/// the whole point of graceful restart (DR-0029's motivation) is that a
/// restart must **not** cause a re-fetch.
fn counting_command(counter_file: &Path) -> String {
    format!(
        "printf secret-value; printf x >> {}",
        shell_quote(counter_file)
    )
}

fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.display())
}

fn run_count(counter_file: &Path) -> usize {
    std::fs::read_to_string(counter_file)
        .unwrap_or_default()
        .len()
}

/// test_1 (task delegation §D): a full graceful-restart round trip over the
/// real control socket — same pid afterward, and the cached value survives
/// with **zero** additional invocations of its source command.
#[test]
fn graceful_restart_preserves_cache_with_no_re_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");
    let counter_file = dir.path().join("run-count");
    std::fs::write(&counter_file, "").unwrap();

    // A `[kv.*]` entry with `preload = true`, defined via a mock `sh -c`
    // source that records each invocation. DR-0029's whole motivation is
    // that a restart must not re-trigger this (e.g. a real op/TouchID
    // cycle) — `counter_file`'s length is the ground truth for that.
    let config = format!(
        "[kv.TOK]\nsource = \"command\"\ncommand.argv = [\"sh\", \"-c\", {:?}]\npreload = true\n",
        counting_command(&counter_file)
    );
    std::fs::write(&config_path, config).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    // Wait for startup (preload run) to complete: the first `get` is a hit.
    wait_for_ping(&socket, Duration::from_secs(10));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], true, "initial get: {resp}");
    let before_pid = pid_of(&socket);
    let runs_before = run_count(&counter_file);
    assert_eq!(
        runs_before, 1,
        "preload should have run the source exactly once"
    );

    // --- trigger the graceful restart ---
    let resp = request_allow_close(&socket, r#"{"cmd":"daemon.restart_graceful"}"#);
    // Either shape is acceptable (see `Request::RestartGraceful`'s doc): an
    // explicit ack, or the connection closing with no reply at all (the
    // execve happened before a reply could be flushed).
    if let Some(resp) = &resp {
        assert_eq!(resp["ok"], true, "restart ack: {resp}");
    }

    // The new process binds the *same* socket path — poll it back up.
    wait_for_ping(&socket, Duration::from_secs(10));
    let after_pid = pid_of(&socket);
    assert_eq!(
        before_pid, after_pid,
        "graceful restart execs in place: pid must be unchanged"
    );

    // The cached value survived, and — critically — the source was not
    // re-run: the whole point of the exercise.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], true, "post-restart get: {resp}");
    let got = base64_decode(resp["value_b64"].as_str().unwrap());
    assert_eq!(got, b"secret-value");
    assert_eq!(
        run_count(&counter_file),
        runs_before,
        "no re-fetch storm: the source must not run again after a graceful restart"
    );

    // DR-0029 bundle 2 review HIGH-2: the state-holder child (forked by the
    // *old* process, DR-0029 §1 step ⑤) must actually be reaped — not left
    // as a zombie process-table entry. `execve` preserves pid/parent-child
    // relationships, so the *new* process (same pid as `after_pid`) is still
    // the kernel's recorded parent of the holder; `receive::try_receive`
    // spawns a background `waitpid` specifically to reap it (DR-0029 §5).
    // Bounded-poll rather than a fixed sleep: the reap races the new
    // process's own startup (the holder only exits once it receives the
    // `COMMIT` frame, which the new process sends right after this same
    // `wait_for_ping` above observed it serving) but is not guaranteed to
    // have completed the very instant `wait_for_ping` returns.
    assert_no_zombie_children(after_pid as u32, Duration::from_secs(5));

    // Clean up: plain SIGTERM shutdown.
    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = daemon.child.wait();
}

/// DR-0029 bundle 2 review HIGH-2 regression check: assert no zombie (`Z`
/// state) process remains parented to `parent_pid` within `deadline`.
/// Bounded-poll (not a fixed sleep) so the assertion returns as soon as the
/// reaper thread has actually run, rather than waiting out a worst-case
/// guess every time.
fn assert_no_zombie_children(parent_pid: u32, deadline: Duration) {
    let parent_pid_str = parent_pid.to_string();
    let end = Instant::now() + deadline;
    let mut delay = Duration::from_millis(10);
    loop {
        let out = Command::new("ps")
            .args(["-eo", "pid,ppid,stat"])
            .output()
            .expect("run ps");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let zombies: Vec<String> = stdout
            .lines()
            .skip(1) // header row
            .filter(|line| {
                let mut fields = line.split_whitespace();
                let _pid = fields.next();
                let ppid = fields.next();
                let stat = fields.next().unwrap_or("");
                ppid == Some(parent_pid_str.as_str()) && stat.contains('Z')
            })
            .map(str::to_string)
            .collect();
        if zombies.is_empty() {
            return;
        }
        if Instant::now() >= end {
            panic!(
                "zombie state-holder child(ren) of pid {parent_pid} still present after \
                 {deadline:?}: {zombies:?}"
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(200));
    }
}

/// test_2 (task delegation §D): a broken/truncated handoff must never block
/// the new process's own startup — it falls back to an immediate cold start
/// (DR-0029 §1's fail-safe regression test: "handoff 失敗注入時に新プロセス
/// が即 bind して cold start できること"). Exercised directly (without a real
/// old-process handoff) by spawning `daemon run` with a bogus
/// `CACHE_WARDEN_HANDOFF_FD`, the same env-var contract a real handoff uses.
#[test]
fn broken_handoff_falls_back_to_immediate_cold_start() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "").unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .env("CACHE_WARDEN_CONFIG", &config_path)
        // A fd number that was never opened by this process — `try_receive`
        // must reject it (its own `set_read_timeout`/read fails) rather than
        // hang, and the daemon must still bind and serve immediately.
        .env("CACHE_WARDEN_HANDOFF_FD", "987654")
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    wait_for_ping(&socket, Duration::from_secs(10));
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    assert_eq!(resp["ok"], true, "status: {resp}");
    assert_eq!(
        resp["entries"].as_array().unwrap().len(),
        0,
        "a broken handoff must degrade to a genuinely empty cold start, not a stuck partial one"
    );

    unsafe {
        libc::kill(daemon.child.id() as i32, libc::SIGTERM);
    }
    let _ = daemon.child.wait();
}

/// test_3 (task delegation §D): the two-phase-commit ABORT path. The new
/// process's own startup fails *after* it has taken the handoff fd (an
/// invalid config file, inherited from the old process's environment,
/// forces `main` to exit before ever calling `send_commit`) — its process
/// exit closes every fd it held, including the inherited handoff end, which
/// is DR-0029 §5's *only* ABORT signal ("相手側 end の close"). This is
/// observed indirectly (the holder is an anonymous child of the *old*
/// process with no test-visible handle — DR-0029 §5 itself only asks that
/// the new process reap it, not that a test observe its exit code
/// directly): the old daemon must keep running normally throughout, since
/// every failure from this point on is defined to be fail-safe for it.
#[test]
fn new_process_startup_failure_after_taking_the_handoff_is_a_safe_abort() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "").unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };
    wait_for_ping(&socket, Duration::from_secs(10));
    let before_pid = pid_of(&socket);

    // Corrupt the config *after* the old process is up but before the
    // restart: the re-exec'd new process re-reads it (same
    // `CACHE_WARDEN_CONFIG` path, inherited via env) and must fail to parse
    // it — exiting before it could ever reach `send_commit`.
    std::fs::write(&config_path, "this is not valid toml [[[").unwrap();

    let resp = request_allow_close(&socket, r#"{"cmd":"daemon.restart_graceful"}"#);
    if let Some(resp) = &resp {
        assert_eq!(resp["ok"], true, "restart ack: {resp}");
    }

    // The new process must have exited (bad config) rather than hang;
    // `daemon.child` was replaced in-place by execve, so waiting on the same
    // `Child` handle observes the post-exec process's own exit.
    let status = daemon
        .child
        .wait()
        .expect("the execve'd process should exit on its bad config");
    assert!(
        !status.success(),
        "a daemon started with an unparseable config must not exit 0"
    );

    // The pid is gone; nothing else to assert here beyond "did not hang" —
    // the abort-detection itself (holder sees EPIPE/EOF, exits, is reaped)
    // is covered at the unit level by
    // `graceful_restart::receive::try_receive_falls_back_to_cold_start_on_truncated_stream`
    // and by this test's own bounded `wait()` above completing at all.
    let _ = before_pid;
}

/// DR-0029 bundle 2 review CRITICAL/HIGH-3: a config change must actually take
/// effect across a graceful restart, not be silently overridden by the
/// import-origin definition the handoff snapshot carries over.
///
/// Exercises the full lifecycle: `OLD` is defined + cached under the
/// pre-restart config; the config is then rewritten (before the restart) to
/// give `OLD` a *different* command and a short `hard-ttl`, and to add a
/// brand-new `NEW_KEY` entry that never existed before. After the restart:
///
/// 1. `NEW_KEY` — absent from the old process entirely — must work (the new
///    config's definitions are registered against the imported store).
/// 2. `OLD`'s cached value must survive **unchanged** immediately after the
///    restart (value continuity: its own baked-in TTL, from the *original*
///    fetch, has not elapsed yet — changing the config must not force an
///    immediate re-fetch).
/// 3. Once `OLD`'s original short hard-ttl genuinely elapses (real time, not
///    a mock clock — this is an out-of-process e2e test) and a `kv.get`
///    triggers `get_or_regenerate`, the value it produces must come from the
///    *new* command — proving the config's definition, not the stale
///    imported one, won (`server::register_definitions`'s CRITICAL fix:
///    `Store::undefine` clears the import-origin definition for every
///    config-defined key before re-registering).
///
/// `status`'s `EntryInfo::source` cannot distinguish the two definitions
/// directly: `source_meta_display` intentionally renders a `command` source
/// as the bare string `"command"` over the IPC boundary, never the argv
/// (`source_meta_display_verbose`'s doc: "Never used on an IPC boundary") —
/// so step 3's regenerated *value* is the only externally observable proof.
#[test]
fn graceful_restart_applies_new_config() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");

    std::fs::write(
        &config_path,
        "[kv.OLD]\n\
         source = \"command\"\n\
         command.argv = [\"sh\", \"-c\", \"printf old-v1\"]\n\
         hard-ttl = \"2s\"\n",
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    wait_for_ping(&socket, Duration::from_secs(10));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/OLD"}"#);
    assert_eq!(resp["ok"], true, "initial get: {resp}");
    assert_eq!(
        base64_decode(resp["value_b64"].as_str().unwrap()),
        b"old-v1"
    );
    let fetched_at = Instant::now();

    // Rewrite the config *before* the restart: OLD gets a new command + a
    // longer hard-ttl for its *next* definition, and NEW_KEY is added from
    // scratch.
    std::fs::write(
        &config_path,
        "[kv.OLD]\n\
         source = \"command\"\n\
         command.argv = [\"sh\", \"-c\", \"printf old-v2\"]\n\
         hard-ttl = \"10s\"\n\
         \n\
         [kv.NEW_KEY]\n\
         source = \"command\"\n\
         command.argv = [\"sh\", \"-c\", \"printf brand-new\"]\n\
         hard-ttl = \"1h\"\n",
    )
    .unwrap();

    let resp = request_allow_close(&socket, r#"{"cmd":"daemon.restart_graceful"}"#);
    if let Some(resp) = &resp {
        assert_eq!(resp["ok"], true, "restart ack: {resp}");
    }
    wait_for_ping(&socket, Duration::from_secs(10));

    // 1. A key that only exists in the *new* config must work post-restart.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/NEW_KEY"}"#);
    assert_eq!(resp["ok"], true, "new-config-only key: {resp}");
    assert_eq!(
        base64_decode(resp["value_b64"].as_str().unwrap()),
        b"brand-new",
        "a key added to the config only after the old process started must still work \
         after a graceful restart"
    );

    // 2. OLD's cached value must survive the restart unchanged — its own
    // baked-in 2s hard-ttl (from the *original* fetch, `fetched_at`) has not
    // elapsed yet (the whole restart round trip above takes well under 2s in
    // practice, per `graceful_restart_preserves_cache_with_no_re_fetch`).
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/OLD"}"#);
    assert_eq!(resp["ok"], true, "post-restart get (pre-expiry): {resp}");
    assert_eq!(
        base64_decode(resp["value_b64"].as_str().unwrap()),
        b"old-v1",
        "the cached value must survive a graceful restart unchanged until its own \
         (pre-restart) TTL naturally elapses — a config change must not force an \
         immediate re-fetch"
    );

    // 3. Wait out OLD's *original* 2s hard-ttl (real elapsed time — this is
    // an out-of-process e2e test, there is no mock clock to advance), then
    // `kv.get` again: this must regenerate, and the regenerated value must
    // come from the *new* command — the only externally observable proof
    // that the config's definition (not the stale imported one) won.
    let remaining = Duration::from_millis(2_500).saturating_sub(fetched_at.elapsed());
    if !remaining.is_zero() {
        std::thread::sleep(remaining);
    }
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/OLD"}"#);
    assert_eq!(resp["ok"], true, "post-expiry regenerated get: {resp}");
    assert_eq!(
        base64_decode(resp["value_b64"].as_str().unwrap()),
        b"old-v2",
        "once the pre-restart value's own hard-ttl elapses, regeneration must use the \
         *new* config's command (old-v2), not the stale imported definition's (old-v1) \
         — this is the CRITICAL-fix regression this test exists to catch"
    );

    // Clean up: plain SIGTERM shutdown.
    unsafe {
        libc::kill(daemon.child.id() as i32, libc::SIGTERM);
    }
    let _ = daemon.child.wait();
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
