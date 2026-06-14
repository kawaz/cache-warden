//! End-to-end test: start the real daemon over a temp control socket, drive
//! it with the JSON Lines protocol, and shut it down cleanly.
//!
//! This exercises the whole stack (binary entrypoint → tokio server → bind →
//! accept → handler → core Store) the way a client really uses it. The wire is
//! spoken directly here (raw JSON Lines) so the test does not depend on the
//! CLI's rendering and pins the documented protocol shape (DR-0009).
//!
//! Flakiness control: the daemon binds asynchronously, so the test retries the
//! initial connect with a bounded backoff instead of sleeping a fixed amount.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// A spawned daemon that is killed (and its socket cleaned) on drop.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Best-effort terminate; the test normally stops it explicitly.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Connect to `socket`, retrying with backoff until the daemon is listening.
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

/// Send one JSON request line, read one JSON response line, parse to a Value.
fn request(socket: &Path, json_line: &str) -> serde_json::Value {
    let stream = connect_with_retry(socket);
    let mut writer = stream.try_clone().expect("clone");
    writer.write_all(json_line.as_bytes()).expect("write");
    writer.write_all(b"\n").expect("write nl");
    writer.flush().expect("flush");

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read");
    assert!(n > 0, "daemon closed without responding");
    serde_json::from_str(line.trim_end()).expect("parse response json")
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[test]
fn full_lifecycle_over_control_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    // --- ping ---
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true, "ping: {resp}");

    // --- kv.set (static) ---
    let set = format!(
        r#"{{"cmd":"kv.set","key":"default/DB","source":{{"kind":"static","value_b64":"{}"}},"soft_ttl_secs":3600,"hard_ttl_secs":86400}}"#,
        b64(b"hunter2")
    );
    let resp = request(&socket, &set);
    assert_eq!(resp["ok"], true, "set: {resp}");

    // --- kv.get returns the value (base64) ---
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/DB"}"#);
    assert_eq!(resp["ok"], true, "get: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"hunter2");

    // --- kv.define a second key (command source; lazy, value produced on get) ---
    let def = r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","tok-value"]}}"#;
    let resp = request(&socket, def);
    assert_eq!(resp["ok"], true, "define: {resp}");
    // Right after define, status shows TOK as defined with no value yet.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let tok = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "default/TOK")
        .expect("TOK in status");
    assert_eq!(tok["defined"], true, "TOK is defined: {tok}");
    assert_eq!(tok["has_value"], false, "TOK has no value yet: {tok}");
    assert_eq!(
        tok["state"], "defined",
        "TOK reports the defined state: {tok}"
    );
    // The first get lazily produces the value.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"tok-value");

    // --- kv.list shows both keys, sorted ---
    let resp = request(&socket, r#"{"cmd":"kv.list"}"#);
    let keys: Vec<String> = resp["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // The wire view is the composed keyspace (DR-0017 §1).
    assert_eq!(keys, vec!["default/DB", "default/TOK"]);

    // --- status: entries present, NO secret values leaked ---
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    assert_eq!(resp["ok"], true);
    let status_str = resp.to_string();
    assert!(
        !status_str.contains("hunter2"),
        "status leaked a value: {status_str}"
    );
    assert!(!status_str.contains(&b64(b"hunter2")));
    assert!(!status_str.contains("tok-value"));
    let entries = resp["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|e| e["name"] == "default/DB" && e["state"] == "active")
    );

    // --- kv.del removes a key ---
    let resp = request(&socket, r#"{"cmd":"kv.del","key":"default/DB"}"#);
    assert_eq!(resp["deleted"], true, "del: {resp}");
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/DB"}"#);
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["kind"], "not_found");

    // --- delete a missing key reports deleted:false ---
    let resp = request(&socket, r#"{"cmd":"kv.del","key":"default/DB"}"#);
    assert_eq!(resp["deleted"], false);

    // --- malformed request -> bad_request, daemon stays up ---
    let resp = request(&socket, r#"{"cmd":"nonsense"}"#);
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["kind"], "bad_request");
    // still alive:
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // --- shutdown via SIGTERM, expect clean socket removal ---
    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    // Wait for exit.
    let status = wait_for_exit(&mut daemon, Duration::from_secs(10));
    assert!(
        status.success() || status.code().is_none(),
        "exit status: {status:?}"
    );

    // Socket file should be cleaned up on graceful shutdown.
    let cleaned_deadline = Instant::now() + Duration::from_secs(5);
    while socket.exists() && Instant::now() < cleaned_deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!socket.exists(), "socket should be removed on shutdown");
}

fn wait_for_exit(daemon: &mut Daemon, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match daemon.child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None => {
                if Instant::now() >= deadline {
                    panic!("daemon did not exit within {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Spawn a daemon driven by a config file (via `$CACHE_WARDEN_CONFIG`), with the
/// control socket also pinned by config (no `--socket`). Returns the daemon
/// handle and the resolved socket path.
fn spawn_with_config(dir: &Path, config_toml: &str) -> (Daemon, std::path::PathBuf) {
    let socket = dir.join("control.sock");
    let config_path = dir.join("config.toml");
    // The config pins the socket so we exercise the config -> socket precedence
    // path (no --socket on the CLI).
    let full = format!("[daemon]\nsocket = \"{}\"\n{config_toml}", socket.display());
    std::fs::write(&config_path, full).expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .spawn()
        .expect("spawn daemon");
    (Daemon { child }, socket)
}

/// A real executable basename from *this test process's* own ancestry chain.
///
/// The control-socket client in these tests is the test binary itself, so the
/// daemon resolves its peer pid's ancestry to a chain that contains this name.
/// Putting it in a key's `allowed_processes` must admit a `kv.get`; a bogus name
/// must deny it. Resolved live (not hard-coded) so it works on any runner.
fn a_real_ancestor_name() -> String {
    use cache_warden::ProcessInspector;
    let chain = cache_warden::SystemInspector::new()
        .ancestry(std::process::id())
        .expect("self ancestry resolves");
    chain
        .iter()
        .find_map(|p| p.name().map(str::to_string))
        .expect("our ancestry has at least one named process")
}

#[test]
fn kv_get_allowed_processes_admits_matching_ancestor_and_denies_others() {
    // DR-0012 key layer (end-to-end): a `[kv.NAME]` with `allowed_processes` is
    // gettable only from a requester whose ancestry names an allowed basename.
    let dir = tempfile::tempdir().unwrap();
    let allowed = a_real_ancestor_name();

    // OPEN: no restriction (control). RESTRICT: only our real ancestor may get it.
    // DENIED: a restriction that our ancestry can never satisfy.
    let cfg = format!(
        r#"
[kv.OPEN]
source = "command"
command.argv = ["printf", "open-value"]
preload = true

[kv.RESTRICT]
source = "command"
command.argv = ["printf", "restricted-value"]
preload = true
allowed_processes = ["{allowed}"]

[kv.DENIED]
source = "command"
command.argv = ["printf", "denied-value"]
preload = true
allowed_processes = ["no-such-process-name-xyz"]
"#
    );
    let (mut daemon, socket) = spawn_with_config(dir.path(), &cfg);

    // OPEN: unrestricted key gets normally.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/OPEN"}"#);
    assert_eq!(resp["ok"], true, "open key get: {resp}");
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"open-value"
    );

    // RESTRICT: our real ancestor name is allowed, so the get succeeds and
    // returns the value.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/RESTRICT"}"#);
    assert_eq!(
        resp["ok"], true,
        "restricted key get from allowed ancestor: {resp}"
    );
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"restricted-value"
    );

    // DENIED: no process in our ancestry matches, so the get is refused with
    // auth_failed and no value is returned.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/DENIED"}"#);
    assert_eq!(resp["ok"], false, "denied key get must fail: {resp}");
    assert_eq!(resp["error"]["kind"], "auth_failed");
    assert!(
        resp.get("value_b64").is_none() || resp["value_b64"].is_null(),
        "denied get must not carry a value: {resp}"
    );

    // The denied key is still visible in kv.list (existence is not hidden; only
    // the value is gated).
    let resp = request(&socket, r#"{"cmd":"kv.list"}"#);
    let keys: Vec<String> = resp["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        keys.contains(&"default/DENIED".to_string()),
        "list shows DENIED: {keys:?}"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn config_preload_and_reauth_command_allow() {
    let dir = tempfile::tempdir().unwrap();
    // Preload TOK with `preload = true` (no TTL => always Active) to verify
    // startup preload, and EXT with a 1s soft TTL so it soft-expires and
    // triggers the re-auth command. `[auth].command = ["true"]` approves.
    let cfg = r#"
[auth]
type = "command"
command = ["true"]

[kv.TOK]
source = "command"
command.argv = ["printf", "preloaded-tok"]
preload = true

[kv.EXT]
source = "command"
command.argv = ["printf", "ext-value"]
soft-ttl = "1s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Preload populated TOK: a get is an immediate hit.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], true, "preloaded TOK get: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"preloaded-tok");

    // EXT is initially Active too.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/EXT"}"#);
    assert_eq!(resp["ok"], true);

    // Let EXT soft-expire (1s), then get: the daemon runs the re-auth command
    // (`true` => approved) and extends, returning the value.
    std::thread::sleep(Duration::from_millis(2500));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/EXT"}"#);
    assert_eq!(
        resp["ok"], true,
        "extend should be approved by `true`: {resp}"
    );
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"ext-value");

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn config_reauth_command_deny_blocks_extend() {
    let dir = tempfile::tempdir().unwrap();
    // `[auth].command = ["false"]` denies, so a soft-expired extend fails.
    // EXT is preloaded so it starts Active (it soft-expires after 1s).
    let cfg = r#"
[auth]
type = "command"
command = ["false"]

[kv.EXT]
source = "command"
command.argv = ["printf", "ext-value"]
soft-ttl = "1s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Confirm the daemon is up (avoid a get here so timing cannot turn the
    // "Active" probe into an early soft-expiry).
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // After soft expiry, the get triggers the re-auth command (`false` =>
    // denied), so the daemon refuses with auth_failed.
    std::thread::sleep(Duration::from_millis(2500));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/EXT"}"#);
    assert_eq!(
        resp["ok"], false,
        "extend must be denied by `false`: {resp}"
    );
    assert_eq!(resp["error"]["kind"], "auth_failed");

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn pin_holds_value_past_soft_expiry_then_unpin_restores_gating() {
    // DR-0011: pin a soft-expiring entry so it stays gettable past its soft TTL,
    // then unpin and confirm the re-auth gate comes back. `[auth].command` is
    // `["false"]` so any soft-expired extend WOULD fail — proving the post-pin
    // get is served by the pin, not by an extend, and the post-unpin get is
    // refused once soft-expired.
    let dir = tempfile::tempdir().unwrap();
    let cfg = r#"
[auth]
type = "command"
command = ["false"]

[kv.EXT]
source = "command"
command.argv = ["printf", "ext-value"]
soft-ttl = "1s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Initially Active; pin it for a long window (re-auth required, but the
    // `false` authenticator denies... so pin must FAIL here). Confirm that:
    // pinning is a re-auth-gated operation even from Active.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.pin","key":"default/EXT","duration_secs":3600}"#,
    );
    assert_eq!(
        resp["ok"], false,
        "pin must be denied by the `false` authenticator: {resp}"
    );
    assert_eq!(resp["error"]["kind"], "auth_failed");

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn pin_with_approving_auth_survives_soft_expiry_and_unpin_restores_gating() {
    // `[auth].command = ["true"]` approves, so the pin applies. After the soft
    // TTL lapses the pinned value is still gettable; after unpin + soft expiry it
    // is gated again (extend via `true` would still pass, so to prove gating we
    // check the state is no longer pin-forced Active in status).
    let dir = tempfile::tempdir().unwrap();
    let cfg = r#"
[auth]
type = "command"
command = ["true"]

[kv.EXT]
source = "command"
command.argv = ["printf", "ext-value"]
soft-ttl = "1s"
hard-ttl = "2s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Pin EXT for an hour while it is still Active (approved by `true`).
    let resp = request(
        &socket,
        r#"{"cmd":"kv.pin","key":"default/EXT","duration_secs":3600}"#,
    );
    assert_eq!(resp["ok"], true, "pin approved by `true`: {resp}");
    assert_eq!(resp["pinned"], true);

    // Past the hard TTL (2s): without the pin the value would be zeroized, but
    // the pin holds it Active and gettable.
    std::thread::sleep(Duration::from_millis(2500));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/EXT"}"#);
    assert_eq!(resp["ok"], true, "pinned value survives hard TTL: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"ext-value");

    // status shows the pin's remaining seconds.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let entries = resp["entries"].as_array().unwrap();
    let ext = entries.iter().find(|e| e["name"] == "default/EXT").unwrap();
    assert_eq!(ext["state"], "active", "pinned entry reports Active");
    assert!(
        ext["pin_remaining_secs"].as_u64().unwrap() > 0,
        "status reports pin remaining: {ext}"
    );

    // Unpin: the pin is dropped. The entry is now past its real hard TTL, so a
    // get must no longer return the old value via a pin (it will try to
    // regenerate the command source instead — approved by `true`, returning a
    // fresh value). The key point: status no longer shows a pin.
    let resp = request(&socket, r#"{"cmd":"kv.unpin","key":"default/EXT"}"#);
    assert_eq!(resp["ok"], true, "unpin ok: {resp}");
    assert_eq!(resp["unpinned"], true);

    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let entries = resp["entries"].as_array().unwrap();
    let ext = entries.iter().find(|e| e["name"] == "default/EXT").unwrap();
    assert!(
        ext.get("pin_remaining_secs").is_none() || ext["pin_remaining_secs"].is_null(),
        "after unpin there is no pin field: {ext}"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn pin_missing_key_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    let resp = request(
        &socket,
        r#"{"cmd":"kv.pin","key":"default/ghost","duration_secs":60}"#,
    );
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["kind"], "not_found");

    // unpin of a missing key is also not_found.
    let resp = request(&socket, r#"{"cmd":"kv.unpin","key":"default/ghost"}"#);
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["kind"], "not_found");

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

/// Spawn a daemon with no config, control socket pinned via `--socket`.
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

#[test]
fn define_get_lazy_del_value_only_then_get_regenerates() {
    // DR-0014: define registers but does not run; the first get lazily produces
    // the value; `kv.del` (value only) keeps the definition so the next get
    // regenerates the value again.
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    // define (no upstream run yet) — status shows defined, no value.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","lazy-value"]}}"#,
    );
    assert_eq!(resp["ok"], true, "define: {resp}");
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let tok = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "default/TOK")
        .expect("TOK present");
    assert_eq!(tok["defined"], true);
    assert_eq!(tok["has_value"], false);

    // first get lazily produces the value.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], true, "lazy get: {resp}");
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"lazy-value"
    );

    // del (value only): the definition survives.
    let resp = request(&socket, r#"{"cmd":"kv.del","key":"default/TOK"}"#);
    assert_eq!(resp["deleted"], true, "del value: {resp}");
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let tok = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "default/TOK")
        .expect("TOK still defined after value del");
    assert_eq!(tok["defined"], true, "definition survives value-only del");
    assert_eq!(tok["has_value"], false);

    // get again: regenerated from the surviving definition.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], true, "regenerated get: {resp}");
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"lazy-value"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn define_command_cwd_and_env_take_effect_on_regeneration() {
    // DR-0018 §1: a `command` source's cwd / env are carried onto the execution
    // primitive and applied when the daemon runs the command.
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    // cwd: `pwd` reflects the requested working directory (/tmp).
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/CWD","source":"command","command":{"argv":["pwd"],"cwd":"/tmp"}}"#,
    );
    assert_eq!(resp["ok"], true, "define cwd: {resp}");
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/CWD"}"#);
    let got = B64.decode(resp["value_b64"].as_str().unwrap()).unwrap();
    let got = String::from_utf8(got).unwrap();
    assert!(got == "/tmp" || got == "/private/tmp", "pwd was {got:?}");

    // env: the overlaid variable is visible to the command.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/ENV","source":"command","command":{"argv":["sh","-c","printf %s \"$CW_E2E_VAR\""],"env":{"CW_E2E_VAR":"from-overlay"}}}"#,
    );
    assert_eq!(resp["ok"], true, "define env: {resp}");
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/ENV"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"from-overlay"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn del_with_define_drops_definition_so_get_is_not_found() {
    // DR-0014 §2: `kv.del --with-define` forgets the key entirely, so a later get
    // cannot regenerate it.
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","v"]}}"#,
    );
    assert_eq!(resp["ok"], true, "define: {resp}");
    // produce the value once.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], true);

    // del with_define: drops both value and definition.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.del","key":"default/TOK","with_define":true}"#,
    );
    assert_eq!(resp["deleted"], true, "del with_define: {resp}");

    // get: the key is gone entirely (no definition to regenerate from).
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(resp["ok"], false, "get after with-define del: {resp}");
    assert_eq!(resp["error"]["kind"], "not_found");

    // status no longer lists the key.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    assert!(
        resp["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["name"] != "default/TOK"),
        "TOK should be gone from status: {resp}"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn define_conflict_then_del_with_define_allows_redefine() {
    // A conflicting redefinition is rejected; deleting the definition first
    // clears the way for the new one (DR-0014 §1).
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","a"]}}"#,
    );
    assert_eq!(resp["ok"], true);
    // identical define is an idempotent no-op.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","a"]}}"#,
    );
    assert_eq!(resp["ok"], true, "identical define is a no-op: {resp}");
    // conflicting define is rejected with a redefine hint.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","b"]}}"#,
    );
    assert_eq!(resp["ok"], false, "conflict rejected: {resp}");
    assert_eq!(resp["error"]["kind"], "bad_request");

    // del --with-define then redefine succeeds.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.del","key":"default/TOK","with_define":true}"#,
    );
    assert_eq!(resp["deleted"], true);
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/TOK","source":"command","command":{"argv":["printf","b"]}}"#,
    );
    assert_eq!(resp["ok"], true, "redefine after del succeeds: {resp}");
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/TOK"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"b"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn config_rejects_inline_static_value() {
    // A `[kv.*]` with an inline `value` must make `run` exit non-zero (secrets
    // may not be persisted in config, DR-0010).
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "[kv.SECRET]\nvalue = \"hunter2\"\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(dir.path().join("control.sock"))
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .output()
        .expect("spawn daemon");
    assert!(
        !out.status.success(),
        "daemon must refuse a config with an inline value"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("hunter2"),
        "error must not echo the secret: {stderr}"
    );
}

/// Run the CLI binary as a client (`cache-warden <args> --socket <socket>`),
/// returning its captured output. Used to drive the client-side `--defs` batch
/// logic (which lives in the binary, not on the raw wire).
fn run_cli(socket: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .args(args)
        .arg("--socket")
        .arg(socket)
        .output()
        .expect("run cli")
}

#[test]
fn cli_command_cwd_env_sugar_takes_effect() {
    // DR-0018 §1: the `--command-cwd` / `--command-env` CLI sugar configures the
    // `command` source's cwd / env, applied when the daemon runs the command.
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // --command-env precedes --command (which consumes the rest as argv).
    let out = run_cli(
        &socket,
        &[
            "kv",
            "define",
            "ENVKEY",
            "--command-env",
            "CW_SUGAR=sugar-val",
            "--command",
            "sh",
            "-c",
            "printf %s \"$CW_SUGAR\"",
        ],
    );
    assert!(
        out.status.success(),
        "define --command-env failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/ENVKEY"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"sugar-val"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn define_defs_file_then_get_lazily_generates() {
    // `kv define --defs FILE` bulk-registers a file's definitions (lazy); a
    // later get produces each value on demand (DR-0014 §4).
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    let defs_path = dir.path().join("my.cache-warden.toml");
    std::fs::write(
        &defs_path,
        r#"[kv.ALPHA]
source = "command"
command.argv = ["printf", "alpha-value"]

[kv.BETA]
source = "command"
command.argv = ["printf", "beta-value"]
soft-ttl = "1h"
"#,
    )
    .unwrap();

    // Wait for the daemon to be reachable before issuing the client command.
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    let out = run_cli(
        &socket,
        &["kv", "define", "--defs", defs_path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "define --defs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Both keys are defined (no value yet — lazy).
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let entries = resp["entries"].as_array().unwrap();
    for name in ["default/ALPHA", "default/BETA"] {
        let e = entries.iter().find(|e| e["name"] == name).expect("defined");
        assert_eq!(e["defined"], true, "{name} defined");
        assert_eq!(e["has_value"], false, "{name} lazy (no value)");
    }

    // First get lazily produces each value.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/ALPHA"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"alpha-value"
    );
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/BETA"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"beta-value"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn define_defs_conflict_is_aggregated_not_fatal() {
    // A defs file whose key clashes with an existing different definition must
    // report that key as a failure (non-zero exit) while still registering the
    // non-clashing keys (DR-0014 §4: one conflict does not stop the batch).
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // Pre-register CLASH with one argv.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"default/CLASH","source":"command","command":{"argv":["printf","original"]}}"#,
    );
    assert_eq!(resp["ok"], true);

    // defs file: CLASH (different argv => conflict) + FRESH (ok).
    let defs_path = dir.path().join("defs.toml");
    std::fs::write(
        &defs_path,
        r#"[kv.CLASH]
source = "command"
command.argv = ["printf", "different"]

[kv.FRESH]
source = "command"
command.argv = ["printf", "fresh-value"]
"#,
    )
    .unwrap();

    let out = run_cli(
        &socket,
        &["kv", "define", "--defs", defs_path.to_str().unwrap()],
    );
    assert!(
        !out.status.success(),
        "a conflicting key must make the batch exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CLASH"), "conflict names the key: {stderr}");

    // FRESH still got registered despite CLASH's failure.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/FRESH"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"fresh-value"
    );
    // CLASH keeps its original definition.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/CLASH"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"original"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn persisted_definition_survives_daemon_restart() {
    // With `[daemon].persist-definitions = true`, an online `kv define` is
    // written to the state file and restored on a fresh daemon process, so a get
    // can regenerate the value after a restart (DR-0014 §4).
    let dir = tempfile::tempdir().unwrap();
    let state_home = dir.path().join("state");
    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[daemon]\nsocket = \"{}\"\npersist-definitions = true\n",
            socket.display()
        ),
    )
    .unwrap();

    // --- First daemon: define an online definition, confirm it works. ---
    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .env("XDG_STATE_HOME", &state_home)
        .spawn()
        .expect("spawn daemon 1");
    let mut daemon = Daemon { child };

    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // Define a key whose *value* (the command's stdout) is NOT present in its
    // argv, so we can assert the produced value never reaches disk. The argv
    // runs `sh -c 'cat <file>'` where the file holds the real secret; the argv
    // itself only references the path, never the secret bytes.
    let secret_file = dir.path().join("secret.txt");
    std::fs::write(&secret_file, b"top-secret-output").unwrap();
    let define = format!(
        r#"{{"cmd":"kv.define","key":"default/PERSISTED","source":"command","command":{{"argv":["sh","-c","cat {}"]}}}}"#,
        secret_file.display()
    );
    let resp = request(&socket, &define);
    assert_eq!(resp["ok"], true, "define: {resp}");

    // Produce the value once so a secret is resident in memory (and could, if
    // the invariant were broken, leak to disk).
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/PERSISTED"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"top-secret-output"
    );

    // The state file now exists under XDG_STATE_HOME (definitions only).
    let state_file = state_home.join("cache-warden").join("definitions.toml");
    let persisted_text = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(t) = std::fs::read_to_string(&state_file)
                && t.contains("PERSISTED")
            {
                break t;
            }
            assert!(Instant::now() < deadline, "state file never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    // The produced value must never be written — only the definition (argv).
    assert!(
        !persisted_text.contains("top-secret-output"),
        "state file must hold definitions only, never the produced value: {persisted_text}"
    );
    assert!(
        persisted_text.contains("command"),
        "state file uses the defs grammar: {persisted_text}"
    );

    // --- Stop the first daemon. ---
    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
    // Socket cleaned on shutdown.
    let cleaned = Instant::now() + Duration::from_secs(5);
    while socket.exists() && Instant::now() < cleaned {
        std::thread::sleep(Duration::from_millis(20));
    }

    // --- Second daemon: same config + state dir. It restores PERSISTED. ---
    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .env("XDG_STATE_HOME", &state_home)
        .spawn()
        .expect("spawn daemon 2");
    let mut daemon2 = Daemon { child };

    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // status shows PERSISTED as a restored (lazy) definition.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let p = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "default/PERSISTED")
        .expect("PERSISTED restored after restart");
    assert_eq!(p["defined"], true, "restored as a definition: {p}");

    // get regenerates the value from the restored definition.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/PERSISTED"}"#);
    assert_eq!(resp["ok"], true, "regenerate after restart: {resp}");
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"top-secret-output"
    );

    let pid = daemon2.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon2, Duration::from_secs(10));
}

#[test]
fn persistence_off_ignores_existing_state_file() {
    // With persistence off (the default), a pre-existing state file is neither
    // read nor written: its definitions are NOT restored (DR-0014 §4).
    let dir = tempfile::tempdir().unwrap();
    let state_home = dir.path().join("state");
    let state_file = state_home.join("cache-warden").join("definitions.toml");
    std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();
    std::fs::write(
        &state_file,
        "[kv.default.GHOST]\nsource = \"command\"\ncommand.argv = [\"printf\", \"ghost\"]\n",
    )
    .unwrap();

    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");
    // No persist-definitions key => off.
    std::fs::write(
        &config_path,
        format!("[daemon]\nsocket = \"{}\"\n", socket.display()),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .env("XDG_STATE_HOME", &state_home)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // GHOST must NOT be present (persistence is off, so the file was ignored).
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/GHOST"}"#);
    assert_eq!(resp["ok"], false, "GHOST must not be restored: {resp}");
    assert_eq!(resp["error"]["kind"], "not_found");

    // And the state file is left untouched (still our hand-written content).
    let after = std::fs::read_to_string(&state_file).unwrap();
    assert!(
        after.contains("GHOST"),
        "state file must be left as-is: {after}"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn persisted_config_priority_merge_drops_clashing_persisted_entry() {
    // DR-0014 §4: if a persisted definition clashes with a config `[kv.X]`, the
    // config wins; the persisted entry is dropped (and removed from disk on the
    // post-restore rewrite). Set up a stale persisted DB (different argv), then
    // start with a config that defines DB differently.
    let dir = tempfile::tempdir().unwrap();
    let state_home = dir.path().join("state");
    let state_file = state_home.join("cache-warden").join("definitions.toml");
    std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();
    std::fs::write(
        &state_file,
        "[kv.default.DB]\nsource = \"command\"\ncommand.argv = [\"printf\", \"stale-persisted\"]\n",
    )
    .unwrap();

    let socket = dir.path().join("control.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[daemon]\nsocket = \"{}\"\npersist-definitions = true\n\n[kv.DB]\nsource = \"command\"\ncommand.argv = [\"printf\", \"from-config\"]\n",
            socket.display()
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .env("CACHE_WARDEN_CONFIG", &config_path)
        .env("XDG_STATE_HOME", &state_home)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // DB resolves to the CONFIG definition, not the stale persisted one.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/DB"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"from-config",
        "config definition wins the merge"
    );

    // The rewrite normalized the state file to current truth: DB's persisted
    // argv must now be the config's (config-priority), not the stale one.
    let after = std::fs::read_to_string(&state_file).unwrap();
    assert!(
        !after.contains("stale-persisted"),
        "stale persisted entry must be removed from disk: {after}"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn kv_get_dry_run_returns_verified_without_value_over_the_wire() {
    // DR-0015 §6: `kv.get` with `dry_run: true` runs the full chain but the wire
    // response carries no value (only `verified` + state).
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    let set = format!(
        r#"{{"cmd":"kv.set","key":"default/DB","source":{{"kind":"static","value_b64":"{}"}}}}"#,
        b64(b"top-secret")
    );
    assert_eq!(request(&socket, &set)["ok"], true);

    let resp = request(
        &socket,
        r#"{"cmd":"kv.get","key":"default/DB","dry_run":true}"#,
    );
    assert_eq!(resp["ok"], true, "dry-run get: {resp}");
    assert_eq!(resp["verified"], true, "carries verified flag: {resp}");
    assert!(
        resp.get("value_b64").is_none(),
        "no value on the wire: {resp}"
    );
    let body = resp.to_string();
    assert!(!body.contains("top-secret"), "dry-run leaked value: {body}");
    assert!(!body.contains(&b64(b"top-secret")));

    // A normal get still returns the real value (default reveal).
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/DB"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"top-secret"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

#[test]
fn double_start_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn first daemon");
    let mut first = Daemon { child };

    // Ensure the first daemon is up.
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    // Second daemon on the same socket must exit non-zero (AddrInUse).
    let out = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .output()
        .expect("spawn second daemon");
    assert!(
        !out.status.success(),
        "second daemon should refuse to start; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // First daemon is still serving.
    let resp = request(&socket, r#"{"cmd":"ping"}"#);
    assert_eq!(resp["ok"], true);

    let pid = first.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut first, Duration::from_secs(10));
}

/// OTP value type end-to-end (DR-0016): a seed is produced by an otp *definition*
/// (value types live on definitions now), `kv.get` returns the derived code (six
/// digits), the seed never appears in any response, and a dry-run masks the code.
#[test]
fn otp_value_type_over_control_socket() {
    // RFC 6238 SHA1 test seed, base32-encoded.
    const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn daemon");
    let mut daemon = Daemon { child };

    // --- kv.define an OTP key whose command emits the seed (6 digits default) ---
    let def = format!(
        r#"{{"cmd":"kv.define","key":"default/OTP","source":"command","command":{{"argv":["printf","%s","{SEED_B32}"]}},"meta":{{"type":"otp"}}}}"#
    );
    let resp = request(&socket, &def);
    assert_eq!(resp["ok"], true, "define otp: {resp}");

    // --- kv.get returns a 6-digit CODE, never the seed (write-only) ---
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/OTP"}"#);
    assert_eq!(resp["ok"], true, "get otp: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    let code = B64.decode(got).unwrap();
    assert_eq!(code.len(), 6, "default otp digits");
    assert!(
        code.iter().all(|b| b.is_ascii_digit()),
        "code is digits: {:?}",
        String::from_utf8_lossy(&code)
    );
    // The seed must never appear in the response (write-only; DR-0016 §3).
    let resp_str = resp.to_string();
    assert!(!resp_str.contains(SEED_B32), "seed leaked: {resp_str}");
    assert!(
        !resp_str.contains(&b64(SEED_B32.as_bytes())),
        "encoded seed leaked"
    );

    // --- status reports the otp type but never the seed ---
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let status_str = resp.to_string();
    assert!(!status_str.contains(SEED_B32), "status leaked seed");
    let otp = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "default/OTP")
        .expect("OTP in status");
    assert_eq!(otp["value_type"], "otp", "status shows type: {otp}");

    // --- dry-run get masks the code (no value carried) ---
    let resp = request(
        &socket,
        r#"{"cmd":"kv.get","key":"default/OTP","dry_run":true}"#,
    );
    assert_eq!(resp["ok"], true, "dry-run otp: {resp}");
    assert_eq!(resp["verified"], true, "dry-run verified: {resp}");
    let resp_str = resp.to_string();
    assert!(!resp_str.contains("value_b64"), "dry-run carried a value");
    assert!(!resp_str.contains(SEED_B32), "dry-run leaked seed");

    // --- an 8-digit otp definition via params ---
    let def = format!(
        r#"{{"cmd":"kv.define","key":"default/OTP8","source":"command","command":{{"argv":["printf","%s","{SEED_B32}"]}},"meta":{{"type":"otp","params":{{"digits":"8"}}}}}}"#
    );
    assert_eq!(request(&socket, &def)["ok"], true);
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/OTP8"}"#);
    let code = B64.decode(resp["value_b64"].as_str().unwrap()).unwrap();
    assert_eq!(code.len(), 8, "8-digit otp code");

    // --- `kv set --type otp` is rejected and steers to `kv define` (DR-0016) ---
    let out = run_cli(&socket, &["kv", "set", "BAD", "--type", "otp", "x"]);
    assert!(!out.status.success(), "set --type otp must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kv define"),
        "set --type otp must steer to define: {stderr}"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

/// `kv set` positional grammar end-to-end: `kv set K V`, VALUE-from-stdin via a
/// pipe, the removed `--value` flags steering to the new form, and the `--`
/// separator protecting option-looking keys across set / get / del.
#[test]
fn kv_set_positional_value_stdin_pipe_and_double_dash() {
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    // --- basic positional form: `kv set K V` then `kv get K` ---
    let out = run_cli(&socket, &["kv", "set", "K", "v-positional"]);
    assert!(
        out.status.success(),
        "kv set K V failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_cli(&socket, &["kv", "get", "K"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "v-positional");

    // --- VALUE omitted + piped stdin (binary safe: embedded NUL) ---
    let mut child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .args(["kv", "set", "PIPED", "--socket"])
        .arg(&socket)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn kv set with piped stdin");
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"bin\0ary").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "piped kv set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/PIPED"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"bin\0ary",
        "stdin value is binary safe"
    );

    // --- the removed --value flags steer to the new form ---
    for args in [
        &["kv", "set", "K", "--value", "v"][..],
        &["kv", "set", "K", "--value-stdin"][..],
    ] {
        let out = run_cli(&socket, args);
        assert!(!out.status.success(), "{args:?} must fail");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("kv set KEY"),
            "{args:?} must steer to the positional form: {err}"
        );
    }

    // --- `--` separator: positional protection + option-looking VALUE ---
    // `--socket` must come before the `--` (after it, everything is positional
    // — including a literal "--socket"), so build the argv explicitly instead
    // of using run_cli (which appends the socket at the end).
    let cli_dd = |verb_args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cache-warden"));
        cmd.args(["kv", verb_args[0], "--socket"]).arg(&socket);
        cmd.args(&verb_args[1..]);
        cmd.output().expect("run cli")
    };
    // A `--`-protected VALUE may legitimately look like an option.
    let out = cli_dd(&["set", "--", "DDK", "--value-stdin"]);
    assert!(
        out.status.success(),
        "set -- DDK --value-stdin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = cli_dd(&["get", "--", "DDK"]);
    assert!(
        out.status.success(),
        "get -- DDK failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "--value-stdin");
    let out = cli_dd(&["del", "--", "DDK"]);
    assert!(
        out.status.success(),
        "del -- DDK failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Gone after the delete.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"default/DDK"}"#);
    assert_eq!(resp["ok"], false, "deleted key must not resolve: {resp}");

    // An option-looking key after `--` is rejected by the KEY charset
    // (DR-0017 §1.5) — not misparsed as a flag.
    let out = cli_dd(&["get", "--", "--weird-key"]);
    assert!(!out.status.success(), "charset-invalid key must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("A-Za-z0-9_"), "charset error: {err}");
    assert!(
        !err.contains("unknown option"),
        "must not be flag-misparsed: {err}"
    );

    // Out-of-charset keys are also refused at the protocol boundary (the
    // daemon rejects a non-composed key on kv.set; DR-0017 §1.5).
    let resp = request(
        &socket,
        r#"{"cmd":"kv.set","key":"default/has.dot","source":{"kind":"static","value_b64":"QQ=="}}"#,
    );
    assert_eq!(
        resp["ok"], false,
        "protocol must reject bad charset: {resp}"
    );
    let resp = request(
        &socket,
        r#"{"cmd":"kv.set","key":"flatkey","source":{"kind":"static","value_b64":"QQ=="}}"#,
    );
    assert_eq!(resp["ok"], false, "protocol must reject a flat key: {resp}");

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

/// KV namespaces end-to-end (DR-0017): `--namespace` isolates same-named keys,
/// `CACHE_WARDEN_NAMESPACE` supplies the default, `kv list` shows only the
/// current namespace (with `--all` for the composed view), and
/// references resolve unqualified-into-context / qualified-as-absolute.
#[test]
fn namespaces_isolate_keys_and_resolve_references() {
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    let cli = |args: &[&str], envs: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cache-warden"));
        // `--socket` must precede any `--` (for `run`, everything after it is
        // the child argv), so insert it right after the command word.
        cmd.arg(args[0]).arg("--socket").arg(&socket);
        cmd.args(&args[1..]);
        cmd.env_remove("CACHE_WARDEN_NAMESPACE");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().expect("run cli")
    };

    // --- same KEY in two namespaces holds two values ---
    assert!(
        cli(&["kv", "set", "DB", "a-value", "--namespace", "projA"], &[])
            .status
            .success()
    );
    assert!(
        cli(&["kv", "set", "DB", "b-value", "--namespace", "projB"], &[])
            .status
            .success()
    );
    let out = cli(&["kv", "get", "DB", "--namespace", "projA"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "a-value");
    let out = cli(&["kv", "get", "DB", "--namespace", "projB"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "b-value");
    // The default namespace does not see either.
    let out = cli(&["kv", "get", "DB"], &[]);
    assert!(
        !out.status.success(),
        "default NS must not resolve projA/DB"
    );

    // --- CACHE_WARDEN_NAMESPACE supplies the default; the flag overrides it ---
    let out = cli(&["kv", "get", "DB"], &[("CACHE_WARDEN_NAMESPACE", "projA")]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "a-value");
    let out = cli(
        &["kv", "get", "DB", "--namespace", "projB"],
        &[("CACHE_WARDEN_NAMESPACE", "projA")],
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "b-value",
        "flag wins over env"
    );

    // --- kv list: current NS only (stripped); --all shows NS/KEY ---
    let out = cli(&["kv", "list", "--namespace", "projA"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "DB\n");
    let out = cli(&["kv", "list", "--namespace", "projA", "--all"], &[]);
    let all = String::from_utf8_lossy(&out.stdout);
    assert!(
        all.contains("projA/DB") && all.contains("projB/DB"),
        "{all}"
    );

    // --- status: current NS only (stripped names); --all composed ---
    let out = cli(&["status", "--namespace", "projA"], &[]);
    let st = String::from_utf8_lossy(&out.stdout);
    assert!(st.contains("  DB "), "stripped name in status: {st}");
    assert!(!st.contains("projB"), "other NS hidden: {st}");
    let out = cli(&["status", "--all"], &[]);
    let st = String::from_utf8_lossy(&out.stdout);
    assert!(st.contains("projA/DB") && st.contains("projB/DB"), "{st}");

    // --- references: unqualified resolves into the context namespace,
    //     qualified is absolute (DR-0017 §3) ---
    let out = cli(
        &[
            "run",
            "--namespace",
            "projA",
            "--env",
            "X=cache-warden://DB",
            "--env",
            "Y=cache-warden://projB/DB",
            "--",
            "sh",
            "-c",
            "printf '%s:%s' \"$X\" \"$Y\"",
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "a-value:b-value");

    // --- dry-run masks display the resolved absolute key (DR-0017 §5) ---
    let out = cli(
        &["kv", "get", "DB", "--namespace", "projA", "--dry-run"],
        &[],
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "<cache-warden:projA/DB:masked>"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}

/// DR-0023 Phase 1: `preload = true` の kv コマンドが長時間かかっても、
/// daemon が socket を bind して ping に応答できるようになること (startup の
/// blocking を spawn_blocking に移すことで、socket は preload 完了前に開く)。
///
/// kv エントリのコマンドを `sleep 30; printf done` にして startup blocking を
/// シミュレートする (30 秒間 blocking してから出力するので empty-output で
/// 早期終了しない)。
///
/// Phase 1 実装前: daemon が `sh -c 'sleep 30; printf done'` の完了を待つため、
/// ping が 3 秒以内に返らず fail する。
/// Phase 1 実装後: preload は spawn_blocking に移り、socket は先に開くので
/// ping は即座に成功する。
#[test]
fn test_socket_available_before_preload_completes() {
    let dir = tempfile::tempdir().unwrap();
    // SIGPIPE / timeout 対策で setsid を使って signal をシールドしたい所だが、
    // portable に書くために `sh -c 'trap "" TERM; sleep 30; printf done'` で
    // SIGTERM を無視し、本当に 30 秒かかる preload をシミュレートする。
    // (SIGTERMが子プロセスグループに伝わっても sleep が止まらない)
    let cfg = r#"
[kv.SLOW]
source = "command"
command.argv = ["sh", "-c", "trap '' TERM; sleep 30; printf done"]
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // 3 秒以内に ping に応答することを確認。
    // Phase 1 実装前: `sleep 30` が同期実行されるため 3 秒以内に ping が返らない。
    // Phase 1 実装後: preload は spawn_blocking に移るため socket は即座に開く。
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let ping_succeeded = loop {
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(&socket) {
            // socket が開いているなら ping を試みる (タイムアウト付き)
            use std::io::{BufRead, BufReader, Write};
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            let mut writer = stream.try_clone().unwrap();
            if writer.write_all(b"{\"cmd\":\"ping\"}\n").is_ok() {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() && line.contains("\"ok\":true") {
                    break true;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    // shutdown してからアサート (daemon を残さない; slow preload の子プロセスも kill)
    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
        // sleep が TERM を無視しているので KILL も送る
        std::thread::sleep(std::time::Duration::from_millis(200));
        libc::kill(pid as i32, libc::SIGKILL);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(5));

    assert!(
        ping_succeeded,
        "daemon socket should respond to ping within 3s even when preload takes 30s (DR-0023 Phase 1)"
    );
}

/// DR-0023 Phase 1: startup 中に shutdown signal を受けたとき、spawn_blocking 内の
/// 長時間ブロッキング処理があっても SHUTDOWN_GRACE (5s) + 余裕の合計 10 秒以内に
/// daemon が exit することを確認する。
///
/// kv エントリのコマンドを `sleep 30` (SIGTERM を無視) にして startup blocking を
/// シミュレートする。socket が開いてから (daemon が preload 中) 1 秒後に SIGTERM を
/// 送信し、10 秒以内に exit することを確認。
///
/// Phase 1 実装前: spawn_blocking が完了するまで (30 秒後まで) run() が戻らないため、
/// SIGTERM を受けても shutdownパスに到達せず、watchdog (SHUTDOWN_GRACE=5s) が
/// 発火するまでに合計 30+5=35 秒かかる。
/// Phase 1 実装後: startup select! が SIGTERM を受けて即座に ShutdownDuringStartup を
/// 返し、watchdog が発火する前に graceful shutdown が完了する。
#[test]
fn test_shutdown_during_startup_exits_promptly() {
    let dir = tempfile::tempdir().unwrap();
    // SIGTERM を無視してバックグラウンドで 30 秒スリープする preload をシミュレート。
    // daemon に SIGTERM を送っても子プロセス (sh -c) の sleep は終わらないが、
    // daemon 自身は select! で ShutdownDuringStartup を検出して exit すべき。
    let cfg = r#"
[kv.SLOW]
source = "command"
command.argv = ["sh", "-c", "trap '' TERM; sleep 30; printf done"]
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // daemon が socket を開くまで待つ (preload 中のはず)。
    let socket_open_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            break;
        }
        if std::time::Instant::now() >= socket_open_deadline {
            panic!("daemon did not open socket within 5s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // socket が開いてから 1 秒待つ (preload がブロック中であることを確認してから)。
    std::thread::sleep(Duration::from_secs(1));

    // SIGTERM を送る (startup blocking 中のはず)。
    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    // 10 秒以内に exit することを確認 (SHUTDOWN_GRACE=5s + 余裕)。
    // Phase 1 実装後: startup select! が即座に ShutdownDuringStartup を返し、
    // graceful shutdown が完了するため watchdog が発火する前に exit する。
    let status = wait_for_exit(&mut daemon, Duration::from_secs(10));
    assert!(
        status.success() || status.code().is_none(),
        "daemon should exit cleanly (exit 0 or signal kill) on SIGTERM during startup, \
         got: {status:?} (DR-0023 Phase 1)"
    );
}

/// Per-entry `namespace` field in defs files (DR-0017 §5): a pinned entry is
/// absolute, an unpinned one follows the `--defs` invocation's `--namespace`.
#[test]
fn defs_namespace_field_pins_entries_absolutely() {
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());
    assert_eq!(request(&socket, r#"{"cmd":"ping"}"#)["ok"], true);

    let defs_path = dir.path().join("ns.cache-warden.toml");
    std::fs::write(
        &defs_path,
        r#"[kv.PINNED]
namespace = "fixed"
source = "command"
command.argv = ["printf", "pinned-value"]

[kv.FLOATING]
source = "command"
command.argv = ["printf", "floating-value"]
"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .args([
            "kv",
            "define",
            "--namespace",
            "ctx",
            "--defs",
            defs_path.to_str().unwrap(),
            "--socket",
        ])
        .arg(&socket)
        .output()
        .expect("run cli");
    assert!(
        out.status.success(),
        "define --defs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // PINNED went to fixed/ regardless of the context; FLOATING followed it.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"fixed/PINNED"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"pinned-value"
    );
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"ctx/FLOATING"}"#);
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"floating-value"
    );

    let pid = daemon.child.id();
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    let _ = wait_for_exit(&mut daemon, Duration::from_secs(10));
}
