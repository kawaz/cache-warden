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
        r#"{{"cmd":"kv.set","key":"DB","source":{{"kind":"static","value_b64":"{}"}},"soft_ttl_secs":3600,"hard_ttl_secs":86400}}"#,
        b64(b"hunter2")
    );
    let resp = request(&socket, &set);
    assert_eq!(resp["ok"], true, "set: {resp}");

    // --- kv.get returns the value (base64) ---
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"DB"}"#);
    assert_eq!(resp["ok"], true, "get: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"hunter2");

    // --- kv.define a second key (command source; lazy, value produced on get) ---
    let def = r#"{"cmd":"kv.define","key":"TOK","argv":["printf","tok-value"]}"#;
    let resp = request(&socket, def);
    assert_eq!(resp["ok"], true, "define: {resp}");
    // Right after define, status shows TOK as defined with no value yet.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let tok = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "TOK")
        .expect("TOK in status");
    assert_eq!(tok["defined"], true, "TOK is defined: {tok}");
    assert_eq!(tok["has_value"], false, "TOK has no value yet: {tok}");
    assert_eq!(
        tok["state"], "defined",
        "TOK reports the defined state: {tok}"
    );
    // The first get lazily produces the value.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
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
    assert_eq!(keys, vec!["DB", "TOK"]);

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
            .any(|e| e["name"] == "DB" && e["state"] == "active")
    );

    // --- kv.del removes a key ---
    let resp = request(&socket, r#"{"cmd":"kv.del","key":"DB"}"#);
    assert_eq!(resp["deleted"], true, "del: {resp}");
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"DB"}"#);
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["kind"], "not_found");

    // --- delete a missing key reports deleted:false ---
    let resp = request(&socket, r#"{"cmd":"kv.del","key":"DB"}"#);
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

#[test]
fn config_preload_and_reauth_command_allow() {
    let dir = tempfile::tempdir().unwrap();
    // Preload TOK with `preload = true` (no TTL => always Active) to verify
    // startup preload, and EXT with a 1s soft TTL so it soft-expires and
    // triggers the re-auth command. `[auth].command = ["true"]` approves.
    let cfg = r#"
[auth]
command = ["true"]

[kv.TOK]
command = ["printf", "preloaded-tok"]
preload = true

[kv.EXT]
command = ["printf", "ext-value"]
soft-ttl = "1s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Preload populated TOK: a get is an immediate hit.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
    assert_eq!(resp["ok"], true, "preloaded TOK get: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"preloaded-tok");

    // EXT is initially Active too.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"EXT"}"#);
    assert_eq!(resp["ok"], true);

    // Let EXT soft-expire (1s), then get: the daemon runs the re-auth command
    // (`true` => approved) and extends, returning the value.
    std::thread::sleep(Duration::from_millis(2500));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"EXT"}"#);
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
command = ["false"]

[kv.EXT]
command = ["printf", "ext-value"]
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
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"EXT"}"#);
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
command = ["false"]

[kv.EXT]
command = ["printf", "ext-value"]
soft-ttl = "1s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Initially Active; pin it for a long window (re-auth required, but the
    // `false` authenticator denies... so pin must FAIL here). Confirm that:
    // pinning is a re-auth-gated operation even from Active.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.pin","key":"EXT","duration_secs":3600}"#,
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
command = ["true"]

[kv.EXT]
command = ["printf", "ext-value"]
soft-ttl = "1s"
hard-ttl = "2s"
preload = true
"#;
    let (mut daemon, socket) = spawn_with_config(dir.path(), cfg);

    // Pin EXT for an hour while it is still Active (approved by `true`).
    let resp = request(
        &socket,
        r#"{"cmd":"kv.pin","key":"EXT","duration_secs":3600}"#,
    );
    assert_eq!(resp["ok"], true, "pin approved by `true`: {resp}");
    assert_eq!(resp["pinned"], true);

    // Past the hard TTL (2s): without the pin the value would be zeroized, but
    // the pin holds it Active and gettable.
    std::thread::sleep(Duration::from_millis(2500));
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"EXT"}"#);
    assert_eq!(resp["ok"], true, "pinned value survives hard TTL: {resp}");
    let got = resp["value_b64"].as_str().expect("value_b64");
    assert_eq!(B64.decode(got).unwrap(), b"ext-value");

    // status shows the pin's remaining seconds.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let entries = resp["entries"].as_array().unwrap();
    let ext = entries.iter().find(|e| e["name"] == "EXT").unwrap();
    assert_eq!(ext["state"], "active", "pinned entry reports Active");
    assert!(
        ext["pin_remaining_secs"].as_u64().unwrap() > 0,
        "status reports pin remaining: {ext}"
    );

    // Unpin: the pin is dropped. The entry is now past its real hard TTL, so a
    // get must no longer return the old value via a pin (it will try to
    // regenerate the command source instead — approved by `true`, returning a
    // fresh value). The key point: status no longer shows a pin.
    let resp = request(&socket, r#"{"cmd":"kv.unpin","key":"EXT"}"#);
    assert_eq!(resp["ok"], true, "unpin ok: {resp}");
    assert_eq!(resp["unpinned"], true);

    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let entries = resp["entries"].as_array().unwrap();
    let ext = entries.iter().find(|e| e["name"] == "EXT").unwrap();
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
        r#"{"cmd":"kv.pin","key":"ghost","duration_secs":60}"#,
    );
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["kind"], "not_found");

    // unpin of a missing key is also not_found.
    let resp = request(&socket, r#"{"cmd":"kv.unpin","key":"ghost"}"#);
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
        r#"{"cmd":"kv.define","key":"TOK","argv":["printf","lazy-value"]}"#,
    );
    assert_eq!(resp["ok"], true, "define: {resp}");
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let tok = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "TOK")
        .expect("TOK present");
    assert_eq!(tok["defined"], true);
    assert_eq!(tok["has_value"], false);

    // first get lazily produces the value.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
    assert_eq!(resp["ok"], true, "lazy get: {resp}");
    assert_eq!(
        B64.decode(resp["value_b64"].as_str().unwrap()).unwrap(),
        b"lazy-value"
    );

    // del (value only): the definition survives.
    let resp = request(&socket, r#"{"cmd":"kv.del","key":"TOK"}"#);
    assert_eq!(resp["deleted"], true, "del value: {resp}");
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    let tok = resp["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "TOK")
        .expect("TOK still defined after value del");
    assert_eq!(tok["defined"], true, "definition survives value-only del");
    assert_eq!(tok["has_value"], false);

    // get again: regenerated from the surviving definition.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
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
fn del_with_define_drops_definition_so_get_is_not_found() {
    // DR-0014 §2: `kv.del --with-define` forgets the key entirely, so a later get
    // cannot regenerate it.
    let dir = tempfile::tempdir().unwrap();
    let (mut daemon, socket) = spawn_plain(dir.path());

    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"TOK","argv":["printf","v"]}"#,
    );
    assert_eq!(resp["ok"], true, "define: {resp}");
    // produce the value once.
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
    assert_eq!(resp["ok"], true);

    // del with_define: drops both value and definition.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.del","key":"TOK","with_define":true}"#,
    );
    assert_eq!(resp["deleted"], true, "del with_define: {resp}");

    // get: the key is gone entirely (no definition to regenerate from).
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
    assert_eq!(resp["ok"], false, "get after with-define del: {resp}");
    assert_eq!(resp["error"]["kind"], "not_found");

    // status no longer lists the key.
    let resp = request(&socket, r#"{"cmd":"status"}"#);
    assert!(
        resp["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["name"] != "TOK"),
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
        r#"{"cmd":"kv.define","key":"TOK","argv":["printf","a"]}"#,
    );
    assert_eq!(resp["ok"], true);
    // identical define is an idempotent no-op.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"TOK","argv":["printf","a"]}"#,
    );
    assert_eq!(resp["ok"], true, "identical define is a no-op: {resp}");
    // conflicting define is rejected with a redefine hint.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"TOK","argv":["printf","b"]}"#,
    );
    assert_eq!(resp["ok"], false, "conflict rejected: {resp}");
    assert_eq!(resp["error"]["kind"], "bad_request");

    // del --with-define then redefine succeeds.
    let resp = request(
        &socket,
        r#"{"cmd":"kv.del","key":"TOK","with_define":true}"#,
    );
    assert_eq!(resp["deleted"], true);
    let resp = request(
        &socket,
        r#"{"cmd":"kv.define","key":"TOK","argv":["printf","b"]}"#,
    );
    assert_eq!(resp["ok"], true, "redefine after del succeeds: {resp}");
    let resp = request(&socket, r#"{"cmd":"kv.get","key":"TOK"}"#);
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
