//! End-to-end tests for the encrypted vault (DR-0034 §5/§6/§11).
//!
//! These exercise the property the vault exists for: a credential
//! cache-warden owns outlives the process holding it, and stays unreadable
//! until someone opens the vault again. That claim only means anything across
//! a real restart, so every test here drives the real binary over a real
//! control socket and speaks the JSON Lines wire directly, following
//! `tests/e2e.rs`'s conventions (bounded-backoff connect rather than a sleep,
//! since the daemon binds asynchronously — DR-0023).
//!
//! Every daemon here is pinned to a config in a temp directory whose
//! `[vault] path` points inside that same directory. Nothing touches the
//! developer's real state directory or the launchd daemon.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// A spawned daemon, killed on drop.
struct Daemon {
    child: Child,
}

impl Daemon {
    /// Stop the daemon the way a crash or a reboot would: no chance to hand
    /// anything over. This is what makes the vault's job observable — a
    /// cooperative shutdown could have preserved state some other way.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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

/// Poll `ping` until the daemon answers. Used after every spawn: the listener
/// is bound from an async task, so "the process started" is not "the socket
/// works" (DR-0023).
fn wait_for_ping(socket: &Path) {
    let end = Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(5);
    loop {
        if let Some(resp) = request_allow_close(socket, r#"{"cmd":"ping"}"#)
            && resp["ok"] == true
        {
            return;
        }
        if Instant::now() >= end {
            panic!("daemon at {} never answered ping", socket.display());
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(200));
    }
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// The test's own patch of the world: a socket, a config and a vault file that
/// all live inside one temp directory.
struct Fixture {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    config: PathBuf,
}

impl Fixture {
    /// `extra` is appended to the generated config, for tests that need a
    /// `[kv.*]` declaration.
    fn new(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let config = dir.path().join("config.toml");
        let vault = dir.path().join("vault.cwv");
        std::fs::write(
            &config,
            format!("[vault]\npath = {:?}\n{extra}", vault.display().to_string()),
        )
        .expect("write config");
        Fixture {
            _dir: dir,
            socket,
            config,
        }
    }

    /// Start a daemon against this fixture and wait until it answers.
    fn spawn(&self) -> Daemon {
        let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
            .arg("daemon")
            .arg("run")
            .arg("--socket")
            .arg(&self.socket)
            .env("CACHE_WARDEN_CONFIG", &self.config)
            .spawn()
            .expect("spawn daemon");
        let daemon = Daemon { child };
        wait_for_ping(&self.socket);
        daemon
    }

    fn request(&self, line: &str) -> serde_json::Value {
        request(&self.socket, line)
    }

    /// Create the vault and return its recovery code — the only key material
    /// in these tests, and the reason they need no passkey ceremony.
    fn init_vault(&self) -> String {
        let resp = self.request(r#"{"cmd":"vault.init"}"#);
        assert_eq!(resp["ok"], true, "vault.init: {resp}");
        resp["recovery_code"]
            .as_str()
            .expect("a recovery code")
            .to_string()
    }

    fn set_persisted(&self, key: &str, value: &[u8]) -> serde_json::Value {
        self.request(&format!(
            r#"{{"cmd":"kv.set","key":"{key}","source":{{"kind":"static","value_b64":"{}"}},"persist":true}}"#,
            b64(value)
        ))
    }

    fn get(&self, key: &str) -> serde_json::Value {
        self.request(&format!(r#"{{"cmd":"kv.get","key":"{key}"}}"#))
    }

    fn unlock(&self, code: &str) -> serde_json::Value {
        self.request(&format!(
            r#"{{"cmd":"vault.unlock","recovery_code":"{code}"}}"#
        ))
    }
}

fn value_of(resp: &serde_json::Value) -> Vec<u8> {
    assert_eq!(resp["ok"], true, "expected a value: {resp}");
    B64.decode(resp["value_b64"].as_str().expect("value_b64"))
        .unwrap()
}

fn err_kind(resp: &serde_json::Value) -> String {
    assert_eq!(resp["ok"], false, "expected an error: {resp}");
    resp["error"]["kind"].as_str().expect("kind").to_string()
}

/// Find one entry in a `status` / `kv.list` reply.
fn entry<'a>(resp: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    resp["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("no entries array: {resp}"))
        .iter()
        .find(|e| e["key"] == key || e["name"] == key)
        .unwrap_or_else(|| panic!("no entry {key} in {resp}"))
}

/// Whether an entry reports itself as behind a closed vault.
///
/// The field is omitted rather than serialized as `false` (its
/// `skip_serializing_if`), so "absent" and "not locked" are the same answer.
fn is_locked(entry: &serde_json::Value) -> bool {
    entry["locked"].as_bool().unwrap_or(false)
}

/// A configuration-declared persistent entry.
///
/// The `source` is not optional: the configuration will not accept a `[kv.*]`
/// entry without one, and `persist` rules out `op` (DR-0034 §5), so a declared
/// persistent entry always names a command. That command is how the credential
/// is *first* acquired; once a value exists, the vault owns it. The tests below
/// use a command whose output is unmistakable, so any answer that came from
/// running it instead of from the vault is visible on sight.
const DECLARED_PERSISTENT: &str =
    "[kv.RT]\nsource = \"command\"\ncommand.argv = [\"printf\", \"regenerated\"]\npersist = true\n";

/// The whole point of the vault, end to end (DR-0034 §5/§6): a value
/// cache-warden owns survives a process that dies without warning, comes back
/// visible-but-closed, and is readable again after an unlock — with its
/// version intact, so a writer that slept through the restart still loses the
/// compare-and-swap it should lose.
#[test]
fn a_persisted_value_survives_a_crash_and_returns_on_unlock() {
    let fx = Fixture::new(DECLARED_PERSISTENT);
    let mut daemon = fx.spawn();
    let code = fx.init_vault();

    assert_eq!(
        fx.set_persisted("default/RT", b"refresh-token-1")["ok"],
        true
    );
    assert_eq!(value_of(&fx.get("default/RT")), b"refresh-token-1");
    let version_before = entry(&fx.request(r#"{"cmd":"status"}"#), "default/RT")["version"]
        .as_u64()
        .expect("a version");

    // No graceful anything: the process is destroyed.
    daemon.kill();
    let _daemon = fx.spawn();

    // Closed, but not silent. The entry is declared in the config, so it is
    // still listed — with `locked` saying why its value is unavailable.
    let status = fx.request(r#"{"cmd":"status"}"#);
    assert_eq!(
        status["vault"]["state"], "locked",
        "a cold start must not carry the data key over: {status}"
    );
    assert!(is_locked(entry(&status, "default/RT")), "{status}");
    assert!(is_locked(entry(
        &fx.request(r#"{"cmd":"kv.list"}"#),
        "default/RT"
    )));

    // Reading it says "locked", specifically. An OAuth client that read this
    // as an authorization failure would mint a duplicate grant (DR-0034 §6).
    assert_eq!(err_kind(&fx.get("default/RT")), "vault_locked");

    let resp = fx.unlock(&code);
    assert_eq!(resp["ok"], true, "unlock: {resp}");
    assert_eq!(resp["entries_restored"], 1, "{resp}");

    assert_eq!(value_of(&fx.get("default/RT")), b"refresh-token-1");
    assert_eq!(
        entry(&fx.request(r#"{"cmd":"status"}"#), "default/RT")["version"],
        version_before,
        "the version travels with the value, or a stale writer wins a CAS it should lose"
    );
}

/// DR-0034 §11: a graceful restart carries the data key across, because the
/// point of graceful restart is that an upgrade does not make the user
/// re-authenticate everything. Contrast with the crash above — same value,
/// same vault, opposite outcome, and that difference is the whole design.
#[cfg(target_os = "macos")]
#[test]
fn a_graceful_restart_keeps_the_vault_open() {
    let fx = Fixture::new(DECLARED_PERSISTENT);
    let _daemon = fx.spawn();
    fx.init_vault();
    assert_eq!(
        fx.set_persisted("default/RT", b"refresh-token-1")["ok"],
        true
    );

    // Either shape is fine: an ack, or the connection closing because the
    // execve beat the reply out (see `Request::RestartGraceful`).
    if let Some(resp) = request_allow_close(&fx.socket, r#"{"cmd":"daemon.restart_graceful"}"#) {
        assert_eq!(resp["ok"], true, "restart ack: {resp}");
    }
    wait_for_ping(&fx.socket);

    let status = fx.request(r#"{"cmd":"status"}"#);
    assert_eq!(
        status["vault"]["state"], "unlocked",
        "the handoff carries the data key: {status}"
    );
    assert!(!is_locked(entry(&status, "default/RT")), "{status}");
    assert_eq!(
        value_of(&fx.get("default/RT")),
        b"refresh-token-1",
        "no unlock ceremony should have been needed"
    );
}

/// DR-0034 §5: `persist` and an `op` source claim opposite things about where
/// the newest value lives. Honouring both would leave cache-warden serving a
/// stale copy of something 1Password still considers authoritative, so the
/// daemon refuses to start rather than pick one silently.
#[test]
fn persist_with_an_op_source_is_refused_at_startup() {
    let fx = Fixture::new("[kv.RT]\nsource = \"op\"\nop.uri = \"op://v/i/f\"\npersist = true\n");
    let out = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&fx.socket)
        .env("CACHE_WARDEN_CONFIG", &fx.config)
        .output()
        .expect("run daemon");
    assert!(!out.status.success(), "the daemon must not start");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("persist") && stderr.contains("source of truth"),
        "the refusal must explain the conflict, got: {stderr}"
    );
}

/// DR-0034 §4, end to end: the refresh claim is the thing that stops two
/// callers from asking the provider to rotate the same credential at once. A
/// claim that lived only in memory would be lost by exactly the crash it is
/// there for, and the successor would start the second refresh — which for a
/// provider doing reuse detection revokes the whole token family.
#[test]
fn a_refresh_claim_outlives_the_process_that_took_it() {
    let fx = Fixture::new(DECLARED_PERSISTENT);
    let mut daemon = fx.spawn();
    let code = fx.init_vault();
    assert_eq!(
        fx.set_persisted("default/RT", b"refresh-token-1")["ok"],
        true
    );

    let resp = fx.request(
        r#"{"cmd":"kv.claim","key":"default/RT","expected_version":1,"duration_secs":300}"#,
    );
    assert_eq!(resp["ok"], true, "claim: {resp}");
    let token = resp["claim_token"].as_str().expect("a token").to_string();

    daemon.kill();
    let _daemon = fx.spawn();
    assert_eq!(fx.unlock(&code)["ok"], true);

    // A second caller is still held off.
    let resp = fx.set_persisted("default/RT", b"refresh-token-2");
    assert_eq!(
        err_kind(&resp),
        "claim_token_mismatch",
        "the successor must fence against the claim the dead process took: {resp}"
    );

    // The original caller finishes with the token it was given before the crash.
    let resp = fx.request(&format!(
        r#"{{"cmd":"kv.set","key":"default/RT","source":{{"kind":"static","value_b64":"{}"}},"persist":true,"claim_token":"{token}"}}"#,
        b64(b"refresh-token-2")
    ));
    assert_eq!(
        resp["ok"], true,
        "the claim holder must be able to finish: {resp}"
    );
    assert_eq!(value_of(&fx.get("default/RT")), b"refresh-token-2");
}

/// DR-0034 §5: deleting a cache-warden-owned entry discards the credential.
/// There is no upstream to fetch it back from — cache-warden was the
/// upstream — so a later get must ask for an explicit re-acquisition instead
/// of quietly producing a replacement, and the deletion must be as durable as
/// the write was.
#[test]
fn a_discarded_credential_is_not_re_created() {
    // A command source alongside `persist` is the trap this test exists for:
    // an ordinary cached entry with this definition would regenerate happily.
    let fx = Fixture::new(DECLARED_PERSISTENT);
    let mut daemon = fx.spawn();
    let code = fx.init_vault();
    assert_eq!(
        fx.set_persisted("default/RT", b"refresh-token-1")["ok"],
        true
    );

    let resp = fx.request(r#"{"cmd":"kv.del","key":"default/RT"}"#);
    assert_eq!(resp["ok"], true, "del: {resp}");

    let resp = fx.get("default/RT");
    assert_eq!(
        err_kind(&resp),
        "not_regenerable",
        "a discarded credential must not be re-made from its definition: {resp}"
    );

    // And it stayed gone on disk: the delete was as durable as the write, so
    // unlocking a fresh process does not resurrect the discarded credential.
    //
    // What the fresh process *does* have again is this entry's configured
    // acquisition command — the configuration is re-read at every start, and
    // it is where the operator declared how this credential is first obtained
    // (DR-0034 §5's promotion path). So a get after the restart runs that
    // command and gets a new credential; what it can never do is hand back the
    // one that was thrown away.
    daemon.kill();
    let _daemon = fx.spawn();
    let resp = fx.unlock(&code);
    assert_eq!(resp["ok"], true, "unlock: {resp}");
    assert_eq!(
        resp["entries_restored"], 0,
        "the vault must have kept nothing: {resp}"
    );
    assert_eq!(
        value_of(&fx.get("default/RT")),
        b"regenerated",
        "a re-acquisition through the declared command, not the deleted value"
    );
}
