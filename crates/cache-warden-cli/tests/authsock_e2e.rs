//! End-to-end test for the authsock adapter (port plan Iteration 1).
//!
//! Exercises the whole stack the way an SSH client does: generate a real
//! Ed25519 key with `ssh-keygen`, preload its PEM into the core KV via a config
//! `command` source, start the daemon with an `[authsock.sockets.*]` agent
//! socket, then:
//!
//! 1. `SSH_AUTH_SOCK=<sock> ssh-add -l` lists the public key (REQUEST_IDENTITIES).
//! 2. A raw SIGN_REQUEST over the agent wire returns a signature that verifies
//!    against the public key (the signing path — the other half of the milestone).
//! 3. With a denying `[auth].command`, a soft-expired key's SIGN_REQUEST returns
//!    SSH_AGENT_FAILURE and no secret leaks.
//!
//! `ssh-keygen` / `ssh-add` are assumed present (they ship on GitHub Actions
//! Linux and macOS runners). If absent, the test fails loudly rather than
//! silently skipping, so a missing tool is visible in CI.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// A spawned daemon that is killed on drop.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Generate an Ed25519 key pair at `path`, returning the public-key OpenSSH line.
fn ssh_keygen_ed25519(path: &Path, comment: &str) -> String {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", comment, "-q", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen must be installed on this runner");
    assert!(status.success(), "ssh-keygen failed");
    let pub_path = path.with_extension("pub");
    std::fs::read_to_string(&pub_path)
        .expect("read .pub")
        .trim()
        .to_string()
}

/// Wait until `socket` accepts a connection (the daemon has bound it).
fn wait_for_socket(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(5);
    loop {
        if UnixStream::connect(socket).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "agent socket never became reachable at {}",
                socket.display()
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(200));
    }
}

/// Run `ssh-add -l` against the agent socket, returning combined stdout.
fn ssh_add_list(socket: &Path) -> (bool, String) {
    let out = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", socket)
        .output()
        .expect("ssh-add must be installed on this runner");
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

// ---- minimal SSH agent wire helpers (no dependency on the crate internals) ----

fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Send one agent message (type + payload) framed with a 4-byte length prefix,
/// read one framed response, and return `(type, payload)`.
fn agent_round_trip(socket: &Path, msg_type: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    let mut stream = UnixStream::connect(socket).expect("connect agent socket");
    let body_len = 1 + payload.len();
    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&(body_len as u32).to_be_bytes());
    frame.push(msg_type);
    frame.extend_from_slice(payload);
    stream.write_all(&frame).expect("write request");
    stream.flush().expect("flush");

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read length");
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read body");
    let resp_type = body[0];
    (resp_type, body[1..].to_vec())
}

/// Wire blob of an OpenSSH public-key line: `string(keytype) + key fields`.
fn public_key_blob(pub_openssh: &str) -> Vec<u8> {
    use ssh_encoding::Encode;
    let pk = ssh_key::PublicKey::from_openssh(pub_openssh).expect("parse public key");
    let mut blob = Vec::new();
    pk.key_data().encode(&mut blob).expect("encode blob");
    blob
}

const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_FAILURE: u8 = 5;

/// Build a config file content for an authsock socket whose single key is the
/// PEM at `key_path` (loaded via a `cat` command source). `auth_cmd` is an
/// optional `[auth].command` argv element (e.g. "false" to deny).
fn config_content(
    sock_path: &Path,
    key_path: &Path,
    soft_ttl: Option<&str>,
    auth_false: bool,
) -> String {
    let mut s = String::new();
    if auth_false {
        s.push_str("[auth]\ncommand = [\"false\"]\n\n");
    }
    s.push_str("[kv.GITHUB_KEY]\n");
    s.push_str(&format!(
        "command = [\"cat\", \"{}\"]\n",
        key_path.display()
    ));
    if let Some(t) = soft_ttl {
        s.push_str(&format!("soft-ttl = \"{t}\"\n"));
    }
    s.push('\n');
    s.push_str("[authsock.sockets.default]\n");
    s.push_str(&format!("path = \"{}\"\n", sock_path.display()));
    s.push_str("keys = [\"GITHUB_KEY\"]\n");
    s
}

/// Spawn the daemon with `config_path`; returns (Daemon, control socket path).
fn spawn_daemon(dir: &Path, config_path: &Path) -> (Daemon, PathBuf) {
    let control = dir.join("control.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&control)
        .env("CACHE_WARDEN_CONFIG", config_path)
        .spawn()
        .expect("spawn daemon");
    (Daemon { child }, control)
}

#[test]
fn ssh_add_lists_key_and_sign_request_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let pub_line = ssh_keygen_ed25519(&key_path, "e2e-key");

    let agent_sock = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        config_content(&agent_sock, &key_path, None, false),
    )
    .unwrap();

    let (_daemon, _control) = spawn_daemon(dir.path(), &config_path);
    wait_for_socket(&agent_sock);

    // --- (1) REQUEST_IDENTITIES via ssh-add -l ---
    let (ok, listing) = ssh_add_list(&agent_sock);
    assert!(ok, "ssh-add -l failed: {listing}");
    // ssh-add -l prints the fingerprint + comment; the comment must appear.
    assert!(
        listing.contains("e2e-key"),
        "ssh-add -l should list the key comment, got: {listing}"
    );

    // --- (2) SIGN_REQUEST over the raw agent wire, then verify ---
    let blob = public_key_blob(&pub_line);
    let data = b"end-to-end signing challenge";
    let mut payload = Vec::new();
    put_string(&mut payload, &blob);
    put_string(&mut payload, data);
    payload.extend_from_slice(&0u32.to_be_bytes()); // flags = 0
    let (resp_type, resp_payload) =
        agent_round_trip(&agent_sock, SSH_AGENTC_SIGN_REQUEST, &payload);
    assert_eq!(
        resp_type, SSH_AGENT_SIGN_RESPONSE,
        "expected SIGN_RESPONSE, got type {resp_type}"
    );

    // resp_payload = string(signature_blob); parse and verify it.
    let sig_len = u32::from_be_bytes(resp_payload[..4].try_into().unwrap()) as usize;
    let sig_blob = &resp_payload[4..4 + sig_len];
    let sig = ssh_key::Signature::try_from(sig_blob).expect("parse signature");
    let pk = ssh_key::PublicKey::from_openssh(&pub_line).unwrap();
    <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
        .expect("agent signature must verify against the public key");
}

#[test]
fn denied_reauth_returns_failure_without_leaking_secret() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let pub_line = ssh_keygen_ed25519(&key_path, "deny-key");

    let agent_sock = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    // soft-ttl = 1s so the key soft-expires quickly; [auth].command = ["false"]
    // means any re-auth is denied.
    std::fs::write(
        &config_path,
        config_content(&agent_sock, &key_path, Some("1s"), true),
    )
    .unwrap();

    let (_daemon, _control) = spawn_daemon(dir.path(), &config_path);
    wait_for_socket(&agent_sock);

    // Let the soft TTL lapse so the next sign needs (denied) re-auth.
    std::thread::sleep(Duration::from_millis(1500));

    let blob = public_key_blob(&pub_line);
    let data = b"challenge after soft expiry";
    let mut payload = Vec::new();
    put_string(&mut payload, &blob);
    put_string(&mut payload, data);
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (resp_type, resp_payload) =
        agent_round_trip(&agent_sock, SSH_AGENTC_SIGN_REQUEST, &payload);

    assert_eq!(
        resp_type, SSH_AGENT_FAILURE,
        "denied re-auth must yield SSH_AGENT_FAILURE, got type {resp_type}"
    );
    assert!(
        resp_payload.is_empty(),
        "FAILURE must carry no payload (no secret/detail leak)"
    );
}
