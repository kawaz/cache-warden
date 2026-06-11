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
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_FAILURE: u8 = 5;

/// A fake upstream agent (a minimal SSH agent over a Unix socket) used to test
/// the daemon's upstream merge / forwarding. It serves, for each connection:
///
/// - REQUEST_IDENTITIES → IDENTITIES_ANSWER advertising `pub_line`'s key.
/// - SIGN_REQUEST for that key → a fixed SIGN_RESPONSE (a sentinel blob the test
///   can recognize); any other key → FAILURE.
///
/// Runs in a background thread until `stop` is set, then exits. It is not a real
/// signer — the sentinel signature only proves the request was *forwarded* to
/// (and answered by) the upstream, which is what Iteration 2 must verify.
struct FakeUpstream {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Nudge the accept loop by connecting once so it observes `stop`.
        let _ = UnixStream::connect(&self.path);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Sentinel signature payload the fake upstream returns (so a forwarded sign is
/// distinguishable from a local one).
const UPSTREAM_SENTINEL_SIG: &[u8] = b"UPSTREAM-FORWARDED-SIGNATURE";

fn spawn_fake_upstream(pub_line: &str) -> FakeUpstream {
    // Short, collision-free path under /tmp (stays under the sockaddr_un length
    // limit on macOS; a process-wide counter avoids clashes across parallel
    // tests that bind in the same nanosecond).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let path = PathBuf::from(format!("/tmp/cw-e2e-up-{}-{seq}.sock", std::process::id()));

    let blob = public_key_blob(pub_line);
    let comment = "upstream-key".to_string();
    let _ = std::fs::remove_file(&path); // clear any stale socket from a prior run
    let listener = UnixListener::bind(&path).expect("bind fake upstream");
    listener.set_nonblocking(false).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);

    let handle = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop_thread.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = conn else { continue };
            let blob = blob.clone();
            let comment = comment.clone();
            // Serve messages on this connection until the peer closes it.
            std::thread::spawn(move || {
                loop {
                    let mut len = [0u8; 4];
                    if stream.read_exact(&mut len).is_err() {
                        return;
                    }
                    let n = u32::from_be_bytes(len) as usize;
                    let mut body = vec![0u8; n];
                    if stream.read_exact(&mut body).is_err() {
                        return;
                    }
                    let resp = match body[0] {
                        SSH_AGENTC_REQUEST_IDENTITIES => {
                            // IDENTITIES_ANSWER: count(1) + string(blob) + string(comment)
                            let mut p = Vec::new();
                            p.push(SSH_AGENT_IDENTITIES_ANSWER);
                            p.extend_from_slice(&1u32.to_be_bytes());
                            put_string(&mut p, &blob);
                            put_string(&mut p, comment.as_bytes());
                            p
                        }
                        SSH_AGENTC_SIGN_REQUEST => {
                            // body = type + string(key_blob) + string(data) + u32(flags)
                            let mut cur = &body[1..];
                            let klen = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
                            let key = &cur[4..4 + klen];
                            cur = &cur[4 + klen..];
                            let _ = cur;
                            if key == blob.as_slice() {
                                let mut p = Vec::new();
                                p.push(SSH_AGENT_SIGN_RESPONSE);
                                put_string(&mut p, UPSTREAM_SENTINEL_SIG);
                                p
                            } else {
                                vec![SSH_AGENT_FAILURE]
                            }
                        }
                        _ => vec![SSH_AGENT_FAILURE],
                    };
                    let mut frame = Vec::with_capacity(4 + resp.len());
                    frame.extend_from_slice(&(resp.len() as u32).to_be_bytes());
                    frame.extend_from_slice(&resp);
                    if stream.write_all(&frame).is_err() || stream.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });

    FakeUpstream {
        path,
        stop,
        handle: Some(handle),
    }
}

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

/// Like [`config_content`] but the authsock socket also forwards to `upstream`.
fn config_content_with_upstream(sock_path: &Path, key_path: &Path, upstream: &Path) -> String {
    let mut s = config_content(sock_path, key_path, None, false);
    s.push_str(&format!("upstreams = [\"{}\"]\n", upstream.display()));
    s
}

/// Parse an IDENTITIES_ANSWER payload into a list of (key_blob, comment).
fn parse_identities(payload: &[u8]) -> Vec<(Vec<u8>, String)> {
    let mut out = Vec::new();
    let count = u32::from_be_bytes(payload[..4].try_into().unwrap());
    let mut cur = &payload[4..];
    for _ in 0..count {
        let klen = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
        let blob = cur[4..4 + klen].to_vec();
        cur = &cur[4 + klen..];
        let clen = u32::from_be_bytes(cur[..4].try_into().unwrap()) as usize;
        let comment = String::from_utf8_lossy(&cur[4..4 + clen]).to_string();
        cur = &cur[4 + clen..];
        out.push((blob, comment));
    }
    out
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

// ---- Iteration 2: upstream agent forwarding ----

/// `ssh-add -l` must list both the local KV key and the upstream agent's key,
/// proving the daemon merges identities from a forwarded upstream.
#[test]
fn upstream_keys_are_merged_into_identities() {
    let dir = tempfile::tempdir().unwrap();

    // Local key (signed locally).
    let local_key = dir.path().join("id_local");
    let local_pub = ssh_keygen_ed25519(&local_key, "local-key");

    // A separate key the fake upstream advertises.
    let up_key = dir.path().join("id_upstream");
    let up_pub = ssh_keygen_ed25519(&up_key, "upstream-key");
    let upstream = spawn_fake_upstream(&up_pub);

    let agent_sock = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        config_content_with_upstream(&agent_sock, &local_key, &upstream.path),
    )
    .unwrap();

    let (_daemon, _control) = spawn_daemon(dir.path(), &config_path);
    wait_for_socket(&agent_sock);

    // ssh-add -l lists both comments.
    let (ok, listing) = ssh_add_list(&agent_sock);
    assert!(ok, "ssh-add -l failed: {listing}");
    assert!(
        listing.contains("local-key"),
        "missing local key, got: {listing}"
    );
    assert!(
        listing.contains("upstream-key"),
        "missing upstream key (merge failed), got: {listing}"
    );

    // Cross-check on the raw wire: both blobs present in IDENTITIES_ANSWER.
    let (rtype, rpayload) = agent_round_trip(&agent_sock, SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    assert_eq!(rtype, SSH_AGENT_IDENTITIES_ANSWER);
    let ids = parse_identities(&rpayload);
    let blobs: Vec<_> = ids.iter().map(|(b, _)| b.clone()).collect();
    assert!(blobs.contains(&public_key_blob(&local_pub)));
    assert!(blobs.contains(&public_key_blob(&up_pub)));
}

/// A SIGN_REQUEST for an upstream-only key must be forwarded to the upstream and
/// return the upstream's signature (here, the recognizable sentinel blob).
#[test]
fn sign_for_upstream_key_is_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let local_key = dir.path().join("id_local");
    let _local_pub = ssh_keygen_ed25519(&local_key, "local-key");
    let up_key = dir.path().join("id_upstream");
    let up_pub = ssh_keygen_ed25519(&up_key, "upstream-key");
    let upstream = spawn_fake_upstream(&up_pub);

    let agent_sock = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        config_content_with_upstream(&agent_sock, &local_key, &upstream.path),
    )
    .unwrap();
    let (_daemon, _control) = spawn_daemon(dir.path(), &config_path);
    wait_for_socket(&agent_sock);

    // Enumerate first so the daemon records the upstream route for this blob.
    let _ = agent_round_trip(&agent_sock, SSH_AGENTC_REQUEST_IDENTITIES, &[]);

    // Sign the upstream's key blob.
    let blob = public_key_blob(&up_pub);
    let mut payload = Vec::new();
    put_string(&mut payload, &blob);
    put_string(&mut payload, b"forward-me");
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (resp_type, resp_payload) =
        agent_round_trip(&agent_sock, SSH_AGENTC_SIGN_REQUEST, &payload);

    assert_eq!(
        resp_type, SSH_AGENT_SIGN_RESPONSE,
        "upstream sign should be forwarded and answered, got type {resp_type}"
    );
    // The payload is the forwarded upstream signature: string(sentinel).
    let sig_len = u32::from_be_bytes(resp_payload[..4].try_into().unwrap()) as usize;
    assert_eq!(&resp_payload[4..4 + sig_len], UPSTREAM_SENTINEL_SIG);
}

// ---- Iteration 3: per-socket key filters ----

/// Build a config with two KV keys (`GITHUB_KEY`, `OTHER_KEY`) preloaded via
/// `cat`, exposed through two agent sockets:
/// - `filtered_sock`: `filters = ["comment=github*"]` (only the github key),
/// - `all_sock`: no filter (both keys).
fn config_two_sockets_one_filtered(
    github_key_path: &Path,
    other_key_path: &Path,
    filtered_sock: &Path,
    all_sock: &Path,
) -> String {
    let mut s = String::new();
    s.push_str("[kv.GITHUB_KEY]\n");
    s.push_str(&format!(
        "command = [\"cat\", \"{}\"]\n\n",
        github_key_path.display()
    ));
    s.push_str("[kv.OTHER_KEY]\n");
    s.push_str(&format!(
        "command = [\"cat\", \"{}\"]\n\n",
        other_key_path.display()
    ));

    s.push_str("[authsock.sockets.filtered]\n");
    s.push_str(&format!("path = \"{}\"\n", filtered_sock.display()));
    s.push_str("keys = [\"GITHUB_KEY\", \"OTHER_KEY\"]\n");
    s.push_str("filters = [\"comment=github*\"]\n\n");

    s.push_str("[authsock.sockets.all]\n");
    s.push_str(&format!("path = \"{}\"\n", all_sock.display()));
    s.push_str("keys = [\"GITHUB_KEY\", \"OTHER_KEY\"]\n");
    s
}

/// The filtered socket exposes only the matching key; the unfiltered socket
/// exposes both; and a SIGN_REQUEST for the hidden key on the filtered socket is
/// SSH_AGENT_FAILURE (filtering applies to signing, not just enumeration).
#[test]
fn filter_socket_hides_non_matching_key_and_rejects_its_sign() {
    let dir = tempfile::tempdir().unwrap();

    // Two real keys with distinct comments.
    let github_key = dir.path().join("id_github");
    let github_pub = ssh_keygen_ed25519(&github_key, "github-work");
    let other_key = dir.path().join("id_other");
    let other_pub = ssh_keygen_ed25519(&other_key, "other-personal");

    let filtered_sock = dir.path().join("filtered.sock");
    let all_sock = dir.path().join("all.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        config_two_sockets_one_filtered(&github_key, &other_key, &filtered_sock, &all_sock),
    )
    .unwrap();

    let (_daemon, _control) = spawn_daemon(dir.path(), &config_path);
    wait_for_socket(&filtered_sock);
    wait_for_socket(&all_sock);

    // --- filtered socket: only the github key is enumerated ---
    let (ok, listing) = ssh_add_list(&filtered_sock);
    assert!(ok, "ssh-add -l on filtered sock failed: {listing}");
    assert!(
        listing.contains("github-work"),
        "filtered sock must list the github key, got: {listing}"
    );
    assert!(
        !listing.contains("other-personal"),
        "filtered sock must NOT list the other key, got: {listing}"
    );

    // Cross-check on the wire: only the github blob is present.
    let (rtype, rpayload) = agent_round_trip(&filtered_sock, SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    assert_eq!(rtype, SSH_AGENT_IDENTITIES_ANSWER);
    let blobs: Vec<_> = parse_identities(&rpayload)
        .into_iter()
        .map(|(b, _)| b)
        .collect();
    assert!(blobs.contains(&public_key_blob(&github_pub)));
    assert!(!blobs.contains(&public_key_blob(&other_pub)));

    // --- filtered socket: signing the github key works ---
    let blob = public_key_blob(&github_pub);
    let data = b"filtered-sock signs the allowed key";
    let mut payload = Vec::new();
    put_string(&mut payload, &blob);
    put_string(&mut payload, data);
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (resp_type, resp_payload) =
        agent_round_trip(&filtered_sock, SSH_AGENTC_SIGN_REQUEST, &payload);
    assert_eq!(resp_type, SSH_AGENT_SIGN_RESPONSE);
    let sig_len = u32::from_be_bytes(resp_payload[..4].try_into().unwrap()) as usize;
    let sig = ssh_key::Signature::try_from(&resp_payload[4..4 + sig_len]).unwrap();
    let pk = ssh_key::PublicKey::from_openssh(&github_pub).unwrap();
    <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
        .expect("allowed key signs on the filtered socket");

    // --- filtered socket: signing the HIDDEN key is FAILURE ---
    let hidden_blob = public_key_blob(&other_pub);
    let mut payload = Vec::new();
    put_string(&mut payload, &hidden_blob);
    put_string(&mut payload, b"should be rejected");
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (resp_type, resp_payload) =
        agent_round_trip(&filtered_sock, SSH_AGENTC_SIGN_REQUEST, &payload);
    assert_eq!(
        resp_type, SSH_AGENT_FAILURE,
        "signing a filtered-out key must yield FAILURE, got type {resp_type}"
    );
    assert!(
        resp_payload.is_empty(),
        "FAILURE must carry no payload (no leak)"
    );

    // --- unfiltered socket: BOTH keys are enumerated ---
    let (ok, listing) = ssh_add_list(&all_sock);
    assert!(ok, "ssh-add -l on all sock failed: {listing}");
    assert!(
        listing.contains("github-work") && listing.contains("other-personal"),
        "unfiltered sock must list both keys, got: {listing}"
    );

    // And the unfiltered socket signs the "other" key fine.
    let mut payload = Vec::new();
    put_string(&mut payload, &public_key_blob(&other_pub));
    let data = b"unfiltered sock signs the other key";
    put_string(&mut payload, data);
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (resp_type, resp_payload) = agent_round_trip(&all_sock, SSH_AGENTC_SIGN_REQUEST, &payload);
    assert_eq!(resp_type, SSH_AGENT_SIGN_RESPONSE);
    let sig_len = u32::from_be_bytes(resp_payload[..4].try_into().unwrap()) as usize;
    let sig = ssh_key::Signature::try_from(&resp_payload[4..4 + sig_len]).unwrap();
    let pk = ssh_key::PublicKey::from_openssh(&other_pub).unwrap();
    <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
        .expect("other key signs on the unfiltered socket");
}

/// With the upstream down, the daemon must still serve the local key
/// (degradation): `ssh-add -l` lists the local key and a local sign verifies.
#[test]
fn local_key_survives_when_upstream_is_down() {
    let dir = tempfile::tempdir().unwrap();
    let local_key = dir.path().join("id_local");
    let local_pub = ssh_keygen_ed25519(&local_key, "local-key");

    // Point at an upstream socket path that nothing is listening on.
    let dead_upstream = dir.path().join("dead-upstream.sock");

    let agent_sock = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        config_content_with_upstream(&agent_sock, &local_key, &dead_upstream),
    )
    .unwrap();
    let (_daemon, _control) = spawn_daemon(dir.path(), &config_path);
    wait_for_socket(&agent_sock);

    // ssh-add -l still lists the local key (the dead upstream is skipped).
    let (ok, listing) = ssh_add_list(&agent_sock);
    assert!(ok, "ssh-add -l failed: {listing}");
    assert!(
        listing.contains("local-key"),
        "local key must survive a dead upstream, got: {listing}"
    );

    // And the local key still signs verifiably.
    let blob = public_key_blob(&local_pub);
    let data = b"degraded-but-local";
    let mut payload = Vec::new();
    put_string(&mut payload, &blob);
    put_string(&mut payload, data);
    payload.extend_from_slice(&0u32.to_be_bytes());
    let (resp_type, resp_payload) =
        agent_round_trip(&agent_sock, SSH_AGENTC_SIGN_REQUEST, &payload);
    assert_eq!(resp_type, SSH_AGENT_SIGN_RESPONSE);
    let sig_len = u32::from_be_bytes(resp_payload[..4].try_into().unwrap()) as usize;
    let sig = ssh_key::Signature::try_from(&resp_payload[4..4 + sig_len]).unwrap();
    let pk = ssh_key::PublicKey::from_openssh(&local_pub).unwrap();
    <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
        .expect("local signature must verify");
}
