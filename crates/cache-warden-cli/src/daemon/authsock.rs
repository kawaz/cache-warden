//! SSH agent listener(s) for the authsock adapter (port plan Iteration 1).
//!
//! Each `[authsock.sockets.NAME]` becomes one agent socket the daemon serves in
//! this same process (DR-0008): an SSH client points `SSH_AUTH_SOCK` at it and
//! the daemon answers REQUEST_IDENTITIES (public keys) and SIGN_REQUEST
//! (signatures) using private-key PEMs cached in the core [`Store`].
//!
//! # How a socket maps to the core
//!
//! At startup each socket derives a [`PublicKeyRegistry`] from the PEMs of its
//! configured KV keys (the public half only — the private value never leaves
//! the core). REQUEST_IDENTITIES answers straight from the registry without
//! touching any secret. On SIGN_REQUEST the registry maps the client's key blob
//! back to a core KV key; the daemon fetches that key's value through the
//! **same auth gate** as the control socket (`extend_authenticated` on soft
//! expiry, `regenerate` on hard expiry for command sources), borrows the PEM via
//! `expose_secret` just long enough to sign, and — on success — calls `extend`
//! to refresh the idle window (DR-0011 idle-extend semantics).
//!
//! Any failure (unknown key, denied auth, hard-expired static key, malformed
//! request, signing error) is answered with `SSH_AGENT_FAILURE`: the agent
//! protocol learns nothing beyond "no".
//!
//! # Isolation
//!
//! Like the control socket, the per-connection handler runs on the blocking
//! pool: a re-authentication can block on a user prompt for minutes, which must
//! not pin an async worker.

use std::path::PathBuf;
use std::sync::Arc;

use cache_warden::{
    Authenticator, Clock, EntryState, ProcessInfo, ProcessInspector, RegenerateOutcome,
    SourceRunner, Store, SystemInspector,
};
use cache_warden_authsock::{AgentCodec, AgentMessage, MessageType, PublicKeyRegistry, sign};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::peer::peer_pid;
use super::server::{Shared, bind_control_socket};
use crate::config::AuthsockSocket;

/// Build a public-key registry for `keys` from the PEMs cached in `store`.
///
/// Each key's value is read once (it must be Active right now — typically just
/// preloaded) and its public half derived into the registry. A key that is
/// absent / not Active / whose PEM cannot be parsed is logged and skipped: the
/// socket still serves the keys that did resolve. Only the *public* key is
/// retained; the borrowed PEM is dropped at the end of each iteration.
fn build_registry(
    socket_name: &str,
    keys: &[String],
    store: &mut Store,
    clock: &impl Clock,
) -> PublicKeyRegistry {
    let mut registry = PublicKeyRegistry::new();
    for kv_key in keys {
        match store.get(kv_key, clock) {
            Some(secret) => {
                // The PEM is borrowed only for derivation; the registry keeps
                // the public blob, never the secret.
                let pem = String::from_utf8_lossy(secret.expose_secret());
                match registry.register_from_pem(kv_key.clone(), &pem) {
                    Ok(()) => {}
                    Err(e) => eprintln!(
                        "cache-warden: authsock `{socket_name}`: key `{kv_key}` is not a usable \
                         private key, skipping ({e})"
                    ),
                }
            }
            None => eprintln!(
                "cache-warden: authsock `{socket_name}`: key `{kv_key}` is not loaded (absent or \
                 expired), skipping at startup"
            ),
        }
    }
    registry
}

/// Per-socket state shared across its connection tasks.
struct SocketState {
    /// Socket name (for diagnostics).
    name: String,
    /// Public keys this socket serves (REQUEST_IDENTITIES) and can sign with.
    registry: PublicKeyRegistry,
    /// The shared process core (Store / auth / runner / clock).
    shared: Arc<Shared>,
}

/// Spawn one listener task per validated `[authsock.sockets.*]`.
///
/// Returns `(socket_path, JoinHandle)` pairs so the caller can await each task
/// on shutdown and remove its socket file. A socket whose registry ends up
/// empty (no key resolved) is still bound — it simply answers REQUEST_IDENTITIES
/// with an empty list until a key is set.
pub fn spawn_listeners(
    sockets: &[AuthsockSocket],
    shared: Arc<Shared>,
    shutdown_rx: watch::Receiver<bool>,
) -> Vec<(PathBuf, JoinHandle<()>)> {
    let mut handles = Vec::new();
    for socket in sockets {
        // Derive this socket's public-key registry up front (under the store
        // lock) from the configured keys' currently-cached PEMs.
        let registry = {
            let mut store = match shared.store.lock() {
                Ok(g) => g,
                Err(_) => {
                    eprintln!(
                        "cache-warden: authsock `{}`: store lock poisoned; skipping socket",
                        socket.name
                    );
                    continue;
                }
            };
            build_registry(&socket.name, &socket.keys, &mut store, &shared.clock)
        };

        let listener = match bind_control_socket(&socket.path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "cache-warden: authsock `{}`: failed to bind {}: {e}",
                    socket.name,
                    socket.path.display()
                );
                continue;
            }
        };

        println!(
            "cache-warden: authsock `{}` listening on {} ({} key(s))",
            socket.name,
            socket.path.display(),
            registry.len()
        );

        let state = Arc::new(SocketState {
            name: socket.name.clone(),
            registry,
            shared: Arc::clone(&shared),
        });
        let path = socket.path.clone();
        let rx = shutdown_rx.clone();
        let handle = tokio::spawn(serve(listener, state, rx));
        handles.push((path, handle));
    }
    handles
}

/// Accept loop for one agent socket: serve connections until shutdown.
async fn serve(
    listener: UnixListener,
    state: Arc<SocketState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state).await {
                                eprintln!("cache-warden: authsock connection error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("cache-warden: authsock `{}` accept error: {e}", state.name);
                    }
                }
            }
        }
    }
}

/// Handle one agent connection: read framed messages, reply per message.
///
/// A client (e.g. `ssh-add`, `ssh`) keeps the socket open for several messages.
/// Each is decoded by [`AgentCodec`]; the synchronous core work (lookup, auth,
/// sign) is moved to the blocking pool so a re-auth prompt cannot stall the
/// runtime.
async fn handle_connection(stream: UnixStream, state: Arc<SocketState>) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let peer = peer_pid(stream.as_raw_fd());

    let (mut read_half, mut write_half) = stream.into_split();
    while let Some(msg) = AgentCodec::read(&mut read_half)
        .await
        .map_err(std::io::Error::other)?
    {
        let state_for_handler = Arc::clone(&state);
        let response = tokio::task::spawn_blocking(move || respond(&state_for_handler, peer, &msg))
            .await
            .unwrap_or_else(|_| AgentMessage::failure());
        AgentCodec::write(&mut write_half, &response)
            .await
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// Produce the agent response for one request message (synchronous; runs on the
/// blocking pool). Resolves the requester ancestry from `peer` and dispatches.
fn respond(state: &SocketState, peer: Option<u32>, msg: &AgentMessage) -> AgentMessage {
    let requester: Option<Vec<ProcessInfo>> =
        peer.and_then(|pid| SystemInspector::new().ancestry(pid).ok());
    handle_agent_message(
        &state.registry,
        &state.shared.store,
        state.shared.auth.as_ref(),
        &state.shared.runner,
        &state.shared.clock,
        requester.as_deref(),
        msg,
    )
}

/// Pure dispatch for one agent message against the core (no socket I/O).
///
/// Factored out of the async server so the whole REQUEST_IDENTITIES /
/// SIGN_REQUEST → core → signature path is unit-testable without a runtime.
///
/// - REQUEST_IDENTITIES → IDENTITIES_ANSWER from the registry (no secret access).
/// - SIGN_REQUEST → look up the key blob, fetch the PEM through the auth gate,
///   sign, refresh the idle window, and return SIGN_RESPONSE. Any failure is
///   SSH_AGENT_FAILURE.
/// - anything else → SSH_AGENT_FAILURE.
#[allow(clippy::too_many_arguments)]
fn handle_agent_message<A, R, C>(
    registry: &PublicKeyRegistry,
    store: &std::sync::Mutex<Store>,
    auth: &A,
    runner: &R,
    clock: &C,
    requester: Option<&[ProcessInfo]>,
    msg: &AgentMessage,
) -> AgentMessage
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    match msg.msg_type {
        MessageType::RequestIdentities => {
            AgentMessage::build_identities_answer(&registry.identities())
        }
        MessageType::SignRequest => {
            let fields = match msg.parse_sign_request() {
                Ok(f) => f,
                Err(_) => return AgentMessage::failure(),
            };
            let Some(registered) = registry.lookup(&fields.key_blob) else {
                // Unknown key: do not reveal which keys exist beyond IDENTITIES.
                return AgentMessage::failure();
            };
            let kv_key = registered.kv_key.clone();

            let mut store = match store.lock() {
                Ok(g) => g,
                Err(_) => return AgentMessage::failure(),
            };

            // Fetch the PEM through the same auth gate as the control socket.
            if !ensure_active(&mut store, &kv_key, auth, runner, requester, clock) {
                return AgentMessage::failure();
            }

            // Borrow the PEM only for the signing call.
            let signature = match store.get(&kv_key, clock) {
                Some(secret) => {
                    let pem = String::from_utf8_lossy(secret.expose_secret());
                    sign(&pem, &fields.data, fields.flags)
                }
                None => return AgentMessage::failure(),
            };

            match signature {
                Ok(blob) => {
                    // Idle-extend (DR-0011): a successful sign refreshes the soft
                    // window without prompting (the entry is Active here). Best
                    // effort — a failure here must not fail the signature.
                    let _ = store.extend(&kv_key, clock);
                    AgentMessage::sign_response(&blob)
                }
                Err(_) => AgentMessage::failure(),
            }
        }
        _ => AgentMessage::failure(),
    }
}

/// Make `key`'s value readable (Active), running the core's auth gate.
///
/// Returns `true` if the value is now Active (already-Active, extended after
/// soft expiry, or regenerated after hard expiry). Returns `false` on any
/// failure (missing, denied, hard-expired static, regenerate error) — the
/// caller maps that to SSH_AGENT_FAILURE.
fn ensure_active<A, R, C>(
    store: &mut Store,
    key: &str,
    auth: &A,
    runner: &R,
    requester: Option<&[ProcessInfo]>,
    clock: &C,
) -> bool
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    match store.state_of(key, clock) {
        None => false,
        Some(EntryState::Active) => true,
        Some(EntryState::SoftExpired) => {
            matches!(
                store.extend_authenticated(key, auth, requester, clock),
                Ok(())
            )
        }
        Some(EntryState::HardExpired) => {
            match store.regenerate(key, runner, auth, requester, clock) {
                Ok(()) => true,
                // A static hard-expired key cannot regenerate; not signable.
                Err(
                    RegenerateOutcome::NotFound
                    | RegenerateOutcome::NotRegenerable
                    | RegenerateOutcome::NotHardExpired
                    | RegenerateOutcome::RunFailed(_)
                    | RegenerateOutcome::AuthFailed(_),
                ) => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache_warden::{
        AllowAll, DenyAll, FakeClock, RunError, SecretBytes, SourceRunner, Ttl, ValueSource,
    };
    use std::sync::Mutex;
    use std::time::Duration;

    /// Test PKCS#8 Ed25519 PEM (1Password DR-014 spec). FOR TESTS ONLY.
    const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILfg0K3JM0GwuUuqBcJ79jKqV2owfa4zpRsarl64dDjC\noSMDIQBuIlSrfmaRn6Jj82jh6SDZkTFg0u5TlA9B1wYE2+lIyQ==\n-----END PRIVATE KEY-----\n";
    const ED25519_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4iVKt+ZpGfomPzaOHpINmRMWDS7lOUD0HXBgTb6UjJ";

    const SOFT: u64 = 10;
    const HARD: u64 = 30;

    struct NoRunner;
    impl SourceRunner for NoRunner {
        fn run(&self, _argv: &[String]) -> Result<SecretBytes, RunError> {
            Err(RunError::EmptyOutput)
        }
    }

    fn ttl() -> Ttl {
        Ttl::new(
            Some(Duration::from_secs(SOFT)),
            Some(Duration::from_secs(HARD)),
        )
        .unwrap()
    }

    /// A store with one static Ed25519 PEM under `GITHUB_KEY`, plus a registry.
    fn fixture(clock: &FakeClock) -> (Mutex<Store>, PublicKeyRegistry) {
        let mut store = Store::new();
        store.set(
            "GITHUB_KEY",
            ValueSource::Static,
            SecretBytes::from(ED25519_PEM),
            ttl(),
            clock,
        );
        let registry = build_registry("test", &["GITHUB_KEY".into()], &mut store, clock);
        (Mutex::new(store), registry)
    }

    fn blob_of(pub_openssh: &str) -> Vec<u8> {
        use ssh_encoding::Encode;
        let pk = ssh_key::PublicKey::from_openssh(pub_openssh).unwrap();
        let mut b = Vec::new();
        pk.key_data().encode(&mut b).unwrap();
        b
    }

    fn sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> AgentMessage {
        use bytes::{BufMut, BytesMut};
        let mut payload = BytesMut::new();
        payload.put_u32(key_blob.len() as u32);
        payload.put_slice(key_blob);
        payload.put_u32(data.len() as u32);
        payload.put_slice(data);
        payload.put_u32(flags);
        AgentMessage::new(MessageType::SignRequest, payload.freeze())
    }

    #[test]
    fn build_registry_skips_missing_keys() {
        let clock = FakeClock::new();
        let mut store = Store::new();
        store.set(
            "GITHUB_KEY",
            ValueSource::Static,
            SecretBytes::from(ED25519_PEM),
            ttl(),
            &clock,
        );
        let reg = build_registry(
            "s",
            &["GITHUB_KEY".into(), "ABSENT".into()],
            &mut store,
            &clock,
        );
        // Only the present, parseable key is registered.
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn request_identities_returns_registered_public_key() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp =
            handle_agent_message(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::IdentitiesAnswer);
        let ids = resp.parse_identities().unwrap();
        assert_eq!(ids.len(), 1);
        // The returned blob equals the known public key.
        assert_eq!(ids[0].key_blob.as_ref(), blob_of(ED25519_PUB).as_slice());
    }

    #[test]
    fn sign_request_for_active_key_produces_verifiable_signature() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let data = b"agent challenge bytes";
        let req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp =
            handle_agent_message(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::SignResponse);

        // The response carries one length-prefixed signature blob; verify it.
        let mut buf = &resp.payload[..];
        use bytes::Buf;
        let len = buf.get_u32() as usize;
        let sig_blob = &buf[..len];
        let sig = ssh_key::Signature::try_from(sig_blob).unwrap();
        let pk = ssh_key::PublicKey::from_openssh(ED25519_PUB).unwrap();
        <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
            .unwrap();
    }

    #[test]
    fn sign_request_for_unknown_key_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let req = sign_request(b"bogus-blob", b"data", 0);
        let resp =
            handle_agent_message(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn sign_request_denied_auth_is_failure_and_leaks_nothing() {
        // Soft-expire so a sign needs re-auth; DenyAll blocks it -> FAILURE.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(SOFT + 1));
        let data = b"data";
        let req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp = handle_agent_message(&registry, &store, &DenyAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn sign_request_soft_expired_extends_then_signs_with_allow_all() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(SOFT + 1)); // soft-expired
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp =
            handle_agent_message(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_hard_expired_static_key_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(HARD)); // hard-expired, static => destroyed
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp =
            handle_agent_message(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn successful_sign_refreshes_idle_window() {
        // After a sign while soft-expired-then-extended, a second sign within the
        // refreshed window must not need auth again (idle extend, DR-0011).
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        // Advance near soft expiry, sign (Active -> extend refreshes window).
        clock.advance(Duration::from_secs(SOFT - 1));
        let req = sign_request(&blob_of(ED25519_PUB), b"d1", 0);
        let resp = handle_agent_message(&registry, &store, &DenyAll, &NoRunner, &clock, None, &req);
        // Active sign with DenyAll still succeeds (no prompt while Active) and
        // extends the window.
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        // Advance past the *original* soft deadline but within the refreshed one.
        clock.advance(Duration::from_secs(2));
        let req2 = sign_request(&blob_of(ED25519_PUB), b"d2", 0);
        let resp2 =
            handle_agent_message(&registry, &store, &DenyAll, &NoRunner, &clock, None, &req2);
        assert_eq!(
            resp2.msg_type,
            MessageType::SignResponse,
            "idle extend should keep the key Active without re-auth"
        );
    }

    #[test]
    fn unsupported_message_type_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let req = AgentMessage::new(MessageType::Lock, bytes::Bytes::new());
        let resp =
            handle_agent_message(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::Failure);
    }
}
