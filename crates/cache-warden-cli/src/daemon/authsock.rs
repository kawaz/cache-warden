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
//! # Upstream agents (port plan Iteration 2)
//!
//! A socket may also list `upstreams` — other agent sockets (the 1Password
//! agent, a system `ssh-agent`, ...) whose keys it offers but whose private
//! material it cannot hold. For those, signing is **forwarded**:
//!
//! - REQUEST_IDENTITIES merges the local registry with each upstream's
//!   identities, de-duplicating by key blob with **local keys winning** (a blob
//!   we can sign locally is never shadowed by an upstream copy). An upstream
//!   that is down is skipped with a one-line stderr warning; the socket still
//!   answers with the rest (graceful degradation).
//! - SIGN_REQUEST: a blob in the local registry is signed locally (the
//!   Iteration 1 path). Otherwise the request is forwarded to the upstream that
//!   advertised that blob during the last enumeration; if no such record exists
//!   (e.g. a client that signs without first enumerating), every upstream is
//!   tried in order until one returns a SIGN_RESPONSE (the authsock-warden
//!   fallback). All upstreams failing yields SSH_AGENT_FAILURE.
//!
//! Upstream connections are opened per request (no pooling) — see
//! [`cache_warden_authsock::Upstream`] for why.
//!
//! # Isolation
//!
//! The local (KV) sign path runs on the blocking pool: a re-authentication can
//! block on a user prompt for minutes, which must not pin an async worker. The
//! upstream calls are async (non-blocking socket I/O) and stay on the runtime.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use cache_warden::{
    Authenticator, Clock, EntryState, ProcessInfo, ProcessInspector, RegenerateOutcome,
    SourceRunner, Store, SystemInspector,
};
use cache_warden_authsock::{
    AgentCodec, AgentMessage, Identity, MessageType, PublicKeyRegistry, Upstream, sign,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::peer::peer_pid;
use super::server::{Shared, bind_control_socket};
use super::upstream_path::resolve_upstream_path;
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
    /// Public keys this socket serves (REQUEST_IDENTITIES) and can sign with
    /// **locally** (their PEMs live in the core KV).
    registry: PublicKeyRegistry,
    /// Upstream agents this socket forwards to (keys merged, signatures
    /// relayed). Resolved paths (macOS TCC symlink applied); empty for a
    /// local-only socket. Cheap to clone per connection.
    upstreams: Vec<Upstream>,
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

        // Resolve each configured upstream path (macOS TCC symlink for Group
        // Container sockets; verbatim elsewhere) into an `Upstream`.
        let upstreams: Vec<Upstream> = socket
            .upstreams
            .iter()
            .map(|p| Upstream::new(resolve_upstream_path(p)))
            .collect();

        println!(
            "cache-warden: authsock `{}` listening on {} ({} local key(s), {} upstream(s))",
            socket.name,
            socket.path.display(),
            registry.len(),
            upstreams.len()
        );

        let state = Arc::new(SocketState {
            name: socket.name.clone(),
            registry,
            upstreams,
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

/// Per-connection routing record: which upstream advertised a given key blob in
/// the most recent REQUEST_IDENTITIES. Used to send a SIGN_REQUEST straight to
/// the upstream that owns the key. Only upstream blobs are recorded (local blobs
/// are in the registry).
type UpstreamRoutes = HashMap<Vec<u8>, usize>;

/// Handle one agent connection: read framed messages, reply per message.
///
/// A client (e.g. `ssh-add`, `ssh`) keeps the socket open for several messages.
/// Each is decoded by [`AgentCodec`]. Local (KV) work — lookup, auth, sign — is
/// moved to the blocking pool so a re-auth prompt cannot stall the runtime;
/// upstream calls are async and stay on the runtime. A per-connection routing
/// map records which upstream owns each remote blob from the last enumeration.
async fn handle_connection(stream: UnixStream, state: Arc<SocketState>) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let peer = peer_pid(stream.as_raw_fd());

    let (mut read_half, mut write_half) = stream.into_split();
    let mut routes: UpstreamRoutes = HashMap::new();
    while let Some(msg) = AgentCodec::read(&mut read_half)
        .await
        .map_err(std::io::Error::other)?
    {
        let response = respond(&state, peer, &msg, &mut routes).await;
        AgentCodec::write(&mut write_half, &response)
            .await
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// Produce the agent response for one request message.
///
/// REQUEST_IDENTITIES merges local + upstream keys (async, updating `routes`);
/// SIGN_REQUEST signs locally (blocking pool) or forwards (async). Anything else
/// is SSH_AGENT_FAILURE.
async fn respond(
    state: &Arc<SocketState>,
    peer: Option<u32>,
    msg: &AgentMessage,
    routes: &mut UpstreamRoutes,
) -> AgentMessage {
    match msg.msg_type {
        MessageType::RequestIdentities => request_identities(state, msg, routes).await,
        MessageType::SignRequest => sign_request(state, peer, msg, routes).await,
        _ => AgentMessage::failure(),
    }
}

/// REQUEST_IDENTITIES: local registry keys plus each upstream's keys, merged and
/// de-duplicated by blob (local wins). Down upstreams are skipped with a stderr
/// warning. `routes` is rebuilt to map each surviving upstream blob to its
/// upstream index.
async fn request_identities(
    state: &Arc<SocketState>,
    request: &AgentMessage,
    routes: &mut UpstreamRoutes,
) -> AgentMessage {
    // Local identities first so they win de-dup against any upstream copy.
    let mut merged: Vec<Identity> = state.registry.identities();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        merged.iter().map(|id| id.key_blob.to_vec()).collect();

    routes.clear();
    for (idx, upstream) in state.upstreams.iter().enumerate() {
        match upstream_identities(upstream, request).await {
            Ok(identities) => {
                for id in identities {
                    let blob = id.key_blob.to_vec();
                    if seen.insert(blob.clone()) {
                        routes.insert(blob, idx);
                        merged.push(id);
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "cache-warden: authsock `{}`: upstream {} unavailable, skipping ({e})",
                    state.name,
                    upstream.socket_path().display()
                );
            }
        }
    }

    AgentMessage::build_identities_answer(&merged)
}

/// Ask one upstream for its identities. A non-IdentitiesAnswer reply is treated
/// as "no keys" (not an error) — same lenient handling as authsock-warden.
async fn upstream_identities(
    upstream: &Upstream,
    request: &AgentMessage,
) -> cache_warden_authsock::Result<Vec<Identity>> {
    let mut conn = upstream.connect().await?;
    let response = conn.send_receive(request).await?;
    if response.msg_type != MessageType::IdentitiesAnswer {
        return Ok(Vec::new());
    }
    response.parse_identities()
}

/// SIGN_REQUEST dispatch: local registry key → local sign (blocking pool);
/// otherwise forward to the recorded upstream, then fall back to trying every
/// upstream in order. All paths failing yields SSH_AGENT_FAILURE.
async fn sign_request(
    state: &Arc<SocketState>,
    peer: Option<u32>,
    msg: &AgentMessage,
    routes: &UpstreamRoutes,
) -> AgentMessage {
    let fields = match msg.parse_sign_request() {
        Ok(f) => f,
        Err(_) => return AgentMessage::failure(),
    };
    let key_blob = fields.key_blob.to_vec();

    // 1. A blob we can sign locally (Iteration 1 path) is signed on the blocking
    //    pool through the core auth gate.
    if state.registry.lookup(&key_blob).is_some() {
        let state = Arc::clone(state);
        let msg = msg.clone();
        return tokio::task::spawn_blocking(move || local_sign(&state, peer, &msg))
            .await
            .unwrap_or_else(|_| AgentMessage::failure());
    }

    // 2. No upstreams configured -> unknown key.
    if state.upstreams.is_empty() {
        return AgentMessage::failure();
    }

    // 3. Forward to the upstream that advertised this blob last enumeration.
    if let Some(&idx) = routes.get(&key_blob)
        && let Some(upstream) = state.upstreams.get(idx)
        && let Some(resp) = forward_sign(upstream, msg).await
    {
        return resp;
    }

    // 4. Fallback: a client may sign without enumerating first (or our record is
    //    stale). Try every upstream in order until one signs (authsock-warden).
    for upstream in &state.upstreams {
        if let Some(resp) = forward_sign(upstream, msg).await {
            return resp;
        }
    }

    AgentMessage::failure()
}

/// Forward a SIGN_REQUEST to one upstream, returning `Some(SIGN_RESPONSE)` only
/// when the upstream actually signed. A connect/transport error or any
/// non-SIGN_RESPONSE reply (including the upstream's own FAILURE) yields `None`
/// so the caller can try the next upstream.
async fn forward_sign(upstream: &Upstream, msg: &AgentMessage) -> Option<AgentMessage> {
    let mut conn = upstream.connect().await.ok()?;
    let resp = conn.send_receive(msg).await.ok()?;
    (resp.msg_type == MessageType::SignResponse).then_some(resp)
}

/// Sign one SIGN_REQUEST with a **local** registry key (synchronous; runs on the
/// blocking pool). Resolves the requester ancestry from `peer`, fetches the PEM
/// through the same auth gate as the control socket, signs, and idle-extends.
fn local_sign(state: &SocketState, peer: Option<u32>, msg: &AgentMessage) -> AgentMessage {
    let requester: Option<Vec<ProcessInfo>> =
        peer.and_then(|pid| SystemInspector::new().ancestry(pid).ok());
    handle_local_sign(
        &state.registry,
        &state.shared.store,
        state.shared.auth.as_ref(),
        &state.shared.runner,
        &state.shared.clock,
        requester.as_deref(),
        msg,
    )
}

/// Pure local-sign dispatch for one SIGN_REQUEST against the core (no socket
/// I/O). The blob is assumed to be in `registry` (the async caller checked).
///
/// Factored out of the async server so the SIGN_REQUEST → core → signature path
/// is unit-testable without a runtime. Looks up the key blob, fetches the PEM
/// through the auth gate, signs, refreshes the idle window, returns
/// SIGN_RESPONSE. Any failure (unknown, denied, hard-expired static, sign error)
/// is SSH_AGENT_FAILURE.
fn handle_local_sign<A, R, C>(
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
            // Idle-extend (DR-0011): a successful sign refreshes the soft window
            // without prompting (the entry is Active here). Best effort — a
            // failure here must not fail the signature.
            let _ = store.extend(&kv_key, clock);
            AgentMessage::sign_response(&blob)
        }
        Err(_) => AgentMessage::failure(),
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
    fn local_registry_identities_answer_returns_registered_public_key() {
        let clock = FakeClock::new();
        let (_store, registry) = fixture(&clock);
        // The local-only REQUEST_IDENTITIES answer is built straight from the
        // registry (the async merge layer adds upstreams on top of this).
        let resp = AgentMessage::build_identities_answer(&registry.identities());
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
        let resp = handle_local_sign(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
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
        let resp = handle_local_sign(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
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
        let resp = handle_local_sign(&registry, &store, &DenyAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn sign_request_soft_expired_extends_then_signs_with_allow_all() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(SOFT + 1)); // soft-expired
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_hard_expired_static_key_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(HARD)); // hard-expired, static => destroyed
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
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
        let resp = handle_local_sign(&registry, &store, &DenyAll, &NoRunner, &clock, None, &req);
        // Active sign with DenyAll still succeeds (no prompt while Active) and
        // extends the window.
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        // Advance past the *original* soft deadline but within the refreshed one.
        clock.advance(Duration::from_secs(2));
        let req2 = sign_request(&blob_of(ED25519_PUB), b"d2", 0);
        let resp2 = handle_local_sign(&registry, &store, &DenyAll, &NoRunner, &clock, None, &req2);
        assert_eq!(
            resp2.msg_type,
            MessageType::SignResponse,
            "idle extend should keep the key Active without re-auth"
        );
    }

    #[test]
    fn local_sign_of_unsupported_payload_is_failure() {
        // A Lock message has no SIGN_REQUEST payload, so the local sign path
        // fails to parse and returns FAILURE.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let req = AgentMessage::new(MessageType::Lock, bytes::Bytes::new());
        let resp = handle_local_sign(&registry, &store, &AllowAll, &NoRunner, &clock, None, &req);
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    // ---- Iteration 2: upstream merge / routing (async, against a fake agent) ----

    use cache_warden::SystemClock;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// A short, unique socket path under `/tmp` (under the sockaddr_un limit).
    fn short_sock(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        PathBuf::from(format!("/tmp/cw-as-{tag}-{}-{n}.sock", std::process::id()))
    }

    /// Read one framed agent message from `stream`, returning its raw body
    /// (type byte + payload).
    async fn read_frame(stream: &mut tokio::net::UnixStream) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await.ok()?;
        let n = u32::from_be_bytes(len) as usize;
        let mut body = vec![0u8; n];
        stream.read_exact(&mut body).await.ok()?;
        Some(body)
    }

    async fn write_frame(stream: &mut tokio::net::UnixStream, msg: &AgentMessage) {
        let encoded = msg.encode();
        let _ = stream.write_all(&encoded).await;
        let _ = stream.flush().await;
    }

    /// A fake upstream agent that, per connection, answers REQUEST_IDENTITIES
    /// with `identities` and SIGN_REQUEST with a fixed `sign_resp` (or FAILURE).
    /// Serves connections until the listener is dropped (when the handle ends).
    fn spawn_fake_upstream(
        identities: Vec<Identity>,
        sign_resp: Option<AgentMessage>,
    ) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let sock = short_sock("up");
        let listener = UnixListener::bind(&sock).unwrap();
        let path = sock.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let ids = identities.clone();
                let sresp = sign_resp.clone();
                tokio::spawn(async move {
                    while let Some(body) = read_frame(&mut stream).await {
                        let resp = match MessageType::from(body[0]) {
                            MessageType::RequestIdentities => {
                                AgentMessage::build_identities_answer(&ids)
                            }
                            MessageType::SignRequest => {
                                sresp.clone().unwrap_or_else(AgentMessage::failure)
                            }
                            _ => AgentMessage::failure(),
                        };
                        write_frame(&mut stream, &resp).await;
                    }
                });
            }
        });
        (path, handle)
    }

    /// Build a `SocketState` with the GITHUB_KEY local registry plus the given
    /// upstream paths.
    fn socket_state(upstream_paths: &[&Path]) -> Arc<SocketState> {
        let clock = SystemClock::new();
        let mut store = Store::new();
        store.set(
            "GITHUB_KEY",
            ValueSource::Static,
            SecretBytes::from(ED25519_PEM),
            ttl(),
            &clock,
        );
        let registry = build_registry("test", &["GITHUB_KEY".into()], &mut store, &clock);
        let shared = Arc::new(crate::daemon::server::Shared::new_for_test(
            store,
            Box::new(AllowAll),
            clock,
        ));
        Arc::new(SocketState {
            name: "test".into(),
            registry,
            upstreams: upstream_paths.iter().map(Upstream::new).collect(),
            shared,
        })
    }

    /// A synthetic upstream identity whose blob does not collide with our local
    /// key (so it always routes to the upstream, never signs locally).
    fn upstream_identity(comment: &str) -> Identity {
        // A synthetic, non-local blob (must not collide with ED25519_PUB).
        let blob = bytes::Bytes::from_static(b"\x00\x00\x00\x0bssh-ed25519FAKEKEYBLOB");
        Identity::new(blob, comment.to_string())
    }

    #[tokio::test]
    async fn respond_unsupported_message_type_is_failure() {
        let state = socket_state(&[]);
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::Lock, bytes::Bytes::new());
        let resp = respond(&state, None, &req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[tokio::test]
    async fn identities_merge_local_plus_upstream() {
        let up_id = upstream_identity("upstream-key");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], None);
        let state = socket_state(&[&path]);
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &req, &mut routes).await;

        let ids = resp.parse_identities().unwrap();
        // Local GITHUB_KEY + the one upstream key.
        assert_eq!(ids.len(), 2);
        let blobs: Vec<_> = ids.iter().map(|i| i.key_blob.to_vec()).collect();
        assert!(blobs.contains(&blob_of(ED25519_PUB)));
        assert!(blobs.contains(&up_id.key_blob.to_vec()));
        // The upstream blob is routed to upstream index 0.
        assert_eq!(routes.get(&up_id.key_blob.to_vec()), Some(&0));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn identities_dedup_prefers_local_over_upstream() {
        // An upstream that advertises *the same* blob as our local key must not
        // produce a duplicate, and the blob must NOT be routed to the upstream
        // (local wins -> it will be signed locally).
        let local_dup = Identity::new(bytes::Bytes::from(blob_of(ED25519_PUB)), "dup".into());
        let (path, _h) = spawn_fake_upstream(vec![local_dup], None);
        let state = socket_state(&[&path]);
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &req, &mut routes).await;

        let ids = resp.parse_identities().unwrap();
        assert_eq!(ids.len(), 1, "the duplicate blob must appear once");
        assert!(
            !routes.contains_key(&blob_of(ED25519_PUB)),
            "a local blob must not be routed to an upstream"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn identities_degrade_when_upstream_is_down() {
        // A nonexistent upstream socket must be skipped; the local key still answers.
        let dead = PathBuf::from("/tmp/cw-as-dead-does-not-exist-999.sock");
        let state = socket_state(&[&dead]);
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        assert_eq!(ids.len(), 1, "local key survives a dead upstream");
        assert_eq!(ids[0].key_blob.as_ref(), blob_of(ED25519_PUB).as_slice());
    }

    #[tokio::test]
    async fn sign_request_routes_to_upstream_after_enumeration() {
        // Enumerate so the upstream blob is routed, then sign that blob: the
        // upstream's SIGN_RESPONSE must be returned verbatim.
        let up_id = upstream_identity("up");
        let upstream_sig = AgentMessage::sign_response(b"UPSTREAM-SIG-BLOB");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], Some(upstream_sig.clone()));
        let state = socket_state(&[&path]);
        let mut routes = UpstreamRoutes::new();

        let enum_req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let _ = respond(&state, None, &enum_req, &mut routes).await;

        let sign_req = sign_request(&up_id.key_blob, b"challenge", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        assert_eq!(resp.payload, upstream_sig.payload);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn sign_request_falls_back_to_trying_upstreams_without_enumeration() {
        // A client that signs an upstream blob without enumerating first must
        // still succeed: every upstream is tried in order.
        let up_id = upstream_identity("up");
        let upstream_sig = AgentMessage::sign_response(b"FALLBACK-SIG");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], Some(upstream_sig.clone()));
        let state = socket_state(&[&path]);
        let mut routes = UpstreamRoutes::new(); // empty: no prior enumeration

        let sign_req = sign_request(&up_id.key_blob, b"challenge", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        assert_eq!(resp.payload, upstream_sig.payload);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn sign_request_local_key_still_signs_with_upstreams_present() {
        // A local blob is signed locally even when upstreams are configured
        // (graceful degradation: an unrelated dead upstream does not matter).
        let dead = PathBuf::from("/tmp/cw-as-dead2-999.sock");
        let state = socket_state(&[&dead]);
        let mut routes = UpstreamRoutes::new();
        let data = b"local-with-upstreams";
        let sign_req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::SignResponse);

        // Verify it is a real signature by our local key.
        let mut buf = &resp.payload[..];
        use bytes::Buf;
        let len = buf.get_u32() as usize;
        let sig = ssh_key::Signature::try_from(&buf[..len]).unwrap();
        let pk = ssh_key::PublicKey::from_openssh(ED25519_PUB).unwrap();
        <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
            .unwrap();
    }

    #[tokio::test]
    async fn sign_request_unknown_blob_no_upstream_is_failure() {
        let state = socket_state(&[]);
        let mut routes = UpstreamRoutes::new();
        let sign_req = sign_request(b"totally-unknown-blob", b"d", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::Failure);
    }
}
