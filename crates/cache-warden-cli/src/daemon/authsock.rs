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

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use cache_warden::{
    AuthContext, Authenticator, Clock, EntryState, ProcessInfo, ProcessInspector,
    RegenerateOutcome, SourceRunner, Store, SystemInspector, Ttl, ValueSource,
};
use cache_warden_authsock::{
    AgentCodec, AgentMessage, DiscoveredKey, FilterEvaluator, GithubFetcher, GithubMatcher,
    Identity, KeySource, MessageType, OpKeyCache, OpSource, PublicKeyRegistry, RealGithubFetcher,
    RealOpClient, RegisteredKey, Upstream, chain_gate_passes, discover_keys, private_key_argv,
    sign,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::peer::peer_pid;
use super::server::{Shared, bind_control_socket};
use super::upstream_path::resolve_upstream_path;
use crate::config::{AuthsockSocket, AuthsockSource};

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
    /// Per-socket key filter (port plan Iteration 3). Restricts which public keys
    /// this socket enumerates (REQUEST_IDENTITIES) and can sign with
    /// (SIGN_REQUEST). An empty evaluator matches every key (no filtering).
    filter: FilterEvaluator,
    /// Executable basenames allowed to use this socket (port plan Iteration 5).
    /// Empty means no restriction (the connection-time process gate is skipped).
    /// Otherwise a connection is admitted only when some process in the peer's
    /// ancestry chain has a matching basename; an unattributable peer (no pid /
    /// ancestry failure) is refused (fail-closed). See [`process_gate_passes`].
    allowed_processes: Vec<String>,
    /// The shared process core (Store / auth / runner / clock).
    shared: Arc<Shared>,
}

/// Discover the keys of every `[authsock.sources.*]` once, with the production
/// `op` CLI client. A source's discovery failure (op not signed in, network
/// down) is logged and the source yields no keys — startup is never blocked, and
/// the socket comes up so a later `refresh` can populate it (port plan §2).
///
/// Returns a `source name → discovered keys` map. Sharing one discovery across
/// every socket that references the same source mirrors authsock-warden's shared
/// op state (one TouchID-bearing `op item list`, not one per socket).
fn discover_all_sources(sources: &[AuthsockSource]) -> BTreeMap<String, Vec<DiscoveredKey>> {
    let mut out = BTreeMap::new();
    for source in sources {
        let client = match &source.op_account {
            Some(a) => RealOpClient::with_account(a.clone()),
            None => RealOpClient::new(),
        };
        let op_sources: Vec<OpSource> = source
            .members
            .iter()
            .filter_map(|m| OpSource::parse(m))
            .collect();
        let cache = OpKeyCache::load();
        match discover_keys(&client, &op_sources, cache) {
            Ok((keys, fresh_cache)) => {
                fresh_cache.save();
                println!(
                    "cache-warden: authsock source `{}`: discovered {} op key(s)",
                    source.name,
                    keys.len()
                );
                out.insert(source.name.clone(), keys);
            }
            Err(e) => {
                eprintln!(
                    "cache-warden: authsock source `{}`: op discovery failed ({e}); \
                     serving no keys from this source",
                    source.name
                );
                out.insert(source.name.clone(), Vec::new());
            }
        }
    }
    out
}

/// Register a source's discovered keys into `registry` as op-sourced keys.
///
/// Each discovered key becomes a [`KeySource::Op`] entry: the public key is
/// enumerable now (REQUEST_IDENTITIES), and the private PEM is fetched lazily at
/// first sign via `op item get` (the argv built by [`private_key_argv`]). The
/// core KV key is namespaced (`__authsock_op:<item_id>`) so it never collides
/// with a manual `[kv.*]` entry. A key whose public blob fails to parse is
/// logged and skipped. Returns how many keys were registered.
fn register_op_keys(
    socket_name: &str,
    exe: &str,
    source: &AuthsockSource,
    keys: &[DiscoveredKey],
    registry: &mut PublicKeyRegistry,
) -> usize {
    let mut n = 0;
    for key in keys {
        let kv_key = op_kv_key(&key.item_id);
        let argv = private_key_argv(exe, &key.item_id, source.op_account.as_deref());
        let src = KeySource::Op {
            argv,
            soft_ttl_secs: source.soft_ttl_secs,
            hard_ttl_secs: source.hard_ttl_secs,
        };
        match registry.register_op_key(&kv_key, &key.public_key, &key.title, src) {
            Ok(()) => n += 1,
            Err(e) => eprintln!(
                "cache-warden: authsock `{socket_name}`: op key `{}` is not a usable public \
                 key, skipping ({e})",
                key.title
            ),
        }
    }
    n
}

/// The core KV key name for an op-sourced key (namespaced to avoid `[kv.*]`
/// collisions). The item id is alphanumeric (validated at fetch time).
fn op_kv_key(item_id: &str) -> String {
    format!("__authsock_op:{item_id}")
}

/// Spawn one listener task per validated `[authsock.sockets.*]`.
///
/// Returns `(socket_path, JoinHandle)` pairs so the caller can await each task
/// on shutdown and remove its socket file. A socket whose registry ends up
/// empty (no key resolved) is still bound — it simply answers REQUEST_IDENTITIES
/// with an empty list until a key is set.
///
/// `sources` are the validated `[authsock.sources.*]`; their keys are discovered
/// once up front (see [`discover_all_sources`]) and registered into the registry
/// of every socket that references them via `source`.
pub fn spawn_listeners(
    sockets: &[AuthsockSocket],
    sources: &[AuthsockSource],
    github: GithubSettings,
    shared: Arc<Shared>,
    shutdown_rx: watch::Receiver<bool>,
) -> Vec<(PathBuf, JoinHandle<()>)> {
    // Discover every op source once (shared across sockets referencing it).
    let discovered = discover_all_sources(sources);
    let source_by_name: BTreeMap<&str, &AuthsockSource> =
        sources.iter().map(|s| (s.name.as_str(), s)).collect();

    // Resolve this binary's path once: op keys lazily re-execute it (the
    // `__authsock-op-private-key` subcommand) to fetch their PEM via op's JSON
    // output. If we cannot resolve it, op keys cannot be served — register none
    // (fail-closed) rather than building a broken argv.
    let exe = match std::env::current_exe() {
        Ok(p) => Some(p.to_string_lossy().into_owned()),
        Err(e) => {
            eprintln!(
                "cache-warden: authsock: cannot resolve own binary path ({e}); op-sourced keys \
                 will be unavailable for signing"
            );
            None
        }
    };

    // Collect every `github=<user>` matcher across all sockets so the refresh
    // task can populate (and periodically re-fetch) their published key sets.
    // Clones share each matcher's cache, so updates here reach the synchronous
    // `matches()` on the hot path.
    let mut github_matchers: Vec<GithubMatcher> = Vec::new();

    let mut handles = Vec::new();
    for socket in sockets {
        // Derive this socket's public-key registry up front (under the store
        // lock) from the configured keys' currently-cached PEMs, then add any
        // op-sourced keys from the source it references.
        let mut registry = {
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

        // Add op-sourced keys (lazily loaded at sign time; see [`KeySource::Op`]).
        // Skipped entirely when the binary path is unknown (fail-closed above).
        let mut op_key_count = 0;
        if let Some(exe) = &exe
            && let Some(source_name) = &socket.source
            && let (Some(source), Some(keys)) = (
                source_by_name.get(source_name.as_str()),
                discovered.get(source_name),
            )
        {
            op_key_count = register_op_keys(&socket.name, exe, source, keys, &mut registry);
        }

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

        // Build the key filter. The tokens were validated at config parse, so
        // this re-parse cannot fail; fall back to an unfiltered evaluator (and
        // warn) on the impossible error rather than aborting the socket.
        let filter = match FilterEvaluator::parse(&socket.filters) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "cache-warden: authsock `{}`: filter rebuild failed ({e}); serving unfiltered",
                    socket.name
                );
                FilterEvaluator::default()
            }
        };

        // Collect this socket's github matchers (clones share the cache the
        // socket's filter reads). The refresh task fetches their keys.
        github_matchers.extend(filter.github_matchers().into_iter().cloned());

        println!(
            "cache-warden: authsock `{}` listening on {} ({} key(s) incl. {} op, {} upstream(s), {} filter term(s))",
            socket.name,
            socket.path.display(),
            registry.len(),
            op_key_count,
            upstreams.len(),
            filter.len()
        );

        let state = Arc::new(SocketState {
            name: socket.name.clone(),
            registry,
            upstreams,
            filter,
            allowed_processes: socket.allowed_processes.clone(),
            shared: Arc::clone(&shared),
        });
        let path = socket.path.clone();
        let rx = shutdown_rx.clone();
        let handle = tokio::spawn(serve(listener, state, rx));
        handles.push((path, handle));
    }

    // Start the single github key-refresh task (no-op if no socket uses a github
    // filter). It does the initial fetch and the periodic re-fetch; until it
    // populates a matcher, that matcher is fail-closed (admits nothing).
    if !github_matchers.is_empty() {
        let task = tokio::spawn(spawn_github_refresh(
            github_matchers,
            github,
            Arc::new(RealGithubFetcher::new()),
            shutdown_rx,
        ));
        // The refresh task has no socket file; pair it with a throwaway path the
        // caller's cleanup ignores (remove_file on a non-path is best-effort).
        handles.push((PathBuf::new(), task));
    }
    handles
}

/// Settings for the github key-refresh task: how long a fetched set is reused
/// and how long one fetch may take.
#[derive(Debug, Clone, Copy)]
pub struct GithubSettings {
    /// Reuse window before a background re-fetch (`[authsock.github].cache_ttl`).
    pub cache_ttl: std::time::Duration,
    /// Per-fetch timeout (`[authsock.github].timeout`, curl `--max-time`).
    pub timeout: std::time::Duration,
}

/// The background github key-refresh task (one per daemon).
///
/// Does an initial fetch of every matcher's published key set, then re-fetches
/// any matcher whose cache is due (`needs_refresh`) on each `cache_ttl` tick,
/// until shutdown. Each fetch runs on the blocking pool (`curl` is blocking and
/// must never run on an async worker — the load-bearing constraint). A fetch
/// failure calls [`GithubMatcher::mark_failed`] (fail-closed) and logs a single
/// stderr line; the daemon keeps running.
///
/// Generic over [`GithubFetcher`] so tests drive it with a fake fetcher (no real
/// network / `curl` in CI).
async fn spawn_github_refresh<F>(
    matchers: Vec<GithubMatcher>,
    settings: GithubSettings,
    fetcher: Arc<F>,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    F: GithubFetcher + Send + Sync + 'static,
{
    // Initial fetch: every matcher needs_refresh (never fetched) right now.
    refresh_due_matchers(&matchers, &settings, &fetcher).await;

    let mut ticker = tokio::time::interval(settings.cache_ttl);
    // The first tick fires immediately; consume it (we just fetched above).
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                refresh_due_matchers(&matchers, &settings, &fetcher).await;
            }
        }
    }
}

/// Re-fetch every matcher whose cache is due, on the blocking pool.
///
/// `needs_refresh` is checked against the wall clock so a not-yet-stale matcher
/// is skipped (cheap when several sockets share a TTL). Duplicate users across
/// matchers are fetched independently (cache dedup is left as a future
/// optimisation, see the port plan).
async fn refresh_due_matchers<F>(
    matchers: &[GithubMatcher],
    settings: &GithubSettings,
    fetcher: &Arc<F>,
) where
    F: GithubFetcher + Send + Sync + 'static,
{
    let now = std::time::Instant::now();
    for matcher in matchers {
        if !matcher.needs_refresh(settings.cache_ttl, now) {
            continue;
        }
        let user = matcher.user().to_string();
        let timeout = settings.timeout;
        let fetcher = Arc::clone(fetcher);
        // `curl` is blocking: run it off the async worker pool.
        let result = tokio::task::spawn_blocking(move || fetcher.fetch_keys(&user, timeout)).await;
        match result {
            Ok(Ok(keys)) => matcher.set_keys(keys, std::time::Instant::now()),
            Ok(Err(e)) => {
                eprintln!(
                    "cache-warden: github filter: fetch failed for {} ({e}); serving no keys \
                     from it until the next refresh",
                    matcher.user()
                );
                matcher.mark_failed(std::time::Instant::now());
            }
            Err(e) => {
                eprintln!(
                    "cache-warden: github filter: refresh task panicked for {} ({e})",
                    matcher.user()
                );
                matcher.mark_failed(std::time::Instant::now());
            }
        }
    }
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

    // Connection-time process gate (port plan Iteration 5). A socket with a
    // non-empty `allowed_processes` admits a connection only when the peer's
    // ancestry chain names an allowed executable; otherwise *every* request on
    // this connection is answered with SSH_AGENT_FAILURE (enumeration and signing
    // alike — the client learns nothing about which keys exist). The peer pid is
    // fixed for a connection, so this is judged once here rather than per message.
    // An empty list short-circuits to "admitted" without resolving ancestry.
    let admitted = process_gate_passes(peer, &state.allowed_processes);

    let (mut read_half, mut write_half) = stream.into_split();
    let mut routes: UpstreamRoutes = HashMap::new();
    while let Some(msg) = AgentCodec::read(&mut read_half)
        .await
        .map_err(std::io::Error::other)?
    {
        let response = if admitted {
            respond(&state, peer, &msg, &mut routes).await
        } else {
            // Rejected connection: a uniform FAILURE for every message type.
            AgentMessage::failure()
        };
        AgentCodec::write(&mut write_half, &response)
            .await
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// Whether a connection from peer process `peer` is admitted by `allowed`.
///
/// - `allowed` empty → admitted unconditionally (no restriction; the ancestry is
///   never resolved, so an unattributable peer is still admitted — the existing
///   "no policy" behaviour is preserved exactly).
/// - `allowed` non-empty → resolve the peer's ancestry and admit only when
///   [`chain_allowed`] passes. **Fail-closed**: a missing peer pid or an ancestry
///   lookup failure denies the connection (we cannot identify who is asking, so a
///   restricted socket refuses).
///
/// Design rationale: cache-warden deliberately fails *closed* here where
/// authsock-warden failed *open* (it logged "could not determine client process,
/// allowing by default"). On a socket whose operator explicitly restricted the
/// callers, an unidentifiable peer is exactly the case to refuse — DR-0012.
fn process_gate_passes(peer: Option<u32>, allowed: &[String]) -> bool {
    // Resolve the peer's ancestry (only needed when a restriction is set), then
    // defer the admit/deny decision — including the fail-closed handling of an
    // unidentifiable peer — to the shared `chain_gate_passes` (DR-0012). An empty
    // list short-circuits inside the helper without resolving ancestry.
    let chain = if allowed.is_empty() {
        None
    } else {
        peer.and_then(|pid| SystemInspector::new().ancestry(pid).ok())
    };
    chain_gate_passes(chain.as_deref(), allowed)
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

/// REQUEST_IDENTITIES: local registry keys plus each upstream's keys, merged,
/// de-duplicated by blob (local wins), then **filtered** (port plan Iteration 3).
/// Only keys that pass this socket's filter are enumerated. Down upstreams are
/// skipped with a stderr warning. `routes` is rebuilt to map each surviving
/// (post-filter) upstream blob to its upstream index — so a blob the filter
/// hides is never routable for a later SIGN_REQUEST either.
async fn request_identities(
    state: &Arc<SocketState>,
    request: &AgentMessage,
    routes: &mut UpstreamRoutes,
) -> AgentMessage {
    // Local identities first so they win de-dup against any upstream copy. Apply
    // the filter on the full comment-bearing identity (the registry keeps it).
    let mut merged: Vec<Identity> = state
        .registry
        .identities()
        .into_iter()
        .filter(|id| state.filter.matches(id))
        .collect();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        merged.iter().map(|id| id.key_blob.to_vec()).collect();

    routes.clear();
    for (idx, upstream) in state.upstreams.iter().enumerate() {
        match upstream_identities(upstream, request).await {
            Ok(identities) => {
                for id in identities {
                    // Filter upstream keys too: a hidden key is neither shown nor
                    // routed (so a later SIGN for it falls through to FAILURE).
                    if !state.filter.matches(&id) {
                        continue;
                    }
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
    //    pool through the core auth gate. The filter is enforced inside the sign
    //    path (via `signable_kv_key`, using the registry's comment), so a key this
    //    socket hides yields FAILURE even though its PEM is reachable.
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
    //    `routes` only holds blobs that passed the filter during enumeration, so
    //    a hidden key is never routed here.
    if let Some(&idx) = routes.get(&key_blob)
        && let Some(upstream) = state.upstreams.get(idx)
        && let Some(resp) = forward_sign(upstream, msg).await
    {
        return resp;
    }

    // 4. Fallback: a client may sign without enumerating first (or our record is
    //    stale). Try every upstream in order until one signs (authsock-warden).
    //
    //    The filter still applies, but here we only know the *blob* (no comment).
    //    A comment-dependent filter cannot be judged without the comment, and
    //    judging it against an empty comment is unsafe: a `not-comment=secret*`
    //    rule would *admit* a hidden key (empty comment does not match `secret*`,
    //    so the negation passes). So if the filter needs a comment at all, fail
    //    closed — a key can only be signed after it was enumerated (where the
    //    real comment was available). This is the intended "no enumerate, no
    //    sign" behaviour for comment filters. A blob-only filter (fingerprint /
    //    type / pubkey / keyfile) is evaluated exactly.
    if !state.filter.is_blob_only()
        || !state
            .filter
            .matches(&Identity::new(fields.key_blob.clone(), String::new()))
    {
        return AgentMessage::failure();
    }
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
    let ctx = LocalSignCtx {
        registry: &state.registry,
        filter: &state.filter,
        store: &state.shared.store,
        auth: state.shared.auth.as_ref(),
        runner: &state.shared.runner,
        clock: &state.shared.clock,
        kv_process_policies: &state.shared.kv_process_policies,
    };
    sign_local_with_ctx(&ctx, requester.as_deref(), msg)
}

/// Resolve the registered key a SIGN_REQUEST may use, or `None` to reject it.
///
/// Returns `Some(&RegisteredKey)` only when the requested blob is registered
/// (local KV or op-sourced) **and** passes the socket filter (judged with the
/// registry's comment, so a comment filter holds on the direct-sign path — a key
/// the socket does not expose cannot be signed with). An unknown blob or a
/// filtered-out key yields `None`, which the caller maps to SSH_AGENT_FAILURE.
fn signable_key<'r>(
    registry: &'r PublicKeyRegistry,
    filter: &FilterEvaluator,
    key_blob: &[u8],
) -> Option<&'r RegisteredKey> {
    let registered = registry.lookup(key_blob)?;
    let identity = Identity::new(registered.key_blob.clone(), registered.comment.clone());
    filter.matches(&identity).then_some(registered)
}

/// The borrowed core services a local sign needs, grouped so the signing helper
/// keeps a small argument list (the alternative — passing five separate borrows
/// — trips `clippy::too_many_arguments`). Each field is a short-lived borrow of a
/// `Shared` member; nothing here owns a secret.
struct LocalSignCtx<'a, A: ?Sized, R, C> {
    /// The registered public keys (blob → KV key) this socket can sign with.
    registry: &'a PublicKeyRegistry,
    /// The socket's key filter (a hidden key is rejected even though reachable).
    filter: &'a FilterEvaluator,
    /// The core store holding the private-key PEMs.
    store: &'a std::sync::Mutex<Store>,
    /// The re-authentication gate (shared with the control socket).
    auth: &'a A,
    /// The command runner used to regenerate a hard-expired command source.
    runner: &'a R,
    /// The monotonic clock for TTL evaluation.
    clock: &'a C,
    /// Key-level process-access policies (DR-0012 key layer): KV key name → its
    /// non-empty `allowed_processes` list. The same table the control socket
    /// consults for `kv.get`. A SIGN_REQUEST resolving a restricted KV key is
    /// admitted only when the requester's ancestry passes the gate (fail-closed on
    /// an unknown requester); a key absent from the table is unrestricted. op-keys
    /// carry an internal `__authsock_op:*` KV name that never appears in `[kv.*]`
    /// config, so they are naturally unrestricted here.
    kv_process_policies: &'a std::collections::BTreeMap<String, Vec<String>>,
}

/// Pure local-sign dispatch for one SIGN_REQUEST against the core (no socket
/// I/O). The blob is assumed to be in `ctx.registry` (the async caller checked).
///
/// Factored out of the async server so the SIGN_REQUEST → core → signature path
/// is unit-testable without a runtime. Resolves the key blob to a signable KV key
/// via [`signable_kv_key`] (registry lookup **and** the socket filter), fetches
/// the PEM through the auth gate, signs, refreshes the idle window, returns
/// SIGN_RESPONSE. Any failure (unknown, filtered out, denied, hard-expired
/// static, sign error) is SSH_AGENT_FAILURE.
fn sign_local_with_ctx<A, R, C>(
    ctx: &LocalSignCtx<'_, A, R, C>,
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
    // Unknown key or filtered-out key: do not reveal which keys exist beyond
    // IDENTITIES. Clone the small bits we need so the registry borrow ends before
    // we take the store lock (the source carries the op fetch spec).
    let Some(registered) = signable_key(ctx.registry, ctx.filter, &fields.key_blob) else {
        return AgentMessage::failure();
    };
    let kv_key = registered.kv_key.clone();
    let source = registered.source.clone();

    // Key-level process-access gate (DR-0012 key layer). When this KV key carries
    // an `allowed_processes` restriction, the requester's ancestry must pass the
    // shared gate (fail-closed on an unknown requester) before the PEM is fetched
    // or signed with. A restricted key the requester is not permitted to use is
    // refused with a plain SSH_AGENT_FAILURE — the same "leak nothing" response as
    // an unknown or filtered-out key (the connection already enumerated this key,
    // mirroring the socket layer's per-key warden behaviour: the key may be listed
    // but cannot be signed with). An op-key's internal `__authsock_op:*` name never
    // appears in `[kv.*]` config, so it is unrestricted here.
    if let Some(allowed) = ctx.kv_process_policies.get(&kv_key)
        && !chain_gate_passes(requester, allowed)
    {
        return AgentMessage::failure();
    }
    let (auth, runner, clock) = (ctx.auth, ctx.runner, ctx.clock);

    let mut store = match ctx.store.lock() {
        Ok(g) => g,
        Err(_) => return AgentMessage::failure(),
    };

    // Fetch the PEM through the same auth gate as the control socket. For an
    // op-sourced key the core entry may not exist yet (lazy NotLoaded): the
    // first sign fetches it via `op item get`, authenticates, and `set`s it.
    if !ensure_loaded(&mut store, &kv_key, &source, auth, runner, requester, clock) {
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
/// `source` describes how the private value reaches the core:
///
/// - [`KeySource::Local`]: the entry exists from startup. An absent entry is a
///   failure (its PEM was never loaded); otherwise the Iteration 1 gate applies
///   (Active passes, SoftExpired extends, HardExpired regenerates if regenerable).
/// - [`KeySource::Op`]: the entry is created **lazily**. If the core has no entry
///   yet (the NotLoaded case), the source command (`op item get`) is run to fetch
///   the PEM, the user re-authenticates, and the value is `set` as a command
///   source with the source's TTLs — then it is Active. Once it exists, the same
///   Iteration 1 gate applies (idle extend within soft, regenerate via the same
///   command after hard).
///
/// Returns `true` if the value is now Active, `false` on any failure (denied,
/// hard-expired static, fetch error) — the caller maps that to SSH_AGENT_FAILURE.
#[allow(clippy::too_many_arguments)]
fn ensure_loaded<A, R, C>(
    store: &mut Store,
    key: &str,
    source: &KeySource,
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
        // Absent. For an op key this is the lazy NotLoaded path: fetch + auth +
        // set. A local key has no value to load, so it stays a failure.
        None => match source {
            KeySource::Local => false,
            KeySource::Op {
                argv,
                soft_ttl_secs,
                hard_ttl_secs,
            } => lazy_load_op_key(
                store,
                key,
                argv,
                *soft_ttl_secs,
                *hard_ttl_secs,
                auth,
                runner,
                requester,
                clock,
            ),
        },
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

/// First-sign load of an op key: run the fetch command, re-authenticate, and
/// `set` the value into the core as a command source (port plan §1.3 / §1.4).
///
/// The command (`op item get ... --reveal`) runs **before** the auth prompt so an
/// upstream failure (op not signed in) surfaces without wasting a TouchID — the
/// same order the core's `regenerate` uses. The fetched `SecretBytes` is dropped
/// (zeroized) if auth is denied, leaving no entry behind. On success the value is
/// `set` with the source's TTLs and is immediately Active.
#[allow(clippy::too_many_arguments)]
fn lazy_load_op_key<A, R, C>(
    store: &mut Store,
    key: &str,
    argv: &[String],
    soft_ttl_secs: Option<u64>,
    hard_ttl_secs: Option<u64>,
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
    let ttl = match Ttl::new(
        soft_ttl_secs.map(std::time::Duration::from_secs),
        hard_ttl_secs.map(std::time::Duration::from_secs),
    ) {
        Ok(t) => t,
        Err(_) => return false,
    };
    // Fetch the PEM first (before bothering the user for biometrics). This op
    // fetch needs no cwd / env overlay (DR-0018: the authsock op path is internal).
    let value = match runner.run(argv, None, &std::collections::BTreeMap::new()) {
        Ok(v) => v,
        // The RunError Display is secret-free; we drop it silently (FAILURE).
        Err(_) => return false,
    };
    // Re-authenticate. `value` is dropped (zeroized) on denial. The op
    // first-load is the regenerate-equivalent of an absent value, so it uses the
    // Regenerate auth operation (the same context the later hard-expiry
    // regenerate of this key uses).
    let ctx = match requester {
        Some(chain) => AuthContext::regenerate(key).with_requester(chain.to_vec()),
        None => AuthContext::regenerate(key),
    };
    if auth.authenticate(&ctx).is_err() {
        return false;
    }
    store.set(key, ValueSource::command(argv.to_vec()), value, ttl, clock);
    true
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
    /// A second real Ed25519 public key, distinct from `ED25519_PUB`, used as an
    /// upstream key whose blob is a *parseable* SSH key (so blob-derived filters
    /// like `type=ed25519` evaluate it). FOR TESTS ONLY.
    const ED25519_PUB_2: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbyz9iB+TRYs24UYiJkxLijlyJM2nU0INtBiiWHN4tY";

    const SOFT: u64 = 10;
    const HARD: u64 = 30;

    /// An empty evaluator: matches every key (the "no filtering" baseline used by
    /// the Iteration 1/2 tests, whose behaviour must be unchanged).
    fn no_filter() -> FilterEvaluator {
        FilterEvaluator::default()
    }

    /// Test shim for the local-sign path: groups the borrows into a
    /// [`LocalSignCtx`] and calls [`sign_local_with_ctx`]. Kept with the original
    /// flat argument list so the existing tests read unchanged.
    #[allow(clippy::too_many_arguments)]
    fn handle_local_sign<A, R, C>(
        registry: &PublicKeyRegistry,
        filter: &FilterEvaluator,
        store: &Mutex<Store>,
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
        let no_policies = std::collections::BTreeMap::new();
        let ctx = LocalSignCtx {
            registry,
            filter,
            store,
            auth,
            runner,
            clock,
            kv_process_policies: &no_policies,
        };
        sign_local_with_ctx(&ctx, requester, msg)
    }

    /// Like [`handle_local_sign`] but with a key-level process-access policy table
    /// (DR-0012 key layer), for exercising the SIGN_REQUEST gate.
    #[allow(clippy::too_many_arguments)]
    fn handle_local_sign_gated<A, R, C>(
        registry: &PublicKeyRegistry,
        filter: &FilterEvaluator,
        store: &Mutex<Store>,
        auth: &A,
        runner: &R,
        clock: &C,
        requester: Option<&[ProcessInfo]>,
        policies: &std::collections::BTreeMap<String, Vec<String>>,
        msg: &AgentMessage,
    ) -> AgentMessage
    where
        A: Authenticator + ?Sized,
        R: SourceRunner,
        C: Clock,
    {
        let ctx = LocalSignCtx {
            registry,
            filter,
            store,
            auth,
            runner,
            clock,
            kv_process_policies: policies,
        };
        sign_local_with_ctx(&ctx, requester, msg)
    }

    /// A resolved `ProcessInfo` (basename present) for fake requester chains.
    fn proc(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(1),
            path: Some(std::path::PathBuf::from(format!("/usr/bin/{name}"))),
            start_time: Some(Duration::from_secs(pid as u64)),
        }
    }

    fn key_policies(
        entries: &[(&str, &[&str])],
    ) -> std::collections::BTreeMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    struct NoRunner;
    impl SourceRunner for NoRunner {
        fn run(
            &self,
            _argv: &[String],
            _cwd: Option<&std::path::Path>,
            _env: &std::collections::BTreeMap<String, String>,
        ) -> Result<SecretBytes, RunError> {
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
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
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
    fn sign_request_restricted_key_admits_matching_requester() {
        // GITHUB_KEY restricted to `ssh`; a requester whose ancestry includes ssh
        // is admitted and the signature verifies.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let pol = key_policies(&[("GITHUB_KEY", &["ssh"])]);
        let chain = [proc(100, "ssh"), proc(50, "zsh")];
        let data = b"agent challenge";
        let req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp = handle_local_sign_gated(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            Some(&chain),
            &pol,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_restricted_key_denies_non_matching_requester() {
        // A requester whose ancestry has no allowed basename is refused with a
        // bare FAILURE (leak nothing) — even though the key is registered/listed.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let pol = key_policies(&[("GITHUB_KEY", &["ssh"])]);
        let chain = [proc(100, "git"), proc(50, "zsh")];
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_gated(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            Some(&chain),
            &pol,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn sign_request_restricted_key_with_unknown_requester_is_fail_closed() {
        // requester == None + a real restriction => fail-closed (FAILURE).
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let pol = key_policies(&[("GITHUB_KEY", &["ssh"])]);
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_gated(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &pol,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn sign_request_unrestricted_key_admits_even_unknown_requester() {
        // GITHUB_KEY has no policy entry => unrestricted; a None requester signs.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let pol = key_policies(&[("OTHER", &["ssh"])]);
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_gated(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &pol,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_for_unknown_key_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let req = sign_request(b"bogus-blob", b"data", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
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
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &DenyAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn sign_request_soft_expired_extends_then_signs_with_allow_all() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(SOFT + 1)); // soft-expired
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_hard_expired_static_key_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        clock.advance(Duration::from_secs(HARD)); // hard-expired, static => destroyed
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
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
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &DenyAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
        // Active sign with DenyAll still succeeds (no prompt while Active) and
        // extends the window.
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        // Advance past the *original* soft deadline but within the refreshed one.
        clock.advance(Duration::from_secs(2));
        let req2 = sign_request(&blob_of(ED25519_PUB), b"d2", 0);
        let resp2 = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &DenyAll,
            &NoRunner,
            &clock,
            None,
            &req2,
        );
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
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    // ---- Iteration 4: op-sourced keys (lazy load + core KV wiring) ----

    /// A runner that returns the Ed25519 PEM (the op item get fetch), counting
    /// runs so tests can assert the value is fetched at most once until hard
    /// expiry. Ignores argv (the real argv is `op item get ...`).
    struct PemRunner {
        runs: std::cell::Cell<usize>,
    }
    impl PemRunner {
        fn new() -> Self {
            Self {
                runs: std::cell::Cell::new(0),
            }
        }
        fn runs(&self) -> usize {
            self.runs.get()
        }
    }
    impl SourceRunner for PemRunner {
        fn run(
            &self,
            _argv: &[String],
            _cwd: Option<&std::path::Path>,
            _env: &std::collections::BTreeMap<String, String>,
        ) -> Result<SecretBytes, RunError> {
            self.runs.set(self.runs.get() + 1);
            Ok(SecretBytes::from(ED25519_PEM))
        }
    }

    /// A registry holding one op-sourced key (no core entry yet — lazy) plus an
    /// empty store. The op key's KV name is namespaced like the production path.
    fn op_fixture(soft: u64, hard: u64) -> (Mutex<Store>, PublicKeyRegistry) {
        let mut registry = PublicKeyRegistry::new();
        let argv = private_key_argv("/path/cache-warden", "itemABC", Some("kawaz.1password.com"));
        registry
            .register_op_key(
                op_kv_key("itemABC"),
                ED25519_PUB,
                "kawaz op key",
                KeySource::Op {
                    argv,
                    soft_ttl_secs: Some(soft),
                    hard_ttl_secs: Some(hard),
                },
            )
            .unwrap();
        // The core starts empty: the op key's value is loaded lazily on first sign.
        (Mutex::new(Store::new()), registry)
    }

    #[test]
    fn op_key_first_sign_lazily_loads_fetches_and_signs() {
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        let runner = PemRunner::new();
        let data = b"agent challenge for op key";
        let req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &runner,
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        assert_eq!(runner.runs(), 1, "first sign fetches the PEM once");

        // The signature verifies against the public key.
        let mut buf = &resp.payload[..];
        use bytes::Buf;
        let len = buf.get_u32() as usize;
        let sig = ssh_key::Signature::try_from(&buf[..len]).unwrap();
        let pk = ssh_key::PublicKey::from_openssh(ED25519_PUB).unwrap();
        <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(&pk, data, &sig)
            .unwrap();

        // The core now holds the op key's value (lazy load created it).
        let key = op_kv_key("itemABC");
        assert!(store.lock().unwrap().get(&key, &clock).is_some());
    }

    #[test]
    fn op_key_second_sign_within_soft_hits_cache_no_refetch() {
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        let runner = PemRunner::new();
        let req = sign_request(&blob_of(ED25519_PUB), b"d1", 0);
        let r1 = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &runner,
            &clock,
            None,
            &req,
        );
        assert_eq!(r1.msg_type, MessageType::SignResponse);
        // Advance within the soft window; the cached value signs without re-fetch.
        clock.advance(Duration::from_secs(SOFT - 2));
        let req2 = sign_request(&blob_of(ED25519_PUB), b"d2", 0);
        let r2 = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &DenyAll,
            &runner,
            &clock,
            None,
            &req2,
        );
        assert_eq!(
            r2.msg_type,
            MessageType::SignResponse,
            "cached op key signs within soft window without re-auth"
        );
        assert_eq!(runner.runs(), 1, "no second op item get within soft window");
    }

    #[test]
    fn op_key_after_hard_expiry_regenerates_via_same_command() {
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        let runner = PemRunner::new();
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let _ = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &runner,
            &clock,
            None,
            &req,
        );
        assert_eq!(runner.runs(), 1);
        // Past the hard window: the value is destroyed; the next sign regenerates
        // it by re-running the same op item get command (a second fetch).
        clock.advance(Duration::from_secs(HARD + 1));
        let req2 = sign_request(&blob_of(ED25519_PUB), b"d2", 0);
        let r2 = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &runner,
            &clock,
            None,
            &req2,
        );
        assert_eq!(r2.msg_type, MessageType::SignResponse);
        assert_eq!(runner.runs(), 2, "hard-expired op key re-fetches");
    }

    #[test]
    fn op_key_first_sign_denied_auth_loads_nothing_and_fails() {
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        let runner = PemRunner::new();
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &DenyAll,
            &runner,
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
        // The fetch ran (before auth), but the denied value was discarded — no
        // core entry was created.
        assert_eq!(runner.runs(), 1);
        let key = op_kv_key("itemABC");
        assert!(store.lock().unwrap().get(&key, &clock).is_none());
    }

    #[test]
    fn op_key_fetch_failure_skips_auth_and_fails() {
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        // NoRunner always fails the fetch (op not signed in / network down).
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        let key = op_kv_key("itemABC");
        assert!(store.lock().unwrap().get(&key, &clock).is_none());
    }

    #[test]
    fn op_key_unknown_blob_is_failure() {
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        let req = sign_request(b"not-a-registered-blob", b"d", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &PemRunner::new(),
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn op_key_filtered_out_is_failure() {
        // A comment filter that hides the op key denies its direct SIGN_REQUEST.
        let clock = FakeClock::new();
        let (store, registry) = op_fixture(SOFT, HARD);
        let filter = parse_filter(&["comment=nope*"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry,
            &filter,
            &store,
            &AllowAll,
            &PemRunner::new(),
            &clock,
            None,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn op_key_enumerates_with_comment_from_title() {
        // The op key shows in REQUEST_IDENTITIES with the item title as its comment.
        let (_store, registry) = op_fixture(SOFT, HARD);
        let ids = registry.identities();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].key_blob.as_ref(), blob_of(ED25519_PUB).as_slice());
        assert_eq!(ids[0].comment, "kawaz op key");
    }

    // ---- register_op_keys (discovery → registry wiring) ----

    #[test]
    fn register_op_keys_namespaces_and_threads_account_and_ttls() {
        let source = AuthsockSource {
            name: "default".into(),
            op_account: Some("kawaz.1password.com".into()),
            members: vec!["op://".into()],
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
        };
        let keys = vec![DiscoveredKey {
            item_id: "itemABC".into(),
            public_key: ED25519_PUB.into(),
            title: "kawaz key".into(),
            fingerprint: "SHA256:x".into(),
            vault: "Private".into(),
        }];
        let mut registry = PublicKeyRegistry::new();
        let n = register_op_keys("sock", "/path/cache-warden", &source, &keys, &mut registry);
        assert_eq!(n, 1);
        let reg = registry.lookup(&blob_of(ED25519_PUB)).unwrap();
        assert_eq!(reg.kv_key, "__authsock_op:itemABC");
        assert_eq!(reg.comment, "kawaz key");
        match &reg.source {
            KeySource::Op {
                argv,
                soft_ttl_secs,
                hard_ttl_secs,
            } => {
                assert_eq!(*soft_ttl_secs, Some(3600));
                assert_eq!(*hard_ttl_secs, Some(86400));
                // The argv re-executes this binary's hidden private-key
                // subcommand (not `op` directly), threading the item id and
                // account through.
                assert_eq!(argv[0], "/path/cache-warden");
                assert!(argv.contains(&"__authsock-op-private-key".to_string()));
                assert!(argv.contains(&"--account".to_string()));
                assert!(argv.contains(&"kawaz.1password.com".to_string()));
                assert!(argv.contains(&"itemABC".to_string()));
            }
            other => panic!("expected Op source, got {other:?}"),
        }
    }

    #[test]
    fn register_op_keys_skips_unparseable_public_key() {
        let source = AuthsockSource {
            name: "default".into(),
            op_account: None,
            members: vec!["op://".into()],
            soft_ttl_secs: None,
            hard_ttl_secs: None,
        };
        let keys = vec![
            DiscoveredKey {
                item_id: "good".into(),
                public_key: ED25519_PUB.into(),
                title: "good".into(),
                fingerprint: "SHA256:a".into(),
                vault: "v".into(),
            },
            DiscoveredKey {
                item_id: "bad".into(),
                public_key: "not a key".into(),
                title: "bad".into(),
                fingerprint: "SHA256:b".into(),
                vault: "v".into(),
            },
        ];
        let mut registry = PublicKeyRegistry::new();
        let n = register_op_keys("sock", "/path/cache-warden", &source, &keys, &mut registry);
        assert_eq!(n, 1, "the unparseable key is skipped");
    }

    // ---- Iteration 2: upstream merge / routing (async, against a fake agent) ----

    use cache_warden::SystemClock;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// A short, unique socket path under `/tmp` (under the sockaddr_un limit).
    fn short_sock(tag: &str) -> PathBuf {
        // A process-wide atomic counter guarantees uniqueness across parallel
        // tests; a wall-clock timestamp alone can collide when two threads sample
        // the same nanosecond (which surfaced once the suite created enough fake
        // upstream sockets concurrently).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(format!(
            "/tmp/cw-as-{tag}-{}-{seq}.sock",
            std::process::id()
        ))
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
    /// upstream paths (no filter).
    fn socket_state(upstream_paths: &[&Path]) -> Arc<SocketState> {
        socket_state_filtered(upstream_paths, no_filter())
    }

    /// Like [`socket_state`] but with an explicit filter (Iteration 3).
    fn socket_state_filtered(
        upstream_paths: &[&Path],
        filter: FilterEvaluator,
    ) -> Arc<SocketState> {
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
            filter,
            // The unit tests here exercise the per-message respond/sign paths; the
            // process gate (allowed_processes) is judged once at connect time and
            // covered separately by the process_gate_passes tests, so it is
            // unrestricted in this fixture.
            allowed_processes: Vec::new(),
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

    // ---- Iteration 3: per-socket key filters ----
    //
    // The local key registers under the PKCS#8 PEM with no comment, so its
    // registry comment falls back to the kv key name "GITHUB_KEY". The filters
    // below exercise both comment-based (enumeration-bound) and blob-based
    // (type) matching.

    fn parse_filter(tokens: &[&str]) -> FilterEvaluator {
        let groups: Vec<Vec<String>> = tokens.iter().map(|t| vec![t.to_string()]).collect();
        FilterEvaluator::parse(&groups).unwrap()
    }

    #[test]
    fn handle_local_sign_with_matching_filter_signs() {
        // A filter that admits the local key (by its fallback comment) signs.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let filter = parse_filter(&["comment=GITHUB_KEY"]);
        let data = b"filtered-but-allowed";
        let req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn handle_local_sign_with_excluding_filter_is_failure() {
        // A filter that hides the local key rejects a direct SIGN_REQUEST even
        // though the PEM is reachable (no enumeration needed to deny).
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let filter = parse_filter(&["comment=other-key*"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn handle_local_sign_blob_filter_admits_ed25519() {
        // A type=ed25519 filter (blob-derived) admits the Ed25519 local key.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let filter = parse_filter(&["type=ed25519"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn handle_local_sign_blob_filter_excludes_other_type() {
        // A type=rsa filter hides the Ed25519 local key.
        let clock = FakeClock::new();
        let (store, registry) = fixture(&clock);
        let filter = parse_filter(&["type=rsa"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[tokio::test]
    async fn identities_filter_hides_non_matching_local_key() {
        // A filter that excludes the local key yields an empty IDENTITIES_ANSWER.
        let state = socket_state_filtered(&[], parse_filter(&["comment=nope*"]));
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        assert!(ids.is_empty(), "filtered-out local key must not enumerate");
    }

    #[tokio::test]
    async fn identities_filter_keeps_matching_local_key() {
        let state = socket_state_filtered(&[], parse_filter(&["comment=GITHUB_KEY"]));
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].key_blob.as_ref(), blob_of(ED25519_PUB).as_slice());
    }

    #[tokio::test]
    async fn filtered_out_local_key_sign_is_failure_via_respond() {
        // The full async path: a hidden local key's SIGN_REQUEST is FAILURE.
        let state = socket_state_filtered(&[], parse_filter(&["comment=nope*"]));
        let mut routes = UpstreamRoutes::new();
        let sign_req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[tokio::test]
    async fn filter_hides_upstream_key_from_enumeration_and_routing() {
        // An upstream advertises a key whose comment the filter excludes: it must
        // not appear in IDENTITIES and must not be routed (so a later SIGN for it
        // is not forwarded). The local key (which the filter admits) still shows.
        let up_id = upstream_identity("secret-upstream");
        let upstream_sig = AgentMessage::sign_response(b"SHOULD-NOT-REACH");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], Some(upstream_sig));
        // Filter admits only the local key (by its fallback comment), not the
        // upstream's "secret-upstream" comment.
        let state = socket_state_filtered(&[&path], parse_filter(&["comment=GITHUB_KEY"]));
        let mut routes = UpstreamRoutes::new();

        let enum_req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &enum_req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        // Only the local key enumerates; the upstream key is filtered out.
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].key_blob.as_ref(), blob_of(ED25519_PUB).as_slice());
        assert!(
            !routes.contains_key(&up_id.key_blob.to_vec()),
            "a filtered-out upstream key must not be routable"
        );

        // A SIGN for the hidden upstream blob is not forwarded -> FAILURE
        // (comment-only filter, no route, fallback also denies by empty comment).
        let sign_req = sign_request(&up_id.key_blob, b"x", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::Failure);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn negated_comment_filter_cannot_be_bypassed_by_signing_without_enumerating() {
        // Regression: a `not-comment=secret*` filter hides keys whose comment
        // starts with "secret". A client that signs an upstream key's blob
        // WITHOUT enumerating first (routes stays empty) must still be denied.
        // The old fallback judged the filter against an empty comment, and
        // `not-comment=secret*` *passes* an empty comment — wrongly admitting the
        // hidden key. The fix fails closed whenever the filter needs a comment.
        let up_id = upstream_identity("secret-upstream");
        let upstream_sig = AgentMessage::sign_response(b"SHOULD-NOT-REACH");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], Some(upstream_sig));
        let state = socket_state_filtered(&[&path], parse_filter(&["not-comment=secret*"]));
        let mut routes = UpstreamRoutes::new();

        // No enumeration: sign the hidden blob directly.
        let sign_req = sign_request(&up_id.key_blob, b"x", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(
            resp.msg_type,
            MessageType::Failure,
            "a comment-filtered socket must not sign an un-enumerated upstream key"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn blob_only_filter_still_signs_upstream_without_enumerating() {
        // The fail-closed rule must not over-restrict: a blob-only filter
        // (here `type=ed25519`) can be judged from the blob alone, so signing an
        // admitted upstream key without a prior enumeration still works. The
        // upstream key must be a parseable SSH blob for the type filter to read
        // it, so we use a second real key (not the synthetic `upstream_identity`).
        let up_blob = bytes::Bytes::from(blob_of(ED25519_PUB_2));
        let up_id = Identity::new(up_blob.clone(), "anything".to_string());
        let upstream_sig = AgentMessage::sign_response(b"FORWARDED-OK");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], Some(upstream_sig));
        let state = socket_state_filtered(&[&path], parse_filter(&["type=ed25519"]));
        let mut routes = UpstreamRoutes::new();

        let sign_req = sign_request(&up_id.key_blob, b"x", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn filter_admits_upstream_key_when_comment_matches() {
        // Sanity: when the filter admits the upstream comment, the upstream key
        // enumerates and a SIGN for it is forwarded.
        let up_id = upstream_identity("work-upstream");
        let upstream_sig = AgentMessage::sign_response(b"FORWARDED-OK");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], Some(upstream_sig.clone()));
        let state = socket_state_filtered(&[&path], parse_filter(&["comment=*upstream*"]));
        let mut routes = UpstreamRoutes::new();

        let enum_req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, &enum_req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        // The local key's comment "GITHUB_KEY" does not match *upstream*, so only
        // the upstream key passes.
        let blobs: Vec<_> = ids.iter().map(|i| i.key_blob.to_vec()).collect();
        assert!(blobs.contains(&up_id.key_blob.to_vec()));
        assert!(!blobs.contains(&blob_of(ED25519_PUB)));

        let sign_req = sign_request(&up_id.key_blob, b"x", 0);
        let resp = respond(&state, None, &sign_req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        assert_eq!(resp.payload, upstream_sig.payload);
        std::fs::remove_file(&path).ok();
    }

    // ---- github filter refresh task (fake fetcher; no real network) ----

    /// A fake [`GithubFetcher`] returning canned key bodies per user, or an error
    /// for users registered as failing. No `curl`, no network — CI-safe.
    struct FakeGithubFetcher {
        bodies: std::collections::HashMap<String, String>,
        failing: std::collections::HashSet<String>,
    }

    impl FakeGithubFetcher {
        fn new() -> Self {
            Self {
                bodies: std::collections::HashMap::new(),
                failing: std::collections::HashSet::new(),
            }
        }
        fn with_body(mut self, user: &str, body: &str) -> Self {
            self.bodies.insert(user.to_string(), body.to_string());
            self
        }
        fn failing_for(mut self, user: &str) -> Self {
            self.failing.insert(user.to_string());
            self
        }
    }

    impl GithubFetcher for FakeGithubFetcher {
        fn fetch_keys(
            &self,
            user: &str,
            _timeout: Duration,
        ) -> cache_warden_authsock::Result<std::collections::HashSet<Vec<u8>>> {
            if self.failing.contains(user) {
                return Err(cache_warden_authsock::Error::Filter(format!(
                    "fake fetch failure for {user}"
                )));
            }
            let body = self.bodies.get(user).cloned().unwrap_or_default();
            Ok(cache_warden_authsock::parse_keys(&body, user))
        }
    }

    fn github_settings() -> GithubSettings {
        GithubSettings {
            cache_ttl: Duration::from_secs(3600),
            timeout: Duration::from_secs(10),
        }
    }

    fn github_identity(openssh: &str) -> Identity {
        Identity::new(bytes::Bytes::from(blob_of(openssh)), String::new())
    }

    #[tokio::test]
    async fn github_refresh_populates_matcher_so_it_admits_published_key() {
        let matcher = GithubMatcher::new("kawaz");
        // Before any fetch the matcher is fail-closed.
        assert!(!matcher.matches(&github_identity(ED25519_PUB)));

        let fetcher =
            Arc::new(FakeGithubFetcher::new().with_body("kawaz", &format!("{ED25519_PUB}\n")));
        refresh_due_matchers(&[matcher.clone()], &github_settings(), &fetcher).await;

        // Now the published key is admitted, an unpublished one is not.
        assert!(matcher.matches(&github_identity(ED25519_PUB)));
        assert!(!matcher.matches(&github_identity(ED25519_PUB_2)));
    }

    #[tokio::test]
    async fn github_refresh_failure_is_fail_closed() {
        let matcher = GithubMatcher::new("kawaz");
        let fetcher = Arc::new(FakeGithubFetcher::new().failing_for("kawaz"));
        refresh_due_matchers(&[matcher.clone()], &github_settings(), &fetcher).await;
        // A failed fetch must not admit anything.
        assert!(!matcher.matches(&github_identity(ED25519_PUB)));
    }

    #[tokio::test]
    async fn github_refresh_skips_matchers_not_yet_due() {
        // A matcher freshly fetched (valid, within TTL) is not re-fetched even if
        // the fetcher would now return a different (empty) set.
        let matcher = GithubMatcher::new("kawaz");
        let mut keys = std::collections::HashSet::new();
        keys.insert(blob_of(ED25519_PUB));
        matcher.set_keys(keys, std::time::Instant::now());

        // Fetcher returns empty for kawaz now; but the matcher isn't due, so the
        // previously-admitted key stays admitted.
        let fetcher = Arc::new(FakeGithubFetcher::new());
        refresh_due_matchers(&[matcher.clone()], &github_settings(), &fetcher).await;
        assert!(matcher.matches(&github_identity(ED25519_PUB)));
    }

    #[tokio::test]
    async fn github_refresh_task_does_initial_fetch_then_exits_on_shutdown() {
        let matcher = GithubMatcher::new("kawaz");
        let fetcher =
            Arc::new(FakeGithubFetcher::new().with_body("kawaz", &format!("{ED25519_PUB}\n")));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(spawn_github_refresh(
            vec![matcher.clone()],
            github_settings(),
            fetcher,
            rx,
        ));
        // The initial fetch runs on the blocking pool, so its completion is not
        // bounded by a fixed number of yields — on a slow CI the cache write can
        // lag behind. Poll with a generous timeout instead of a fixed sleep /
        // yield count (otherwise this is a timing-dependent flake: green locally,
        // red on a slow runner).
        let m = matcher.clone();
        poll_until(Duration::from_secs(2), move || {
            m.matches(&github_identity(ED25519_PUB))
        })
        .await;
        assert!(
            matcher.matches(&github_identity(ED25519_PUB)),
            "refresh task should have populated the matcher within the timeout"
        );
        // Shutdown stops the task cleanly.
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    // ---- process gate (port plan Iteration 5) ----

    #[test]
    fn process_gate_empty_list_admits_even_unknown_peer() {
        // No restriction: a peer with no resolvable pid is still admitted (the
        // pre-Iteration-5 "no policy" behaviour is unchanged).
        assert!(process_gate_passes(None, &[]));
        assert!(process_gate_passes(Some(std::process::id()), &[]));
    }

    #[test]
    fn process_gate_nonempty_list_denies_unknown_peer_fail_closed() {
        // A restriction is set but the peer pid is unknown: fail-closed.
        assert!(!process_gate_passes(None, &["anything".to_string()]));
    }

    #[test]
    fn process_gate_nonempty_list_denies_absent_pid_fail_closed() {
        // A restricted socket with a definitely-absent pid (ancestry lookup fails)
        // is denied — cannot identify the caller, so refuse.
        let mut absent = 4_000_000u32;
        while SystemInspector::new().inspect(absent).is_ok() {
            absent += 1;
        }
        assert!(!process_gate_passes(
            Some(absent),
            &["anything".to_string()]
        ));
    }

    #[test]
    fn process_gate_admits_when_a_real_ancestor_name_is_allowed() {
        // Resolve our own ancestry, take a genuinely-present executable basename,
        // and assert the gate admits a list containing it (no fakery: the chain is
        // this live test process).
        let me = std::process::id();
        let chain = SystemInspector::new()
            .ancestry(me)
            .expect("self ancestry resolves");
        let a_real_name = chain
            .iter()
            .find_map(|p| p.name().map(str::to_string))
            .expect("at least one process in our ancestry has a resolvable name");
        assert!(process_gate_passes(Some(me), &[a_real_name]));
    }

    #[test]
    fn process_gate_denies_when_no_ancestor_name_matches() {
        // A name that cannot be any real executable basename: the live ancestry
        // chain has nothing matching it, so a restricted socket refuses.
        let bogus = "cw-no-such-process-name-iteration5".to_string();
        assert!(!process_gate_passes(Some(std::process::id()), &[bogus]));
    }

    /// Poll `cond` every 10ms until it returns `true` or `timeout` elapses.
    ///
    /// Replaces fixed sleeps / bounded `yield_now` loops in tests that wait on a
    /// background task (e.g. the github refresh task's blocking-pool fetch) so they
    /// do not flake on a slow CI runner: the work-completion observation point is
    /// polled with real time budget rather than assumed to land within N yields.
    /// On timeout the caller's subsequent assertion fails with a clear message.
    async fn poll_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
