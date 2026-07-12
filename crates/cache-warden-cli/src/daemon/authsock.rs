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
//! `with_exposed` just long enough to sign, and — on success — calls `extend`
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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use cache_warden::{
    Authenticator, Clock, DefineError, EntryState, ProcessInfo, ProcessInspector,
    RegenerateDefOutcome, RegenerateOutcome, SourceRunner, Store, SystemInspector, Ttl,
    ValueSource,
};
use cache_warden_authsock::{
    AgentCodec, AgentMessage, DiscoveredKey, DiscoveryOutcome, FilterEvaluator, GithubFetcher,
    GithubMatcher, Identity, KeySource, MessageType, OpKeyCache, OpSource, PublicKeyRegistry,
    RealGithubFetcher, RealOpClient, RegisteredKey, SignRequestFields, Upstream, chain_gate_passes,
    discover_keys, merge_source_cache, private_key_argv, seed_from_cache, sign,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::guard::{self as guard_eval, GetterAuditToken, GetterProcess};
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
///
/// # DR-0030 startup preload is not a guarded delegation
///
/// A DR-0030 `access_guard` restricts *who may act as the getter of the
/// private key*, and this preload has no getter: it only derives the
/// **public** identity for enumeration (`REQUEST_IDENTITIES`), which is
/// public information the socket would advertise regardless. The private
/// PEM is read only long enough to derive the public blob and is dropped
/// before the function returns; no peer is being delegated authority over
/// the key here. The guard evaluator therefore runs on the SIGN_REQUEST
/// path (see [`sign_with_resolved_key`]), where a real peer *is* asking to
/// use the private half.
fn build_registry(
    socket_name: &str,
    keys: &[String],
    store: &mut Store,
    cap: &cache_warden::Capability,
    clock: &impl Clock,
) -> PublicKeyRegistry {
    let mut registry = PublicKeyRegistry::new();
    for kv_key in keys {
        match store.get(kv_key, cap, clock).ok().flatten() {
            Some(secret) => {
                // The PEM is borrowed only for derivation (scoped by `with_exposed`,
                // DR-0028); the registry keeps the public blob, never the secret.
                let outcome = secret.with_exposed(|bytes| {
                    let pem = String::from_utf8_lossy(bytes);
                    registry.register_from_pem(kv_key.clone(), &pem)
                });
                match outcome {
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
    ///
    /// Behind an `RwLock` so background op discovery (DR-0023 Phase 2) can
    /// hot-swap the freshly discovered op-key set after the socket has already
    /// bound and started serving the disk-cache seed. Every hot-path read is
    /// **brief**: REQUEST_IDENTITIES snapshots the identities, and a local sign
    /// takes the read lock only to resolve the key (blob → KV key) then drops it
    /// before the auth gate / op fetch ([`local_sign_first_pass`]). The refresh takes the
    /// write lock only to swap the whole registry, so it never waits behind (nor
    /// stalls new readers during) a slow sign.
    registry: Arc<RwLock<PublicKeyRegistry>>,
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

/// The result of one [`discover_all_sources`] pass (DR-0023 Phase 2).
pub struct SourceDiscovery {
    /// `source name → discovered keys`. On a `Stale`/`Err` source the map still
    /// carries whatever the disk-cache fallback recovered (possibly empty), so a
    /// registry rebuilt from this never drops below the seed it was serving.
    pub keys: BTreeMap<String, Vec<DiscoveredKey>>,
    /// The names of the sources whose `op item list` succeeded (`Fresh`) this
    /// pass. Tracked **per source** (not a single global flag) so the background
    /// refresh can hot-swap each source's registry the moment *that* source
    /// enumerates live, and keep retrying only the sources still unavailable — a
    /// permanently-unreachable source must not withhold a healthy source's freshly
    /// discovered keys, nor keep the whole retry loop spinning `op item list` for
    /// sources already resolved.
    pub fresh: BTreeSet<String>,
}

impl SourceDiscovery {
    /// A "nothing discovered, nothing fresh" result — used when the background
    /// discovery task itself panics, so the caller retries after backoff rather
    /// than treating the panic as success.
    fn failed() -> Self {
        Self {
            keys: BTreeMap::new(),
            fresh: BTreeSet::new(),
        }
    }
}

/// Discover the keys of every `[authsock.sources.*]` once, with the production
/// `op` CLI client. A source's discovery failure (op not signed in, network
/// down, launchd-context biometric unreachable) is logged and the source falls
/// back to the disk cache (DR-0026); the returned `fresh` set records **which**
/// sources enumerated live so the background refresh (DR-0023 Phase 2) can apply
/// each resolved source at once and keep retrying only the ones still down.
///
/// Sharing one discovery across every socket that references the same source
/// mirrors authsock-warden's shared op state (one TouchID-bearing `op item
/// list`, not one per socket).
///
/// `op item list` / `op item get` are synchronous CLI calls that must not block
/// the async runtime workers, so the caller runs this on the blocking pool.
pub fn discover_all_sources(sources: &[AuthsockSource]) -> SourceDiscovery {
    let mut out = BTreeMap::new();
    let mut fresh = BTreeSet::new();
    // Merge every Fresh source's keys into one cache loaded once, saved once at the
    // end (below). A per-source `fresh_cache.save()` would clobber the shared
    // `op_map.json` down to the last source's keys — each `discover_keys` rebuilds
    // its cache from only its own source — erasing sibling sources' keys from the
    // disk seed Phase 2 binds from. For a single source the merged result is
    // identical to the old per-source save; multi-source now preserves every
    // source's keys (see `merge_source_cache`).
    let mut merged = OpKeyCache::load();
    let mut any_fresh = false;
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
        // The warm-cache hint is the current merged view (this run's earlier
        // sources included), so a fingerprint another source already resolved is
        // reused without a second `op item get`.
        let hint = merged.clone();
        match discover_keys(&client, &op_sources, source.op_account.as_deref(), hint) {
            Ok(DiscoveryOutcome::Fresh {
                keys,
                cache: fresh_cache,
            }) => {
                merge_source_cache(
                    &mut merged,
                    &op_sources,
                    source.op_account.as_deref(),
                    fresh_cache,
                );
                any_fresh = true;
                println!(
                    "cache-warden: authsock source `{}`: discovered {} op key(s)",
                    source.name,
                    keys.len()
                );
                fresh.insert(source.name.clone());
                out.insert(source.name.clone(), keys);
            }
            Ok(DiscoveryOutcome::Stale { keys, error }) => {
                // `op item list` failed: serve the last-known keys recovered from
                // the disk cache (bounded to this source's account + members).
                // The cache is intentionally NOT re-saved on this path — a
                // transient op outage must never discard the known-good mapping.
                // Not in `fresh`: the background refresh must retry this source.
                eprintln!(
                    "cache-warden: authsock source `{}`: op discovery failed ({error}); \
                     serving {} key(s) from stale cache",
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
    // Persist the merged cache once (best effort). Only when at least one source
    // was Fresh: an all-Stale pass has nothing new to save and must not rewrite the
    // file (a transient op outage must never discard the known-good mapping).
    if any_fresh {
        merged.save();
    }
    SourceDiscovery { keys: out, fresh }
}

/// Seed every source's keys from the disk cache **without** invoking `op`
/// (DR-0023 Phase 2): lets the agent sockets bind immediately from the
/// last-known keys instead of blocking startup on `op item list`. Background
/// discovery ([`op_discovery_refresh`]) then replaces the seed with a live set.
///
/// Uses the same per-source account/vault boundary as [`discover_all_sources`]
/// (via [`seed_from_cache`]), so the seed enumerates exactly the subset a live
/// discovery-failure fallback would have served. A cold first-ever start (no
/// cache) seeds nothing and the sockets bind empty — still an improvement over
/// blocking until `op` returns (or hangs).
pub fn seed_all_sources_from_cache(
    sources: &[AuthsockSource],
) -> BTreeMap<String, Vec<DiscoveredKey>> {
    let mut out = BTreeMap::new();
    for source in sources {
        let op_sources: Vec<OpSource> = source
            .members
            .iter()
            .filter_map(|m| OpSource::parse(m))
            .collect();
        let cache = OpKeyCache::load();
        let keys = seed_from_cache(&cache, &op_sources, source.op_account.as_deref());
        if !keys.is_empty() {
            println!(
                "cache-warden: authsock source `{}`: seeded {} op key(s) from disk cache \
                 (live discovery pending in background)",
                source.name,
                keys.len()
            );
        }
        out.insert(source.name.clone(), keys);
    }
    out
}

/// Register a source's discovered keys into `registry` as op-sourced keys.
///
/// Each discovered key becomes a [`KeySource::Op`] entry: the public key is
/// enumerable now (REQUEST_IDENTITIES), and the private PEM is fetched lazily at
/// first sign via `op item get` (the argv built by [`private_key_argv`]). The
/// core KV key is composed into the reserved `authsock` namespace
/// ([`OpKvKey`], `authsock/op_<item_id>`) so it never collides with a manual
/// `[kv.*]` entry and satisfies the core's composed-key syntax gate (DR-0018
/// §4.5). A key whose item id is not composable, or whose public blob fails to
/// parse, is logged and skipped. Returns how many keys were registered.
fn register_op_keys(
    socket_name: &str,
    exe: &str,
    source: &AuthsockSource,
    keys: &[DiscoveredKey],
    registry: &mut PublicKeyRegistry,
) -> usize {
    let mut n = 0;
    for key in keys {
        let Some(kv_key) = OpKvKey::new(&key.item_id) else {
            eprintln!(
                "cache-warden: authsock `{socket_name}`: op key `{}` has a non-alphanumeric item \
                 id, skipping (cannot form a valid store key)",
                key.title
            );
            continue;
        };
        let argv = private_key_argv(exe, &key.item_id, source.op_account.as_deref());
        let src = KeySource::Op {
            argv,
            soft_ttl_secs: source.soft_ttl_secs,
            hard_ttl_secs: source.hard_ttl_secs,
        };
        match registry.register_op_key(kv_key.as_str(), &key.public_key, &key.title, src) {
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

/// The core KV key for an op-sourced private key: the reserved `authsock`
/// namespace composed with an `op_<item_id>` segment (`authsock/op_<item_id>`,
/// DR-0018 §4.5). Built only from an alphanumeric op item id, so its serialized
/// form is always a valid composed key the core accepts — never the retired
/// `:`-bearing `__authsock_op:` pseudo-prefix that violated the DR-0017 §1.5
/// charset. This adapter owns the serialization so the core stays a generic
/// syntax gate rather than learning the authsock key shape.
struct OpKvKey(String);

impl OpKvKey {
    /// Compose the KV key for `item_id`, or `None` if the id is not composable.
    ///
    /// 1Password item ids are alphanumeric; an empty or non-alphanumeric id
    /// (never observed from op) is refused rather than composed into a segment
    /// the core would reject, so a bad id degrades to a skipped key instead of a
    /// hard error deep in `store.define`.
    fn new(item_id: &str) -> Option<Self> {
        if item_id.is_empty() || !item_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        Some(Self(format!(
            "{}/op_{item_id}",
            crate::namespace::RESERVED_NAMESPACE_AUTHSOCK
        )))
    }

    /// The composed key as a string slice.
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A socket whose op-sourced registry can be refreshed once background op
/// discovery completes (DR-0023 Phase 2).
///
/// Holds the immutable local `base` (the config `keys`' public halves, derived
/// once at bind time and **never re-read from the core**, so a local key present
/// at bind can never vanish on a refresh even if its TTL later expires) and a
/// handle to the `live` registry the hot path reads. A refresh rebuilds
/// `base.clone()` + freshly discovered op keys and swaps it into `live`.
pub struct DiscoveryTarget {
    /// The socket this target refreshes (its `source` name and diagnostics name).
    socket: AuthsockSocket,
    /// Immutable local-key base, cloned on every rebuild.
    base: PublicKeyRegistry,
    /// The live registry the hot path reads; the swap target on a refresh.
    live: Arc<RwLock<PublicKeyRegistry>>,
}

/// What [`spawn_listeners`] hands back.
pub struct ListenerSet {
    /// `(socket_path, JoinHandle)` pairs the caller awaits on shutdown (and whose
    /// socket file it removes). Includes the github-refresh task (empty path).
    pub handles: Vec<(PathBuf, JoinHandle<()>)>,
    /// Per-socket refresh targets for the background op-discovery task. Empty
    /// when no socket has an op `source` (or the own-binary path is unknown).
    pub discovery_targets: Vec<DiscoveryTarget>,
    /// The resolved own-binary path op keys re-exec to fetch their PEM. Passed to
    /// the background refresh so it can build op keys the same way. `None` when it
    /// could not be resolved (op keys are then unavailable — fail-closed).
    pub exe: Option<String>,
}

/// Register a socket's op-sourced keys as core definitions so `get_or_regenerate`
/// (DR-0014 lazy path) can produce their PEMs at sign time.
///
/// Takes the **store lock only** (never while a registry lock is held) so it
/// cannot invert against [`local_sign_first_pass`]'s registry-read → store-lock order. A
/// `Conflict` is a no-op (idempotent re-start, a shared source across sockets, or
/// a background refresh re-registering the same key); a bad TTL / other error is
/// logged and that key skipped.
fn register_op_definitions(shared: &Arc<Shared>, registry: &PublicKeyRegistry, socket_name: &str) {
    let mut store = match shared.store.lock() {
        Ok(g) => g,
        Err(_) => {
            eprintln!(
                "cache-warden: authsock `{socket_name}`: store lock poisoned; skipping op key \
                 definition registration"
            );
            return;
        }
    };
    for reg in registry.all_keys() {
        if let KeySource::Op {
            argv,
            soft_ttl_secs,
            hard_ttl_secs,
        } = &reg.source
        {
            let ttl = match Ttl::new(
                soft_ttl_secs.map(std::time::Duration::from_secs),
                hard_ttl_secs.map(std::time::Duration::from_secs),
            ) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!(
                        "cache-warden: authsock `{socket_name}`: op key `{}` has invalid TTL \
                         configuration ({e}); skipping definition registration",
                        reg.kv_key
                    );
                    continue;
                }
            };
            match store.define(&reg.kv_key, ValueSource::command(argv.clone()), ttl) {
                Ok(()) | Err(DefineError::Conflict) => {} // ok or idempotent
                Err(e) => {
                    eprintln!(
                        "cache-warden: authsock `{socket_name}`: failed to register definition for \
                         op key `{}` ({e}); lazy loading via get_or_regenerate unavailable",
                        reg.kv_key
                    );
                }
            }
        }
    }
}

/// Build a socket's full registry: the immutable local `base` plus this run's
/// op-sourced keys. Pure (no store / lock) so the background refresh rebuilds off
/// the same base without re-reading the core. Returns the merged registry and how
/// many op keys were layered on (0 when `exe` is unknown — op keys unavailable).
fn op_registry_from(
    base: &PublicKeyRegistry,
    socket_name: &str,
    exe: Option<&str>,
    source: &AuthsockSource,
    keys: &[DiscoveredKey],
) -> (PublicKeyRegistry, usize) {
    let mut registry = base.clone();
    let op_key_count = match exe {
        Some(exe) => register_op_keys(socket_name, exe, source, keys, &mut registry),
        None => 0,
    };
    (registry, op_key_count)
}

/// Spawn one listener task per validated `[authsock.sockets.*]`.
///
/// Returns a [`ListenerSet`]: the join handles (awaited on shutdown), the
/// per-socket [`DiscoveryTarget`]s for background op discovery, and the resolved
/// own-binary path. A socket whose registry ends up empty (no key resolved) is
/// still bound — it answers REQUEST_IDENTITIES with an empty list until a key is
/// set (or background discovery populates it).
///
/// `sources` are the validated `[authsock.sources.*]`.
///
/// `discovered` is the **seed** `source name → keys` map (from the disk cache,
/// [`seed_all_sources_from_cache`]) — not a live discovery. The socket binds
/// immediately from this seed (DR-0023 Phase 2: startup never blocks on `op`); a
/// background task ([`op_discovery_refresh`]) then replaces it with a live set.
/// `spawn_listeners` stays free of synchronous blocking work (it spawns async
/// tasks and must not call `tokio::spawn` from inside a `spawn_blocking` closure).
pub fn spawn_listeners(
    sockets: &[AuthsockSocket],
    sources: &[AuthsockSource],
    discovered: BTreeMap<String, Vec<DiscoveredKey>>,
    github: GithubSettings,
    shared: Arc<Shared>,
    shutdown_rx: watch::Receiver<bool>,
) -> ListenerSet {
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
    let mut discovery_targets = Vec::new();
    for socket in sockets {
        // Derive this socket's immutable local base registry up front (under the
        // store lock) from the configured keys' currently-cached PEMs.
        let base = {
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
            build_registry(
                &socket.name,
                &socket.keys,
                &mut store,
                &shared.authsock_cap,
                &shared.clock,
            )
        };

        // Layer this socket's op-sourced keys onto a copy of the base, seeded from
        // the disk-cache `discovered` map (lazily loaded at sign time; see
        // [`KeySource::Op`]). Skipped when the binary path is unknown (fail-closed
        // above) — that socket then never gets a refresh target either.
        let socket_source: Option<&AuthsockSource> = socket
            .source
            .as_deref()
            .and_then(|n| source_by_name.get(n).copied());
        let mut registry = base.clone();
        let mut op_key_count = 0;
        let has_op_source = if let (Some(exe_path), Some(source)) = (exe.as_deref(), socket_source)
        {
            let seed_keys = socket
                .source
                .as_deref()
                .and_then(|n| discovered.get(n))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            op_key_count =
                register_op_keys(&socket.name, exe_path, source, seed_keys, &mut registry);
            true
        } else {
            false
        };

        // Register definitions for all op-sourced keys in the core Store so that
        // get_or_regenerate (DR-0014 lazy path) can produce their values. This
        // replaces the former lazy_load_op_key independent fetch/set path (A-3a).
        register_op_definitions(&shared, &registry, &socket.name);

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

        let registry_len = registry.len();
        println!(
            "cache-warden: authsock `{}` listening on {} ({} key(s) incl. {} op, {} upstream(s), {} filter term(s))",
            socket.name,
            socket.path.display(),
            registry_len,
            op_key_count,
            upstreams.len(),
            filter.len()
        );

        // The live registry the hot path reads; background op discovery swaps it.
        let live = Arc::new(RwLock::new(registry));

        // A socket with a resolvable op source gets a refresh target: the
        // background task rebuilds `base` + freshly discovered op keys and swaps
        // `live`. Local-only sockets never change after bind, so they need none.
        if has_op_source {
            discovery_targets.push(DiscoveryTarget {
                socket: socket.clone(),
                base,
                live: Arc::clone(&live),
            });
        }

        let state = Arc::new(SocketState {
            name: socket.name.clone(),
            registry: live,
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
    ListenerSet {
        handles,
        discovery_targets,
        exe,
    }
}

/// Task-level retry backoff bounds for background op discovery (DR-0023 Phase 2).
///
/// Distinct from DR-0022's *per-key fetch* backoff: this governs how often the
/// daemon retries the **whole** `op item list` discovery until it first
/// succeeds. The first success replaces the disk-cache seed with a live set and
/// stops the loop — thereafter op keys are re-fetched lazily at sign time
/// (DR-0014), so a warm registry needs no polling.
const DISCOVERY_RETRY_INITIAL: std::time::Duration = std::time::Duration::from_secs(2);
/// Upper bound on the retry delay (a launchd-context daemon whose biometric path
/// is unreachable keeps serving the seed rather than spinning tightly).
const DISCOVERY_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(60);

/// The next retry delay: double the current one, capped at [`DISCOVERY_RETRY_MAX`].
/// Pure so the backoff progression is unit-tested without real waiting.
fn next_backoff(current: std::time::Duration) -> std::time::Duration {
    (current * 2).min(DISCOVERY_RETRY_MAX)
}

/// Rebuild one target's registry from its immutable local base plus the freshly
/// discovered op keys, register the op-key definitions in the core, and swap the
/// result into the live registry the hot path reads.
///
/// Locks are never nested: the fresh registry is built lock-free
/// ([`op_registry_from`]), definitions are registered under the store lock alone
/// ([`register_op_definitions`]), and the swap takes the registry write lock
/// alone. Combined with [`local_sign_first_pass`] holding the registry read lock only to
/// resolve the key (never across the store lock), no lock is ever held while
/// acquiring another here — so this cannot deadlock or invert against a sign.
///
/// Runs on the blocking pool (see [`op_discovery_refresh`]): the store lock it
/// takes can be held by a concurrent sign across an `op item get` / TouchID, so
/// this synchronous wait must stay off the async workers (DR-0008).
fn apply_discovery(
    target: &DiscoveryTarget,
    exe: Option<&str>,
    source: &AuthsockSource,
    keys: &[DiscoveredKey],
    shared: &Arc<Shared>,
) {
    let (registry, op_key_count) =
        op_registry_from(&target.base, &target.socket.name, exe, source, keys);
    // Store lock only (no registry lock held) — see the lock-ordering note above.
    register_op_definitions(shared, &registry, &target.socket.name);
    // Registry write lock only.
    *target.live.write().unwrap_or_else(|e| e.into_inner()) = registry;
    println!(
        "cache-warden: authsock `{}`: op discovery updated registry ({} op key(s))",
        target.socket.name, op_key_count
    );
}

/// Background op discovery (DR-0023 Phase 2).
///
/// The agent sockets have already bound and are serving the disk-cache seed. This
/// task runs the (blocking) `op item list` discovery off the async runtime and
/// hot-updates each target's registry **per source**, the moment that source
/// enumerates live — a healthy source's freshly discovered keys are served at
/// once even while another source is still unreachable. It keeps retrying (capped
/// task-level backoff) only the sources not yet resolved, and stops once every
/// op-`source` socket serves a live registry. A source that is permanently
/// unreachable (a launchd-context daemon whose biometric path never reaches the
/// GUI session) keeps serving its seed and is retried on the backoff, without
/// withholding any resolved source's keys.
///
/// There is no periodic re-discovery of an already-resolved source — op keys are
/// re-fetched lazily at sign time (DR-0014), so a warm registry needs no polling
/// (DR-0023: "成功後は既存 refresh 経路に委ねる"). Every wait — the discovery
/// itself, the (blocking-pool) apply, and the backoff — is select-able with the
/// shutdown channel so a stop signal is honoured immediately even mid-discovery /
/// mid-apply / mid-backoff (DR-0023 Phase 1 responsiveness, carried forward).
pub async fn op_discovery_refresh(
    targets: Vec<DiscoveryTarget>,
    sources: Vec<AuthsockSource>,
    exe: Option<String>,
    shared: Arc<Shared>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    // The op-`source` names whose sockets have a refresh target — the set the loop
    // must resolve before it is done. `Arc` so the blocking-pool apply closure can
    // borrow every target without moving them out of the task.
    let targets = Arc::new(targets);
    let pending_sources: BTreeSet<String> = targets
        .iter()
        .filter_map(|t| t.socket.source.clone())
        .collect();
    // Sources already hot-swapped to a live registry: never re-discovered or
    // re-applied, and — once this covers every `pending_sources` entry — the loop
    // is done.
    let mut applied: BTreeSet<String> = BTreeSet::new();
    let mut backoff = DISCOVERY_RETRY_INITIAL;

    loop {
        // Discover only the sources not yet resolved: an already-applied source is
        // never re-run through `op item list` (no periodic re-discovery, DR-0023
        // §4; a resolved source keeps no session-warming biometric traffic alive).
        let sources_for_task: Vec<AuthsockSource> = sources
            .iter()
            .filter(|s| !applied.contains(&s.name))
            .cloned()
            .collect();
        // Run the synchronous op CLI discovery on the blocking pool so a hung
        // `op` never pins an async worker (it cannot be aborted — the process
        // exit / DR-0021 watchdog bounds a truly wedged op).
        let discover = tokio::task::spawn_blocking(move || discover_all_sources(&sources_for_task));
        let discovery = tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { return; }
                continue;
            }
            res = discover => match res {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("cache-warden: authsock: background discovery task panicked ({e})");
                    SourceDiscovery::failed()
                }
            },
        };

        // Hot-swap every source that enumerated live this pass and has a target —
        // per source, so a healthy source is served immediately even while another
        // stays unreachable. The apply runs on the blocking pool: `apply_discovery`
        // takes the store lock (op-key definition registration) and the registry
        // write lock, and a concurrent sign can hold the store lock across an
        // `op item get` / TouchID — that synchronous wait must not pin an async
        // worker (DR-0008).
        let newly_fresh: Vec<String> = discovery
            .fresh
            .iter()
            .filter(|name| pending_sources.contains(*name) && !applied.contains(*name))
            .cloned()
            .collect();
        if !newly_fresh.is_empty() {
            let targets_apply = Arc::clone(&targets);
            let shared_apply = Arc::clone(&shared);
            let exe_apply = exe.clone();
            let sources_apply = sources.clone();
            let apply_set: BTreeSet<String> = newly_fresh.iter().cloned().collect();
            let keys_apply: BTreeMap<String, Vec<DiscoveredKey>> = newly_fresh
                .iter()
                .filter_map(|n| discovery.keys.get(n).map(|k| (n.clone(), k.clone())))
                .collect();
            let apply = tokio::task::spawn_blocking(move || {
                let source_by_name: BTreeMap<&str, &AuthsockSource> =
                    sources_apply.iter().map(|s| (s.name.as_str(), s)).collect();
                for target in targets_apply.iter() {
                    let Some(name) = target.socket.source.as_deref() else {
                        continue;
                    };
                    if !apply_set.contains(name) {
                        continue;
                    }
                    if let (Some(source), Some(keys)) =
                        (source_by_name.get(name).copied(), keys_apply.get(name))
                    {
                        apply_discovery(target, exe_apply.as_deref(), source, keys, &shared_apply);
                    }
                }
            });
            // Await the apply but stay responsive to a stop signal — the apply's
            // blocking-pool task completes (or is torn down at process exit) even
            // if we return early on shutdown.
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { return; }
                }
                _ = apply => {}
            }
            applied.extend(newly_fresh);
        }

        // Every op-`source` socket now serves a live registry: done.
        if pending_sources.iter().all(|n| applied.contains(n)) {
            eprintln!("cache-warden: authsock: background op discovery complete");
            return;
        }

        // Some source is still unavailable (op down / hung / not signed in): keep
        // serving its seed and retry after a bounded, shutdown-interruptible wait.
        eprintln!(
            "cache-warden: authsock: op discovery incomplete ({}/{} source(s) live); \
             retrying in {:.0}s (serving disk-cache seed for the rest)",
            applied.len(),
            pending_sources.len(),
            backoff.as_secs_f64()
        );
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { return; }
            }
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = next_backoff(backoff);
    }
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
    let fd = stream.as_raw_fd();
    let peer = peer_pid(fd);
    // DR-0030: capture the peer's audit token now, while the raw fd still
    // refers to the connected socket. `peer_audit_token` is race-free per the
    // kernel's `LOCAL_PEERTOKEN` contract (keyed on the fd, not on a pid), so
    // caching it once at accept time is safe for the whole connection
    // lifetime — SIGN_REQUEST paths derive their `SameUser` decision from
    // this snapshot without a second syscall per message. On Linux / a
    // non-socket / a getsockopt failure this collapses to `None`, and the
    // guard evaluator denies whenever a `SameUser` constraint requires it
    // (fail-closed).
    // DR-0031 §4 dialog integration: we need both the reduced
    // [`GetterAuditToken`] (euid/ruid, fed to the guard evaluator) and the
    // full [`macos_process_inspect::AuditToken`] (fed to the wire
    // adapter's `Requester.audit_token`). Both derive from the same
    // race-free `LOCAL_PEERTOKEN` snapshot taken here at accept time.
    let peer_token_full = macos_process_inspect::peer_audit_token(fd);
    let peer_token = peer_token_full.map(|t| GetterAuditToken {
        euid: t.euid(),
        ruid: t.ruid(),
    });

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
            respond(&state, peer, peer_token, peer_token_full, &msg, &mut routes).await
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
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
    msg: &AgentMessage,
    routes: &mut UpstreamRoutes,
) -> AgentMessage {
    match msg.msg_type {
        MessageType::RequestIdentities => request_identities(state, msg, routes).await,
        MessageType::SignRequest => {
            sign_request(state, peer, peer_token, peer_token_full, msg, routes).await
        }
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
    // A brief read lock snapshots the identities into an owned Vec before the
    // async upstream loop below, so the guard is never held across an await
    // (background discovery's write swap is not blocked by a slow upstream).
    let mut merged: Vec<Identity> = {
        let registry = state.registry.read().unwrap_or_else(|e| e.into_inner());
        registry
            .identities()
            .into_iter()
            .filter(|id| state.filter.matches(id))
            .collect()
    };
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
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
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
    //    socket hides yields FAILURE even though its PEM is reachable. The read
    //    lock is dropped before dispatching (local_sign_first_pass re-takes it).
    //
    //    DR-0031 §8 dialog integration (SIGN parity with `kv.get`): the local
    //    sign runs as a two-pass flow, mirroring `run_request_async`. First
    //    pass on the blocking pool derives the requester chain, resolves the
    //    key, runs policy + guard checks; unguarded keys return the signed
    //    reply directly (no dialog, matching pre-DR-0031 behaviour), guarded
    //    keys evaluate the record and — if it passes — hand back the
    //    material needed to build the ApproveRequest. The store lock is
    //    dropped before the async dialog await so a multi-second human
    //    approval cannot queue every other request on this daemon behind
    //    it. On `Approved`, the finalize pass re-takes the lock, re-evaluates
    //    the guard fail-closed (in case a concurrent `kv.set` replaced the
    //    record while the human was deciding — DR-0030 §5 "last declaration
    //    wins"), then runs the same post-guard body (`sign_body_after_guard`)
    //    the unguarded path uses. Non-`Approved` outcomes surface as bare
    //    `SSH_AGENT_FAILURE` with a structured stderr diag naming the
    //    reason — the agent wire has no error kind, so the diag is the audit
    //    trail.
    if known_local(state, &key_blob) {
        let state1 = Arc::clone(state);
        let msg1 = msg.clone();
        let first = tokio::task::spawn_blocking(move || {
            local_sign_first_pass(&state1, peer, peer_token, &msg1)
        })
        .await
        .unwrap_or_else(|_| SignFirstPass::Direct(AgentMessage::failure()));

        return match first {
            SignFirstPass::Direct(resp) => resp,
            SignFirstPass::NeedsApproval(material) => {
                let SignNeedsApprovalMaterial {
                    guard_eval,
                    kv_key,
                    source,
                    requester,
                    guard_chain,
                } = *material;
                let wire_req = super::approver_wire::build_approve_request(
                    super::server::mint_approver_request_id(),
                    kv_key.clone(),
                    "sign",
                    guard_chain.as_deref().unwrap_or(&[]),
                    peer_token_full.as_ref(),
                    None,
                    &guard_eval,
                    super::server::APPROVER_WIRE_TIMEOUT_SECS,
                );
                let outcome = state
                    .shared
                    .approver
                    .await_dialog_outcome(
                        wire_req,
                        super::server::HELPER_STARTING_WAIT,
                        super::server::APPROVER_REQUEST_TIMEOUT,
                    )
                    .await;
                match outcome {
                    super::server::ApprovalOutcome::Approved => {
                        let state2 = Arc::clone(state);
                        let msg2 = msg.clone();
                        tokio::task::spawn_blocking(move || {
                            local_sign_finalize_after_approval(
                                &state2,
                                peer_token,
                                requester,
                                guard_chain,
                                kv_key,
                                source,
                                &msg2,
                            )
                        })
                        .await
                        .unwrap_or_else(|_| AgentMessage::failure())
                    }
                    super::server::ApprovalOutcome::Ipc(err) => {
                        eprintln!(
                            "cache-warden: authsock sign denied for {kv_key:?}: approver \
                             dialog failed ({err})"
                        );
                        AgentMessage::failure()
                    }
                    rejection => {
                        eprintln!(
                            "cache-warden: authsock sign denied for {kv_key:?}: {}",
                            rejection.label()
                        );
                        AgentMessage::failure()
                    }
                }
            }
        };
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

/// Whether `key_blob` is registered in this socket's live registry.
///
/// Extracted so [`sign_request`]'s local-fast-path check is greppable with
/// the tests that pin it — and to keep the async dispatcher's read-lock
/// hold to the shortest possible window (the `known_local` snapshot).
fn known_local(state: &Arc<SocketState>, key_blob: &[u8]) -> bool {
    let registry = state.registry.read().unwrap_or_else(|e| e.into_inner());
    registry.lookup(key_blob).is_some()
}

/// The outcome of the SIGN first pass — the mirror of the control-socket
/// [`crate::daemon::server::GuardedGetFirstPass`] for `kv.get`.
///
/// `Direct` carries either the signed reply (unguarded fast path — the
/// same body as the pre-DR-0031 `local_sign`), an early
/// `SSH_AGENT_FAILURE` for a policy / guard denial, or the sentinel
/// failure for a malformed / unknown / filtered blob. `NeedsApproval`
/// carries every piece the finalize pass will need after the dialog
/// returns `Approved`.
enum SignFirstPass {
    Direct(AgentMessage),
    /// Boxed because the `NeedsApproval` variant is >300 bytes (large
    /// `GuardEvalOutput` + `KeySource` + a `Vec<GetterProcess>` chain)
    /// while `Direct` is ~40 bytes; boxing the material keeps the enum
    /// small on the common (unguarded / direct-failure) path
    /// (`clippy::large_enum_variant`).
    NeedsApproval(Box<SignNeedsApprovalMaterial>),
}

struct SignNeedsApprovalMaterial {
    guard_eval: guard_eval::GuardEvalOutput,
    kv_key: String,
    source: KeySource,
    /// Requester chain snapshotted at first-pass time — reused by both
    /// the wire builder (for the dialog) and the second-pass
    /// re-evaluation, so a mid-approval `proc_pidinfo` shift cannot
    /// make the re-check disagree with the just-approved evaluation.
    requester: Option<Vec<ProcessInfo>>,
    /// Same chain enriched with `unique_id` for the guard evaluator's
    /// second-pass re-run.
    guard_chain: Option<Vec<GetterProcess>>,
}

/// Result of evaluating the DR-0030 guard record for a SIGN_REQUEST.
///
/// Shared by the three SIGN entry points that must consult the guard on a
/// resolved KV key: the first pass ([`local_sign_first_pass`]) hands
/// `Passed` off to the approver as dialog material; the finalize pass
/// ([`local_sign_finalize_after_approval`]) re-checks after `Approved`
/// and only cares that the record still passes; and the test-only
/// [`sign_with_resolved_key`] mirrors the pre-DR-0031 inline body. The
/// three sites differ only in what they log (site-1/3 say "guard
/// constraint … failed", site-2 says "after approval … on re-evaluation
/// (record changed during approval)") and in the return type they map
/// each variant to; the branching + `guard_eval::evaluate` call is
/// centralized here so a fourth SIGN entry cannot accidentally skip a
/// step.
enum SignGuardCheck {
    /// Key has no guard record — take the unguarded path.
    Unguarded,
    /// Guard present and every constraint matched. The output carries
    /// the dialog material the first pass hands off to the approver;
    /// the finalize / legacy paths discard it (their re-check only
    /// needs "still passes").
    Passed(guard_eval::GuardEvalOutput),
    /// The record required a requester chain but the peer could not be
    /// walked (`None`). Fail-closed at every site.
    ChainMissing,
    /// Guard denied. Carries the wire-safe kind label
    /// ([`guard_eval::denied_kind_label`]) for the caller's stderr diag.
    Denied(&'static str),
}

/// Evaluate the guard on `kv_key` under an already-held store lock.
///
/// Extracts the tri-branch (unguarded / chain-missing / evaluate) shared
/// by [`local_sign_first_pass`], [`local_sign_finalize_after_approval`],
/// and [`sign_with_resolved_key`]. The caller keeps the store lock across
/// the call and handles the site-specific logging + return-type mapping.
fn eval_sign_guard(
    store: &Store,
    kv_key: &str,
    guard_chain: Option<&[GetterProcess]>,
    peer_token: Option<GetterAuditToken>,
) -> SignGuardCheck {
    let Some(record) = store.guard_of(kv_key) else {
        return SignGuardCheck::Unguarded;
    };
    let Some(chain) = guard_chain else {
        return SignGuardCheck::ChainMissing;
    };
    match guard_eval::evaluate(chain, peer_token, record) {
        Ok(output) => SignGuardCheck::Passed(output),
        Err(denied) => SignGuardCheck::Denied(guard_eval::denied_kind_label(denied.kind)),
    }
}

/// First-pass evaluation for a local SIGN_REQUEST (blocking).
///
/// Mirrors [`crate::daemon::server::guarded_get_first_pass`] shape:
///
/// - Resolve the requester chain (best effort) and the key blob → KV key
///   (via [`signable_key`]).
/// - Apply the DR-0012 key-level process policy (fail-closed on an
///   unknown requester when the key is restricted).
/// - Take the store lock, check for a guard record. Unguarded ⇒ run the
///   sign body inline under the held lock (single-lock hot path, matches
///   pre-DR-0031 latency); guarded ⇒ evaluate the record fail-closed
///   ([`guard_eval::evaluate`]), release the lock, and either return
///   `Direct(failure)` on a denial or `NeedsApproval` with the material
///   the wire adapter needs (guard_eval output, kv_key, source, chain).
///
/// The lock is released before returning `NeedsApproval` so the async
/// dialog await never sits behind it.
fn local_sign_first_pass(
    state: &SocketState,
    peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    msg: &AgentMessage,
) -> SignFirstPass {
    let requester: Option<Vec<ProcessInfo>> =
        peer.and_then(|pid| SystemInspector::new().ancestry(pid).ok());
    let guard_chain: Option<Vec<GetterProcess>> = requester.as_ref().map(|chain| {
        chain
            .iter()
            .map(|info| GetterProcess {
                info: info.clone(),
                unique_id: macos_process_inspect::unique_id(info.pid)
                    .ok()
                    .map(|u| u.unique_id),
            })
            .collect()
    });
    let fields = match msg.parse_sign_request() {
        Ok(f) => f,
        Err(_) => return SignFirstPass::Direct(AgentMessage::failure()),
    };
    let (kv_key, source) = {
        let registry = state.registry.read().unwrap_or_else(|e| e.into_inner());
        match signable_key(&registry, &state.filter, &fields.key_blob) {
            Some(r) => (r.kv_key.clone(), r.source.clone()),
            None => return SignFirstPass::Direct(AgentMessage::failure()),
        }
    };

    // Key-level process policy (DR-0012). Matches `sign_with_resolved_key`'s
    // pre-gate exactly — a restricted key with an unknown requester is
    // denied here so the dialog never fires on a request that would be
    // refused post-approval anyway.
    if let Some(allowed) = state.shared.kv_process_policies.get(&kv_key)
        && !chain_gate_passes(requester.as_deref(), allowed)
    {
        return SignFirstPass::Direct(AgentMessage::failure());
    }

    let mut store = match state.shared.store.lock() {
        Ok(g) => g,
        Err(_) => return SignFirstPass::Direct(AgentMessage::failure()),
    };
    match eval_sign_guard(&store, &kv_key, guard_chain.as_deref(), peer_token) {
        SignGuardCheck::Unguarded => {
            // Unguarded fast path: run the post-guard body inline while
            // holding the lock (single lock take, identical to pre-DR-0031).
            let resp = sign_body_after_guard(
                &mut store,
                state.shared.auth.as_ref(),
                &state.shared.runner,
                &state.shared.clock,
                &state.shared.authsock_cap,
                requester.as_deref(),
                &kv_key,
                &source,
                &fields,
            );
            SignFirstPass::Direct(resp)
        }
        SignGuardCheck::Passed(output) => {
            drop(store);
            SignFirstPass::NeedsApproval(Box::new(SignNeedsApprovalMaterial {
                guard_eval: output,
                kv_key,
                source,
                requester,
                guard_chain,
            }))
        }
        SignGuardCheck::ChainMissing => {
            drop(store);
            eprintln!(
                "cache-warden: authsock sign denied for {kv_key:?}: guard requires a \
                 requester chain but the peer could not be walked"
            );
            SignFirstPass::Direct(AgentMessage::failure())
        }
        SignGuardCheck::Denied(kind) => {
            drop(store);
            eprintln!(
                "cache-warden: authsock sign denied for {kv_key:?}: guard constraint \
                 {kind:?} failed"
            );
            SignFirstPass::Direct(AgentMessage::failure())
        }
    }
}

/// Second-pass finalize after the dialog returned `Approved`.
///
/// Mirrors [`crate::daemon::server::guarded_get_finalize_after_approval`]:
/// re-take the store lock, re-evaluate the guard record fail-closed
/// (concurrent `kv.set` may have swapped the record, DR-0030 §5 "last
/// declaration wins"), and — if it still passes — run the same
/// post-guard body (`sign_body_after_guard`) the unguarded path used.
/// If the guard has been *dropped* since the first pass, the entry is
/// now unguarded and a plain sign is safe (matching the get side).
fn local_sign_finalize_after_approval(
    state: &SocketState,
    peer_token: Option<GetterAuditToken>,
    requester: Option<Vec<ProcessInfo>>,
    guard_chain: Option<Vec<GetterProcess>>,
    kv_key: String,
    source: KeySource,
    msg: &AgentMessage,
) -> AgentMessage {
    let fields = match msg.parse_sign_request() {
        Ok(f) => f,
        Err(_) => return AgentMessage::failure(),
    };
    // Re-resolve `signable_key` against the current registry (fail-closed on
    // absence / kv_key drift). The first pass captured `kv_key` / `source`
    // under a brief registry read lock and then dropped it before awaiting
    // the (up to ~95s) approver dialog; a background op-discovery hot-swap
    // (DR-0023 Phase 2, `Arc<RwLock<PublicKeyRegistry>>`) could have rotated
    // the blob out — or re-registered it under a *different* KV key —
    // during that window. Signing against the stale snapshot would use a
    // PEM the socket no longer exposes. Take the read lock only long enough
    // to look up + compare, then drop it before the store lock (the same
    // lock-ordering `local_sign_first_pass` documents).
    {
        let registry = state.registry.read().unwrap_or_else(|e| e.into_inner());
        match signable_key(&registry, &state.filter, &fields.key_blob) {
            Some(reg) if reg.kv_key == kv_key => {}
            _ => {
                eprintln!(
                    "cache-warden: authsock sign denied for {kv_key:?} after approval: \
                     registry no longer resolves this blob to the approved KV key \
                     (rotated / removed / filter-hidden during the dialog await)"
                );
                return AgentMessage::failure();
            }
        }
    }
    let mut store = match state.shared.store.lock() {
        Ok(g) => g,
        Err(_) => return AgentMessage::failure(),
    };
    match eval_sign_guard(&store, &kv_key, guard_chain.as_deref(), peer_token) {
        SignGuardCheck::Unguarded | SignGuardCheck::Passed(_) => {}
        SignGuardCheck::ChainMissing => {
            drop(store);
            eprintln!(
                "cache-warden: authsock sign denied for {kv_key:?} after approval: guard \
                 requires a requester chain but the peer could not be walked"
            );
            return AgentMessage::failure();
        }
        SignGuardCheck::Denied(kind) => {
            drop(store);
            eprintln!(
                "cache-warden: authsock sign denied for {kv_key:?} after approval: guard \
                 constraint {kind:?} failed on re-evaluation (record changed during approval)"
            );
            return AgentMessage::failure();
        }
    }
    sign_body_after_guard(
        &mut store,
        state.shared.auth.as_ref(),
        &state.shared.runner,
        &state.shared.clock,
        &state.shared.authsock_cap,
        requester.as_deref(),
        &kv_key,
        &source,
        &fields,
    )
}

/// The post-guard sign body: fetch the PEM through the auth gate
/// (lazily fetching an op key on its first use), sign, refresh the idle
/// window, and return `SIGN_RESPONSE`. Any failure surfaces as
/// `SSH_AGENT_FAILURE`.
///
/// Extracted so both the fast unguarded path (`local_sign_first_pass`'s
/// inline branch) and the guarded finalize
/// (`local_sign_finalize_after_approval`) share the exact same body under
/// their respective one-shot store-lock holds. `sign_with_resolved_key`
/// also delegates here after its own guard check, so unit tests that hit
/// the legacy entry point keep their behaviour verbatim.
#[allow(clippy::too_many_arguments)]
fn sign_body_after_guard<A, R, C>(
    store: &mut Store,
    auth: &A,
    runner: &R,
    clock: &C,
    cap: &cache_warden::Capability,
    requester: Option<&[ProcessInfo]>,
    kv_key: &str,
    source: &KeySource,
    fields: &SignRequestFields,
) -> AgentMessage
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    if !ensure_loaded(store, kv_key, source, auth, runner, requester, cap, clock) {
        return AgentMessage::failure();
    }
    let signature = match store.get(kv_key, cap, clock).ok().flatten() {
        Some(secret) => secret.with_exposed(|bytes| {
            let pem = String::from_utf8_lossy(bytes);
            sign(&pem, &fields.data, fields.flags)
        }),
        None => return AgentMessage::failure(),
    };
    match signature {
        Ok(blob) => {
            let _ = store.extend(kv_key, cap, clock);
            AgentMessage::sign_response(&blob)
        }
        Err(_) => AgentMessage::failure(),
    }
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
///
/// Test-only: production signs via [`local_sign_first_pass`] →
/// [`sign_with_resolved_key`] (resolving the key under a brief registry
/// read lock, gating on any DR-0031 dialog). The unit tests drive the
/// same resolve-then-sign composition through [`sign_local_with_ctx`].
#[cfg(test)]
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
    /// carry an internal `authsock/op_*` KV name that never appears in `[kv.*]`
    /// config, so they are naturally unrestricted here.
    kv_process_policies: &'a std::collections::BTreeMap<String, Vec<String>>,
    /// Capability token for store access (authsock operations use the authsock cap).
    authsock_cap: &'a cache_warden::Capability,
    /// DR-0030: the requester's ancestry chain enriched with
    /// `unique_id`, captured at the same walk that produced the DR-0012
    /// `requester` above. `None` on non-macOS or when the peer pid could
    /// not be walked. Fed to [`guard_eval::evaluate`] on a guarded key
    /// (fail-closed when a `same-ancestor` / `same-shell` constraint
    /// needs it but the chain is `None`).
    guard_chain: Option<&'a [GetterProcess]>,
    /// DR-0030: the peer's `peer_audit_token` snapshot (euid/ruid),
    /// captured at connection accept time (`handle_connection`). Race-
    /// free per the kernel's `LOCAL_PEERTOKEN` contract, so the
    /// same value is reused for every SIGN_REQUEST on the connection.
    /// `None` outside macOS or on a `getsockopt` failure; the evaluator
    /// then denies whenever a `same-user` constraint requires it.
    guard_audit_token: Option<GetterAuditToken>,
}

/// Test-only resolve-then-sign shim (no socket I/O): resolves the key blob to a
/// signable KV key via [`signable_key`] (registry lookup **and** the socket
/// filter), then delegates to [`sign_with_resolved_key`]. It mirrors the exact
/// composition production runs (`local_sign_first_pass` does the same resolve + delegate,
/// but under a live socket's registry read lock), so the SIGN_REQUEST → core →
/// signature path stays unit-testable without a runtime or a full `SocketState`.
#[cfg(test)]
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
    // IDENTITIES. Clone the small bits we need so the registry borrow ends here,
    // before the (possibly slow) auth gate / op fetch (the source carries the op
    // fetch spec). `local_sign_first_pass` relies on the same split to bound its registry
    // read-lock hold to just this resolution (see its lock-ordering note).
    let Some(registered) = signable_key(ctx.registry, ctx.filter, &fields.key_blob) else {
        return AgentMessage::failure();
    };
    let kv_key = registered.kv_key.clone();
    let source = registered.source.clone();

    let exec = SignExecCtx {
        store: ctx.store,
        auth: ctx.auth,
        runner: ctx.runner,
        clock: ctx.clock,
        kv_process_policies: ctx.kv_process_policies,
        authsock_cap: ctx.authsock_cap,
        guard_chain: ctx.guard_chain,
        guard_audit_token: ctx.guard_audit_token,
    };
    sign_with_resolved_key(&exec, requester, &kv_key, &source, &fields)
}

/// The borrowed core services the **post-resolution** half of a local sign needs
/// (no registry / filter — the key is already resolved). Grouped so the signing
/// helper keeps a small argument list (`clippy::too_many_arguments`). Each field
/// is a short-lived borrow of a `Shared` member; nothing here owns a secret.
///
/// Test-only: production runs the resolve + guard + body flow directly
/// through [`local_sign_first_pass`] / [`local_sign_finalize_after_approval`]
/// (no intermediate context struct). This kept the pre-DR-0031 unit tests
/// (`handle_local_sign*` shims) working verbatim against
/// [`sign_with_resolved_key`], which is itself test-only now.
#[cfg(test)]
struct SignExecCtx<'a, A: ?Sized, R, C> {
    /// The core store holding the private-key PEMs.
    store: &'a std::sync::Mutex<Store>,
    /// The re-authentication gate (shared with the control socket).
    auth: &'a A,
    /// The command runner used to regenerate a hard-expired command source.
    runner: &'a R,
    /// The monotonic clock for TTL evaluation.
    clock: &'a C,
    /// Key-level process-access policies (DR-0012 key layer): KV key name → its
    /// non-empty `allowed_processes` list.
    kv_process_policies: &'a std::collections::BTreeMap<String, Vec<String>>,
    /// Capability token for store access (authsock operations use the authsock cap).
    authsock_cap: &'a cache_warden::Capability,
    /// DR-0030: the requester's ancestry chain enriched with
    /// `unique_id`, captured at the same walk that produced `requester`
    /// above (see [`local_sign_first_pass`]). `None` on non-macOS / when the peer
    /// pid could not be walked. Fed to [`guard_eval::evaluate`] on a
    /// guarded key (fail-closed if the constraint needs it and it is
    /// missing).
    guard_chain: Option<&'a [GetterProcess]>,
    /// DR-0030: the peer's `peer_audit_token` snapshot (euid/ruid), taken
    /// at connection accept time. Race-free per `LOCAL_PEERTOKEN`, so
    /// reused across every SIGN_REQUEST on this connection.
    guard_audit_token: Option<GetterAuditToken>,
}

/// Sign a SIGN_REQUEST whose key is already resolved to `kv_key` / `source`
/// (registry lookup + filter applied by the caller). Runs the key-level process
/// gate, fetches the PEM through the auth gate (lazily fetching an op key on its
/// first use), signs, refreshes the idle window, and returns SIGN_RESPONSE. Any
/// failure (denied, hard-expired static, sign error) is SSH_AGENT_FAILURE.
///
/// Test-only entry point kept for the pre-DR-0031 unit tests
/// (`handle_local_sign*`). Production runs the equivalent flow through
/// [`local_sign_first_pass`] (unguarded ⇒ inline
/// [`sign_body_after_guard`] under one lock) or the finalize path
/// [`local_sign_finalize_after_approval`] (guarded ⇒ re-eval + body).
#[cfg(test)]
fn sign_with_resolved_key<A, R, C>(
    ctx: &SignExecCtx<'_, A, R, C>,
    requester: Option<&[ProcessInfo]>,
    kv_key: &str,
    source: &KeySource,
    fields: &SignRequestFields,
) -> AgentMessage
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    // Key-level process-access gate (DR-0012 key layer). When this KV key carries
    // an `allowed_processes` restriction, the requester's ancestry must pass the
    // shared gate (fail-closed on an unknown requester) before the PEM is fetched
    // or signed with. A restricted key the requester is not permitted to use is
    // refused with a plain SSH_AGENT_FAILURE — the same "leak nothing" response as
    // an unknown or filtered-out key (the connection already enumerated this key,
    // mirroring the socket layer's per-key warden behaviour: the key may be listed
    // but cannot be signed with). An op-key's internal `authsock/op_*` name never
    // appears in `[kv.*]` config, so it is unrestricted here.
    if let Some(allowed) = ctx.kv_process_policies.get(kv_key)
        && !chain_gate_passes(requester, allowed)
    {
        return AgentMessage::failure();
    }
    let (auth, runner, clock) = (ctx.auth, ctx.runner, ctx.clock);

    let mut store = match ctx.store.lock() {
        Ok(g) => g,
        Err(_) => return AgentMessage::failure(),
    };

    // DR-0030 evaluation order ③ (symmetric with `handle_get`): a per-entry
    // guard is checked *before* the retrieval chain so a denied requester
    // never triggers regeneration / TouchID / a re-auth prompt on the SIGN
    // path — the denial must be silent and cost-free. A signature is the
    // consumption of the private key just as `kv.get` is the consumption of
    // the plaintext; guarding the value but not the signing use would let
    // any same-uid process bypass the setter's declared restriction
    // (`[authsock.sockets.*].keys` can name non-reserved KV keys). §4 also
    // requires the setter identity never crosses back to the getter side,
    // so a denial answers with the same `SSH_AGENT_FAILURE` an unknown /
    // filtered-out key uses (the agent protocol has no ErrorKind — the
    // wire message shape is fixed to bare FAILURE, and the constraint kind
    // is recorded only in the daemon's structured stderr diagnostic).
    match eval_sign_guard(&store, kv_key, ctx.guard_chain, ctx.guard_audit_token) {
        SignGuardCheck::Unguarded | SignGuardCheck::Passed(_) => {}
        SignGuardCheck::ChainMissing => {
            eprintln!(
                "cache-warden: authsock sign denied for {kv_key:?}: guard \
                 requires a requester chain but the peer could not be walked"
            );
            return AgentMessage::failure();
        }
        SignGuardCheck::Denied(kind) => {
            eprintln!(
                "cache-warden: authsock sign denied for {kv_key:?}: guard \
                 constraint {kind:?} failed"
            );
            return AgentMessage::failure();
        }
    }

    // Fetch + sign + idle-extend, shared with the DR-0031 §8 finalize
    // path (`local_sign_finalize_after_approval`). Runs under the store
    // lock we already hold above.
    sign_body_after_guard(
        &mut store,
        auth,
        runner,
        clock,
        ctx.authsock_cap,
        requester,
        kv_key,
        source,
        fields,
    )
}

/// Make `key`'s value readable (Active), running the core's auth gate.
///
/// `source` describes how the private value reaches the core:
///
/// - [`KeySource::Local`]: the entry exists from startup. An absent entry is a
///   failure (its PEM was never loaded); otherwise the Iteration 1 gate applies
///   (Active passes, SoftExpired extends, HardExpired regenerates if regenerable).
/// - [`KeySource::Op`]: the entry is created **lazily**. If the core has no entry
///   yet (the NotLoaded case), [`Store::get_or_regenerate`] is called: it uses
///   the definition registered at spawn time (DR-0014 lazy path) to run the fetch
///   command, re-authenticate, and install the value — then it is Active. Once it
///   exists, the same Iteration 1 gate applies (idle extend within soft, regenerate
///   via the same command after hard).
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
    cap: &cache_warden::Capability,
    clock: &C,
) -> bool
where
    A: Authenticator + ?Sized,
    R: SourceRunner,
    C: Clock,
{
    match store.state_of(key, clock) {
        // Absent. For an op key this is the lazy NotLoaded path: the definition
        // was registered at spawn time, so get_or_regenerate can fetch + auth +
        // set the value via the core DR-0014 path. A local key has no value to
        // load, so it stays a failure.
        None => match source {
            KeySource::Local => false,
            KeySource::Op { .. } => {
                match store.get_or_regenerate(key, runner, auth, requester, cap, clock) {
                    Ok(()) | Err(RegenerateDefOutcome::ValueResident) => true,
                    // DR-0022 §3: same observability hook on the lazy NotLoaded path —
                    // an op-sourced key whose first fetch is still inside the backoff
                    // window from a previous failure surfaces as `agent refused`, with
                    // this single stderr line so the cause is not opaque.
                    Err(RegenerateDefOutcome::Backoff { retry_after }) => {
                        eprintln!(
                            "cache-warden: sign refused for `{key}` (backoff active for {:.1}s after previous fetch failure)",
                            retry_after.as_secs_f64()
                        );
                        false
                    }
                    Err(_) => false,
                }
            }
        },
        Some(EntryState::Active) => true,
        Some(EntryState::SoftExpired) => {
            matches!(
                store.extend_authenticated(key, auth, requester, cap, clock),
                Ok(())
            )
        }
        Some(EntryState::HardExpired) => {
            match store.regenerate(key, runner, auth, requester, cap, clock) {
                Ok(()) => true,
                // A static hard-expired key cannot regenerate; not signable.
                // DR-0022: Backoff means a previous fetch failed recently; treat as
                // non-signable (agent refused). The ssh client side retries via
                // ConnectionAttempts / ssh-retry wrappers after the backoff elapses.
                Err(RegenerateOutcome::Backoff { retry_after }) => {
                    // Emit a one-line stderr diagnostic so an operator watching
                    // the daemon log can tell "agent refused" was caused by a
                    // recent fetch failure (DR-0022 §3 observability), not by a
                    // missing or filtered key. The key name is value-free.
                    eprintln!(
                        "cache-warden: sign refused for `{key}` (backoff active for {:.1}s after previous fetch failure)",
                        retry_after.as_secs_f64()
                    );
                    false
                }
                Err(
                    RegenerateOutcome::NotFound
                    | RegenerateOutcome::NotRegenerable
                    | RegenerateOutcome::NotHardExpired
                    | RegenerateOutcome::RunFailed(_)
                    | RegenerateOutcome::AuthFailed(_)
                    | RegenerateOutcome::CapMismatch,
                ) => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cache_warden::{
        AllowAll, DeclaredAncestor, DenyAll, FakeClock, GuardConstraint, GuardRecord, GuardSetter,
        PinnedProcess, RunError, SecretBytes, SourceRunner, Ttl, ValueSource,
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
        cap: &cache_warden::Capability,
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
            authsock_cap: cap,
            guard_chain: None,
            guard_audit_token: None,
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
        cap: &cache_warden::Capability,
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
            authsock_cap: cap,
            guard_chain: None,
            guard_audit_token: None,
        };
        sign_local_with_ctx(&ctx, requester, msg)
    }

    /// Test shim for the DR-0030 guard path on a SIGN_REQUEST: threads a
    /// prepared `GetterProcess` chain + `GetterAuditToken` into
    /// [`LocalSignCtx`] so tests can exercise a guarded key's sign path
    /// without a real socket / `peer_audit_token` syscall. Mirrors
    /// [`handle_local_sign`] with the additional guard material.
    #[allow(clippy::too_many_arguments)]
    fn handle_local_sign_with_guard<A, R, C>(
        registry: &PublicKeyRegistry,
        filter: &FilterEvaluator,
        store: &Mutex<Store>,
        auth: &A,
        runner: &R,
        clock: &C,
        requester: Option<&[ProcessInfo]>,
        guard_chain: Option<&[GetterProcess]>,
        guard_audit_token: Option<GetterAuditToken>,
        cap: &cache_warden::Capability,
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
            authsock_cap: cap,
            guard_chain,
            guard_audit_token,
        };
        sign_local_with_ctx(&ctx, requester, msg)
    }

    /// The composed core KV key for an op item id, in the reserved `authsock`
    /// namespace (`authsock/op_<item_id>`). A thin wrapper over the production
    /// [`OpKvKey`] so tests read against the same serialization the daemon uses.
    fn op_kv_key(item_id: &str) -> String {
        OpKvKey::new(item_id)
            .expect("test item id is alphanumeric")
            .as_str()
            .to_string()
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
    fn fixture(clock: &FakeClock) -> (Mutex<Store>, cache_warden::Capability, PublicKeyRegistry) {
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        store
            .set(
                "GITHUB_KEY",
                ValueSource::Static,
                SecretBytes::from(ED25519_PEM),
                ttl(),
                &cap,
                clock,
            )
            .unwrap();
        let registry = build_registry("test", &["GITHUB_KEY".into()], &mut store, &cap, clock);
        (Mutex::new(store), cap, registry)
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
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        store
            .set(
                "GITHUB_KEY",
                ValueSource::Static,
                SecretBytes::from(ED25519_PEM),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
        let reg = build_registry(
            "s",
            &["GITHUB_KEY".into(), "ABSENT".into()],
            &mut store,
            &cap,
            &clock,
        );
        // Only the present, parseable key is registered.
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn local_registry_identities_answer_returns_registered_public_key() {
        let clock = FakeClock::new();
        let (_store, _cap, registry) = fixture(&clock);
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
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
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
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_restricted_key_denies_non_matching_requester() {
        // A requester whose ancestry has no allowed basename is refused with a
        // bare FAILURE (leak nothing) — even though the key is registered/listed.
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn sign_request_restricted_key_with_unknown_requester_is_fail_closed() {
        // requester == None + a real restriction => fail-closed (FAILURE).
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn sign_request_unrestricted_key_admits_even_unknown_requester() {
        // GITHUB_KEY has no policy entry => unrestricted; a None requester signs.
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    // ---- DR-0030: per-entry guard on the SIGN_REQUEST path ----
    //
    // These pin the same evaluation order the control-socket `handle_get`
    // uses (DR-0030 §4 ③), extended to authsock: a guarded KV key referenced
    // by `[authsock.sockets.*].keys` cannot be signed with unless the
    // requester's chain + audit token satisfy the setter's declaration. The
    // authsock wire has no ErrorKind — a denial is bare `SSH_AGENT_FAILURE`
    // (same shape as unknown / filtered-out key), so tests assert on
    // `MessageType::Failure` + empty payload.

    /// Attach a `same-user` guard to `GITHUB_KEY` for setter uid 501. Shared
    /// across the guard-path tests to keep each test focused on its
    /// requester side.
    fn install_same_user_guard(store: &Mutex<Store>, cap: &cache_warden::Capability) {
        let record = GuardRecord::new(
            vec![GuardConstraint::SameUser],
            GuardSetter {
                euid: 501,
                ruid: 501,
            },
        );
        store
            .lock()
            .unwrap()
            .set_guard("GITHUB_KEY", record, cap)
            .expect("set_guard must succeed with the authsock cap");
    }

    /// Enrich a plain `ProcessInfo` chain into `GetterProcess` with no
    /// unique_id (the non-macOS / private-API-failure fallback). The
    /// evaluator then compares by pid + start_time.
    fn getter_chain(chain: &[ProcessInfo]) -> Vec<GetterProcess> {
        chain
            .iter()
            .map(|info| GetterProcess {
                info: info.clone(),
                unique_id: None,
            })
            .collect()
    }

    /// A guarded key whose `same-user` constraint is satisfied by the
    /// requester's audit token → SignResponse (the auth gate / retrieval
    /// continues as before). Pins that a guard does not break the happy
    /// path when the constraint holds.
    #[test]
    fn sign_request_guarded_key_admits_matching_requester() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        install_same_user_guard(&store, &cap);
        let chain = [proc(100, "ssh"), proc(50, "zsh")];
        let g_chain = getter_chain(&chain);
        let token = GetterAuditToken {
            euid: 501,
            ruid: 501,
        };
        let req = sign_request(&blob_of(ED25519_PUB), b"agent challenge", 0);
        let resp = handle_local_sign_with_guard(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            Some(&chain),
            Some(&g_chain),
            Some(token),
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    /// Constraint fails (setter recorded uid 501, getter connected as 502)
    /// → bare `SSH_AGENT_FAILURE`. Verifies §4 "denial is silent" — no
    /// setter identity crosses back (payload is empty), and the same
    /// FAILURE shape an unknown key returns is reused.
    #[test]
    fn sign_request_guarded_key_denies_on_constraint_mismatch() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        install_same_user_guard(&store, &cap);
        let chain = [proc(100, "ssh"), proc(50, "zsh")];
        let g_chain = getter_chain(&chain);
        // Different euid than the setter's snapshot → same-user constraint
        // fails inside `guard_eval::evaluate` and the whole sign path
        // returns FAILURE before the store lock / auth gate is exercised.
        let token = GetterAuditToken {
            euid: 502,
            ruid: 502,
        };
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_with_guard(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            Some(&chain),
            Some(&g_chain),
            Some(token),
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    /// Guard present but the connection carries no audit token (non-macOS
    /// / getsockopt failure) → `MissingContext` deny (fail-closed). This
    /// pins the "material acquisition failed → deny" branch that DR-0030
    /// §Security calls out for the `SameUser` constraint.
    #[test]
    fn sign_request_guarded_key_fail_closed_when_audit_token_missing() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        install_same_user_guard(&store, &cap);
        let chain = [proc(100, "ssh")];
        let g_chain = getter_chain(&chain);
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_with_guard(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            Some(&chain),
            Some(&g_chain),
            None, // audit token unavailable
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    /// Guard present, `SameAncestor` constraint requires a getter chain,
    /// and the daemon could not walk the peer's ancestry (`guard_chain =
    /// None`) → deny before any store work. Symmetric with the
    /// `handle_get` "peer could not be walked" branch.
    #[test]
    fn sign_request_guarded_key_fail_closed_when_chain_missing() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::SameShell {
                    shell_name: "zsh".to_string(),
                },
                pinned: PinnedProcess {
                    pid: 50,
                    start_time: Some(Duration::from_secs(50)),
                    unique_id: None,
                    path: std::path::PathBuf::from("/bin/zsh"),
                    name: "zsh".to_string(),
                },
            }],
            GuardSetter {
                euid: 501,
                ruid: 501,
            },
        );
        store
            .lock()
            .unwrap()
            .set_guard("GITHUB_KEY", record, &cap)
            .unwrap();
        let token = GetterAuditToken {
            euid: 501,
            ruid: 501,
        };
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_with_guard(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None, // requester chain unknown
            None, // guard chain unavailable
            Some(token),
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty());
    }

    /// A key with no `access_guard` record signs as before — DR-0030 gate
    /// is a strict addition, unguarded keys keep the Iteration 1 behaviour
    /// (regression pin for the "guard is opt-in per entry" property).
    #[test]
    fn sign_request_unguarded_key_bypasses_guard_gate() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        // No `set_guard` call: `guard_of("GITHUB_KEY")` returns None and
        // the guard block short-circuits, so even a totally-missing chain
        // + token still signs.
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign_with_guard(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            None,
            None,
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    /// Guard denial must not fire the auth gate: a `DenyAll` authenticator
    /// would trip re-auth on a soft-expired entry, so if the guard let
    /// evaluation reach `ensure_loaded` the test would still fail. But
    /// here the entry is Active — the point of this test is instead that
    /// the guard denial happens **before** the store lock is used for any
    /// state transition (idle-extend / regenerate). We assert that after
    /// the denied SIGN_REQUEST the entry is unchanged (still gettable
    /// without re-auth from an `AllowAll` follow-up), pinning "no
    /// regenerate / no TouchID / no backoff" on the deny path.
    #[test]
    fn sign_request_guarded_key_denial_leaves_entry_untouched() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        install_same_user_guard(&store, &cap);
        let chain = [proc(100, "ssh")];
        let g_chain = getter_chain(&chain);
        let deny_token = GetterAuditToken {
            euid: 999,
            ruid: 999,
        };
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let denied = handle_local_sign_with_guard(
            &registry,
            &no_filter(),
            &store,
            &DenyAll, // would fail any re-auth if the deny path reached it
            &NoRunner,
            &clock,
            Some(&chain),
            Some(&g_chain),
            Some(deny_token),
            &cap,
            &req,
        );
        assert_eq!(denied.msg_type, MessageType::Failure);
        // Value is still there, still Active — the entry survived unchanged.
        let mut guard = store.lock().unwrap();
        let value = guard.get("GITHUB_KEY", &cap, &clock).ok().flatten();
        assert!(
            value.is_some(),
            "denied guard must not destroy / regenerate the entry"
        );
    }

    #[test]
    fn sign_request_for_unknown_key_is_failure() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        let req = sign_request(b"bogus-blob", b"data", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn sign_request_denied_auth_is_failure_and_leaks_nothing() {
        // Soft-expire so a sign needs re-auth; DenyAll blocks it -> FAILURE.
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn sign_request_soft_expired_extends_then_signs_with_allow_all() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn sign_request_hard_expired_static_key_is_failure() {
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn successful_sign_refreshes_idle_window() {
        // After a sign while soft-expired-then-extended, a second sign within the
        // refreshed window must not need auth again (idle extend, DR-0011).
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
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
            &cap,
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
            &cap,
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
        let (store, cap, registry) = fixture(&clock);
        let req = AgentMessage::new(MessageType::Lock, bytes::Bytes::new());
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &cap,
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

    /// A registry holding one op-sourced key (no core entry yet — lazy) plus a
    /// store that has the op key's definition registered (as spawn_listeners does
    /// after A-3a). The op key's KV name is namespaced like the production path.
    fn op_fixture(
        soft: u64,
        hard: u64,
    ) -> (Mutex<Store>, cache_warden::Capability, PublicKeyRegistry) {
        let argv = private_key_argv("/path/cache-warden", "itemABC", Some("kawaz.1password.com"));
        let kv_key = op_kv_key("itemABC");
        let mut registry = PublicKeyRegistry::new();
        registry
            .register_op_key(
                kv_key.clone(),
                ED25519_PUB,
                "kawaz op key",
                KeySource::Op {
                    argv: argv.clone(),
                    soft_ttl_secs: Some(soft),
                    hard_ttl_secs: Some(hard),
                },
            )
            .unwrap();
        // Register the definition so get_or_regenerate can lazily produce the value
        // (mirrors what spawn_listeners now does after A-3a).
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let ttl = Ttl::new(
            Some(Duration::from_secs(soft)),
            Some(Duration::from_secs(hard)),
        )
        .unwrap();
        store
            .define(kv_key, ValueSource::command(argv), ttl)
            .expect("define must succeed for a fresh store");
        (Mutex::new(store), cap, registry)
    }

    #[test]
    fn op_key_first_sign_lazily_loads_fetches_and_signs() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
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
            &cap,
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
        assert!(
            store
                .lock()
                .unwrap()
                .get(&key, &cap, &clock)
                .ok()
                .flatten()
                .is_some()
        );
    }

    #[test]
    fn op_key_second_sign_within_soft_hits_cache_no_refetch() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
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
            &cap,
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
            &cap,
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
        let (store, cap, registry) = op_fixture(SOFT, HARD);
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
            &cap,
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
            &cap,
            &req2,
        );
        assert_eq!(r2.msg_type, MessageType::SignResponse);
        assert_eq!(runner.runs(), 2, "hard-expired op key re-fetches");
    }

    #[test]
    fn op_key_first_sign_denied_auth_loads_nothing_and_fails() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
        // The fetch ran (before auth), but the denied value was discarded — no
        // core entry was created.
        assert_eq!(runner.runs(), 1);
        let key = op_kv_key("itemABC");
        assert!(
            store
                .lock()
                .unwrap()
                .get(&key, &cap, &clock)
                .ok()
                .flatten()
                .is_none()
        );
    }

    #[test]
    fn op_key_fetch_failure_skips_auth_and_fails() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        let key = op_kv_key("itemABC");
        assert!(
            store
                .lock()
                .unwrap()
                .get(&key, &cap, &clock)
                .ok()
                .flatten()
                .is_none()
        );
    }

    #[test]
    fn op_key_unknown_blob_is_failure() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
        let req = sign_request(b"not-a-registered-blob", b"d", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &PemRunner::new(),
            &clock,
            None,
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn op_key_filtered_out_is_failure() {
        // A comment filter that hides the op key denies its direct SIGN_REQUEST.
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
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
            &cap,
            &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[test]
    fn op_key_enumerates_with_comment_from_title() {
        // The op key shows in REQUEST_IDENTITIES with the item title as its comment.
        let (_store, _cap, registry) = op_fixture(SOFT, HARD);
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
        // The core KV key is composed into the reserved `authsock` namespace
        // (DR-0018 §4.5): `authsock/op_<item_id>`, replacing the retired
        // `__authsock_op:` pseudo-prefix that violated the DR-0017 §1.5 charset.
        assert_eq!(reg.kv_key, "authsock/op_itemABC");
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

    #[test]
    fn op_kv_key_composes_into_the_reserved_authsock_namespace() {
        // The domain type owns the serialization: an alphanumeric item id yields
        // `authsock/op_<id>`, which is a valid composed key the core accepts.
        let key = OpKvKey::new("itemABC").unwrap();
        assert_eq!(key.as_str(), "authsock/op_itemABC");
        // The composed form must pass the core's own syntax gate (the whole point
        // of moving off the `:`-bearing prefix — DR-0017 §1.5 / DR-0018 §4.5).
        assert!(cache_warden::validate_key_syntax(key.as_str()).is_ok());
    }

    #[test]
    fn op_kv_key_rejects_non_alphanumeric_item_ids() {
        // A `:` in an item id can never be composed (it would reproduce the old
        // charset violation); the same for other non-alphanumeric bytes and the
        // empty id. Rejecting here degrades to a skipped key, not a store error.
        for bad in [
            "", "item:ABC", "item-abc", "item/abc", "item abc", "item_abc",
        ] {
            assert!(
                OpKvKey::new(bad).is_none(),
                "{bad:?} must not compose into a store key"
            );
        }
    }

    #[test]
    fn register_op_keys_skips_a_non_composable_item_id() {
        // A discovered key whose item id cannot form a valid segment is skipped
        // rather than registered — the socket still serves the composable keys.
        let source = AuthsockSource {
            name: "default".into(),
            op_account: None,
            members: vec!["op://".into()],
            soft_ttl_secs: None,
            hard_ttl_secs: None,
        };
        let keys = vec![DiscoveredKey {
            item_id: "bad:id".into(),
            public_key: ED25519_PUB.into(),
            title: "weird".into(),
            fingerprint: "SHA256:z".into(),
            vault: "v".into(),
        }];
        let mut registry = PublicKeyRegistry::new();
        let n = register_op_keys("sock", "/path/cache-warden", &source, &keys, &mut registry);
        assert_eq!(n, 0, "a non-composable item id registers no key");
    }

    // ---- A-3a: op key definition registration + get_or_regenerate unification ----
    //
    // These tests capture the post-refactor contract: after spawn_listeners-level
    // setup (registry registration + store.define), the core's get_or_regenerate
    // path handles lazy loading rather than the now-deleted lazy_load_op_key.
    //
    // Step 2 (TDD red): written before the implementation exists; all three fail
    // until step 3 (spawn_listeners define registration + ensure_loaded rewrite).

    /// After spawn_listeners-equivalent setup (op_fixture now calls store.define),
    /// the op key's kv_key is registered in the definition registry.
    #[test]
    fn op_key_registers_definition_in_store_at_spawn() {
        let clock = FakeClock::new();
        let (store, _cap, _registry) = op_fixture(SOFT, HARD);
        let kv_key = op_kv_key("itemABC");
        assert!(
            store.lock().unwrap().is_defined(&kv_key),
            "op key must be registered in the definition registry after spawn"
        );
        let _ = clock; // suppress unused warning
    }

    /// When a definition is registered, ensure_loaded for an absent op key goes
    /// through store.get_or_regenerate rather than the former lazy_load_op_key.
    #[test]
    fn op_key_lazy_load_goes_through_get_or_regenerate() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
        let runner = PemRunner::new();
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &runner,
            &clock,
            None,
            &cap,
            &req,
        );
        // The runner must have been called exactly once (lazy load via get_or_regenerate).
        assert_eq!(
            runner.runs(),
            1,
            "get_or_regenerate must invoke the runner once for a missing op key"
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    /// After a fetch failure, the definition persists (is_defined true) but no
    /// value entry is created (has_value false), allowing the next call to retry.
    #[test]
    fn op_key_fetch_failure_does_not_remove_definition() {
        let clock = FakeClock::new();
        let (store, cap, registry) = op_fixture(SOFT, HARD);
        let kv_key = op_kv_key("itemABC");

        // NoRunner always fails the fetch.
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry,
            &no_filter(),
            &store,
            &AllowAll,
            &NoRunner,
            &clock,
            None,
            &cap,
            &req,
        );
        assert_eq!(
            resp.msg_type,
            MessageType::Failure,
            "fetch failure yields SSH_AGENT_FAILURE"
        );

        let guard = store.lock().unwrap();
        // Definition persists through failure so the next attempt can retry.
        assert!(
            guard.is_defined(&kv_key),
            "definition must survive a fetch failure (retry is possible)"
        );
        // No value was installed.
        assert!(
            !guard.has_value(&kv_key),
            "no value entry must exist after a fetch failure"
        );
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
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        store
            .set(
                "GITHUB_KEY",
                ValueSource::Static,
                SecretBytes::from(ED25519_PEM),
                ttl(),
                &cap,
                &clock,
            )
            .unwrap();
        let registry = build_registry("test", &["GITHUB_KEY".into()], &mut store, &cap, &clock);
        let shared = Arc::new(crate::daemon::server::Shared::new_for_test(
            store,
            cap,
            Box::new(AllowAll),
            clock,
        ));
        Arc::new(SocketState {
            name: "test".into(),
            registry: Arc::new(RwLock::new(registry)),
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
        let resp = respond(&state, None, None, None, &req, &mut routes).await;
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[tokio::test]
    async fn identities_merge_local_plus_upstream() {
        let up_id = upstream_identity("upstream-key");
        let (path, _h) = spawn_fake_upstream(vec![up_id.clone()], None);
        let state = socket_state(&[&path]);
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, None, None, &req, &mut routes).await;

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
        let resp = respond(&state, None, None, None, &req, &mut routes).await;

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
        let resp = respond(&state, None, None, None, &req, &mut routes).await;
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
        let _ = respond(&state, None, None, None, &enum_req, &mut routes).await;

        let sign_req = sign_request(&up_id.key_blob, b"challenge", 0);
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let (store, cap, registry) = fixture(&clock);
        let filter = parse_filter(&["comment=GITHUB_KEY"]);
        let data = b"filtered-but-allowed";
        let req = sign_request(&blob_of(ED25519_PUB), data, 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &cap, &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn handle_local_sign_with_excluding_filter_is_failure() {
        // A filter that hides the local key rejects a direct SIGN_REQUEST even
        // though the PEM is reachable (no enumeration needed to deny).
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        let filter = parse_filter(&["comment=other-key*"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &cap, &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
    }

    #[test]
    fn handle_local_sign_blob_filter_admits_ed25519() {
        // A type=ed25519 filter (blob-derived) admits the Ed25519 local key.
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        let filter = parse_filter(&["type=ed25519"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &cap, &req,
        );
        assert_eq!(resp.msg_type, MessageType::SignResponse);
    }

    #[test]
    fn handle_local_sign_blob_filter_excludes_other_type() {
        // A type=rsa filter hides the Ed25519 local key.
        let clock = FakeClock::new();
        let (store, cap, registry) = fixture(&clock);
        let filter = parse_filter(&["type=rsa"]);
        let req = sign_request(&blob_of(ED25519_PUB), b"d", 0);
        let resp = handle_local_sign(
            &registry, &filter, &store, &AllowAll, &NoRunner, &clock, None, &cap, &req,
        );
        assert_eq!(resp.msg_type, MessageType::Failure);
    }

    #[tokio::test]
    async fn identities_filter_hides_non_matching_local_key() {
        // A filter that excludes the local key yields an empty IDENTITIES_ANSWER.
        let state = socket_state_filtered(&[], parse_filter(&["comment=nope*"]));
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, None, None, &req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        assert!(ids.is_empty(), "filtered-out local key must not enumerate");
    }

    #[tokio::test]
    async fn identities_filter_keeps_matching_local_key() {
        let state = socket_state_filtered(&[], parse_filter(&["comment=GITHUB_KEY"]));
        let mut routes = UpstreamRoutes::new();
        let req = AgentMessage::new(MessageType::RequestIdentities, bytes::Bytes::new());
        let resp = respond(&state, None, None, None, &req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &enum_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        let resp = respond(&state, None, None, None, &enum_req, &mut routes).await;
        let ids = resp.parse_identities().unwrap();
        // The local key's comment "GITHUB_KEY" does not match *upstream*, so only
        // the upstream key passes.
        let blobs: Vec<_> = ids.iter().map(|i| i.key_blob.to_vec()).collect();
        assert!(blobs.contains(&up_id.key_blob.to_vec()));
        assert!(!blobs.contains(&blob_of(ED25519_PUB)));

        let sign_req = sign_request(&up_id.key_blob, b"x", 0);
        let resp = respond(&state, None, None, None, &sign_req, &mut routes).await;
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
        refresh_due_matchers(std::slice::from_ref(&matcher), &github_settings(), &fetcher).await;

        // Now the published key is admitted, an unpublished one is not.
        assert!(matcher.matches(&github_identity(ED25519_PUB)));
        assert!(!matcher.matches(&github_identity(ED25519_PUB_2)));
    }

    #[tokio::test]
    async fn github_refresh_failure_is_fail_closed() {
        let matcher = GithubMatcher::new("kawaz");
        let fetcher = Arc::new(FakeGithubFetcher::new().failing_for("kawaz"));
        refresh_due_matchers(std::slice::from_ref(&matcher), &github_settings(), &fetcher).await;
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
        refresh_due_matchers(std::slice::from_ref(&matcher), &github_settings(), &fetcher).await;
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

    // ---- DR-0023 Phase 2: background op discovery refresh ----

    /// Build a `DiscoveredKey` from a public OpenSSH line (op item id + title are
    /// the metadata the registry keeps as the `ssh-add -l` comment / kv key).
    fn discovered(item_id: &str, public_openssh: &str, title: &str) -> DiscoveredKey {
        DiscoveredKey {
            item_id: item_id.into(),
            public_key: public_openssh.into(),
            title: title.into(),
            fingerprint: format!("SHA256:{item_id}"),
            vault: "Private".into(),
        }
    }

    /// A default op source (bare `op://`, no account) with TTLs — the shape
    /// `AuthsockSource::validate` produces for a `[authsock.sources.*] kind="op"`
    /// with no `members`.
    fn op_source() -> AuthsockSource {
        AuthsockSource {
            name: "src".into(),
            op_account: None,
            members: vec!["op://".into()],
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
        }
    }

    /// The wire blob of an OpenSSH public-key line (the SIGN/IDENTITIES id).
    fn openssh_blob(public_openssh: &str) -> Vec<u8> {
        use ssh_encoding::Encode;
        let pk = ssh_key::PublicKey::from_openssh(public_openssh).unwrap();
        let mut b = Vec::new();
        pk.key_data().encode(&mut b).unwrap();
        b
    }

    #[test]
    fn next_backoff_doubles_then_caps() {
        // The task-level retry delay doubles each attempt and never exceeds the
        // cap, so a persistently unavailable op (launchd biometric unreachable) is
        // retried on a widening interval instead of a tight spin (DR-0023 Phase 2:
        // 無限 tight loop 禁止). This is the `(e) 失敗 retry が backoff する` case.
        let d = std::time::Duration::from_secs;
        assert_eq!(
            next_backoff(DISCOVERY_RETRY_INITIAL),
            d(4),
            "2s doubles to 4s"
        );
        assert_eq!(next_backoff(d(4)), d(8));
        assert_eq!(next_backoff(d(16)), d(32));
        assert_eq!(
            next_backoff(d(32)),
            d(60),
            "doubling 32s would be 64s, capped at the 60s max"
        );
        assert_eq!(
            next_backoff(DISCOVERY_RETRY_MAX),
            DISCOVERY_RETRY_MAX,
            "already at the cap stays at the cap (never grows unbounded)"
        );
    }

    #[test]
    fn op_registry_from_layers_op_keys_onto_immutable_base() {
        // A discovery rebuild is `base` (local keys) + freshly discovered op keys.
        // The local base key must survive and the op key must be added — this is
        // the registry side of `(c) background discovery 完了後に registry が
        // 更新される`, at the deterministic unit level.
        let mut base = PublicKeyRegistry::new();
        base.register_from_pem("LOCAL_KEY", ED25519_PEM).unwrap();
        let keys = vec![discovered("itemAAA", ED25519_PUB_2, "Op Key")];

        let (registry, n) = op_registry_from(
            &base,
            "sock",
            Some("/path/to/cache-warden"),
            &op_source(),
            &keys,
        );

        assert_eq!(n, 1, "one op key layered on");
        assert_eq!(registry.len(), 2, "local base key + op key both present");
        assert_eq!(
            base.len(),
            1,
            "the base is immutable — a rebuild never mutates it"
        );
        // The local key is still resolvable.
        assert!(
            registry.lookup(&openssh_blob(ED25519_PUB)).is_some(),
            "the local base key survives the rebuild"
        );
        // The op key resolves with a lazy Op source (private PEM fetched at sign).
        let op = registry
            .lookup(&openssh_blob(ED25519_PUB_2))
            .expect("op key present after rebuild");
        assert!(
            matches!(op.source, KeySource::Op { .. }),
            "a discovered op key carries a lazy Op source"
        );
    }

    #[test]
    fn op_registry_from_rebuild_replaces_op_keys_but_keeps_base() {
        // A second discovery that no longer returns the previous op key rebuilds
        // to base-only (the stale op key is gone), while the local base key
        // persists across both rebuilds because the base is never re-read from the
        // core. This is the "hot-update replaces, does not accumulate" property.
        let mut base = PublicKeyRegistry::new();
        base.register_from_pem("LOCAL_KEY", ED25519_PEM).unwrap();

        let first = vec![discovered("itemAAA", ED25519_PUB_2, "First")];
        let (r1, _) = op_registry_from(&base, "sock", Some("/exe"), &op_source(), &first);
        assert_eq!(r1.len(), 2, "first rebuild: local + one op key");

        // A later discovery returns no op keys at all → rebuild is base-only.
        let (r2, n2) = op_registry_from(&base, "sock", Some("/exe"), &op_source(), &[]);
        assert_eq!(n2, 0, "no op keys in the second discovery");
        assert_eq!(
            r2.len(),
            1,
            "only the local base key remains (op key dropped)"
        );
        assert!(
            r2.lookup(&openssh_blob(ED25519_PUB)).is_some(),
            "the local base key persists across rebuilds"
        );
    }

    // ---- DR-0031 §8 approver-dialog integration on the SIGN path ----
    //
    // Pin the two-pass gated flow the control-socket `kv.get` already runs
    // (see server.rs). A guarded reveal SIGN must (a) leave unguarded
    // signs untouched — `FakeApprover.calls()` stays 0, (b) fire the
    // dialog only on a guarded key whose first-pass eval passes,
    // (c) map every non-`Approved` wire outcome onto bare FAILURE,
    // (d) fail-closed when the helper is `Down`, and (e) re-evaluate
    // the guard record after the dialog so a concurrent replace can
    // still deny (DR-0030 §5 "last declaration wins").

    #[cfg(target_os = "macos")]
    use cache_warden_approver::wire::Outcome as WireOutcomeT;

    /// The current process's euid+ruid — needed to build a
    /// `GetterAuditToken` that matches a same-user guard record seeded
    /// with `GuardSetter { euid, ruid }` derived from the *real* running
    /// test process. `local_sign_first_pass` walks the real chain from
    /// `std::process::id()`, so the guard evaluator receives the same
    /// uid whether the test seeds `501` or the current uid; using the
    /// current uid keeps the test portable across dev machines / CI.
    #[cfg(target_os = "macos")]
    fn current_uid() -> u32 {
        // SAFETY: `geteuid` takes no pointer arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Attach a same-user guard to `GITHUB_KEY` bound to the current
    /// process's uid so the SIGN first pass's real chain walk +
    /// `peer_audit_token` derivation actually satisfy the constraint.
    #[cfg(target_os = "macos")]
    fn install_same_user_guard_current_uid(shared: &crate::daemon::server::Shared) {
        let uid = current_uid();
        let record = GuardRecord::new(
            vec![GuardConstraint::SameUser],
            GuardSetter {
                euid: uid,
                ruid: uid,
            },
        );
        shared
            .store
            .lock()
            .unwrap()
            .set_guard("GITHUB_KEY", record, &shared.authsock_cap)
            .expect("set_guard succeeds with the authsock cap");
    }

    /// A `GetterAuditToken` matching the running test process — the
    /// runtime shape `peer_audit_token(fd)` returns for a real
    /// connection from this process to itself.
    #[cfg(target_os = "macos")]
    fn current_uid_token() -> GetterAuditToken {
        GetterAuditToken {
            euid: current_uid(),
            ruid: current_uid(),
        }
    }

    /// Build a `SocketState` (GITHUB_KEY registry, no filter, no upstream,
    /// no policy) and install the approver `slot_setter` on its shared.
    /// Returns the `state` and a handle to the shared for guard seeding
    /// / call-count assertions.
    #[cfg(target_os = "macos")]
    fn socket_state_with_approver<F>(setup: F) -> Arc<SocketState>
    where
        F: FnOnce(&crate::daemon::server::Shared),
    {
        let state = socket_state(&[]);
        setup(&state.shared);
        state
    }

    /// End-to-end: guarded SIGN + Approved outcome → verifiable
    /// `SignResponse` (the happy path of the two-pass flow). Pins that
    /// the dialog fires exactly once (`FakeApprover.calls() == 1`) and
    /// the finalize pass reaches the signing body.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_guarded_key_approved_returns_signature() {
        let fake = Arc::new(super::super::approver_wire::FakeApprover::new(
            WireOutcomeT::Approved,
        ));
        let fake_for_state = Arc::clone(&fake);
        let state = socket_state_with_approver(|shared| {
            install_same_user_guard_current_uid(shared);
            shared.approver.set_ready(fake_for_state.clone());
        });
        let mut routes = HashMap::new();
        let req = sign_request(&blob_of(ED25519_PUB), b"agent challenge", 0);
        let resp = super::sign_request(
            &state,
            Some(std::process::id()),
            Some(current_uid_token()),
            None,
            &req,
            &routes,
        )
        .await;
        // Silence "unused variable: routes" if this file's macro ever
        // reshuffles — routes is genuinely read by upstream forwarding
        // which does not fire here (blob is a local key).
        routes.clear();
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        assert_eq!(fake.calls(), 1, "dialog must fire exactly once");
    }

    /// Every non-`Approved` outcome on a guarded SIGN maps to bare
    /// `SSH_AGENT_FAILURE` with an empty payload — the agent wire has
    /// no error kind, so the classification is only observable in
    /// stderr (which the test does not capture — the important
    /// invariant is `Failure` + empty payload). Pins the outcome
    /// switch in `sign_request`.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_guarded_key_non_approved_outcomes_all_return_failure() {
        for outcome in [
            WireOutcomeT::Denied,
            WireOutcomeT::Cancelled,
            WireOutcomeT::Timeout,
            WireOutcomeT::PeerGone,
            WireOutcomeT::BiometricFailed,
        ] {
            let fake = Arc::new(super::super::approver_wire::FakeApprover::new(outcome));
            let fake_for_state = Arc::clone(&fake);
            let state = socket_state_with_approver(|shared| {
                install_same_user_guard_current_uid(shared);
                shared.approver.set_ready(fake_for_state.clone());
            });
            let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
            let resp = super::sign_request(
                &state,
                Some(std::process::id()),
                Some(current_uid_token()),
                None,
                &req,
                &HashMap::new(),
            )
            .await;
            assert_eq!(
                resp.msg_type,
                MessageType::Failure,
                "outcome {outcome:?} must map to FAILURE"
            );
            assert!(resp.payload.is_empty(), "FAILURE must carry no detail");
            assert_eq!(
                fake.calls(),
                1,
                "outcome {outcome:?}: dialog must fire exactly once"
            );
        }
    }

    /// Guarded SIGN with the approver slot in `Down` (helper unavailable)
    /// fails closed — matches the §9 promise the control-socket
    /// `helper_down_fails_guarded_reveal_get_closed` pins on `kv.get`.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_guarded_key_with_helper_down_fails_closed() {
        // `Shared::new_for_test` starts the approver slot in `Down`.
        let state = socket_state_with_approver(|shared| {
            install_same_user_guard_current_uid(shared);
        });
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = super::sign_request(
            &state,
            Some(std::process::id()),
            Some(current_uid_token()),
            None,
            &req,
            &HashMap::new(),
        )
        .await;
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty());
    }

    /// Unguarded SIGN with a `Ready` approver never invokes the dialog —
    /// `FakeApprover.calls()` stays 0. Pins the DR-0031 §8 promise that
    /// the gate is opt-in per entry: adding a helper must not put the
    /// dialog on every SSH signing request.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_unguarded_key_never_fires_dialog() {
        let fake = Arc::new(super::super::approver_wire::FakeApprover::new(
            WireOutcomeT::Approved,
        ));
        let fake_for_state = Arc::clone(&fake);
        // No `install_same_user_guard_current_uid` — GITHUB_KEY is
        // unguarded, so the SIGN first pass takes the fast-path branch.
        let state = socket_state_with_approver(|shared| {
            shared.approver.set_ready(fake_for_state.clone());
        });
        let req = sign_request(&blob_of(ED25519_PUB), b"agent challenge", 0);
        let resp = super::sign_request(
            &state,
            Some(std::process::id()),
            Some(current_uid_token()),
            None,
            &req,
            &HashMap::new(),
        )
        .await;
        assert_eq!(resp.msg_type, MessageType::SignResponse);
        assert_eq!(fake.calls(), 0, "unguarded key must not invoke the dialog");
    }

    /// The most important second-pass property: a guard *changed*
    /// during the dialog must fail-closed — the approval was against
    /// the *previous* record, not the newly-installed one. Simulates
    /// a concurrent `set_guard` swap between first pass and finalize
    /// by using a `BlockingApprover` that pauses inside `request`
    /// until we release it; while paused we replace the record with
    /// a `SameUser` guard bound to a non-matching uid.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_guarded_key_record_replaced_during_approval_fails_closed() {
        use tokio::sync::oneshot;

        struct BlockingApprover {
            entered: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
            unblock: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
            call_count: std::sync::atomic::AtomicUsize,
        }
        impl super::super::approver_wire::Approver for BlockingApprover {
            fn request<'a>(
                &'a self,
                request: cache_warden_approver::wire::ApproveRequest,
                _timeout: Duration,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = std::io::Result<cache_warden_approver::wire::ApproveResponse>,
                        > + Send
                        + 'a,
                >,
            > {
                self.call_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Box::pin(async move {
                    if let Some(tx) = self.entered.lock().await.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = self.unblock.lock().await.take() {
                        let _ = rx.await;
                    }
                    Ok(cache_warden_approver::wire::ApproveResponse {
                        v: cache_warden_approver::wire::WIRE_VERSION,
                        request_id: request.request_id,
                        outcome: WireOutcomeT::Approved,
                        biometric_kind: Some("TouchID".into()),
                    })
                })
            }
            fn shutdown<'a>(
                &'a self,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
                Box::pin(async {})
            }
        }

        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (unblock_tx, unblock_rx) = oneshot::channel::<()>();
        let blocker = Arc::new(BlockingApprover {
            entered: tokio::sync::Mutex::new(Some(entered_tx)),
            unblock: tokio::sync::Mutex::new(Some(unblock_rx)),
            call_count: std::sync::atomic::AtomicUsize::new(0),
        });
        let blocker_for_state = Arc::clone(&blocker);
        let state = socket_state_with_approver(|shared| {
            install_same_user_guard_current_uid(shared);
            shared.approver.set_ready(blocker_for_state.clone());
        });
        let state_bg = Arc::clone(&state);
        let sign_task = tokio::spawn(async move {
            let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
            super::sign_request(
                &state_bg,
                Some(std::process::id()),
                Some(current_uid_token()),
                None,
                &req,
                &HashMap::new(),
            )
            .await
        });
        entered_rx
            .await
            .expect("approver must enter `request` for the guarded sign");
        // Concurrent guard swap: same key, but bound to a uid the
        // running test process cannot satisfy. `set_guard` replaces
        // the record (DR-0030 §5 "last declaration wins").
        {
            let never_uid = current_uid().wrapping_add(1);
            let denying = GuardRecord::new(
                vec![GuardConstraint::SameUser],
                GuardSetter {
                    euid: never_uid,
                    ruid: never_uid,
                },
            );
            state
                .shared
                .store
                .lock()
                .unwrap()
                .set_guard("GITHUB_KEY", denying, &state.shared.authsock_cap)
                .expect("swap the guard record while the dialog waits");
        }
        // Release the approver — finalize now re-evaluates the (new,
        // denying) record and must fail-closed.
        let _ = unblock_tx.send(());
        let resp = sign_task.await.expect("sign task must not panic");
        assert_eq!(
            resp.msg_type,
            MessageType::Failure,
            "record replaced during approval must not authorize the sign"
        );
        assert!(resp.payload.is_empty());
    }

    /// While a guarded reveal-SIGN awaits the dialog, an unrelated
    /// unguarded `kv.get` on the *same daemon* (same `Shared`) must
    /// progress — the SIGN flow drops the store lock before entering
    /// the dialog await, so a multi-second human decision cannot
    /// queue every other request on this daemon behind it. Uses the
    /// control-socket `run_request_async` path directly against the
    /// authsock `SocketState.shared`, mirroring the get-side
    /// `parallel_unguarded_get_progresses_while_gated_get_awaits_dialog`
    /// test.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_unrelated_get_progresses_while_guarded_sign_awaits_dialog() {
        use tokio::sync::oneshot;

        struct BlockingApprover {
            entered: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
            unblock: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
        }
        impl super::super::approver_wire::Approver for BlockingApprover {
            fn request<'a>(
                &'a self,
                request: cache_warden_approver::wire::ApproveRequest,
                _timeout: Duration,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = std::io::Result<cache_warden_approver::wire::ApproveResponse>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    if let Some(tx) = self.entered.lock().await.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = self.unblock.lock().await.take() {
                        let _ = rx.await;
                    }
                    Ok(cache_warden_approver::wire::ApproveResponse {
                        v: cache_warden_approver::wire::WIRE_VERSION,
                        request_id: request.request_id,
                        outcome: WireOutcomeT::Approved,
                        biometric_kind: Some("TouchID".into()),
                    })
                })
            }
            fn shutdown<'a>(
                &'a self,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
                Box::pin(async {})
            }
        }

        // Set up state with GITHUB_KEY guarded. Separately seed an
        // *unguarded* KV entry `default/U` on the same shared store;
        // the parallel work will be a control-socket `kv.get` for
        // that key, which needs the same store lock the guarded
        // SIGN's dialog await must have released.
        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (unblock_tx, unblock_rx) = oneshot::channel::<()>();
        let blocker = Arc::new(BlockingApprover {
            entered: tokio::sync::Mutex::new(Some(entered_tx)),
            unblock: tokio::sync::Mutex::new(Some(unblock_rx)),
        });
        let state = socket_state_with_approver(|shared| {
            install_same_user_guard_current_uid(shared);
            shared.approver.set_ready(blocker.clone());
            shared
                .store
                .lock()
                .unwrap()
                .set(
                    "default/U".to_string(),
                    ValueSource::Static,
                    SecretBytes::from("unguarded-plain"),
                    Ttl::never(),
                    &shared.control_cap,
                    &shared.clock,
                )
                .unwrap();
        });

        // Fire the guarded sign in the background — it must sit on
        // the dialog until we send `unblock`.
        let state_g = Arc::clone(&state);
        let guarded = tokio::spawn(async move {
            let req = sign_request(&blob_of(ED25519_PUB), b"data-g", 0);
            super::sign_request(
                &state_g,
                Some(std::process::id()),
                Some(current_uid_token()),
                None,
                &req,
                &HashMap::new(),
            )
            .await
        });
        entered_rx
            .await
            .expect("approver must enter `request` for the guarded sign");
        // The unguarded control-socket `kv.get` on the *same*
        // `Shared` must progress while the guarded SIGN is captive on
        // the (unreleased) approver — proving the SIGN flow released
        // the store lock before awaiting the dialog. `run_request_async`
        // is the same entry point the production control listener
        // uses, so this exercises the real cross-adapter path.
        let get_resp = crate::daemon::server::run_request_async(
            &state.shared,
            None,
            None,
            None,
            crate::protocol::wire::Request::KvGet {
                key: "default/U".to_string(),
                dry_run: false,
            },
        )
        .await;
        assert!(
            get_resp.is_ok(),
            "unguarded kv.get must progress while a guarded SIGN is captive on the dialog: {get_resp:?}"
        );
        assert!(
            !guarded.is_finished(),
            "guarded SIGN must still be pending on the blocking approver"
        );
        let _ = unblock_tx.send(());
        let guarded = guarded.await.expect("guarded task must not panic");
        assert_eq!(guarded.msg_type, MessageType::SignResponse);
    }

    /// First-pass denial (guard bound to a uid the running test process
    /// cannot satisfy) must NOT fire the approver dialog. Pins the
    /// promise that a denied requester never sees TouchID / a human
    /// prompt on the SIGN path — the denial is silent and cost-free.
    /// The production path (`super::sign_request`) is exercised end-to-end
    /// with a `FakeApprover(Approved)` installed; the test would fail if
    /// the first pass ever handed the dialog a denied request. Companion
    /// to `sign_request_unguarded_key_never_fires_dialog` from the
    /// unguarded side.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_guarded_key_first_pass_denied_no_dialog() {
        let fake = Arc::new(super::super::approver_wire::FakeApprover::new(
            WireOutcomeT::Approved,
        ));
        let fake_for_state = Arc::clone(&fake);
        let state = socket_state_with_approver(|shared| {
            // Guard bound to a uid the running test process cannot
            // satisfy — first-pass eval must deny before any dialog.
            let never_uid = current_uid().wrapping_add(1);
            let denying = GuardRecord::new(
                vec![GuardConstraint::SameUser],
                GuardSetter {
                    euid: never_uid,
                    ruid: never_uid,
                },
            );
            shared
                .store
                .lock()
                .unwrap()
                .set_guard("GITHUB_KEY", denying, &shared.authsock_cap)
                .expect("set_guard succeeds with the authsock cap");
            shared.approver.set_ready(fake_for_state.clone());
        });
        let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
        let resp = super::sign_request(
            &state,
            Some(std::process::id()),
            Some(current_uid_token()),
            None,
            &req,
            &HashMap::new(),
        )
        .await;
        assert_eq!(resp.msg_type, MessageType::Failure);
        assert!(resp.payload.is_empty());
        assert_eq!(
            fake.calls(),
            0,
            "denied first-pass must not fire the approver dialog"
        );
    }

    /// Registry hot-swap during the approver dialog await must fail-closed
    /// at finalize. The first pass snapshots `kv_key` under a brief
    /// registry read lock and then drops it before awaiting the (~95s)
    /// dialog; a background op-discovery hot-swap (DR-0023 Phase 2) can
    /// land in that window. If the blob no longer resolves under the
    /// current registry, signing against the pre-dialog snapshot would
    /// leak a PEM the socket no longer exposes. Uses the same
    /// `BlockingApprover` pattern as
    /// `sign_request_guarded_key_record_replaced_during_approval_fails_closed`
    /// but the concurrent mutation is a registry replacement, not a
    /// guard-record swap.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sign_request_guarded_key_registry_dropped_during_approval_fails_closed() {
        use tokio::sync::oneshot;

        struct BlockingApprover {
            entered: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
            unblock: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
        }
        impl super::super::approver_wire::Approver for BlockingApprover {
            fn request<'a>(
                &'a self,
                request: cache_warden_approver::wire::ApproveRequest,
                _timeout: Duration,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = std::io::Result<cache_warden_approver::wire::ApproveResponse>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    if let Some(tx) = self.entered.lock().await.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = self.unblock.lock().await.take() {
                        let _ = rx.await;
                    }
                    Ok(cache_warden_approver::wire::ApproveResponse {
                        v: cache_warden_approver::wire::WIRE_VERSION,
                        request_id: request.request_id,
                        outcome: WireOutcomeT::Approved,
                        biometric_kind: Some("TouchID".into()),
                    })
                })
            }
            fn shutdown<'a>(
                &'a self,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
                Box::pin(async {})
            }
        }

        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (unblock_tx, unblock_rx) = oneshot::channel::<()>();
        let blocker = Arc::new(BlockingApprover {
            entered: tokio::sync::Mutex::new(Some(entered_tx)),
            unblock: tokio::sync::Mutex::new(Some(unblock_rx)),
        });
        let blocker_for_state = Arc::clone(&blocker);
        let state = socket_state_with_approver(|shared| {
            install_same_user_guard_current_uid(shared);
            shared.approver.set_ready(blocker_for_state.clone());
        });
        let state_bg = Arc::clone(&state);
        let sign_task = tokio::spawn(async move {
            let req = sign_request(&blob_of(ED25519_PUB), b"data", 0);
            super::sign_request(
                &state_bg,
                Some(std::process::id()),
                Some(current_uid_token()),
                None,
                &req,
                &HashMap::new(),
            )
            .await
        });
        entered_rx
            .await
            .expect("approver must enter `request` for the guarded sign");
        // Concurrent hot-swap: replace the registry with an empty one.
        // `known_local` already committed on the first pass; the finalize
        // pass's re-resolve is what must catch this.
        *state.registry.write().unwrap() = PublicKeyRegistry::new();
        // Release the approver — finalize now re-resolves and must
        // fail-closed (blob no longer in the registry).
        let _ = unblock_tx.send(());
        let resp = sign_task.await.expect("sign task must not panic");
        assert_eq!(
            resp.msg_type,
            MessageType::Failure,
            "registry dropped during approval must not authorize the sign"
        );
        assert!(resp.payload.is_empty());
    }

    #[test]
    fn op_registry_from_without_exe_adds_no_op_keys() {
        // With no resolvable own-binary path, op keys cannot be re-fetched at sign
        // time, so none are registered (fail-closed) — only the local base
        // survives. Mirrors `spawn_listeners`' exe-unknown branch.
        let mut base = PublicKeyRegistry::new();
        base.register_from_pem("LOCAL_KEY", ED25519_PEM).unwrap();
        let keys = vec![discovered("itemAAA", ED25519_PUB_2, "Op")];

        let (registry, n) = op_registry_from(&base, "sock", None, &op_source(), &keys);

        assert_eq!(n, 0, "no exe → no op keys layered");
        assert_eq!(registry.len(), 1, "only the local base key");
    }
}
