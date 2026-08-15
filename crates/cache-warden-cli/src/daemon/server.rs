//! Tokio control-socket server for `cache-warden run`.
//!
//! Single process, single multi-thread runtime (DR-0008): one listener task on
//! the control socket plus one task per accepted connection. Shutdown is fanned
//! out over a `watch` channel triggered by SIGINT / SIGTERM (authsock-warden
//! precedent). The shared [`Store`] sits behind an `Arc<Mutex<_>>`; the core is
//! synchronous so the lock is held only for the duration of one request.
//!
//! The synchronous source-command execution that `regenerate` performs is moved
//! off the async worker with `spawn_blocking` (DR-0008): a regen can block on an
//! upstream prompt, which must not stall the runtime.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Errors that can terminate the daemon's `run` loop.
#[derive(Debug)]
pub enum ServerError {
    /// A shutdown signal arrived while the daemon was still starting up.
    ShutdownDuringStartup,
    /// An I/O error (bind failure, etc.).
    Io(std::io::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShutdownDuringStartup => write!(f, "shutdown signal received during startup"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

use cache_warden::{
    AllowAll, Authenticator, Capability, CommandAuthenticator, CommandRunner, DefineError,
    ProcessInfo, ProcessInspector, SourceRunner, Store, StoreBuilder, SystemClock, SystemInspector,
    Ttl,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};

use super::approver_wire::{self, Approver};
use super::graceful_restart;
use super::guard::{self as guard_eval, GetterAuditToken, GetterProcess};
use super::handler::{self, GuardCheckMode, HandlerCtx};
use super::peer::peer_pid;
use crate::config::{Config, KvDefinition};
use crate::protocol::wire::{ErrorKind, Request, Response};
use crate::protocol::{decode_request, encode_response};
use cache_warden_approver::wire::ApproveRequest;
use cache_warden_approver::wire::Outcome as WireOutcome;

/// Daemon version reported by `status`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The production source-command runner.
///
/// The core [`Store::regenerate`] calls [`SourceRunner::run`] synchronously
/// while the store lock is held, so the whole locked handler section runs on
/// the blocking pool (see [`handle_connection`]) — that satisfies DR-0008's
/// "isolate synchronous work" mandate without changing the core. Requests for
/// other keys still queue on the store lock during a long regeneration; finer
/// locking is deferred until that contention is real.
type Runner = CommandRunner;

/// Bind the control socket, removing a dead stale socket first.
///
/// If a socket file already exists at `path`, we try to connect to it: a
/// successful connect means another daemon is already live there, which is an
/// error (refuse to clobber a running peer). A failed connect means the socket
/// is stale (left by a crashed daemon); we remove it and bind fresh.
///
/// The socket is created with mode 0600 via a restrictive umask around `bind`
/// (closing the TOCTOU window where the path briefly has umask-default perms).
pub fn bind_control_socket(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another cache-warden daemon is already listening on {}",
                        path.display()
                    ),
                ));
            }
            Err(_) => {
                // Stale socket from a dead daemon; remove and rebind.
                std::fs::remove_file(path)?;
            }
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Restrictive umask so the socket is created 0600 with no TOCTOU window.
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(path);
    unsafe {
        libc::umask(old_umask);
    }
    let listener = listener?;

    // Belt-and-suspenders: enforce 0600 explicitly in case the platform's bind
    // ignored the umask for the socket inode.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(listener)
}

/// The re-authentication boundary wired from config (DR-0010).
///
/// A `[auth].command` in the config produces a [`CommandAuthenticator`]; its
/// absence produces [`AllowAll`] (no re-auth). Boxed behind the trait so the
/// single `run_request` wiring point is config-driven, not hard-coded.
type Auth = Box<dyn Authenticator + Send + Sync>;

/// Build the authenticator from the resolved config (DR-0010).
///
/// `[auth].command` => a [`CommandAuthenticator`] that runs that argv on every
/// TTL-gated unlock; absent => [`AllowAll`] (cache fast, never prompt).
fn build_authenticator(config: &Config) -> Auth {
    match config.auth_command() {
        Some(argv) => Box::new(CommandAuthenticator::new(argv.to_vec())),
        None => Box::new(AllowAll),
    }
}

/// Shared daemon state handed to each connection task.
///
/// `pub(crate)` so the authsock listener (see [`crate::daemon::authsock`]) can
/// share the same `Store` / authenticator / runner / clock as the control
/// socket — both adapters sit in one process around one core (DR-0008).
pub(crate) struct Shared {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) control_cap: Capability,
    pub(crate) authsock_cap: Capability,
    pub(crate) otp_adapter: crate::daemon::otp_adapter::OtpAdapter,
    pub(crate) runner: Runner,
    pub(crate) auth: Auth,
    /// One process-lifetime monotonic clock. It must be shared across preload
    /// and every request: a fresh `SystemClock::new()` rebases its origin to
    /// "now", so per-request clocks would make every entry look freshly
    /// activated and defeat TTL evaluation entirely.
    pub(crate) clock: SystemClock,
    /// Persistence settings for online definitions (DR-0014 §4). Empty (not
    /// set) when `[daemon].persist-definitions` is off; set once after startup
    /// completes. When set, every `kv.define` / `kv.del --with-define` that
    /// changes the definition registry rewrites the state file atomically
    /// (0600), persisting **online** definitions only (config `[kv.*]`
    /// definitions are excluded — the config is their source of truth, not the
    /// state file). Uses `OnceLock` so the slot can be filled after the `Arc`
    /// is handed to the serve loop (DR-0023 Phase 1: startup is non-blocking).
    persist: std::sync::OnceLock<PersistSettings>,
    socket_path: String,
    pid: u32,
    /// Key-level process-access policies (DR-0012 key layer): key name → its
    /// non-empty `allowed_processes` list, built from `[kv.*]` config at startup.
    /// Held here (not in the core `Store`) because policy interpretation is an
    /// adapter/handler concern (DR-0004); the control handler reads it for the
    /// `kv.get` gate, and the authsock listener shares the same `Shared` so a
    /// SIGN_REQUEST resolving a KV key consults the same table.
    pub(crate) kv_process_policies: std::collections::BTreeMap<String, Vec<String>>,
    /// The encrypted vault (DR-0034), or `None` when the config declares none.
    ///
    /// See `HandlerCtx::vault` for the lock-order rule: this mutex is only
    /// ever taken while `store` is already held.
    pub(crate) vault: Option<Arc<Mutex<crate::daemon::vault_state::VaultState>>>,
    /// The passkey ceremony, when one is configured (DR-0034 §10).
    ///
    /// Held here as well as by the serving task because `vault.add_passkey`
    /// arrives on the control socket: the command that passed the local
    /// approval gate is what opens a registration window, and the browser only
    /// ever completes what that command opened.
    pub(crate) ceremony: Option<Arc<Mutex<crate::daemon::ceremony::Ceremony>>>,
    /// Where the ceremony page is served, once it is bound. Reported to the
    /// user by the command that opens a ceremony, which is the only way they
    /// learn the port when the configuration asked for an arbitrary one.
    pub(crate) ceremony_addr: std::sync::OnceLock<std::net::SocketAddr>,
    /// Decides whether a caller satisfies an entry's owner principal
    /// (draft-DR-0033). Held here so tests can substitute a deterministic
    /// verifier for the kernel's answer.
    pub(crate) owner_verifier: Arc<dyn crate::daemon::owner_eval::OwnerVerifier + Send + Sync>,
    /// Keys the config declares `persist = true` (DR-0034 §5). Entry names
    /// live in the vault's sealed body, so while the vault is closed these
    /// declarations are the only way to report a persisted entry at all.
    pub(crate) persisted_keys: std::collections::BTreeSet<String>,
    /// DR-0030 daemon-wide guard policy resolved from `[kv-policy]` at
    /// startup (default-require-same-user, shell-names). Held here so
    /// `run_request` can hand it into every [`HandlerCtx`] without
    /// re-parsing the config each request.
    pub(crate) kv_policy: crate::config::ResolvedKvPolicy,
    /// This process's own exec path, resolved once at startup (DR-0029 §3):
    /// graceful restart always execs *this exact path*, never re-resolving
    /// `current_exe()` at restart time (which would let a `plist`/PATH change
    /// after startup silently redirect the handoff — DR-0029 §3's rationale).
    /// Empty when `current_exe()` failed at startup (rare); graceful restart
    /// then always fails its own verification step, leaving the daemon
    /// otherwise fully functional.
    ///
    /// Only read from `graceful_restart::handle_request`'s
    /// `#[cfg(target_os = "macos")]` branch, hence genuinely unread on every
    /// other target (found while cross-checking this bundle's HIGH-4
    /// non-macOS regression test against `.github/workflows/ci.yml`'s
    /// `ubuntu-latest` runner's `cargo clippy --workspace -- -D warnings` —
    /// a pre-existing issue independent of that test).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) exe_path: PathBuf,
    /// This process's own argv (`std::env::args()`, index 0 included),
    /// captured once at startup and re-used verbatim (minus argv[0], which
    /// [`graceful_restart`] replaces with [`Self::exe_path`] itself) when
    /// re-exec'ing for a graceful restart ("argv 継承", DR-0029 §1 step ⑥).
    /// See [`Self::exe_path`]'s doc for why this is macOS-only in practice.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) argv: Vec<String>,
    /// Coordinates a graceful restart (DR-0029) between the connection
    /// handler that receives `daemon.restart_graceful` and this module's
    /// [`run`] loop, which owns the actual fork/exec.
    pub(crate) restart: graceful_restart::RestartCoordinator,
    /// Tracks in-flight connections so a graceful restart can drain them
    /// (bounded wait, DR-0029 §4) before its accept loop stops and its
    /// listeners close. Not consulted by the normal SIGINT/SIGTERM shutdown
    /// path, which does not drain (pre-existing behaviour, unchanged).
    pub(crate) active_connections: ConnectionTracker,
    /// DR-0031 §3/§9 approver helper handle. `Some(Ready(_))` = spawned,
    /// peer-verified helper ready to prompt. `Some(Down)` = we tried and
    /// failed / gave up (fail-closed for guarded gets, transparent for
    /// unguarded ones). `None` = tests or non-macOS builds that never even
    /// tried. In every case the guard-less path (unguarded `kv.get`, non-
    /// `kv.get`, `dry_run` gets) proceeds untouched.
    pub(crate) approver: ApproverSlot,
    /// Whether this daemon's config can spawn `op`, and therefore whether
    /// Full Disk Access is worth reporting at all (`crate::fda`). Fixed at
    /// startup: it is a property of the config, unlike the permission state
    /// itself, which is probed per `status` request.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fda_applicable: bool,
}

/// Classified outcome of one [`ApproverSlot::await_dialog_outcome`] call —
/// the layer shared across every gated adapter (control get, authsock
/// sign). Everything except [`ApprovalOutcome::Approved`] is a rejection
/// the caller must map onto its own wire-shape failure (control:
/// `Response::Err(AuthFailed, …)`; authsock: bare `SSH_AGENT_FAILURE`
/// plus a structured stderr diag). Distinguishing them at the daemon
/// level lets each adapter log a matching diagnostic even though the
/// user-facing shape collapses to one denial (draft-DR-0031 §Security:
/// dialog outcomes are per-approval facts, not per-caller).
#[derive(Debug, Clone)]
pub(crate) enum ApprovalOutcome {
    Approved,
    /// `helper_down` / `wait_ready` timed out — §9 fail-closed shape.
    HelperUnavailable,
    Denied,
    Cancelled,
    Timeout,
    PeerGone,
    BiometricFailed,
    /// A wire-level I/O failure (`ApproverClient::request` surfaced an
    /// error before returning an outcome). The daemon logs this so an
    /// operator can distinguish a helper glitch from a user-driven
    /// rejection, but the user-facing wire shape is the same denial.
    Ipc(String),
}

impl ApprovalOutcome {
    /// A short user-facing label for the rejection reason, matching the
    /// message shape the control adapter surfaces (`"approval denied by
    /// user"`, `"approval cancelled"`, …). The authsock adapter reuses
    /// this string in its structured stderr diagnostic so both surfaces
    /// stay in lockstep with the DR-0031 §Outcomes vocabulary.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::HelperUnavailable => "approver helper unavailable",
            Self::Denied => "approval denied by user",
            Self::Cancelled => "approval cancelled",
            Self::Timeout => "approval timed out",
            Self::PeerGone => "requesting process exited before approval",
            Self::BiometricFailed => "biometric authentication failed",
            Self::Ipc(_) => "approver dialog failed",
        }
    }

    /// The message a **client** gets when this outcome denies its request —
    /// deliberately coarser than [`label`](Self::label), which is the
    /// daemon's own log vocabulary.
    ///
    /// Two outcomes are told apart because they call for opposite next
    /// moves, and a caller that cannot tell them apart gets one of them
    /// wrong (kawaz 裁定 2026-08-12):
    ///
    /// - **cancelled** — a person saw the prompt and said no. Asking again
    ///   just puts the same prompt back on their screen.
    /// - **timed out** — nobody answered. The request was never actually
    ///   judged, so retrying when someone is present is the right move.
    ///
    /// Everything else collapses into one indistinguishable denial. Whether
    /// the finger did not match, whether the caller's own process vanished
    /// mid-prompt, whether a policy refused before anyone was asked — none
    /// of that changes what the caller should do next (it does not get the
    /// secret), and each distinction is a bit of information about the user
    /// or the entry's guard that a caller has no business learning by
    /// probing (DR-0030 §7's non-disclosure applied to the dialog's
    /// outcomes).
    ///
    /// Three variants share that arm without ever reaching it in practice:
    /// `Approved` is not a denial at all, and the control path answers
    /// [`HelperUnavailable`](Self::HelperUnavailable) / [`Ipc`](Self::Ipc)
    /// before it gets here — those two are broken plumbing rather than a
    /// verdict on the request, and saying so plainly is what lets an
    /// operator fix them. They are listed so this match stays exhaustive
    /// and so a future caller that does route them here gets the safe
    /// wording by default.
    pub(crate) fn client_message(&self) -> &'static str {
        match self {
            Self::Cancelled => {
                "approval declined at the confirmation prompt; \
                 asking again will only re-prompt — check with the user first"
            }
            Self::Timeout => {
                "approval timed out: the confirmation prompt went unanswered; \
                 retry while someone is at the machine"
            }
            Self::Approved
            | Self::Denied
            | Self::PeerGone
            | Self::BiometricFailed
            | Self::HelperUnavailable
            | Self::Ipc(_) => "approval was not granted",
        }
    }
}

/// The lifecycle-aware slot for the DR-0031 approver helper.
///
/// `Ready(_)` and `Down` are terminal states — the daemon does not currently
/// respawn a helper after it decides to give up (§9 `helper_down`
/// permanent). `Starting` is currently only used during the brief window
/// between `Shared` construction and the async helper-init task filling in
/// the final state; guarded gets that arrive in that window await the
/// [`Notify`] with a bounded timeout ([`HELPER_STARTING_WAIT`]) before
/// treating it as `Down`.
pub(crate) struct ApproverSlot {
    state: Mutex<ApproverState>,
    notify: tokio::sync::Notify,
    /// The approvals currently on screen (or queued for it), keyed by the
    /// question they ask. A second request for a question already in flight
    /// joins the first instead of stacking another dialog — see
    /// [`CoalesceKey`] and [`ApproverSlot::await_dialog_outcome`].
    inflight: Mutex<std::collections::HashMap<CoalesceKey, broadcast::Sender<ApprovalOutcome>>>,
}

/// What makes two approval requests "the same question", for coalescing.
///
/// # Why these fields
///
/// An approval answers "may *this process* do *this thing* to *this entry*",
/// so the identity has to pin all three or a shared answer would be answering
/// something the user was never asked:
///
/// - `key` — the entry. Different entries are different secrets.
/// - `operation` — reading a key and signing with it are different asks, and
///   the dialog says so in as many words ("read" vs "sign with"), so they
///   must not share an answer.
/// - `pid` + `pid_version` — the requesting process *instance*. `pid` alone
///   is not an identity: macOS reuses it, and `pid_version` is exactly the
///   generation counter that tells a live process from a later one wearing
///   its number (the same pairing DR-0031 §7 uses for peer-exit detection
///   and DR-0030 §Security for pinned identities).
/// - `euid` — belt and braces. The approver socket is 0600 so a
///   cross-user requester should be impossible already; including the uid
///   means a bug elsewhere degrades into "no coalescing" rather than into
///   one user's approval answering another's request.
///
/// # What this deliberately does not do
///
/// Only *concurrent* requests share an answer. The entry is removed the
/// moment the leader has one, so a request arriving afterwards raises a
/// fresh prompt. This is not "remember the approval for N seconds" — that
/// would be a real weakening of the one-prompt-per-access contract, and it
/// is not what the retry storms need: ssh's per-key SIGN retries all pile up
/// *while the first prompt is still open*.
///
/// Nor does it merge requests from *different processes* (each is its own
/// `pid` + `pid_version`): a storm of parallel ssh clients asking for the
/// same key raises one prompt per process by design — a different process is
/// a different question — and the queue's depth cap, not coalescing, is what
/// bounds that shape of pile-up.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CoalesceKey {
    key: String,
    operation: String,
    pid: u32,
    pid_version: u32,
    euid: u32,
}

impl CoalesceKey {
    /// Derive the key from a wire request, or `None` when the request
    /// carries no usable requester identity.
    ///
    /// `None` means "do not coalesce this one": without a trustworthy
    /// process identity there is no way to tell two requesters apart, and
    /// guessing would risk handing one caller's approval to another. A
    /// separate prompt is the conservative failure mode.
    fn from_request(req: &ApproveRequest) -> Option<Self> {
        let token = &req.requester.audit_token;
        if token.pid == 0 {
            return None;
        }
        Some(Self {
            key: req.key.clone(),
            operation: req.operation.clone(),
            pid: token.pid,
            pid_version: token.pid_version,
            euid: token.euid,
        })
    }
}

/// Removes the in-flight entry when the leader is done with it — including
/// when the leader's future is dropped mid-approval (its client
/// disconnected, a shutdown raced it). Without the `Drop`, an abandoned
/// leader would leave its key in the map forever and every later request
/// for that question would wait on an answer nobody is coming back with.
struct InflightGuard<'a> {
    map: &'a Mutex<std::collections::HashMap<CoalesceKey, broadcast::Sender<ApprovalOutcome>>>,
    key: CoalesceKey,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

enum ApproverState {
    Starting,
    Ready(Arc<dyn Approver>),
    Down,
}

impl ApproverSlot {
    pub(crate) fn new_starting() -> Self {
        Self {
            state: Mutex::new(ApproverState::Starting),
            notify: tokio::sync::Notify::new(),
            inflight: Mutex::new(std::collections::HashMap::new()),
        }
    }
    /// A pre-constructed slot in the `Down` terminal state, used by every
    /// non-approver-aware code path (tests, non-`run()` callers of
    /// `Shared`). Skips the transient `Starting` bounded wait entirely —
    /// guarded gets get `AuthFailed("approver helper unavailable")`
    /// immediately, matching the production `helper_down` shape.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new_down() -> Self {
        Self {
            state: Mutex::new(ApproverState::Down),
            notify: tokio::sync::Notify::new(),
            inflight: Mutex::new(std::collections::HashMap::new()),
        }
    }
    pub(crate) fn set_ready(&self, a: Arc<dyn Approver>) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = ApproverState::Ready(a);
        self.notify.notify_waiters();
    }
    pub(crate) fn set_down(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = ApproverState::Down;
        self.notify.notify_waiters();
    }
    /// Snapshot the currently-ready helper if any, without waiting. Used by
    /// the graceful-shutdown / restart paths to call
    /// [`Approver::shutdown`] on the live handle.
    pub(crate) fn current_ready(&self) -> Option<Arc<dyn Approver>> {
        let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match &*g {
            ApproverState::Ready(a) => Some(Arc::clone(a)),
            _ => None,
        }
    }
    /// Await a terminal state, up to `timeout`. Returns `Some(approver)` if
    /// the helper reached `Ready` in time, `None` on `Down` or on the
    /// bounded-wait expiring (both collapse to the caller's fail-closed
    /// branch — the distinction between "we gave up" and "we ran out of
    /// time waiting for startup" is not meaningful at the get-path caller
    /// level).
    ///
    /// # Notify race avoidance
    ///
    /// The `Notify` future is created and *enabled* **before** the state
    /// guard is taken so that a concurrent [`set_ready`](Self::set_ready) /
    /// [`set_down`](Self::set_down) landing between the state check and
    /// registering the waiter still wakes us. Without the pre-registration
    /// step [`tokio::sync::Notify::notified`] arms a permit only on the
    /// first poll, so a `notify_waiters` call fired in that window would
    /// be lost — the caller would then time out even though the slot
    /// reached a terminal state promptly. Every loop turn re-arms a
    /// fresh `notified` before the next state check for the same reason.
    /// The timeout branch also re-checks the state once more before
    /// giving up, so a `set_ready` fired exactly at the deadline is not
    /// lost.
    /// Shared approval-dialog workflow used by every gated adapter (control
    /// socket `kv.get`, authsock `SIGN_REQUEST`, …). Awaits the helper to
    /// reach a terminal state, sends `request` on the DR-0031 wire, and
    /// classifies the response into an [`ApprovalOutcome`].
    ///
    /// The store lock — or any adapter-side registry lock — must be
    /// released before entering this method: dialog latency is bounded only
    /// by the human, so holding a lock across it would queue every other
    /// request behind a single approval.
    ///
    /// Each caller maps the [`ApprovalOutcome`] onto its own wire-shape
    /// failure (control: `Response::Err(AuthFailed, …)`; authsock: bare
    /// `SSH_AGENT_FAILURE` + a structured stderr diag) — the daemon-side
    /// semantics stay identical, only the surface differs.
    pub(crate) async fn await_dialog_outcome(
        &self,
        request: ApproveRequest,
        starting_wait: Duration,
        request_timeout: Duration,
    ) -> ApprovalOutcome {
        // Join an identical approval already in flight rather than stacking
        // a second dialog for the same question (see `CoalesceKey`). ssh is
        // the case that forces this: it sends a SIGN per key and retries on
        // failure, so one guarded key can queue a dozen prompts that all ask
        // the user the same thing.
        let coalesce_key = CoalesceKey::from_request(&request);
        // Decide leader vs. follower under the map lock, and hold nothing
        // across an await (the lock is a std mutex; the awaits below can
        // last as long as a human takes to answer).
        enum Role {
            Follow(broadcast::Receiver<ApprovalOutcome>),
            Lead(Option<broadcast::Sender<ApprovalOutcome>>),
        }
        let role = match &coalesce_key {
            Some(ck) => {
                let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
                match map.get(ck) {
                    Some(tx) => Role::Follow(tx.subscribe()),
                    None => {
                        let (tx, _rx) = broadcast::channel(1);
                        map.insert(ck.clone(), tx.clone());
                        Role::Lead(Some(tx))
                    }
                }
            }
            None => Role::Lead(None),
        };
        let sender = match role {
            Role::Follow(rx) => {
                // `coalesce_key` is `Some` on this arm by construction.
                let ck = coalesce_key.as_ref().expect("follower has a key");
                return self.follow_inflight(ck, rx, request_timeout).await;
            }
            Role::Lead(sender) => sender,
        };
        // From here on this call is the leader: it owns the dialog, and
        // whatever it learns is broadcast to everyone who joined meanwhile.
        // The guard drops the entry even if this future is cancelled, so an
        // abandoned approval cannot wedge later ones.
        let _guard = coalesce_key.as_ref().map(|ck| InflightGuard {
            map: &self.inflight,
            key: ck.clone(),
        });

        let outcome = self
            .run_dialog(request, starting_wait, request_timeout)
            .await;

        // Retire the entry *before* publishing: a request arriving after the
        // answer is a new question and must raise its own prompt, not attach
        // to one that is already over.
        drop(_guard);
        if let Some(tx) = sender {
            // Fails only when nobody joined — the ordinary case.
            let _ = tx.send(outcome.clone());
        }
        outcome
    }

    /// Wait for the approval this request joined.
    ///
    /// # Deadlines
    ///
    /// Every waiter bounds its own wait with its own `request_timeout`; the
    /// dialog's lifetime belongs to the leader alone. A follower that runs
    /// out of time while the prompt is still up gets [`Timeout`] and fails
    /// closed, even though the user might have approved a moment later —
    /// which is the same thing that would have happened to it without
    /// coalescing, and it keeps the rule to one sentence instead of
    /// arithmetic over other callers' deadlines. A follower can never wait
    /// *longer* than it asked to.
    ///
    /// [`Timeout`]: ApprovalOutcome::Timeout
    async fn follow_inflight(
        &self,
        key: &CoalesceKey,
        mut rx: broadcast::Receiver<ApprovalOutcome>,
        request_timeout: Duration,
    ) -> ApprovalOutcome {
        eprintln!(
            "cache-warden: approver: joining the approval already on screen for {:?} ({}), \
             pid {} — not raising a second prompt",
            key.key, key.operation, key.pid
        );
        match tokio::time::timeout(request_timeout, rx.recv()).await {
            Ok(Ok(outcome)) => outcome,
            // The leader went away without an answer (its caller
            // disconnected, or a shutdown cut it short). Nothing was
            // decided, so this fails closed like any other unanswered
            // approval; the caller may try again, which will raise a fresh
            // prompt now that the entry is gone.
            Ok(Err(_)) => ApprovalOutcome::Ipc(
                "the approval this request joined ended without an answer".to_string(),
            ),
            Err(_) => ApprovalOutcome::Timeout,
        }
    }

    /// Put one dialog on screen and classify what comes back. The
    /// leader-only half of [`await_dialog_outcome`].
    async fn run_dialog(
        &self,
        request: ApproveRequest,
        starting_wait: Duration,
        request_timeout: Duration,
    ) -> ApprovalOutcome {
        let Some(approver) = self.wait_ready(starting_wait).await else {
            return ApprovalOutcome::HelperUnavailable;
        };
        match approver.request(request, request_timeout).await {
            Ok(resp) => match resp.outcome {
                WireOutcome::Approved => ApprovalOutcome::Approved,
                WireOutcome::Denied => ApprovalOutcome::Denied,
                WireOutcome::Cancelled => ApprovalOutcome::Cancelled,
                WireOutcome::Timeout => ApprovalOutcome::Timeout,
                WireOutcome::PeerGone => ApprovalOutcome::PeerGone,
                WireOutcome::BiometricFailed => ApprovalOutcome::BiometricFailed,
            },
            Err(e) => ApprovalOutcome::Ipc(e.to_string()),
        }
    }

    pub(crate) async fn wait_ready(&self, timeout: Duration) -> Option<Arc<dyn Approver>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Enable the waiter FIRST so a `notify_waiters` call that
            // races the state check below still wakes us. See method doc.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            {
                let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                match &*guard {
                    ApproverState::Ready(a) => return Some(Arc::clone(a)),
                    ApproverState::Down => return None,
                    ApproverState::Starting => {}
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                // Timed out at the deadline computation itself: a
                // `set_ready` fired between our state check and now
                // could otherwise be missed. Re-check once before
                // giving up.
                let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                return match &*guard {
                    ApproverState::Ready(a) => Some(Arc::clone(a)),
                    _ => None,
                };
            }
            if tokio::time::timeout(remaining, notified).await.is_err() {
                // Bounded wait expired. Same re-check as above — do not
                // let a set_ready that fired at the deadline instant
                // leak through as a `None`.
                let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                return match &*guard {
                    ApproverState::Ready(a) => Some(Arc::clone(a)),
                    _ => None,
                };
            }
        }
    }
}

/// A bounded-wait connection counter (DR-0029 §4's drain step).
///
/// Incremented when [`serve`] accepts a connection, decremented when
/// [`handle_connection`] returns. [`ConnectionTracker::wait_drained`] resolves
/// as soon as the count reaches zero, or after `deadline` elapses, whichever
/// is first — the design's "現行の全クライアントは per-request 接続 ...
/// deadline 超過分は切断してよい" (DR-0029 §4).
pub(crate) struct ConnectionTracker {
    count: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

impl ConnectionTracker {
    pub(crate) fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn inc(&self) {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn dec(&self) {
        // `fetch_sub` returns the *previous* value; `1` means the count just
        // reached zero, so wake anyone waiting in `wait_drained`.
        if self.count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    /// Wait for the count to reach zero, or for `deadline` to elapse —
    /// whichever comes first. Never panics or errors: a timed-out drain is
    /// an accepted outcome (DR-0029 §4), not a failure.
    async fn wait_drained(&self, deadline: std::time::Duration) {
        let drained = async {
            loop {
                if self.count.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                    return;
                }
                self.notify.notified().await;
            }
        };
        let _ = tokio::time::timeout(deadline, drained).await;
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Open a passkey registration window, once a human here has approved it.
///
/// # Why the gate is here and not in the browser
///
/// A registered passkey is a way into the vault forever after, and the
/// ceremony that creates one runs in a browser — which anything able to reach
/// the loopback port could drive. So the browser half is never what authorizes
/// a registration: this is. The approval dialog is raised on this machine, and
/// the ceremony endpoints refuse to register anything until it has been
/// answered (DR-0034 §1c, DR-0031 for the dialog).
///
/// **Fail-closed**: an approver helper that is missing, down, or unanswered is
/// a refusal, not a pass. The only way past it is `allow_without_local_approval`,
/// which exists so a machine with no working helper is not permanently unable
/// to register — and which is named the way it is so that using it is visible
/// in a shell history, a script, and this reply.
async fn add_passkey(
    shared: &Arc<Shared>,
    label: String,
    allow_without_local_approval: bool,
) -> Response {
    let Some(ceremony) = shared.ceremony.clone() else {
        return Response::error(
            ErrorKind::BadRequest,
            "this daemon runs no passkey ceremony: set [vault] rp-id and expected-origins, \
             then restart it",
        );
    };
    let Some(addr) = shared.ceremony_addr.get().copied() else {
        return Response::error(
            ErrorKind::Internal,
            "the ceremony listener did not start; see the daemon's log",
        );
    };
    // Adding a slot re-wraps the data key for a new recipient, so the vault
    // has to be open — which also means whoever is adding a way in already had
    // one (DR-0034 §1c).
    match shared
        .vault
        .as_deref()
        .map(|v| v.lock().map(|g| g.is_unlocked()).unwrap_or(false))
    {
        None => {
            return Response::error(
                ErrorKind::VaultNotInitialized,
                "this daemon has no vault configured",
            );
        }
        Some(false) => {
            return Response::error(
                ErrorKind::VaultLocked,
                "the vault must be open to register a passkey: unlock it first, with a recovery \
                 code or a passkey you already registered",
            );
        }
        Some(true) => {}
    }

    if allow_without_local_approval {
        eprintln!(
            "cache-warden: warning: a passkey registration was opened with \
             --allow-without-local-approval; no local approval was requested for it"
        );
    } else {
        let request = crate::daemon::approver_wire::build_approve_request(
            uuid_like_request_id(),
            "vault".to_string(),
            "register passkey",
            &[],
            None,
            None,
            // No guard evaluation to show: this approval is about adding a
            // way into the vault, not about one entry's access rules.
            &crate::daemon::guard::GuardEvalOutput {
                constraints: Vec::new(),
                setter_pinned: None,
                getter_matched: None,
            },
            APPROVAL_TIMEOUT_SECS,
        );
        let outcome = shared
            .approver
            .await_dialog_outcome(
                request,
                APPROVER_STARTING_WAIT,
                Duration::from_secs(APPROVAL_TIMEOUT_SECS as u64),
            )
            .await;
        if !matches!(outcome, ApprovalOutcome::Approved) {
            eprintln!(
                "cache-warden: passkey registration refused: {}",
                outcome.label()
            );
            return Response::error(
                ErrorKind::AuthFailed,
                format!(
                    "registering a passkey needs approval on this machine ({}). If this machine \
                     has no working approver, pass --allow-without-local-approval",
                    outcome.label()
                ),
            );
        }
    }

    let expires_in_secs = {
        let Ok(mut guard) = ceremony.lock() else {
            return Response::error(ErrorKind::Internal, "the ceremony is unavailable");
        };
        guard.arm_registration(label);
        crate::daemon::ceremony::REGISTRATION_WINDOW.as_secs()
    };
    Response::ceremony_opened(format!("http://{addr}/"), expires_in_secs)
}

/// Answer a passkey unlock with the URL that performs it.
///
/// No approval gate here, unlike registration: unlocking needs the passkey
/// itself, and the ceremony refuses every response that is not a verified
/// assertion from a registered credential. Gating the *offer* would only stop
/// a user from reaching a page that cannot help an attacker anyway.
fn ceremony_url_for_unlock(shared: &Arc<Shared>) -> Response {
    if shared.vault.is_none() {
        return Response::error(
            ErrorKind::VaultNotInitialized,
            "this daemon has no vault configured",
        );
    }
    let Some(addr) = shared.ceremony_addr.get().copied() else {
        return Response::error(
            ErrorKind::BadRequest,
            "this daemon runs no passkey ceremony, so a passkey cannot unlock it: set [vault] \
             rp-id and expected-origins and restart, or unlock with `--recovery`",
        );
    };
    Response::ceremony_opened(
        format!("http://{addr}/"),
        crate::daemon::ceremony::challenge::CHALLENGE_TTL.as_secs(),
    )
}

/// How long the approval dialog for a registration stays up.
const APPROVAL_TIMEOUT_SECS: u32 = 120;
/// How long to wait for the approver helper to come up before giving up.
const APPROVER_STARTING_WAIT: Duration = Duration::from_secs(5);

/// A request id for the approval dialog.
///
/// The dialog only needs it to match a reply to its request, so any
/// unpredictable string does; this avoids a uuid dependency for one field.
fn uuid_like_request_id() -> String {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bind the ceremony listener and produce the task that serves it.
///
/// `Ok(None)` when there is no vault to run a ceremony against — a relying
/// party is configured but nothing is stored, so there is nothing to unlock.
#[allow(clippy::type_complexity)]
async fn ceremony_listener(
    config: &Config,
    ceremony: Arc<Mutex<crate::daemon::ceremony::Ceremony>>,
    vault: Option<Arc<Mutex<crate::daemon::vault_state::VaultState>>>,
    store: crate::daemon::ceremony::StoreAccess,
) -> Result<
    Option<(
        std::net::SocketAddr,
        impl std::future::Future<Output = ()> + Send + 'static,
    )>,
    crate::daemon::ceremony::ListenError,
> {
    let Some(vault) = vault else {
        return Ok(None);
    };
    if config.vault.expected_origins.is_empty() {
        // An empty list is not "allow anything": every response would be
        // refused for its origin, so the ceremony could never complete. Saying
        // so at startup beats a user discovering it mid-registration.
        eprintln!(
            "cache-warden: warning: [vault] rp-id is set but expected-origins is empty, so no \
             ceremony response can be accepted. Add the origin the page is served from."
        );
    }
    let addr = config
        .vault
        .ceremony_listen
        .clone()
        .unwrap_or_else(|| crate::config::DEFAULT_CEREMONY_LISTEN.to_string());
    let (listener, bound) = crate::daemon::ceremony::bind(&addr).await?;
    Ok(Some((
        bound,
        crate::daemon::ceremony::serve(listener, ceremony, vault, store),
    )))
}

/// Where and what to persist for online definitions (DR-0014 §4).
struct PersistSettings {
    /// The state file path (`$XDG_STATE_HOME/cache-warden/definitions.toml`).
    path: PathBuf,
    /// Names defined by the config `[kv.*]` section. These are **excluded** from
    /// the persisted file: the config is their source of truth, so writing them
    /// to the state file would leak config definitions into the online layer (and
    /// resurrect them as stale "online" definitions if persistence is later
    /// turned off). Only genuinely online definitions are persisted.
    config_names: std::collections::HashSet<String>,
}

#[cfg(test)]
impl Shared {
    /// Build a `Shared` directly for tests (no config / socket binding), using
    /// the production [`CommandRunner`]. The authsock unit tests use this to
    /// exercise the local-sign path against a real core.
    pub(crate) fn new_for_test(
        store: Store,
        cap: Capability,
        auth: Auth,
        clock: SystemClock,
    ) -> Self {
        let otp_adapter = crate::daemon::otp_adapter::OtpAdapter::new(cap.clone());
        Self {
            store: Arc::new(Mutex::new(store)),
            control_cap: cap.clone(),
            authsock_cap: cap,
            otp_adapter,
            ceremony: None,
            ceremony_addr: std::sync::OnceLock::new(),
            owner_verifier: Arc::new(crate::daemon::owner_eval::CodeSignatureVerifier),
            runner: CommandRunner::new(),
            auth,
            clock,
            persist: std::sync::OnceLock::new(),
            socket_path: String::new(),
            pid: std::process::id(),
            kv_process_policies: std::collections::BTreeMap::new(),
            vault: None,
            persisted_keys: std::collections::BTreeSet::new(),
            kv_policy: crate::config::ResolvedKvPolicy {
                default_require_same_user: false,
                shell_names: crate::config::default_shell_names(),
            },
            exe_path: PathBuf::new(),
            argv: Vec::new(),
            restart: graceful_restart::RestartCoordinator::new(),
            active_connections: ConnectionTracker::new(),
            approver: ApproverSlot::new_down(),
            fda_applicable: false,
        }
    }
}

/// Headroom given to the graceful-restart receiving process's `Monotonic`
/// clock (DR-0029 bundle 2 review MEDIUM-6, see the `clock` construction in
/// [`run`]). Chosen generously (a full day) rather than matching some
/// expected restart cadence: the only cost of a larger value is the
/// (essentially free) `Instant` subtraction itself, while too small a value
/// re-opens the exact security gap this constant exists to close for any
/// entry whose TTL/age exceeds it. Falls back to zero headroom
/// (`SystemClock::new()`-equivalent) if the process/system has not been up
/// long enough to represent it — see [`SystemClock::with_epoch_offset`]'s doc.
const GRACEFUL_RESTART_CLOCK_HEADROOM: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// Run the daemon in the foreground until SIGINT / SIGTERM, using `config`.
///
/// Binds `socket_path`, registers the config's `[kv.*]` command definitions
/// (running eagerly only the `preload = true` ones and those referenced by an
/// `[authsock.sockets.*].keys` list), serves the control socket, and removes
/// the socket file on clean shutdown.
///
/// `socket_path` is already resolved by the caller (CLI `--socket` > env >
/// `[daemon].socket` > built-in default); the daemon does not re-derive it.
pub async fn run(socket_path: PathBuf, config: Config) -> Result<(), ServerError> {
    // Install the shutdown-signal notifier *first*, before the (potentially slow)
    // startup work below. The shutdown signals are already blocked process-wide
    // (`block_shutdown_signals`, called before the runtime started); a dedicated
    // `sigwait` thread consumes them. Spawning it up front means a SIGINT/SIGTERM
    // that arrives *during* startup is dequeued immediately and its notification
    // latched (tokio's `Notify` stores one permit), so the daemon still shuts
    // down promptly even if it is signalled before it finishes binding/preloading.
    #[cfg(unix)]
    let shutdown_notify = spawn_shutdown_notifier(socket_path.clone());

    // Suppress core dumps before any secret enters the Store: a crash must not
    // write in-memory secrets (incl. mlocked pages, DR-0007) to disk. Fail-open
    // and consistent with the mlock policy — a failure warns but does not abort
    // (see `hardening::suppress_core_dumps`).
    if !super::hardening::suppress_core_dumps() {
        eprintln!(
            "cache-warden: warning: could not disable core dumps (RLIMIT_CORE); \
             a crash could leak in-memory secrets to a core file"
        );
    }

    // Refuse debugger attachment so a live process inspector cannot read
    // in-memory secrets (DR-0007), defeating the mlock + core-dump layers.
    // Opt-out via `[daemon].allow-debug-attach = true`; never weaken silently —
    // a single stderr warning is printed either way (opt-out or syscall refusal).
    if config.allow_debug_attach() {
        eprintln!(
            "cache-warden: warning: anti-debug hardening disabled \
             ([daemon].allow-debug-attach = true); a debugger can attach and read \
             in-memory secrets"
        );
    } else if !super::hardening::deny_debugger_attach() {
        eprintln!(
            "cache-warden: warning: could not refuse debugger attachment; \
             a debugger could attach and read in-memory secrets"
        );
    }

    // DR-0029 bundle 2 review MEDIUM-5: call `try_receive` (which, as a side
    // effect, also spawns the state-holder reaper —
    // `receive::reap_holder_in_background` — the moment it sees the handoff
    // env var) *before* `bind_control_socket` can fail and return early via
    // `?` below. Previously a bind failure (e.g. another process already
    // holds the path) skipped `try_receive` entirely on a real
    // graceful-restart handoff, leaving the old process's state-holder child
    // unreaped by this process (its kernel parent, post-`execve`) until this
    // process's own eventual exit. Calling it first guarantees the reaper
    // always starts as soon as this process has taken the handoff fd,
    // independent of whether the rest of startup goes on to succeed.
    //
    // `try_receive` reads and parses the snapshot (bounded by its own 60s
    // timeout); any failure — no env var, a malformed stream, a timeout —
    // falls back to `None` here, and the daemon proceeds exactly as a normal
    // cold start (empty store) from this point on.
    let incoming = graceful_restart::receive::try_receive();

    // Bind the control socket early so clients can connect (and answer `ping`)
    // while `preload = true` entries are running (DR-0023 Phase 1).
    let listener = bind_control_socket(&socket_path)?;

    let runner = CommandRunner::new();

    // DR-0029 bundle 2 review MEDIUM-6: a plain `SystemClock::new()` anchors
    // its `Monotonic` numbering to *this* construction, i.e. ~zero headroom.
    // `Store::import_snapshot`'s reconstruction clamps safely when headroom
    // runs out (see `epoch_ms_to_monotonic`'s doc), but "safely" here means an
    // old entry is treated as freshly loaded — extending a hard-TTL secret's
    // true residency past the config's intended maximum age. `incoming` above
    // already tells us whether this is a real handoff (not just whether the
    // env var was *present* — an already-consumed one), so the extra
    // headroom applies exactly when there is a snapshot to import.
    let clock = if incoming.is_some() {
        SystemClock::with_epoch_offset(GRACEFUL_RESTART_CLOCK_HEADROOM)
    } else {
        SystemClock::new()
    };

    // DR-0029 §3: this process's own exec path, resolved once here and never
    // re-derived at restart time (a later `current_exe()` call could be
    // fooled by a changed cwd / a `plist` pointed elsewhere in the meantime —
    // DR-0029 §3's rationale for pinning it to the startup value). Empty on
    // failure (rare); graceful restart's own verification step then always
    // rejects, everything else about the daemon is unaffected.
    let exe_path = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!(
            "cache-warden: warning: cannot resolve this process's own exec path ({e}); \
             `daemon restart --graceful` will be unavailable"
        );
        PathBuf::new()
    });
    let argv: Vec<String> = std::env::args().collect();

    let cold_bundle = || {
        StoreBuilder::new()
            .failure_backoff(config.fetch_failure_backoff())
            .build()
    };
    let (handoff_stream, bundle, inherited_dek) = match incoming {
        Some(graceful_restart::receive::IncomingHandoff {
            stream,
            snapshot,
            dek: handoff_dek,
        }) => {
            match Store::import_snapshot(
                StoreBuilder::new().failure_backoff(config.fetch_failure_backoff()),
                snapshot,
                &clock,
            ) {
                Ok(bundle) => (Some(stream), bundle, handoff_dek),
                Err(e) => {
                    eprintln!(
                        "cache-warden: warning: graceful-restart handoff snapshot was rejected \
                         ({e}); falling back to a cold start"
                    );
                    // `stream` drops here (closes our end) — the ABORT
                    // signal the old process's state-holder is waiting on
                    // (DR-0029 §5). The inherited data key is dropped with it:
                    // a cold start has no imported entries for it to open, and
                    // starting locked is the safe end of a failed handoff.
                    (None, cold_bundle(), None)
                }
            }
        }
        None => (None, cold_bundle(), None),
    };

    // Build `Shared` with the (possibly graceful-restart-imported) Store and
    // an empty `persist` OnceLock. The persist slot is filled from within the
    // blocking startup task after definitions are registered (DR-0023
    // Phase 1): OnceLock allows a single interior write after the Arc has
    // been handed to the serve loop, without needing a Mutex or rebuilding
    // the whole Shared struct.
    let otp_adapter = crate::daemon::otp_adapter::OtpAdapter::new(bundle.otp_cap);
    // Whether Full Disk Access is relevant to this config at all — a property
    // of the config, so resolved once here and carried on `Shared`.
    #[cfg(target_os = "macos")]
    let fda_applicable = crate::fda::has_op_sources(&config);
    #[cfg(not(target_os = "macos"))]
    let fda_applicable = false;
    // DR-0034 §5/§7. A vault is configured whenever the config names one or
    // declares a persisted entry; there is no separate on/off switch (see
    // `VaultConfig`). Opening it here — before the listener binds — means a
    // corrupt vault stops startup rather than surfacing on the first read.
    let vault = {
        let declared = !config.persisted_keys().is_empty();
        let configured = config.vault.path.is_some() || config.vault.profile.is_some();
        match (declared || configured)
            .then(|| {
                crate::daemon::vault_state::resolve_path(
                    config.vault.path.as_deref(),
                    config.vault.profile.as_deref(),
                )
            })
            .flatten()
        {
            None => None,
            Some(path) => {
                let vault_path = path.clone();
                // A vault file that exists but will not parse stops startup:
                // serving a daemon whose user believes their credentials are
                // protected by something unreadable is worse than not serving.
                let state = crate::daemon::vault_state::VaultState::open_at(path)
                    .map_err(|e| ServerError::Io(std::io::Error::other(format!("vault: {e}"))))?;
                // DR-0034 §11: a data key inherited from the predecessor reopens
                // the vault, so a graceful restart does not cost the user an
                // unlock. A key that does not fit leaves the vault locked rather
                // than failing startup — the entries are intact on disk and one
                // `vault unlock` recovers.
                let state = match (state, inherited_dek.as_ref()) {
                    (crate::daemon::vault_state::VaultState::Locked { vault }, Some(key)) => {
                        match vault.unlock_with_dek(key) {
                            Ok(open) => crate::daemon::vault_state::VaultState::Unlocked {
                                vault: Box::new(open),
                            },
                            Err(e) => {
                                eprintln!(
                                    "cache-warden: warning: the vault key handed over by the \
                                     previous process did not open the vault ({e}); it starts \
                                     locked. Run `cache-warden vault unlock`."
                                );
                                // `unlock_with_dek` consumed the handle, so the
                                // locked state is rebuilt by re-reading the file.
                                crate::daemon::vault_state::VaultState::open_at(&vault_path)
                                    .map_err(|e| {
                                        ServerError::Io(std::io::Error::other(format!(
                                            "vault: {e}"
                                        )))
                                    })?
                            }
                        }
                    }
                    (state, _) => state,
                };
                // DR-0034 §7: a vault opens for *any* of its slots, so one slot
                // registered against a development RP sets the strength of the
                // whole vault. Say so at startup, where it is still cheap to act on.
                if state.has_dev_rp_slot() {
                    eprintln!(
                        "cache-warden: warning: this vault has a slot registered against a \
                         development origin (localhost). Any such slot can open the whole \
                         vault — remove it before treating this vault as production."
                    );
                }
                if declared
                    && matches!(
                        state,
                        crate::daemon::vault_state::VaultState::NotInitialized { .. }
                    )
                {
                    eprintln!(
                        "cache-warden: warning: {} entr{} declared `persist = true` but no vault \
                         exists yet. Run `cache-warden vault init`; until then those entries \
                         fail closed.",
                        config.persisted_keys().len(),
                        if config.persisted_keys().len() == 1 {
                            "y is"
                        } else {
                            "ies are"
                        }
                    );
                }
                Some(Arc::new(Mutex::new(state)))
            }
        }
    };

    // Built before `Shared` so both the control-socket handler and the
    // ceremony listener share one instance: a registration armed by the
    // command has to be the one the browser finds.
    let ceremony = config.vault.rp_id.clone().map(|rp_id| {
        Arc::new(Mutex::new(crate::daemon::ceremony::Ceremony::new(
            rp_id,
            config.vault.expected_origins.clone(),
        )))
    });

    let shared = Arc::new(Shared {
        store: Arc::new(Mutex::new(bundle.store)),
        control_cap: bundle.control_cap,
        authsock_cap: bundle.authsock_cap,
        otp_adapter,
        runner,
        auth: build_authenticator(&config),
        clock,
        persist: std::sync::OnceLock::new(), // filled after startup by the blocking task
        socket_path: socket_path.display().to_string(),
        pid: std::process::id(),
        kv_process_policies: config.kv_process_policies(),
        vault,
        ceremony: ceremony.clone(),
        ceremony_addr: std::sync::OnceLock::new(),
        owner_verifier: Arc::new(crate::daemon::owner_eval::CodeSignatureVerifier),
        persisted_keys: config.persisted_keys(),
        kv_policy: config.kv_policy(),
        exe_path,
        argv,
        restart: graceful_restart::RestartCoordinator::new(),
        active_connections: ConnectionTracker::new(),
        // DR-0031 §10: helper is spawned *after* the blocking startup task
        // (which restores the store and registers config definitions), so a
        // guarded reveal-get arriving during that window gets the bounded
        // `helper_starting` wait via `ApproverSlot::wait_ready`. Guard-less
        // `kv.get` never consults this slot (§9: unguarded is transparent).
        approver: ApproverSlot::new_starting(),
        fda_applicable,
    });

    // DR-0034 §10: the ceremony page, on loopback, with TLS terminated in
    // front of it if it is reached from anywhere but this machine.
    //
    // Only started when the configuration names a relying party. Without one
    // there is nothing a ceremony could be for, and a listener nobody can
    // complete a ceremony against is a port open for no reason.
    if let Some(ceremony) = ceremony {
        let store_access = crate::daemon::ceremony::StoreAccess {
            store: shared.store.clone(),
            cap: shared.control_cap.clone(),
            clock: Arc::new(SystemClock::new()),
        };
        match ceremony_listener(&config, ceremony, shared.vault.clone(), store_access).await {
            Ok(Some((addr, task))) => {
                eprintln!("cache-warden: vault ceremony available at http://{addr}/");
                shared
                    .ceremony_addr
                    .set(addr)
                    .expect("the ceremony address is set once");
                tokio::spawn(task);
            }
            Ok(None) => {}
            // A ceremony that cannot start is not a reason to refuse to serve:
            // the daemon's other work is unaffected, and the recovery code
            // still opens the vault. Say so loudly and carry on.
            Err(e) => eprintln!("cache-warden: warning: {e}"),
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start the accept loop immediately so clients can connect while preloading.
    let server = tokio::spawn(serve(listener, Arc::clone(&shared), shutdown_rx.clone()));

    println!(
        "cache-warden daemon listening on {} (pid {}). Press Ctrl+C to stop.",
        shared.socket_path, shared.pid
    );

    // Register `[kv.*]` command definitions on the blocking pool (DR-0023 Phase 1).
    //
    // Each entry is registered as a definition (lazy by default); a `preload = true`
    // entry is also run eagerly so its first `get` is a cache hit. A failed eager
    // preload is a warning, not fatal: the definition stays registered and the value
    // regenerates on the next `get`.
    //
    // Keys referenced by any `[authsock.sockets.*].keys` are force-eager regardless
    // of `preload`: the agent registry derives their public halves at startup
    // (REQUEST_IDENTITIES needs the PEM resident), and the socket declaration itself
    // is the intent — requiring a second `preload = true` on the same key would be a
    // silent-footgun (a forgotten flag would drop the key from the agent;
    // DR-0004's "never interrupt key use" invariant).
    //
    // `register_definitions` may call `runner.run()` for eager entries, which can
    // block for seconds (a secret source may prompt the user). Running it on the
    // blocking pool prevents stalling the tokio runtime. A concurrent `select!` on
    // the shutdown notify lets a SIGTERM received during startup abort the preload
    // immediately (DR-0023 Phase 1).
    let authsock_keys: std::collections::HashSet<String> = config
        .authsock_sockets()
        .iter()
        .flat_map(|s| s.keys.iter().cloned())
        .collect();
    let config_defs = config.kv_definitions();

    // Clone the Arc so the blocking closure can write into the shared Store and
    // fill the OnceLock persist slot.
    let shared_for_startup = Arc::clone(&shared);
    eprintln!("cache-warden: registering config definitions ...");
    let t0 = std::time::Instant::now();

    // Capture everything the blocking closure needs by value so the closure is
    // `'static`. `runner` is Copy. `config_defs` and `authsock_keys` are moved.
    let runner_for_task = runner; // Copy
    let config_defs_for_task = config_defs.clone();
    let authsock_keys_for_task = authsock_keys.clone();
    // Persist-related data also goes into the blocking task to keep all I/O
    // (file reads for restore, file writes for rewrite) off the async runtime.
    let persist_enabled = config.persist_definitions();
    let config_names_for_persist: std::collections::HashSet<String> = config_defs
        .iter()
        .map(|d| d.full_key(crate::namespace::DEFAULT_NAMESPACE))
        .collect();
    let blocking = tokio::task::spawn_blocking(move || {
        // Write config definitions directly into the shared Store while holding
        // its lock. The serve loop is already running but no client request can
        // observe a partial state: each request takes the same lock, so they
        // queue behind this startup write (DR-0008 invariant).
        let mut store = shared_for_startup
            .store
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // DR-0029 bundle 2: whatever already has a value at this point came
        // from a graceful-restart handoff import (run just before `Shared`
        // was built, below) — empty on every other startup. Computed fresh
        // here rather than threaded through from the import step so a cold
        // start (the overwhelmingly common case) pays nothing beyond an
        // empty-store scan.
        let already_loaded: std::collections::HashSet<String> = store
            .list_filtered(|r| r.entry().is_some())
            .into_iter()
            .map(String::from)
            .collect();

        // DR-0029 bundle 2 review CRITICAL fix: see `clear_config_owned_definitions`'s
        // doc. A no-op on a cold start (nothing is defined yet at this point).
        clear_config_owned_definitions(&mut store, &config_names_for_persist);

        register_definitions(
            &mut store,
            &runner_for_task,
            &shared_for_startup.clock,
            &config_defs_for_task,
            &authsock_keys_for_task,
            &already_loaded,
            &shared_for_startup.control_cap,
        );

        // Restore persisted online definitions (DR-0014 §4) inside the same
        // blocking task to keep all startup I/O off the async runtime.
        if persist_enabled {
            let path = crate::defs::definitions_state_path();
            match crate::defs::load_definitions(&path) {
                Ok(persisted) => {
                    // DR-0029 bundle 2 review HIGH-1 fix: see
                    // `purge_stale_import_definitions`'s doc. Computed
                    // *before* `restore_persisted_definitions` consumes
                    // `persisted` below.
                    let persisted_names: std::collections::HashSet<String> = persisted
                        .iter()
                        .map(|d| d.full_key(crate::namespace::DEFAULT_NAMESPACE))
                        .collect();
                    restore_persisted_definitions(&mut store, persisted, &config_names_for_persist);
                    purge_stale_import_definitions(
                        &mut store,
                        &config_names_for_persist,
                        &persisted_names,
                    );
                }
                Err(e) => {
                    eprintln!("cache-warden: {e}; ignoring persisted definitions");
                }
            }
            let settings = PersistSettings {
                path,
                config_names: config_names_for_persist,
            };
            write_online_definitions(&settings, &store);
            // Install into the OnceLock while still holding the store lock so
            // the serve loop never observes a window where the file is written
            // but `persist` is not yet set. The store lock is the gate: any
            // `kv.define` / `kv.del --with-define` request arriving now queues
            // behind this lock and will see `persist` set when it runs.
            let _ = shared_for_startup.persist.set(settings);
        }
        // store lock released here (MutexGuard dropped)
    });

    // Race the blocking startup work against a shutdown signal (DR-0023 Phase 1):
    // if SIGTERM arrives while preload is running, abort and exit cleanly.
    #[cfg(unix)]
    {
        match &shutdown_notify {
            Some(notify) => {
                tokio::select! {
                    res = blocking => {
                        res.map_err(|e| ServerError::Io(
                            io::Error::other(format!("startup task panicked: {e}"))
                        ))?;
                    }
                    _ = notify.notified() => {
                        // Shutdown signal arrived during startup. The blocking task
                        // is still running in the thread pool but we are not
                        // awaiting it — it will complete eventually (or be
                        // terminated when the process exits). The watchdog timer in
                        // spawn_shutdown_notifier bounds the total latency.
                        eprintln!("cache-warden: shutdown signal received during startup");
                        let _ = shutdown_tx.send(true);
                        let _ = server.await;
                        let _ = std::fs::remove_file(&socket_path);
                        return Err(ServerError::ShutdownDuringStartup);
                    }
                }
            }
            None => {
                // No shutdown notifier (extremely unlikely): run to completion.
                blocking.await.map_err(|e| {
                    ServerError::Io(io::Error::other(format!("startup task panicked: {e}")))
                })?;
            }
        }
    }
    #[cfg(not(unix))]
    blocking
        .await
        .map_err(|e| ServerError::Io(io::Error::other(format!("startup task panicked: {e}"))))?;

    eprintln!(
        "cache-warden: startup complete in {:.2}s",
        t0.elapsed().as_secs_f64()
    );

    // DR-0029 §5: if this startup imported a graceful-restart handoff, this
    // process is now fully up (definitions registered, control socket
    // bound) — send the two-phase-commit `COMMIT` frame so the old
    // process's state-holder zeroizes its buffer and exits cleanly instead
    // of waiting out its 60s timeout.
    if let Some(stream) = handoff_stream {
        graceful_restart::receive::send_commit(stream);
    }

    // DR-0031 §10: spawn the approver helper now that the store is fully
    // restored and definitions are registered. Runs in the background so a
    // slow helper spawn does not delay the authsock listeners below (§9:
    // guard-less entries stay transparent even while the helper is starting
    // / down; guarded reveal-gets await `ApproverSlot::wait_ready` with a
    // bounded timeout). A `spawn_helper` failure transitions the slot to
    // `Down`, which is exactly the fail-closed shape guarded gets need.
    let approver_shared = Arc::clone(&shared);
    let approver_socket_path = socket_path
        .parent()
        .map(|d| d.join("approver.sock"))
        .unwrap_or_else(|| PathBuf::from("/tmp/cache-warden-approver.sock"));
    let fda_prompt_wanted = fda_prompt_wanted(fda_applicable);
    tokio::spawn(async move {
        match resolve_approver_helper_path() {
            Some(helper_path) => {
                match super::approver::ApproverClient::start(
                    helper_path,
                    approver_socket_path,
                    HELPER_STARTING_WAIT,
                )
                .await
                {
                    Ok(client) => {
                        let client = Arc::new(client);
                        if fda_prompt_wanted {
                            request_fda_prompt(&client).await;
                        }
                        approver_shared.approver.set_ready(client);
                    }
                    Err(e) => {
                        eprintln!(
                            "cache-warden: warning: could not start approver helper ({e}); \
                             guarded kv.get requests will fail closed with 'approver helper \
                             unavailable'"
                        );
                        approver_shared.approver.set_down();
                    }
                }
            }
            None => {
                eprintln!(
                    "cache-warden: warning: approver helper binary not found; \
                     guarded kv.get requests will fail closed"
                );
                approver_shared.approver.set_down();
            }
        }
    });

    // Start one SSH agent listener per `[authsock.sockets.*]` (port Iteration 1).
    // Each binds its own socket (same 0600 / stale-recovery / double-start guard
    // as the control socket) and shares this process's Store / auth / runner /
    // clock (DR-0008). A bind failure for one socket is logged and skipped; the
    // daemon and the other sockets stay up.
    // Resolve the github filter settings (durations pre-validated at parse).
    let github_settings = super::authsock::GithubSettings {
        cache_ttl: config
            .authsock_github()
            .cache_ttl_duration()
            .unwrap_or_else(|_| std::time::Duration::from_secs(3600)),
        timeout: config
            .authsock_github()
            .timeout_duration()
            .unwrap_or_else(|_| std::time::Duration::from_secs(10)),
    };

    // Bind the authsock listeners immediately, seeded from the disk cache
    // (DR-0023 Phase 2): startup never blocks on `op`. `op item list` /
    // `op item get` are synchronous CLI calls that can hang for tens of seconds (a
    // launchd-context daemon whose biometric path never reaches the GUI session),
    // so instead of running discovery *before* binding, each socket binds from the
    // last-known keys in the disk cache and a background task refreshes them once
    // `op` is reachable. A cold first-ever start seeds nothing and the sockets bind
    // empty until the background discovery populates them. This removes the P1
    // symptom (`docs/issue/2026-06-13`): listeners no longer wait on `op`.
    let authsock_sources = config.authsock_sources();
    let authsock_sockets = config.authsock_sockets();
    let seed = super::authsock::seed_all_sources_from_cache(&authsock_sources);

    let super::authsock::ListenerSet {
        mut handles,
        discovery_targets,
        exe,
    } = super::authsock::spawn_listeners(
        &authsock_sockets,
        &authsock_sources,
        seed,
        github_settings,
        Arc::clone(&shared),
        shutdown_rx.clone(),
    );

    // Spawn the background op discovery (DR-0023 Phase 2): it runs the blocking
    // `op item list` off the async runtime, retries with a capped backoff until
    // the first success, and then hot-updates each socket's registry. It is
    // select-able with the shutdown channel, so a stop signal is honoured at once
    // even while discovery hangs (the sockets are already bound above, so there is
    // no startup block to interrupt). Pushed into `handles` so shutdown awaits it
    // like the github refresh task.
    if !authsock_sources.is_empty() && !discovery_targets.is_empty() {
        let refresh = tokio::spawn(super::authsock::op_discovery_refresh(
            discovery_targets,
            authsock_sources,
            exe,
            Arc::clone(&shared),
            shutdown_rx.clone(),
        ));
        handles.push((PathBuf::new(), refresh));
    }
    let authsock_handles = handles;

    // Race the normal SIGINT/SIGTERM path against a `daemon.restart_graceful`
    // request that has already been verified and prepared (DR-0029 bundle
    // 2). Both converge on the exact same cleanup below (drain, stop
    // accepting, close + unlink every listener) — reusing the existing
    // shutdown path *is* DR-0029 §1's "accept 停止 → drain → close +
    // unlink" step, not a second implementation of it. Only the very last
    // action (return `Ok(())` vs. fork/exec) differs.
    #[cfg(unix)]
    let restart_requested = tokio::select! {
        _ = wait_for_shutdown(shutdown_notify) => false,
        _ = shared.restart.wait() => true,
    };
    #[cfg(not(unix))]
    let restart_requested = {
        wait_for_shutdown().await;
        // Graceful restart's control-socket handler rejects every request on
        // this platform before it could ever call `shared.restart`'s signal
        // (see `graceful_restart::handle_request`'s non-macOS guard), so this
        // is always the outcome here.
        false
    };
    let _ = shutdown_tx.send(true);
    // DR-0029 §4: only the restart path drains — the pre-existing
    // SIGINT/SIGTERM shutdown behaviour (no drain wait) is unchanged.
    if restart_requested {
        shared
            .active_connections
            .wait_drained(RESTART_DRAIN_DEADLINE)
            .await;
    }
    let _ = server.await;
    for (path, handle) in authsock_handles {
        let _ = handle.await;
        // Clean up each agent socket file (best effort).
        let _ = std::fs::remove_file(&path);
    }

    // Clean up the control socket file (best effort).
    let _ = std::fs::remove_file(&socket_path);

    // DR-0031 §10: kill the approver helper before either
    // (a) a graceful `execve` — an orphan helper would keep holding a
    // socket the new daemon needs to bind — or
    // (b) a plain clean shutdown — the helper's own `kill_on_drop` would
    // fire on Arc drop, but a proactive shutdown also unlinks the socket
    // file (`ApproverClient::shutdown`) so the next start's `bind` skips
    // the stale-socket removal branch.
    if let Some(approver) = shared.approver.current_ready() {
        approver.shutdown().await;
    }

    if restart_requested {
        // Every listener is now closed and unlinked (DR-0029 §1's fd-hygiene
        // requirement) — only now is it safe to fork the state-holder and
        // `execve` this process. Does not return on success; if it does
        // return, the fork/exec sequence itself failed at the very last
        // moment and there is nothing left to recover (the listeners are
        // already gone) — fall through to the normal clean-shutdown return
        // below and rely on the service manager to cold-restart this process.
        graceful_restart::execute_after_shutdown(&shared);
    }
    Ok(())
}

/// Register command-source definitions into `store` at startup (DR-0014 §4).
///
/// Every entry is registered as a definition (KEY ↔ command + TTL) — no upstream
/// runs unless the entry is eager, in which case the command is also run so the
/// first `get` is a cache hit. An entry is eager when `preload = true` **or**
/// when its name is in `force_eager` (keys referenced by an
/// `[authsock.sockets.*].keys` list: the agent registry needs the PEM resident at
/// startup to enumerate the public key, so the socket declaration implies
/// preload — no second flag required). A bad TTL bound skips the whole entry; a
/// failed eager run is a single secret-free stderr warning and leaves the
/// definition in place (the value regenerates on the next `get`). The daemon must
/// come up even if an upstream secret source is temporarily down.
///
/// `already_loaded` (DR-0029 bundle 2) is the set of composed keys that
/// already carry a value — populated from a graceful-restart handoff import
/// that ran just before this call, empty on every other startup (cold start,
/// or a handoff that failed and fell back to cold). A `preload` / force-eager
/// entry whose key is already in this set skips its eager run: the value
/// just arrived intact from the old process, so re-running the source here
/// would be exactly the re-fetch storm graceful restart exists to avoid.
fn register_definitions<R, C>(
    store: &mut Store,
    runner: &R,
    clock: &C,
    entries: &[KvDefinition],
    force_eager: &std::collections::HashSet<String>,
    already_loaded: &std::collections::HashSet<String>,
    cap: &Capability,
) where
    R: SourceRunner,
    C: cache_warden::Clock,
{
    for entry in entries {
        // The store key is the composed `NS/KEY` (DR-0017 §5: a pinned
        // `namespace` field is absolute; absent means the daemon-config
        // context, which is the default namespace).
        let full_key = entry.full_key(crate::namespace::DEFAULT_NAMESPACE);
        let ttl = match Ttl::new(
            entry.soft_ttl_secs.map(std::time::Duration::from_secs),
            entry.hard_ttl_secs.map(std::time::Duration::from_secs),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cache-warden: definition `{full_key}` skipped: {e}");
                continue;
            }
        };

        // Register the definition so a later `get` can regenerate the value. A
        // conflict (the same name already defined differently) should not happen
        // at startup from a single config, but is reported defensively. The
        // typed source is lowered to the execution primitive while its typed
        // origin is preserved in the opaque source slot (DR-0018 §1/§2). The
        // opaque value-type metadata (DR-0016) rides along with the definition.
        let source = entry.source.lower();
        let source_meta = entry.source.to_source_meta();
        let meta = crate::daemon::handler::meta_from_wire(entry.meta.clone());
        match store.define_with_meta(
            full_key.clone(),
            source.clone(),
            ttl,
            meta.clone(),
            source_meta,
        ) {
            Ok(()) => {}
            Err(DefineError::Conflict) => {
                eprintln!(
                    "cache-warden: definition `{full_key}` conflicts with an existing definition; skipped"
                );
                continue;
            }
            Err(DefineError::StaticNotDefinable) => {
                // Unreachable: a command source is never static.
                eprintln!("cache-warden: definition `{full_key}` skipped: static source");
                continue;
            }
            Err(DefineError::InvalidKey(e)) => {
                // Unreachable from config: `full_key` is composed from a
                // charset-validated NS + KEY. Reported defensively.
                eprintln!("cache-warden: definition `{full_key}` skipped: {e}");
                continue;
            }
        }

        // Lazy by default; `preload = true` or an authsock-referenced key runs
        // the command eagerly. The produced value is opaque bytes; the key's
        // type (otp) stays on the definition registered just above (DR-0016).
        // `force_eager` holds composed keys (authsock `keys` are normalized at
        // config validation), so the comparison is composed-to-composed.
        if (entry.preload || force_eager.contains(&full_key)) && !already_loaded.contains(&full_key)
        {
            // Run the lowered execution primitive (argv + cwd/env; DR-0018 §1).
            let argv = source.command_argv().unwrap_or(&[]).to_vec();
            let cwd = source.command_cwd().map(|p| p.to_path_buf());
            let env = source.command_env().clone();
            match runner.run(&argv, cwd.as_deref(), &env) {
                Ok(value) => {
                    store
                        .set(full_key.clone(), source, value, ttl, cap, clock)
                        .ok();
                }
                Err(e) => {
                    // The RunError Display is already secret-free (stderr redacted).
                    eprintln!("cache-warden: preload `{full_key}` failed: {e}");
                }
            }
        }
    }
}

/// Merge persisted online definitions into `store` under the config-priority
/// rule (DR-0014 §4).
///
/// For each persisted definition:
/// - if `config_names` already defines that key, the config wins: the persisted
///   entry is **dropped** with a secret-free stderr warning (this is what keeps
///   "I edited the config but the stale persisted def keeps winning" from
///   happening). It is also absent from the post-merge snapshot, so the caller's
///   rewrite removes it from disk.
/// - otherwise the persisted definition is registered. A bad TTL bound or a
///   conflict with an already-registered definition (should not happen since
///   config keys are filtered out first) is warned and skipped, never fatal.
fn restore_persisted_definitions(
    store: &mut Store,
    persisted: Vec<KvDefinition>,
    config_names: &std::collections::HashSet<String>,
) {
    for def in persisted {
        let full_key = def.full_key(crate::namespace::DEFAULT_NAMESPACE);
        if config_names.contains(&full_key) {
            eprintln!(
                "cache-warden: persisted definition `{full_key}` dropped (the config defines \
                 it; config wins)"
            );
            continue;
        }
        let ttl = match Ttl::new(
            def.soft_ttl_secs.map(std::time::Duration::from_secs),
            def.hard_ttl_secs.map(std::time::Duration::from_secs),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cache-warden: persisted definition `{full_key}` skipped: {e}");
                continue;
            }
        };
        let source = def.source.lower();
        let source_meta = def.source.to_source_meta();
        let meta = crate::daemon::handler::meta_from_wire(def.meta.clone());
        match store.define_with_meta(full_key.clone(), source, ttl, meta, source_meta) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("cache-warden: persisted definition `{full_key}` skipped: {e}");
            }
        }
    }
}

/// Clear any existing definition for every key in `config_names` (DR-0029
/// bundle 2 review CRITICAL fix), so `register_definitions`'s upcoming
/// `define_with_meta` call always inserts cleanly instead of ever hitting
/// `DefineError::Conflict`.
///
/// A graceful-restart handoff import can leave the store already carrying a
/// definition for a config-defined key (imported wholesale from the old
/// process's live registry, before this function or `register_definitions`
/// ever runs). `define_with_meta`'s idempotency is an *exact-match* rule
/// (DR-0014 §1): if that imported definition differs from the config's
/// current one at all (e.g. its TTL or argv changed since the old process
/// started), `register_definitions` would hit `Conflict` and skip
/// re-registering it — silently leaving the *stale* imported definition in
/// place, so a config edit would never take effect across a graceful
/// restart. Clearing it first (via [`Store::undefine`], which touches only
/// the definition — never the cached *value* or its failure-backoff record)
/// makes the config always win, exactly as it would on a cold start: the
/// cached value keeps serving uninterrupted, and the next regeneration
/// (`get_or_regenerate`) picks up the new TTL/argv from the
/// freshly-registered definition.
///
/// A no-op on a cold start (nothing is defined yet when this runs).
fn clear_config_owned_definitions(
    store: &mut Store,
    config_names: &std::collections::HashSet<String>,
) {
    for full_key in config_names {
        store.undefine(full_key);
    }
}

/// Remove any definition the store still carries that is neither a current
/// config definition nor a genuinely persisted online one (DR-0029 bundle 2
/// review HIGH-1 fix), returning the removed keys (for logging/testing).
///
/// A graceful-restart handoff import can leave the store carrying a
/// definition for a key the *old* process's config used to define but the
/// *current* config no longer does — an orphan that is neither a config
/// definition (excluded from [`online_definitions`]'s filter) nor ever
/// actually persisted as online. Left alone, such an orphan would still be
/// swept into `write_online_definitions`'s next write as if it *were*
/// genuinely online — resurrecting itself on every subsequent restart. Call
/// this only once `register_definitions` and `restore_persisted_definitions`
/// have both already run, so `expected` names (config ∪ the state file's own
/// persisted names, computed by the caller *before* the latter call
/// consumes its `persisted` argument) reflect every definition that is
/// supposed to still be there.
///
/// Every `kv.define` / `kv.del --with-define` synchronously rewrites the
/// state file (`persist_if_enabled`), so `persisted_names` is always in sync
/// as of the last successful mutation — the only reliable way to tell an
/// orphan apart from a genuinely online definition that just happens to also
/// ride along in the handoff snapshot. Callers gate this to the
/// `persist_enabled` branch only: without persistence there is no such
/// trustworthy record, and a lingering in-memory-only orphan is harmless (it
/// is never written to disk).
fn purge_stale_import_definitions(
    store: &mut Store,
    config_names: &std::collections::HashSet<String>,
    persisted_names: &std::collections::HashSet<String>,
) -> Vec<String> {
    let expected: std::collections::HashSet<&String> =
        config_names.iter().chain(persisted_names).collect();
    let stale: Vec<String> = store
        .list_filtered(|r| r.definition().is_some())
        .into_iter()
        .map(String::from)
        .filter(|k| !expected.contains(k))
        .collect();
    for key in &stale {
        store.undefine(key);
    }
    stale
}

/// The store's **online** definition registry: every definition minus the names
/// the config defines (DR-0014 §4).
///
/// Config `[kv.*]` definitions are the config's responsibility, not the state
/// file's, so they are excluded — persisting them would resurrect them as stale
/// "online" definitions if persistence is later turned off.
fn online_definitions(settings: &PersistSettings, store: &Store) -> Vec<KvDefinition> {
    crate::defs::snapshot_definitions(store)
        .into_iter()
        .filter(|d| {
            !settings
                .config_names
                .contains(&d.full_key(crate::namespace::DEFAULT_NAMESPACE))
        })
        .collect()
}

/// Atomically rewrite the state file from the store's online definitions,
/// warning (non-fatal) on failure. Used at startup to normalize the file.
fn write_online_definitions(settings: &PersistSettings, store: &Store) {
    if let Err(e) =
        crate::defs::save_definitions(&settings.path, &online_definitions(settings, store))
    {
        eprintln!(
            "cache-warden: warning: could not write persisted definitions {}: {e}",
            settings.path.display()
        );
    }
}

/// Persist the store's online definition registry if persistence is on.
///
/// Called from the request path after a definition-changing command
/// (`kv.define` / `kv.del --with-define`) succeeds. A write failure is returned
/// so the caller can surface it (an in-memory/disk divergence is the dangerous
/// case — DR-0014 §4); when persistence is off (or startup has not yet completed)
/// this is a no-op `Ok(())`.
fn persist_if_enabled(shared: &Shared, store: &Store) -> std::io::Result<()> {
    match shared.persist.get() {
        Some(settings) => {
            crate::defs::save_definitions(&settings.path, &online_definitions(settings, store))
        }
        None => Ok(()),
    }
}

/// The accept loop: serve connections until the shutdown signal flips.
async fn serve(
    listener: UnixListener,
    shared: Arc<Shared>,
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
                        let shared = Arc::clone(&shared);
                        shared.active_connections.inc();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, Arc::clone(&shared)).await {
                                // Connection-level I/O errors are non-fatal.
                                eprintln!("cache-warden: connection error: {e}");
                            }
                            shared.active_connections.dec();
                        });
                    }
                    Err(e) => {
                        eprintln!("cache-warden: accept error: {e}");
                    }
                }
            }
        }
    }
}

/// Handle one client connection: read request lines, reply per line.
///
/// One connection may carry multiple request/response lines (the client may
/// keep the socket open). Each line is one JSON request; we reply with one JSON
/// response line. The peer pid is resolved once at accept time.
async fn handle_connection(stream: UnixStream, shared: Arc<Shared>) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let peer = peer_pid(fd);
    // DR-0030: capture the peer's audit token now, while the raw fd
    // still refers to the connected socket. `peer_audit_token` is
    // race-free per the kernel's `LOCAL_PEERTOKEN` contract (keyed on
    // the fd, not on a pid), so caching it once at accept time is safe
    // for the whole connection lifetime — and lets `run_request` build
    // the guard-evaluator material without a second syscall per request.
    // On Linux / a non-socket / a getsockopt failure this collapses to
    // `None` (the guard evaluator then denies whenever a `SameUser`
    // constraint requires it — fail-closed).
    let peer_token_full = macos_process_inspect::peer_audit_token(fd);
    let peer_token = peer_token_full.map(|t| GetterAuditToken {
        euid: t.euid(),
        ruid: t.ruid(),
    });

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = dispatch_async(&shared, peer, peer_token, peer_token_full, &line).await;
        let mut out = encode_response(&response).unwrap_or_else(|_| {
            r#"{"ok":false,"error":{"kind":"internal","message":"failed to encode response"}}"#
                .to_string()
        });
        out.push('\n');
        write_half.write_all(out.as_bytes()).await?;
        write_half.flush().await?;
    }
    Ok(())
}

/// Parse one request line, run it against the store, and produce a response.
///
/// Resolves the requester ancestry from `peer` (best effort) and runs the
/// synchronous handler under the store lock. Retained for the pre-existing
/// malformed-line test; live traffic goes through [`dispatch_async`] so a
/// guarded reveal-get can await the approver dialog.
#[cfg(test)]
fn dispatch(
    shared: &Arc<Shared>,
    peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    line: &str,
) -> Response {
    let req = match decode_request(line) {
        Ok(r) => r,
        Err(e) => {
            return Response::error(ErrorKind::BadRequest, format!("malformed request: {e}"));
        }
    };
    run_request(shared, peer, peer_token, None, req)
}

/// Run a parsed request against the store under lock.
///
/// Factored out so it can be exercised directly in tests without socket I/O.
fn run_request(
    shared: &Arc<Shared>,
    peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
    req: Request,
) -> Response {
    // `ping` needs neither the store lock nor the requester ancestry (it just
    // returns a pong). Short-circuit before taking the lock so pings succeed
    // even while the startup blocking task holds the store lock (DR-0023 Phase 1).
    if matches!(req, Request::Ping) {
        return Response::pong();
    }
    // `daemon.restart_graceful` (DR-0029) is handled entirely by
    // `graceful_restart`, which takes the store lock itself only for the
    // brief snapshot-export step — it never goes through the generic
    // `handler::handle_request` dispatch below.
    if matches!(req, Request::RestartGraceful) {
        return graceful_restart::handle_request(shared);
    }

    // Resolve requester ancestry from the peer pid (best effort). This is
    // the DR-0030 §Security "one snapshot at request receive time" point:
    // both the plain [`ProcessInfo`] chain (used by the DR-0012 gate + the
    // core auth context) and the enriched [`GetterProcess`] chain (fed to
    // the guard evaluator) come from the same walk here, so a mid-request
    // parent exit shows up consistently to every gate.
    let requester: Option<Vec<ProcessInfo>> = peer.and_then(|pid| {
        let inspector = SystemInspector::new();
        inspector.ancestry(pid).ok()
    });
    // Enrich each chain entry with the private-API `unique_id` when
    // available (fail-open: any per-pid failure just drops that entry's
    // unique_id to `None`, which the evaluator handles per DR-0030
    // §Security's stated fallback rules). Non-macOS builds return
    // `Err(Unavailable)` from `unique_id` for every pid, so the entire
    // chain arrives with `unique_id: None` and the evaluator makes the
    // fail-closed calls it already documents.
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

    // DR-0010: the authenticator is wired from config (CommandAuthenticator when
    // `[auth].command` is set, else AllowAll), built once at startup.
    let auth: &dyn Authenticator = shared.auth.as_ref();

    let mut store = match shared.store.lock() {
        Ok(g) => g,
        Err(_) => return Response::error(ErrorKind::Internal, "store lock poisoned"),
    };

    // A command that can change the definition registry triggers a persist on
    // success (DR-0014 §4). Capture this before `req` is moved into the handler.
    let may_change_definitions = matches!(
        req,
        Request::KvDefine { .. }
            | Request::KvDel {
                with_define: true,
                ..
            }
    );

    let ctx = HandlerCtx {
        auth,
        runner: &shared.runner,
        clock: &shared.clock,
        store_cap: &shared.control_cap,
        otp_adapter: &shared.otp_adapter,
        pid: shared.pid,
        version: VERSION,
        socket: &shared.socket_path,
        // Probed for `status` alone — see the field's doc for why not for
        // every request.
        full_disk_access: if matches!(req, Request::Status) {
            Some(current_fda_status(shared))
        } else {
            None
        },
        requester: requester.as_deref(),
        kv_process_policies: &shared.kv_process_policies,
        vault: shared.vault.as_deref(),
        peer_token: peer_token_full.as_ref(),
        owner_verifier: shared.owner_verifier.as_ref(),
        persisted_keys: &shared.persisted_keys,
        guard_chain: guard_chain.as_deref(),
        guard_audit_token: peer_token,
        kv_policy: &shared.kv_policy,
        guard_check_mode: GuardCheckMode::Evaluate,
    };
    let response = handler::handle_request(&mut store, &ctx, req);

    // Persist the (possibly changed) definition registry while still holding the
    // store lock, so the on-disk file is a consistent snapshot of the registry
    // that just mutated (DR-0014 §4). The write is synchronous on the blocking
    // pool (the whole locked section already runs there, DR-0008); `define` /
    // `del --with-define` are low-frequency, so the added latency is acceptable.
    // A write failure becomes an Internal error response rather than silently
    // diverging the in-memory registry from disk (codex review: the divergence
    // is the dangerous failure mode).
    if may_change_definitions
        && matches!(response, Response::Ok(_))
        && let Err(e) = persist_if_enabled(shared, &store)
    {
        return Response::error(
            ErrorKind::Internal,
            format!("definition applied but could not be persisted: {e}"),
        );
    }
    response
}

// ---------------------------------------------------------------------------
// DR-0031 §8 approver-dialog integration
// ---------------------------------------------------------------------------

/// How long a guarded reveal-get waits for the approver helper to reach a
/// terminal state (`Ready` / `Down`) before treating it as `Down` and
/// failing closed. Sized to survive the brief startup window (helper spawn
/// plus peer verification typically completes in tens of ms on a warm host
/// and in low hundreds on a cold one) without pinning a caller for so long
/// that a dead helper is indistinguishable from a slow one.
pub(crate) const HELPER_STARTING_WAIT: Duration = Duration::from_secs(5);

/// How long the daemon waits for the user to answer the approver dialog
/// before giving up. Loose upper bound on the human interaction; matches
/// the DR-0031 §4 wire default (`ApproveRequest.timeout_secs = 60`) plus
/// a small allowance for the helper's own bookkeeping / peer_gone message.
pub(crate) const APPROVER_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

/// The `timeout_secs` field on the wire: the deadline the **helper** runs its
/// dialog countdown against. Deliberately shorter than the daemon's own
/// `APPROVER_REQUEST_TIMEOUT` so the helper's `Outcome::Timeout` response
/// wins the race — the daemon then reports a helper-confirmed timeout rather
/// than giving up on a dialog that is still on screen.
pub(crate) const APPROVER_WIRE_TIMEOUT_SECS: u32 = 60;

/// Monotonically-increasing counter feeding `ApproveRequest.request_id` (a
/// pid + monotonic number). Wire schema documents the field as an "opaque
/// String" — no `uuid` crate dep — and pinning uniqueness within a daemon
/// lifetime is enough (the helper only needs to match responses to
/// pending requests).
static APPROVER_REQUEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn mint_approver_request_id() -> String {
    let n = APPROVER_REQUEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}-{}", std::process::id(), n)
}

/// The outcome of the guard-eval first pass under the store lock, driving
/// whether the async gated flow needs to await the dialog or can return the
/// response the handler already produced.
#[derive(Debug)]
enum GuardedGetFirstPass {
    /// Terminal response — either a happy `Ok(Get)` for an unguarded entry
    /// (the whole handler ran) or an error (reserved-namespace / process-
    /// policy / guard-denied / etc.). Return as-is.
    Direct(Response),
    /// The entry is guarded, the guard evaluation passed, and the dialog
    /// must be shown. Carries the material the wire adapter needs to build
    /// the `ApproveRequest`.
    NeedsApproval {
        guard_eval: guard_eval::GuardEvalOutput,
        /// The requester chain snapshotted at first-pass time — reused
        /// verbatim by both the wire builder (for the dialog) and the
        /// second-pass re-evaluation (so a mid-approval `proc_pidinfo`
        /// change cannot make the re-check disagree with the just-approved
        /// evaluation).
        chain: Option<Vec<GetterProcess>>,
        /// Same chain in the display-only `ProcessInfo` form — needed to
        /// feed the retrieval chain's core `AuthContext` on the second
        /// pass (`ctx.requester`).
        requester: Option<Vec<ProcessInfo>>,
    },
}

/// Async replacement of [`dispatch`] that intercepts guarded reveal-`kv.get`
/// requests to run them through the approver dialog, while every other
/// request keeps the pre-existing `spawn_blocking(dispatch)` shape.
async fn dispatch_async(
    shared: &Arc<Shared>,
    peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
    line: &str,
) -> Response {
    let req = match decode_request(line) {
        Ok(r) => r,
        Err(e) => {
            return Response::error(ErrorKind::BadRequest, format!("malformed request: {e}"));
        }
    };
    run_request_async(shared, peer, peer_token, peer_token_full, req).await
}

/// The async gated dispatcher.
///
/// The gated path is narrow on purpose: **reveal** (`dry_run = false`)
/// `kv.get`s only. Everything else flows through the pre-existing
/// `spawn_blocking(run_request)` shape unchanged.
///
/// # Why `dry_run` is not gated
///
/// A dry-run verifies the retrieval chain (DR-0015) but never returns the
/// secret, so displaying an approver dialog for it would ask the human to
/// approve nothing observable. draft-DR-0031 §8's own listing of the dialog
/// firing conditions predates a dry-run split, so this is the daemon-side
/// resolution: dry-run stays silent. Documented here (rather than only in
/// the DR) because the decision is enforced *at this dispatcher*, not in
/// the handler.
pub(crate) async fn run_request_async(
    shared: &Arc<Shared>,
    peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
    req: Request,
) -> Response {
    // `vault.add_passkey` needs a human at this machine to approve before
    // anything is opened (DR-0034 §1c), and the approval dialog is async, so
    // it is handled here rather than in the sync dispatch below.
    if let Request::VaultAddPasskey {
        label,
        allow_without_local_approval,
    } = &req
    {
        return add_passkey(shared, label.clone(), *allow_without_local_approval).await;
    }

    // A passkey unlock happens in a browser, so what the caller gets back is
    // where to do it. The recovery path carries a code and goes through the
    // ordinary dispatch below.
    if let Request::VaultUnlock {
        recovery_code: None,
    } = &req
    {
        return ceremony_url_for_unlock(shared);
    }

    // Only reveal-`kv.get`s take the gated path. Everything else uses the
    // pre-existing `spawn_blocking(run_request)` shape.
    let key = match &req {
        Request::KvGet {
            key,
            dry_run: false,
        } => key.clone(),
        _ => {
            let shared_c = Arc::clone(shared);
            return tokio::task::spawn_blocking(move || {
                run_request(&shared_c, peer, peer_token, peer_token_full, req)
            })
            .await
            .unwrap_or_else(|e| {
                Response::error(ErrorKind::Internal, format!("handler panicked: {e}"))
            });
        }
    };
    let key = key.clone();

    // Resolve the requester + guard chain once (same snapshot the sync
    // `run_request` builds). Cheap-ish syscall (`proc_pidinfo`) run
    // directly on the async worker: the ancestry walk is not "blocking" in
    // the tokio sense (bounded time, no user prompt).
    let requester: Option<Vec<ProcessInfo>> = peer.and_then(|pid| {
        let inspector = SystemInspector::new();
        inspector.ancestry(pid).ok()
    });
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

    let shared_first = Arc::clone(shared);
    let token_first = peer_token_full;
    let key_first = key.clone();
    let chain_first = guard_chain.clone();
    let requester_first = requester.clone();
    let first_pass_result = tokio::task::spawn_blocking(move || {
        guarded_get_first_pass(
            &shared_first,
            peer,
            peer_token,
            token_first,
            requester_first,
            chain_first,
            key_first,
        )
    })
    .await
    .unwrap_or_else(|e| {
        GuardedGetFirstPass::Direct(Response::error(
            ErrorKind::Internal,
            format!("handler panicked: {e}"),
        ))
    });

    match first_pass_result {
        GuardedGetFirstPass::Direct(resp) => resp,
        GuardedGetFirstPass::NeedsApproval {
            guard_eval: eval_output,
            chain: pass_chain,
            requester: pass_requester,
        } => {
            let wire_req = approver_wire::build_approve_request(
                mint_approver_request_id(),
                key.clone(),
                "get",
                pass_chain.as_deref().unwrap_or(&[]),
                peer_token_full.as_ref(),
                None,
                &eval_output,
                APPROVER_WIRE_TIMEOUT_SECS,
            );
            match shared
                .approver
                .await_dialog_outcome(wire_req, HELPER_STARTING_WAIT, APPROVER_REQUEST_TIMEOUT)
                .await
            {
                ApprovalOutcome::Approved => {}
                ApprovalOutcome::HelperUnavailable => {
                    return Response::error(
                        ErrorKind::AuthFailed,
                        "approver helper unavailable (helper is not running)",
                    );
                }
                ApprovalOutcome::Ipc(err) => {
                    return Response::error(
                        ErrorKind::AuthFailed,
                        format!("approver dialog failed: {err}"),
                    );
                }
                other => {
                    // Log the precise outcome for the operator, hand the
                    // client the coarser message (see `client_message`).
                    eprintln!("cache-warden: kv.get denied for {key:?}: {}", other.label());
                    return Response::error(
                        ErrorKind::AuthFailed,
                        other.client_message().to_string(),
                    );
                }
            }
            let shared_second = Arc::clone(shared);
            let token_second = peer_token_full;
            let key_second = key.clone();
            let chain_second = pass_chain.clone();
            let requester_second = pass_requester.clone();
            tokio::task::spawn_blocking(move || {
                guarded_get_finalize_after_approval(
                    &shared_second,
                    peer,
                    peer_token,
                    token_second,
                    requester_second,
                    chain_second,
                    key_second,
                )
            })
            .await
            .unwrap_or_else(|e| {
                Response::error(ErrorKind::Internal, format!("handler panicked: {e}"))
            })
        }
    }
}

/// First-pass evaluation under the store lock: replicate the reserved-
/// namespace + process-policy pre-gates from [`handler::handle_request`]
/// (so a guarded reveal-get gets exactly the same denial semantics as an
/// unguarded one), then either
///
/// - run the whole handler when the entry is unguarded (returning
///   [`GuardedGetFirstPass::Direct`] with the response the handler
///   produced), or
/// - evaluate the guard record fail-closed and either return `Direct(...)`
///   on denial or [`GuardedGetFirstPass::NeedsApproval`] on success (with
///   the material the wire adapter will need to build the dialog).
///
/// The lock is released on return, so the async caller can await the
/// dialog without keeping the store lock held: a multi-second human
/// approval must never sit behind the store lock, or every other
/// request on this daemon would queue behind it.
#[allow(clippy::too_many_arguments)]
fn guarded_get_first_pass(
    shared: &Arc<Shared>,
    _peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
    requester: Option<Vec<ProcessInfo>>,
    guard_chain: Option<Vec<GetterProcess>>,
    key: String,
) -> GuardedGetFirstPass {
    // Snapshot everything the sync handler would use, so if we fall through
    // to the unguarded branch we can drive `handle_request` with the same
    // context shape the pre-existing `run_request` builds.
    let mut store = match shared.store.lock() {
        Ok(g) => g,
        Err(_) => {
            return GuardedGetFirstPass::Direct(Response::error(
                ErrorKind::Internal,
                "store lock poisoned",
            ));
        }
    };
    // Unguarded entries take the fast path — run the whole handler here so
    // the caller gets a single lock take + single spawn_blocking. Failure
    // mode: the handler itself will still enforce reserved-namespace and
    // process-policy gates, so we do not need to duplicate them.
    if store.guard_of(&key).is_none() {
        let auth: &dyn Authenticator = shared.auth.as_ref();
        let ctx = HandlerCtx {
            auth,
            runner: &shared.runner,
            clock: &shared.clock,
            store_cap: &shared.control_cap,
            otp_adapter: &shared.otp_adapter,
            pid: shared.pid,
            version: VERSION,
            socket: &shared.socket_path,
            full_disk_access: None,
            requester: requester.as_deref(),
            kv_process_policies: &shared.kv_process_policies,
            vault: shared.vault.as_deref(),
            peer_token: peer_token_full.as_ref(),
            owner_verifier: shared.owner_verifier.as_ref(),
            persisted_keys: &shared.persisted_keys,
            guard_chain: guard_chain.as_deref(),
            guard_audit_token: peer_token,
            kv_policy: &shared.kv_policy,
            guard_check_mode: GuardCheckMode::Evaluate,
        };
        let resp = handler::handle_request(
            &mut store,
            &ctx,
            Request::KvGet {
                key,
                dry_run: false,
            },
        );
        return GuardedGetFirstPass::Direct(resp);
    }

    // Guarded path. Apply the same pre-gates as `handle_get`.
    if let Some((ns, _)) = key.split_once('/')
        && crate::namespace::is_reserved_namespace(ns)
    {
        return GuardedGetFirstPass::Direct(Response::error(
            ErrorKind::BadRequest,
            format!("namespace {ns:?} is reserved and cannot be read"),
        ));
    }
    if let Some(allowed) = shared.kv_process_policies.get(&key)
        && !cache_warden_authsock::chain_gate_passes(requester.as_deref(), allowed)
    {
        return GuardedGetFirstPass::Direct(Response::error(
            ErrorKind::AuthFailed,
            "process not permitted to access this key",
        ));
    }

    // Evaluate the guard record. Must live long enough to hand to
    // `guard_eval::evaluate`; a `guard_of` borrow ends when we drop the
    // reference below.
    let record = store.guard_of(&key).expect("checked non-None above");
    let chain_slice: &[GetterProcess] = match guard_chain.as_deref() {
        Some(c) => c,
        None => {
            eprintln!(
                "cache-warden: kv.get denied for {key:?}: guard requires a requester \
                 chain but the peer could not be walked"
            );
            return GuardedGetFirstPass::Direct(Response::error(
                ErrorKind::AuthFailed,
                "access denied by entry guard (kind: missing-context)",
            ));
        }
    };
    match guard_eval::evaluate(chain_slice, peer_token, record) {
        Ok(output) => {
            // Drop the store lock explicitly by ending the scope before
            // returning — the return moves the result out with no
            // borrowed data.
            drop(store);
            GuardedGetFirstPass::NeedsApproval {
                guard_eval: output,
                chain: guard_chain,
                requester,
            }
        }
        Err(denied) => {
            let kind = guard_eval::denied_kind_label(denied.kind);
            eprintln!("cache-warden: kv.get denied for {key:?}: guard constraint {kind:?} failed");
            GuardedGetFirstPass::Direct(Response::error(
                ErrorKind::AuthFailed,
                format!("access denied by entry guard (kind: {kind})"),
            ))
        }
    }
}

/// Second-pass evaluation, run after the dialog returned `Approved`:
/// re-take the store lock, re-evaluate the guard record fail-closed (the
/// record may have been overwritten while the human was deciding), then
/// hand the get to the sync handler with
/// [`GuardCheckMode::AlreadyApproved`] so it does not re-evaluate the
/// guard a third time.
///
/// # Why re-evaluate
///
/// A `kv.set` on the same key concurrent with the dialog can replace the
/// guard record entirely (DR-0030 §5 "last declaration wins"), which
/// might now deny a getter the *previous* record accepted. Approving the
/// first record does not authorize a get against the second. If the guard
/// record disappeared (concurrent unguarded `kv.set`), the entry is now
/// unguarded and a plain get is safe — the handler handles that case.
#[allow(clippy::too_many_arguments)]
fn guarded_get_finalize_after_approval(
    shared: &Arc<Shared>,
    _peer: Option<u32>,
    peer_token: Option<GetterAuditToken>,
    peer_token_full: Option<macos_process_inspect::AuditToken>,
    requester: Option<Vec<ProcessInfo>>,
    guard_chain: Option<Vec<GetterProcess>>,
    key: String,
) -> Response {
    let mut store = match shared.store.lock() {
        Ok(g) => g,
        Err(_) => return Response::error(ErrorKind::Internal, "store lock poisoned"),
    };
    if let Some(record) = store.guard_of(&key) {
        let chain_slice: &[GetterProcess] = match guard_chain.as_deref() {
            Some(c) => c,
            None => {
                return Response::error(
                    ErrorKind::AuthFailed,
                    "access denied by entry guard (kind: missing-context) after approval",
                );
            }
        };
        if let Err(denied) = guard_eval::evaluate(chain_slice, peer_token, record) {
            let kind = guard_eval::denied_kind_label(denied.kind);
            eprintln!(
                "cache-warden: kv.get denied for {key:?} after approval: guard \
                 constraint {kind:?} failed on re-evaluation (record changed \
                 during approval)"
            );
            return Response::error(
                ErrorKind::AuthFailed,
                format!(
                    "access denied by entry guard (kind: {kind}); record changed \
                     during approval"
                ),
            );
        }
    }
    let auth: &dyn Authenticator = shared.auth.as_ref();
    let ctx = HandlerCtx {
        auth,
        runner: &shared.runner,
        clock: &shared.clock,
        store_cap: &shared.control_cap,
        otp_adapter: &shared.otp_adapter,
        pid: shared.pid,
        version: VERSION,
        socket: &shared.socket_path,
        full_disk_access: None,
        requester: requester.as_deref(),
        kv_process_policies: &shared.kv_process_policies,
        vault: shared.vault.as_deref(),
        peer_token: peer_token_full.as_ref(),
        owner_verifier: shared.owner_verifier.as_ref(),
        persisted_keys: &shared.persisted_keys,
        guard_chain: guard_chain.as_deref(),
        guard_audit_token: peer_token,
        kv_policy: &shared.kv_policy,
        guard_check_mode: GuardCheckMode::AlreadyApproved,
    };
    handler::handle_request(
        &mut store,
        &ctx,
        Request::KvGet {
            key,
            dry_run: false,
        },
    )
}

/// Resolve the approver helper binary path.
///
/// Search order (first match wins):
/// 1. `$CACHE_WARDEN_APPROVER_BIN` — dev / integration-test override, so
///    a locally-built helper (`just approver-run` etc.) can be pointed at
///    the daemon without touching config or filesystem layout.
/// 2. `/Applications/CacheWarden.app/Contents/Helpers/CacheWardenApprover.app/Contents/MacOS/cache-warden-approver`
///    — production layout (DR-0031 §11 nested helper bundle).
///
/// Returns `None` when neither candidate exists — the caller transitions
/// the [`ApproverSlot`] to `Down` (§9 helper_down fallback).
///
/// # No sibling fallback
///
/// A `<exe_dir>/cache-warden-approver` sibling probe would sound convenient
/// but backfires in every non-production layout that happens to have the
/// helper built next to the daemon (Cargo's `target/debug/` in particular).
/// Under `cargo test`, spawning the ad-hoc-signed dev helper always fails
/// peer verification and takes 5 s to time out — long enough to leave the
/// helper as a zombie under the daemon and to trip the graceful-restart
/// e2e's zombie-detection assertion. Requiring an explicit env var (or the
/// installed bundle) is the correct default.
fn resolve_approver_helper_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("CACHE_WARDEN_APPROVER_BIN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    let production = PathBuf::from(
        "/Applications/CacheWarden.app/Contents/Helpers/CacheWardenApprover.app/Contents/MacOS/cache-warden-approver",
    );
    if production.is_file() {
        return Some(production);
    }
    None
}

/// Probe this daemon's Full Disk Access state for a `status` reply.
///
/// The daemon is the only process that can answer usefully: TCC attributes a
/// probe to whoever performs it, and this process — running from
/// `CacheWarden.app` — is the one whose permission decides whether `op`
/// launches quietly. That is why `daemon status` asks the daemon instead of
/// probing on its own behalf.
#[cfg(target_os = "macos")]
fn current_fda_status(shared: &Arc<Shared>) -> crate::protocol::wire::FdaStatusWire {
    use crate::protocol::wire::FdaStatusWire;
    if !shared.fda_applicable {
        return FdaStatusWire::NotApplicable;
    }
    if macos_tcc::current_app_bundle().is_none() {
        return FdaStatusWire::Unknown;
    }
    match crate::fda::check_in_process() {
        macos_tcc::AuthState::Granted => FdaStatusWire::Granted,
        macos_tcc::AuthState::NotGranted => FdaStatusWire::NotGranted,
        macos_tcc::AuthState::Unknown => FdaStatusWire::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
fn current_fda_status(_shared: &Arc<Shared>) -> crate::protocol::wire::FdaStatusWire {
    crate::protocol::wire::FdaStatusWire::NotApplicable
}

/// How long [`request_fda_prompt`] gives the send (see
/// [`super::approver::ApproverClient::notify_fda_prompt`]). Generous for one
/// line on a fresh connection, and nothing depends on it succeeding — the
/// daemon runs identically either way.
const FDA_PROMPT_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Decide whether this startup should ask the helper to explain Full Disk
/// Access, and say what it found in the log either way.
///
/// Three conditions, all necessary:
///
/// - the config can spawn `op` (`applicable`, resolved at startup — otherwise
///   the permission buys nothing),
/// - this daemon runs from the installed `.app` bundle (a bare binary has no
///   TCC identity to grant, and the probe below would answer about the wrong
///   process),
/// - the permission is not granted yet.
///
/// The probe is in-process on purpose: this process *is* the bundle, so its
/// own read attempt is attributed correctly — no re-launch trick needed
/// (unlike the CLI surfaces; see [`crate::fda`]).
#[cfg(target_os = "macos")]
fn fda_prompt_wanted(applicable: bool) -> bool {
    if !applicable {
        return false;
    }
    if macos_tcc::current_app_bundle().is_none() {
        eprintln!(
            "cache-warden: full disk access: not checked (this daemon is not running from \
             CacheWarden.app, so there is no bundle identity to grant it to)"
        );
        return false;
    }
    let state = crate::fda::check_in_process();
    eprintln!("cache-warden: full disk access: {state}");
    state != macos_tcc::AuthState::Granted
}

#[cfg(not(target_os = "macos"))]
fn fda_prompt_wanted(_applicable: bool) -> bool {
    false
}

/// Ask the helper to put the Full Disk Access explainer on screen, once per
/// daemon start.
///
/// Fire-and-forget in both directions: the send is bounded and its failure is
/// logged rather than propagated, and no reply is awaited. A daemon that
/// cannot explain the permission still works — the user just keeps answering
/// the system's own dialog on each `op` launch, which is the status quo this
/// prompt is trying to end, not a new failure.
async fn request_fda_prompt(client: &super::approver::ApproverClient) {
    let request_id = mint_approver_request_id();
    match client
        .notify_fda_prompt(request_id, FDA_PROMPT_SEND_TIMEOUT)
        .await
    {
        Ok(()) => eprintln!(
            "cache-warden: full disk access: asked the approver helper to explain how to grant it"
        ),
        Err(e) => eprintln!(
            "cache-warden: warning: could not show the Full Disk Access explainer ({e}); \
             macOS will keep asking for permission on every `op` launch until it is granted"
        ),
    }
}

/// The set of signals that request a graceful daemon shutdown.
#[cfg(unix)]
const SHUTDOWN_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// How long the shutdown watchdog ([`spawn_shutdown_notifier`]) waits for the
/// graceful shutdown to complete before forcing `_exit`. Generous relative to
/// the sub-millisecond graceful path (so an only-moderately-loaded host still
/// shuts down cleanly), but short enough that a stop request is always honoured
/// promptly and well within a service manager's own SIGTERM→SIGKILL window.
#[cfg(unix)]
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a graceful restart waits for in-flight connections to finish
/// before its accept loop stops and its listeners close (DR-0029 §4). A
/// connection still open past this deadline is simply cut when this process
/// later `execve`s — accepted, not treated as a failure.
const RESTART_DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Build a `sigset_t` containing the [`SHUTDOWN_SIGNALS`].
#[cfg(unix)]
fn shutdown_sigset() -> libc::sigset_t {
    // SAFETY: `sigemptyset` / `sigaddset` initialise and populate a `sigset_t` we
    // own exclusively for the duration of these calls; no other memory is touched.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in SHUTDOWN_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
        set
    }
}

/// Block the shutdown signals (SIGINT / SIGTERM) in the calling thread so they
/// can be delivered *synchronously* via [`wait_for_shutdown`]'s `sigwait` thread
/// instead of through an asynchronous handler.
///
/// **Call this before the tokio runtime is built** (see `daemon_cmd`): a thread
/// that spawns children passes its signal mask on to them, so blocking on the
/// main thread first means every runtime worker — and the dedicated `sigwait`
/// thread — inherits the block. Any thread that does *not* block these signals
/// could take one via the kernel's default disposition and kill the process
/// before the cleanup path runs.
///
/// Design rationale: we deliberately avoid `tokio::signal` here. On macOS,
/// `ptrace(PT_DENY_ATTACH)` (the [`hardening::deny_debugger_attach`] layer,
/// DR-0007) makes tokio's asynchronous signal driver miss SIGTERM — the daemon
/// is then killed by the default disposition without removing its control socket
/// (regression covered by the `full_lifecycle_over_control_socket` e2e test). A
/// `sigwait`-on-a-dedicated-thread design is a synchronous kernel call that does
/// not depend on the async driver at all, so it is immune to the interaction —
/// and it has no startup race (blocking happens before the socket is even bound).
///
/// [`hardening::deny_debugger_attach`]: super::hardening::deny_debugger_attach
///
/// Returns `true` if the mask was updated, `false` if the libc call refused
/// (near-impossible for a valid signal set; the caller decides whether to warn).
#[cfg(unix)]
pub fn block_shutdown_signals() -> bool {
    let set = shutdown_sigset();
    // SAFETY: `pthread_sigmask` reads the `sigset_t` we own and updates only the
    // calling thread's signal mask; no memory we own is mutated.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    rc == 0
}

/// Unblock the shutdown signals (SIGINT / SIGTERM) in the calling thread,
/// restoring the kernel's default "terminate" disposition.
///
/// Used only on the degraded fallback path in [`wait_for_shutdown`]: if the
/// dedicated `sigwait` thread could not be spawned, the process would otherwise
/// be left with the signals blocked and *no* consumer — i.e. unkillable by
/// SIGINT/SIGTERM. Unblocking hands shutdown back to the OS default disposition
/// (an abrupt, cleanup-less termination, but reliably killable) rather than
/// relying on tokio's async signal driver, which is the very thing that is
/// broken on macOS under `ptrace(PT_DENY_ATTACH)` (see [`block_shutdown_signals`]).
#[cfg(unix)]
fn unblock_shutdown_signals() {
    let set = shutdown_sigset();
    // SAFETY: as in `block_shutdown_signals`, but unblocking.
    unsafe {
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

/// Spawn the dedicated thread that waits (synchronously, via `sigwait`) for a
/// shutdown signal and latches a [`tokio::sync::Notify`] when one arrives.
///
/// Call this *early* in [`run`], before the startup work, so a signal that
/// arrives during startup is consumed immediately (the signals are blocked
/// process-wide by [`block_shutdown_signals`], so until something `sigwait`s
/// them they only accumulate as pending — they are never lost, but nothing acts
/// on them). The returned `Notify` stores one permit, so an early signal is
/// observed the moment [`run`] reaches its `notified().await`.
///
/// We use a dedicated std thread + `sigwait` rather than `tokio::signal` because
/// tokio's asynchronous signal driver is unreliable on macOS once
/// `ptrace(PT_DENY_ATTACH)` has run (see [`block_shutdown_signals`]); `sigwait`
/// is a synchronous kernel call that does not depend on that driver.
///
/// Returns `None` if the thread could not be spawned (extremely unlikely), in
/// which case [`wait_for_shutdown`] falls back to tokio's async `ctrl_c`.
///
/// After delivering the notification the thread also arms a **shutdown
/// watchdog**: if the process has not exited within [`SHUTDOWN_GRACE`] it unlinks
/// the control socket and forces termination with `_exit`. The async graceful
/// path (flip `shutdown_tx`, drain the accept loop, unlink the sockets) normally
/// completes in well under a millisecond, so the watchdog never fires in
/// practice. It exists to bound the shutdown latency unconditionally: because
/// the shutdown signals are blocked process-wide, the kernel's default
/// "terminate" disposition no longer acts as a backstop, so a daemon wedged
/// mid-shutdown (or starved before it can drive the async shutdown to
/// completion) would otherwise never exit. The watchdog restores the guarantee
/// that a SIGINT/SIGTERM always stops the daemon promptly — and unlinks the
/// control socket first so the forced path still leaves a clean filesystem (any
/// `[authsock.sockets.*]` files rely on the next start's stale-socket recovery,
/// DR-0009).
///
/// `control_socket` is the path to remove on the forced path.
#[cfg(unix)]
fn spawn_shutdown_notifier(control_socket: PathBuf) -> Option<std::sync::Arc<tokio::sync::Notify>> {
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let signalled = std::sync::Arc::clone(&notify);
    let spawned = std::thread::Builder::new()
        .name("cw-signal".to_owned())
        .spawn(move || {
            // Re-assert the block locally: `sigwait`'s contract requires the
            // waited-for signals to be blocked in the calling thread (they are
            // already, via inheritance, but being explicit is robust to how this
            // thread happens to be spawned).
            let _ = block_shutdown_signals();
            let set = shutdown_sigset();
            let mut sig: libc::c_int = 0;
            // Loop until `sigwait` reports a real delivery. It returns 0 on
            // success; on a spurious non-zero return we must NOT fall through and
            // notify (that would trigger shutdown without a signal). With our
            // fixed, valid signal set a non-zero return is not expected, so this
            // simply re-arms rather than acting on a phantom signal.
            loop {
                // SAFETY: `sigwait` reads the `sigset_t` we own and writes the
                // delivered signal number into `sig`, which we own. It blocks
                // until one of the (process-wide blocked) shutdown signals fires.
                let rc = unsafe { libc::sigwait(&set, &mut sig) };
                if rc == 0 {
                    break;
                }
            }
            signalled.notify_one();
            // Watchdog: bound the shutdown latency. If the graceful path has not
            // finished (i.e. the whole process has not exited) within the grace
            // window, clean up the control socket and force termination. If
            // graceful shutdown completes first the process exits and this thread
            // is torn down before the sleep returns, so the lines below are only
            // ever reached on a wedged/starved shutdown.
            std::thread::sleep(SHUTDOWN_GRACE);
            eprintln!(
                "cache-warden: graceful shutdown did not finish within {}s of the \
                 stop signal; forcing exit",
                SHUTDOWN_GRACE.as_secs()
            );
            let _ = std::fs::remove_file(&control_socket);
            // SAFETY: `_exit` takes no pointers and simply terminates the process.
            // Exit 0: a SIGINT/SIGTERM-initiated stop is an intentional shutdown,
            // so we report success (the warning above is the observability hook).
            unsafe { libc::_exit(0) };
        });
    match spawned {
        Ok(_) => Some(notify),
        Err(e) => {
            eprintln!(
                "cache-warden: warning: could not start signal thread ({e}); falling back to async Ctrl+C handling"
            );
            None
        }
    }
}

/// Wait for a shutdown signal: await the notifier installed by
/// [`spawn_shutdown_notifier`].
///
/// `None` means the `sigwait` thread could not be spawned. The signals are still
/// blocked process-wide (from before the runtime started), so there is no async
/// consumer left — we must *unblock* them to hand shutdown back to the kernel's
/// default disposition, then park. We do **not** await `tokio::signal::ctrl_c`
/// here: installing a tokio SIGINT handler would re-disarm the default
/// disposition and route through the async driver that is unreliable under
/// `ptrace(PT_DENY_ATTACH)` — the exact failure this whole design avoids. After
/// unblocking, an abrupt OS terminate is the (degraded but reliable) outcome.
#[cfg(unix)]
async fn wait_for_shutdown(notify: Option<std::sync::Arc<tokio::sync::Notify>>) {
    match notify {
        Some(notify) => notify.notified().await,
        None => {
            unblock_shutdown_signals();
            // Park forever; the unblocked SIGINT/SIGTERM now terminate the
            // process via the kernel default disposition.
            std::future::pending::<()>().await;
        }
    }
}

/// Wait for Ctrl+C on non-Unix platforms.
#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wire::{OkPayload, SetSource};
    use crate::protocol::{decode_b64, encode_b64};
    use tempfile::tempdir;

    fn shared() -> Arc<Shared> {
        let bundle = cache_warden::StoreBuilder::new().build();
        let otp_adapter = crate::daemon::otp_adapter::OtpAdapter::new(bundle.otp_cap);
        Arc::new(Shared {
            store: Arc::new(Mutex::new(bundle.store)),
            control_cap: bundle.control_cap,
            authsock_cap: bundle.authsock_cap,
            otp_adapter,
            ceremony: None,
            ceremony_addr: std::sync::OnceLock::new(),
            owner_verifier: Arc::new(crate::daemon::owner_eval::CodeSignatureVerifier),
            runner: CommandRunner::new(),
            auth: Box::new(AllowAll),
            clock: SystemClock::new(),
            persist: std::sync::OnceLock::new(),
            socket_path: "/tmp/test.sock".into(),
            pid: std::process::id(),
            kv_process_policies: std::collections::BTreeMap::new(),
            vault: None,
            persisted_keys: std::collections::BTreeSet::new(),
            kv_policy: crate::config::ResolvedKvPolicy {
                default_require_same_user: false,
                shell_names: crate::config::default_shell_names(),
            },
            exe_path: PathBuf::new(),
            argv: Vec::new(),
            restart: graceful_restart::RestartCoordinator::new(),
            active_connections: ConnectionTracker::new(),
            approver: ApproverSlot::new_down(),
            fda_applicable: false,
        })
    }

    // ---- DR-0031 §8 approver-dialog integration ----

    use super::super::approver_wire::FakeApprover;
    use super::super::guard::{GetterAuditToken, GetterProcess};
    use cache_warden::{
        DeclaredAncestor, GuardConstraint, GuardRecord, GuardSetter, ProcessInfo, ValueSource,
    };
    use cache_warden_approver::wire::Outcome as WireOutcomeT;

    /// Build a `Shared` whose `approver` slot is already `Ready` with a
    /// deterministic fake — the state a well-behaved production daemon
    /// reaches once helper spawn + verification succeed.
    fn shared_with_fake_approver(outcome: WireOutcomeT) -> Arc<Shared> {
        let s = shared();
        s.approver.set_ready(Arc::new(FakeApprover::new(outcome)));
        s
    }

    // ---- approval coalescing (issue 2026-07-12-approver-release-hardening) ----

    /// An approver that parks every call until the test hands out permits,
    /// so several approvals can be in flight at once and the test can see
    /// exactly how many dialogs were actually raised.
    struct ParkingApprover {
        calls: std::sync::atomic::AtomicUsize,
        release: tokio::sync::Semaphore,
        outcome: WireOutcomeT,
    }

    impl ParkingApprover {
        fn new(outcome: WireOutcomeT) -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                release: tokio::sync::Semaphore::new(0),
                outcome,
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl super::super::approver_wire::Approver for ParkingApprover {
        fn request<'a>(
            &'a self,
            request: cache_warden_approver::wire::ApproveRequest,
            _timeout: Duration,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = io::Result<cache_warden_approver::wire::ApproveResponse>,
                    > + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                let permit = self.release.acquire().await.expect("semaphore open");
                permit.forget();
                Ok(cache_warden_approver::wire::ApproveResponse {
                    v: cache_warden_approver::wire::WIRE_VERSION,
                    request_id: request.request_id,
                    outcome: self.outcome,
                    biometric_kind: None,
                })
            })
        }
        fn shutdown<'a>(
            &'a self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async {})
        }
    }

    /// A wire request with the identity fields coalescing keys on. Every
    /// other field (notably `request_id`) is incidental — two requests that
    /// ask the same question differ in their ids, which is precisely why the
    /// id must not be part of the key.
    fn coalesce_request(
        request_id: &str,
        key: &str,
        operation: &str,
        pid: u32,
    ) -> cache_warden_approver::wire::ApproveRequest {
        use cache_warden_approver::wire::{AuditToken, Requester};
        cache_warden_approver::wire::ApproveRequest {
            v: cache_warden_approver::wire::WIRE_VERSION,
            request_id: request_id.to_string(),
            key: key.to_string(),
            operation: operation.to_string(),
            requester: Requester {
                chain: vec![],
                audit_token: AuditToken {
                    euid: 501,
                    ruid: 501,
                    egid: 20,
                    pid,
                    pid_version: 1,
                },
                responsible_bundle_id: None,
            },
            guard_eval: None,
            timeout_secs: 60,
        }
    }

    /// Spin (yielding, never sleeping) until `cond` holds.
    async fn until<F: Fn() -> bool>(cond: F) {
        for _ in 0..10_000 {
            if cond() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("condition never became true");
    }

    /// A duplicate of an approval already on screen joins it instead of
    /// raising a second dialog, and both callers get the same answer.
    ///
    /// This is what makes ssh survivable: it sends a SIGN per key and
    /// retries, so without coalescing one guarded key marches a queue of
    /// identical prompts across the screen. Checked for an approval *and* a
    /// refusal — the shared answer is whatever the leader got, not just the
    /// happy path.
    #[tokio::test]
    async fn duplicate_requests_join_one_dialog_and_share_its_answer() {
        for outcome in [WireOutcomeT::Approved, WireOutcomeT::Cancelled] {
            let slot = Arc::new(ApproverSlot::new_starting());
            let approver = Arc::new(ParkingApprover::new(outcome));
            slot.set_ready(Arc::clone(&approver) as Arc<dyn super::super::approver_wire::Approver>);

            let leader = {
                let slot = Arc::clone(&slot);
                tokio::spawn(async move {
                    slot.await_dialog_outcome(
                        coalesce_request("first", "default/K", "sign", 4242),
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )
                    .await
                })
            };
            // The leader is inside the dialog once the approver has been
            // called; only then can a second request find it in flight.
            until(|| approver.calls() == 1).await;

            let follower = {
                let slot = Arc::clone(&slot);
                tokio::spawn(async move {
                    slot.await_dialog_outcome(
                        coalesce_request("second", "default/K", "sign", 4242),
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )
                    .await
                })
            };
            // Wait until the follower has actually subscribed (observable as
            // a receiver on the leader's broadcast channel), so releasing the
            // dialog below cannot outrun it.
            until(|| {
                slot.inflight
                    .lock()
                    .unwrap()
                    .values()
                    .any(|tx| tx.receiver_count() > 0)
            })
            .await;

            approver.release.add_permits(1);
            let (a, b) = (
                leader.await.expect("leader task"),
                follower.await.expect("follower task"),
            );

            assert_eq!(
                approver.calls(),
                1,
                "the duplicate must not have raised a second dialog"
            );
            let expected = match outcome {
                WireOutcomeT::Approved => "approved",
                _ => "approval cancelled",
            };
            assert_eq!(a.label(), expected, "leader outcome");
            assert_eq!(b.label(), expected, "follower must get the leader's answer");

            // The question is retired once answered: a later request for the
            // same thing is a new ask and must raise its own prompt.
            assert!(
                slot.inflight.lock().unwrap().is_empty(),
                "the in-flight entry must be gone once the answer is out"
            );
        }
    }

    /// Different entry, different operation, different process — each is a
    /// different question and gets its own prompt. Coalescing that collapsed
    /// any of these would answer something the user was never asked.
    #[tokio::test]
    async fn different_key_operation_or_requester_do_not_join() {
        let slot = Arc::new(ApproverSlot::new_starting());
        let approver = Arc::new(ParkingApprover::new(WireOutcomeT::Approved));
        slot.set_ready(Arc::clone(&approver) as Arc<dyn super::super::approver_wire::Approver>);

        let variants = [
            ("r1", "default/K", "get", 4242u32),
            // same requester + operation, other entry
            ("r2", "default/OTHER", "get", 4242),
            // same requester + entry, other operation
            ("r3", "default/K", "sign", 4242),
            // same entry + operation, other process
            ("r4", "default/K", "get", 9999),
        ];
        let mut tasks = Vec::new();
        for (id, key, op, pid) in variants {
            let slot = Arc::clone(&slot);
            tasks.push(tokio::spawn(async move {
                slot.await_dialog_outcome(
                    coalesce_request(id, key, op, pid),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await
            }));
        }

        // All four must reach the approver — none of them joined another.
        until(|| approver.calls() == variants.len()).await;
        approver.release.add_permits(variants.len());
        for t in tasks {
            assert_eq!(t.await.expect("task").label(), "approved");
        }
        assert_eq!(approver.calls(), variants.len());
    }

    /// A requester the daemon could not identify (no usable pid on the audit
    /// token) is never coalesced: with no identity there is no way to tell
    /// two callers apart, and a shared answer could hand one caller's
    /// approval to another. Separate prompts are the conservative failure.
    #[tokio::test]
    async fn unidentifiable_requesters_are_never_coalesced() {
        let slot = Arc::new(ApproverSlot::new_starting());
        let approver = Arc::new(ParkingApprover::new(WireOutcomeT::Approved));
        slot.set_ready(Arc::clone(&approver) as Arc<dyn super::super::approver_wire::Approver>);

        let mut tasks = Vec::new();
        for id in ["a", "b"] {
            let slot = Arc::clone(&slot);
            tasks.push(tokio::spawn(async move {
                // pid 0 = "no identity resolved" on this wire.
                slot.await_dialog_outcome(
                    coalesce_request(id, "default/K", "get", 0),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .await
            }));
        }
        until(|| approver.calls() == 2).await;
        approver.release.add_permits(2);
        for t in tasks {
            assert_eq!(t.await.expect("task").label(), "approved");
        }
        assert!(
            slot.inflight.lock().unwrap().is_empty(),
            "unidentifiable requests must not register an in-flight entry"
        );
    }

    /// Seat a guarded value directly on the shared store, side-stepping the
    /// `handle_set` guard-plan machinery (which requires a live audit
    /// token). The record here declares `SameUser(501, 501)`.
    fn seed_guarded_value(shared: &Arc<Shared>, key: &str, value: &[u8]) {
        let mut store = shared.store.lock().unwrap();
        store
            .set(
                key.to_string(),
                ValueSource::Static,
                cache_warden::SecretBytes::new(value.to_vec()),
                cache_warden::Ttl::never(),
                &shared.control_cap,
                &shared.clock,
            )
            .expect("seed value");
        let record = GuardRecord::new(
            vec![GuardConstraint::SameUser],
            GuardSetter {
                euid: 501,
                ruid: 501,
            },
        );
        store
            .set_guard(key.to_string(), record, &shared.control_cap)
            .expect("seed guard");
    }

    /// Same as [`seed_guarded_value`] but installs a `same-ancestor` pin so
    /// the getter must match a specific pid+start_time in its chain.
    fn seed_guarded_value_with_ancestor_pin(shared: &Arc<Shared>, key: &str, value: &[u8]) {
        let mut store = shared.store.lock().unwrap();
        store
            .set(
                key.to_string(),
                ValueSource::Static,
                cache_warden::SecretBytes::new(value.to_vec()),
                cache_warden::Ttl::never(),
                &shared.control_cap,
                &shared.clock,
            )
            .expect("seed value");
        let record = GuardRecord::new(
            vec![GuardConstraint::SameAncestor {
                declared: DeclaredAncestor::Named {
                    name: "zsh".to_string(),
                },
                pinned: cache_warden::PinnedProcess {
                    pid: 50,
                    start_time: Some(Duration::from_secs(1)),
                    unique_id: None,
                    path: PathBuf::from("/bin/zsh"),
                    name: "zsh".to_string(),
                },
            }],
            GuardSetter {
                euid: 501,
                ruid: 501,
            },
        );
        store
            .set_guard(key.to_string(), record, &shared.control_cap)
            .expect("seed guard");
    }

    fn same_user_token() -> Option<GetterAuditToken> {
        Some(GetterAuditToken {
            euid: 501,
            ruid: 501,
        })
    }

    /// The euid/ruid of the running test process. Guarded-value fixtures
    /// that intend to *match* the real chain walk from `std::process::id()`
    /// must seed their `GuardSetter` with this uid (not the hard-coded
    /// `501` from [`seed_guarded_value`], which was fine for pure
    /// first-pass unit tests but fails the SameUser check against a
    /// real audit token derived here).
    fn current_uid() -> u32 {
        // SAFETY: `geteuid()` takes no pointer arguments and cannot fail
        // per POSIX.
        unsafe { libc::geteuid() }
    }

    /// A [`GetterAuditToken`] matching the running test process's uid,
    /// suitable for feeding `run_request_async`'s `peer_token` parameter
    /// on tests that seed guards with [`seed_guarded_value_current_uid`].
    fn current_uid_token() -> Option<GetterAuditToken> {
        Some(GetterAuditToken {
            euid: current_uid(),
            ruid: current_uid(),
        })
    }

    /// Same as [`seed_guarded_value`] but with a `GuardSetter` bound to
    /// the *current* process's uid so `guard_eval::evaluate` can accept
    /// a real audit token derived from the running test process (via
    /// `run_request_async`'s peer path). Used by end-to-end tests that
    /// need first-pass to *succeed* and the dialog to actually fire.
    fn seed_guarded_value_current_uid(shared: &Arc<Shared>, key: &str, value: &[u8]) {
        let mut store = shared.store.lock().unwrap();
        store
            .set(
                key.to_string(),
                ValueSource::Static,
                cache_warden::SecretBytes::new(value.to_vec()),
                cache_warden::Ttl::never(),
                &shared.control_cap,
                &shared.clock,
            )
            .expect("seed value");
        let uid = current_uid();
        let record = GuardRecord::new(
            vec![GuardConstraint::SameUser],
            GuardSetter {
                euid: uid,
                ruid: uid,
            },
        );
        store
            .set_guard(key.to_string(), record, &shared.control_cap)
            .expect("seed guard");
    }

    fn zsh_chain() -> Option<Vec<GetterProcess>> {
        Some(vec![GetterProcess {
            info: ProcessInfo {
                pid: 50,
                ppid: Some(1),
                path: Some(PathBuf::from("/bin/zsh")),
                start_time: Some(Duration::from_secs(1)),
            },
            unique_id: None,
        }])
    }

    /// An unguarded reveal-get takes the fast branch inside
    /// `guarded_get_first_pass`: the whole handler runs (returning the
    /// value directly), so a downstream caller (the async gated flow) can
    /// bypass the dialog. Pin this shape so a future refactor cannot slip
    /// an unguarded get past a `NeedsApproval` return.
    #[test]
    fn first_pass_unguarded_returns_direct_success_response() {
        let s = shared();
        assert!(
            run_request(
                &s,
                None,
                None,
                None,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: None,
                    hard_ttl_secs: None,
                    guard_constraints: Vec::new(),
                    expected_version: None,
                    claim_token: None,
                    persist: None,
                    signed_by: None,
                },
            )
            .is_ok()
        );
        let result =
            guarded_get_first_pass(&s, None, None, None, None, None, "default/K".to_string());
        match result {
            GuardedGetFirstPass::Direct(Response::Ok(ok)) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    assert_eq!(decode_b64(&value_b64).unwrap(), b"v")
                }
                other => panic!("expected Get payload, got {other:?}"),
            },
            other => panic!("expected Direct(Ok(Get)), got a different shape: {other:?}"),
        }
    }

    /// A guarded reveal-get whose guard evaluation *passes* returns
    /// `NeedsApproval` (not the value). The dialog must be shown before
    /// the get proceeds — a `Direct(Ok(Get))` here would be a silent
    /// bypass of DR-0031's whole gate.
    #[test]
    fn first_pass_guarded_matching_returns_needs_approval_not_the_value() {
        let s = shared();
        seed_guarded_value(&s, "default/K", b"secret");
        let result = guarded_get_first_pass(
            &s,
            None,
            same_user_token(),
            None,
            None,
            zsh_chain(),
            "default/K".to_string(),
        );
        match result {
            GuardedGetFirstPass::NeedsApproval { guard_eval, .. } => {
                assert_eq!(guard_eval.constraints.len(), 1);
                assert_eq!(guard_eval.constraints[0].kind, "same-user");
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    /// A guarded reveal-get whose guard denies returns
    /// `Direct(AuthFailed)` — the dialog must not fire on a denial (§Security:
    /// dialog exposure would leak that a *guard* denied vs a *policy* denied,
    /// and would let a rejected getter make the user click cancel repeatedly).
    #[test]
    fn first_pass_guarded_denied_returns_direct_auth_failed_without_approver() {
        let s = shared();
        seed_guarded_value(&s, "default/K", b"secret");
        let wrong_uid_token = Some(GetterAuditToken {
            euid: 999,
            ruid: 999,
        });
        let result = guarded_get_first_pass(
            &s,
            None,
            wrong_uid_token,
            None,
            None,
            zsh_chain(),
            "default/K".to_string(),
        );
        match result {
            GuardedGetFirstPass::Direct(Response::Err(e)) => {
                assert_eq!(e.error.kind, ErrorKind::AuthFailed);
                assert!(e.error.message.contains("same-user"));
            }
            other => panic!("expected Direct(AuthFailed), got {other:?}"),
        }
    }

    /// Missing chain on a guarded reveal-get: `MissingContext` denial —
    /// the DR-0030 fail-closed direction.
    #[test]
    fn first_pass_guarded_without_chain_is_missing_context() {
        let s = shared();
        seed_guarded_value(&s, "default/K", b"secret");
        let result = guarded_get_first_pass(
            &s,
            None,
            same_user_token(),
            None,
            None,
            None,
            "default/K".to_string(),
        );
        match result {
            GuardedGetFirstPass::Direct(Response::Err(e)) => {
                assert_eq!(e.error.kind, ErrorKind::AuthFailed);
                assert!(e.error.message.contains("missing-context"));
            }
            other => panic!("expected Direct(AuthFailed missing-context), got {other:?}"),
        }
    }

    /// The finalize-after-approval helper re-evaluates the guard record —
    /// if it still passes, the value is returned. This is the happy-path
    /// second pass.
    #[test]
    fn finalize_after_approval_returns_value_when_guard_still_passes() {
        let s = shared();
        seed_guarded_value(&s, "default/K", b"secret");
        let resp = guarded_get_finalize_after_approval(
            &s,
            None,
            same_user_token(),
            None,
            None,
            zsh_chain(),
            "default/K".to_string(),
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    assert_eq!(decode_b64(&value_b64).unwrap(), b"secret")
                }
                other => panic!("not Get: {other:?}"),
            },
            other => panic!("expected Ok(Get), got {other:?}"),
        }
    }

    /// Concurrent `kv.set` during the dialog can drop the guard entirely.
    /// The second pass then sees no record and the entry is unguarded —
    /// a plain get is safe.
    #[test]
    fn finalize_after_approval_passes_through_when_guard_disappeared() {
        let s = shared();
        seed_guarded_value(&s, "default/K", b"secret");
        // Simulate the concurrent unguarded overwrite.
        {
            let mut store = s.store.lock().unwrap();
            store
                .clear_guard("default/K", &s.control_cap)
                .expect("clear guard");
        }
        let resp = guarded_get_finalize_after_approval(
            &s,
            None,
            None,
            None, // no token needed once guard is gone
            None,
            None, // no chain needed either
            "default/K".to_string(),
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    assert_eq!(decode_b64(&value_b64).unwrap(), b"secret")
                }
                other => panic!("not Get: {other:?}"),
            },
            other => panic!("expected Ok(Get), got {other:?}"),
        }
    }

    /// The most important second-pass property: a guard *changed* while
    /// the human was deciding must fail-closed, not silently authorize a
    /// get the newly-installed record would have denied. Simulates a
    /// concurrent `kv.set --require-same-ancestor=...` that installs a
    /// pin the current getter's chain does not match.
    #[test]
    fn finalize_after_approval_fails_closed_when_guard_changed_to_a_denying_one() {
        let s = shared();
        // First pass: SameUser guard the current getter would satisfy.
        seed_guarded_value(&s, "default/K", b"secret");
        // Simulate the concurrent record replacement.
        {
            let mut store = s.store.lock().unwrap();
            let new_record = GuardRecord::new(
                vec![GuardConstraint::SameAncestor {
                    declared: DeclaredAncestor::Named { name: "zsh".into() },
                    pinned: cache_warden::PinnedProcess {
                        pid: 99, // pid NOT in the chain
                        start_time: Some(Duration::from_secs(1)),
                        unique_id: None,
                        path: PathBuf::from("/bin/zsh"),
                        name: "zsh".to_string(),
                    },
                }],
                GuardSetter {
                    euid: 501,
                    ruid: 501,
                },
            );
            store
                .set_guard("default/K".to_string(), new_record, &s.control_cap)
                .expect("replace record");
        }
        let resp = guarded_get_finalize_after_approval(
            &s,
            None,
            same_user_token(),
            None,
            None,
            zsh_chain(),
            "default/K".to_string(),
        );
        match resp {
            Response::Err(e) => {
                assert_eq!(e.error.kind, ErrorKind::AuthFailed);
                assert!(e.error.message.contains("same-ancestor"));
                assert!(e.error.message.contains("record changed"));
            }
            other => panic!("expected AuthFailed record-changed, got {other:?}"),
        }
        // Silence unused if the pin helper is not used by every case.
        let _ = seed_guarded_value_with_ancestor_pin as fn(&Arc<Shared>, &str, &[u8]);
    }

    /// End-to-end async: guard-less `kv.get` under a daemon whose approver
    /// is `Down` still succeeds — the §9 fallback promise that unguarded
    /// entries stay transparent even when the helper is unavailable.
    #[tokio::test]
    async fn helper_down_leaves_unguarded_get_transparent() {
        let s = shared(); // `new_down` slot by default
        // Set an unguarded value.
        assert!(
            run_request(
                &s,
                None,
                None,
                None,
                Request::KvSet {
                    key: "default/K".into(),
                    source: SetSource::Static {
                        value_b64: encode_b64(b"v"),
                    },
                    soft_ttl_secs: None,
                    hard_ttl_secs: None,
                    guard_constraints: Vec::new(),
                    expected_version: None,
                    claim_token: None,
                    persist: None,
                    signed_by: None,
                },
            )
            .is_ok()
        );
        let resp = run_request_async(
            &s,
            None,
            None,
            None,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        )
        .await;
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    assert_eq!(decode_b64(&value_b64).unwrap(), b"v")
                }
                other => panic!("not Get: {other:?}"),
            },
            other => panic!("expected Ok(Get), got {other:?}"),
        }
    }

    /// `ApproverSlot::wait_ready` must not lose a `set_ready` that lands
    /// **before** any waiter arms a `Notify` — the classic
    /// register-after-signal miss. Concretely: if the slot is already
    /// `Ready` at the moment `wait_ready` is called, it returns
    /// `Some(_)` immediately (the state check inside the loop catches
    /// it), and even if it fires between a hypothetical waiter's arm
    /// and its poll the pre-registration discipline
    /// (`notified.enable()` **before** the state check) still delivers
    /// the wake.
    ///
    /// Pins the fix for the timeout-branch "missed-notification race":
    /// without the pre-registration + timeout-side re-check, this
    /// `set_ready`-then-`wait_ready` sequence would time out on a bounded
    /// wait even though the slot was ready the whole time.
    #[tokio::test]
    async fn wait_ready_returns_immediately_when_slot_is_already_ready() {
        let slot = ApproverSlot::new_starting();
        slot.set_ready(Arc::new(FakeApprover::new(WireOutcomeT::Approved)));
        // A tight bounded wait: if the state check inside `wait_ready`
        // missed the already-set state we would hit the timeout branch
        // and (with the fix) still re-check + return `Some`; a
        // regression that skipped the re-check would return `None`.
        let got = tokio::time::timeout(
            Duration::from_millis(50),
            slot.wait_ready(Duration::from_millis(20)),
        )
        .await
        .expect("outer timeout must not fire — wait_ready should return promptly");
        assert!(
            got.is_some(),
            "wait_ready must observe an already-`Ready` slot even against a bounded timeout"
        );
    }

    /// End-to-end async: guarded reveal-get with a `Ready` approver
    /// returning `Approved` returns the seeded value. Pins the happy
    /// path of the dialog-outcome switch in `run_request_async`.
    ///
    /// macOS-only: same chain-walk dependency as
    /// [`helper_down_fails_guarded_reveal_get_closed`].
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn approved_outcome_returns_seeded_value_end_to_end() {
        let s = shared_with_fake_approver(WireOutcomeT::Approved);
        seed_guarded_value_current_uid(&s, "default/K", b"secret");
        let resp = run_request_async(
            &s,
            Some(std::process::id()),
            current_uid_token(),
            None,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        )
        .await;
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    assert_eq!(decode_b64(&value_b64).unwrap(), b"secret");
                }
                other => panic!("expected Get payload, got {other:?}"),
            },
            other => panic!("expected Ok(Get), got {other:?}"),
        }
    }

    /// Every non-`Approved` outcome surfaces as `AuthFailed`, and the
    /// message tells the client apart exactly two situations: a person
    /// declined, and nobody answered. Those call for opposite next moves
    /// (do not re-prompt vs. retry when someone is around), which is why
    /// they are worth distinguishing at all — see
    /// [`ApprovalOutcome::client_message`].
    ///
    /// Everything else is one indistinguishable denial on purpose: a client
    /// that could tell a failed fingerprint from a policy refusal could
    /// learn things about the user and the entry's guard by probing
    /// (DR-0030 §7). The precise outcome still reaches the daemon log.
    ///
    /// macOS-only: same chain-walk dependency as
    /// [`helper_down_fails_guarded_reveal_get_closed`].
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn client_sees_declined_and_timed_out_apart_but_every_other_denial_alike() {
        async fn message_for(outcome: WireOutcomeT) -> String {
            let s = shared_with_fake_approver(outcome);
            seed_guarded_value_current_uid(&s, "default/K", b"secret");
            let resp = run_request_async(
                &s,
                Some(std::process::id()),
                current_uid_token(),
                None,
                Request::KvGet {
                    key: "default/K".into(),
                    dry_run: false,
                },
            )
            .await;
            match resp {
                Response::Err(e) => {
                    assert_eq!(
                        e.error.kind,
                        ErrorKind::AuthFailed,
                        "outcome {outcome:?} must map to AuthFailed"
                    );
                    e.error.message
                }
                other => panic!("outcome {outcome:?} expected AuthFailed, got {other:?}"),
            }
        }

        let declined = message_for(WireOutcomeT::Cancelled).await;
        let timed_out = message_for(WireOutcomeT::Timeout).await;
        assert!(declined.contains("declined"), "{declined}");
        assert!(timed_out.contains("timed out"), "{timed_out}");
        assert_ne!(
            declined, timed_out,
            "declined and timed out must not read alike — they call for opposite next moves"
        );

        // The rolled-up denials: identical to each other, and carrying none
        // of the words that would give the distinction away.
        let mut rolled = Vec::new();
        for outcome in [
            WireOutcomeT::Denied,
            WireOutcomeT::PeerGone,
            WireOutcomeT::BiometricFailed,
        ] {
            let msg = message_for(outcome).await;
            for leak in [
                "biometric",
                "finger",
                "exited",
                "guard",
                "setter",
                "declined",
            ] {
                assert!(
                    !msg.to_lowercase().contains(leak),
                    "outcome {outcome:?} message leaks {leak:?}: {msg}"
                );
            }
            rolled.push(msg);
        }
        assert!(
            rolled.windows(2).all(|w| w[0] == w[1]),
            "every rolled-up denial must read identically, got {rolled:?}"
        );
        assert_ne!(rolled[0], declined);
        assert_ne!(rolled[0], timed_out);
    }

    /// End-to-end async: guarded reveal-get whose first-pass **passes**
    /// (real chain walk of `std::process::id()` + audit token matching the
    /// setter's uid) but hits a `Down` approver slot → AuthFailed with the
    /// "helper unavailable" message. This is the §9 `helper_down`
    /// fail-closed path for guarded gets, driven end-to-end rather than
    /// via the missing-context short-circuit (which never reaches the
    /// approver slot at all and therefore cannot pin the helper-unavailable
    /// message shape).
    ///
    /// macOS-only: the chain walk depends on `proc_pidinfo`; on Linux the
    /// ancestry call returns `Err(Unavailable)` and first-pass would fall
    /// through to missing-context, defeating the point of this test.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn helper_down_fails_guarded_reveal_get_closed() {
        let s = shared(); // `approver` slot defaults to `Down`.
        seed_guarded_value_current_uid(&s, "default/K", b"secret");
        let resp = run_request_async(
            &s,
            Some(std::process::id()),
            current_uid_token(),
            None,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        )
        .await;
        match resp {
            Response::Err(e) => {
                assert_eq!(e.error.kind, ErrorKind::AuthFailed);
                assert!(
                    e.error.message.contains("approver helper unavailable"),
                    "expected the helper-unavailable message, got {:?}",
                    e.error.message
                );
            }
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    /// `dry_run: true` never triggers the dialog even on a guarded entry:
    /// no value is returned to gate. Pins the DR-0031 §8 daemon-side
    /// resolution (the DR itself is silent on dry-run, so this is the
    /// place the semantics is *stated*).
    #[tokio::test]
    async fn dry_run_never_takes_the_gated_path() {
        // We install a guarded value, then issue a dry-run get. The
        // approver slot is `Down`, so if the gated path were taken this
        // would AuthFail. The dry-run path skips gating and the sync
        // handler denies with `missing-context` — which is fine: the
        // point of this test is that it does *not* hit
        // "approver helper unavailable", proving `run_request_async`
        // never entered the async gated branch on a dry-run.
        let s = shared();
        seed_guarded_value(&s, "default/K", b"secret");
        let resp = run_request_async(
            &s,
            None,
            None,
            None,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: true,
            },
        )
        .await;
        match resp {
            Response::Err(e) => {
                assert!(
                    !e.error.message.contains("approver"),
                    "dry_run must not reach the approver path: {}",
                    e.error.message
                );
            }
            Response::Ok(_) => {
                // Also acceptable — a dry-run passes the (sync) guard on
                // a chain-less denial only if the store side accepts it,
                // which the handler does not for a guarded entry, so
                // this branch is not expected. Fail loudly if it happens.
                panic!("dry_run on a guarded entry with no chain should have denied");
            }
        }
    }

    /// While a guarded reveal-get awaits the approver dialog, unrelated
    /// unguarded gets on the *same* daemon must proceed — the guarded
    /// flow drops the store lock in [`guarded_get_first_pass`] before
    /// returning `NeedsApproval`, so a multi-second human decision cannot
    /// queue every other request on this daemon behind it. Concurrent
    /// test: seed a guarded value the current process would satisfy, wire
    /// a `BlockingApprover` that signals a oneshot the instant the
    /// dialog `request` runs and then parks until released, launch the
    /// guarded get in a task, wait deterministically for that signal (no
    /// `sleep`-based "give it a moment"), run the unguarded get in the
    /// main task and assert it completes, then release the approver and
    /// verify the guarded get resolves to the approved value.
    ///
    /// macOS-only: same chain-walk dependency as
    /// [`helper_down_fails_guarded_reveal_get_closed`].
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn parallel_unguarded_get_progresses_while_gated_get_awaits_dialog() {
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
                            Output = io::Result<cache_warden_approver::wire::ApproveResponse>,
                        > + Send
                        + 'a,
                >,
            > {
                Box::pin(async move {
                    if let Some(tx) = self.entered.lock().await.take() {
                        let _ = tx.send(());
                    }
                    let rx = self.unblock.lock().await.take();
                    if let Some(rx) = rx {
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

        let s = shared();
        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (unblock_tx, unblock_rx) = oneshot::channel::<()>();
        s.approver.set_ready(Arc::new(BlockingApprover {
            entered: tokio::sync::Mutex::new(Some(entered_tx)),
            unblock: tokio::sync::Mutex::new(Some(unblock_rx)),
        }));

        // Seed one guarded value whose first-pass will pass for the
        // current process, plus one unguarded value.
        seed_guarded_value_current_uid(&s, "default/G", b"secret-guarded");
        {
            let mut store = s.store.lock().unwrap();
            store
                .set(
                    "default/U".to_string(),
                    ValueSource::Static,
                    cache_warden::SecretBytes::new(b"secret-unguarded".to_vec()),
                    cache_warden::Ttl::never(),
                    &s.control_cap,
                    &s.clock,
                )
                .unwrap();
        }

        // Kick off the guarded get in a task — it will pass first-pass
        // (real chain walk of this process + matching uid token) and
        // block inside the approver until we send `unblock`.
        let s_g = Arc::clone(&s);
        let guarded_handle = tokio::spawn(async move {
            run_request_async(
                &s_g,
                Some(std::process::id()),
                current_uid_token(),
                None,
                Request::KvGet {
                    key: "default/G".into(),
                    dry_run: false,
                },
            )
            .await
        });

        // Wait for the approver to prove it has entered its `request` —
        // now the guarded get is provably sitting on the dialog and the
        // store lock is released. No `sleep`-based fallback.
        entered_rx
            .await
            .expect("approver must enter `request` for the guarded get");

        // The unguarded get must complete while the guarded one is still
        // blocked on the (unreleased) approver.
        let unguarded = run_request_async(
            &s,
            None,
            None,
            None,
            Request::KvGet {
                key: "default/U".into(),
                dry_run: false,
            },
        )
        .await;
        assert!(
            unguarded.is_ok(),
            "unguarded get must complete while a guarded get is captive on the dialog, got {unguarded:?}"
        );
        assert!(
            !guarded_handle.is_finished(),
            "guarded get must still be pending on the blocking approver"
        );

        // Release the approver and verify the guarded get resolves to the
        // approved value.
        let _ = unblock_tx.send(());
        let guarded = guarded_handle.await.expect("guarded task must not panic");
        match guarded {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => {
                    assert_eq!(decode_b64(&value_b64).unwrap(), b"secret-guarded");
                }
                other => panic!("expected Get payload for guarded, got {other:?}"),
            },
            other => panic!("expected Ok(Get) for guarded, got {other:?}"),
        }
    }

    #[test]
    fn run_request_set_then_get() {
        let s = shared();
        let set = Request::KvSet {
            key: "default/K".into(),
            source: SetSource::Static {
                value_b64: encode_b64(b"v"),
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            guard_constraints: Vec::new(),
            expected_version: None,
            claim_token: None,
            persist: None,
            signed_by: None,
        };
        assert!(run_request(&s, None, None, None, set).is_ok());
        let resp = run_request(
            &s,
            None,
            None,
            None,
            Request::KvGet {
                key: "default/K".into(),
                dry_run: false,
            },
        );
        match resp {
            Response::Ok(ok) => match ok.payload {
                OkPayload::Get { value_b64 } => assert_eq!(decode_b64(&value_b64).unwrap(), b"v"),
                _ => panic!("not get"),
            },
            _ => panic!("expected ok"),
        }
    }

    #[test]
    fn dispatch_malformed_line_is_bad_request() {
        let s = shared();
        let resp = dispatch(&s, None, None, "{not json");
        match resp {
            Response::Err(e) => assert_eq!(e.error.kind, ErrorKind::BadRequest),
            _ => panic!("expected error"),
        }
    }

    // ---- daemon.restart_graceful dispatch (DR-0029 bundle 2) ----

    #[test]
    fn restart_graceful_without_a_resolvable_exe_path_is_aborted() {
        // The `shared()` test helper leaves `exe_path` empty (no real daemon
        // binary behind this test `Shared`) — the request must be cleanly
        // rejected rather than attempt anything, on every platform. On
        // macOS this exercises `verify_exec_target`'s own rejection (fails at
        // `File::open("")`, before ever reaching the codesign check); on
        // every other platform `graceful_restart::handle_request`'s
        // early guard rejects it before touching the store at all.
        let s = shared();
        let resp = run_request(&s, None, None, None, Request::RestartGraceful);
        match resp {
            Response::Err(e) => assert_eq!(e.error.kind, ErrorKind::RestartAborted),
            other => panic!("expected RestartAborted, got {other:?}"),
        }
    }

    // ---- build_authenticator (config -> Authenticator) ----

    #[test]
    fn build_authenticator_without_command_allows() {
        let cfg = Config::parse("").unwrap();
        let auth = build_authenticator(&cfg);
        assert!(
            auth.authenticate(&cache_warden::AuthContext::extend("K"))
                .is_ok()
        );
    }

    #[test]
    fn build_authenticator_with_failing_command_denies() {
        // `[auth].command = ["false"]` => CommandAuthenticator that always denies.
        let cfg = Config::parse("[auth]\ntype = \"command\"\ncommand = [\"false\"]\n").unwrap();
        let auth = build_authenticator(&cfg);
        assert_eq!(
            auth.authenticate(&cache_warden::AuthContext::extend("K")),
            Err(cache_warden::AuthError::Denied)
        );
    }

    #[test]
    fn build_authenticator_with_passing_command_allows() {
        let cfg = Config::parse("[auth]\ntype = \"command\"\ncommand = [\"true\"]\n").unwrap();
        let auth = build_authenticator(&cfg);
        assert!(
            auth.authenticate(&cache_warden::AuthContext::extend("K"))
                .is_ok()
        );
    }

    // ---- register_definitions (DR-0014 §4) ----

    /// An empty force-eager set (no authsock-referenced keys).
    fn no_eager() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    /// An empty `already_loaded` set (no graceful-restart handoff in play) —
    /// every pre-existing `register_definitions` test exercises the cold-start
    /// shape, where this is always empty (DR-0029 bundle 2).
    fn none_already_loaded() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    #[test]
    fn definition_without_preload_is_lazy_no_value_yet() {
        // Default (preload = false): the definition is registered but the
        // command is NOT run, so no value is resident until the first get.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "tok-value".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            preload: false,
            meta: Default::default(),
        }];
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        assert!(store.is_defined("default/TOK"), "definition registered");
        assert!(
            !store.has_value("default/TOK"),
            "value not produced eagerly (lazy)"
        );
    }

    #[test]
    fn definition_with_preload_runs_eagerly() {
        // preload = true keeps the old behaviour: run the command at startup so
        // the first get is a cache hit.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "tok-value".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: Some(3600),
            hard_ttl_secs: Some(86400),
            preload: true,
            meta: Default::default(),
        }];
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        let secret = store
            .get("default/TOK", &cap, &clock)
            .ok()
            .flatten()
            .expect("entry preloaded");
        secret.with_exposed(|b| assert_eq!(b, b"tok-value"));
    }

    #[test]
    fn authsock_referenced_key_is_eager_even_without_preload() {
        // A key listed in an `[authsock.sockets.*].keys` must be resident at
        // startup (the agent registry derives its public key then), so it is
        // force-eager regardless of `preload` — no second flag required.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![
            KvDefinition {
                name: "AGENT_KEY".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["printf".into(), "pem-bytes".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: false, // not preloaded by flag…
                meta: Default::default(),
            },
            KvDefinition {
                name: "OTHER".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["printf".into(), "other".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: false,
                meta: Default::default(),
            },
        ];
        let eager: std::collections::HashSet<String> =
            ["default/AGENT_KEY".to_string()].into_iter().collect();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &eager,
            &none_already_loaded(),
            &cap,
        );
        // …but the authsock reference forces it resident.
        store
            .get("default/AGENT_KEY", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| {
                assert_eq!(
                    b, b"pem-bytes",
                    "authsock-referenced key is eagerly materialized"
                )
            });
        // The unreferenced key stays lazy.
        assert!(store.is_defined("default/OTHER"));
        assert!(
            !store.has_value("default/OTHER"),
            "unreferenced key stays lazy"
        );
    }

    #[test]
    fn preload_failure_is_non_fatal_and_keeps_definition() {
        // A failed eager preload must not abort startup; the definition stays
        // registered (so a later get regenerates), and other entries still load.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![
            KvDefinition {
                name: "BAD".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["this-binary-does-not-exist-cw-preload".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: true,
                meta: Default::default(),
            },
            KvDefinition {
                name: "GOOD".into(),
                namespace: None,
                source: crate::protocol::wire::SourceSpecWire::Command {
                    command: crate::protocol::wire::CommandSpecWire {
                        argv: vec!["printf".into(), "ok".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                },
                soft_ttl_secs: None,
                hard_ttl_secs: None,
                preload: true,
                meta: Default::default(),
            },
        ];
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        // BAD's eager run failed, but its definition survives for regeneration.
        assert!(
            store.is_defined("default/BAD"),
            "definition kept after failed preload"
        );
        assert!(
            store
                .get("default/BAD", &cap, &clock)
                .ok()
                .flatten()
                .is_none(),
            "no value after failed preload"
        );
        store
            .get("default/GOOD", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| assert_eq!(b, b"ok", "subsequent preload still runs"));
    }

    #[test]
    fn authsock_forced_eager_failure_is_non_fatal_and_keeps_definition() {
        // The force-eager path shares the preload failure contract: warn,
        // continue, keep the definition (the agent socket simply starts without
        // that key until the upstream recovers).
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "AGENT_KEY".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["this-binary-does-not-exist-cw-preload".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: false,
            meta: Default::default(),
        }];
        let eager: std::collections::HashSet<String> =
            ["default/AGENT_KEY".to_string()].into_iter().collect();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &eager,
            &none_already_loaded(),
            &cap,
        );
        assert!(store.is_defined("default/AGENT_KEY"), "definition survives");
        assert!(
            !store.has_value("default/AGENT_KEY"),
            "no value after failed run"
        );
    }

    // ---- already_loaded (DR-0029 bundle 2: skip eager re-fetch on graceful restart) ----

    #[test]
    fn already_loaded_key_skips_eager_rerun_even_when_preload_is_true() {
        // Simulates a key that arrived with a value via a graceful-restart
        // handoff import (DR-0029 bundle 2), seeded directly via `store.set`
        // here rather than through a real import for test isolation.
        // `preload = true` must NOT re-run the source for it — doing so would
        // be exactly the re-fetch storm graceful restart exists to avoid.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "TOK".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "re-fetched-value".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: true,
            meta: Default::default(),
        }];
        store
            .set(
                "default/TOK".to_string(),
                cache_warden::ValueSource::Static,
                b"imported-value".to_vec().into(),
                cache_warden::Ttl::never(),
                &cap,
                &clock,
            )
            .unwrap();
        let already_loaded: std::collections::HashSet<String> =
            ["default/TOK".to_string()].into_iter().collect();

        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &no_eager(),
            &already_loaded,
            &cap,
        );

        store
            .get("default/TOK", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| {
                assert_eq!(
                    b, b"imported-value",
                    "already-loaded preload key must not be re-fetched"
                )
            });
    }

    #[test]
    fn already_loaded_key_skips_eager_rerun_for_force_eager_too() {
        // Same contract as the `preload` case above, but via the
        // authsock-referenced force-eager path.
        use cache_warden::FakeClock;
        let runner = CommandRunner::new();
        let clock = FakeClock::new();
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let entries = vec![KvDefinition {
            name: "AGENT_KEY".into(),
            namespace: None,
            source: crate::protocol::wire::SourceSpecWire::Command {
                command: crate::protocol::wire::CommandSpecWire {
                    argv: vec!["printf".into(), "re-fetched-pem".into()],
                    cwd: None,
                    env: Default::default(),
                },
            },
            soft_ttl_secs: None,
            hard_ttl_secs: None,
            preload: false,
            meta: Default::default(),
        }];
        store
            .set(
                "default/AGENT_KEY".to_string(),
                cache_warden::ValueSource::Static,
                b"imported-pem".to_vec().into(),
                cache_warden::Ttl::never(),
                &cap,
                &clock,
            )
            .unwrap();
        let eager: std::collections::HashSet<String> =
            ["default/AGENT_KEY".to_string()].into_iter().collect();
        let already_loaded = eager.clone();

        register_definitions(
            &mut store,
            &runner,
            &clock,
            &entries,
            &eager,
            &already_loaded,
            &cap,
        );

        store
            .get("default/AGENT_KEY", &cap, &clock)
            .ok()
            .flatten()
            .unwrap()
            .with_exposed(|b| {
                assert_eq!(
                    b, b"imported-pem",
                    "already-loaded force-eager key must not be re-fetched"
                )
            });
    }

    // ---- restore_persisted_definitions (config-priority merge; DR-0014 §4) ----

    fn cmd_src(argv: &[&str]) -> crate::protocol::wire::SourceSpecWire {
        use crate::protocol::wire::{CommandSpecWire, SourceSpecWire};
        SourceSpecWire::Command {
            command: CommandSpecWire {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
            },
        }
    }

    fn pdef(name: &str, argv: &[&str], soft: Option<u64>, hard: Option<u64>) -> KvDefinition {
        KvDefinition {
            name: name.into(),
            namespace: None,
            source: cmd_src(argv),
            soft_ttl_secs: soft,
            hard_ttl_secs: hard,
            preload: false,
            meta: Default::default(),
        }
    }

    #[test]
    fn restore_registers_keys_not_in_config() {
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        let config_names = std::collections::HashSet::new();
        restore_persisted_definitions(
            &mut store,
            vec![pdef("TOK", &["printf", "v"], Some(3600), Some(86400))],
            &config_names,
        );
        assert!(store.is_defined("default/TOK"), "persisted def restored");
        let d = store.definition_of("default/TOK").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["printf".to_string(), "v".to_string()]
        );
        assert_eq!(d.ttl().soft(), Some(std::time::Duration::from_secs(3600)));
    }

    #[test]
    fn restore_drops_persisted_key_that_config_already_defines() {
        // Config wins: a clashing persisted entry must not overwrite the config
        // definition, even if its argv differs.
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        let runner = CommandRunner::new();
        let clock = cache_warden::FakeClock::new();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &[pdef("DB", &["config-cmd"], None, None)],
            &no_eager(),
            &none_already_loaded(),
            &_cap,
        );
        let config_names: std::collections::HashSet<String> =
            ["default/DB".to_string()].into_iter().collect();
        // Persisted DB has a DIFFERENT argv; it must be dropped, not applied.
        restore_persisted_definitions(
            &mut store,
            vec![pdef("DB", &["persisted-cmd"], None, None)],
            &config_names,
        );
        let d = store.definition_of("default/DB").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["config-cmd".to_string()],
            "config definition wins the merge"
        );
    }

    // ---- clear_config_owned_definitions / purge_stale_import_definitions
    //      (DR-0029 bundle 2 review CRITICAL / HIGH-1 fixes) ----
    //
    // Symmetric to `restore_drops_persisted_key_that_config_already_defines`
    // above (config wins over a *persisted-file*-origin definition): these
    // cover config winning over an *import-origin* (graceful-restart
    // handoff) definition instead, the scenario `restore_persisted_definitions`
    // never had to handle because a persisted-file restore never carries a
    // co-resident value entry the way a handoff import does.

    #[test]
    fn clear_config_owned_definitions_lets_a_changed_config_definition_win_over_import() {
        // Simulate what a graceful-restart handoff import leaves behind:
        // a definition for `OLD` with the *old* argv/TTL, plus its cached
        // value already resident (imported wholesale, before either
        // `clear_config_owned_definitions` or `register_definitions` runs).
        let (mut store, cap) = cache_warden::test_helpers::store_with_cap();
        let clock = cache_warden::FakeClock::new();
        store
            .define_with_meta(
                "default/OLD",
                cmd_src(&["old-cmd"]).lower(),
                Ttl::new(None, Some(std::time::Duration::from_secs(3600))).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();
        store
            .set(
                "default/OLD",
                cmd_src(&["old-cmd"]).lower(),
                cache_warden::SecretBytes::new(b"cached-value".to_vec()),
                Ttl::new(None, Some(std::time::Duration::from_secs(3600))).unwrap(),
                &cap,
                &clock,
            )
            .unwrap();

        let config_names: std::collections::HashSet<String> =
            ["default/OLD".to_string()].into_iter().collect();
        clear_config_owned_definitions(&mut store, &config_names);

        // The definition is gone (cleared)...
        assert!(
            !store.is_defined("default/OLD"),
            "clear_config_owned_definitions must remove the import-origin definition"
        );
        // ...but the cached *value* must survive untouched.
        store
            .get("default/OLD", &cap, &clock)
            .ok()
            .flatten()
            .expect("value must still be present")
            .with_exposed(|b| assert_eq!(b, b"cached-value", "cached value must be undisturbed"));

        // register_definitions (the CRITICAL fix's actual caller) can now
        // insert the *new* config definition cleanly — no Conflict, even
        // though its argv differs from what was just cleared.
        let runner = CommandRunner::new();
        register_definitions(
            &mut store,
            &runner,
            &clock,
            &[pdef("OLD", &["new-cmd"], None, Some(10))],
            &no_eager(),
            &none_already_loaded(),
            &cap,
        );
        let d = store.definition_of("default/OLD").unwrap();
        assert_eq!(
            d.source().command_argv().unwrap(),
            &["new-cmd".to_string()],
            "the new config definition must win over the cleared import-origin one"
        );
        // The cached value is still untouched by register_definitions too
        // (it only registers definitions; it does not touch existing values
        // for keys not in `already_loaded`... this key already has a value,
        // but register_definitions never overwrites an existing value on a
        // non-eager entry).
        store
            .get("default/OLD", &cap, &clock)
            .ok()
            .flatten()
            .expect("value must still be present after register_definitions")
            .with_exposed(|b| assert_eq!(b, b"cached-value"));
    }

    #[test]
    fn purge_stale_import_definitions_removes_orphaned_config_removed_key_but_keeps_persisted_online_one()
     {
        // Two import-origin definitions land in the store (as a handoff
        // import would leave them): `REMOVED_FROM_CONFIG` (used to be a
        // config key in the *old* process, no longer is) and `STILL_ONLINE`
        // (a genuinely online definition, created via `kv.define` at
        // runtime, unrelated to any config).
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        store
            .define_with_meta(
                "default/REMOVED_FROM_CONFIG",
                cmd_src(&["stale-cmd"]).lower(),
                Ttl::new(None, None).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();
        store
            .define_with_meta(
                "default/STILL_ONLINE",
                cmd_src(&["online-cmd"]).lower(),
                Ttl::new(None, None).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();

        // The *current* config no longer mentions either key (both look
        // identical to the reconciliation logic at this point); only the
        // state file's own persisted names distinguish them.
        let config_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let persisted_names: std::collections::HashSet<String> =
            ["default/STILL_ONLINE".to_string()].into_iter().collect();

        let stale = purge_stale_import_definitions(&mut store, &config_names, &persisted_names);

        assert_eq!(
            stale,
            vec!["default/REMOVED_FROM_CONFIG".to_string()],
            "only the orphaned (config-removed, never-persisted) key must be purged"
        );
        assert!(
            !store.is_defined("default/REMOVED_FROM_CONFIG"),
            "the orphaned definition must actually be gone"
        );
        assert!(
            store.is_defined("default/STILL_ONLINE"),
            "a genuinely persisted online definition must survive the purge"
        );
    }

    #[test]
    fn purge_stale_import_definitions_keeps_current_config_keys() {
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        store
            .define_with_meta(
                "default/STILL_CONFIGURED",
                cmd_src(&["cmd"]).lower(),
                Ttl::new(None, None).unwrap(),
                cache_warden::ValueMeta::new(),
                cache_warden::SourceMeta::new(),
            )
            .unwrap();
        let config_names: std::collections::HashSet<String> =
            ["default/STILL_CONFIGURED".to_string()]
                .into_iter()
                .collect();
        let persisted_names = std::collections::HashSet::new();

        let stale = purge_stale_import_definitions(&mut store, &config_names, &persisted_names);

        assert!(
            stale.is_empty(),
            "a current config key must never be purged"
        );
        assert!(store.is_defined("default/STILL_CONFIGURED"));
    }

    #[test]
    fn restore_skips_bad_ttl_without_aborting_others() {
        let (mut store, _cap) = cache_warden::test_helpers::store_with_cap();
        let config_names = std::collections::HashSet::new();
        // First entry has soft > hard (invalid Ttl); it must be skipped while the
        // second still registers.
        restore_persisted_definitions(
            &mut store,
            vec![
                pdef("BAD", &["echo"], Some(100), Some(10)),
                pdef("GOOD", &["echo"], None, None),
            ],
            &config_names,
        );
        assert!(
            !store.is_defined("default/BAD"),
            "invalid TTL entry skipped"
        );
        assert!(
            store.is_defined("default/GOOD"),
            "subsequent entry still restored"
        );
    }

    #[tokio::test]
    async fn bind_detects_double_start() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let _l1 = bind_control_socket(&path).expect("first bind");
        // The first listener is live; a plain connect succeeds against it at the
        // kernel level, so the second bind must error AddrInUse.
        let err = bind_control_socket(&path).expect_err("second bind must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn bind_removes_stale_socket() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("control.sock");
        // A leftover regular file (not a live socket) simulates a stale path.
        std::fs::write(&path, b"stale").unwrap();
        // connect() to a regular file fails => treated as stale => removed+bound.
        let _l = bind_control_socket(&path).expect("should rebind over stale");
        assert!(path.exists());
    }

    #[tokio::test]
    async fn bind_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let _l = bind_control_socket(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
