//! Generic process inspection and ancestry walking.
//!
//! Process authentication (DESIGN-ja "プロセス認証", DR-0003/DR-0004) verifies a
//! requesting process by walking its parent chain toward `init`/`launchd`. This
//! module is the *generic* half of that: it answers "what is process N?" and
//! "what is the ancestry of process N?" and nothing more.
//!
//! # What lives here vs. an adapter
//!
//! Per DR-0004 the core holds only **generic process authentication** —
//! inspecting a pid and walking ancestry. The *policy interpretation* ("which
//! socket / which key may a given chain touch", allowed-process matching) belongs
//! to an adapter layer and is deliberately absent here: [`ProcessInfo`] exposes
//! the raw facts (pid / parent pid / executable path / start time) and a derived
//! [`ProcessInfo::name`], but no `matches`/`allowed` helpers.
//!
//! # The inspector trait
//!
//! [`ProcessInspector`] is the seam. Production code uses [`SystemInspector`]
//! (OS-backed, platform-specific); tests use [`FakeInspector`] to build arbitrary
//! process trees without touching the real OS. [`ProcessInspector::ancestry`] has
//! a default implementation built on [`ProcessInspector::inspect`], so a backend
//! only has to answer single-pid queries.
//!
//! # PID reuse
//!
//! A pid is recycled once the original process exits, so a pid alone does not
//! identify a process across time. [`ProcessInfo::start_time`] captures the
//! process start instant (where the OS exposes it) precisely so a caller can
//! detect reuse — a pid whose start time differs from a previously recorded one
//! is a *different* process. The core only records this fact; consuming it for
//! reuse checks is left to higher layers.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

/// Facts about a single process.
///
/// Only the fields the generic process-authentication core needs are kept:
/// the pid, its parent pid, the executable path, and the start time. User /
/// group ids, cwd and argv are intentionally omitted (they are display / policy
/// concerns for an adapter, not core authentication facts — see DR-0006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID, if known. `None` at the top of the tree
    /// (`init`/`launchd` reports parent `0`, which we normalize to `None`) or
    /// when the OS does not expose it.
    pub ppid: Option<u32>,
    /// Full path to the executable, if the OS could resolve it.
    pub path: Option<PathBuf>,
    /// Process start time, expressed as an offset since the system epoch
    /// (boot time on Linux, the Unix epoch on macOS), if available.
    ///
    /// The unit is opaque across platforms; only equality / comparison between
    /// two start times *of the same pid* is meaningful, and it exists for PID
    /// reuse detection (see the module docs).
    pub start_time: Option<Duration>,
}

impl ProcessInfo {
    /// The process name: the basename of [`ProcessInfo::path`], if any.
    ///
    /// Returns `None` when the executable path is unknown. This is a *derived*
    /// convenience; policy matching against it belongs to an adapter, not here.
    pub fn name(&self) -> Option<&str> {
        self.path.as_ref()?.file_name()?.to_str()
    }
}

/// Reason a [`ProcessInspector`] could not return information for a pid.
#[derive(Debug, PartialEq, Eq)]
pub enum InspectError {
    /// No process exists with the requested pid (or it exited before inspection).
    NotFound {
        /// The pid that could not be found.
        pid: u32,
    },
    /// The inspection mechanism was unavailable or errored out (permission
    /// denied, unsupported platform, OS API failure, ...).
    Unavailable {
        /// Human-readable detail. Must not contain secret material.
        message: String,
    },
}

impl InspectError {
    /// Construct an [`InspectError::Unavailable`] with a message.
    pub fn unavailable(message: impl Into<String>) -> Self {
        InspectError::Unavailable {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InspectError::NotFound { pid } => write!(f, "no such process: pid {pid}"),
            InspectError::Unavailable { message } => {
                write!(f, "process inspection unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for InspectError {}

/// Inspects processes and walks their ancestry.
///
/// Implementors only need to provide [`ProcessInspector::inspect`]; the default
/// [`ProcessInspector::ancestry`] builds the chain from it, with cycle and
/// runaway protection built in.
pub trait ProcessInspector {
    /// Look up a single process by pid.
    fn inspect(&self, pid: u32) -> Result<ProcessInfo, InspectError>;

    /// Walk the parent chain from `pid` toward `init`/`launchd`.
    ///
    /// The returned vector starts with `pid` itself and proceeds to each
    /// successive parent, stopping when:
    ///
    /// - a process reports no parent (`ppid == None`, e.g. `init`/`launchd`), or
    /// - a parent pid has already been visited (cycle guard — a corrupt or
    ///   racing process table could otherwise loop forever), or
    /// - a parent can no longer be inspected ([`InspectError::NotFound`], e.g. it
    ///   exited mid-walk): the chain collected so far is returned successfully.
    ///
    /// If the *starting* pid cannot be inspected, the error is propagated. A
    /// non-`NotFound` error while walking a parent (e.g. permission denied) is
    /// also propagated, since it signals the inspector itself is unhealthy
    /// rather than a benign race.
    ///
    /// Design rationale: stopping (rather than erroring) on a *parent* that
    /// vanished mid-walk reflects the reality that ancestry is a best-effort
    /// snapshot — the requesting process is alive, but its ancestors may exit at
    /// any moment.
    fn ancestry(&self, pid: u32) -> Result<Vec<ProcessInfo>, InspectError> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = Some(pid);

        while let Some(p) = current {
            // Cycle / kernel guard: a real tree never revisits a pid, and pid 0
            // is the kernel — stop rather than risk looping.
            if p == 0 || !visited.insert(p) {
                break;
            }
            let info = match self.inspect(p) {
                Ok(info) => info,
                // The first pid must exist; a parent vanishing mid-walk is a
                // benign race, so stop with what we have.
                Err(InspectError::NotFound { .. }) if !chain.is_empty() => break,
                Err(e) => return Err(e),
            };
            current = info.ppid;
            chain.push(info);
        }

        Ok(chain)
    }
}

impl<I: ProcessInspector + ?Sized> ProcessInspector for &I {
    fn inspect(&self, pid: u32) -> Result<ProcessInfo, InspectError> {
        (**self).inspect(pid)
    }
}

/// A test [`ProcessInspector`] over an in-memory process tree.
///
/// Build an arbitrary tree with [`FakeInspector::with`]; pids absent from the
/// tree report [`InspectError::NotFound`]. Lets tests drive ancestry walking,
/// cycle handling and missing-parent behaviour without the real OS.
#[derive(Debug, Default, Clone)]
pub struct FakeInspector {
    procs: std::collections::HashMap<u32, ProcessInfo>,
}

impl FakeInspector {
    /// An empty tree (every pid is [`InspectError::NotFound`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) a process in the tree.
    ///
    /// `path` becomes the executable path (so [`ProcessInfo::name`] works);
    /// `ppid` of `None` marks a tree root. Returns `self` for chaining.
    pub fn with(
        mut self,
        pid: u32,
        ppid: Option<u32>,
        path: impl Into<PathBuf>,
        start_time: Option<Duration>,
    ) -> Self {
        self.procs.insert(
            pid,
            ProcessInfo {
                pid,
                ppid,
                path: Some(path.into()),
                start_time,
            },
        );
        self
    }

    /// Insert a fully-specified [`ProcessInfo`] (e.g. one with no path).
    pub fn insert(mut self, info: ProcessInfo) -> Self {
        self.procs.insert(info.pid, info);
        self
    }
}

impl ProcessInspector for FakeInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessInfo, InspectError> {
        self.procs
            .get(&pid)
            .cloned()
            .ok_or(InspectError::NotFound { pid })
    }
}

/// OS-backed [`ProcessInspector`] for the host platform.
///
/// Backed by libc on macOS (`proc_pidpath` / `proc_pidinfo`) and by `/proc` on
/// Linux. On unsupported platforms every call reports
/// [`InspectError::Unavailable`]. See DR-0006 for the dependency rationale.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemInspector;

impl SystemInspector {
    /// Create a system inspector.
    pub fn new() -> Self {
        SystemInspector
    }
}

impl ProcessInspector for SystemInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessInfo, InspectError> {
        platform::inspect(pid)
    }
}

// --- platform backends ---

#[cfg(target_os = "macos")]
mod platform {
    use super::{InspectError, ProcessInfo};
    use std::ffi::CStr;
    use std::path::PathBuf;
    use std::time::Duration;

    pub(super) fn inspect(pid: u32) -> Result<ProcessInfo, InspectError> {
        // proc_bsdinfo gives ppid and start time and also tells us the process
        // exists; resolve the path separately (it may be unavailable for some
        // system processes even when the bsdinfo call succeeds).
        let bsd = bsd_info(pid)?;
        let path = exe_path(pid);
        Ok(ProcessInfo {
            pid,
            ppid: if bsd.ppid > 0 { Some(bsd.ppid) } else { None },
            path,
            start_time: bsd.start_time,
        })
    }

    struct Bsd {
        ppid: u32,
        start_time: Option<Duration>,
    }

    fn bsd_info(pid: u32) -> Result<Bsd, InspectError> {
        use std::mem;

        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                mem::size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        // proc_pidinfo returns the number of bytes written; a short / zero return
        // means the pid does not exist (or is not inspectable).
        if ret as usize != mem::size_of::<libc::proc_bsdinfo>() {
            return Err(InspectError::NotFound { pid });
        }
        // pbi_start_tvsec/_tvusec are the process start time as a wall-clock
        // (Unix epoch) timestamp; combine into a Duration since the epoch.
        let start_time = if info.pbi_start_tvsec > 0 {
            Some(
                Duration::from_secs(info.pbi_start_tvsec)
                    + Duration::from_micros(info.pbi_start_tvusec),
            )
        } else {
            None
        };
        Ok(Bsd {
            ppid: info.pbi_ppid,
            start_time,
        })
    }

    fn exe_path(pid: u32) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let ret = unsafe {
            libc::proc_pidpath(
                pid as i32,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as u32,
            )
        };
        if ret <= 0 {
            return None;
        }
        let c_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        let path = PathBuf::from(c_str.to_string_lossy().into_owned());
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{InspectError, ProcessInfo};
    use std::path::PathBuf;
    use std::time::Duration;

    pub(super) fn inspect(pid: u32) -> Result<ProcessInfo, InspectError> {
        // /proc/{pid}/stat is the authoritative "does this process exist" probe
        // here; if it is missing, the process does not exist.
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(InspectError::NotFound { pid });
            }
            Err(e) => {
                return Err(InspectError::unavailable(format!(
                    "read /proc/{pid}/stat: {e}"
                )));
            }
        };
        let (ppid, start_time) = parse_stat(&stat);
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        Ok(ProcessInfo {
            pid,
            ppid: ppid.filter(|&p| p > 0),
            path,
            start_time,
        })
    }

    /// Parse parent pid (field 4) and start time (field 22) out of a
    /// `/proc/{pid}/stat` line. The comm field (2) is parenthesized and may
    /// contain spaces / parentheses, so we split *after* the last `)`.
    fn parse_stat(stat: &str) -> (Option<u32>, Option<Duration>) {
        let after_comm = match stat.rfind(')') {
            Some(idx) => &stat[idx + 1..],
            None => return (None, None),
        };
        // After the comm, fields are: state(3) ppid(4) ... starttime(22).
        // Splitting the post-comm remainder, index 0 = state, so ppid is index 1
        // and starttime is index 19.
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let ppid = fields.get(1).and_then(|s| s.parse::<u32>().ok());
        let start_time = fields
            .get(19)
            .and_then(|s| s.parse::<u64>().ok())
            .and_then(ticks_to_duration);
        (ppid, start_time)
    }

    /// Convert a starttime in clock ticks (since boot) to a Duration.
    ///
    /// The unit only needs to be self-consistent for PID-reuse comparison, so we
    /// normalize ticks to a Duration using `_SC_CLK_TCK`.
    fn ticks_to_duration(ticks: u64) -> Option<Duration> {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            return None;
        }
        let hz = hz as u64;
        let secs = ticks / hz;
        let rem = ticks % hz;
        let nanos = (rem * 1_000_000_000) / hz;
        Some(Duration::new(secs, nanos as u32))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::{InspectError, ProcessInfo};

    pub(super) fn inspect(_pid: u32) -> Result<ProcessInfo, InspectError> {
        Err(InspectError::unavailable(
            "process inspection is not implemented on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_secs(pid: u32, ppid: Option<u32>, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            path: Some(PathBuf::from(format!("/usr/bin/{name}"))),
            start_time: Some(Duration::from_secs(pid as u64)),
        }
    }

    // --- ProcessInfo ---

    #[test]
    fn name_is_basename_of_path() {
        let info = path_secs(10, Some(1), "zsh");
        assert_eq!(info.name(), Some("zsh"));
    }

    #[test]
    fn name_is_none_without_path() {
        let info = ProcessInfo {
            pid: 10,
            ppid: Some(1),
            path: None,
            start_time: None,
        };
        assert_eq!(info.name(), None);
    }

    // --- InspectError ---

    #[test]
    fn inspect_error_displays_without_leaking() {
        assert!(
            InspectError::NotFound { pid: 4242 }
                .to_string()
                .contains("4242")
        );
        let u = InspectError::unavailable("permission denied");
        assert!(u.to_string().contains("permission denied"));
    }

    // --- FakeInspector / inspect ---

    #[test]
    fn fake_inspect_returns_known_process() {
        let insp = FakeInspector::new().with(100, Some(50), "/bin/ssh", None);
        let info = insp.inspect(100).unwrap();
        assert_eq!(info.pid, 100);
        assert_eq!(info.ppid, Some(50));
        assert_eq!(info.name(), Some("ssh"));
    }

    #[test]
    fn fake_inspect_unknown_pid_is_not_found() {
        let insp = FakeInspector::new();
        assert_eq!(insp.inspect(7), Err(InspectError::NotFound { pid: 7 }));
    }

    // --- ancestry (default impl over the trait) ---

    #[test]
    fn ancestry_walks_from_pid_to_root() {
        // 100 (ssh) -> 50 (git) -> 10 (zsh) -> 1 (launchd, no parent)
        let insp = FakeInspector::new()
            .with(100, Some(50), "/bin/ssh", None)
            .with(50, Some(10), "/bin/git", None)
            .with(10, Some(1), "/bin/zsh", None)
            .with(1, None, "/sbin/launchd", None);
        let chain = insp.ancestry(100).unwrap();
        let names: Vec<_> = chain.iter().map(|p| p.name().unwrap()).collect();
        assert_eq!(names, vec!["ssh", "git", "zsh", "launchd"]);
        // Starts with the requested pid.
        assert_eq!(chain[0].pid, 100);
    }

    #[test]
    fn ancestry_starting_pid_missing_propagates_error() {
        let insp = FakeInspector::new();
        assert_eq!(insp.ancestry(100), Err(InspectError::NotFound { pid: 100 }));
    }

    #[test]
    fn ancestry_stops_when_parent_vanished_mid_walk() {
        // 100 -> 50, but 50 is not in the tree (exited mid-walk). The chain
        // collected so far (just 100) is returned successfully.
        let insp = FakeInspector::new().with(100, Some(50), "/bin/ssh", None);
        let chain = insp.ancestry(100).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pid, 100);
    }

    #[test]
    fn ancestry_breaks_on_cycle() {
        // Corrupt tree: 10 -> 20 -> 10. Must not loop forever.
        let insp = FakeInspector::new()
            .with(10, Some(20), "/bin/a", None)
            .with(20, Some(10), "/bin/b", None);
        let chain = insp.ancestry(10).unwrap();
        // Visits 10 then 20, then 20's parent 10 is already visited -> stop.
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].pid, 10);
        assert_eq!(chain[1].pid, 20);
    }

    #[test]
    fn ancestry_stops_at_pid_zero_parent() {
        // launchd reports ppid 0 on macOS in some snapshots; treat 0 as kernel.
        let insp = FakeInspector::new().with(1, Some(0), "/sbin/launchd", None);
        let chain = insp.ancestry(1).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pid, 1);
    }

    #[test]
    fn ancestry_self_referential_root_does_not_loop() {
        // A process that claims itself as parent (pathological) must not loop.
        let insp = FakeInspector::new().with(5, Some(5), "/bin/x", None);
        let chain = insp.ancestry(5).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn inspector_works_through_reference() {
        let insp = FakeInspector::new().with(1, None, "/sbin/init", None);
        fn run(i: impl ProcessInspector) -> usize {
            i.ancestry(1).unwrap().len()
        }
        assert_eq!(run(&insp), 1);
    }

    // --- SystemInspector: real-OS tests ---
    //
    // These run against the live process table. They are written to work on any
    // host (assert structural facts, not specific process names) so they pass on
    // both the macOS dev machine and Linux CI.

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn system_inspect_self() {
        let insp = SystemInspector::new();
        let me = std::process::id();
        let info = insp.inspect(me).unwrap();
        assert_eq!(info.pid, me);
        // The current process always has a parent (the test runner / shell).
        assert!(info.ppid.is_some(), "self should have a parent pid");
        // Our own executable path resolves on both platforms.
        assert!(info.path.is_some(), "self should have an exe path");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn system_ancestry_self_walks_a_consistent_chain() {
        let insp = SystemInspector::new();
        let chain = insp.ancestry(std::process::id()).unwrap();
        // self + at least one ancestor (the chain is never just ourselves).
        assert!(
            chain.len() >= 2,
            "ancestry should include at least self and a parent, got {}",
            chain.len()
        );
        assert_eq!(chain[0].pid, std::process::id());
        // Each successive entry is the parent of the previous one — the walk
        // followed real parent links rather than fabricating a chain.
        for pair in chain.windows(2) {
            assert_eq!(
                pair[0].ppid,
                Some(pair[1].pid),
                "chain[n].ppid must equal chain[n+1].pid"
            );
        }
        // The walk terminates cleanly: either it reached a parentless root
        // (init / launchd) or it stopped at a process whose parent could no
        // longer be inspected. On macOS, proc_pidinfo cannot read the bsdinfo of
        // privileged ancestors (e.g. pid 1 launchd), so the chain legitimately
        // stops at a privilege boundary before pid 1 — and `ancestry` must still
        // return Ok with the chain collected so far (verified by the unwrap
        // above). We therefore assert termination, not full root reachability.
        let last = chain.last().unwrap();
        match last.ppid {
            // Reached a real root.
            None => {}
            // Stopped at a privilege boundary: the named parent must be one we
            // genuinely cannot inspect (otherwise the walk would have continued).
            Some(parent) => assert!(
                insp.inspect(parent).is_err(),
                "walk stopped at pid {} whose parent {} is inspectable — it should have continued",
                last.pid,
                parent
            ),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn system_inspect_nonexistent_pid_is_not_found() {
        let insp = SystemInspector::new();
        // pid 0 is the kernel; a very high pid is almost certainly unused.
        // Probe upward to find a definitely-absent pid, then assert NotFound.
        let mut probe = 4_000_000u32;
        while insp.inspect(probe).is_ok() {
            probe += 1;
        }
        assert_eq!(
            insp.inspect(probe),
            Err(InspectError::NotFound { pid: probe })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_inspect_init_has_no_parent() {
        // On Linux, /proc/1/stat is world-readable, so pid 1 (init) inspects
        // successfully and is the ancestry root: its parent is absent or pid 0
        // (kernel), which we normalize to None.
        let insp = SystemInspector::new();
        let info = insp.inspect(1).unwrap();
        assert_eq!(info.pid, 1);
        assert!(
            info.ppid.is_none(),
            "pid 1 should have no real parent, got {:?}",
            info.ppid
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_inspect_privileged_init_is_not_found() {
        // Empirically verified on macOS: proc_pidinfo(PROC_PIDTBSDINFO) for pid 1
        // (launchd) returns 0 bytes because an unprivileged process cannot read a
        // privileged process's bsdinfo. We surface that as NotFound (we cannot
        // distinguish "absent" from "not permitted" through this API), which is
        // why an ancestry walk legitimately stops at this boundary rather than
        // reaching pid 1. This test pins that observed behaviour.
        let insp = SystemInspector::new();
        assert_eq!(insp.inspect(1), Err(InspectError::NotFound { pid: 1 }));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn system_self_records_start_time() {
        // start_time is the PID-reuse signal; assert the OS actually exposes it
        // for our own live process.
        let insp = SystemInspector::new();
        let info = insp.inspect(std::process::id()).unwrap();
        assert!(
            info.start_time.is_some(),
            "self should expose a start time for reuse detection"
        );
    }
}
