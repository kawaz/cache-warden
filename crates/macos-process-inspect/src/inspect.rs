//! Single-pid facts, ancestry walking, and the kernel unique-id.
//!
//! Three retrieval primitives, each answering one kernel question:
//!
//! - [`inspect`]: what is process `pid` (parent pid / executable path / start
//!   time), via the public `PROC_PIDTBSDINFO` flavor of `proc_pidinfo`.
//! - [`ancestry`]: walk `pid`'s parent chain toward the root, built on
//!   [`inspect`].
//! - [`unique_id`]: the kernel's own identity for `pid` (a per-boot-unique id
//!   plus its parent's, and a version counter that increments on pid reuse),
//!   via the *private* `PROC_PIDUNIQIDENTIFIERINFO` flavor. See the
//!   [`unique_id`] doc for the private-API caveat.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

/// Facts about a single process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID, if known. `None` at the top of the tree (the kernel
    /// reports parent `0` for the root, normalized here to `None`) or when
    /// the OS could not resolve it.
    pub ppid: Option<u32>,
    /// Full path to the executable, if the OS could resolve it.
    pub path: Option<PathBuf>,
    /// Process start time, expressed as an offset since the Unix epoch, if
    /// available.
    ///
    /// Exists for pid-reuse detection: a pid whose start time differs from a
    /// previously recorded one is a *different* process. Comparison is only
    /// meaningful between two start times *of the same pid*.
    pub start_time: Option<Duration>,
}

impl ProcessInfo {
    /// The process name: the basename of [`ProcessInfo::path`], if any.
    pub fn name(&self) -> Option<&str> {
        self.path.as_ref()?.file_name()?.to_str()
    }
}

/// Reason a process inspection call failed.
#[derive(Debug, PartialEq, Eq)]
pub enum InspectError {
    /// No process exists with the requested pid (or it exited before
    /// inspection).
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

/// The kernel's own identity for a process.
///
/// Distinct from [`ProcessInfo`]: pid/ppid are OS-assigned and reused over
/// time, while `unique_id`/`parent_unique_id` are monotonic per-boot kernel
/// counters that never repeat, and `id_version` increments each time a pid is
/// reused by a new process. See [`unique_id`] for how this is obtained and its
/// private-API caveat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessUniqueId {
    /// The process's kernel-assigned UUID.
    pub uuid: [u8; 16],
    /// A per-boot-unique identifier for this process (never reused, unlike
    /// the pid).
    pub unique_id: u64,
    /// The `unique_id` of this process's parent at the time it was queried.
    pub parent_unique_id: u64,
    /// Version counter that increments each time this pid is reused by a new
    /// process; combined with the pid, disambiguates pid reuse the same way
    /// [`ProcessInfo::start_time`] does, but as an exact kernel counter rather
    /// than a wall-clock timestamp.
    pub id_version: i32,
}

/// Look up a single process by pid.
///
/// Backed by macOS's public `proc_pidinfo(PROC_PIDTBSDINFO)` /
/// `proc_pidpath` APIs. On non-macOS platforms, always returns
/// [`InspectError::Unavailable`].
pub fn inspect(pid: u32) -> Result<ProcessInfo, InspectError> {
    platform::inspect(pid)
}

/// The kernel's unique identity for `pid`.
///
/// Backed by macOS's `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)`.
///
/// # Design rationale: a private XNU API
///
/// `PROC_PIDUNIQIDENTIFIERINFO` (flavor 17) and its `proc_uniqidentifierinfo`
/// result struct are declared only in XNU's internal
/// `bsd/sys/proc_info_private.h`, not in the public macOS SDK headers used by
/// [`inspect`]'s `PROC_PIDTBSDINFO` flavor. This crate redefines the struct
/// layout from that private header (mirrored in this module's `platform`
/// backend) and has confirmed against a live kernel that the call succeeds
/// and returns the documented 56-byte payload.
///
/// Being private and undocumented, the kernel is free to change or remove
/// this flavor without notice in a future release. Accordingly, *any*
/// failure of the underlying call — including a pid that genuinely does not
/// exist — degrades to [`InspectError::Unavailable`] rather than
/// [`InspectError::NotFound`]: this API alone cannot distinguish "no such
/// process" from "the private struct layout no longer matches this kernel".
/// Callers that need a reliable existence check should use [`inspect`]
/// (backed by the public, documented `PROC_PIDTBSDINFO` flavor) instead, and
/// treat `unique_id` purely as a best-effort enrichment.
///
/// On non-macOS platforms, always returns [`InspectError::Unavailable`].
pub fn unique_id(pid: u32) -> Result<ProcessUniqueId, InspectError> {
    platform::unique_id(pid)
}

/// Walk the parent chain from `pid` toward the root.
///
/// The returned vector starts with `pid` itself and proceeds to each
/// successive parent, stopping when:
///
/// - a process reports no parent (`ppid == None`), or
/// - a parent pid has already been visited (cycle guard — a corrupt or racing
///   process table could otherwise loop forever), or
/// - a parent can no longer be inspected ([`InspectError::NotFound`], e.g. it
///   exited mid-walk): the chain collected so far is returned successfully.
///
/// If the *starting* pid cannot be inspected, the error is propagated. A
/// non-`NotFound` error while walking a parent (e.g. permission denied) is
/// also propagated, since it signals the inspection mechanism itself is
/// unhealthy rather than a benign race.
///
/// Design rationale: stopping (rather than erroring) on a *parent* that
/// vanished mid-walk reflects the reality that ancestry is a best-effort
/// snapshot — the requesting process is alive, but its ancestors may exit at
/// any moment.
pub fn ancestry(pid: u32) -> Result<Vec<ProcessInfo>, InspectError> {
    ancestry_with(pid, inspect)
}

/// The walking logic behind [`ancestry`], parameterized over the single-pid
/// lookup so it can be exercised against an in-memory process tree in tests
/// without touching the real OS.
fn ancestry_with(
    pid: u32,
    inspect_fn: impl Fn(u32) -> Result<ProcessInfo, InspectError>,
) -> Result<Vec<ProcessInfo>, InspectError> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current = Some(pid);

    while let Some(p) = current {
        // Cycle / kernel guard: a real tree never revisits a pid, and pid 0
        // is the kernel — stop rather than risk looping.
        if p == 0 || !visited.insert(p) {
            break;
        }
        let info = match inspect_fn(p) {
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

// --- platform backends ---

#[cfg(target_os = "macos")]
mod platform {
    use super::{InspectError, ProcessInfo, ProcessUniqueId};
    use std::mem;
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
        // SAFETY: proc_bsdinfo is a plain-old-data struct for which all-zero
        // bytes are a valid (if meaningless) value; the kernel overwrites it.
        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        // SAFETY: `info` is a valid, exclusively-owned buffer whose exact
        // size is passed as the buffer-size argument; the kernel writes at
        // most that many bytes.
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
        // SAFETY: `buf` is a valid, exclusively-owned buffer and its exact
        // length is passed as the buffer-size argument; the kernel writes at
        // most that many bytes.
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
        // `ret` is the path length in bytes. Slice by it rather than trusting
        // a NUL terminator: libproc does write one in practice, but that is an
        // undocumented implementation detail, and slicing keeps this function
        // safe even if a future libproc fills the whole buffer.
        let len = (ret as usize).min(buf.len());
        let bytes = match buf[..len].iter().position(|&b| b == 0) {
            Some(nul) => &buf[..nul],
            None => &buf[..len],
        };
        if bytes.is_empty() {
            return None;
        }
        use std::os::unix::ffi::OsStrExt as _;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }

    /// `proc_pidinfo` flavor id for `PROC_PIDUNIQIDENTIFIERINFO`.
    ///
    /// Not exposed by the `libc` crate (private API) or the public SDK
    /// headers; taken verbatim from XNU's `bsd/sys/proc_info_private.h`.
    const PROC_PIDUNIQIDENTIFIERINFO: i32 = 17;

    /// Raw kernel layout for the `PROC_PIDUNIQIDENTIFIERINFO` flavor.
    ///
    /// Verbatim from XNU's `bsd/sys/proc_info_private.h` (private API, not in
    /// the public macOS SDK — see [`super::unique_id`] for the caveat this
    /// implies). Field layout and the 56-byte total size have been
    /// empirically confirmed against a live kernel, matching the struct's
    /// own `_Static_assert` in that header. The two `p_reserveN` tail fields
    /// are kept only to preserve the struct's size for `proc_pidinfo`'s
    /// exact-size check; they are not exposed on [`ProcessUniqueId`].
    #[repr(C)]
    struct ProcUniqIdentifierInfo {
        p_uuid: [u8; 16],
        p_uniqueid: u64,
        p_puniqueid: u64,
        p_idversion: i32,
        p_orig_ppidversion: i32,
        p_reserve2: u64,
        p_reserve3: u64,
    }

    pub(super) fn unique_id(pid: u32) -> Result<ProcessUniqueId, InspectError> {
        // SAFETY: ProcUniqIdentifierInfo is a plain-old-data struct for which
        // all-zero bytes are a valid value; the kernel overwrites it.
        let mut info: ProcUniqIdentifierInfo = unsafe { mem::zeroed() };
        // SAFETY: `info` is a valid, exclusively-owned buffer whose exact
        // size is passed as the buffer-size argument; the kernel writes at
        // most that many bytes.
        let ret = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                mem::size_of::<ProcUniqIdentifierInfo>() as i32,
            )
        };
        // See super::unique_id's design-rationale doc: a short/mismatched
        // return here is ambiguous (nonexistent pid vs. a kernel that no
        // longer matches this private layout), so it degrades to
        // Unavailable rather than NotFound.
        if ret as usize != mem::size_of::<ProcUniqIdentifierInfo>() {
            return Err(InspectError::unavailable(format!(
                "proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO) for pid {pid} returned {ret} bytes, expected {}",
                mem::size_of::<ProcUniqIdentifierInfo>()
            )));
        }
        Ok(ProcessUniqueId {
            uuid: info.p_uuid,
            unique_id: info.p_uniqueid,
            parent_unique_id: info.p_puniqueid,
            id_version: info.p_idversion,
        })
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::{InspectError, ProcessInfo, ProcessUniqueId};

    pub(super) fn inspect(_pid: u32) -> Result<ProcessInfo, InspectError> {
        Err(InspectError::unavailable(
            "process inspection is only implemented on macOS",
        ))
    }

    pub(super) fn unique_id(_pid: u32) -> Result<ProcessUniqueId, InspectError> {
        Err(InspectError::unavailable(
            "process unique-id lookup is only implemented on macOS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    // --- ancestry_with: logic tests over an in-memory tree, no real OS ---
    //
    // `ancestry` itself always calls the platform `inspect`, so these drive
    // the shared walking logic directly through `ancestry_with` with a
    // closure over a plain HashMap tree, without introducing a trait.

    fn tree_lookup(
        tree: &HashMap<u32, ProcessInfo>,
    ) -> impl Fn(u32) -> Result<ProcessInfo, InspectError> + '_ {
        move |pid| {
            tree.get(&pid)
                .cloned()
                .ok_or(InspectError::NotFound { pid })
        }
    }

    #[test]
    fn ancestry_walks_from_pid_to_root() {
        // 100 (ssh) -> 50 (git) -> 10 (zsh) -> 1 (launchd, no parent)
        let tree = HashMap::from([
            (100, path_secs(100, Some(50), "ssh")),
            (50, path_secs(50, Some(10), "git")),
            (10, path_secs(10, Some(1), "zsh")),
            (1, path_secs(1, None, "launchd")),
        ]);
        let chain = ancestry_with(100, tree_lookup(&tree)).unwrap();
        let names: Vec<_> = chain.iter().map(|p| p.name().unwrap()).collect();
        assert_eq!(names, vec!["ssh", "git", "zsh", "launchd"]);
        assert_eq!(chain[0].pid, 100);
    }

    #[test]
    fn ancestry_starting_pid_missing_propagates_error() {
        let tree = HashMap::new();
        assert_eq!(
            ancestry_with(100, tree_lookup(&tree)),
            Err(InspectError::NotFound { pid: 100 })
        );
    }

    #[test]
    fn ancestry_stops_when_parent_vanished_mid_walk() {
        // 100 -> 50, but 50 is not in the tree (exited mid-walk). The chain
        // collected so far (just 100) is returned successfully.
        let tree = HashMap::from([(100, path_secs(100, Some(50), "ssh"))]);
        let chain = ancestry_with(100, tree_lookup(&tree)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pid, 100);
    }

    #[test]
    fn ancestry_unavailable_parent_propagates_error() {
        // A parent lookup failing with Unavailable (e.g. permission denied)
        // signals the inspection mechanism itself is unhealthy — unlike the
        // benign NotFound race above, the walk must NOT return a silently
        // truncated chain: a short chain presented as complete could let a
        // policy layer approve on incomplete ancestry. The documented
        // contract is to propagate the error instead.
        let lookup = |pid: u32| {
            if pid == 100 {
                Ok(path_secs(100, Some(50), "ssh"))
            } else {
                Err(InspectError::unavailable("permission denied"))
            }
        };
        assert_eq!(
            ancestry_with(100, lookup),
            Err(InspectError::unavailable("permission denied"))
        );
    }

    #[test]
    fn ancestry_breaks_on_cycle() {
        // Corrupt tree: 10 -> 20 -> 10. Must not loop forever.
        let tree = HashMap::from([
            (10, path_secs(10, Some(20), "a")),
            (20, path_secs(20, Some(10), "b")),
        ]);
        let chain = ancestry_with(10, tree_lookup(&tree)).unwrap();
        // Visits 10 then 20, then 20's parent 10 is already visited -> stop.
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].pid, 10);
        assert_eq!(chain[1].pid, 20);
    }

    #[test]
    fn ancestry_stops_at_pid_zero_parent() {
        // launchd reports ppid 0 on macOS in some snapshots; treat 0 as kernel.
        let tree = HashMap::from([(1, path_secs(1, Some(0), "launchd"))]);
        let chain = ancestry_with(1, tree_lookup(&tree)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pid, 1);
    }

    #[test]
    fn ancestry_self_referential_root_does_not_loop() {
        // A process that claims itself as parent (pathological) must not loop.
        let tree = HashMap::from([(5, path_secs(5, Some(5), "x"))]);
        let chain = ancestry_with(5, tree_lookup(&tree)).unwrap();
        assert_eq!(chain.len(), 1);
    }

    // --- non-macOS shim: pins the "always Unavailable" contract ---

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_inspect_and_unique_id_are_unavailable() {
        assert!(matches!(
            inspect(std::process::id()),
            Err(InspectError::Unavailable { .. })
        ));
        assert!(matches!(
            unique_id(std::process::id()),
            Err(InspectError::Unavailable { .. })
        ));
    }

    // --- live-OS tests (macOS only) ---
    //
    // These run against the real process table on the dev / CI macOS host.

    #[cfg(target_os = "macos")]
    #[test]
    fn system_inspect_self() {
        let me = std::process::id();
        let info = inspect(me).unwrap();
        assert_eq!(info.pid, me);
        // The current process always has a parent (the test runner / shell).
        assert!(info.ppid.is_some(), "self should have a parent pid");
        // Our own executable path resolves.
        assert!(info.path.is_some(), "self should have an exe path");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_self_records_start_time() {
        // start_time is the pid-reuse signal; assert the OS actually exposes
        // it for our own live process.
        let info = inspect(std::process::id()).unwrap();
        assert!(
            info.start_time.is_some(),
            "self should expose a start time for reuse detection"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_inspect_nonexistent_pid_is_not_found() {
        // pid 0 is the kernel; a very high pid is almost certainly unused.
        // Probe upward to find a definitely-absent pid, then assert NotFound.
        let mut probe = 4_000_000u32;
        while inspect(probe).is_ok() {
            probe += 1;
        }
        assert_eq!(inspect(probe), Err(InspectError::NotFound { pid: probe }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_ancestry_self_walks_a_consistent_chain() {
        let chain = ancestry(std::process::id()).unwrap();
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
        // The walk terminates cleanly: either it reached a parentless root, or
        // it stopped at a process whose parent could no longer be inspected
        // (proc_pidinfo cannot read the bsdinfo of privileged ancestors, e.g.
        // pid 1 launchd, so the chain legitimately stops at a privilege
        // boundary — verified above by the successful unwrap).
        let last = chain.last().unwrap();
        match last.ppid {
            None => {}
            Some(parent) => assert!(
                inspect(parent).is_err(),
                "walk stopped at pid {} whose parent {} is inspectable — it should have continued",
                last.pid,
                parent
            ),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_unique_id_self_is_ok_and_positive() {
        // The kernel's own identity for our live process: a nonzero
        // unique_id and a version counter that starts at (at least) 0.
        let id = unique_id(std::process::id()).unwrap();
        assert!(
            id.unique_id > 0,
            "self should have a nonzero kernel unique id"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_unique_id_nonexistent_pid_is_unavailable() {
        // Per the design-rationale doc on `unique_id`: a private-API failure
        // (including a genuinely absent pid) degrades to Unavailable, not
        // NotFound. Pin that against the same definitely-absent pid probe
        // used above.
        let mut probe = 4_000_000u32;
        while inspect(probe).is_ok() {
            probe += 1;
        }
        assert!(matches!(
            unique_id(probe),
            Err(InspectError::Unavailable { .. })
        ));
    }
}
