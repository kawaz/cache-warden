//! Peer credentials for an accepted `AF_UNIX` (`SOL_LOCAL`) socket connection.
//!
//! Three `getsockopt(SOL_LOCAL, ...)` lookups, each keyed by the connected
//! file descriptor rather than a pid — they answer "who is on the other end
//! of *this* socket", which is race-free (a pid alone can be reused between
//! `accept()` and a separate lookup, but the socket option is resolved by the
//! kernel against the live peer at call time):
//!
//! - [`peer_pid`]: the peer's pid (`LOCAL_PEERPID`).
//! - [`peer_effective_pid`]: the peer's *effective* pid — differs from
//!   [`peer_pid`] when the peer is itself acting on behalf of another process
//!   (`LOCAL_PEEREPID`; e.g. XPC-proxied connections).
//! - [`peer_audit_token`]: the peer's full audit token (`LOCAL_PEERTOKEN`),
//!   which additionally carries uid/gid and the pid-reuse version counter —
//!   see [`AuditToken`].

use std::os::unix::io::RawFd;

/// A macOS audit token: the kernel's compact credential/identity record for a
/// process, as returned by `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`.
///
/// # Design rationale: field layout
///
/// `audit_token_t` is a public opaque `struct { unsigned int val[8]; }`
/// (`mach/message.h`); Apple does not publish the meaning of each `val[N]`
/// slot in the public SDK, only the `audit_token_to_*` accessor macros in
/// `bsm/audit_session.h`. This type mirrors those macros' effective layout
/// (`auid, euid, egid, ruid, rgid, pid, asid, pidversion`), which has been
/// empirically confirmed against a live kernel: a `socketpair` peer token's
/// decoded `pid`/`pid_version` fields matched `getpid()` and a freshly-forked
/// child's version counter. As with [`super::unique_id`]'s private struct,
/// this is a kernel-internal layout convention rather than a documented
/// contract, so a future kernel could in principle renumber it — the
/// accessors exist as a single point to revisit if that ever happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditToken {
    val: [u32; 8],
}

impl AuditToken {
    /// Audit user id (the identity used for audit trail attribution; not the
    /// same as the login or effective uid in general).
    ///
    /// For a process without an audit session (e.g. a daemon launched
    /// directly by `launchd`), this is `AU_DEFAUDITID` (= `u32::MAX`) — a
    /// sentinel, not a uid. Do not compare it against user ids.
    pub fn auid(&self) -> u32 {
        self.val[0]
    }

    /// Effective user id of the peer process.
    pub fn euid(&self) -> u32 {
        self.val[1]
    }

    /// Effective group id of the peer process.
    pub fn egid(&self) -> u32 {
        self.val[2]
    }

    /// Real user id of the peer process.
    pub fn ruid(&self) -> u32 {
        self.val[3]
    }

    /// Real group id of the peer process.
    pub fn rgid(&self) -> u32 {
        self.val[4]
    }

    /// The peer's pid, or `None` if the kernel reported pid `0` (no
    /// meaningful process — e.g. a kernel-originated token).
    pub fn pid(&self) -> Option<u32> {
        let pid = self.val[5];
        if pid == 0 { None } else { Some(pid) }
    }

    /// Audit session id of the peer process.
    pub fn asid(&self) -> u32 {
        self.val[6]
    }

    /// Version counter that increments each time the peer's pid is reused by
    /// a new process — the same disambiguation role as
    /// [`super::ProcessUniqueId::id_version`], obtained here without a
    /// separate `proc_pidinfo` call.
    pub fn pid_version(&self) -> i32 {
        self.val[7] as i32
    }

    /// The raw 32-byte audit token as the kernel returned it, in native byte
    /// order — the same shape `kSecGuestAttributeAudit` expects when handed
    /// to `SecCodeCopyGuestWithAttributes` via a `CFData`. See
    /// [`super::codesign`] for the peer-authentication use.
    ///
    /// The [`AuditToken`] struct stores each of the kernel's 8 `u32` slots
    /// unchanged, so the reconstruction is a slot-by-slot `to_ne_bytes` —
    /// no byte-order or width conversion happens here.
    pub fn raw_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, v) in self.val.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_ne_bytes());
        }
        out
    }
}

/// The peer process id for the connection on `fd`, or `None` if unavailable.
///
/// Returns `None` on non-macOS platforms, or if the kernel call fails — the
/// caller should treat that as "no requester attribution available" rather
/// than an error. Failures collapse to `None` regardless of kind (`ENOTSOCK`,
/// `EBADF`, an unconnected socket, ...); the errno is intentionally discarded
/// because every failure means the same thing to a caller: no attribution.
#[cfg(target_os = "macos")]
pub fn peer_pid(fd: RawFd) -> Option<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` is a valid, exclusively-owned pid_t and `len` is
    // initialized to its exact size; the kernel writes at most `len` bytes
    // into it and updates `len` with the written length.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && len as usize == std::mem::size_of::<libc::pid_t>() && pid > 0 {
        Some(pid as u32)
    } else {
        None
    }
}

/// See the macOS variant for the contract; non-macOS always returns `None`.
#[cfg(not(target_os = "macos"))]
pub fn peer_pid(_fd: RawFd) -> Option<u32> {
    None
}

/// The peer's *effective* process id for the connection on `fd`.
///
/// Differs from [`peer_pid`] when the peer is acting on behalf of another
/// process (e.g. an XPC-proxied connection); identical to [`peer_pid`] for a
/// direct, non-proxied connection. Returns `None` on non-macOS, or if the
/// kernel call fails.
#[cfg(target_os = "macos")]
pub fn peer_effective_pid(fd: RawFd) -> Option<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: same contract as `peer_pid` — `pid`/`len` describe an
    // exclusively-owned, correctly-sized output buffer.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEEREPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && len as usize == std::mem::size_of::<libc::pid_t>() && pid > 0 {
        Some(pid as u32)
    } else {
        None
    }
}

/// See the macOS variant for the contract; non-macOS always returns `None`.
#[cfg(not(target_os = "macos"))]
pub fn peer_effective_pid(_fd: RawFd) -> Option<u32> {
    None
}

/// The peer's full audit token for the connection on `fd`.
///
/// Returns `None` on non-macOS, or if the kernel call fails or returns a
/// short/mismatched payload.
#[cfg(target_os = "macos")]
pub fn peer_audit_token(fd: RawFd) -> Option<AuditToken> {
    // mach/message.h: `typedef struct { unsigned int val[8]; } audit_token_t;`
    // (32 bytes). Not exposed by the `libc` crate, so redefined here verbatim.
    #[repr(C)]
    struct RawAuditToken {
        val: [u32; 8],
    }

    let mut token: RawAuditToken = RawAuditToken { val: [0; 8] };
    let mut len = std::mem::size_of::<RawAuditToken>() as libc::socklen_t;
    // SAFETY: `token` is a valid, exclusively-owned 32-byte buffer and `len`
    // is initialized to its exact size; the kernel writes at most `len` bytes.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            &mut token as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && len as usize == std::mem::size_of::<RawAuditToken>() {
        Some(AuditToken { val: token.val })
    } else {
        None
    }
}

/// See the macOS variant for the contract; non-macOS always returns `None`.
#[cfg(not(target_os = "macos"))]
pub fn peer_audit_token(_fd: RawFd) -> Option<AuditToken> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    // --- AuditToken accessors: pure logic, no OS dependency ---

    #[test]
    fn audit_token_accessors_read_expected_slots() {
        let token = AuditToken {
            val: [11, 22, 33, 44, 55, 66, 77, 88],
        };
        assert_eq!(token.auid(), 11);
        assert_eq!(token.euid(), 22);
        assert_eq!(token.egid(), 33);
        assert_eq!(token.ruid(), 44);
        assert_eq!(token.rgid(), 55);
        assert_eq!(token.pid(), Some(66));
        assert_eq!(token.asid(), 77);
        assert_eq!(token.pid_version(), 88);
    }

    #[test]
    fn audit_token_raw_bytes_round_trips_native_slots() {
        // Every u32 slot must serialize to exactly 4 bytes in native order,
        // packed contiguously into 32 bytes — the shape
        // `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` expects.
        // Using `to_ne_bytes` on the same values inline mirrors the intended
        // implementation (native, per-slot) rather than a byte-order-specific
        // literal that would drift on a big-endian target.
        let vals = [0x0102_0304u32, 0, 0xffff_fffe, 42, 43, 44, 45, 46];
        let token = AuditToken { val: vals };
        let bytes = token.raw_bytes();
        let mut expected = [0u8; 32];
        for (i, v) in vals.iter().enumerate() {
            expected[i * 4..(i + 1) * 4].copy_from_slice(&v.to_ne_bytes());
        }
        assert_eq!(bytes, expected);
    }

    #[test]
    fn audit_token_zero_pid_is_none() {
        // A pid slot of 0 has no meaningful process (e.g. a kernel-originated
        // token) — surfaced as None rather than a bogus Some(0).
        let token = AuditToken {
            val: [0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(token.pid(), None);
    }

    // --- live-OS tests (macOS only): a socketpair has both ends in this
    // process, so every peer credential must resolve to our own identity.

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_pid_of_self_socketpair_is_current_pid() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        assert_eq!(peer_pid(a.as_raw_fd()), Some(std::process::id()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_effective_pid_of_self_socketpair_is_current_pid() {
        // No proxying involved in a same-process socketpair, so the
        // effective pid equals the real pid.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        assert_eq!(peer_effective_pid(a.as_raw_fd()), Some(std::process::id()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_audit_token_of_self_socketpair_matches_current_process() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let token = peer_audit_token(a.as_raw_fd()).expect("audit token");
        assert_eq!(token.pid(), Some(std::process::id()));
        // A live process always has a nonnegative id-version counter; assert
        // it decoded to *some* concrete value rather than garbage bits (a
        // negative i32 would indicate the val[7] slot is not what this
        // module assumes it is).
        assert!(
            token.pid_version() >= 0,
            "pid_version should decode as a small nonnegative counter, got {}",
            token.pid_version()
        );
    }

    // --- failure paths (macOS): every failure kind collapses to None, per
    // the documented "no attribution available" contract. These pin the
    // `ret == 0` / length checks — a refactor that drops them would turn an
    // uninitialized 0 into a bogus Some and these tests would catch it.

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_lookups_on_non_socket_fd_are_none() {
        // /dev/null is a character device, not a socket — getsockopt fails
        // with ENOTSOCK, which must surface as None (not a panic, not Some).
        use std::os::fd::AsRawFd as _;
        let f = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = f.as_raw_fd();
        assert_eq!(peer_pid(fd), None);
        assert_eq!(peer_effective_pid(fd), None);
        assert_eq!(peer_audit_token(fd), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_lookups_on_unconnected_listener_are_none() {
        // A bound-but-unconnected listener has no peer to attribute — the
        // kernel call fails and must surface as None.
        use std::os::fd::AsRawFd as _;
        let dir = std::env::temp_dir().join(format!("mpi-peer-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("l.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let fd = listener.as_raw_fd();
        assert_eq!(peer_pid(fd), None);
        assert_eq!(peer_effective_pid(fd), None);
        assert_eq!(peer_audit_token(fd), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- non-macOS shim: pins the "always None" contract ---

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_peer_lookups_are_none() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        assert_eq!(peer_pid(a.as_raw_fd()), None);
        assert_eq!(peer_effective_pid(a.as_raw_fd()), None);
        assert_eq!(peer_audit_token(a.as_raw_fd()), None);
    }
}
