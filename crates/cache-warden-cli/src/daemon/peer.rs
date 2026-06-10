//! Peer credential lookup for an accepted control-socket connection.
//!
//! Determines the connecting peer's process id from the socket so the daemon
//! can attach the requester's process ancestry to the core auth context
//! (DR-0006/0008). The pid is obtained per-connection from the kernel:
//!
//! - macOS: `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`
//! - Linux: `getsockopt(SOL_SOCKET, SO_PEERCRED)` (`ucred.pid`)
//!
//! This is intentionally separated from the async server so the unsafe FFI is
//! isolated and testable with a plain socket pair.

use std::os::unix::io::RawFd;

/// The peer process id for the connection on `fd`, or `None` if unavailable.
///
/// Returns `None` on platforms without a supported peer-credential mechanism
/// or if the kernel call fails — the caller then proceeds with no requester
/// attribution (the UDS 0600 + same-uid gate remains the primary defense).
#[cfg(target_os = "macos")]
pub fn peer_pid(fd: RawFd) -> Option<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && pid > 0 {
        Some(pid as u32)
    } else {
        None
    }
}

/// The peer process id for the connection on `fd`, or `None` if unavailable.
///
/// See the macOS variant for the contract.
#[cfg(target_os = "linux")]
pub fn peer_pid(fd: RawFd) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && cred.pid > 0 {
        Some(cred.pid as u32)
    } else {
        None
    }
}

/// Fallback for unsupported platforms: no peer credential available.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_pid(_fd: RawFd) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn peer_pid_of_self_socketpair_is_current_pid() {
        // A socketpair has both ends in this process, so the peer pid is ours.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let pid = peer_pid(a.as_raw_fd());
        assert_eq!(pid, Some(std::process::id()));
    }
}
