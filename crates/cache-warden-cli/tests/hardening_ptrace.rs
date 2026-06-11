//! Real-effect E2E for anti-debug hardening (design §3 judgement 5b).
//!
//! Verifies that a running daemon actually refuses debugger attachment:
//! spawn `cache-warden daemon run`, wait until it is serving, then try to
//! `PTRACE_ATTACH` (Linux) / `ptrace(PT_ATTACH)` (macOS) from this test process
//! and assert the attach is refused. A second run with
//! `[daemon].allow-debug-attach = true` asserts the opt-out lets attach succeed.
//!
//! ## Why these are `#[ignore]`d by default
//!
//! The attach assertion is environment-sensitive and not safe for every CI:
//!
//! - **Linux**: whether an unprivileged *same-uid* `PTRACE_ATTACH` to a
//!   non-dumpable process is refused depends on `yama` `ptrace_scope`, container
//!   capabilities, and whether the runner grants `CAP_SYS_PTRACE`. A privileged
//!   container would let the attach through even with `PR_SET_DUMPABLE=0`,
//!   producing a spurious failure.
//! - **macOS**: `ptrace(PT_ATTACH)` against another process can be gated by SIP /
//!   `task_for_pid` hardening on the runner, independent of our `PT_DENY_ATTACH`.
//!
//! The stable CI signal lives in the in-process unit tests
//! (`daemon::hardening::tests`: Linux reads back `PR_GET_DUMPABLE == 0`; macOS
//! asserts the `PT_DENY_ATTACH` call shape, itself `#[ignore]`d because it
//! mutates the test process). These E2E tests are the human-run confirmation that
//! the syscall has the intended *external* effect.
//!
//! Run locally with:
//! ```text
//! cargo test -p cache-warden-cli --test hardening_ptrace -- --ignored --nocapture
//! ```

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// A spawned daemon killed on drop.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `cache-warden daemon run` with the given config; returns the daemon and
/// its control-socket path.
fn spawn_daemon(dir: &Path, allow_debug_attach: bool) -> (Daemon, PathBuf) {
    let control = dir.join("control.sock");
    let config = dir.join("config.toml");
    let body = if allow_debug_attach {
        "[daemon]\nallow-debug-attach = true\n"
    } else {
        "[daemon]\n"
    };
    std::fs::write(&config, body).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .arg("daemon")
        .arg("run")
        .arg("--socket")
        .arg(&control)
        .env("CACHE_WARDEN_CONFIG", &config)
        .spawn()
        .expect("spawn daemon");
    (Daemon { child }, control)
}

/// Block until the control socket exists (the daemon is serving) or time out.
fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("daemon control socket never appeared: {}", path.display());
}

/// Attempt to attach to `pid` with ptrace. Returns `Ok(())` if the attach
/// succeeded (and detaches), `Err(errno)` if the kernel refused.
#[cfg(target_os = "linux")]
fn try_attach(pid: i32) -> Result<(), i32> {
    // SAFETY: PTRACE_ATTACH takes no pointer args we own; it only signals `pid`.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // Reap the stop and detach so we leave the daemon runnable for Drop::kill.
    unsafe {
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn try_attach(pid: i32) -> Result<(), i32> {
    const PT_ATTACH: libc::c_int = 10; // <sys/ptrace.h>
    const PT_DETACH: libc::c_int = 11;
    // SAFETY: PT_ATTACH takes no pointer args we own; it only signals `pid`.
    let ret = unsafe { libc::ptrace(PT_ATTACH, pid, std::ptr::null_mut::<libc::c_char>(), 0) };
    if ret == -1 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    unsafe {
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::ptrace(PT_DETACH, pid, std::ptr::null_mut::<libc::c_char>(), 0);
    }
    Ok(())
}

#[test]
#[ignore = "ptrace attach behaviour is environment-sensitive (yama/SIP/CAP_SYS_PTRACE); run manually"]
fn daemon_refuses_debugger_attach_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, control) = spawn_daemon(dir.path(), false);
    wait_for_socket(&control);

    let pid = daemon.child.id() as i32;
    let res = try_attach(pid);
    assert!(
        res.is_err(),
        "PTRACE_ATTACH to a hardened daemon must be refused, but it succeeded"
    );
}

#[test]
#[ignore = "ptrace attach behaviour is environment-sensitive; run manually to confirm opt-out"]
fn daemon_allows_debugger_attach_when_opted_out() {
    // Control: a non-hardened child of the same uid. If even *this* cannot be
    // attached, the platform itself blocks same-uid ptrace (macOS SIP /
    // `task_for_pid`, or Linux without CAP_SYS_PTRACE under a strict
    // `ptrace_scope`) and the opt-out is unobservable here — treat as
    // inconclusive rather than failing.
    let baseline = {
        let mut sleeper = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        std::thread::sleep(Duration::from_millis(100));
        let r = try_attach(sleeper.id() as i32);
        let _ = sleeper.kill();
        let _ = sleeper.wait();
        r
    };
    if baseline.is_err() {
        eprintln!(
            "skipping opt-out assertion: platform blocks same-uid ptrace (errno {baseline:?}); \
             the default-refuses test is the meaningful signal here"
        );
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let (daemon, control) = spawn_daemon(dir.path(), true);
    wait_for_socket(&control);

    let pid = daemon.child.id() as i32;
    let res = try_attach(pid);
    assert!(
        res.is_ok(),
        "with allow-debug-attach = true the daemon must be attachable, errno {res:?}"
    );
}
