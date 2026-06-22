//! macOS TCC (Transparency, Consent, Control) permission inspection and
//! Settings-guided grant flow.
//!
//! This crate provides a minimal API for checking whether the running
//! application has been granted a specific TCC permission, opening the
//! relevant System Settings pane, and waiting for the user to grant access.
//!
//! On non-macOS platforms, all functions return stub values so callers can
//! compile and run without platform guards everywhere.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// A TCC-controlled permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Full Disk Access — required to read protected directories such as
    /// `/Library/Application Support/com.apple.TCC/TCC.db`.
    FullDiskAccess,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::FullDiskAccess => write!(f, "Full Disk Access"),
        }
    }
}

/// The authorization state of a [`Permission`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// The permission has been granted.
    Granted,
    /// The permission has not been granted.
    NotGranted,
    /// The state could not be determined (e.g. non-macOS, or a feature was
    /// disabled at compile time).
    Unknown,
}

impl std::fmt::Display for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthState::Granted => write!(f, "granted"),
            AuthState::NotGranted => write!(f, "not granted"),
            AuthState::Unknown => write!(f, "unknown"),
        }
    }
}

/// Options for [`wait_for_grant`].
#[derive(Debug, Clone)]
pub struct WaitOpts {
    /// How often to re-check authorization state.
    pub poll_interval: Duration,
    /// Maximum time to wait before returning [`WaitOutcome::TimedOut`].
    /// `None` = wait forever (until the user grants or skips).
    pub timeout: Option<Duration>,
}

impl Default for WaitOpts {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            timeout: None,
        }
    }
}

/// The outcome of [`wait_for_grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The permission was granted before the timeout or user skip.
    Granted,
    /// The user pressed Enter to skip without granting.
    UserSkipped,
    /// The timeout elapsed without the permission being granted.
    TimedOut,
}

// ────────────────────────────────────────────────────────────────────────────
// macOS implementation
// ────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::io::{self, BufRead};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    /// Check `p` by probing a protected path (in-process, no subprocess).
    ///
    /// Under the `fda` feature: attempt to `stat`
    /// `/Library/Application Support/com.apple.TCC/TCC.db`. Access succeeds
    /// only when Full Disk Access has been granted.
    pub fn check(p: Permission) -> AuthState {
        match p {
            Permission::FullDiskAccess => {
                #[cfg(feature = "fda")]
                {
                    std::fs::metadata("/Library/Application Support/com.apple.TCC/TCC.db")
                        .map(|_| AuthState::Granted)
                        .unwrap_or(AuthState::NotGranted)
                }
                #[cfg(not(feature = "fda"))]
                AuthState::Unknown
            }
        }
    }

    /// Return the `.app` bundle that contains the current executable, if any.
    pub fn current_app_bundle() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let canonical = exe.canonicalize().ok()?;
        let s = canonical.to_str()?;
        app_bundle_from_path(s)
    }

    /// Extract the `.app` bundle path from a string representation of an
    /// executable path. Testable without a real filesystem.
    pub fn app_bundle_from_path(path: &str) -> Option<PathBuf> {
        // Look for `.app/Contents/MacOS/` in the path.
        let marker = ".app/Contents/MacOS/";
        let pos = path.find(marker)?;
        // Include the `.app` suffix itself.
        let bundle_end = pos + ".app".len();
        Some(PathBuf::from(&path[..bundle_end]))
    }

    /// RAII guard that deletes a temp file on drop.
    struct TempFileGuard(PathBuf);

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Probe authorization by re-launching the current `.app` bundle with
    /// `self_check_args` and reading the result file it writes.
    ///
    /// The subprocess is expected to write `"ok\n"` to the result file when
    /// the permission is granted, or any other content otherwise.
    pub fn check_via_app_bundle(
        p: Permission,
        app_path: &Path,
        self_check_args: &[&str],
    ) -> io::Result<AuthState> {
        let perm_name = match p {
            Permission::FullDiskAccess => "fda",
        };
        let tmp_path =
            std::env::temp_dir().join(format!("macos-tcc-{}-{}", std::process::id(), perm_name));
        let _guard = TempFileGuard(tmp_path.clone());

        // Build the argument list: self_check_args... followed by
        // --result-file <path>
        let mut open_args: Vec<String> = Vec::new();
        open_args.push("--wait-apps".to_string());
        open_args.push(app_path.to_string_lossy().into_owned());
        if !self_check_args.is_empty() {
            open_args.push("--args".to_string());
            for a in self_check_args {
                open_args.push((*a).to_string());
            }
            open_args.push("--result-file".to_string());
            open_args.push(tmp_path.to_string_lossy().into_owned());
        }

        let status = Command::new("open")
            .args(&open_args)
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            return Ok(AuthState::NotGranted);
        }

        match std::fs::read_to_string(&tmp_path) {
            Ok(content) if content.starts_with("ok") => Ok(AuthState::Granted),
            Ok(_) => Ok(AuthState::NotGranted),
            Err(_) => Ok(AuthState::NotGranted),
        }
    }

    /// Open the System Settings pane for `p`.
    pub fn open_settings(p: Permission) -> io::Result<()> {
        let url = match p {
            Permission::FullDiskAccess => {
                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
            }
        };
        Command::new("open").arg(url).status()?;
        Ok(())
    }

    /// Poll until the permission is granted, the user skips, or a timeout
    /// elapses.
    pub fn wait_for_grant(
        p: Permission,
        app_path: &Path,
        self_check_args: &[&str],
        opts: WaitOpts,
    ) -> WaitOutcome {
        let (tx, rx) = mpsc::channel::<WaitOutcome>();

        // Poll thread.
        let tx_poll = tx.clone();
        let app_path_owned = app_path.to_path_buf();
        let args_owned: Vec<String> = self_check_args.iter().map(|s| s.to_string()).collect();
        let poll_interval = opts.poll_interval;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(poll_interval);
                let args_ref: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
                if let Ok(AuthState::Granted) = check_via_app_bundle(p, &app_path_owned, &args_ref)
                {
                    let _ = tx_poll.send(WaitOutcome::Granted);
                    return;
                }
            }
        });

        // Enter / skip thread.
        let tx_enter = tx.clone();
        std::thread::spawn(move || {
            let stdin = io::stdin();
            let mut line = String::new();
            let _ = stdin.lock().read_line(&mut line);
            let _ = tx_enter.send(WaitOutcome::UserSkipped);
        });

        // Timeout thread (optional).
        if let Some(timeout) = opts.timeout {
            let tx_timeout = tx.clone();
            std::thread::spawn(move || {
                std::thread::sleep(timeout);
                let _ = tx_timeout.send(WaitOutcome::TimedOut);
            });
        }

        rx.recv().unwrap_or(WaitOutcome::TimedOut)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Non-macOS stubs
// ────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "macos"))]
mod non_macos {
    use super::*;
    use std::io;

    pub fn check(_p: Permission) -> AuthState {
        AuthState::Unknown
    }

    pub fn current_app_bundle() -> Option<PathBuf> {
        None
    }

    pub fn check_via_app_bundle(
        _p: Permission,
        _app_path: &Path,
        _self_check_args: &[&str],
    ) -> io::Result<AuthState> {
        Ok(AuthState::Unknown)
    }

    pub fn open_settings(_p: Permission) -> io::Result<()> {
        Ok(())
    }

    pub fn wait_for_grant(
        _p: Permission,
        _app_path: &Path,
        _self_check_args: &[&str],
        _opts: WaitOpts,
    ) -> WaitOutcome {
        WaitOutcome::TimedOut
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Public API — thin wrappers that delegate to the platform module
// ────────────────────────────────────────────────────────────────────────────

/// Check the authorization state of `p` in-process (no subprocess).
///
/// On macOS with the `fda` feature, this probes a TCC-guarded path to detect
/// whether Full Disk Access has been granted. On other platforms, or when the
/// feature is disabled, returns [`AuthState::Unknown`].
pub fn check(p: Permission) -> AuthState {
    #[cfg(target_os = "macos")]
    {
        macos::check(p)
    }
    #[cfg(not(target_os = "macos"))]
    {
        non_macos::check(p)
    }
}

/// Return the `.app` bundle that contains the current executable, if any.
///
/// Returns `None` when the binary is not inside an `.app/Contents/MacOS/`
/// directory or on non-macOS.
pub fn current_app_bundle() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        macos::current_app_bundle()
    }
    #[cfg(not(target_os = "macos"))]
    {
        non_macos::current_app_bundle()
    }
}

/// Probe authorization by re-launching the app bundle and reading the result.
///
/// Spawns `open --wait-apps <app_path> --args <self_check_args...>
/// --result-file <tmp>`. The subprocess should write `"ok\n"` to the result
/// file when the permission is granted. Returns `Ok(Granted)` if the file
/// starts with `"ok"`, `Ok(NotGranted)` otherwise.
///
/// On non-macOS, returns `Ok(Unknown)`.
pub fn check_via_app_bundle(
    p: Permission,
    app_path: &Path,
    self_check_args: &[&str],
) -> std::io::Result<AuthState> {
    #[cfg(target_os = "macos")]
    {
        macos::check_via_app_bundle(p, app_path, self_check_args)
    }
    #[cfg(not(target_os = "macos"))]
    {
        non_macos::check_via_app_bundle(p, app_path, self_check_args)
    }
}

/// Open the System Settings pane for `p`.
///
/// On macOS, opens the privacy pane for the permission. On other platforms,
/// is a no-op.
pub fn open_settings(p: Permission) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::open_settings(p)
    }
    #[cfg(not(target_os = "macos"))]
    {
        non_macos::open_settings(p)
    }
}

/// Poll until `p` is granted, the user presses Enter to skip, or `opts.timeout`
/// elapses.
///
/// Authorization is checked by calling [`check_via_app_bundle`] every
/// `opts.poll_interval`. The calling thread is also waiting for a line on
/// stdin so the user can skip.
///
/// On non-macOS, returns [`WaitOutcome::TimedOut`] immediately.
pub fn wait_for_grant(
    p: Permission,
    app_path: &Path,
    self_check_args: &[&str],
    opts: WaitOpts,
) -> WaitOutcome {
    #[cfg(target_os = "macos")]
    {
        macos::wait_for_grant(p, app_path, self_check_args, opts)
    }
    #[cfg(not(target_os = "macos"))]
    {
        non_macos::wait_for_grant(p, app_path, self_check_args, opts)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_display() {
        assert_eq!(Permission::FullDiskAccess.to_string(), "Full Disk Access");
    }

    #[test]
    fn auth_state_display() {
        assert_eq!(AuthState::Granted.to_string(), "granted");
        assert_eq!(AuthState::NotGranted.to_string(), "not granted");
        assert_eq!(AuthState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn wait_outcome_variants_exist() {
        let _g = WaitOutcome::Granted;
        let _s = WaitOutcome::UserSkipped;
        let _t = WaitOutcome::TimedOut;
        // Verify Debug is implemented.
        assert!(format!("{_g:?}").contains("Granted"));
        assert!(format!("{_s:?}").contains("UserSkipped"));
        assert!(format!("{_t:?}").contains("TimedOut"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_bundle_from_path_inside_app() {
        let result = macos::app_bundle_from_path("/Applications/Foo.app/Contents/MacOS/foo");
        assert_eq!(result, Some(PathBuf::from("/Applications/Foo.app")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_bundle_from_path_without_app() {
        assert_eq!(
            macos::app_bundle_from_path("/usr/local/bin/cache-warden"),
            None
        );
        assert_eq!(
            macos::app_bundle_from_path("/opt/homebrew/bin/cache-warden"),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_bundle_from_path_deeply_nested() {
        let result = macos::app_bundle_from_path(
            "/Applications/Deep/CacheWarden.app/Contents/MacOS/cache-warden",
        );
        assert_eq!(
            result,
            Some(PathBuf::from("/Applications/Deep/CacheWarden.app"))
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_stubs_return_unknown_or_none() {
        assert_eq!(check(Permission::FullDiskAccess), AuthState::Unknown);
        assert_eq!(current_app_bundle(), None);
        let dummy = PathBuf::from("/tmp/dummy.app");
        assert_eq!(
            check_via_app_bundle(Permission::FullDiskAccess, &dummy, &[]).unwrap(),
            AuthState::Unknown
        );
        assert!(open_settings(Permission::FullDiskAccess).is_ok());
        assert_eq!(
            wait_for_grant(Permission::FullDiskAccess, &dummy, &[], WaitOpts::default()),
            WaitOutcome::TimedOut
        );
    }
}
