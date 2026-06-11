//! Resolve an upstream agent socket path to one we can reach without tripping a
//! TCC privacy prompt on macOS (port plan Iteration 2; ported from
//! authsock-warden's `onepassword_agent_socket` symlink trick).
//!
//! # The macOS problem
//!
//! The 1Password SSH agent socket lives under
//! `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`. Reaching
//! into `~/Library/Group Containers/` from a launchd-managed service triggers a
//! TCC ("privacy") consent dialog. A symlink **outside** that container, in our
//! own state directory, lets us `connect()` to the same socket without touching
//! the protected directory at access time — the kernel follows the symlink to
//! the real socket, and the symlink itself is in an unprotected location.
//!
//! So on macOS, if the configured upstream path is under `Library/Group
//! Containers/`, we create (once) a stable symlink under
//! `$XDG_STATE_HOME/cache-warden/upstreams/` and hand the daemon that path
//! instead. Everywhere else (and on Linux) the path is used verbatim.

use std::path::{Path, PathBuf};

/// Resolve `configured` to a path the daemon can connect to.
///
/// On macOS, a path under `Library/Group Containers/` is redirected through a
/// stable symlink in the state dir to avoid a TCC prompt; the symlink is
/// (re)created to point at the real socket. On any other path — and on Linux —
/// the input is returned unchanged.
///
/// Symlink creation is best-effort: if it fails (state dir not writable, etc.)
/// the original path is returned so the daemon still tries the direct route.
pub fn resolve_upstream_path(configured: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if is_group_container_path(configured)
            && let Some(link) = make_state_symlink(configured)
        {
            return link;
        }
        configured.to_path_buf()
    }

    #[cfg(not(target_os = "macos"))]
    {
        // No TCC on Linux/other; use the configured path directly.
        configured.to_path_buf()
    }
}

/// True if `path` points inside a macOS app Group Container (TCC-protected).
#[cfg(target_os = "macos")]
fn is_group_container_path(path: &Path) -> bool {
    path.to_string_lossy().contains("Library/Group Containers/")
}

/// Create (or refresh) a stable symlink in the state dir pointing at `target`,
/// returning the symlink path. `None` on any filesystem failure.
#[cfg(target_os = "macos")]
fn make_state_symlink(target: &Path) -> Option<PathBuf> {
    // Derive a stable, collision-free symlink name from the target path so two
    // different Group-Container sockets don't share one link.
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("agent");
    let stem = sanitize_component(file_name);
    let dir = state_upstreams_dir()?;
    let link = dir.join(format!("{stem}.sock"));

    // If a correct symlink already exists, reuse it.
    if let Ok(existing) = std::fs::read_link(&link)
        && existing == target
    {
        return Some(link);
    }

    std::fs::create_dir_all(&dir).ok()?;
    // Replace any stale link/file, then create the fresh symlink.
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(target, &link).ok()?;
    Some(link)
}

/// `$XDG_STATE_HOME/cache-warden/upstreams` (or `~/.local/state/...`).
#[cfg(target_os = "macos")]
fn state_upstreams_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("cache-warden/upstreams"))
}

/// Reduce a socket file name to a safe symlink stem (alnum / `-` / `_`).
#[cfg(target_os = "macos")]
fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .trim_end_matches(".sock")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "agent".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_group_container_path_is_returned_verbatim() {
        let p = PathBuf::from("/tmp/some-agent.sock");
        assert_eq!(resolve_upstream_path(&p), p);
    }

    #[test]
    fn linux_path_is_returned_verbatim() {
        // The ~/.1password/agent.sock Linux path is not a Group Container.
        let p = PathBuf::from("/home/user/.1password/agent.sock");
        assert_eq!(resolve_upstream_path(&p), p);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn group_container_path_is_redirected_to_a_state_symlink() {
        // Point XDG_STATE_HOME at a temp dir so the symlink lands there.
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: single-threaded test; restored below.
        let saved = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        // A fake target socket to link to (must exist for read_link reuse path,
        // though symlink creation itself does not require the target to exist).
        let target = tmp
            .path()
            .join("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"").unwrap();

        let resolved = resolve_upstream_path(&target);
        // The resolved path must differ from the input and live under the state
        // dir, and must be a symlink pointing back at the target.
        assert_ne!(resolved, target);
        assert!(resolved.starts_with(tmp.path().join("cache-warden/upstreams")));
        assert_eq!(std::fs::read_link(&resolved).unwrap(), target);

        // A second resolve reuses the existing link (idempotent).
        let resolved2 = resolve_upstream_path(&target);
        assert_eq!(resolved, resolved2);

        match saved {
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }
}
