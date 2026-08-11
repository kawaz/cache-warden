//! Test-only lock serializing process-global environment mutation.
//!
//! `cargo test` runs tests of one binary on parallel threads sharing a single
//! environment. Any test that `set_var`s a variable another test (or the code
//! under test) reads — `HOME` for `~` expansion, `XDG_STATE_HOME` for default
//! socket paths, the graceful-restart handoff fd — races with them: the CI
//! failure `authsock_socket_path_tilde_is_expanded` observed the runner's real
//! `HOME` because a sibling test restored it mid-flight. Every env-mutating
//! test must hold this lock for its whole mutate → observe → restore span.

use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the process-wide env-mutation lock. A panic while holding the lock
/// (an assert inside the critical section) poisons it; later tests still need
/// serialization, so poisoning is deliberately ignored.
pub fn lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
