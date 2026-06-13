//! E2E for `daemon register / unregister / status` (DR-0019).
//!
//! CI-safe coverage exercises the pure path through the real binary:
//! `daemon register --print` renders the service definition to stdout and
//! installs nothing. The live install (`launchctl bootstrap` / `systemctl
//! enable`) is gated behind `#[ignore]` (run manually) because it mutates the
//! per-user service manager — it uses a throwaway test label and cleans up.

use std::process::{Command, Output};

/// Invoke the built `cache-warden` binary with `args` in an isolated config
/// environment so nothing real is baked in and the `--print` output stays
/// deterministic across machines.
///
/// Config resolution checks `$CACHE_WARDEN_CONFIG`, then `$XDG_CONFIG_HOME`,
/// then `$HOME/.config` (`config::config_search_paths`). Overriding only
/// `CACHE_WARDEN_CONFIG` is not enough: a dogfooding host has a real
/// `~/.config/cache-warden/config.toml`, which the `$HOME` fallback would find
/// and bake into the rendered service definition. Point all three at a fresh
/// empty temp dir so every candidate resolves to a nonexistent file.
fn cw(args: &[&str]) -> Output {
    let isolated = tempfile::tempdir().expect("tempdir for isolated config env");
    Command::new(env!("CARGO_BIN_EXE_cache-warden"))
        .args(args)
        .env(
            "CACHE_WARDEN_CONFIG",
            isolated.path().join("nonexistent.toml"),
        )
        .env("XDG_CONFIG_HOME", isolated.path().join("xdg"))
        .env("HOME", isolated.path())
        .output()
        .expect("spawn cache-warden")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

// ---- `--print`: render only, install nothing (CI-safe) ------------------

#[test]
fn register_print_renders_definition_and_installs_nothing() {
    let o = cw(&[
        "daemon",
        "register",
        "--socket",
        "/tmp/cw-test.sock",
        "--label",
        "com.github.kawaz.cache-warden-printtest",
        "--print",
    ]);
    assert!(o.status.success(), "register --print should exit 0");
    let out = stdout(&o);

    if cfg!(target_os = "macos") {
        // launchd plist shape.
        assert!(out.contains("<plist version=\"1.0\">"), "plist: {out}");
        assert!(
            out.contains("<string>com.github.kawaz.cache-warden-printtest</string>"),
            "label baked in: {out}"
        );
        assert!(out.contains("<string>daemon</string>"), "{out}");
        assert!(out.contains("<string>run</string>"), "{out}");
        assert!(out.contains("<string>--socket</string>"), "{out}");
        assert!(out.contains("<string>/tmp/cw-test.sock</string>"), "{out}");
        assert!(out.contains("<key>KeepAlive</key>"), "{out}");
        assert!(out.contains("<key>RunAtLoad</key>"), "{out}");
        // PATH is baked in so `op` is found; no config existed → no CACHE_WARDEN_CONFIG.
        assert!(out.contains("<key>PATH</key>"), "{out}");
        assert!(
            !out.contains("CACHE_WARDEN_CONFIG"),
            "no config baked: {out}"
        );
    } else if cfg!(target_os = "linux") {
        // systemd unit shape.
        assert!(out.contains("[Service]"), "unit: {out}");
        assert!(out.contains("ExecStart="), "{out}");
        assert!(
            out.contains("daemon run --socket /tmp/cw-test.sock"),
            "{out}"
        );
        assert!(out.contains("Restart=on-failure"), "{out}");
        assert!(out.contains("WantedBy=default.target"), "{out}");
        assert!(out.contains("Environment=\"PATH="), "{out}");
        assert!(
            !out.contains("CACHE_WARDEN_CONFIG"),
            "no config baked: {out}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn register_print_plist_passes_plutil_lint() {
    // The rendered plist must be a well-formed property list. Pipe `--print`
    // output through `plutil -lint -` (reads stdin).
    use std::io::Write as _;
    use std::process::Stdio;

    let o = cw(&[
        "daemon",
        "register",
        "--label",
        "com.github.kawaz.cache-warden-linttest",
        "--print",
    ]);
    assert!(o.status.success());

    let mut child = Command::new("plutil")
        .args(["-lint", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plutil");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&o.stdout)
        .expect("write plist to plutil");
    let lint = child.wait_with_output().expect("plutil wait");
    assert!(
        lint.status.success(),
        "plutil -lint rejected the rendered plist: {}",
        String::from_utf8_lossy(&lint.stderr)
    );
}

// ---- live install (manual; mutates the service manager) -----------------

/// Full register → status → unregister loop against the real service manager.
///
/// Ignored by default: it actually bootstraps a launchd / systemd service. Run
/// manually with `cargo test --test service_e2e -- --ignored`. Uses a throwaway
/// label and always cleans up (unregister) at the end, even on assertion
/// failure (via a drop guard).
#[test]
#[ignore = "mutates the per-user service manager; run manually with --ignored"]
fn live_register_status_unregister_roundtrip() {
    let label = format!("com.github.kawaz.cache-warden-test-{}", std::process::id());
    let socket = format!("/tmp/cw-test-{}.sock", std::process::id());

    // Drop guard: always attempt unregister so a failed assertion never leaves
    // a stray service registered.
    struct Cleanup {
        label: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new(env!("CARGO_BIN_EXE_cache-warden"))
                .args(["daemon", "unregister", "--label", &self.label])
                .output();
        }
    }
    let _guard = Cleanup {
        label: label.clone(),
    };

    // register
    let reg = cw(&["daemon", "register", "--socket", &socket, "--label", &label]);
    assert!(
        reg.status.success(),
        "register failed: {}",
        String::from_utf8_lossy(&reg.stderr)
    );

    // status: registered + (eventually) running
    let st = cw(&["daemon", "status", "--label", &label]);
    assert!(st.status.success());
    let st_out = stdout(&st);
    assert!(st_out.contains("registered: yes"), "status: {st_out}");
    assert!(st_out.contains(&label), "status names the label: {st_out}");

    // unregister
    let unreg = cw(&["daemon", "unregister", "--label", &label]);
    assert!(unreg.status.success());

    // status after unregister: not registered
    let st2 = cw(&["daemon", "status", "--label", &label]);
    assert!(st2.status.success());
    assert!(
        stdout(&st2).contains("registered: no"),
        "should be gone: {}",
        stdout(&st2)
    );
}
