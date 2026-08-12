//! `cache-warden-approver` — draft-DR-0031 §3 案 (b) の **常駐 GUI helper**。
//!
//! # スコープ (Phase 1.6 Block 1: helper 常駐化)
//!
//! - `--socket <path>` (or `CACHE_WARDEN_APPROVER_SOCKET`) 指定時は **daemon
//!   に 1 本の接続を張ったまま**、`ApproveRequest` を JSON Lines で N 回読み、
//!   各 request につき LAAuthenticationView 埋め込みの承認 dialog を表示、
//!   outcome (Approved / BiometricFailed / Cancelled) を `ApproveResponse` に
//!   詰めて **同じ接続に書き戻す**。dialog は request ごとに新規作成 + close で
//!   閉じ、次の request を待つ (§3 採用案 (b)、§8 一連の approval は人間操作で
//!   直列)
//! - focus 奪取 (`.Accessory` activation policy を維持したまま `/usr/bin/open`
//!   経由で LaunchServices に activate させる、draft-DR-0031 §UX policy)
//! - Cancel button / window close (Cmd+W, close button) → `Outcome::Cancelled` を
//!   送信して window を閉じる。これは Rust 側 delegate class
//!   (`ApproverDelegate`) で実装 — Phase 1.4 の「terminate: 直結 +
//!   `WillTerminate` observer」は常駐化では使えない (terminate すると 2 件目
//!   以降の request が来ても helper が居ない) ため置き換え
//! - `LAContext.evaluatePolicy` の completion block 内で outcome を確定して
//!   dialog を閉じる。completion block が呼ばれるスレッドは Apple の契約に
//!   無いので、AppKit 操作 (window.close()) は必ず `dispatch_main` 経由で
//!   main queue に投げ直す
//! - `ApproveRequest.timeout_secs` を helper 自身の countdown として消費する
//!   (`arm_dialog_timeout`): 期限までに人間が答えなければ dialog を自分で
//!   閉じて `Outcome::Timeout` を返し、次の request に進む。放置 dialog が
//!   後続 request を無期限に塞ぐ可用性 DoS の根治
//! - daemon が接続を切ったら (read が 0 バイト EOF) helper 側も terminate
//!   (§7 の逆方向: daemon が居ないのに常駐しない)
//! - `--socket` 無しの standalone dialog (dev 単独起動) は **debug build
//!   限定**。release build は同一 uid の攻撃者が hardcoded サマリで TouchID
//!   prompt を出せる経路を持たないよう起動を拒否する
//!
//! # 意図的な非スコープ (後続 Phase)
//!
//! - Requester icon / チップ / 詳細展開 UI (Phase 2)
//! - kqueue で peer_gone 検知 (Phase 2)

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod approver {
    use block2::RcBlock;
    use std::ffi::c_void;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    /// `register_focus_steal_on_launch` (debug-only standalone path) 専用。
    #[cfg(debug_assertions)]
    use std::ptr::NonNull;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, Bool, NSObject, NSObjectProtocol, ProtocolObject};
    use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, sel};
    #[cfg(debug_assertions)]
    use objc2_app_kit::NSApplicationDidFinishLaunchingNotification;
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSButton, NSControlSize,
        NSFloatingWindowLevel, NSStackView, NSStackViewDistribution, NSTextField,
        NSUserInterfaceLayoutOrientation, NSWindow, NSWindowDelegate, NSWindowStyleMask,
    };
    #[cfg(debug_assertions)]
    use objc2_foundation::NSNotificationCenter;
    use objc2_foundation::{NSError, NSNotification, NSPoint, NSRect, NSSize, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use objc2_local_authentication_embedded_ui::LAAuthenticationView;

    use cache_warden_approver::wire::{
        ApproveRequest, ApproveResponse, HelperRequest, HelperResponse, Outcome, WIRE_VERSION,
    };

    // --- libdispatch FFI: main-queue への任意 closure dispatch -------------
    //
    // background reader thread が確定した「次の request」を main thread に届け、
    // またLAcompletion block が (念のため) window.close() を main thread で
    // 呼ぶために `dispatch_async_f(dispatch_get_main_queue(), ...)` を使う。
    // dispatch2 crate 等の高レベル wrapper 依存を追加せず、raw FFI で最小限。

    #[link(name = "System", kind = "dylib")]
    unsafe extern "C" {
        static _dispatch_main_q: c_void;
        fn dispatch_async_f(
            queue: *mut c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
        /// `dispatch_time_t dispatch_time(dispatch_time_t when, int64_t delta)`
        /// — `when = DISPATCH_TIME_NOW (0)` makes `delta` (nanoseconds) an
        /// offset from now.
        fn dispatch_time(when: u64, delta: i64) -> u64;
        fn dispatch_after_f(
            when: u64,
            queue: *mut c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    /// `DISPATCH_TIME_NOW` (`dispatch/time.h`).
    const DISPATCH_TIME_NOW: u64 = 0;

    /// Box a `FnOnce` into the thin `*mut c_void` + trampoline pair libdispatch
    /// can carry. See [`dispatch_main`]'s comment for why the two-level `Box`
    /// is required.
    fn into_dispatch_context<F: FnOnce() + Send + 'static>(
        f: F,
    ) -> (*mut c_void, unsafe extern "C" fn(*mut c_void)) {
        let boxed: Box<Box<dyn FnOnce() + Send + 'static>> = Box::new(Box::new(f));
        unsafe extern "C" fn trampoline(ctx: *mut c_void) {
            let boxed: Box<Box<dyn FnOnce() + Send + 'static>> =
                unsafe { Box::from_raw(ctx as *mut Box<dyn FnOnce() + Send + 'static>) };
            (*boxed)();
        }
        (Box::into_raw(boxed) as *mut c_void, trampoline)
    }

    /// 任意の `FnOnce` を libdispatch の main queue で実行する。`Send` を要求
    /// するのは dispatch がスレッド越境するため — main thread only な
    /// `Retained<T>` 等を capture することはできない (SendWrapper 経由で
    /// 「main で使う限り安全」を宣言する場合を除く)。
    fn dispatch_main<F: FnOnce() + Send + 'static>(f: F) {
        // `Box<Box<dyn FnOnce>>` の 2 段 Box は「thin pointer で受け渡す」ため。
        // dispatch は `*mut c_void` しか運べないので、`Box<dyn FnOnce>` (= fat
        // pointer) を直接 into_raw できず、もう 1 段 Box して thin にする。
        let (ctx, trampoline) = into_dispatch_context(f);
        unsafe {
            dispatch_async_f(
                &_dispatch_main_q as *const _ as *mut c_void,
                ctx,
                trampoline,
            );
        }
    }

    /// `dispatch_main` の遅延版 — `secs` 秒後に main queue で `f` を実行する。
    /// timer 相当を sleep ループなしで組む唯一の main-thread-safe な primitive
    /// (kernel timer に載るので待っている間の CPU / wakeup が無い)。
    ///
    /// `dispatch_after` は発火をキャンセルできないので、呼び側は「発火時に
    /// まだ意味があるか」を共有 state (take-once slot) で判定する — 詳しくは
    /// [`arm_dialog_timeout`]。
    fn dispatch_main_after<F: FnOnce() + Send + 'static>(secs: u32, f: F) {
        let (ctx, trampoline) = into_dispatch_context(f);
        unsafe {
            let when = dispatch_time(DISPATCH_TIME_NOW, i64::from(secs) * 1_000_000_000);
            dispatch_after_f(
                when,
                &_dispatch_main_q as *const _ as *mut c_void,
                ctx,
                trampoline,
            );
        }
    }

    /// `Retained<T>` を「main thread からしか触らない」約束の下で `Send` に
    /// 見せかける unsafe wrapper。dispatch closure に main-thread-only オブジェクト
    /// (NSWindow 等) を渡すために使う。dispatch 先も main queue なので約束は
    /// 履行される。
    ///
    /// **必ず main thread の dispatch 内でだけ inner を触ること**。それ以外の
    /// スレッドから触るのは UB。
    struct MainOnlySend<T>(T);
    unsafe impl<T> Send for MainOnlySend<T> {}
    unsafe impl<T> Sync for MainOnlySend<T> {}

    impl<T> MainOnlySend<T> {
        /// Unwrap on the main thread.
        ///
        /// Needed as a *method* rather than plain `.0` field access at the
        /// capture site: Rust 2021 captures closure state per field path, so
        /// `move || wrapper.0.foo()` captures the inner `T` — dropping the
        /// `Send` this wrapper exists to assert. Calling a method forces the
        /// whole wrapper into the closure.
        fn into_inner(self) -> T {
            self.0
        }
    }

    // --- IPC 経路 -----------------------------------------------------------

    /// Resolve the daemon IPC socket path from `--socket <path>` /
    /// `--socket=<path>` or the `CACHE_WARDEN_APPROVER_SOCKET` env var.
    /// `None` means standalone mode (no daemon, hardcoded summary).
    fn resolve_socket_path() -> Option<PathBuf> {
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--socket" {
                if let Some(val) = args.next() {
                    return Some(PathBuf::from(val));
                }
            } else if let Some(val) = arg.strip_prefix("--socket=") {
                return Some(PathBuf::from(val));
            }
        }
        std::env::var_os("CACHE_WARDEN_APPROVER_SOCKET").map(PathBuf::from)
    }

    use cache_warden_approver::CACHE_WARDEN_IDENTIFIER_PREFIX;

    /// Verify the daemon peer on the just-connected `UnixStream` has the
    /// same code-signature identity as this helper (draft-DR-0031
    /// §Security). Fail-closed on every deviation — the caller aborts
    /// without ever building UI or reading requests.
    fn verify_daemon_peer(stream: &UnixStream) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        macos_process_inspect::codesign::verify_peer(
            stream.as_raw_fd(),
            CACHE_WARDEN_IDENTIFIER_PREFIX,
        )
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("daemon peer failed code-signature verification: {e}"),
            )
        })
    }

    /// Requester 表示名 (`responsible_bundle_id` 優先、fallback は chain 先頭の
    /// basename)。
    fn requester_display_name(req: &ApproveRequest) -> String {
        if let Some(bundle_id) = &req.requester.responsible_bundle_id {
            return bundle_id.clone();
        }
        req.requester
            .chain
            .first()
            .map(|entry| {
                Path::new(&entry.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| entry.path.clone())
            })
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "requester".to_string())
    }

    /// Summary 行。operation を動詞句にして「何が起きるか」を dialog に示す
    /// (wire doc の「helper only displays it, never branches」どおり、未知の
    /// operation は verbatim 表示に落として認可判断には使わない)。
    fn summary_line(req: &ApproveRequest) -> String {
        let verb = match req.operation.as_str() {
            "sign" => "sign with",
            "get" | "extend" | "regenerate" | "pin" => "read",
            other => other,
        };
        format!(
            "Allow {} to {} {}",
            requester_display_name(req),
            verb,
            req.key
        )
    }

    /// Direct blocking write of `ApproveResponse` on the shared writer. Idempotent
    /// callers wrap this with a "take once" slot to enforce single-send per
    /// request (Cancel / Approved / BiometricFailed の競合防止)。
    fn write_response(
        writer: &Arc<Mutex<UnixStream>>,
        request_id: &str,
        outcome: Outcome,
        biometric_kind: Option<String>,
    ) {
        write_line(
            writer,
            &HelperResponse::Approve(ApproveResponse {
                v: WIRE_VERSION,
                request_id: request_id.to_string(),
                outcome,
                biometric_kind,
            }),
        );
    }

    /// Serialize one enveloped response and write it to the daemon.
    fn write_line(writer: &Arc<Mutex<UnixStream>>, resp: &HelperResponse) {
        match serde_json::to_string(resp) {
            Ok(mut line) => {
                line.push('\n');
                let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = w.write_all(line.as_bytes()).and_then(|_| w.flush()) {
                    eprintln!("cache-warden-approver: failed to send ApproveResponse: {e}");
                }
            }
            Err(e) => eprintln!("cache-warden-approver: failed to encode ApproveResponse: {e}"),
        }
    }

    // --- per-request 状態 + delegate class ---------------------------------

    /// A single approval request's in-flight state. Held by the delegate's
    /// ivar (Mutex-wrapped) and taken exactly once by whichever finalize path
    /// fires first — LA completion block (`Approved`/`BiometricFailed`), Cancel
    /// button (`Cancelled`), or `windowWillClose:` (`Cancelled`). Whoever
    /// `take()`s writes the response + signals the background reader; the
    /// losing paths see `None` and no-op.
    struct PendingOutcome {
        writer: Arc<Mutex<UnixStream>>,
        request_id: String,
        /// Fires exactly once to unblock the background reader (which is
        /// awaiting the next line only after the current request's finalize).
        completion_tx: mpsc::SyncSender<()>,
    }

    /// Shared per-request pending slot — cloned into (a) the delegate's ivar,
    /// (b) the LA completion block, and (c) the Cancel button's action path
    /// (via the delegate). Whichever site takes first "wins" and writes the
    /// response + signals the background reader.
    type PendingSlot = Arc<Mutex<Option<PendingOutcome>>>;

    /// The main-thread-only objects the countdown timer needs to shut a
    /// timed-out dialog down (`LAContext` to `invalidate()`, `NSWindow` to
    /// `close()`).
    struct DialogHandles {
        ctx: Retained<LAContext>,
        window: Retained<NSWindow>,
    }

    /// Shared slot holding the countdown timer's [`DialogHandles`].
    ///
    /// `dispatch_after` cannot be cancelled, so "disarming" the timer means
    /// emptying this slot: the fired closure finds `None` and returns without
    /// touching AppKit, and — the reason the slot exists at all — the
    /// retained `NSWindow` / `LAContext` drop the moment the dialog is
    /// answered instead of lingering until the timer's (up to
    /// `timeout_secs`-long) deadline. On a persistent helper that lingering
    /// would otherwise pile up one window per approval.
    ///
    /// **Only ever taken/dropped on the main thread** — every finalize path
    /// either already runs there (AppKit delegate callbacks, the timer
    /// closure itself) or goes through [`dispatch_main`] first (the LA
    /// completion block, whose thread Apple does not contract).
    type TimerSlot = Arc<Mutex<Option<MainOnlySend<DialogHandles>>>>;

    /// Delegate class fields. `pending` is the shared take-once slot the LA
    /// completion block also holds; `ctx` is the per-request `LAContext`
    /// that this delegate's Cancel paths (`cancelClicked:` /
    /// `windowWillClose:`) call `invalidate()` on to unblock the pending
    /// `evaluatePolicy` — see the invalidate calls below for the leak-
    /// avoidance rationale; `timer` is the countdown's handle slot, emptied
    /// by those same paths (see [`TimerSlot`]). Storing `Retained<LAContext>`
    /// here is consistent with the delegate being `MainThreadOnly`.
    struct DelegateIvars {
        pending: PendingSlot,
        ctx: Retained<LAContext>,
        timer: TimerSlot,
    }

    define_class!(
        // `MainThreadOnly` は `NSWindowDelegate` conformance の要件。AppKit
        // の delegate callbacks は main thread からしか呼ばれないので、
        // conformance と実際の呼出 thread の両方が揃う。
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "CacheWardenApproverDelegate"]
        #[ivars = DelegateIvars]
        struct ApproverDelegate;

        impl ApproverDelegate {
            /// Cancel button の target/action。`windowWillClose:` と違い、
            /// window はまだ open なので明示的に close する必要がある。
            #[unsafe(method(cancelClicked:))]
            fn cancel_clicked(&self, sender: Option<&AnyObject>) {
                finalize_cancelled(&self.ivars().pending);
                // Disarm the countdown (main thread — this is an AppKit
                // action), releasing the window / LAContext it retains.
                disarm_dialog_timeout(&self.ivars().timer);
                // Invalidate `LAContext` so the pending `evaluatePolicy`
                // completion block fires (with `LAErrorAppCancel`). That
                // block owns a strong reference to `self` (see the
                // `delegate_for_block` capture in `show_dialog_on_main`),
                // so without this call the block would sit unresolved
                // forever — leaking this delegate + `LAContext` +
                // `NSWindow` for every Cancelled approval, and the helper
                // is persistent so those leaks would accumulate for the
                // daemon's lifetime.
                unsafe { self.ivars().ctx.invalidate() };
                // NSButton の superview / superview の window を辿って close。
                // Cancel button 自身から window を確実に取得する経路。
                if let Some(sender) = sender
                    && let Some(button) = sender.downcast_ref::<NSButton>()
                    && let Some(window) = button.window()
                {
                    window.close();
                }
            }

            /// NSWindowDelegate: window close の直前に発火。Cancel button /
            /// LA block が既に take していれば no-op、Cmd+W / close button
            /// から発火した場合は Cancelled を送信する。
            #[unsafe(method(windowWillClose:))]
            fn window_will_close(&self, _notif: &NSNotification) {
                finalize_cancelled(&self.ivars().pending);
                disarm_dialog_timeout(&self.ivars().timer);
                // Same leak-avoidance rationale as `cancelClicked:` —
                // Cmd+W / red close-button paths reach here without going
                // through the Cancel button, but the pending
                // `evaluatePolicy` still needs to be released so this
                // delegate can deallocate.
                unsafe { self.ivars().ctx.invalidate() };
            }
        }

        unsafe impl NSObjectProtocol for ApproverDelegate {}

        unsafe impl NSWindowDelegate for ApproverDelegate {}
    );

    impl ApproverDelegate {
        fn new(
            mtm: MainThreadMarker,
            pending: PendingSlot,
            ctx: Retained<LAContext>,
            timer: TimerSlot,
        ) -> Retained<Self> {
            let ivars = DelegateIvars {
                pending,
                ctx,
                timer,
            };
            let this = Self::alloc(mtm).set_ivars(ivars);
            unsafe { objc2::msg_send![super(this), init] }
        }
    }

    /// Send `Cancelled` exactly once (Cancel button / windowWillClose / any
    /// path), then unblock the background reader. Idempotent — the second
    /// caller sees `None` and no-ops.
    fn finalize_cancelled(slot: &PendingSlot) {
        let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(pending) = taken else {
            return;
        };
        let PendingOutcome {
            writer,
            request_id,
            completion_tx,
        } = pending;
        write_response(&writer, &request_id, Outcome::Cancelled, None);
        let _ = completion_tx.send(());
    }

    /// Empty the countdown's handle slot. **Main thread only** (the handles
    /// are `Retained` AppKit / LocalAuthentication objects). Idempotent.
    fn disarm_dialog_timeout(timer: &TimerSlot) {
        let _ = timer.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// Arm the dialog's own countdown from `ApproveRequest.timeout_secs`.
    ///
    /// Without this the helper would keep an unanswered dialog on screen
    /// forever: the reader thread is deliberately serial (§8 approvals are
    /// human-serial), so one abandoned dialog stalls every subsequent
    /// request — the daemon's own 90 s timeout only frees *its* caller, not
    /// the helper's queue. On expiry we answer the request ourselves with
    /// [`Outcome::Timeout`], invalidate the `LAContext` (which fires the
    /// pending `evaluatePolicy` block so it can release the delegate) and
    /// close the window, letting the reader move on to the next request.
    ///
    /// Racing the human is safe in both directions: the outcome is written
    /// by whoever wins the take-once `pending` slot, and if the user won,
    /// this closure does nothing at all. A daemon-side timeout that already
    /// fired is harmless too — the daemon discards responses whose
    /// `request_id` no longer matches its pending request.
    ///
    /// `timeout_secs == 0` means "no countdown wanted" (the wire field is a
    /// hint from the daemon, not a contract), so the timer is not armed.
    fn arm_dialog_timeout(timeout_secs: u32, pending: PendingSlot, timer: TimerSlot) {
        if timeout_secs == 0 {
            return;
        }
        dispatch_main_after(timeout_secs, move || {
            // Runs on the main queue. `None` = some finalize path already
            // disarmed us; nothing to close and nothing to answer.
            let Some(handles) = timer.lock().unwrap_or_else(|e| e.into_inner()).take() else {
                return;
            };
            let taken = pending.lock().unwrap_or_else(|e| e.into_inner()).take();
            let Some(PendingOutcome {
                writer,
                request_id,
                completion_tx,
            }) = taken
            else {
                // The user answered between the slot check above and here;
                // their outcome stands. Dropping `handles` is all we do.
                return;
            };
            eprintln!(
                "cache-warden-approver: no answer within {timeout_secs}s, closing the dialog \
                 (request_id={request_id:?})"
            );
            write_response(&writer, &request_id, Outcome::Timeout, None);
            let _ = completion_tx.send(());
            // Same leak-avoidance rationale as the Cancel paths: the
            // pending `evaluatePolicy` block holds the delegate alive until
            // it fires, and `invalidate` is what makes it fire.
            unsafe { handles.0.ctx.invalidate() };
            handles.0.window.close();
        });
    }

    // --- window / UI --------------------------------------------------------

    /// activation policy を `.Accessory` に固定する (LSUIElement=YES と一致)。
    fn init_app(mtm: MainThreadMarker) -> Retained<NSApplication> {
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        app
    }

    fn make_floating_panel(mtm: MainThreadMarker) -> Retained<NSWindow> {
        let content_rect = NSRect {
            origin: NSPoint { x: 0.0, y: 0.0 },
            size: NSSize {
                width: 400.0,
                height: 325.0,
            },
        };
        let style = NSWindowStyleMask::Titled | NSWindowStyleMask::Closable;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                content_rect,
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        window.setLevel(NSFloatingWindowLevel);
        window.setTitle(&NSString::from_str("cache-warden approver"));
        // Cancel/close 時に process ごと落とすのではなく window だけ閉じる。
        // 常駐 helper 化に伴う必須変更 (Phase 1.4 の `releasedWhenClosed = true`
        // + terminate: パターンからの脱却)。
        unsafe { window.setReleasedWhenClosed(false) };
        window
    }

    /// Build content view + Cancel button. Cancel button の target は delegate、
    /// action は `cancelClicked:` セレクタ。delegate 側で「Cancelled 送信 +
    /// window.close()」を担う。
    fn build_content(
        mtm: MainThreadMarker,
        delegate: &ApproverDelegate,
        ctx: &LAContext,
        summary_text: &str,
    ) -> (
        Retained<NSStackView>,
        Retained<LAAuthenticationView>,
        Retained<NSButton>,
    ) {
        let stack = NSStackView::new(mtm);
        stack.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
        stack.setDistribution(NSStackViewDistribution::Fill);

        let summary = NSTextField::labelWithString(&NSString::from_str(summary_text), mtm);
        stack.addArrangedSubview(&summary);

        let auth_view = unsafe {
            LAAuthenticationView::initWithContext_controlSize(
                LAAuthenticationView::alloc(mtm),
                ctx,
                NSControlSize::Large,
            )
        };
        stack.addArrangedSubview(&auth_view);

        let cancel = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str("Cancel"),
                Some(delegate.as_ref()),
                Some(sel!(cancelClicked:)),
                mtm,
            )
        };
        stack.addArrangedSubview(&cancel);

        (stack, auth_view, cancel)
    }

    /// draft-DR-0031 §UX policy の focus 奪取。
    fn steal_focus(window: &NSWindow) {
        window.orderFrontRegardless();
        window.makeKeyWindow();

        let bundle = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.ancestors().nth(3).map(std::path::Path::to_path_buf))
            .filter(|p| p.extension().is_some_and(|ext| ext == "app"));
        match bundle {
            Some(bundle) => {
                let spawned = std::process::Command::new("/usr/bin/open")
                    .arg(&bundle)
                    .spawn();
                eprintln!(
                    "cache-warden-approver: steal_focus: open {} -> spawn = {}",
                    bundle.display(),
                    spawned.is_ok()
                );
            }
            None => eprintln!(
                "cache-warden-approver: steal_focus: not in .app bundle, skip open-based activation"
            ),
        }
    }

    // --- main-thread 側: request → dialog 表示 -----------------------------

    /// **Called on main thread only** (via `dispatch_main`). 1 件の
    /// `ApproveRequest` に対して:
    /// 1. delegate + pending state を作る
    /// 2. window + content を組み立て、delegate を window の delegate に据える
    /// 3. LAContext.evaluatePolicy を発火 (completion block が Approved /
    ///    BiometricFailed を確定)
    /// 4. window を中央に置いて表示 + focus 奪取
    ///
    /// `completion_tx` は「1 件の dialog が終わった (outcome 送信完了)」を
    /// background reader thread に signal するチャネル。sleep/polling 不使用
    /// (mpsc は event-driven blocking recv)。
    fn show_dialog_on_main(
        req: ApproveRequest,
        writer: Arc<Mutex<UnixStream>>,
        completion_tx: mpsc::SyncSender<()>,
    ) {
        let mtm = MainThreadMarker::new().expect("show_dialog_on_main must run on main thread");
        let app = NSApplication::sharedApplication(mtm);
        let window = make_floating_panel(mtm);
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };
        let summary_text = summary_line(&req);

        let pending = PendingOutcome {
            writer: writer.clone(),
            request_id: req.request_id.clone(),
            completion_tx: completion_tx.clone(),
        };
        let pending_slot: PendingSlot = Arc::new(Mutex::new(Some(pending)));
        let timer_slot: TimerSlot = Arc::new(Mutex::new(Some(MainOnlySend(DialogHandles {
            ctx: Retained::clone(&ctx),
            window: Retained::clone(&window),
        }))));
        let delegate = ApproverDelegate::new(
            mtm,
            pending_slot.clone(),
            Retained::clone(&ctx),
            timer_slot.clone(),
        );

        let (stack, _auth_view, _cancel) = build_content(mtm, &delegate, &ctx, &summary_text);
        window.setContentView(Some(&stack));
        let delegate_as_window_delegate: &ProtocolObject<dyn NSWindowDelegate> =
            ProtocolObject::from_ref(&*delegate);
        window.setDelegate(Some(delegate_as_window_delegate));

        window.center();
        window.makeKeyAndOrderFront(None);
        steal_focus(&window);

        // Keep the app alive: activation policy already .Accessory since init.
        let _ = app; // suppress unused

        // --- LA evaluatePolicy completion block ---
        //
        // Apple does not contract which queue this block runs on (main is
        // what we observe in practice, but that is not a guarantee), so the
        // block itself only does thread-safe work: the outcome goes out
        // through the `writer` Mutex, and every AppKit / main-thread-only
        // operation (window.close(), releasing the countdown's retained
        // handles) is dispatched onto the main queue.
        //
        // `delegate_for_block`: anchor the delegate's lifetime to this
        // block's. Both `NSWindow::setDelegate` and
        // `NSButton::buttonWithTitle_target_action`'s `target` are
        // *unretained*, so without a strong ref held somewhere `delegate`
        // would deallocate on `show_dialog_on_main`'s return and every
        // subsequent Cancel-flavored callback would `msg_send` to a nil
        // pointer (silent no-op) — leaving the daemon waiting for an
        // outcome that never arrives. `LAContext` keeps this block alive
        // until `evaluatePolicy` completes (or is `invalidate`d — which is
        // precisely how the Cancel paths bring the block to fire), so
        // capturing `delegate` here holds it exactly as long as needed.
        let pending_slot_for_block = pending_slot.clone();
        let timer_slot_for_block = timer_slot.clone();
        let window_for_block = MainOnlySend(Retained::clone(&window));
        let delegate_for_block = MainOnlySend(Retained::clone(&delegate));

        let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            // Force the closure to own `delegate_for_block` for its whole
            // lifetime. We never read it here; the point is to bind the
            // delegate's refcount to the block's refcount, per the
            // `delegate_for_block` docstring above.
            let _keep_delegate_alive_until_block_drops = &delegate_for_block;
            // Take pending; if Cancel/windowWillClose beat us, we've already
            // sent Cancelled — no-op.
            let taken = pending_slot_for_block
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            let Some(pending) = taken else {
                return;
            };
            let PendingOutcome {
                writer,
                request_id,
                completion_tx,
            } = pending;
            let outcome = if ok.as_bool() {
                Outcome::Approved
            } else {
                Outcome::BiometricFailed
            };
            write_response(&writer, &request_id, outcome, Some("TouchID".to_string()));
            let _ = completion_tx.send(());
            // `window.close()` and dropping the countdown's retained
            // handles are main-thread-only; hop to the main queue rather
            // than trusting whichever thread LocalAuthentication called us
            // on. Retaining the window here (`Retained::clone`) is
            // thread-safe on its own — `objc_retain` is atomic; it is
            // *using* AppKit objects that main-thread affinity is about.
            let window_for_close = MainOnlySend(Retained::clone(&window_for_block.0));
            let timer_for_close = timer_slot_for_block.clone();
            dispatch_main(move || {
                disarm_dialog_timeout(&timer_for_close);
                window_for_close.into_inner().close();
            });
        });

        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str("Authenticate to access secret"),
                &block,
            );
        }

        // Start the countdown only once the dialog is up and the policy
        // evaluation is running: the deadline the daemon sent is about how
        // long a *human* gets, so it should not be consumed by our own setup.
        arm_dialog_timeout(req.timeout_secs, pending_slot, timer_slot);
    }

    // --- Full Disk Access explainer -----------------------------------------

    /// The Full Disk Access explainer window (draft-DR-0031 の UX 仕様、issue
    /// `2026-08-12-fda-grant-flow-hardening`)。
    ///
    /// # なぜ設定画面を直接開かないか
    ///
    /// 突然 System Settings が前面に出ても、ユーザは「どのアプリが何のために
    /// 開いたのか」が分からない (複数アプリが同時に同じことをすれば尚更)。
    /// なので **まず説明を出し、開くのはユーザがボタンを押した時だけ** にする。
    ///
    /// # 承認 dialog との共存
    ///
    /// この window は floating level にせず、focus も奪わない (`orderFront`
    /// のみ、`steal_focus` の LaunchServices 経由 activate は使わない)。
    /// 承認 dialog は focus が無いと指紋 sensor input が届かない
    /// (draft-DR-0031 §UX policy) ので、こちらが focus を取り合うと **承認が
    /// 完了できなくなる**。急ぐのは承認、待てるのが FDA 付与、という優先順位を
    /// window の見た目 (level / activation) で表現している。
    ///
    /// 表示言語は日本語 — 同じ FDA 付与フローの先行実装 (`daemon register` の
    /// 誘導メッセージ) が日本語で、同一手順の説明が言語で割れる方が読み手に
    /// とって不親切なため。承認 dialog の英語表記とは別surface として扱う。
    mod fda {
        use super::{
            Arc, MainOnlySend, Mutex, UnixStream, dispatch_main, dispatch_main_after, init_app,
            write_line,
        };
        use objc2::rc::Retained;
        use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
        use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, sel};
        use objc2_app_kit::{
            NSApplication, NSBackingStoreType, NSButton, NSColor, NSStackView,
            NSStackViewDistribution, NSTextField, NSUserInterfaceLayoutOrientation, NSWindow,
            NSWindowDelegate, NSWindowStyleMask,
        };
        use objc2_foundation::{
            NSDistributedNotificationCenter, NSNotification, NSNotificationSuspensionBehavior,
            NSPoint, NSRect, NSSize, NSString,
        };
        use std::sync::atomic::{AtomicBool, Ordering};

        use cache_warden_approver::wire::{
            FdaOutcome, FdaPromptRequest, FdaPromptResponse, HelperResponse, WIRE_VERSION,
        };

        /// The distributed notification macOS posts when a TCC authorization
        /// changes, used purely as a wake-up hint.
        ///
        /// **Private implementation detail, not API**: the name exists in
        /// Apple's own binaries and other software subscribes to it, but
        /// Apple documents neither the name, its firing conditions, nor any
        /// payload (`docs/findings/2026-08-12-tcc-change-event-feasibility.md`).
        /// So it is confined to this one constant, and nothing here treats
        /// receiving it as evidence of a grant — the authority is always the
        /// probe, and [`schedule_poll`] keeps the window correct if the
        /// notification never arrives or is renamed out from under us.
        const TCC_CHANGED_NOTIFICATION: &str = "com.apple.tcc.access.changed";

        /// Poll cadence for the fallback re-probe, while the window is open.
        const POLL_INTERVAL_SECS: u32 = 2;

        const WINDOW_WIDTH: f64 = 460.0;
        const TEXT_WIDTH: f64 = 420.0;

        const HEADING: &str = "cache-warden にフルディスクアクセスを許可してください";
        const WHY: &str = "cache-warden はシークレットの取得に 1Password CLI (op) を起動します。\
            フルディスクアクセスが無いと、op を起動するたびに macOS の許可ダイアログが表示されます。";
        const HOW: &str = "下のボタンで設定画面を開き、リストの「CacheWarden」を探して\
            スイッチを ON にしてください。";
        const DECLINE_NOTE: &str = "許可しなくても cache-warden は使えます。\
            その場合はアップデートのたびに確認ダイアログが出るので、都度 OK してください。";
        const STATUS_NOT_GRANTED: &str = "現在: 未許可";
        const STATUS_GRANTED: &str = "設定が確認できました。このダイアログは閉じて構いません。";

        /// At most one explainer at a time. The daemon asks once per start, but
        /// a second request (a restart racing the first window, a future
        /// caller) must raise the existing window rather than stack another.
        static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);

        /// The live explainer's main-thread state.
        struct FdaDialog {
            window: Retained<NSWindow>,
            status: Retained<NSTextField>,
            /// The window's delegate and both buttons' target. AppKit holds
            /// all three *unretained*, so this is the strong reference that
            /// keeps the callbacks alive.
            delegate: Retained<FdaDelegate>,
            writer: Arc<Mutex<UnixStream>>,
            request_id: String,
            granted: bool,
            /// Whether an [`FdaPromptResponse`] has already gone out. Grant
            /// answers immediately (while the window stays up for the user to
            /// read); otherwise the answer is written when the window closes.
            answered: bool,
        }

        /// The shared slot holding the live explainer, if any.
        ///
        /// Taking the dialog out of the slot is what ends its life: the poll
        /// closure finds `None` and stops re-arming, and — since the delegate
        /// holds a clone of this same `Arc` — dropping the dialog is also what
        /// breaks the delegate↔slot reference cycle. **Main thread only**: the
        /// contents are AppKit objects.
        type FdaSlot = Arc<Mutex<Option<MainOnlySend<FdaDialog>>>>;

        struct FdaIvars {
            slot: FdaSlot,
        }

        define_class!(
            #[unsafe(super(NSObject))]
            #[thread_kind = MainThreadOnly]
            #[name = "CacheWardenFdaDelegate"]
            #[ivars = FdaIvars]
            struct FdaDelegate;

            impl FdaDelegate {
                /// "設定を開く" ボタン。ここで初めて System Settings を開く。
                #[unsafe(method(openSettingsClicked:))]
                fn open_settings_clicked(&self, _sender: Option<&AnyObject>) {
                    if let Err(e) = macos_tcc::open_settings(macos_tcc::Permission::FullDiskAccess)
                    {
                        eprintln!(
                            "cache-warden-approver: could not open the Full Disk Access settings pane: {e}"
                        );
                    }
                }

                /// "閉じる" ボタン。`windowWillClose:` が後始末を担う。
                #[unsafe(method(closeClicked:))]
                fn close_clicked(&self, _sender: Option<&AnyObject>) {
                    let window = {
                        let guard = self
                            .ivars()
                            .slot
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        guard.as_ref().map(|d| Retained::clone(&d.0.window))
                    };
                    if let Some(window) = window {
                        window.close();
                    }
                }

                /// [`TCC_CHANGED_NOTIFICATION`] 受信 — 権限が動いたので
                /// probe し直す。通知が来ない環境でも [`schedule_poll`] が
                /// 拾うので、この経路が無音でも壊れない。
                #[unsafe(method(tccChanged:))]
                fn tcc_changed(&self, _notif: &NSNotification) {
                    refresh(&self.ivars().slot);
                }

                #[unsafe(method(windowWillClose:))]
                fn window_will_close(&self, _notif: &NSNotification) {
                    finalize(&self.ivars().slot);
                }
            }

            unsafe impl NSObjectProtocol for FdaDelegate {}

            unsafe impl NSWindowDelegate for FdaDelegate {}
        );

        impl FdaDelegate {
            fn new(mtm: MainThreadMarker, slot: FdaSlot) -> Retained<Self> {
                let this = Self::alloc(mtm).set_ivars(FdaIvars { slot });
                unsafe { objc2::msg_send![super(this), init] }
            }
        }

        /// Probe Full Disk Access from this helper process.
        ///
        /// **裏取り未**: probe は helper 自身の open+read なので、TCC が
        /// これを (daemon = responsible process ではなく) helper 単体の
        /// アクセスとして扱う可能性がある。その場合 daemon 側が granted でも
        /// ここが not granted に見える (逆は無い) ため、live 表示が遅れて
        /// 緑にならないだけで、誤って「許可済み」と表示することはない
        /// (fail-safe 側に転ぶ)。実機での attribution 確認は未実施。
        fn probe() -> bool {
            macos_tcc::check(macos_tcc::Permission::FullDiskAccess) == macos_tcc::AuthState::Granted
        }

        /// Re-probe and, on a fresh grant, switch the window to its confirmed
        /// state and answer the daemon. Idempotent and cheap enough to call
        /// from both the notification and the poll. **Main thread only.**
        fn refresh(slot: &FdaSlot) {
            let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            let Some(dialog) = guard.as_mut().map(|d| &mut d.0) else {
                return;
            };
            if dialog.granted || !probe() {
                return;
            }
            dialog.granted = true;
            dialog
                .status
                .setStringValue(&NSString::from_str(STATUS_GRANTED));
            dialog
                .status
                .setTextColor(Some(&NSColor::systemGreenColor()));
            if !dialog.answered {
                dialog.answered = true;
                write_line(
                    &dialog.writer,
                    &HelperResponse::FdaPrompt(FdaPromptResponse {
                        v: WIRE_VERSION,
                        request_id: dialog.request_id.clone(),
                        outcome: FdaOutcome::Granted,
                    }),
                );
            }
        }

        /// Re-arm the fallback probe for as long as the window is open.
        ///
        /// Design rationale: the event subscription
        /// ([`TCC_CHANGED_NOTIFICATION`]) is the primary signal — this poll
        /// exists only because that notification's delivery to a background
        /// `.Accessory` process is not something we have confirmed on a real
        /// machine, and a status light that silently never turns green would
        /// be worse than a few probes. It is scoped as tightly as a fallback
        /// should be: it runs only while the explainer is on screen, stops the
        /// moment the window closes or the permission is granted, and rides a
        /// kernel timer (`dispatch_after`) rather than a sleeping thread.
        fn schedule_poll(slot: FdaSlot) {
            dispatch_main_after(POLL_INTERVAL_SECS, move || {
                {
                    let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
                    match guard.as_ref() {
                        // Window closed — stop re-arming.
                        None => return,
                        // Already confirmed — nothing left to watch for.
                        Some(d) if d.0.granted => return,
                        Some(_) => {}
                    }
                }
                refresh(&slot);
                schedule_poll(slot);
            });
        }

        /// End the explainer: answer the daemon if the grant never came,
        /// unsubscribe, and drop the window. Idempotent. **Main thread only.**
        fn finalize(slot: &FdaSlot) {
            let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            let Some(dialog) = taken.map(MainOnlySend::into_inner) else {
                return;
            };
            if !dialog.answered {
                write_line(
                    &dialog.writer,
                    &HelperResponse::FdaPrompt(FdaPromptResponse {
                        v: WIRE_VERSION,
                        request_id: dialog.request_id.clone(),
                        outcome: FdaOutcome::Dismissed,
                    }),
                );
            }
            // Detach every unretained reference to the delegate *before* its
            // last strong reference can go away.
            dialog
                .window
                .setDelegate(None::<&ProtocolObject<dyn NSWindowDelegate>>);
            unsafe {
                NSDistributedNotificationCenter::defaultCenter().removeObserver_name_object(
                    dialog.delegate.as_ref() as &AnyObject,
                    Some(&NSString::from_str(TCC_CHANGED_NOTIFICATION)),
                    None,
                );
            }
            WINDOW_OPEN.store(false, Ordering::Release);

            // Release the dialog — and with it the delegate — on the *next*
            // main-queue turn rather than here.
            //
            // This function's usual caller is `windowWillClose:`, i.e. an
            // Objective-C method running on the delegate itself, and the
            // dialog we just took out of the slot holds that delegate's only
            // strong reference (AppKit's window-delegate and button-target
            // pointers are both unretained). Dropping it inline would
            // deallocate the receiver while its own method is still on the
            // stack. Deferring costs one queue hop and makes the release
            // unconditionally safe, whichever path called us. The approval
            // dialog avoids the same hazard differently — its delegate is
            // owned by the LocalAuthentication completion block, so it is
            // never released from inside its own callback.
            let deferred = MainOnlySend(dialog);
            dispatch_main(move || drop(deferred.into_inner()));
        }

        fn label(mtm: MainThreadMarker, text: &str) -> Retained<NSTextField> {
            let field = NSTextField::wrappingLabelWithString(&NSString::from_str(text), mtm);
            field.setPreferredMaxLayoutWidth(TEXT_WIDTH);
            field
        }

        /// Put the explainer on screen. **Called on the main thread only**
        /// (via `dispatch_main` from the reader thread).
        pub fn show_fda_dialog_on_main(req: FdaPromptRequest, writer: Arc<Mutex<UnixStream>>) {
            let mtm =
                MainThreadMarker::new().expect("show_fda_dialog_on_main must run on main thread");
            if WINDOW_OPEN.swap(true, Ordering::AcqRel) {
                eprintln!(
                    "cache-warden-approver: a Full Disk Access explainer is already open; \
                     ignoring the duplicate request (request_id={:?})",
                    req.request_id
                );
                return;
            }
            // The approval path calls this too; harmless if it already ran.
            let _app: Retained<NSApplication> = init_app(mtm);

            let slot: FdaSlot = Arc::new(Mutex::new(None));
            let delegate = FdaDelegate::new(mtm, Arc::clone(&slot));

            let window = unsafe {
                NSWindow::initWithContentRect_styleMask_backing_defer(
                    NSWindow::alloc(mtm),
                    NSRect {
                        origin: NSPoint { x: 0.0, y: 0.0 },
                        size: NSSize {
                            width: WINDOW_WIDTH,
                            height: 320.0,
                        },
                    },
                    NSWindowStyleMask::Titled | NSWindowStyleMask::Closable,
                    NSBackingStoreType::Buffered,
                    false,
                )
            };
            window.setTitle(&NSString::from_str("cache-warden: フルディスクアクセス"));
            unsafe { window.setReleasedWhenClosed(false) };

            let stack = NSStackView::new(mtm);
            stack.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
            stack.setDistribution(NSStackViewDistribution::Fill);
            stack.addArrangedSubview(&label(mtm, HEADING));
            stack.addArrangedSubview(&label(mtm, WHY));
            stack.addArrangedSubview(&label(mtm, HOW));

            let granted = probe();
            let status = label(
                mtm,
                if granted {
                    STATUS_GRANTED
                } else {
                    STATUS_NOT_GRANTED
                },
            );
            let status_color = if granted {
                NSColor::systemGreenColor()
            } else {
                NSColor::systemRedColor()
            };
            status.setTextColor(Some(&status_color));
            stack.addArrangedSubview(&status);

            let open_button = unsafe {
                NSButton::buttonWithTitle_target_action(
                    &NSString::from_str("フルディスクアクセスの設定を開く"),
                    Some(delegate.as_ref()),
                    Some(sel!(openSettingsClicked:)),
                    mtm,
                )
            };
            stack.addArrangedSubview(&open_button);
            stack.addArrangedSubview(&label(mtm, DECLINE_NOTE));
            let close_button = unsafe {
                NSButton::buttonWithTitle_target_action(
                    &NSString::from_str("閉じる"),
                    Some(delegate.as_ref()),
                    Some(sel!(closeClicked:)),
                    mtm,
                )
            };
            stack.addArrangedSubview(&close_button);

            window.setContentView(Some(&stack));
            let as_window_delegate: &ProtocolObject<dyn NSWindowDelegate> =
                ProtocolObject::from_ref(&*delegate);
            window.setDelegate(Some(as_window_delegate));

            // Live watch: event subscription first, poll as the fallback.
            unsafe {
                NSDistributedNotificationCenter::defaultCenter()
                    .addObserver_selector_name_object_suspensionBehavior(
                        delegate.as_ref() as &AnyObject,
                        sel!(tccChanged:),
                        Some(&NSString::from_str(TCC_CHANGED_NOTIFICATION)),
                        None,
                        NSNotificationSuspensionBehavior::DeliverImmediately,
                    );
            }

            // Already granted when the window went up (the daemon's probe and
            // this one disagreed, or the user granted it in between): answer
            // `Granted` now. Leaving it unanswered would send `Dismissed` on
            // close and tell the daemon's log the exact opposite of what
            // happened. The window still opens — it is the confirmation the
            // user is owed, in its green state.
            if granted {
                write_line(
                    &writer,
                    &HelperResponse::FdaPrompt(FdaPromptResponse {
                        v: WIRE_VERSION,
                        request_id: req.request_id.clone(),
                        outcome: FdaOutcome::Granted,
                    }),
                );
            }

            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(MainOnlySend(FdaDialog {
                window: Retained::clone(&window),
                status,
                delegate,
                writer,
                request_id: req.request_id,
                granted,
                answered: granted,
            }));

            window.center();
            // Order front without activating: the approval dialog needs the
            // focus more than this one does (see the module doc).
            window.orderFrontRegardless();

            if !granted {
                schedule_poll(slot);
            }
        }
    }

    // --- background reader thread ------------------------------------------

    /// Persistent connection reader. On its own std::thread so the AppKit
    /// runloop on main thread stays clear. Reads `ApproveRequest` lines one
    /// by one; for each, dispatches `show_dialog_on_main` and blocks on
    /// `completion_rx.recv()` until that dialog's outcome is sent. On daemon
    /// EOF or any read error, requests the whole helper to terminate.
    ///
    /// # No per-read timeout on the reader loop
    ///
    /// Phase 1.5 put a 30 s `read_timeout` on the helper's post-verify
    /// `read_line` because that read was one-shot: verify → read request →
    /// dialog → exit, so an unbounded wait meant "daemon accepted us and
    /// died silently". Phase 1.6 makes the helper persistent, so arbitrarily
    /// long quiet periods between approval requests are the normal case, and
    /// any fixed timeout would kill the helper needlessly (a fresh spawn +
    /// verify per request would defeat the point of §3 案 (b)). The bounded
    /// wait for "daemon accepted us and never wrote" is preserved by a
    /// different lever: if the daemon dies (crash, graceful shutdown, or
    /// [`ApproverClient::shutdown`]'s SIGKILL of *this* process's parent
    /// path), the kernel closes the Unix socket and `read_line` returns 0
    /// bytes, terminating the helper cleanly via the EOF branch below.
    fn spawn_reader_thread(
        stream_read: UnixStream,
        writer: Arc<Mutex<UnixStream>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream_read);
            loop {
                let mut line = String::new();
                let n = match reader.read_line(&mut line) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("cache-warden-approver: read error, terminating helper: {e}");
                        break;
                    }
                };
                if n == 0 {
                    // Daemon closed the socket (§7 逆方向: daemon が居ないのに
                    // 常駐しない)。Clean shutdown of the helper.
                    eprintln!(
                        "cache-warden-approver: daemon closed the approver socket, terminating helper"
                    );
                    break;
                }
                let envelope: HelperRequest = match serde_json::from_str(line.trim_end()) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("cache-warden-approver: failed to decode a request: {e}");
                        // Malformed request: cannot signal an outcome for it
                        // (no request_id / no way to know what the daemon
                        // expected). Terminate — safer than a stuck reader.
                        break;
                    }
                };

                let req = match envelope {
                    HelperRequest::Approve(req) => req,
                    HelperRequest::FdaPrompt(prompt) => {
                        if prompt.v != WIRE_VERSION {
                            eprintln!(
                                "cache-warden-approver: unsupported wire version {} (helper speaks {WIRE_VERSION})",
                                prompt.v
                            );
                            break;
                        }
                        // Deliberately *not* awaited: the explainer stays up
                        // while the user walks through System Settings, and
                        // approvals must keep flowing the whole time. Show it
                        // and go straight back to reading (draft-DR-0031 §4:
                        // the FDA prompt is not part of the approval queue).
                        let writer_for_fda = writer.clone();
                        dispatch_main(move || {
                            fda::show_fda_dialog_on_main(prompt, writer_for_fda);
                        });
                        continue;
                    }
                };
                if req.v != WIRE_VERSION {
                    eprintln!(
                        "cache-warden-approver: unsupported wire version {} (helper speaks {WIRE_VERSION})",
                        req.v
                    );
                    break;
                }

                // Per-request completion signaling. `bounded(1)` guarantees the
                // send in show_dialog_on_main never blocks (only 1 send per
                // request), and recv here is the event-driven wait — no
                // polling.
                let (tx, rx) = mpsc::sync_channel::<()>(1);
                let writer_for_dispatch = writer.clone();
                dispatch_main(move || {
                    show_dialog_on_main(req, writer_for_dispatch, tx);
                });
                // Block until the dialog's outcome is sent. If the daemon
                // times out and drops the connection, the write in
                // show_dialog_on_main will fail (broken pipe) but the
                // completion_tx send still fires — we don't deadlock.
                if rx.recv().is_err() {
                    // tx dropped without send — dialog never completed (bug).
                    eprintln!(
                        "cache-warden-approver: dialog dropped without sending outcome, terminating"
                    );
                    break;
                }
            }
            // Terminate the process from main thread.
            dispatch_main(|| {
                let mtm = MainThreadMarker::new().expect("terminate on main thread");
                NSApplication::sharedApplication(mtm).terminate(None);
            });
        })
    }

    // --- standalone (--socket 未指定) 経路 ---------------------------------

    #[cfg(debug_assertions)]
    const STANDALONE_SUMMARY: &str = "Allow requester to read secret";

    /// Dispatch the `--socket`-less invocation.
    ///
    /// A standalone dialog puts a real TouchID prompt on screen from a
    /// hardcoded summary, with no daemon behind it. In a shipped build that
    /// is an attack primitive rather than a feature: any same-uid process can
    /// `open CacheWardenApprover.app` and raise a prompt that looks exactly
    /// like cache-warden asking for a secret — MFA-fatigue / phishing
    /// material that dulls the reflex the whole dialog design depends on
    /// (draft-DR-0031 §Security review L-2). Nothing legitimate needs it
    /// either: production always spawns the helper with `--socket`.
    ///
    /// It stays available in debug builds because that is the dev loop
    /// (`just approver-run`) for iterating on the dialog without a daemon.
    fn run_without_socket() {
        #[cfg(debug_assertions)]
        run_standalone();

        #[cfg(not(debug_assertions))]
        {
            eprintln!(
                "cache-warden-approver: refusing to run without --socket \
                 (this helper is launched by the cache-warden daemon)"
            );
            std::process::exit(2);
        }
    }

    /// dev 単独起動 (`just approver-run`) の one-shot 動作。
    /// dialog 1 枚 + Approved/BiometricFailed/Cancel いずれかで terminate。
    /// terminate 経路は `NSApplicationWillTerminateNotification` observer で
    /// 「未送信 = Cancelled」を stderr にログ (IPC 無しなので Outcome だけ
    /// 表示)。
    #[cfg(debug_assertions)]
    fn run_standalone() {
        let mtm = MainThreadMarker::new().expect("must run on main thread");
        let app = init_app(mtm);
        let window = make_floating_panel(mtm);
        // standalone は 1 枚しか出さないので、close で release されて OK。
        unsafe { window.setReleasedWhenClosed(true) };
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };

        let stack = NSStackView::new(mtm);
        stack.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
        stack.setDistribution(NSStackViewDistribution::Fill);
        let summary = NSTextField::labelWithString(&NSString::from_str(STANDALONE_SUMMARY), mtm);
        stack.addArrangedSubview(&summary);
        let auth_view = unsafe {
            LAAuthenticationView::initWithContext_controlSize(
                LAAuthenticationView::alloc(mtm),
                &ctx,
                NSControlSize::Large,
            )
        };
        stack.addArrangedSubview(&auth_view);
        // Cancel は Phase 1.4 と同じで terminate: 直結 (standalone なので OK)。
        let cancel = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str("Cancel"),
                Some(app.as_ref()),
                Some(sel!(terminate:)),
                mtm,
            )
        };
        stack.addArrangedSubview(&cancel);
        window.setContentView(Some(&stack));
        window.center();
        window.makeKeyAndOrderFront(None);
        let _focus_observer = register_focus_steal_on_launch(&window);

        let app_for_block: Retained<NSApplication> = Retained::clone(&app);
        let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let outcome = if ok.as_bool() {
                Outcome::Approved
            } else {
                Outcome::BiometricFailed
            };
            eprintln!("cache-warden-approver: outcome (standalone, no IPC): {outcome:?}");
            app_for_block.terminate(None);
        });
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str("Authenticate to access secret"),
                &block,
            );
        }
        app.run();
    }

    /// `run_standalone` 専用 (常駐経路は request ごとに `steal_focus` を直接
    /// 呼ぶ)。
    #[cfg(debug_assertions)]
    fn register_focus_steal_on_launch(
        window: &Retained<NSWindow>,
    ) -> Retained<ProtocolObject<dyn NSObjectProtocol>> {
        let window = Retained::clone(window);
        let block = RcBlock::new(move |_notif: NonNull<NSNotification>| {
            steal_focus(&window);
        });
        let center = NSNotificationCenter::defaultCenter();
        unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSApplicationDidFinishLaunchingNotification),
                None,
                None,
                &block,
            )
        }
    }

    // --- 常駐 helper 経路 ---------------------------------------------------

    fn run_persistent(socket_path: &Path) {
        let mtm = MainThreadMarker::new().expect("must run on main thread");
        let app = init_app(mtm);

        // Connect + verify peer BEFORE app.run() and BEFORE any UI is built.
        // Fail-fast per Phase 1.4/1.5 policy: if we cannot talk to the daemon,
        // never show a dialog (a "TouchID prompt with no daemon to answer" is
        // a UX contradiction — the user's fingerprint would be consumed but
        // no secret release could follow).
        let stream = match UnixStream::connect(socket_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "cache-warden-approver: connect to daemon socket {socket_path:?} failed: {e}"
                );
                std::process::exit(1);
            }
        };
        if let Err(e) = verify_daemon_peer(&stream) {
            eprintln!("cache-warden-approver: daemon peer verification failed: {e}");
            std::process::exit(1);
        }

        // Split into read + write halves. The read side is owned by the
        // background reader thread; the write side is shared under a Mutex
        // (LA block + Cancel/close all write to it, but only ever one at a
        // time because pending state serializes them).
        let stream_read = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cache-warden-approver: try_clone on approver socket failed: {e}");
                std::process::exit(1);
            }
        };
        let writer = Arc::new(Mutex::new(stream));

        // On persistent mode, focus-steal must fire per request (not once at
        // launch). The `register_focus_steal_on_launch` observer is not used
        // here — `show_dialog_on_main` calls `steal_focus` directly for every
        // dialog.
        let _reader_join = spawn_reader_thread(stream_read, writer);

        app.run();
    }

    pub fn run() {
        match resolve_socket_path() {
            Some(path) => run_persistent(&path),
            None => run_without_socket(),
        }
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    approver::run();

    #[cfg(not(target_os = "macos"))]
    eprintln!("cache-warden-approver is macOS-only (LocalAuthenticationEmbeddedUI).");
}
