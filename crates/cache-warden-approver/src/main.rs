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

    use cache_warden_approver::wire::{ApproveRequest, ApproveResponse, Outcome, WIRE_VERSION};

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
        let resp = ApproveResponse {
            v: WIRE_VERSION,
            request_id: request_id.to_string(),
            outcome,
            biometric_kind,
        };
        match serde_json::to_string(&resp) {
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
                let req: ApproveRequest = match serde_json::from_str(line.trim_end()) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("cache-warden-approver: failed to decode ApproveRequest: {e}");
                        // Malformed request: cannot signal an outcome for it
                        // (no request_id / no way to know what the daemon
                        // expected). Terminate — safer than a stuck reader.
                        break;
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
