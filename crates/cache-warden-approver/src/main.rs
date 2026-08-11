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
//!   dialog を閉じる。**Phase 1.5 の残課題「completion block の main-thread
//!   明示 dispatch」は本 Phase では対応しない** (別 issue で管理) — completion
//!   block が呼ばれるスレッドは実測 main が多いが公式保証なしという既知条件
//!   のまま
//! - daemon が接続を切ったら (read が 0 バイト EOF) helper 側も terminate
//!   (§7 の逆方向: daemon が居ないのに常駐しない)
//!
//! # 意図的な非スコープ (後続 Phase)
//!
//! - `LAContext.evaluatePolicy` completion block を明示 dispatch_main する
//!   hardening (Phase 1.5 残課題 `2026-07-12-approver-release-hardening`)
//! - Requester icon / チップ / 詳細展開 UI (Phase 2)
//! - kqueue で peer_gone 検知 (Phase 2)
//! - `timeout_secs` の helper 内タイマー (Phase 2、現状は daemon 側 timeout
//!   のみ)

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod approver {
    use block2::RcBlock;
    use std::ffi::c_void;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::ptr::NonNull;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, Bool, NSObject, NSObjectProtocol, ProtocolObject};
    use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSApplicationDidFinishLaunchingNotification,
        NSBackingStoreType, NSButton, NSControlSize, NSFloatingWindowLevel, NSStackView,
        NSStackViewDistribution, NSTextField, NSUserInterfaceLayoutOrientation, NSWindow,
        NSWindowDelegate, NSWindowStyleMask,
    };
    use objc2_foundation::{
        NSError, NSNotification, NSNotificationCenter, NSPoint, NSRect, NSSize, NSString,
    };
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
    }

    /// 任意の `FnOnce` を libdispatch の main queue で実行する。`Send` を要求
    /// するのは dispatch がスレッド越境するため — main thread only な
    /// `Retained<T>` 等を capture することはできない (SendWrapper 経由で
    /// 「main で使う限り安全」を宣言する場合を除く)。
    fn dispatch_main<F: FnOnce() + Send + 'static>(f: F) {
        // `Box<Box<dyn FnOnce>>` の 2 段 Box は「thin pointer で受け渡す」ため。
        // dispatch は `*mut c_void` しか運べないので、`Box<dyn FnOnce>` (= fat
        // pointer) を直接 into_raw できず、もう 1 段 Box して thin にする。
        let boxed: Box<Box<dyn FnOnce() + Send + 'static>> = Box::new(Box::new(f));
        let ctx = Box::into_raw(boxed) as *mut c_void;
        unsafe extern "C" fn trampoline(ctx: *mut c_void) {
            let boxed: Box<Box<dyn FnOnce() + Send + 'static>> =
                unsafe { Box::from_raw(ctx as *mut Box<dyn FnOnce() + Send + 'static>) };
            (*boxed)();
        }
        unsafe {
            dispatch_async_f(
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
                    eprintln!("approver: failed to send ApproveResponse: {e}");
                }
            }
            Err(e) => eprintln!("approver: failed to encode ApproveResponse: {e}"),
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

    /// Delegate class fields. `pending` is the shared take-once slot the LA
    /// completion block also holds; `ctx` is the per-request `LAContext`
    /// that this delegate's Cancel paths (`cancelClicked:` /
    /// `windowWillClose:`) call `invalidate()` on to unblock the pending
    /// `evaluatePolicy` — see the invalidate calls below for the leak-
    /// avoidance rationale. Storing `Retained<LAContext>` here is
    /// consistent with the delegate being `MainThreadOnly`.
    struct DelegateIvars {
        pending: PendingSlot,
        ctx: Retained<LAContext>,
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
        ) -> Retained<Self> {
            let ivars = DelegateIvars { pending, ctx };
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
                    "steal_focus: open {} -> spawn = {}",
                    bundle.display(),
                    spawned.is_ok()
                );
            }
            None => eprintln!("steal_focus: not in .app bundle, skip open-based activation"),
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
        let delegate = ApproverDelegate::new(mtm, pending_slot.clone(), Retained::clone(&ctx));

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
        // 実測では main thread に発火することが多いが公式保証なし
        // (Phase 1.5 残課題)。ここでは worker が実行するスレッドを問わず
        // 動くよう、outcome 送信 (socket write) は thread-safe な `writer`
        // Mutex 経由、window.close() は dispatch_main 経由で main queue に
        // 投げ直す。
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
            // window.close() is a main-thread-only AppKit operation. Phase 1.5
            // residual issue `2026-07-12-approver-release-hardening` covers
            // making the LA completion block explicitly dispatch to main
            // thread; today the block is observed to run on main in practice
            // and this call inherits that assumption. If we ever add the
            // explicit dispatch, this close moves into the dispatched
            // closure.
            window_for_block.0.close();
        });

        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str("Authenticate to access secret"),
                &block,
            );
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
                        eprintln!("approver: read error, terminating helper: {e}");
                        break;
                    }
                };
                if n == 0 {
                    // Daemon closed the socket (§7 逆方向: daemon が居ないのに
                    // 常駐しない)。Clean shutdown of the helper.
                    eprintln!("approver: daemon closed the approver socket, terminating helper");
                    break;
                }
                let req: ApproveRequest = match serde_json::from_str(line.trim_end()) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("approver: failed to decode ApproveRequest: {e}");
                        // Malformed request: cannot signal an outcome for it
                        // (no request_id / no way to know what the daemon
                        // expected). Terminate — safer than a stuck reader.
                        break;
                    }
                };
                if req.v != WIRE_VERSION {
                    eprintln!(
                        "approver: unsupported wire version {} (helper speaks {WIRE_VERSION})",
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
                    eprintln!("approver: dialog dropped without sending outcome, terminating");
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

    const STANDALONE_SUMMARY: &str = "Allow requester to read secret";

    /// Phase 1.4 の one-shot 動作を維持 (dev 単独起動 `just approver-run`)。
    /// dialog 1 枚 + Approved/BiometricFailed/Cancel いずれかで terminate。
    /// terminate 経路は `NSApplicationWillTerminateNotification` observer で
    /// 「未送信 = Cancelled」を stderr にログ (IPC 無しなので Outcome だけ
    /// 表示)。
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
            eprintln!("approver outcome (standalone, no IPC): {outcome:?}");
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
                eprintln!("approver: connect to daemon socket {socket_path:?} failed: {e}");
                std::process::exit(1);
            }
        };
        if let Err(e) = verify_daemon_peer(&stream) {
            eprintln!("approver: daemon peer verification failed: {e}");
            std::process::exit(1);
        }

        // Split into read + write halves. The read side is owned by the
        // background reader thread; the write side is shared under a Mutex
        // (LA block + Cancel/close all write to it, but only ever one at a
        // time because pending state serializes them).
        let stream_read = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("approver: try_clone on approver socket failed: {e}");
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
            None => run_standalone(),
        }
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    approver::run();

    #[cfg(not(target_os = "macos"))]
    eprintln!("cache-warden-approver is macOS-only (LocalAuthenticationEmbeddedUI).");
}
