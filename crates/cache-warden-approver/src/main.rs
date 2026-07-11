//! `cache-warden-approver` — draft-DR-0031 の常駐 GUI helper 本実装。
//!
//! # スコープ (Phase 1.4)
//!
//! - LAAuthenticationView 埋め込みの承認 dialog を独自 NSWindow に表示
//! - focus 奪取 (`.Accessory` activation policy を維持したまま `/usr/bin/open`
//!   経由で LaunchServices に activate させる、draft-DR-0031 §UX policy)
//! - IPC (unix socket + serde_json、draft-DR-0031 §4): `--socket <path>` (または
//!   `CACHE_WARDEN_APPROVER_SOCKET` env) 指定時、daemon 側 (`approver.sock`) に
//!   接続して `ApproveRequest` を 1 行 read → サマリ表示に反映 → outcome 確定時に
//!   `ApproveResponse` を 1 行 write。socket 指定なしはスタンドアロン動作
//!   (hardcoded サマリ) を維持する
//! - Cancel button の target/action は `NSApplication::terminate:` に直結したまま、
//!   `NSApplicationWillTerminateNotification` observer で「未送信なら cancelled を
//!   送る」方式で IPC 応答を確定する (Approved/BiometricFailed が先に送信済みなら
//!   no-op、二重送信なし)
//! - LAContext.evaluatePolicy の completion block 内で outcome を確定して terminate
//!
//! # 意図的な非スコープ (後続 Phase)
//!
//! - Info.plist (`LSUIElement=YES`) + `.app` バンドル化: `.Accessory` +
//!   `/usr/bin/open` 経由の focus 奪取は既に実機確認済みだが、実際の `.app`
//!   バンドル生成 + codesign/notarize は release.yml 側の作業 (Phase 3)
//! - 双方向 peer 認証 (§Security): daemon → helper / helper → daemon の identity
//!   検証 (`getsockopt(LOCAL_PEERTOKEN)`) は未実装。現状は socketpair 相当の
//!   name-based socket に接続するのみ
//! - Cancel button の Rust 側 delegate class 定義 (peer_gone / 詳細 cancel reason 用、
//!   Phase 2)
//! - Requester icon / チップ / 詳細展開 UI (Phase 2)
//! - kqueue で peer_gone 検知 (Phase 2)
//! - `timeout_secs` の helper 内タイマー実装 (wire field としては存在するが、
//!   Phase 1.4 の timeout enforcement は daemon 側の
//!   `tokio::time::timeout` のみ)
//! - codesign + notarize (Phase 3、release.yml 拡張)

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod approver {
    use block2::RcBlock;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::ptr::NonNull;
    use std::sync::{Arc, Mutex};

    use objc2::rc::Retained;
    use objc2::runtime::{Bool, NSObjectProtocol, ProtocolObject};
    use objc2::{MainThreadMarker, MainThreadOnly, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSApplicationDidFinishLaunchingNotification,
        NSApplicationWillTerminateNotification, NSBackingStoreType, NSButton, NSControlSize,
        NSFloatingWindowLevel, NSStackView, NSStackViewDistribution, NSTextField,
        NSUserInterfaceLayoutOrientation, NSWindow, NSWindowStyleMask,
    };
    use objc2_foundation::{
        NSError, NSNotification, NSNotificationCenter, NSPoint, NSRect, NSSize, NSString,
    };
    use objc2_local_authentication::{LAContext, LAPolicy};
    use objc2_local_authentication_embedded_ui::LAAuthenticationView;

    use cache_warden_approver::wire::{ApproveRequest, ApproveResponse, Outcome, WIRE_VERSION};

    /// The open IPC connection to the daemon plus the pending request's id,
    /// or `None` once the outcome has been sent.
    ///
    /// Wrapped in `Arc<Mutex<Option<_>>>` so the `evaluate` completion block
    /// and the terminate-time fallback (`register_cancel_on_terminate`) can
    /// both hold a clone and race safely: whichever fires first `take()`s the
    /// connection and sends; the loser sees `None` and no-ops. `None` from the
    /// start when the helper was launched standalone (no `--socket`).
    type WireConn = Arc<Mutex<Option<(UnixStream, String)>>>;

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

    /// Connect to the daemon's approver socket and read the single
    /// `ApproveRequest` line it sends immediately after accepting (§4: helper
    /// connects, daemon binds/accepts/sends). Blocking I/O: this runs on the
    /// main thread before any UI is built, matching the "connect + read
    /// before `app.run()`" requirement.
    fn connect_and_read_request(path: &Path) -> std::io::Result<(UnixStream, ApproveRequest)> {
        let stream = UnixStream::connect(path)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed the approver socket before sending a request",
            ));
        }
        let req: ApproveRequest = serde_json::from_str(line.trim_end())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // version 不一致は「別世代の daemon」からの request。v1 の意味論で
        // 半端に解釈して dialog を出すより、ここで拒否して fail-fast に落とす
        // (daemon 側 `exchange` も response の v を対称に検証する)。
        if req.v != WIRE_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported approver wire version {} (helper speaks {WIRE_VERSION})",
                    req.v
                ),
            ));
        }
        Ok((stream, req))
    }

    /// The requester name shown in the dialog summary ("Allow \<name\> to read
    /// \<key\>"): `responsible_bundle_id` when resolvable, else the basename
    /// of the chain's leading (requester) process path.
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

    /// Send `outcome` over the wire connection exactly once. A `None` `wire`
    /// (standalone mode) or an already-taken connection (outcome already
    /// sent) is a silent no-op — see [`WireConn`]'s race-safety doc.
    fn send_outcome(wire: &Option<WireConn>, outcome: Outcome, biometric_kind: Option<String>) {
        let Some(wire) = wire else {
            eprintln!("approver outcome (standalone, no IPC): {outcome:?}");
            return;
        };
        let taken = wire.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some((mut stream, request_id)) = taken else {
            return;
        };
        let resp = ApproveResponse {
            v: WIRE_VERSION,
            request_id,
            outcome,
            biometric_kind,
        };
        match serde_json::to_string(&resp) {
            Ok(mut line) => {
                line.push('\n');
                if let Err(e) = stream
                    .write_all(line.as_bytes())
                    .and_then(|_| stream.flush())
                {
                    eprintln!("approver: failed to send ApproveResponse: {e}");
                }
            }
            Err(e) => eprintln!("approver: failed to encode ApproveResponse: {e}"),
        }
    }

    /// activation policy を `.Accessory` に固定する (Info.plist の
    /// `LSUIElement=YES` と一致)。Phase 1.1 で `.Regular` にすると Dock Icon が
    /// 出る問題が確認され、Phase 1.2 で `.app` バンドル + Info.plist LSUIElement=YES
    /// に切替。runtime で `.Regular` を呼ぶと LSUIElement=YES が上書きされて Dock
    /// Icon が復活するため、runtime も `.Accessory` を明示する。
    ///
    /// `.Accessory` はフォーカス奪取に制約があるが、focus 奪取は別対策 (新
    /// `NSApplication::activate` API / `NSRunningApplication.current.activate`
    /// 等) で潰す。§UX policy で確認済みの通り、focus 状態が sensor input 配送の
    /// ゲートなので、Dock Icon 出さない + focus 奪える両立が必要。
    fn init_app(mtm: MainThreadMarker) -> Retained<NSApplication> {
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        app
    }

    /// draft-DR-0031 §5 layout: 400x325、Titled|Closable、Floating panel level。
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
        window
    }

    /// draft-DR-0031 §5 情報階層 (呼び出し元 → チェック → cw、見出し、ボタン)。
    /// summary label + LAAuthenticationView + Cancel button の最小 3 要素のみ。
    /// requester icon / チップ / 詳細展開は Phase 2。
    fn build_content(
        mtm: MainThreadMarker,
        app: &NSApplication,
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

        // "Allow <requester> to read <ns/key>" — IPC 経由 (§4) の ApproveRequest
        // から `requester_display_name` + `key` で組み立てる。socket 指定なしの
        // スタンドアロン起動では固定文言 (`run` 参照)。
        let summary = NSTextField::labelWithString(&NSString::from_str(summary_text), mtm);
        stack.addArrangedSubview(&summary);

        // draft-DR-0031 §6 Mode A: LAAuthenticationView 埋め込み。cache-warden-approver-poc
        // ver.2 で Mode A 成立を実機確定済み (視覚証拠 + coreauthd 側 uiMechanism:
        // MechanismTouchId 単独)。
        let auth_view = unsafe {
            LAAuthenticationView::initWithContext_controlSize(
                LAAuthenticationView::alloc(mtm),
                ctx,
                NSControlSize::Large,
            )
        };
        stack.addArrangedSubview(&auth_view);

        // Cancel button: target = NSApplication、action = terminate: セレクタに直結。
        // Phase 2 で Rust 側 delegate class を導入し「Cancel = IPC で Outcome::Cancelled
        // を daemon に送る + terminate」に置換する。
        let cancel = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str("Cancel"),
                Some(app.as_ref()),
                Some(sel!(terminate:)),
                mtm,
            )
        };
        stack.addArrangedSubview(&cancel);

        (stack, auth_view, cancel)
    }

    /// LAContext.evaluatePolicy の completion block 経由で outcome を確定。
    /// Approved / BiometricFailed の 2 経路とも `send_outcome` で IPC 応答を
    /// (socket 指定時は) 送ってから terminate する。
    fn evaluate(
        app: &Retained<NSApplication>,
        ctx: &LAContext,
        reason: &NSString,
        wire: Option<WireConn>,
    ) {
        let app_for_block: Retained<NSApplication> = Retained::clone(app);
        let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let (outcome, biometric_kind) = if ok.as_bool() {
                (Outcome::Approved, Some("TouchID".to_string()))
            } else {
                (Outcome::BiometricFailed, Some("TouchID".to_string()))
            };
            send_outcome(&wire, outcome, biometric_kind);
            app_for_block.terminate(None);
        });
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                reason,
                &block,
            );
        }
    }

    /// `NSApplicationWillTerminateNotification` observer: sends
    /// `Outcome::Cancelled` if no outcome has been sent yet (Cancel button /
    /// window close / any other termination path). A no-op when `evaluate`'s
    /// completion block already sent Approved/BiometricFailed and took the
    /// connection — see [`WireConn`]'s race-safety doc. This is the "推奨"
    /// pattern from draft-DR-0031 Phase 1.4 scope: no Rust-side delegate class
    /// needed, `terminate:` posts `WillTerminate` synchronously before the
    /// process actually exits.
    fn register_cancel_on_terminate(
        wire: Option<WireConn>,
    ) -> Retained<ProtocolObject<dyn NSObjectProtocol>> {
        let block = RcBlock::new(move |_notif: NonNull<NSNotification>| {
            send_outcome(&wire, Outcome::Cancelled, None);
        });
        let center = NSNotificationCenter::defaultCenter();
        unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSApplicationWillTerminateNotification),
                None,
                None,
                &block,
            )
        }
    }

    /// draft-DR-0031 §UX policy: focus 制御の default steal を実装する。
    ///
    /// 実機観察 (Phase 1.1〜1.2):
    /// - `.Accessory` activation policy + `activateIgnoringOtherApps(true)` では
    ///   フォーカスを奪えず、focus 無しでは指紋 sensor input も app に配送されない
    ///   (Apple safety design 推定)
    ///
    /// Phase 1.3 試験 (d): LaunchServices 経由の activation。自分の `.app`
    /// バンドルパスに対して `/usr/bin/open` を spawn し、LaunchServices に
    /// 「既に走っている app の再 open = activate」をさせる。
    ///
    /// Design rationale: ユーザ操作起点でない self-activation はプロセス内の
    /// どの API 経路でも macOS に拒否された (実機観察、macOS 26):
    /// - (a) `NSRunningApplication.currentApplication().activateWithOptions:` →
    ///   戻り値 false (request 送信自体が拒否)
    /// - (b) `NSApplication::activate()` (macOS 14+ cooperative activation) →
    ///   frontmost の yield 無しでは不成立
    /// - (c-1) runtime `setActivationPolicy(.Regular)` + activate → Dock Icon は
    ///   出るが activation は不成立
    /// - (c-2) Carbon `TransformProcessType(kProcessTransformToForegroundApplication)`
    ///   → OSStatus 0 (成功) でも activation は不成立
    ///
    /// `open` は LaunchServices (システム側プロセス) が activation を実行するため、
    /// self-activation 制限の対象外 (実機で focus 奪取成立を確認済み)。
    ///
    /// 発火タイミングはイベント駆動: `NSApplicationDidFinishLaunching` 通知 (= run
    /// loop 開始 + launch 完了後) を待ってから spawn する。起動直後に spawn すると
    /// LaunchServices 側の activation が window 表示より先に届いた場合に focus
    /// されない競合があるため、sleep でなく通知で順序を保証する。
    fn steal_focus(window: &NSWindow) {
        window.orderFrontRegardless();
        window.makeKeyWindow();

        // current_exe = <bundle>/Contents/MacOS/cache-warden-approver → 3 つ上が
        // .app バンドル。バンドル外 (直接バイナリ起動) では focus steal を諦める
        // (Phase 1.2 以降 `.app` 化が正規起動経路)。
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

    /// `NSApplicationDidFinishLaunching` で `steal_focus` を発火する observer を
    /// 登録する。戻り値の observer token は `app.run()` の間 (= プロセス生存中)
    /// 保持しておく必要がある (drop すると解除)。
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
                // queue = None: 通知を post したスレッド (= main thread) で block を
                // 実行する。AppKit 操作 (orderFront 等) は main thread 前提。
                None,
                &block,
            )
        }
    }

    /// standalone (socket 指定なし) 起動時の hardcoded サマリ。既存の単独動作
    /// (`just approver-run`) を完全維持する。
    const STANDALONE_SUMMARY: &str = "Allow requester to read secret";

    pub fn run() {
        let mtm = MainThreadMarker::new().expect("must run on main thread");
        let app = init_app(mtm);
        let window = make_floating_panel(mtm);
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };

        // IPC 接続 + ApproveRequest read は UI 構築前 (main thread、app.run() 前)
        // に行う (draft-DR-0031 §4)。socket が明示されているのに daemon と話せない
        // 場合は dialog を出さずに fail-fast する: standalone 表示に落とすと
        // 「承認対象を表示しない偽 dialog で TouchID を求め、ユーザが指紋を通しても
        // daemon 側は応答を受け取れず timeout で fail-closed する」UX 矛盾を生む。
        // standalone 表示は socket 指定なし (dev 単独起動) 専用。
        let (summary_text, wire): (String, Option<WireConn>) = match resolve_socket_path() {
            Some(path) => match connect_and_read_request(&path) {
                Ok((stream, req)) => {
                    let summary =
                        format!("Allow {} to read {}", requester_display_name(&req), req.key);
                    let conn: WireConn = Arc::new(Mutex::new(Some((stream, req.request_id))));
                    (summary, Some(conn))
                }
                Err(e) => {
                    eprintln!(
                        "approver: IPC connect/read failed ({e}); refusing to show a dialog without a daemon connection"
                    );
                    std::process::exit(1);
                }
            },
            None => (STANDALONE_SUMMARY.to_string(), None),
        };

        let (stack, _auth_view, _cancel) = build_content(mtm, &app, &ctx, &summary_text);
        window.setContentView(Some(&stack));
        // `mainScreen` は「現在キーウィンドウを持つ画面」を返す (Apple 用語の罠だが、
        // Accessory app の起動時点では他アプリがフォーカスを持っているため、その
        // アプリのある画面 = ユーザが直前に操作していた画面 の中央に置かれる)。
        // マルチモニタ環境で「フォーカスを持つアプリのモニタ中央」に配置する要求
        // (kawaz) に対応する。
        window.center();
        window.makeKeyAndOrderFront(None);

        // draft-DR-0031 §UX policy: default focus_steal = true。現状 config を
        // 導入せず常に steal する (config parse + opt-out は後続 Phase)。
        // observer token は app.run() の間 drop しないよう保持する。
        let _focus_observer = register_focus_steal_on_launch(&window);

        // outcome 未送信のまま terminate した場合の fallback (Cancel button /
        // window close 等)。evaluate の completion block が先に送信済みなら
        // no-op (WireConn の take-once 保証)。
        let _cancel_observer = register_cancel_on_terminate(wire.clone());

        let reason = NSString::from_str("Authenticate to access secret");
        evaluate(&app, &ctx, &reason, wire);

        app.run();
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    approver::run();

    #[cfg(not(target_os = "macos"))]
    eprintln!("cache-warden-approver is macOS-only (LocalAuthenticationEmbeddedUI).");
}
