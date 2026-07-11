//! `cache-warden-approver` — draft-DR-0031 の常駐 GUI helper 本実装 (Phase 1)。
//!
//! # スコープ (Phase 1.1)
//!
//! - LAAuthenticationView 埋め込みの承認 dialog を独自 NSWindow に表示
//! - focus 奪取 (activation policy = `.Regular` + `activate` + `makeKey` +
//!   `orderFrontRegardless`)。draft-DR-0031 §UX policy: focus 制御 default steal
//!   に対応
//! - Cancel button の target/action を `NSApplication::terminate:` に直結
//! - LAContext.evaluatePolicy の completion block 内で outcome を確定して terminate
//!
//! # 意図的な非スコープ (後続 Phase)
//!
//! - IPC (unix socket + serde_json、Phase 1.2): 現状は helper 単独起動時の
//!   スタンドアロン挙動を確認するだけ。承認対象情報 (kv key / requester chain /
//!   guard 評価結果) は hardcoded サマリで表示
//! - Info.plist (`LSUIElement=YES`) + `.app` バンドル化 (Phase 1.2 or Phase 1.3):
//!   まず非バンドル + `.Regular` activation policy で Dock Icon の挙動を実機確認する
//! - 双方向 peer 認証 (§Security、Phase 1.3): daemon → helper の identity 検証と
//!   helper → daemon の identity 検証は IPC 実装時に組む
//! - Cancel button の Rust 側 delegate class 定義 (peer_gone / 詳細 cancel reason 用、
//!   Phase 2)
//! - Requester icon / チップ / 詳細展開 UI (Phase 2)
//! - kqueue で peer_gone 検知 (Phase 2)
//! - codesign + notarize (Phase 3、release.yml 拡張)

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod approver {
    use block2::RcBlock;
    use std::ptr::NonNull;

    use objc2::rc::Retained;
    use objc2::runtime::{Bool, NSObjectProtocol, ProtocolObject};
    use objc2::{MainThreadMarker, MainThreadOnly, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSApplicationDidFinishLaunchingNotification,
        NSBackingStoreType, NSButton, NSControlSize, NSFloatingWindowLevel, NSStackView,
        NSStackViewDistribution, NSTextField, NSUserInterfaceLayoutOrientation, NSWindow,
        NSWindowStyleMask,
    };
    use objc2_foundation::{
        NSError, NSNotification, NSNotificationCenter, NSPoint, NSRect, NSSize, NSString,
    };
    use objc2_local_authentication::{LAContext, LAPolicy};
    use objc2_local_authentication_embedded_ui::LAAuthenticationView;

    /// draft-DR-0031 §4 の `ApproveResponse.outcome`。Phase 1.1 では UI 側の 2 経路
    /// (Approved / Cancelled) のみ block callback から到達、他は Phase 2 以降で
    /// helper 側 kqueue / IPC タイムアウトから到達する。
    #[derive(Debug, Clone, Copy)]
    #[allow(dead_code)]
    pub enum Outcome {
        Approved,
        Cancelled,
        PeerGone,
        BiometricFailed,
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
    /// Phase 1.1 では summary label + LAAuthenticationView + Cancel button の最小 3
    /// 要素のみ。requester icon / チップ / 詳細展開は Phase 2。
    fn build_content(
        mtm: MainThreadMarker,
        app: &NSApplication,
        ctx: &LAContext,
    ) -> (
        Retained<NSStackView>,
        Retained<LAAuthenticationView>,
        Retained<NSButton>,
    ) {
        let stack = NSStackView::new(mtm);
        stack.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
        stack.setDistribution(NSStackViewDistribution::Fill);

        // Phase 1.2 で ApproveRequest 由来のサマリテキストに差し替える
        // (「Allow <requester> to read <ns/key>」テンプレ)。
        let summary = NSTextField::labelWithString(
            &NSString::from_str("Allow requester to read secret"),
            mtm,
        );
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

    /// LAContext.evaluatePolicy の completion block 経由で outcome を確定。Phase 1.1
    /// では Approved / BiometricFailed の 2 経路を eprintln! で報告し、いずれも
    /// terminate。Phase 1.2 で IPC (ApproveResponse 送信) に置換する。
    fn evaluate(app: &Retained<NSApplication>, ctx: &LAContext, reason: &NSString) {
        let app_for_block: Retained<NSApplication> = Retained::clone(app);
        let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let outcome = if ok.as_bool() {
                Outcome::Approved
            } else {
                Outcome::BiometricFailed
            };
            eprintln!("approver outcome: {outcome:?}");
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

    pub fn run() {
        let mtm = MainThreadMarker::new().expect("must run on main thread");
        let app = init_app(mtm);
        let window = make_floating_panel(mtm);
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };
        let (stack, _auth_view, _cancel) = build_content(mtm, &app, &ctx);
        window.setContentView(Some(&stack));
        // `mainScreen` は「現在キーウィンドウを持つ画面」を返す (Apple 用語の罠だが、
        // Accessory app の起動時点では他アプリがフォーカスを持っているため、その
        // アプリのある画面 = ユーザが直前に操作していた画面 の中央に置かれる)。
        // マルチモニタ環境で「フォーカスを持つアプリのモニタ中央」に配置する要求
        // (kawaz、Phase 1.3) に対応する。
        window.center();
        window.makeKeyAndOrderFront(None);

        // draft-DR-0031 §UX policy: default focus_steal = true。現状 config を
        // 導入せず常に steal する (config parse + opt-out は後続 Phase)。
        // observer token は app.run() の間 drop しないよう保持する。
        let _focus_observer = register_focus_steal_on_launch(&window);

        let reason = NSString::from_str("Authenticate to access secret");
        evaluate(&app, &ctx, &reason);

        app.run();
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    approver::run();

    #[cfg(not(target_os = "macos"))]
    eprintln!("cache-warden-approver is macOS-only (LocalAuthenticationEmbeddedUI).");
}
