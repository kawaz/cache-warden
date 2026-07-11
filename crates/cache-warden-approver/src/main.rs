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
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2::{MainThreadMarker, MainThreadOnly, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSButton, NSControlSize,
        NSFloatingWindowLevel, NSStackView, NSStackViewDistribution, NSTextField,
        NSUserInterfaceLayoutOrientation, NSWindow, NSWindowStyleMask,
    };
    use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
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

    /// draft-DR-0031 §UX policy: focus 制御の default steal を実現するため
    /// activation policy を `.Regular` にする。非バンドル起動時は Dock Icon が出るか
    /// 出ないかが実装依存 = Phase 1.1 の実機確認項目 (出たら Info.plist + .app
    /// バンドル化を Phase 1.2 で追加)。
    fn init_app(mtm: MainThreadMarker) -> Retained<NSApplication> {
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Regular);
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
    /// PoC ver.2 で判明した実機観察:
    /// - `.Accessory` activation policy + `activateIgnoringOtherApps(true)` では
    ///   フォーカスを奪えず、focus 無しでは指紋 sensor input も受け付けられない
    ///   (Apple safety design 推定)
    ///
    /// この関数は `.Regular` activation policy を前提に、fokus 奪取のための追加処理を
    /// 順に呼ぶ:
    /// 1. `NSApplication::activate` (macOS 14+ の新 API) と旧 `activateIgnoringOtherApps`
    ///    (deprecated だが macOS 12 で必要) を併用
    /// 2. `window.orderFrontRegardless()` で ordering を強制
    /// 3. `window.makeKey()` で key window 化を明示
    fn steal_focus(app: &NSApplication, window: &NSWindow) {
        // 順序: orderFront → activate → makeKey で「見える → active → focused」の
        // 状態遷移を明示。macOS のバージョン依存挙動は Phase 1.1 の実機確認で
        // 詳細を詰める。
        window.orderFrontRegardless();

        // macOS 14+ (Sonoma) では非 deprecated な `activate` を使うが、objc2-app-kit
        // 0.3 系の bindings では `activate` の可用性が要確認 (unsafe 相当)。
        // Phase 1.1 は deprecated 経路の `activateIgnoringOtherApps(true)` を残す。
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        window.makeKeyWindow();
    }

    pub fn run() {
        let mtm = MainThreadMarker::new().expect("must run on main thread");
        let app = init_app(mtm);
        let window = make_floating_panel(mtm);
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };
        let (stack, _auth_view, _cancel) = build_content(mtm, &app, &ctx);
        window.setContentView(Some(&stack));
        window.makeKeyAndOrderFront(None);

        // draft-DR-0031 §UX policy: default focus_steal = true。Phase 1.1 では
        // config を導入せず常に steal する。Phase 1.2 で config parse + opt-out 実装。
        steal_focus(&app, &window);

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
