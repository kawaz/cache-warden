//! draft-DR-0031 案 A (Rust + objc2 統一) の PoC gate 検証用バイナリ。
//!
//! # スコープ
//!
//! DR-0031 §2「Rust PoC 合格条件」のうち **build レベルで検査できる項目**
//! (バインディングが揃うか、シグネチャが噛み合うか、`NSApplication` /
//! `NSWindow` / `LAAuthenticationView` / `LAContext.evaluatePolicy` +
//! `block2::RcBlock` の Rust 側統合パスが型検査を通るか) を確認するための
//! 最小コード。実行しての UI 動作 (指紋アイコンの染色アニメ / 標準シートが
//! 別途出るか出ないか / codesign+notarize / daemon spawn + fd 渡し) は
//! kawaz 在席時の実機検証 (メインセッション主導) に委ねる。
//!
//! # 意図的な非スコープ
//!
//! - IPC socket / socketpair / peer 認証 (§Security): 未知は UI 側なので
//!   PoC 対象外。DR-0031 §4 の wire schema と §Security の双方向 peer 認証は
//!   別 PR で helper crate 本実装時に整備する
//! - `Contents/Info.plist` の `LSUIElement=YES`: bundle 化時に付ける (本 PoC は
//!   単独 exe、`NSApplication::setActivationPolicy(Accessory)` で dock 非表示は
//!   実行時に効く)
//! - Cancel ボタンの target/action ワイヤリング: `NSButton` のインスタンス化
//!   まで通るところを検査、実 target は Objective-C class delegate 実装を要する
//!   ため helper 本実装時に組む。build 検査上は Outcome enum で 4 経路の型が
//!   揃っていることを確認する
//! - `peer_gone` の kqueue 検知 (§7): daemon 側の関心事、本 PoC は Outcome の
//!   型のみ用意

// PoC 全体が macOS 依存 (LocalAuthenticationEmbeddedUI が macOS 専用)。
// 非 macOS では main を空にして workspace 全体 build を壊さない。
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod poc {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSButton, NSControlSize,
        NSFloatingWindowLevel, NSStackView, NSStackViewDistribution, NSTextField,
        NSUserInterfaceLayoutOrientation, NSWindow, NSWindowStyleMask,
    };
    use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use objc2_local_authentication_embedded_ui::LAAuthenticationView;

    /// DR-0031 §4 の `ApproveResponse.outcome` のうち、PoC が UI 側で
    /// 到達可能な 4 経路。IPC への直列化は本 PoC の非スコープ。
    #[derive(Debug, Clone, Copy)]
    #[allow(dead_code)]
    pub enum Outcome {
        Approved,
        Cancelled,
        PeerGone,
        BiometricFailed,
    }

    /// LSUIElement 相当の Dock 非表示 + Accessory activation policy。
    fn init_app(mtm: MainThreadMarker) -> Retained<NSApplication> {
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        app
    }

    /// DR-0031 §5 の layout 制約 (400px 前後、floating panel level)。
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
        // NSWindow::Level の isize alias `NSFloatingWindowLevel` を渡す。
        // `NSWindow.Level.floating` に相当。
        window.setLevel(NSFloatingWindowLevel);
        window.setTitle(&NSString::from_str("cache-warden approver (PoC)"));
        window
    }

    /// DR-0031 §5 サマリ dialog の情報階層 (呼び出し元 → チェック → cw、
    /// 見出し、ボタン) を最小要素で組む。requester icon / チップ / 詳細展開
    /// は helper 本実装時に追加。
    fn build_content(
        mtm: MainThreadMarker,
        ctx: &LAContext,
    ) -> (
        Retained<NSStackView>,
        Retained<LAAuthenticationView>,
        Retained<NSButton>,
    ) {
        let stack = NSStackView::new(mtm);
        stack.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
        stack.setDistribution(NSStackViewDistribution::Fill);

        // サマリ label (「Allow <requester> to read <key>」相当)。
        let summary = NSTextField::labelWithString(
            &NSString::from_str("Allow requester to read secret"),
            mtm,
        );
        stack.addArrangedSubview(&summary);

        // 本 PoC の中心: LAAuthenticationView を独自 NSStackView に埋め込む。
        // DR-0031 §6 の Mode A (LAAuthenticationView 埋め込み) 相当。
        let auth_view = unsafe {
            LAAuthenticationView::initWithContext_controlSize(
                LAAuthenticationView::alloc(mtm),
                ctx,
                NSControlSize::Large,
            )
        };
        stack.addArrangedSubview(&auth_view);

        // Cancel ボタン。target/action ワイヤリングは helper 本実装時に
        // Objective-C delegate class 実装を追加して結線する。
        // SAFETY: title は本 PoC が保持する static-lifetime NSString、
        // target/action は nil、mtm はメインスレッド。副作用は allocation のみ。
        let cancel = unsafe {
            NSButton::buttonWithTitle_target_action(&NSString::from_str("Cancel"), None, None, mtm)
        };
        stack.addArrangedSubview(&cancel);

        (stack, auth_view, cancel)
    }

    /// DR-0031 §6 の `evaluate` 相当。`RcBlock` で `LAContext.evaluatePolicy`
    /// の completion callback を Rust closure に橋渡しし、Approved /
    /// BiometricFailed の 2 経路を Outcome に変換する。
    ///
    /// Cancelled / PeerGone は呼び出し側 (Cancel ボタン handler / kqueue
    /// `NOTE_EXIT` handler) が `ctx.invalidate()` を呼び、その結果として
    /// この block が `err.code == LAError.appCancel` などで戻ってくる経路と、
    /// block を待たずに outcome を先送りする経路が併存する (v1 helper で
    /// 詳細分岐)。本 PoC は 4 経路の型が並ぶことのみ検査する。
    fn evaluate(ctx: &LAContext, reason: &NSString) {
        let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
            let outcome = if ok.as_bool() {
                Outcome::Approved
            } else {
                // biometric failed / cancelled / peer_gone のいずれも
                // 現段階では BiometricFailed に丸める (詳細は err.code で
                // 分岐する — helper 本実装時)。
                Outcome::BiometricFailed
            };
            // 本 PoC では outcome を捨てる (IPC は非スコープ)。
            let _ = outcome;
        });
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                reason,
                &block,
            );
        }
    }

    /// 参照はしないが、4 経路すべてが到達可能であることを型レベルで示す。
    /// dead_code を避けたい場合に呼ばれる想定 (main から一度参照)。
    #[allow(dead_code)]
    pub fn all_outcomes() -> [Outcome; 4] {
        [
            Outcome::Approved,
            Outcome::Cancelled,
            Outcome::PeerGone,
            Outcome::BiometricFailed,
        ]
    }

    pub fn run() {
        // build 検査目的なので run() 経路も型が揃うことを示す。
        // 実行時は NSApplication::run() で main loop に入り、evaluatePolicy
        // の block callback が Cocoa main queue で dispatch される。
        let mtm = MainThreadMarker::new().expect("must run on main thread");
        let app = init_app(mtm);
        let window = make_floating_panel(mtm);
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };
        let (stack, _auth_view, _cancel) = build_content(mtm, &ctx);
        window.setContentView(Some(&stack));
        window.makeKeyAndOrderFront(None);

        let reason = NSString::from_str("Authenticate to access secret");
        evaluate(&ctx, &reason);

        // 4 outcome 経路の到達性を型レベルで確認。
        let _ = all_outcomes();

        // 実行時に UI を出す場合は `unsafe { app.run() };`。
        // 本 PoC は build gate 目的なので明示 return し、実行時起動は
        // kawaz 在席時の実機検証に譲る (TouchID が発火するため)。
        let _ = app;
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    poc::run();

    #[cfg(not(target_os = "macos"))]
    eprintln!("cache-warden-approver-poc is macOS-only (LocalAuthenticationEmbeddedUI).");
}
