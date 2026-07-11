# Phase 1.3 — 自動 focus 奪取問題の解決 (2026-07-11)

draft-DR-0031 (custom TouchID dialog) の Phase 1.3 が完了。`.Accessory` (Dock Icon
非表示) を維持したまま自動 focus 奪取を成立させる経路を実機で確定した。詳細な
DR 反映は `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` §Phase 1.3
実機観察 に集約済み — 本 journal は経緯 (試行錯誤 / ハマり所) を残す。

## 前提

Phase 1.2 で `.app` バンドル化 + Info.plist `LSUIElement=YES` により Dock Icon は
消せた。ただし `.Accessory` activation policy では自動 focus を奪えず、focus 無し
では指紋 sensor input が app に配送されない (Apple safety design、DR §UX policy)。
Phase 1.3 の唯一の焦点はこの矛盾の解消。

## 試験順序 (state file §10 で予告した順)

Fable 5 セッション末尾 → Opus 4.7 [1m] xhigh に途中で切替。試験順序:

| 試験 | 経路 | 結果 |
|---|---|---|
| (a) | `NSRunningApplication.currentApplication().activateWithOptions:` | 戻り値 `false` (request 拒否)、focus 奪えず |
| (b) | `NSApplication::activate()` (macOS 14+ cooperative activation) | `isActive = false`、focus 奪えず |
| (c-1) | runtime `setActivationPolicy(.Regular)` + activate | Dock Icon 復活、focus 奪えず |
| (c-2) | Carbon `TransformProcessType(kProcessTransformToForegroundApplication)` + activate | OSStatus 0 でも focus 奪えず |
| (d) | `/usr/bin/open <bundle>.app` spawn | **成立**。activation → focus → 指紋配送 → `matched` |

## ハマり所 → 解決策のペア

### プロセス内 API では self-activation が全滅

**症状**: (a)〜(c-2) いずれも失敗、`isActive` が false のまま。coreauthd 側は
`will start matching` は heartbeat で発火するが `finger-on` が来ない。

**根本原因**: macOS 14+ の cooperative activation で「フォーカス盗み防止」が
強化されており、**ユーザ操作起点でない self-activation はプロセス内のどの
AppKit / Carbon API 経路でも拒否される**。試験 (a) の戻り値 false、(b) の
`isActive = false`、(c-2) の OSStatus 0 (関数自体は成功) でも activate が来ない、
のトリオが揃って初めて確信できた。

**解決策**: `/usr/bin/open` を子プロセスとして spawn し、LaunchServices
(システム側プロセス) に activate 要求を出させる。self ではなく別プロセス起点の
activate なので防止機構の対象外になる。

### 起動直後 spawn の順序競合を sleep で誤魔化しかけた

**症状**: 試験 (d) 初回、`open` を `run()` の主線で spawn したら 1 回目は成立
したが、順序として「window 表示 → LaunchServices activation 要求 → focus 着」の
順を保証していない。kawaz 指摘「sleep じゃなく window イベントの後にやるべき」
= sleep は [[sloppy-ai-patterns]] の代表格。

**解決策**: `NSNotificationCenter.defaultCenter.addObserverForName:` で
`NSApplicationDidFinishLaunchingNotification` を待ち、observer block から
`open` を spawn。sleep なしで順序保証 (event-driven primitive の適用)。observer
token を `run()` scope に `_focus_observer` として保持し drop 防止。

### ダイアログが「メインスクリーンの左下」に出る

**症状**: `make_floating_panel` で `NSRect { origin: (0, 0), ... }` を渡していた
= macOS の window 座標系「メインスクリーン左下原点」の (0, 0)。マルチモニタ環境
で謎の場所に見えた (kawaz 指摘)。

**解決策**: `setContentView` 後 `makeKeyAndOrderFront` 前に `window.center()`
を呼ぶ。`NSScreen::mainScreen` は「現在キーウィンドウを持つ画面」なので、
`.Accessory` app 起動時点では **他アプリ (起動前 frontmost) のある画面** の中央
に置かれる = ユーザが直前に触っていたモニタの中央。

## Fable 5 → Opus 4.7 [1m] 切替の経緯

- 前セッション末尾 (Fable 5) で Phase 1.2 完遂
- 本 session 開始も Fable 5 で試験 (a)〜(d) まで通したが、`safeguard` に触れて
  応答不能になった (kawaz 診断: **短時間の連続 TouchID チャレンジ (6 回)** が
  anomaly detection トリガと推定)
- Opus 4.7 [1m] xhigh に切替、Phase 1.3 のドキュメント整備を完遂

**教訓**: モデル依存だが、Fable は TouchID / biometric 関連の高頻度実機叩きに
過敏。Phase 1.4 以降で再度実機試験を頻回に要求する場面は Opus [1m] で進める
のが安全。

## Phase 1.3 で確定した helper 実装 (`crates/cache-warden-approver`)

- `steal_focus(window)`: `orderFrontRegardless` → `makeKeyWindow` →
  `/usr/bin/open <bundle>.app` spawn
- `register_focus_steal_on_launch(window)`:
  `NSApplicationDidFinishLaunching` observer 登録、observer token を返す
- `run()`: `window.center()` → `makeKeyAndOrderFront` → observer 登録 →
  `evaluate` → `app.run()`
- Cargo.toml: objc2-foundation に `NSNotification` / `NSOperation` / `block2`
  feature 追加、objc2-app-kit から `NSRunningApplication` / Carbon 関連依存を
  削除

## 次フェーズ (Phase 1.4) への引き渡し

- Phase 1.4: IPC (unix socket + serde_json) + wire schema。承認情報 hardcoded →
  ApproveRequest 構造体を Rust 側で定義、daemon 側 `daemon/approver.rs` 新設
- Phase 1.5: 双方向 peer 認証 (`macos-process-inspect` crate 活用、DR-0031
  §Security)
- draft 剥がし (DR-0030/0031/0032 → 番号採番): Phase 1.5 完了時に kawaz 判断で

## 関連

- `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` §Phase 1.3 実機観察
- 前 journal / findings: 本リポには Phase 1.1〜1.2 の journal は無し (DR 内 §Phase
  1.1 実機観察 に集約されていた)。Phase 1.3 で「試行錯誤の物語」が長くなったので
  journal 側にも切り出した
