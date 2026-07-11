# draft-DR-0031: custom TouchID 承認 dialog — 1Password 方式の独自 GUI helper

- Status: Draft — **方向性は kawaz 裁定済み (2026-07-10)**: 「TouchID はローカル本人確認
  として UX が良いので進めて良い。helper app で UI を出し daemon とはソケット通信、
  相手プロセス / TCC / 署名確認は基本。Linux 対応はなし」。リモート承認
  (draft-DR-0032) と相補構成にする (例: passkey 登録時はローカル TouchID 必須)。
  **Open Q4 (helper 実装言語) は 2026-07-11 実機 PoC 通過で案 A (Rust 統一) に確定**
  (§PoC gate 実機検証結果 参照)。helper 本実装フェーズの accept 判断は kawaz 明示指示待ち
- Date: 2026-07-10
- 関連: issue `2026-06-22-custom-touchid-dialog` (背景・受け入れ条件) /
  draft-DR-0030 (kv per-entry peer-identity guard、評価結果を dialog で表示する接続点) /
  DR-0022 `[auth].command` (再認証ゲート、helper と共存させる評価順) /
  DR-0020 (macOS codesign / notarize / .app / TCC 常駐要件) /
  crate `macos-process-inspect` (dialog に載せる requester chain の取得 API) /
  research `docs/research/2026-07-10-touchid-dialog-ui-options.md` (実現手段の事前調査)

## Context

1Password が op CLI 経由で secret を出そうとするときに表示する承認 dialog は
「〈呼び出し元 app 名〉が SSH の許可を求めています」程度しか示さない **白紙委任**で、
secret の消費側は「何が呼ばれたか、どの item に触ろうとしているか、承認したら何が
起きるか」が分からないまま指紋を押す構造になっている。

一方、1Password 本体 (op CLI ではなく GUI app) が自ら secret を出すときに使う承認
dialog は、実機観察により **1Password.app 本体が host する独自 UI** であることが
判明した (kawaz 実機、2026-07-10):

- Karabiner-EventViewer: `frontmost_application.bundle_identifier = com.1password.1password`
  (dialog を出しているのは 1Password.app 本体プロセス)
- `focused_ui_element.role_string = AXWebArea` (Web view で描画)
- 見た目: 角丸ダークパネル、requester (Ghostty) → チェック → 1Password の対称アイコン、
  対象 vault 名 (「河津家」)、「認証 Touch ID」ラベル + 指紋アイコン、Cancel ボタン
- 挙動: dialog window の中で **指紋アイコンが徐々に赤く染色するアニメーション**、
  TouchID を触ると染色が完了し dialog が消える (標準 evaluatePolicy シートが**別に
  出ている痕跡は視認されない**)

bundle 実機観察 (2026-07-10、`ls` / `otool -L` / `codesign -d`、read-only):

- 主要 UI は **Electron** (`Contents/Frameworks/Electron Framework.framework`、
  Web リソースは 38 MB の `app.asar` に閉じ込め)。1P が Electron を選んだのは**アプリ
  全体 UI が Web ベースだから**であり、TouchID dialog 単体には Electron は必要ない
- `Contents/Frameworks/index.node` (Rust 製ネイティブアドオン、build path から
  `libop_core_node.dylib` を確認) と `libop_sdk_lib_core.dylib` (Rust 製 SDK) が
  **`LocalAuthenticationEmbeddedUI.framework` を直接リンク**している
- Electron Framework 本体は `LocalAuthentication.framework` のみリンク、`op-ssh-sign`
  (別バイナリ、SSH 用) は LocalAuthentication 系一切リンクなし (SecKey API 経由と推定)
- LocalAuthentication 系 entitlement は要求されていない (メイン .app の entitlements
  で確認)
- 稼働プロセス: メイン (pid 822、Electron) + Renderer × 2 + GPU + Network utility +
  Login Items 2 種、helper.app の入れ子構造は Electron 由来

これから読み取れる示唆 (recon 結論):

- **`LocalAuthenticationEmbeddedUI.framework` が「独自 UI 内に埋め込む指紋 UI」の実装
  経路として最有力**。1P はこれを Rust 製ライブラリから直接呼んでいる = **Rust から
  技術的に到達可能な実証例が存在**
- **Electron は cache-warden の設計に不要**。dialog 単体なら SwiftUI or Rust + AppKit
  で 400x325 の floating panel を出せば足りる
- **軽量 helper 分離パターン** (メイン UI と署名専用軽量バイナリ `op-ssh-sign` を分離)
  は cache-warden の「daemon 本体 / dialog 専用 helper」分離設計と親和的

**LAEmbeddedUI の公開度は確定** (2026-07-10 の 2 本 recon: `lacontext-inline-recon` +
`laeui-recon`。後者は実機ヘッダ + Xcode SDK で verbatim 確認):

- **公開 API**: `/System/Library/Frameworks/LocalAuthenticationEmbeddedUI.framework/`
  直下配置 (PrivateFrameworks ではない)、Xcode SDK に Objective-C header + Swift
  module interface + module.modulemap が完備、Beta/Deprecated 表記なしの安定 API
- **最小プラットフォームバージョン (実機ヘッダ verbatim)**: **macOS 12.0 (Monterey)** /
  iOS 16.0 / iPadOS 16.0 / Mac Catalyst 16.0 / visionOS 1.0。当初 recon で示唆された
  「macOS 13 Ventura」は誤り、正しくは Monterey
- 発表: WWDC22 セッション "Streamline local authorization flows" (session 10108)
  で LAContext 全般の中で言及、embedded UI 専用セッションはなし
- API 構成 (実機ヘッダ verbatim):
  - `LAAuthenticationView : NSView` (macOS 12.0+、AppKit ベース、iOS/watchOS/tvOS は unavailable)
    - `- (instancetype)initWithContext:(LAContext *)context;`
    - `- (instancetype)initWithContext:(LAContext *)context controlSize:(NSControlSize)controlSize;`
    - readonly properties: `context`, `controlSize`
  - サポート policy: `LAPolicyDeviceOwnerAuthenticationWithBiometrics` /
    `WithCompanion` / `WithBiometricsOrCompanion` / `DeviceOwnerAuthentication`
  - `LARight (UI)` カテゴリ (macOS 13.0+):
    `authorizeWithLocalizedReason:inPresentationContext:completion:` — 別 API
  - `LAPresentationContext` = `NSWindow` alias (macOS) / `UIWindow` (iOS)
- ヘッダ doc comment verbatim: "Compact authentication view providing authentication
  similar to LAContext evaluatePolicy API. This view is non-textual, it displays only
  a compact icon hinting users to use Touch ID or Watch to authenticate. **The reason
  for the authentication must be apparent from the surrounding UI to avoid confusion
  and security risks.**"
- Rust binding: **`objc2-local-authentication-embedded-ui` crate が既存**
  (v0.3.2, 2025-10-04 公開, docs.rs 100%対応, Zlib/Apache/MIT)。madsmtm/objc2 の一部。
  cache-warden の依存は現状 objc2 系ゼロなので新規追加になる
- SwiftUI 統合: `_LocalAuthentication_SwiftUI.framework` の中身を la-swiftui-recon で
  実機ヘッダ + Xcode SDK swiftinterface 確認した結果、**SwiftUI ネイティブ View
  `LocalAuthenticationView` (public struct、macOS 13.0+/Ventura) が存在**。macCatalyst
  以外の macOS 専用、内部で `import LocalAuthenticationEmbeddedUI` して AppKit の
  LAAuthenticationView を wrap している構造 (推定):

  ```swift
  // .swiftinterface verbatim (抜粋)
  @available(macOS 13.0, *)
  public struct LocalAuthenticationView<Label> : View where Label : View {
    public init(context: LAContext, @ViewBuilder label: () -> Label)
    public init(_ titleKey: LocalizedStringKey, context: LAContext) where Label == Text
    public init(reason: Text, context: LAContext? = nil,
                result: @escaping (Result<Void, Error>) -> Void,
                @ViewBuilder label: () -> Label)
    // ...
  }
  ```

  ただし customization surface は title/reason/context/result callback のみで、
  1P dialog のようなリッチ UI (呼び出し元アイコン + 詳細 tap 展開等) を作るには
  自前で作り込みが残る (SwiftUI 側の宣言的レイアウトに乗せられる分は楽になる)
- **1P の完成度が高い理由の仮説 (推測)**: `_LocalAuthentication_SwiftUI.tbd` に
  swiftinterface に露出していない private シンボル `SheetConfiguration` (callerName /
  callerIconPath / authenticationTitle / authenticationMessage / authenticationHint /
  submitButtonTitle / fallbackButtonTitle 等の豊富な customization フィールド) +
  `View.authenticationSheet(isPresented:configuration:onCompletion:)` modifier が存在
  (la-swiftui-recon で確認)。1P dialog の完成度 (呼び出し元アイコン + カスタム文言 +
  Vault 展開等) は SheetConfiguration の各フィールドと一致度が高く、**1P はこの
  private API を使っている可能性が高い** (App Store 提出しないので Developer ID +
  notarize で通す前提)。**cache-warden は private API 不採用** — 将来 OS 更新で
  無警告 break のリスクが実運用として過大。public API の範囲で実装する結果、
  1P より控えめな dialog になる可能性を許容する
- notarize / entitlement: 明示的な追加 entitlement 要求は公式 doc に見当たらず、
  1Password.app が Developer ID notarize で通っている実例が最有力の状況証拠。
  cache-warden 自身での通過は未検証 (Phase 1 land 前に必ず実機確認)

これで 1P dialog の「指紋アイコンが徐々に染色するアニメ」は **LAAuthenticationView を
独自 dialog window 内に埋め込んだもの**という仮説が最も蓋然性が高い (Occam's razor:
公式に目的が一致する framework がある以上、private API に走る動機は薄い)。

参考: `docs/research/2026-07-10-touchid-dialog-ui-options.md` (先行研究) と、
本 DR 執筆に伴い実施した 4 本の recon (`1p-bundle-recon` + `lacontext-inline-recon` +
`laeui-recon` + `la-swiftui-recon`)。

この方式は cache-warden の要件 (requester 情報の透明性、対象 kv entry の明示、
DR-0030 の guard 評価結果の可視化) と設計目標が一致する。本 DR は 1Password 方式に
倣った独自 dialog を cache-warden に導入する設計を確定する。

先行研究 (`docs/research/2026-07-10-touchid-dialog-ui-options.md`) の 3 案:

- A 案 (Rust 完結、`localizedReason` に 1 行圧縮): 標準シートしか出せず「プロセスツリー
  表示」の受け入れ条件を満たせない。中間段として先行実装する価値はあるが最終形にならない
- B 案 (daemon 内 AppKit): tokio との NSApplication run loop 争奪、不採用
- **C 案 (Swift/AppKit helper を .app 同梱、IPC + カスタム window)**: 1Password 方式に
  最も近い。本 DR で採用

## Decision (骨子)

### 1. アーキテクチャ — 常駐 GUI helper + IPC

`CacheWarden.app` bundle 内に GUI helper `CacheWardenApprover.app`
(または `Contents/Helpers/CacheWardenApprover.app`) を同梱し、以下の 2 プロセス構成にする:

```
┌─────────────────────────┐    unix socket    ┌──────────────────────────┐
│ cache-warden (daemon)   │ ─────────────────▶ │ CacheWardenApprover      │
│ - CLI, tokio            │   ApproveRequest   │ - Swift + SwiftUI/AppKit │
│ - kv/authsock/auth      │ ◀───────────────── │ - LocalAuthentication    │
│ - LSUIElement (実質)    │   ApproveResponse  │ - LSUIElement=YES        │
│ - control socket 主体   │                    │ - LAContext              │
└─────────────────────────┘                    └──────────────────────────┘
```

- **daemon (現行 `cache-warden`)**: 変更なしを原則、helper 呼び出し口 (`daemon/approver.rs`) を
  新設。Rust のまま
- **helper (`CacheWardenApprover`)**: 実装言語は **Rust + objc2 統一** と
  **Swift + SwiftUI** の 2 案が現実的 (§2 で 2 案比較、判断は Open Question 4 で kawaz
  レビュー)。laeui-recon で `objc2-local-authentication-embedded-ui` crate の存在が
  確認されたため、当初の「Swift 確定」判断は撤回し両論併記に戻す

### 2. helper 実装言語 — Rust 統一と Swift 併存の 2 案 (判断保留)

recon 4 本の結果を統合すると、helper 実装言語には 3 通りの現実的な選択肢がある:

- **案 A**: Rust + objc2 系 (LAAuthenticationView を直接叩く、macOS 12+ 対応)
- **案 B1**: Swift + SwiftUI native (LocalAuthenticationView を使う、macOS 13+ 必要)
- **案 B2**: Swift + AppKit ラップ (LAAuthenticationView を NSViewRepresentable で
  wrap、macOS 12+ 対応)

**案 A: Rust 統一 (helper も Rust + objc2 系)**:

依存追加 (helper crate):
- `objc2` (v0.6 系、既に cache-warden の transitive dep 候補) — Foundation / Runtime
- `objc2-app-kit` (v0.3 系) — NSWindow / NSView / NSButton / NSTextField / NSImageView /
  NSApplication
- `objc2-local-authentication` — LAContext / LAPolicy / evaluatePolicy
- `objc2-local-authentication-embedded-ui` — LAAuthenticationView (recon 実測、
  docs.rs 100% coverage、Zlib/Apache/MIT ライセンス、依存が透明)
- `objc2-foundation` — NSString / NSError

実装距離見積 (helper 全体):
- NSApplication + NSWindow (Floating panel, LSUIElement) 立ち上げ: 100〜150 行
- SwiftUI 版 `ApproverDialog` 相当の NSView 階層構築 (角丸パネル、requester icon,
  summary label, chip, LAAuthenticationView 埋め込み, ボタン): 250〜400 行
- LAContext.evaluatePolicy の block/closure 経由 callback: 50〜100 行
- IPC (unix socket + serde_json)、pid polling (§7): 150〜200 行 (daemon 側と共通の
  wire schema crate を引ける)
- **合計目安: 550〜850 行の unsafe/objc2 コード** (当初想定の 1500-2500 行は過大評価
  だった。既存 crate がバインドを提供している分の恩恵)

Pros:
- 言語統一維持、build system 変更最小 (release.yml 追加ステップなし、cross-compile 経路
  はそのまま)
- daemon 側と wire schema (serde 型) を共有できる — JSON 化しても型は 1 箇所定義
- 依存追加は objc2 系のみ、macOS フレームワーク直接叩きが cache-warden の既存
  `libc` FFI パターンと同じ思想
- 保守: 1 言語で完結、SDK 更新は objc2 の crate バージョン追随で吸収

Cons:
- AppKit runloop + tokio の同居は不要 (helper は独立プロセス、NSApplication.run() が
  main thread) だが、Rust から AppKit を扱う trial & error コストが読みにくい
  (laeui-recon 所感)。madsmtm/objc2 の examples に近い形はあるが、
  LAAuthenticationView + `NSViewRepresentable` 相当の統合パターンの参考実装は少ない
- SwiftUI の宣言的 layout システムより手続き的 (add subview 呼ぶ形式)、将来 dialog を
  凝るときの修正距離が SwiftUI より長い

**案 B1: Swift + SwiftUI native (`LocalAuthenticationView` 使用、macOS 13+)**:

実装距離見積:
- SwiftUI `ApproverDialog` View (`LocalAuthenticationView` が直接 View、
  NSViewRepresentable ラッパー不要): 200〜300 行 (la-swiftui-recon 所感: 「SwiftUI
  ネイティブ利用でも AppKit ラップ相当分の 100 行程度しか削減されない、customization
  surface が制限的で結局自前作り込みが残る」)
- LAContext.evaluatePolicy 相当は `LocalAuthenticationView` が内部で扱う: 統合コード 30〜50 行
- IPC (SwiftNIO or Foundation.URLSession の unix socket、peer_pid 取得): 100〜200 行
- **合計目安: 330〜550 行**

Pros:
- SwiftUI ネイティブで LocalAuthenticationView を宣言的に配置可能
- Apple 公式 sample (WWDC22 session 10108 系) 流用が最短
- SwiftUI の宣言的 layout で将来の見た目調整コストが低い

Cons:
- **macOS 13.0 (Ventura) 最小要件**: LocalAuthenticationView が Ventura 以降。
  cache-warden のこれまでの実質下限 (Monterey) から 1 バージョン上げる判断
- build system 追加 (xcodebuild + Swift Package Manager)、release.yml と .app packaging
  変更 (DR-0020 の署名・notarize 手順に nested Swift bundle のステップ追加)
- helper のロジックが daemon 側と言語分離、型共有が失われる (JSON wire schema)
- Swift 依存導入 — 「Rust オンリー」の設計原則を helper に限って緩める判断
- customization surface が制限的 (title/reason/context/result callback のみ)。1P 風の
  リッチ UI (呼び出し元アイコン等) を実現するには結局 SwiftUI 側で自前 View 構築が必要

**案 B2: Swift + AppKit ラップ (`LAAuthenticationView` を NSViewRepresentable で wrap、macOS 12+)**:

実装距離見積:
- NSViewRepresentable ラッパー (LAAuthenticationView 用): 30〜50 行
- SwiftUI `ApproverDialog` View: 200〜300 行
- LAContext.evaluatePolicy の Swift async/await 統合: 30〜50 行
- IPC: 100〜200 行
- **合計目安: 360〜600 行**

Pros:
- macOS 12 (Monterey) 対応維持 (案 A と同じ下限)
- SwiftUI の宣言的 layout の利益は得られる
- 案 B1 と同じ SwiftUI + LAContext の統合パターン

Cons:
- 案 B1 と同じ build system 追加 + Swift 依存導入コスト
- NSViewRepresentable の追加実装 (SwiftUI native 版なら不要だった 30-50 行)
- Apple 公式 sample は SwiftUI native 版が多く、AppKit ラップの参考は少ない

**両案共通の設計**:
「§1 の 2 プロセス構成」「§4 の JSON IPC」「§5 の dialog 情報階層」「§7 peer exit」
「§8 二重 dialog 防止」「§9 fallback」「§10 graceful restart 整合」は言語非依存で成立。
言語選択が変わっても daemon 側は無傷、helper 内部のみ切替可能。

**実装距離の総括**:

| 案 | 実装距離見積 | macOS 下限 | build system 変更 |
|---|---|---|---|
| A: Rust 統一 (objc2 系) | 550-850 行 | 12.0 Monterey | 最小 (Cargo に crate 追加のみ) |
| B1: Swift + SwiftUI native | 330-550 行 | 13.0 Ventura | 大 (xcodebuild + SwiftPM) |
| B2: Swift + AppKit ラップ | 360-600 行 | 12.0 Monterey | 大 (xcodebuild + SwiftPM) |

実装距離差は当初想定の 1/3-1/5 ではなく **1.3-1.6 倍程度**に収束 (la-swiftui-recon で
Swift native の短縮効果が限定的と判明したため)。

**現時点の推奨 (PoC 実施後に確定、Open Question 4)** — codex review medium-5 対応:

行数見積は「短い方が実装が終わる」を保証しない。Rust 案は AppKit runloop / NSView
hierarchy / Auto Layout / block callback / LAContext lifetime / NSWindow activation の
trial & error コストが読みにくく、Swift 案は逆に xcodebuild/SPM/nested app 署名
notarize/CI cache/JSON schema 二重定義の運用負担が読みにくい。draft の Rust 推奨は
**最終判断ではなく PoC gate に置く**:

**Rust PoC 合格条件** (Phase 1 land 前に満たす必要):
1. `NSApplication` main thread run loop で NSWindow が floating panel として表示され、
   Dock 非表示 (LSUIElement=YES) が有効
2. LAAuthenticationView が dialog window 内に埋め込まれ表示される
3. LAContext.evaluatePolicy が block callback 経由で完了、以下 4 経路がすべて動く:
   `.approved` / `.cancelled` / `.peer_gone` / `.biometricFailed`
4. helper bundle が Developer ID + notarize で **実機で** 通り、
   `codesign --verify --deep --strict CacheWardenApprover.app` が通る
5. daemon から spawn + fd 渡し + 双方向 peer 認証 (§Security) が動作

**Swift PoC 合格条件** (Phase 1 land 前に満たす必要):
1-5 は上と同じ。加えて:
6. xcodebuild + SwiftPM が Cargo と共存し、release.yml の GitHub Actions runner
   (macos-latest) で cross-target build まで通る
7. nested Swift `.app` を含めた `.app` 全体の codesign / notarize が通る (DR-0020
   の bottom-up sign 手順に helper が正しく含まれる)
8. JSON wire schema (§4) を daemon (Rust serde) と helper (Swift Codable) の両側で
   互換に保つ contract test が回る

Rust PoC が (1-5) を通れば **案 A で v1 land**。通らなければ Swift PoC (1-8) が通る
案 B1 or B2 に切替。実装距離差が 1.3-1.6 倍程度なので、Phase 1 の中で両方を並行 PoC
することも許容 (最初に land した方を採用する形)。

**判断軸 (どちらの PoC を優先するか)**:
- 「Rust オンリー」の設計原則を helper のためだけに崩したくない → 案 A を先行
- SwiftUI 宣言的 UI で将来の見た目大幅リッチ化が予定される、macOS 13+ 許容 → 案 B1 を先行
- Swift 依存を受け入れつつ Monterey 下限を維持したい → 案 B2 を先行

### 3. helper のライフサイクル

3 択:

- **(a) 常駐 (LaunchAgent 別登録)**: 起動即応、Activity Monitor に増加、DR-0019 に追加
- **(b) daemon が起動時に spawn し維持**: LaunchAgent 登録不要、daemon 死亡で helper も
  自然消滅、shutdown 制御が単純
- **(c) on-demand spawn (承認要求のたびに fork/exec)**: 常駐ゼロ、起動レイテンシ
  100〜300ms が体感を悪化

**採用: (b)**。daemon 側 `graceful restart` (DR-0029) の下位ケースとして helper を扱う。
daemon が exec で自身を差し替える時、helper は kill されるが KeepAlive はしない
(daemon の shutdown = 意図した消失)。daemon 起動時に helper.spawn、helper 死亡を
検知したら再 spawn、`shutdown` で helper に SIGTERM。

on-demand を採らない理由: 1Password の実機観察でも 1Password.app 本体 (pid 822) が
常駐しており、dialog 要求のたびに起動していない。TouchID 認証は「反応が速い」ことが
UX の中心要件で、100ms オーダの起動遅延は体感で明確に劣化する。

LaunchAgent 別登録 (a) を採らない理由: daemon が死んでる時に helper だけ生きていても
できることが無い (承認結果を渡す先がない)。「daemon の存在に helper がタグ付いている」
親子構造の方がライフサイクル一致度が高い。

### 4. IPC — Unix socket + JSON、control socket とは別チャネル

daemon → helper の approval request は以下の性質を持つ:

- 認証承認という強い意味論を持つ
- 応答が遅い (人間の指紋操作、数秒〜十数秒)
- 失敗パスが多い (Cancel / Timeout / Peer exit / Biometric fail)

これを既存 control socket (`control.sock`) に載せると、他の client からの kv / status
リクエストと同じキューに乗ってしまい、承認 pending がブロッカーになりうる。

**採用: helper が別 unix socket `approver.sock` をリスンし、daemon が接続する**
(control socket と分離)。

- socket path: `$XDG_STATE_HOME/cache-warden/approver.sock` (control socket と同一 dir)
- wire format: JSON 単発 request + response (control socket と同じ line-delimited JSON)。
  helper 内部は Swift、daemon 側は Rust なので typed schema は共有できず JSON 化が
  合流点として自然

wire schema (draft):

```
Request:  ApproveRequest {
    request_id: uuid,
    key: String,                       // 対象 kv entry (namespace 込み)
    operation: String,                 // "get" | "extend" | "regenerate" | "pin"
    requester: {
        chain: [{                       // macos-process-inspect の ProcessInfo
            pid, ppid, path, start_time
        }],
        audit_token: {                  // macos-process-inspect の AuditToken
            euid, ruid, egid, pid, pid_version
        },
        responsible_bundle_id: ?String, // TCC responsible process の bundle_id
    },
    guard_eval: {                       // DR-0030 の評価結果、guard 無しなら null (下記構造化 schema)
        constraints: [{
            kind: String,               // "same-user" | "same-shell" | "same-ancestor" | "command"
            matched: bool,              // 評価結果 (dialog 通過時は必ず全 true)
            strength: String,           // "strong" | "weak" (弱識別マークは Dialog 表示で明示)
            display_label: String,      // "same-shell (zsh)" 等の表示用
            risk_note: ?String,         // 弱識別の警告文 (weak の場合)
        }],
        setter_pinned: ?{               // 実体 pin された setter プロセス snapshot (same-ancestor 系のみ)
            pid: u32, start_time: u64, unique_id: ?u64,
            path: String, name: String,
        },
        getter_matched: ?{              // 実体 pin と一致した getter chain のプロセス
            pid: u32, start_time: u64, unique_id: ?u64,
            path: String, name: String,
        },
        evaluated_at: u64,              // Unix epoch nanoseconds
    } | null,
    timeout_secs: u32,                  // 60 デフォルト、helper 内で bounded
}
Response: ApproveResponse {
    request_id: uuid,
    outcome: "approved" | "denied" | "cancelled" | "peer_gone" | "timeout" | "biometric_failed"
    biometric_kind: ?String,            // "TouchID" | "Watch" | null (denied 等)
}
```

`requester.responsible_bundle_id` は既存 macos-tcc crate から取得
(DR-0020 の TCC responsible process 概念、findings 2026-06-12)。dialog 上部の
「呼び出し元アイコン」の解決に使う (`NSWorkspace.icon(forURL:)` で `.app` から取得)。
`responsible_bundle_id` が取れない CLI (Ghostty から起動した curl 等) は
requester.chain の最上位祖先 .app を helper 側で探索して fallback。

**`guard_eval` を構造化する理由** (codex review medium-4 対応): 単純な文字列
`matched_constraints: [String]` + human summary では、(a) dialog の詳細展開で
constraint ごとの詳細 (pin された pid/start_time/unique_id 等) を表示できない、
(b) 弱識別 (`command` 等) の警告表示ができない、(c) 将来 localization / redaction /
audit log に流用できない。setter identity data を helper に渡すが、`setter_pinned` /
`getter_matched` は既に **guard 通過した getter の accessible な情報範囲** で、
DR-0030 §7 の「setter identity を get 側 error に返さない」規定は「拒否時」の話であり、
承認時は setter/getter 両方の識別情報が dialog に必要になる (getter が「なぜこの
セッションから承認できるか」を理解するため)。

### 5. dialog の情報階層 (2 段: サマリ + 展開)

issue 受け入れ条件を満たすには「シンプル表示 + 詳細展開」の 2 段。
1Password 方式のサマリ + cache-warden 独自の詳細を追加:

**サマリ (デフォルト)**:
- [呼び出し元 app アイコン] → チェック → [cache-warden アイコン]
- 見出し: "Allow **〈requester 名〉** to read `〈key〉`"
- 補助行: guard 評価結果があれば「Verified: same-shell, same-user」を緑チップで
- ボタン: `Cancel` + `Touch ID authenticate`

**展開 (トグル)**:
- Requester ancestry chain (最新→launchd 方向): `zsh (pid 12345) → tmux (pid 12000) → sshd (pid 800)`
- code signature: `identifier=com.mitchellh.ghostty` (取得できれば)
- guard 評価詳細: constraint ごとに「◯ same-shell (pid pinned at zsh#12345, started 2h ago)」
- kv entry metadata: source (op / static / command)、TTL、last extended

**layout 制約**:
- 幅は 1Password と同等 (400px 前後)、高さは可変 (展開時)
- floating panel level (`NSWindow.Level.floating`)、他の window に隠れない
- LSUIElement=YES で Dock に helper アイコン非表示

### 6. LAContext + LAEmbeddedUI の統合 — v1 で LAAuthenticationView 採用

laeui-recon (§Context) で `LAAuthenticationView` が macOS 12 Monterey 以降の
**公開 API** と確定した。1P dialog の「指紋アイコンが徐々に染色するアニメ」の実装は
これで正体が判明したものとして扱い、v1 で採用する。

**v1 (Phase 1) の実装スケッチ (§2 案 A: Rust 統一)**:

```rust
// crates/cache-warden-approver/src/dialog.rs (概念スケッチ、正確なシグネチャは実装時)
use objc2::rc::Retained;
use objc2_app_kit::{NSWindow, NSView, NSButton, NSStackView, NSApplication};
use objc2_local_authentication::{LAContext, LAPolicy};
use objc2_local_authentication_embedded_ui::LAAuthenticationView;

fn build_dialog(request: &ApproveRequest) -> Retained<NSWindow> {
    let window = build_floating_panel(400.0, 325.0);
    let stack = NSStackView::new();
    stack.addArrangedSubview(&requester_header(request));       // icon → check → cw icon
    stack.addArrangedSubview(&summary_label(request));          // "Allow ... to read <key>"
    if let Some(g) = &request.guard_eval {
        stack.addArrangedSubview(&verified_chip(&g.matched_constraints));
    }
    let context = LAContext::new();
    let auth_view = LAAuthenticationView::initWithContext_controlSize(
        &context, NSControlSize::Large,
    );
    stack.addArrangedSubview(&auth_view);
    stack.addArrangedSubview(&button_row(cancel_handler, || evaluate(&context, request)));
    window.setContentView(Some(&stack));
    window
}

fn evaluate(ctx: &LAContext, request: &ApproveRequest) {
    let reason = NSString::from_str(&request.short_reason);
    unsafe {
        ctx.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics, &reason,
            block2::RcBlock::new(move |ok, err| {
                send_outcome_over_ipc(if ok { Outcome::Approved } else { Outcome::BiometricFailed });
            }),
        );
    }
}
```

**v1 (Phase 1) の実装スケッチ (§2 案 B1: Swift + SwiftUI native)**:

```swift
// SwiftUI, macOS 13+
struct ApproverDialog: View {
    let request: ApproveRequest
    let onOutcome: (ApproveOutcome) -> Void

    var body: some View {
        VStack {
            RequesterHeader(request: request)          // icon → check → cw icon
            SummaryLine(request: request)              // "Allow ... to read <key>"
            if let g = request.guardEval {
                VerifiedChip(matched: g.matchedConstraints)
            }
            // public LocalAuthenticationView (macOS 13+)
            LocalAuthenticationView(
                reason: Text("Authenticate to access \(request.key)"),
                context: LAContext(),
                result: { r in
                    switch r {
                    case .success:      onOutcome(.approved)
                    case .failure(let e): onOutcome(.biometricFailed(e))
                    }
                },
                label: { Text("Touch ID") }
            )
            Button("Cancel") { onOutcome(.cancelled) }
        }
    }
}
```

**v1 (Phase 1) の実装スケッチ (§2 案 B2: Swift + AppKit ラップ)**:

```swift
// SwiftUI + NSViewRepresentable, macOS 12+
struct LAAuthViewRepresentable: NSViewRepresentable {
    let context: LAContext
    func makeNSView(context: Context) -> LAAuthenticationView {
        LAAuthenticationView(context: self.context, controlSize: .large)
    }
    func updateNSView(_ nsView: LAAuthenticationView, context: Context) {}
}

struct ApproverDialog: View {
    @State var context = LAContext()
    let request: ApproveRequest
    let onOutcome: (ApproveOutcome) -> Void

    var body: some View {
        VStack {
            RequesterHeader(request: request)
            SummaryLine(request: request)
            if let g = request.guardEval {
                VerifiedChip(matched: g.matchedConstraints)
            }
            LAAuthViewRepresentable(context: context)
            HStack {
                Button("Cancel") { onOutcome(.cancelled) }
                Spacer()
                Button("Touch ID") { evaluate() }
            }
        }
    }

    func evaluate() {
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: request.shortReason) { ok, err in
            onOutcome(ok ? .approved : .biometricFailed(err))
        }
    }
}
```

**Mode A / Mode B の切替 (実装 PoC で判明する落とし穴への保険、land 条件を分離)**:

**LAAuthenticationView が標準モーダルシートを完全に代替する** ことは公式資料 verbatim
では未確認 (AI 要約経由の推論、laeui-recon は「ヘッダ doc + 状況証拠から推論、動画未
視聴」と明示)。**Mode A が実機 PoC で "標準 sheet が出ない、embedded UI 内で TouchID
完結" と確認できた場合にのみ「custom TouchID dialog」の受け入れ条件を満たしたと
みなす** (codex review medium-3 対応):

- **Mode A land 条件 (custom TouchID dialog として v1 完成)**:
  1. LAAuthenticationView 埋め込み dialog を表示し標準 evaluatePolicy シートが**出ない**
     ことを目視 + Accessibility Inspector で確認
  2. TouchID タッチで embedded UI の指紋アイコンが染色 → success 遷移
  3. Cancel / Peer gone / Biometric failed の各終了経路が dialog 内で完結

- **Mode B (暫定 UX、"metadata pre-prompt + standard LA sheet")**: Mode A の PoC で
  上記が満たせなかった場合の暫定形。「custom TouchID dialog を完全実装した」とは呼ば
  ずに release notes / doc で "metadata pre-prompt (v1 暫定形)" と明示する:
  - helper が独自 dialog を表示、metadata (requester chain / kv key / guard 評価結果) を
    見せる
  - ユーザが `Touch ID authenticate` ボタンを押すと標準 evaluatePolicy を呼ぶ
  - 標準シートが dialog の上に一瞬出て、TouchID を触ると完了
  - `localizedReason` は「Authenticate to access `<key>`」程度に短く
  - 二重 UI 体験 (独自 dialog → 標準シート) を許容 = **1P と等価な UX ではない**
    ことを明示、issue 受け入れ条件の「シンプル表示 + 詳細展開」は満たすが「dialog
    window 内で TouchID 完結」は Phase 3 に持ち越し

Mode A と Mode B の切替は helper 内部で完結し、daemon 側の IPC schema (§4) には
影響しない。Phase 1 の PoC で Mode A が動けば custom TouchID dialog として land、
動かなければ Mode B (metadata pre-prompt) で先行 land し Mode A は Phase 3 に回す。

**macOS 下限バージョン**: 実装言語選択 (Open Q4) と連動して以下の 2 択:

- 案 A (Rust + LAAuthenticationView) or 案 B2 (Swift + AppKit ラップ): **macOS 12 Monterey**
  最小要件 (LAAuthenticationView が Monterey 以降)
- 案 B1 (Swift + SwiftUI native LocalAuthenticationView): **macOS 13 Ventura** 最小要件

CI runner の `macos-latest` は既に Sonoma/Sequoia。cache-warden は特定の deployment
target を指定していないが、実質的には Monterey 以降で動いている。本 DR で公式化する
バージョンは実装言語選択の結果で確定 (Open Q3)。

`LARight` / `LARightStore` (新しい高レベル API、macOS 13.0+) の採用は Phase 3+ で再検討:
cache-warden の「kv entry の secret access permission」の抽象と semantic 的に近く、
DR-0030 の guard record を LARightStore に持たせる将来経路もあり得るが、v1 では扱わない。

### 7. peer exit 処理

dialog 表示中に requester プロセスが exit した場合の意味論:

- helper は dialog 表示開始時に `requester.chain[0].pid` / `start_time` /
  `audit_token.pid_version` / macOS `unique_id` を pin (§4 の構造化 schema による)
- **検知方式** (v1 実装、codex review medium-7 対応):
  - **第一選択**: `kqueue` + `EVFILT_PROC` + `NOTE_EXIT` による event-driven 検知。
    peer exit の瞬間に即座に通知され、polling オーバヘッドがない (kqueue 登録は
    dialog 表示開始時に 1 回、破棄は dialog 閉じ時に 1 回)。macOS の proc kqueue は
    root 権限不要で自 uid のプロセスに使える
  - **fallback**: kqueue で登録できないケース (稀、権限問題等) は 500ms 周期
    `macos-process-inspect::inspect(pid)` polling に degrade
- **検知時の UX** (codex review medium-7 対応、突然消える dialog の混乱防止):
  - dialog window を即座に閉じず、**「Request ended (the requesting process exited)」
    メッセージを 1.5 秒表示** してから閉じる。ユーザに「承認完了 / helper crash /
    peer exit」の区別を付ける
  - **TouchID 評価前**: 上記メッセージ表示後に閉じ、`ApproveResponse { outcome: "peer_gone" }` を daemon に返す
  - **TouchID 評価中 (evaluatePolicy 呼び出し済み)**: `LAContext.invalidate()` で
    キャンセル → メッセージ表示 → 閉じる。invalidate が embedded UI をどう閉じるかは
    PoC 時に verify (Mode A/B いずれでも正しく動作すること)
- **pid 再利用対策** (codex review medium-4 / medium-7 統合): 単純な `NotFound` 判定
  だけでなく、`start_time` / `pid_version` / `unique_id` の一致検査で「同じ pid の
  別プロセス」を偽陽性なく峻別。3 者いずれかが不一致なら peer_gone
- daemon 側は `peer_gone` を受けたら kv get を **AuthFailed** で返す (secret を送信しない)

「peer が消えたのに secret を返す」経路は作らない (issue 受け入れ条件)。

### 8. 二重 dialog 防止 (1Password op fetch との共存)

cache-warden から secret を返せるパスは 2 つ:

- (i) **cache HIT (hot path)**: 既に in-memory にある値を返す → cache-warden dialog の
  出番
- (ii) **cache MISS (cold path)**: op CLI 経由で 1Password に fetch → **1Password の
  白紙委任 dialog が既に出る** → 取得成功で cache に入る

**v1 の判断: (i) のみ cache-warden dialog を出す**。(ii) は 1Password dialog に委ねる
(fetch 成功で cache 化 → 次回 (i) で cache-warden dialog)。

理由: (ii) で cache-warden dialog を挟むと 1Password dialog と cache-warden dialog の
二重体験になり、そもそも 1Password の白紙委任を置き換えたい動機と齟齬する。
「cache-warden 経由に切り替えたら 1Password dialog は原則見なくなる」が理想形で、
(ii) の 1Password dialog は「初回だけ」で済む。

**発火条件の明確化 (v1)**:
- entry に guard (DR-0030) がある → 常に cache-warden dialog
- guard は無いが `[auth].command` (DR-0022) が定義済みで soft/hard expiry → cache-warden
  dialog に切り替え可 (現行 CommandAuthenticator の外部コマンド起動を dialog に置換)
- guard も auth.command も無い entry → dialog なし (現行の透過的 get 挙動を維持)

**「1P 白紙委任から段階的置き換え」ロードマップの現実的制約** (codex review medium-6
対応): 単純に「全 entry に guard を宣言 → 1P dialog を実質見なくなる」ではない。
DR-0030 v1 は guard を **kv set (Static 値) のみ** で受け付ける (definition 由来 =
config `[kv.*]` / `kv define` は対象外)。op source を持つ entry は:

1. **初回 fetch (cache MISS, cold path)**: op CLI 経由で 1P dialog が出る。この経路は
   cache-warden dialog では置き換えられない (op が secret 送出する側)。**残る 1P dialog
   の既知制約**として release notes / doc に明示
2. **hard TTL 到達 → regenerate**: 同じく op fetch が発火 → 1P dialog
3. **soft TTL 到達 → extend**: 通常は在庫値を返しつつ background で refresh、cache-warden
   dialog は出ない (現行挙動維持)

「1P dialog を実質見なくなる」を目指すなら、**別 phase として definition (op source
含む) にも peer-identity policy を付ける DR** が必要 (DR-0030 の後継)。これは
「definition が config で運用者宣言」の DR-0012 と、「per-entry consumer 宣言」の
DR-0030 の合成問題であり、本 DR のスコープ外。

代わりに v1 では:
- prefetch (DR-0018) / longer hard TTL 設定で cold path 到達頻度を下げる (kawaz 運用側)
- 1P dialog を「初回 & TTL 切れの時のみ」に許容する運用として明示、cache-warden
  dialog は「hot path で最も頻繁に出るもの」として最適化
- config definition + guard の統合は将来 DR で扱う (Phase 3+ の「LARight/LARightStore
  検討」と併せて再検討)

### 9. fallback — helper 不在時の挙動

helper が spawn 失敗・接続喪失・応答なしのとき、**状態を 2 種に区別する**
(codex review high-2 対応):

- **`helper_starting` (transient)**: daemon 起動直後 / graceful restart 直後 / helper
  respawn 中の一時状態。**bounded wait** (最大 5 秒程度、実装 PoC で調整) で helper
  ready を待ってから承認要求を処理。timeout 到達で下記 `helper_down` に格下げ
- **`helper_down` (permanent)**: bounded wait を超えた真の helper 不在。以下の
  fallback:
  - **guard がある entry** (DR-0030): fail-closed で `AuthFailed` (secret を送信しない、
    ユーザには「helper 不在」を伝える)
  - **guard が無いが auth.command が定義済み**: 現行 CommandAuthenticator にフォールバック
    (外部コマンド exit code で承認)
  - **どちらも無い**: 従来の透過 get 挙動を維持

`daemon status` に helper の稼働状態 (running / starting / down) と最終 ready 時刻、
respawn 回数を表示。`cache-warden helper restart` サブコマンド (新設) で手動再起動を
提供。**restart 中の既存 dialog** は helper kill によって消えるため、次の kv.get 要求
時に helper ready を待って新規 dialog を出し直す (状態が消えることを明示する短い
transient メッセージが helper 側にあれば理想、v1 では省略可)。

### 10. graceful restart との整合 (DR-0029)

daemon が graceful restart (同一 PID exec + state-holder child) するとき、**helper
readiness を control socket serve 開始条件に組み込む** (codex review high-2 対応):

- helper は daemon の子プロセスなので **daemon exec 前に kill** する (子プロセスは
  execve で継承されない設計と一致)
- 新 daemon が起動 → **helper を spawn し、双方向 peer 認証成立 (§Security) までの
  ready 状態を確認してから control socket serve を開始する**
- 起動シーケンスの厳密順序:
  1. daemon 内部初期化 (kv store restore、config load)
  2. helper spawn + fd/env 渡し (§Security の socketpair 経路)
  3. helper `HELLO` 受領 (helper 側で双方向 peer 認証成立、dialog 表示準備完了)
  4. control socket 開始 + authsock listener 開始
- helper spawn 失敗時: control socket は開始する (guard 無し entry の kv.get は
  透過的に動く必要があるため)、guard 付き entry は §9 の `helper_down` fallback
- restart 中 (2-3 の窓) に kv.get 要求が並んでいる場合: 3 完了までは §9 の
  `helper_starting` に該当し、bounded wait で吸収

「helper を daemon exec で継承させる」案は不採用: dialog UI 状態を跨いで受け渡す
契機がなく、fresh restart の方が状態機械が単純。restart の hot cache 保持
(DR-0029) と helper 再起動は独立の関心事。

### 11. TCC / codesign / notarize / release 影響

`CacheWardenApprover.app` は helper bundle として:

- `LSUIElement = YES` (Dock 非表示、Activity Monitor には出る)
- `NSMainNibFile` 不要 (SwiftUI で `@main` 起動)
- codesign: `CacheWarden.app` と同一 identity (Developer ID Application)
- notarize: `CacheWarden.app` と一緒に notarize (helper が nested になるので stapler も含む)
- **entitlements の扱い** (codex review low-9 対応): 1P 実機観察では
  LocalAuthentication 系 entitlement は**明示されていない**にもかかわらず Developer ID +
  notarize で通っている実例あり (§Context の bundle 観察)。**v1 では entitlement を
  追加しない前提で PoC → notarize を実施し、失敗した場合にのみ追加**の順序で進める
  (誤った entitlement を hardened runtime に入れると notarize 失敗要因になる):
  - `com.apple.developer.biometrics` の要否は PoC で verify (現時点で「必要」と主張する
    一次資料はなし)
  - FDA は helper には不要 (secret を触るのは daemon 側、helper は評価しか行わない)
- `AssociatedBundleIdentifiers` (DR-0020): daemon の bundle_id と helper の bundle_id を
  互いに登録し、TCC 上「同じアプリの構成要素」として認識させる

**release 影響 (macOS 下限規定に伴う運用変更、codex review low-9 対応)**:

- **README / release notes**: 「macOS 12 Monterey 以降 (Open Q3 で確定) が必要」の
  明示を追加。Homebrew Cask (`kawaz/homebrew-tap/Casks/cache-warden.rb`) の `depends_on
  macos: ">= :monterey"` (現在未明示なら追加) 相当の宣言も要検討
- **Homebrew の cask metadata**: `depends_on macos:` の更新 (現状の cask を確認して
  Monterey 未満のサポート範囲を明示的にカット)
- **Cargo target / build.rs**: macOS deployment target を `12.0` に固定
  (現状未指定なら `build.rs` or Cargo.toml の rustflags 経由で明示)
- **既存ユーザへの影響**: Monterey 未満のユーザが存在するかは kawaz の運用範囲で
  未確認 (cache-warden ユーザは kawaz 個人 + dogfood レベル、実質的に問題ない見込み)。
  Homebrew Cask の macos_requirement 更新で古い OS ユーザは自動的に upgrade 不可に
  なるため、事実上の non-breaking change として扱える
- **CI matrix**: 現行 `macos-latest` (Sonoma / Sequoia) のみで、Monterey での CI 実行は
  していない。Monterey 対応の実機検証は v1 land 前の PoC で 1 回実施 (以降は
  `macos-latest` のみで維持) — 完全な Monterey CI matrix は overkill

## Security considerations

- **helper 権限**: helper は secret を触らない (dialog 表示と TouchID 評価のみ)。daemon は
  ApproveResponse の `outcome == "approved"` を受けて初めて kv 値を requester へ送信
- **helper 双方向 peer 認証 (承認バイパス防止)**: helper 応答は secret 送信の最終ゲート
  なので、「同一 uid の別プロセスが先に `approver.sock` を bind して偽 helper 化する」
  経路を厳密に塞ぐ必要がある。単純な socket 0600 + bundle path pin では不十分:
  - **socket 名前解決を廃止**: daemon が `socketpair(2)` (or `pipe/UNIX socket 事前 listen`)
    を作り、fd を helper spawn 時に環境変数/argv で helper に渡す。ファイル名 socket
    での rendez-vous を回避し、preemptive bind 攻撃を根本的に不可能にする (第一の候補)
  - **接続後の peer 検証**: それでも名前付き socket が必要な設計にする場合、connect
    後即座に `getsockopt(LOCAL_PEERTOKEN)` で peer audit token を取得、以下 3 点を
    照合:
    1. peer pid が daemon の spawn した child pid と一致
    2. peer の `pid_version` (audit_token) と `start_time` が spawn 時に記録した値と一致
       (pid 再利用対策)
    3. peer の `codesign` identifier が cache-warden 同一 (bundle 内 codesign
       identity)
  - **helper 側の逆方向 peer 検証**: helper も `getsockopt(LOCAL_PEERTOKEN)` で
    daemon 側 peer を検証、pid == 起動時に env var/argv で受け取った parent pid、
    codesign identifier 一致を確認。**双方向 peer 認証**が成立してから ApproveRequest
    受付を開始する
  - **失敗時**: helper socket 検証失敗 = daemon は fail-closed で AuthFailed、
    stderr / syslog に警告 (同一 uid 内攻撃の兆候)
- **dialog 情報 (metadata) の sensitive 扱い**: dialog に載せるのは metadata のみ
  (key 名 / requester chain / guard 評価結果)。secret 値そのものは helper に一切送信
  しない。**加えて metadata 自体も sensitive-adjacent と扱う** (codex review low-8):
  - helper は request/response をログしない (tracing 出力なし、`os_log` 使う場合も
    `%{public}` にしない)
  - crash report / diagnostic dump に載らないよう `NSApp.setActivationPolicy(.accessory)`
    や `pref: NSCrashReporterKey.disable` 相当の設定を検討 (未確認、実装時に verify)
  - AX / screenshot 経路の露出は macOS の Screen Recording 権限依存で cache-warden
    側から完全遮断はできないが、AX role を `AXSensitive` 相当にできる場合は設定
  - 将来的に「表示名 alias / redaction 設定」を config で提供する経路を残す
    (v1 では実装しない)
- **DR-0030 との合成順序**: guard 評価 → fail なら dialog 出さずに拒否 (dialog を出す =
  「拒否理由が setter identity 由来」と間接的に漏らすため、DR-0030 §7 の「拒否理由を
  詳細に返さない」規定と整合)
- **evaluatePolicy の biometric fallback**: TouchID を持たない Mac (M4 iMac 等) では
  LocalAuthentication が Password fallback を要求。helper は `.deviceOwnerAuthenticationWithBiometrics`
  で biometric-only を強制 (Password fallback を許すと「passphrase 打鍵で承認」になり
  独自 dialog の意義が薄れる)。TouchID 不在 Mac ではメッセージで「biometric 必須」を表示

## 実装 phase 分割

- **Phase 1 (最小 land)**:
  - `CacheWardenApprover.app` bundle 骨格 (macOS 下限は Open Q3/Q4 で確定)
  - IPC socket + JSON schema、daemon 側 `approver.rs`
  - dialog サマリ表示のみ (詳細展開は無し)
  - guard がある entry のみ dialog 発火 (DR-0030 と同時 land 前提)
  - TouchID 統合は Mode A (LAAuthenticationView 埋め込み) を目標。実装 PoC で
    標準シートが別途出るなど問題があれば Mode B (標準シート許容) に fallback
  - fallback は「helper 不在 → guard 付き entry を fail-closed」のみ
  - build system は Open Q4 の言語選択で分岐:
    - 案 A (Rust 統一): 既存 Cargo workspace に helper crate 追加のみ、release.yml
      変更は helper の nested `.app` を .app packaging 手順に含めるだけ
    - 案 B1 / B2 (Swift + SwiftUI): xcodebuild + Swift Package を release.yml に統合、
      DR-0020 の codesign / notarize フローを拡張して nested Swift `.app` を含める

- **Phase 2**:
  - dialog 詳細展開 (ancestry chain / guard 詳細)
  - `[auth].command` 経路の dialog 化 (CommandAuthenticator との統合)
  - responsible_bundle_id の解決経路整備 (macos-tcc 拡張)
  - helper 死亡検知 + 自動 restart

- **Phase 3 (条件付き)**:
  - Phase 1 で Mode B (標準シート) を選んだ場合、Mode A (LAAuthenticationView) への移行
  - Watch 認証対応
  - `LARight` / `LARightStore` の採用検討 (DR-0030 の guard record を LARightStore に
    委譲する経路)
  - dialog カスタマイズ (config 由来のテーマ / 表示項目選択)

## Open questions (kawaz 判断待ち)

1. **helper bundle の配置**: `/Applications/CacheWarden.app/Contents/Helpers/CacheWardenApprover.app`
   (nested) vs 別 top-level `.app`。draft は nested 提案 (同一 codesign identity、
   AssociatedBundleIdentifiers 管理が単純)
2. **helper ライフサイクル**: (b) daemon spawn を提案。ただし kawaz が「daemon 死亡時も
   dialog を残したい」ケース (常駐 daemon が graceful restart 中でも dialog は生かす)
   を優先するなら (a) LaunchAgent 別登録に切替
3. **macOS 下限バージョン**: Open Q4 の実装言語選択と連動:
   - 案 A (Rust + objc2) or 案 B2 (Swift + AppKit ラップ) → **macOS 12 Monterey**
   - 案 B1 (Swift + SwiftUI native) → **macOS 13 Ventura**

   cache-warden の実質下限は既に Monterey (macos-latest = Sonoma/Sequoia)。本 DR で
   公式化するときの選択次第で 1 バージョン上げるか維持するか。draft は Monterey 維持を
   推奨 (現行ユーザに影響しない、案 A/B2 との組み合わせなら追加コストなし)
4. **helper 実装言語 (3 案から選択)**: §2 で 3 案を比較、実装距離見積 550-850 行 (A) vs
   330-550 行 (B1) vs 360-600 行 (B2) と 1.3-1.6 倍差に収束。draft は案 A 推奨だが
   最終判断は kawaz レビュー。判断軸:
   - 「Rust オンリー」の設計原則を helper のためだけに崩したくない → 案 A
   - build system の単純さ (release.yml 変更最小、cross-compile 経路無変更) → 案 A
   - macOS 下限を Monterey に維持したい → 案 A or 案 B2
   - SwiftUI の宣言的 layout + Apple 公式サンプル流用の速度優先 → 案 B1
   - Ventura 下限を許容し「dialog を Vault 展開・詳細トグル・アニメーション」で将来
     大幅変更を予定 → 案 B1
   - Swift 依存を受け入れつつ Monterey 下限を維持したい → 案 B2
   - **【裁定 2026-07-11】案 A (Rust 統一) に確定**: PoC gate を実機通過
     (§PoC gate 実機検証結果)。macOS 下限 Monterey 維持 + 「Rust オンリー」原則保持 +
     build system 無変更の 3 拍子が揃った。ver.2 PoC (`crates/cache-warden-approver-poc`)
     で LAAuthenticationView 埋め込み + LAContext.evaluatePolicy + Cancel/Approved
     両経路が実機動作。案 B (Swift 系) は不採用
5. **`[auth].command` を dialog 化するかの scope**: Phase 2 で CommandAuthenticator を
   dialog に置き換えると、既存の外部コマンド運用 (osascript / 独自 GUI) を持つユーザは
   移行が必要。draft は「共存を維持、config で dialog / command を選択」を提案 (両立
   させる) が、simplification を優先するなら「dialog を land した時点で command は
   deprecated 予告」も選択肢
5. **二重 dialog 防止方針**: v1 の「(i) cache HIT のみ dialog」で妥当か。「(ii) op fetch
   時にも cache-warden dialog を出して 1P dialog を後ろに隠す」設計の余地

## PoC gate 実機検証結果 (2026-07-11、案 A Rust 統一で通過)

`crates/cache-warden-approver-poc` (ver.1 = build gate、ver.2 = 実機実行) で PoC
gate を通過した。案 A (Rust + objc2 統一) が実装可能であることを実機で確定。

### 検証構成 (ver.2)

- crate 依存: `objc2 = 0.6` + `objc2-app-kit = 0.3` + `objc2-foundation = 0.3` +
  `objc2-local-authentication = 0.3` + `objc2-local-authentication-embedded-ui = 0.3`
  + `block2 = 0.6`
- UI 構造: `NSApplication(Accessory)` + `NSWindow(400x325, Titled|Closable, Floating)`
  + `NSStackView(Vertical, Fill)` に `NSTextField(summary label)` + `LAAuthenticationView(ctx, .Large)`
  + `NSButton(Cancel)` を積む
- 承認呼び出し: `LAContext.evaluatePolicy_localizedReason_reply(DeviceOwnerAuthenticationWithBiometrics, ...,
  RcBlock<Fn(Bool, *mut NSError)>)`
- Cancel 経路: `NSButton::buttonWithTitle_target_action` の target =
  `NSApplication`、action = `sel!(terminate:)` に直結 (delegate class 定義不要)
- Approved 経路: completion block 内で `outcome = Approved` を eprintln! + `app.terminate(None)`
- build 検証: `cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings`
  / `cargo build --workspace` が fresh でグリーン

### Mode A 成立の証拠 (両側完全一致)

**視覚証拠 (kawaz 実機スクショ)**: cache-warden approver (PoC) タイトルの単一
`NSWindow` 内に、summary label + `LAAuthenticationView` が描画した指紋アイコン (濃い
赤色) + Cancel ボタンが積まれた状態。**別途 macOS 標準 evaluatePolicy シートは
一切出現しない** = Mode A (LAAuthenticationView 内で TouchID 完結) 成立。指紋
アイコンの色調は前セッションで観察した 1Password 本体 dialog の「徐々に赤く染色する
アニメーション」と一致 = 1P と cache-warden PoC が同じ `LAAuthenticationView`
描画ロジックを共有していることの強い示唆。

**coreauthd 側の間接証拠**: `coreauthd` の evaluatePolicy dispatch ログが
`uiMechanism: MechanismTouchId[N] nonUiMechanism: MechanismTouchId[N]` で、TouchId
mechanism 自体が UI 提供 (= 標準 `MechanismUI` を経由しない) と記録される。前セッション
で観察した 1P op fetch (Mode B 相当) は `uiMechanism: MechanismUI[N] nonUiMechanism:
MechanismTouchId[N](par:N)` で標準 UI mechanism が親の構造。今回の PoC はこの構造を
一切経由せず、`Interactive,Biometry` フラグ + `MechanismTouchId` 単独 = LA 側が
「LAAuthenticationView がプロセス内にあるので標準シートを出さない」と判断した経路。

### 経路別動作確認

| 経路 | 実観測 |
|---|---|
| Cancel | Cancel button 押下 → `terminate:` セレクタ → NSApplication 終了 → LAContext invalidate → coreauthd `Code=-9 "Invalidated by client"` → PoC プロセス exit 0 |
| Approved | 指紋センサー接触 → coreauthd `has received finger-on` → `has matched by <private>` (指紋一致の grand truth) → `has finished with { ... }` → RcBlock callback (main queue) で `outcome = Approved` を eprintln!、`app.terminate(None)` → PoC プロセス exit 0 |
| BiometricFailed | 型レベル到達可能性のみ (`all_outcomes()` で確認)。実観測は helper 本実装フェーズで |
| PeerGone | 型レベル到達可能性のみ。実観測は helper 本実装 (kqueue `NOTE_EXIT` 経路) で |

### 実装距離への含意

- draft §7 の 550-850 行見積 (案 A) に対し、PoC ver.2 は約 200 行で「UI 表示 + Cancel/
  Approved 両経路の block callback 統合 + terminate」まで実装済み。**helper 本実装で
  上乗せするのは IPC socketpair + peer 認証 (双方向: daemon → helper の identity 検証
  と helper → daemon の identity 検証)、Info.plist LSUIElement、AssociatedBundleIdentifiers
  (TCC 永続化)、codesign + notarize、summary/detail の requester icon / チップ /
  詳細展開 UI、kqueue で peer_gone 検知**。見積の 550-850 行は現実的な範囲に収まる
  見込み
- objc2 crate 群の deref coercion (`Retained<T>` → `&T` → `&NSObject` → `&AnyObject`)
  + `sel!()` macro で NSApplication 標準 selector を再利用する経路が、案 A の
  「delegate class を Rust 側で define_class! する」パスを部分的に不要にする。helper
  本実装でも Cancel は同じパターンが使える (delegate class は kqueue peer_gone 用
  callback のみで済む可能性)

### PoC で意図的に非スコープにした項目 (helper 本実装で追加)

- IPC (socketpair + JSON wire schema、§4) と双方向 peer 認証 (§Security)
- `Contents/Info.plist` の `LSUIElement=YES` と AssociatedBundleIdentifiers (§DR-0020 連携)
- Developer ID codesign + notarize (release.yml 拡張)
- Cancel button の delegate class 実装 (peer_gone / detailed cancel reason 用)
- Requester icon (Bundle icon 抽出) と詳細展開 UI (chevron toggle、guard 評価結果の表示)
- daemon 側 helper spawn + fd 継承 + readiness gate (§10)

## Confirmed via codex adversarial review (2026-07-10, job task-mrebtdaf-j8x4dt)

codex review で「妥当な判断」と AGREED された設計要素 (kawaz レビューでの判断負荷
軽減用):

- **2 プロセス構成 (§1)**: 既存 daemon は tokio/control/authsock 中心で、B 案不採用
  理由 (daemon 内 AppKit runloop を避ける) と整合
- **control socket と approver socket の分離 (§4)**: 人間操作で数秒 pending する承認
  リクエストを control/status と同じキューに載せない判断は妥当。peer 認証と readiness
  gate 強化を反映済み (§Security / §10)
- **guard 拒否時に dialog を出さない (Security 節)**: DR-0030 §4/§6 の
  「拒否は fail-closed、auth/TouchID をトリガしない」「setter identity を漏らさない」
  と整合
- **helper 不在時に guard 付き entry を fail-closed (§9)**: 安全側で妥当。graceful
  restart 中の transient は bounded wait 対応済み (§9 の `helper_starting` /
  `helper_down` 区別)
- **`LARight` / `LARightStore` を Phase 3+ に送る判断 (Phase 分割)**: v1 要件は
  dialog/metadata/guard 表示で、macOS 13+ API へ寄せると Monterey 下限や意味論が増える
  ため妥当
- **`[auth].command` を即廃止せず共存 (Open Q5)**: DR-0010 が command auth を既存の
  正式 Authenticator として扱っており、移行猶予が必要
- **helper に secret 値を送らない (Security 節)**: 必須で妥当。metadata の sensitive
  扱いも強化済み (Security 節 low-8 対応)
