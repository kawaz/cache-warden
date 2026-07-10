# draft-DR-0031: custom TouchID 承認 dialog — 1Password 方式の独自 GUI helper

- Status: Draft (kawaz レビュー待ち。codex adversarial review 予定)
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

**LAEmbeddedUI の公開度は確定** (2026-07-10 recon `lacontext-inline-recon`):

- **公開 API**: macOS 13 Ventura / iOS 16 以降で正式提供、WWDC22 セッション
  "Streamline local authorization flows" (session 10108) で公式発表
- 提供クラス: **`LAAuthenticationView`** (AppKit/UIKit)。SwiftUI 版
  `LocalAuthenticationView` の存在も示唆 (macOS 15 以降推定、詳細 API shape は
  verbatim 未確認)
- 用途: 「開発者が任意にデザインした認証パネル内に、標準の指紋アイコン部品を埋め込む」。
  公式説明 verbatim: "you can use the Local Authentication Embedded UI framework to
  present that standard local authentication view icon in a custom authentication
  view" / "the authentication view displays an icon that users associate with
  biometric authentication, like the Touch ID icon, and then modifies that icon over
  time to reflect changes in the authentication state"
- 制約: **GUI framework (AppKit/SwiftUI) 依存** = SwiftUI/AppKit View 型のため、
  Rust から呼ぶには objc2 の raw msg_send による NSView 操作が必要、実装距離が長い
- 新 API `LARight` / `LARightStore` との組み合わせで「アプリケーションウィンドウ内に
  統合された UI」となる方向性が WWDC22 で示された (verbatim 未確認、AI 要約経由)

これで 1P dialog の「指紋アイコンが徐々に染色するアニメ」は **LAAuthenticationView を
独自 dialog window 内に埋め込んだもの**という仮説が最も蓋然性が高い (Occam's razor:
公式に目的が一致する framework がある以上、private API に走る動機は薄い)。

参考: `docs/research/2026-07-10-touchid-dialog-ui-options.md` (先行研究) と、
本 DR 執筆に伴い実施した 2 本の recon (`1p-bundle-recon` + `lacontext-inline-recon`)。

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
- **helper (`CacheWardenApprover`)**: **Swift + SwiftUI** で新規実装 (§2 で確定)。
  LAAuthenticationView が SwiftUI/AppKit の View 型として提供されており、Swift が
  最短経路。cache-warden プロジェクトで初の Swift 依存導入となる

### 2. helper 実装言語 — Swift + SwiftUI で確定

LAEmbeddedUI recon で **`LAAuthenticationView` は SwiftUI/AppKit の View 型**として
提供されることが確定した (macOS 13 Ventura 以降の公開 API、WWDC22 発表)。この事実が
言語選択を実質的に確定させる:

**Rust 統一を選ぶ場合のコスト (棄却)**:
- LAAuthenticationView は NSView subclass。Rust から使うには objc2 の raw msg_send で
  NSView 継承を模倣し、layout / auto-resizing / event routing を全部手書き
- LocalAuthentication は objc2-local-authentication (v0.3.2) が存在するが、
  LAEmbeddedUI の objc2 crate は 2026-07 時点で未確認。対応がなければ raw bindings を
  手書きする追加コスト
- NSWindow + NSApplication + SwiftUI もしくは AppKit の layout system を Rust 側で
  完全に模倣する必要
- 総実装距離: helper 全体で 1500〜2500 行程度の unsafe objc2 コード見積 (SwiftUI の
  約 200 行と対比)

**Swift 選択のコスト (受容)**:
- build system が 2 言語構成に (Cargo + xcodebuild + Swift Package Manager)。release.yml と
  .app packaging が変わる (DR-0020 の署名・notarize 手順に追加ステップ)
- helper のロジック (chain 表示、peer exit 検知、IPC) が daemon 側と言語分離するため
  型共有が失われる (代わりに JSON wire schema を明示、下 §4)
- Swift の追加は cache-warden プロジェクトで初 — 「Rust オンリー」の設計原則を helper
  に限って緩める判断。この境界は helper 内部に限定し、core / adapter / cli / daemon
  本体には Swift を持ち込まない (境界の物理的分離を bundle 構造で強制、§1)

**Swift 選択の利益**:
- SwiftUI + LAAuthenticationView の統合が Apple 公式サンプル (WWDC22 session 10108)
  そのままで済む
- dialog レイアウトが 200 行 SwiftUI で書ける (Rust + objc2 で通すと 800 行超の見積、
  上記)
- LAContext / LARight などの新 API を追加するときの実装距離が短い
- app icon 取得・NSWorkspace 系 API が言語ネイティブ
- SwiftUI の宣言的スタイルは 「dialog を Vault 展開・詳細トグル・アニメーション」で
  凝りたい将来変更にも耐える

**判断: Swift + SwiftUI 採用**。実装距離差が 5〜10 倍あり、「言語統一」の抽象的利益が
build system 追加負担を正当化できない。境界の物理的分離 (helper は独立 `.app` bundle)
で「Swift を持ち込む場所を helper に限定」の運用を保証する。

なお「§1 の 2 プロセス構成」「§4 の JSON IPC」「§5 の dialog 情報階層」「§7 peer exit」
「§8 二重 dialog 防止」「§9 fallback」「§10 graceful restart 整合」の設計は言語非依存で
成立する — 万一将来 Swift 依存を撤回する判断が出ても、helper を Rust に書き直せば
daemon 側は無傷。

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
    guard_eval: {                       // DR-0030 の評価結果、guard 無しなら null
        matched_constraints: [String],  // "same-user" | "same-shell" ...
        setter_snapshot_summary: String // "set by zsh (pid 12345) 3h ago"
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

LAEmbeddedUI recon (§Context) で `LAAuthenticationView` が macOS 13 Ventura 以降の
**公開 API** と確定した。1P dialog の「指紋アイコンが徐々に染色するアニメ」の実装は
これで正体が判明したものとして扱い、v1 で採用する。

**v1 (Phase 1) の実装スケッチ**:

```swift
// SwiftUI
struct ApproverDialog: View {
    @State var context = LAContext()
    let request: ApproveRequest
    let onOutcome: (ApproveOutcome) -> Void

    var body: some View {
        VStack {
            RequesterHeader(request: request)          // icon → check → cw icon
            SummaryLine(request: request)              // "Allow ... to read <key>"
            if let guardEval = request.guardEval {
                VerifiedChip(matched: guardEval.matchedConstraints)
            }

            // LAAuthenticationView が指紋アイコン + 染色アニメを描画
            LAAuthenticationView(context: context, controlSize: .large)

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

上記の verbatim シグネチャ (`controlSize` パラメータ名や `LocalAuthenticationView`
SwiftUI 版が存在するか) は WWDC22 session 10108 と公式サンプルコードで最終確認して
実装する。ここでは方向性のみ示す。

**LAAuthenticationView が標準モーダルシートを完全に代替する** ことは公式資料 verbatim
では未確認 (AI 要約経由の推論)。もし実装 PoC で「LAAuthenticationView 使用中も別途
標準シートが立ち上がる」ことが判明した場合の緊急退避策 (Mode B):

- helper が独自 dialog を表示
- ユーザが `Touch ID authenticate` ボタンを押すと標準 evaluatePolicy を呼ぶ
- 標準シートが dialog の上に一瞬出て、TouchID を触ると完了
- `localizedReason` は「Authenticate to access `<key>`」程度に短く
- 二重 UI 体験 (独自 dialog → 標準シート) を許容

Mode A と Mode B の切替は helper 内部で完結し、daemon 側の IPC schema (§4) には
影響しない。Phase 1 の PoC で Mode A が動けば land、動かなければ Mode B で先行 land し
Mode A は Phase 3 に回す。

**macOS 下限バージョン**: 本 DR で cache-warden の最小要件を **macOS 13 Ventura** に
明示する (LAAuthenticationView が Ventura 以降の API のため)。既存の cache-warden は
特定の deployment target を指定しておらず、CI runner の `macos-latest` は既に
Sonoma/Sequoia。Ventura 未満は元々サポート対象外だったが本 DR で公式にする。

`LARight` / `LARightStore` (新しい高レベル API) の採用は Phase 3+ で再検討: cache-warden
の「kv entry の secret access permission」の抽象と semantic 的に近く、DR-0030 の
guard record を LARightStore に持たせる将来経路もあり得るが、v1 では扱わない。

### 7. peer exit 処理

dialog 表示中に requester プロセスが exit した場合の意味論:

- helper は dialog 表示開始時に `requester.chain[0].pid` と `start_time` を pin
- 500ms 周期で `macos-process-inspect::inspect(pid)` を呼び、
  `NotFound` または `start_time` 不一致 (pid 再利用) を検知したら:
  - **TouchID 評価前**: dialog を自動で閉じ、`ApproveResponse { outcome: "peer_gone" }` を daemon に返す
  - **TouchID 評価中 (evaluatePolicy 呼び出し済み)**: LAContext.invalidate() でキャンセル、
    `peer_gone` を返す
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

これで「1Password 白紙委任から段階的に置き換える」ロードマップになる:
guard を宣言した entry から順に cache-warden dialog 化 → 全 entry に guard を宣言 →
1Password dialog を実質見なくなる。

### 9. fallback — helper 不在時の挙動

helper が spawn 失敗・接続喪失・応答なしのとき:

- **guard がある entry** (DR-0030): fail-closed で `AuthFailed` (secret を送信しない、
  ユーザには「helper 不在」を伝える)
- **guard が無いが auth.command が定義済み**: 現行 CommandAuthenticator にフォールバック
  (外部コマンド exit code で承認)
- **どちらも無い**: 従来の透過 get 挙動を維持

`daemon status` に helper の稼働状態 (running / not-running / stale) を表示。
`cache-warden helper restart` サブコマンド (新設) で手動再起動を提供。

### 10. graceful restart との整合 (DR-0029)

daemon が graceful restart (同一 PID exec + state-holder child) するとき:

- helper は daemon の子プロセスなので **daemon exec 前に kill** する (子プロセスは
  execve で継承されない設計と一致)
- 新 daemon が起動 → helper を再 spawn
- restart 中 (helper 未起動の窓) に承認要求が来たら、上記 §9 の fallback ロジック

「helper を daemon exec で継承させる」案は不採用: dialog UI 状態を跨いで受け渡す
契機がなく、fresh restart の方が状態機械が単純。

### 11. TCC / codesign / notarize

`CacheWardenApprover.app` は helper bundle として:

- `LSUIElement = YES` (Dock 非表示、Activity Monitor には出る)
- `NSMainNibFile` 不要 (SwiftUI で `@main` 起動)
- codesign: `CacheWarden.app` と同一 identity (Developer ID Application)
- notarize: `CacheWarden.app` と一緒に notarize (helper が nested になるので stapler も含む)
- entitlements: LocalAuthentication (Biometric) 使用のため
  `com.apple.developer.biometrics = true` (要確認、要件次第)。FDA は helper には不要
  (secret を触るのは daemon 側、helper は評価しか行わない)。1P 実機観察では
  LocalAuthentication 系 entitlement は明示されておらず、Developer ID + notarize で
  通っている実例あり (§Context の bundle 観察)
- `AssociatedBundleIdentifiers` (DR-0020): daemon の bundle_id と helper の bundle_id を
  互いに登録し、TCC 上「同じアプリの構成要素」として認識させる

## Security considerations

- **helper 権限**: helper は secret を触らない (dialog 表示と TouchID 評価のみ)。daemon は
  ApproveResponse の `outcome == "approved"` を受けて初めて kv 値を requester へ送信
- **helper のなりすまし**: helper socket は 0600 same-uid、helper の bundle 内 executable
  path を daemon が起動時に固定 pin (改竄検知は codesign 自己一致で)
- **dialog 情報の secret 混入禁止**: dialog に載せるのは metadata のみ (key 名 / requester
  chain / guard 評価結果)。secret 値そのものは helper に一切送信しない
- **DR-0030 との合成順序**: guard 評価 → fail なら dialog 出さずに拒否 (dialog を出す =
  「拒否理由が setter identity 由来」と間接的に漏らすため、DR-0030 §7 の「拒否理由を
  詳細に返さない」規定と整合)
- **evaluatePolicy の biometric fallback**: TouchID を持たない Mac (M4 iMac 等) では
  LocalAuthentication が Password fallback を要求。helper は `.deviceOwnerAuthenticationWithBiometrics`
  で biometric-only を強制 (Password fallback を許すと「passphrase 打鍵で承認」になり
  独自 dialog の意義が薄れる)。TouchID 不在 Mac ではメッセージで「biometric 必須」を表示

## 実装 phase 分割

- **Phase 1 (最小 land)**:
  - `CacheWardenApprover.app` bundle 骨格 (Swift + SwiftUI、macOS 13+)
  - IPC socket + JSON schema、daemon 側 `approver.rs`
  - dialog サマリ表示のみ (詳細展開は無し)
  - guard がある entry のみ dialog 発火 (DR-0030 と同時 land 前提)
  - TouchID 統合は Mode A (LAAuthenticationView 埋め込み) を目標。実装 PoC で
    標準シートが別途出るなど問題があれば Mode B (標準シート許容) に fallback
  - fallback は「helper 不在 → guard 付き entry を fail-closed」のみ
  - build system: xcodebuild + Swift Package を release.yml に統合、DR-0020 の
    codesign / notarize フローを拡張して nested `.app` を含める

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
3. **macOS 下限を Ventura に明示するか**: LAAuthenticationView が Ventura 以降のため、
   本 DR は最小要件を **macOS 13 Ventura** と規定。cache-warden は既に特定の deployment
   target を明示しておらず、実質 Ventura 以降で動いているが、公式に「Ventura 未満は
   非サポート」と `Cargo.toml` / release.yml / README に書く判断。draft は明示提案
4. **Swift 依存の受け入れ**: §2 で Swift + SwiftUI 採用を確定として提示したが、
   「Rust オンリー」の設計原則から helper だけとはいえ Swift を持ち込むことに
   kawaz が難色を示す場合は Rust + objc2 raw bindings に切替の判断。実装距離差の
   見積 (200 行 vs 1500-2500 行) は draft に明記済み
5. **`[auth].command` を dialog 化するかの scope**: Phase 2 で CommandAuthenticator を
   dialog に置き換えると、既存の外部コマンド運用 (osascript / 独自 GUI) を持つユーザは
   移行が必要。draft は「共存を維持、config で dialog / command を選択」を提案 (両立
   させる) が、simplification を優先するなら「dialog を land した時点で command は
   deprecated 予告」も選択肢
5. **二重 dialog 防止方針**: v1 の「(i) cache HIT のみ dialog」で妥当か。「(ii) op fetch
   時にも cache-warden dialog を出して 1P dialog を後ろに隠す」設計の余地
