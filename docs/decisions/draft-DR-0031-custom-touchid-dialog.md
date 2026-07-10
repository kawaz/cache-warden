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
- **helper (`CacheWardenApprover`)**: **Swift + SwiftUI** で新規実装。LocalAuthentication /
  AppKit / NSWorkspace のネイティブ体験、objc2 バインディング経由より圧倒的に短い実装距離。
  Rust 統一を諦めるが、UI + Biometric ドメインは Apple 純正言語に倒す方が長期メンテコストが低い

### 2. helper 実装言語の選定理由 (Rust vs Swift の tradeoff 記録)

Rust で通すと以下が全部自前になる:
- NSApplication / NSWindow / SwiftUI (objc2-app-kit binding は存在するが hot path で
  頻繁に触るには摩擦が高い、[[touchid-dialog-ui-options]] research §3)
- LAContext / evaluatePolicy の callback interop (objc2-local-authentication は動くが
  クロージャブリッジは煩雑)
- NSWorkspace の app icon 取得
- AXWebArea を模倣したアニメーション (角丸パネル、指紋染色トランジション)

**Swift 選択のコスト**:
- build system が 2 言語構成に (Cargo + xcodebuild)。release.yml と .app packaging が
  変わる (DR-0020 の署名・notarize 手順に追加ステップ)
- helper のロジック (chain 表示、peer exit 検知、IPC) の分岐が daemon 側と分離するため、
  型共有が失われる (代わりに wire schema を JSON で明示、下 §4)
- Swift の追加は cache-warden プロジェクトで初 — 「Rust オンリー」の設計原則を 1 点だけ
  緩める判断。この境界は helper に限定し、core / adapter / cli には Swift を持ち込まない

**Swift 選択の利益**:
- SwiftUI で dialog デザインが 200 行程度で書ける (Rust + objc2 で書くと 800 行超)
- LAContext との integration が公式サンプルそのまま (Apple の Framework 統合ドキュメント
  が Swift 前提)
- app icon 取得・NSWorkspace 系 API が言語ネイティブ
- 将来 SwiftUI で見た目を凝りたくなった時 (Vault 展開・詳細トグル・アニメーション) の
  コストが Rust 経由の 1/3〜1/5

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

### 6. LAContext との統合 — v1 は標準シート許容、v2 で inline 検討

1Password の実機観察では「独自 dialog 内で指紋アニメが完結」しているように見えるが、
これが公開 API で実現可能かは要検証 (research 未確認事項)。

**v1 (本 DR の実装スコープ)**:
- helper が独自 dialog を表示
- ユーザが `Touch ID authenticate` ボタンを押すと `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, reason: <短い要約>)` を呼ぶ
- 標準 evaluatePolicy シートが独自 dialog の上に一瞬出て、TouchID を触ると完了
- 標準シートの `localizedReason` は独自 dialog と重複する情報 (短めに)。dialog 側で
  詳細を出している前提で「Authenticate to access `key`」程度
- 二重 UI 体験 (独自 dialog → 標準シート) は許容: 情報の可視化と TouchID の統合は
  step-by-step で完結する

**v2 (将来、条件付き)**:
- 1Password 方式の inline 統合 (標準シートを出さずに evaluatePolicy 完了) が公開 API で
  可能と判明した場合に移行
- 判断根拠 (公開 API パス / 非公開 API 依存 / private framework 使用) は当該時点で
  別 DR にする
- v1 と v2 の切替は user-facing に影響しない (dialog の見た目は同じ、内部の TouchID
  呼び出し方だけ変わる)

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
  (secret を触るのは daemon 側、helper は評価しか行わない)
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
  - `CacheWardenApprover.app` bundle 骨格 (SwiftUI + LocalAuthentication)
  - IPC socket + JSON schema、daemon 側 approver.rs
  - dialog サマリ表示のみ (展開は無し)
  - guard がある entry のみ dialog 発火 (DR-0030 と同時 land 前提)
  - v1 の LAContext 統合 (標準シート許容)
  - fallback は「helper 不在 → guard 付き entry を fail-closed」のみ

- **Phase 2**:
  - dialog 詳細展開 (ancestry chain / guard 詳細)
  - `[auth].command` 経路の dialog 化 (CommandAuthenticator との統合)
  - responsible_bundle_id の解決経路整備 (macos-tcc 拡張)
  - helper 死亡検知 + 自動 restart

- **Phase 3 (条件付き)**:
  - inline TouchID (1Password 方式) 実装 (v1 → v2 の LAContext 統合切替)
  - Watch 認証対応
  - dialog カスタマイズ (config 由来のテーマ / 表示項目選択)

## Open questions (kawaz 判断待ち)

1. **helper bundle の配置**: `/Applications/CacheWarden.app/Contents/Helpers/CacheWardenApprover.app`
   (nested) vs 別 top-level `.app`。draft は nested 提案 (同一 codesign identity、
   AssociatedBundleIdentifiers 管理が単純)
2. **helper ライフサイクル**: (b) daemon spawn を提案。ただし kawaz が「daemon 死亡時も
   dialog を残したい」ケース (常駐 daemon が graceful restart 中でも dialog は生かす)
   を優先するなら (a) LaunchAgent 別登録に切替
3. **v1 の LAContext 統合方式**: 標準シート許容 (実装コスト低) vs 標準シート抑制の
   PoC を先にやってから v1 を land。draft は前者を提案 (Phase 1 の land 速度優先)
4. **Swift 依存の導入判断**: cache-warden の設計原則「Rust 一本」を helper に限って
   緩める判断。この境界を kawaz が受け入れるか (対抗案: Rust + objc2 で通す。実装
   コスト 3-5 倍・保守コスト増と引き換えに言語統一)
5. **二重 dialog 防止方針**: v1 の「(i) cache HIT のみ dialog」で妥当か。「(ii) op fetch
   時にも cache-warden dialog を出して 1P dialog を後ろに隠す」設計の余地
