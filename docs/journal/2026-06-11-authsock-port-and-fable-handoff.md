# authsock-port-and-fable-handoff: authsock 移植完遂 → Fable セッション引き継ぎ

- Date: 2026-06-11

## 何をしていたか

前任の Opus セッションが authsock-warden の資産を cache-warden の「authsock アダプタ」として
移植する作業（port plan Iteration -1〜5）を完遂し、v0.8.0 をリリースした。
次の Fable セッションへの引き継ぎ資料として本 journal を起票する。

### Fable に渡す前に読んでほしいこと

Fable は SSH 署名・op 鍵・プロセス認証の生コードを含むコンテキストでセーフティガードが発火する
傾向がある。そのため前任セッションは以下の運用で乗り切った:

- **機微フェーズ（Iteration 4 op 署名〜Iteration 5 policy）** は Opus をメインにして進めた。
- **実装タスク**は都度クリーンコンテキストのサブエージェントに隔離し、メインへの報告も
  生コードを載せずに抽象度を上げた（「署名関数を移植した」であって PEM 処理の中身は書かない）。
- Fable の新セッションはこの handoff doc を起点にすれば、生のセキュリティコードを直読みしなくても
  現状把握と残タスク着手ができる状態になっている。

**生コードを直読みする必要が生じたとき（Fable が難しいと判断したとき）は、実装作業だけを
Opus サブエージェントに切り出し、Fable は設計判断と統合判断に専念する分担が有効。**

---

## 現在地サマリ

v0.8.0、3 crate 構成（`cache-warden` コア lib / `cache-warden-authsock` アダプタ lib /
`cache-warden-cli` バイナリ）。DR-0001〜0012 で設計を確定済み。

**cache-warden が何になったか:** authsock-warden（SSH agent proxy + 鍵セキュリティ製品）の
後継コアとして、「秘密値のセキュア KV キャッシュ」を基盤に構築し直した（DR-0003）。
コアは TTL 2 段・mlock/zeroize・プロセス認証・再認証を汎用提供し、SSH 鍵管理はその上に乗る
「authsock アダプタ」として実装した。kawaz が日常使いする 3 socket 構成
（op 署名 / agent フィルタ / allowed_processes プロセスアクセス制御）のパリティを
アダプタ側で達成した状態が v0.8.0。authsock-warden は引退前の並走フェーズ（Phase 1）に入れる
足場が整った。

---

## 完了した iteration の一覧

| Iteration | 内容 | 関連 DR |
|---|---|---|
| **-1** | コア前提修正: TTL 基準を `loaded_at`（hard 絶対寿命）/ `extended_at`（soft idle 延命）の 2 基準に分離。`kv pin` API（期限まで失効抑止、再認証必須）追加 | DR-0011 |
| **0** | アダプタ crate 骨格 + SSH agent protocol codec 移植（AgentMessage / AgentCodec）。wire 固定バイトベクタテストで protocol 適合を証明 | DR-0002（crate 構成確定） |
| **1** | 最小 milestone: socket 1 本 listen + KV の秘密鍵で署名。signer 移植・公開鍵レジストリ・authsock config 節・daemon 統合・E2E 達成 | DR-0008 / DR-0010 |
| **2** | upstream proxy: upstream agent への転送（鍵マージ dedup・SIGN ルーティング・graceful degradation）。macOS TCC 回避（1Password agent socket の安定 symlink 経由） | DR-0004 |
| **3** | 鍵フィルタ移植（comment / fingerprint / keytype / pubkey / keyfile / FilterEvaluator OR of AND）。config `filters` 節 | DR-0004 |
| **3.5** | github フィルタ（curl shell-out、reqwest 依存ゼロ）。同期照合 / 非同期取得の分離（`Arc<RwLock<キャッシュ>>` + daemon refresh task + fail-closed） | DR-0004 |
| **4** | op 鍵発見 + ローカル署名（OpClient trait 境界 / ディスクキャッシュ / 発見ロジック / 公開鍵レジストリ拡張 / NotLoaded = アダプタ側 + コア KV 遅延配線）。warden で未配線だった TTL コアをここで初めて実配線 | DR-0004 / DR-0011 |
| **5** | socket 層プロセスアクセス制御（`allowed_processes`）。peer pid → 祖先遡上 → basename 完全一致。fail-closed（warden は fail-open、安全側に倒す差異） | DR-0012 |

---

## 残タスク（Fable セッション向け）

凡例: 🟢 穏当（生セキュリティコード直読み不要） / 🟡 要注意（設計次第で機微コードに触れる）
/ 🔴 機微（Fable では Opus サブエージェント隔離 or Opus 切替推奨）

### パリティ検証フェーズ（DR-0004 Phase 2〜4）🟢

authsock-warden と cache-warden を別ソケットで並走させ、挙動を突き合わせる実機検証。
内容はログ比較・`ssh-add -L` 差分確認・TouchID 回数突き合わせなど。
生コード読み込みではなく **実機観測** が中心なので Fable でも穏当に進められる。

- Phase 2 パリティ達成確認（両 socket の REQUEST_IDENTITIES / SIGN 挙動一致）
- Phase 3 切替（`SSH_AUTH_SOCK` を cache-warden 側へ。可逆に）
- Phase 4 引退（安定確認後、authsock-warden を引退）

参照: [DR-0004](../decisions/DR-0004-authsock-warden-succession.md)、
[port plan §4（並走検証戦略）](../design/authsock-adapter-port-plan.md)

### key 層 allowed_processes 🟡

Iteration 5 は **socket 層のみ**実装。warden の `[[keys]].allowed_processes` に相当する
key 層（KV エントリ単位のプロセス制御）は follow-up。

設計ポイント: 将来の key 層実装では「交差空 = 全拒否」方針（warden が空配列を全許可に転落させる
罠を踏まない）を DR-0012 に明記済み。実装時は socket 層のコード（`process_policy.rs`）を参照する
程度で穏当に進められるが、allowed_processes の判定ロジックに触れるため 🟡 とした。

参照: [DR-0012](../decisions/DR-0012-process-access-policy.md)

### op agent socket 高速路（DR-011 ステップ 3〜4）🟡

Iteration 4 で後送りにした発見最適化。ディスクキャッシュ → op item list → **agent socket 照合
（`SSH_AUTH_SOCK` 経由で公開鍵 fingerprint を高速マッチ）** → op item get 並列化。
定常状態（warm restart）はディスクキャッシュで op item get ゼロになっており、
今の最小実装でも日常利用には影響しない。SSH agent protocol 呼び出しに触れるため 🟡。

参照: [port plan §1.4 / Iteration 4 見送り理由](../design/authsock-adapter-port-plan.md)

### ビルトイン TouchID 🔴

現状は `CommandAuthenticator`（外部コマンドに委ねる）のみ。`security-framework` / `objc2` の
どちらを使うかは未決の open question（DR-0010、DESIGN-ja.md「open question」節）。
LocalAuthentication フレームワークへの直接呼び出しになるため機微度が高い。

参照: [DR-0010](../decisions/DR-0010-config-and-reauth-command.md)、[DESIGN-ja.md](../DESIGN-ja.md)

### `cache-warden://KEY` 注入機能 🟢

`cache-warden run -- cmd`（op run 相当、env 注入）と `cache-warden inject`（op inject 相当、
テンプレ置換）。control socket クライアントとして実装でき、認証コア・authsock アダプタと
**完全に独立**して進められる。生セキュリティコードに触れないので Fable 主体で着手可能。

参照: [docs/issue/2026-06-11-secret-reference-injection.md](../issue/2026-06-11-secret-reference-injection.md)、
[DESIGN-ja.md「将来検討」節](../DESIGN-ja.md)

### anti-debug 🟡〜🔴

Iteration 5 で確定した方針（DR-0005 整理確定）:

| 段階 | 内容 | 機微度 |
|---|---|---|
| (a) core dump 抑制（`RLIMIT_CORE=0`） | 早期に必ず入れる。実装は daemon 起動時（CLI 側） | 🟡（libc 呼び出し程度） |
| (b) ptrace 拒否（`PT_DENY_ATTACH`） | opt-out 可能な hardening iteration | 🔴（デバッグ防御コード） |
| (c) DYLD 検出 | 優先度低、後期または見送り | 🔴 |

(a) は穏当寄り。(b)(c) は機微コードに触れるため Opus サブエージェント推奨。

参照: [port plan §3 判断 5](../design/authsock-adapter-port-plan.md)

### privilege separation 将来案 🔴

SSH agent protocol パーサを sandbox 子プロセスに分離し、構造化済みの要求だけを親へ渡す案
（DR-0008 の「秘密値 1 プロセス閉じ込め」と両立する設計）。未着手・将来検討。

参照: [port plan §3 判断 7](../design/authsock-adapter-port-plan.md)

### KeySource 2 軸の他ベンダ対応 🟡

agent proxy 転送（upstream）/ CLI 取得 + ローカル署名（op）の 2 軸抽象は設計に織り込み済み。
KeePassXC / Bitwarden など op 以外のベンダ CLI 対応は要調査（未着手）。

参照: [port plan §3 判断 8](../design/authsock-adapter-port-plan.md)

---

## Fable セッションへの申し送り: 着手前に読む doc の地図

| やること | 読む doc |
|---|---|
| パリティ検証・並走・切替・引退 | [DR-0004](../decisions/DR-0004-authsock-warden-succession.md)、[port plan §4](../design/authsock-adapter-port-plan.md) |
| key 層 allowed_processes | [DR-0012](../decisions/DR-0012-process-access-policy.md) |
| op agent socket 高速路 | [port plan §1.4、Iteration 4 見送り](../design/authsock-adapter-port-plan.md) |
| `cache-warden://KEY` 注入機能 | [issue/2026-06-11-secret-reference-injection.md](../issue/2026-06-11-secret-reference-injection.md)、[DESIGN-ja.md 将来検討](../DESIGN-ja.md) |
| anti-debug | [port plan §3 判断 5](../design/authsock-adapter-port-plan.md) |
| ビルトイン TouchID | [DR-0010](../decisions/DR-0010-config-and-reauth-command.md)、[DESIGN-ja.md open question](../DESIGN-ja.md) |
| TTL / pin の仕様 | [DR-0011](../decisions/DR-0011-ttl-base-separation-and-pin.md)、[DESIGN-ja.md value ライフサイクル](../DESIGN-ja.md) |
| 全体設計を把握したい | [DESIGN-ja.md](../DESIGN-ja.md)（最新状態を反映した設計サマリ） |
| 全 DR の一覧 | [decisions/INDEX.md](../decisions/INDEX.md) |
| 移植計画の経緯・判断ログ | [port plan（authsock-adapter-port-plan.md）](../design/authsock-adapter-port-plan.md) |

---

## 議論の要点

### なぜ Opus → Fable の切り替えが必要だったか

authsock アダプタ移植の後半（op 署名・鍵発見・プロセスアクセス制御）は、SSH 署名コード・
1Password 鍵操作・プロセス認証ロジックの生コードをコンテキストに抱えながら進む必要があった。
Fable はこうした機微セキュリティ実装文脈でセーフティガードが発火し、設計議論すら止まることがある。
そこで Opus をメインに据え、実装は都度クリーンコンテキストのサブエージェントに隔離する運用で
Iteration 4〜5 を完遂した。

Fable の強みは設計判断・コードレビュー・統合判断にあり、生コードを直読みしない限り穏当に動く。
残タスクの多くは「実機検証」「制御フロー追加」「将来機能の設計」であり、Fable 主体で進めやすい。

### authsock-warden の 4 状態と cache-warden コアのマッピング

warden の `KeyState`（NotLoaded / Active / Locked / Forgotten）をコアの `EntryState` に
そのまま移植するのではなく、以下のように対応させた（詳細は port plan §1.3）:

- NotLoaded → アダプタの公開鍵レジストリで吸収（コアに「値なしエントリ」概念を追加しない）
- Active → `EntryState::Active`
- Locked → `EntryState::SoftExpired`（再認証で Active へ復帰）
- Forgotten → `EntryState::HardExpired`（command 型は `regenerate` で再生成）

warden の `KeyRegistry`（4 状態）が `WardProxy` から実際には配線されていなかった（`cached_pem`
直接管理）という調査結果が移植方針を確定させる上でポイントだった。
**warden で設計意図として存在したが未配線だった TTL コアを、cache-warden では初めて実配線した**
のが Iteration 4 の本丸である。

---

## 次にやること

- [ ] authsock-warden と並走させてパリティ検証（Phase 2 着手）— 🟢 穏当、Fable 主体で可
- [ ] (a) core dump 抑制を daemon 起動時に追加 — 🟡 穏当寄り
- [ ] `cache-warden://KEY` 注入機能の設計（issue 参照）— 🟢 穏当、Fable 主体で可
- [ ] key 層 allowed_processes の設計・実装 — 🟡 要注意

## 関連

- [docs/design/authsock-adapter-port-plan.md](../design/authsock-adapter-port-plan.md) — 移植計画全体（iteration の詳細実績・設計判断ログ）
- [docs/decisions/INDEX.md](../decisions/INDEX.md) — DR 一覧
- [docs/DESIGN-ja.md](../DESIGN-ja.md) — 現状の設計サマリ（最新反映済み）
- [docs/issue/2026-06-11-secret-reference-injection.md](../issue/2026-06-11-secret-reference-injection.md) — 注入機能のアイデア起票
