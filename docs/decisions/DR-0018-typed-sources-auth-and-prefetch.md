# DR-0018: 型付き source / auth スキーマと prefetch モード

- Status: Active
- Date: 2026-06-12

## Context

パリティ検証 (Phase 2) の TouchID 観測から派生した 3 つの設計課題をまとめて確定する。

1. **鍵ごとの初回認可**: op の認可はアプリセッション単位で、鍵 (item) 単位の再認可を
   op 側に強制する手段がない。鍵単位の初回ゲートの信頼できる置き場は cache-warden 自身の
   Authenticator である (lazy 生成は既に `AuthOperation::Regenerate` として認証ゲートを通る)。
2. **メカニズムが「command」に焼き付いている**: `[auth].command` は外部コマンドが唯一の
   認証方式としてフィールド名に固定され、ビルトイン TouchID (DR-0010 open question) や
   リモート承認 (push 通知) を足す受け皿がない。define の source も逆向きに歪んでいて、
   `command` (argv) がプリミティブ、`op://` は parse 時に argv へ展開されて**原形が消える**
   糖衣になっている (status に argv しか出せない、DR-0014 の v1 妥協)。
3. **取得モードの選択** (パリティ検証で出たパターン A/B): 現行は「公開鍵と item id の
   対応だけ先に取得し、秘密鍵は初回要求時に lazy fetch」(= B)。対して「全鍵を起動時に
   取得して warden 内に封印し、鍵ごとの初回利用を warden の認証で解放する」(= A) には
   「リモートから普段使わない鍵を op なしで出せる」という固有の価値がある。

共通解は **「kind + kind 別フィールド」の型付きスキーマ** (`--type otp` + `--otp-*` の
prefix グルーピングと同じパターン) を source と auth の両方に適用すること。

## Decision

### 1. 型付き source スキーマ（`source = "<kind>"` が判別子、kind 別テーブルに実態）

kind 別の実態は kind 名のテーブル (`command.*` / `op.*`) に書き、**どれを使うかは
`source = "<kind>"` フィールドが明示**する。TOML (config / defs):

```toml
[kv.DB_PASSWORD]
source = "command"
command.argv = ["op", "read", "op://v/i/f"]
command.cwd  = "/tmp"            # optional
command.env.K1 = "V1"            # optional (map)
soft-ttl = "1h"

[kv.GITHUB_KEY]
source = "op"
op.uri = "op://vault/github/private_key"
op.account = "my.1password.com"  # optional
command.argv = ["..."]           # 選ばれていない kind テーブルは無視 (エラーにしない)
```

kind 別フィールド (v1):

| kind (テーブル名) | 必須 | optional (v1) | 将来の余地 |
|---|---|---|---|
| `command` | `argv: [str]` | `cwd: str` / `env: {str: str}` | timeout、stdin 供給等 |
| `op` | `uri: str` (op:// 参照) | `account: str` | ssh-format、batch 取得等 |
| (将来ベンダ) | kind ごとに定義 | — | KeePassXC / Bitwarden 等 |

- 判別は `source` フィールドのみ: **排他検証が不要**になり (kind テーブルの共存を
  数えない)、エラーは「`source = "command"` なのに `command.argv` が無い」式の
  kind 別 required チェックだけに縮む。選ばれていない kind テーブルは**無視**
  (副産物: 両方の spec を書いたまま `source` 1 行で切り替えられる)。
- エントリ構造体は `source: String` + `command: Option<CommandSpec>` /
  `op: Option<OpSpec>` / …。各 Spec は `deny_unknown_fields`、
  **optional フィールドの追加は非破壊**なので「余地」が構造的に保証される。
- 冪等 (b) 規則の完全一致は「`source` + 選ばれた kind のテーブル + TTL」。
  無視されている kind テーブルは比較対象外 (不活性なので変わっても同一定義)。
- **bare な `command = [...]` (配列形) は廃止**。同じキーが配列にもテーブルにもなる
  二形態は TOML として曖昧で、argv だけの場合も `command.argv = [...]` で 1 行
  (冗長化はほぼゼロ)。
- `command.env` は daemon の環境にマージ (同名は上書き)。env に秘密を直書きすると
  定義永続化でディスクに残る (argv と同じ shell-history 同等リスク、doc 注意書き)。
- `op.account` は authsock source の `op_account` と同じ意味 (`--account` に渡る)。
- **原形を保持する**: `op` kind は実行時に argv へ**降ろす** (lowering: 既存の内部
  サブコマンド経由の op fetch) が、定義には型付き原形が残り、status / 永続化 /
  冪等比較は**型付き形式で**行う。wire も同形 (`{"source": "command",
  "command": {...}}`) を運ぶ。
- CLI: `--command ARGV...` (rest 消費) = 「`source = "command"` + `command.argv`」の
  糖衣、`--source URI` = 「`source = "op"` + `op.uri`」の糖衣として維持。cwd/env は
  `--command-cwd` / `--command-env NAME=V` の prefix グルーピング (`--otp-*` と同じ
  手法) で `--command` より前に置く。`--command-argv` という別名は作らない
  (同じものに名前を 2 つ与えない)。

### 2. コアの保持方法: 第 2 の不透明スロット

core の `Definition` は lowering 済みの `ValueSource::Command`（実行プリミティブ、
CommandRunner 契約不変）に加え、**型付き原形を不透明スロットとして保持**する
(otp の `ValueMeta` と同じ「コアは保存・比較のみで解釈しない」扱い。value 型と
source 型は直交軸なのでスロットは分ける)。

- 永続化は store からの snapshot で完結し続ける (CLI 側に並行テーブルを作らない —
  DR-0012 key 層実装時に config_names 並行管理で踏みかけたドリフトの教訓)。

### 3. 型付き auth スキーマ

```toml
[auth]
type = "command"                     # v1 で実装するのはこれのみ
command = ["/path/to/approve"]       # type=command の実態 (既存の契約そのまま)
```

- `[auth]` 省略 = AllowAll (不変)。`[auth]` を書くなら `type` 必須。
- 将来の kind 枠: `touchid` (ビルトイン LocalAuthentication、DR-0010 open question の
  受け皿) / `push` (リモート承認ゲート) 等。kind 別フィールドは各実装時の DR で定義。
- 既存 config の `[auth] command = [...]` (type なし) は**エラー**にする
  (pre-1.0、移行レイヤなし。type 1 行を足すだけ)。

### 4. prefetch — 起動時 config と手動サブコマンドの 2 トリガ

prefetch (lazy 定義の能動的な実体化) は**同じ内部操作の 2 トリガ**として提供する。

#### 4a. 起動時 (config、パターン A/B)

`[authsock.sources.NAME]` に `prefetch = false` (デフォルト、現行 = パターン B) を追加:

- **B (lazy、デフォルト)**: 起動時は公開鍵 + item id の対応のみ。秘密鍵は初回署名要求で
  fetch (認証ゲート = `Regenerate` を通る。`[auth]` を設定していれば**鍵ごとの初回に
  warden の認証**が出る)。
- **A (`prefetch = true`、opt-in)**: 起動時に発見した全鍵の秘密鍵を fetch して KV に封印。
  **エントリは SoftExpired 状態で投入**し、鍵ごとの初回利用が `extend_authenticated`
  (= warden の認証) を必ず通るようにする — 「封印 + 鍵ごとの初回解放」を既存の
  状態機械の再利用だけで実現する (新しい状態を作らない)。
  - 価値: 普段使わない鍵も warden 内にあるため、op に触れない状況 (リモート等) でも
    warden の Authenticator (将来の push 承認等) の裁量で取り出せる。
  - リスク (opt-in の理由): 利用予定のない秘密鍵まで取得する over-collection。
    filters で発見範囲を絞る + op 側監査ログに一括アクセスが残ることで緩和。
  - prefetch の起動時 fetch は op セッション認可 (起動時 1 回) に乗る。

#### 4b. 手動 (`kv prefetch`)

```
cache-warden kv prefetch [KEY...] [--namespace NS]... [--pin DURATION]
```

- 位置引数 KEY = 現在 NS のキー、`--namespace NS` (反復可) = その NS の**全定義**を
  対象集合に追加。両方を混ぜられる。
- **引数なし = 現在 NS の全定義** (`kv list` の既定スコープと同じ規則。default NS
  だけで運用している場合は素の `kv prefetch --pin 12h` で全部仕込める)。
  全 NS 横断の糖衣 (`--all` 等) は持たない — 複数 NS は `--namespace` の反復で
  表現でき、まとめ方はユーザのスクリプト側の工夫に委ねる。
- 対象のうち **lazy 未実体化と HardExpired (定義あり)** だけを取得する。Active /
  SoftExpired は取得 skip (SoftExpired は `--pin` 指定時に pin が拾う)。
- 手動 prefetch の投入は **Active** (起動時 prefetch の SoftExpired 封印と異なる —
  ユーザがいま明示的に認証して取得しているので、封印して初回をもう一度ゲートする
  意味がない)。
- `--pin DURATION` 併用で、取得後に対象全部を pin。**認証はバッチで 1 回**
  (「外出前に 1 回 TouchID して全部仕込む」体験。AuthOperation の複合表現は実装時設計)。
- ユースケース: 寝る前/外出前のウォームアップを自分の bin の小粒スクリプトに:

```bash
# ~/bin/itumono-prefetch.sh
cache-warden kv prefetch --namespace authsock --namespace e2e_test AWS_MFA --pin 12h
```

  TouchID は cache-warden のバッチ認証 1 回 + (op セッション切れ時のみ) op 側、の
  数回に収まり、以降は SSH 署名・OTP コード導出 (DR-0016、seed さえ resident なら
  op 不要)・E2E クレデンシャルが期限まで保証される。

### 4.5. authsock 内部鍵の `authsock` namespace 正規化

- authsock op 鍵の内部キー `__authsock_op:ITEMID` (正規文字種外の擬似 prefix =
  検証の内部特例) を廃止し、**予約 namespace `authsock`** の正規キー
  (`authsock/op_<itemid>` 等、文字種準拠) に移す。DR-0017 の機構への統合で
  内部特例が消え、`kv prefetch --namespace authsock` / `kv list` / key 層
  ポリシーが正規に効くようになる。
- `authsock` NS は**予約**: ユーザの `kv define/set --namespace authsock` は拒否。
- **`authsock` NS の `kv.get` は拒否する**: SSH 秘密鍵 PEM は agent protocol
  (SIGN_REQUEST) 経由でのみ使える、という warden 以来の性質を維持する
  (OTP の seed write-only と同系の非対称)。`kv list` / `status` / `prefetch` /
  `pin` / dry-run (value-free) は可。

## Alternatives Considered

- **auth に `command` 以外を足すとき別フィールドを増やす**（`touchid = true` 等の並列）
  - 不採用理由: 方式が増えるたびに排他検証が増える。tag 付き enum なら「type を増やす」
    だけで排他が構造的に成立する。
- **source の型付き原形を CLI/daemon 側の並行テーブルで持つ**
  - 不採用理由: 永続化 snapshot が store で完結しなくなり、並行状態のドリフトリスク。
    コアの不透明スロット (解釈しない約束) は otp で実証済みのパターン。
- **`source = { type = "command", ... }` の tag 付き封筒形式**
  - 不採用理由 (検討過程の暫定案): kind 別フィールドが封筒の中に閉じ、TOML の
    dotted key として読みにくい。kind 別テーブル + `source` 判別子の方が自然。
- **フィールドの存在のみで判別（`source` フィールドなし、「ちょうど 1 つ」検証）**
  - 不採用理由 (検討過程の暫定案): 排他エラーの検証と文書化が必要になる。明示の
    `source = "<kind>"` なら排他が概念ごと消え、エラーは kind 別 required チェック
    だけに縮む。選ばれない spec を残したまま 1 行で切り替えられる利点もある。
- **bare な `command = [...]` (配列形) を shorthand として残す**
  - 不採用理由: 同じキーが配列 (shorthand) にもテーブル (`command.argv`) にもなる
    二形態は TOML として曖昧で、パースも文書も割れる。`command.argv = [...]` は
    1 行で書けるため shorthand の利得がほぼない。
- **op:// の argv 展開（原形破棄）を維持**
  - 不採用理由: status / 永続化に意図 (op 参照) を表示できず、ベンダ固有の最適化の
    置き場もない。本 DR の主目的の 1 つ。
- **prefetch 鍵を Active で投入（封印なし）**
  - 不採用理由: Active な値の取得は認証を通らないため「鍵ごとの初回に warden が認証」が
    成立しない。SoftExpired 投入なら既存状態機械の再利用で済む。
- **op 側に鍵単位の再認可を求める**
  - 不可: op の認可はアプリセッション単位で、item 単位の強制再認可フラグが存在しない
    (Phase 2 実測)。鍵単位ゲートは warden 側 Authenticator が唯一の信頼できる置き場。

## Consequences

- breaking: `[auth]` に `type` 必須化 / source の冪等比較が型付き形式基準に変わる。
  pre-1.0、移行レイヤなし。
- wire (`kv.define`) は型付き source を運ぶ形に変わる (composed key 等の他の wire 設計は不変)。
- `--command-cwd` / `--command-env` / `[auth].type` / `[authsock.sources.*].prefetch` /
  `kv prefetch` が CLI / config / help / 補完 / DESIGN に増える。
- 内部キーの `authsock` NS 移行は breaking (status / list の表示名が変わる。
  外部契約ではないので影響は表示のみ)。`kv.get` の authsock NS 拒否が増える。
- ビルトイン TouchID (将来 🔴) は `[auth] type = "touchid"` の実装としてそのまま着地できる。
- パターン B + `[auth]` 設定で「鍵ごとの初回 = warden 認証、以降 soft 延長も warden 認証、
  hard 再取得 = op (+warden)」が運用として成立する (実装変更なしで今日から可能、
  ドキュメント化のみ)。

## 関連

- [DR-0010-config-and-reauth-command](./DR-0010-config-and-reauth-command.md) — 現行 `[auth].command` (本 DR が type 化)
- [DR-0014-kv-definition-model](./DR-0014-kv-definition-model.md) — `--source` 糖衣と原形破棄の v1 妥協 (本 DR が解消)
- [DR-0016-otp-value-type](./DR-0016-otp-value-type.md) — 不透明スロットと prefix グルーピングの前例
- [DR-0011-ttl-base-separation-and-pin](./DR-0011-ttl-base-separation-and-pin.md) — prefetch 封印が再利用する SoftExpired / extend の状態機械
- [docs/journal/2026-06-12-parity-phase2.md](../journal/2026-06-12-parity-phase2.md) — 本 DR の発端 (TouchID 観測)
