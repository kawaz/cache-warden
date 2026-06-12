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

### 1. 型付き source スキーマ（command を kind の 1 つに格下げ）

定義の source を tag 付き構造にする。TOML (config / defs):

```toml
[kv.DB_PASSWORD]
source = { type = "command", argv = ["op", "read", "op://v/i/f"] }

[kv.GITHUB_KEY]
source = { type = "op", uri = "op://vault/github/private_key" }
soft-ttl = "1h"
```

kind 別フィールド (v1):

| type | 必須 | optional (v1) | 将来の余地 |
|---|---|---|---|
| `command` | `argv: [str]` | `cwd: str` / `env: {str: str}` | timeout、stdin 供給等 |
| `op` | `uri: str` (op:// 参照) | `account: str` | ssh-format、batch 取得等 |
| (将来ベンダ) | kind ごとに定義 | — | KeePassXC / Bitwarden 等 |

- serde は `#[serde(tag = "type")]` の enum + variant ごとの `deny_unknown_fields`。
  **optional フィールドの追加は非破壊**なので「余地」が構造的に保証される。
- `command.env` は daemon の環境にマージ (同名は上書き)。env に秘密を直書きすると
  定義永続化でディスクに残る (argv と同じ shell-history 同等リスク、doc 注意書き)。
- `op.account` は authsock source の `op_account` と同じ意味 (`--account` に渡る)。
- **既存の `command = [...]` フィールドは shorthand として維持**する
  (`source = { type = "command", argv = [...] }` に正規化。cwd/env が要るときだけ
  full 形式を書く)。`command` と `source` の同時指定はエラー。
- **原形を保持する**: `op` type は実行時に argv へ**降ろす** (lowering: 既存の内部
  サブコマンド経由の op fetch) が、定義には型付き原形が残り、status / 永続化 /
  冪等比較は**型付き形式で**行う。冪等 (b) 規則の完全一致は「type + 全 kind 別
  フィールド + TTL」の一致。
- CLI: `--command ARGV...` は type=command (argv のみ) の、`--source URI` は type=op の
  shorthand として維持。cwd/env 等の追加フィールドは `--command-cwd` / `--command-env
  NAME=V` の prefix グルーピング (`--otp-*` と同じ手法) で受ける。

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

### 4. authsock op source の取得モード (パターン A/B)

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

## Alternatives Considered

- **auth に `command` 以外を足すとき別フィールドを増やす**（`touchid = true` 等の並列）
  - 不採用理由: 方式が増えるたびに排他検証が増える。tag 付き enum なら「type を増やす」
    だけで排他が構造的に成立する。
- **source の型付き原形を CLI/daemon 側の並行テーブルで持つ**
  - 不採用理由: 永続化 snapshot が store で完結しなくなり、並行状態のドリフトリスク。
    コアの不透明スロット (解釈しない約束) は otp で実証済みのパターン。
- **`command =` shorthand の廃止（full `source = {...}` のみ）**
  - 不採用理由: 支配的ユースケース (argv だけ) の毎回の冗長化に見合う設計利得がない。
    shorthand は正規化 1 点で吸収できる。
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
- `--command-cwd` / `--command-env` / `source = {...}` full 形式 / `[auth].type` /
  `[authsock.sources.*].prefetch` が CLI / config / help / 補完 / DESIGN に増える。
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
