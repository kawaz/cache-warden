# DR-0014: KV definition モデル（define / set / get の責務分離と定義レイヤ）

- Status: Active
- Date: 2026-06-11

## Context

v0.8.1 時点の KV 動詞には 3 つの構造的な不満があった:

1. **`kv set --command` は set 時点でコマンドを即時実行する**。script から毎回叩くと
   毎回 upstream（op read = ~1 秒 + TouchID され得る）が走り、キャッシュの意味が薄れる。
   「なければ登録、あれば読むだけ」の冪等な memoize プリミティブが存在しない。
2. **オンライン登録（`kv set`）は完全にオンメモリ**で、daemon 再起動で値だけでなく
   「KEY ↔ command の紐付け」ごと消える。再起動後は extend も regenerate もできない。
   定義（KEY / valuesource / TTL）は秘密値を含まないので、消える必然がない。
3. **DR-0013 の `run` / `inject` は参照キーの事前登録が前提**で、script / .envrc から
   自己完結で使う経路がない。参照構文をクエリパラメータで拡張する案
   （`cache-warden://KEY?command=...`）は、テンプレートや継承 env という「データ」が
   daemon での任意コマンド実行を引き起こす injection 面を新設してしまう。

検討の過程で「get に `--command` を載せる get-or-init 案」も挙がったが、動詞の責務が
濁る（get が書き込みを持つ）ため不採用とし、**「定義（definition）」を独立概念として
切り出す**方針に収束した。

## Decision

### 1. 動詞の責務分離: define / set / get

| 動詞 | 責務 | upstream 実行 |
|---|---|---|
| `kv define KEY (--command ARGV... \| --source URI) [--soft-ttl D] [--hard-ttl D]` | valuesource 付きキーの**定義**を登録する。冪等 | **しない**（実行は初回 get まで遅延） |
| `kv set KEY (--value V \| --value-stdin) [--soft-ttl D] [--hard-ttl D]` | static 値の投入に専念。**`--command` は廃止** | — |
| `kv get KEY` | 読みに専念。値が無い/HardExpired でも定義があれば regenerate 経路で lazy 生成 | 必要時のみ |

- `kv define` の冪等性は**完全一致規則**で担保する: 既存定義と同一（argv/URI + TTL が一致）
  なら no-op、**不一致ならエラー**（`bad_request` 系）。「コマンドが正本」として黙って
  再定義する案は、同 KEY を別コマンドで使う複数 script が互いに上書きし合うスラッシングを
  隠蔽するため不採用。解消はユーザが明示的に `kv del --with-define` → 再 define で行う。
- `kv set --command` の廃止は breaking だが pre-1.0 であり、互換レイヤは作らない。

### 2. 定義レジストリは値ストアと分離する（NotLoaded を作らない）

「定義はあるが値はまだ無い」状態を `EntryState` に追加**しない**（DR-0004 が NotLoaded を
コアに持ち込まなかった判断と同型）。定義は秘密値ではないただの設定データなので、
**値エントリとは別の定義レジストリ**としてコアに持つ:

- `kv get`: 値エントリが不在 or HardExpired のとき、定義レジストリに定義があれば
  **既存の regenerate 経路**（再認証込み）で値を生成する。EntryState の 3 状態は不変。
- `kv del KEY`: **値のみ破棄**（zeroize）。定義は残るので次の get で再生成される
  （= 実質 invalidate）。`--with-define` を付けると定義ごと削除する。
- static エントリは定義を持たない（del の挙動は従来どおり）。

### 3. 定義ソース: `--command` と `--source URI`

- `--command ARGV...`: 従来どおりの生 argv。
- `--source URI`: scheme → コマンドテンプレートのマッピングによる糖衣。
  v1 は `op://` のみビルトイン（`op read <URI>` に展開）。
  - op の field によっては `--reveal` 等のフラグが必要なケースがあり、テンプレート固定では
    表現できない。その場合は `--command` に逃げる（v1 の明示的な制限）。
  - scheme テーブルの config 拡張（KeePassXC / Bitwarden 等のベンダ CLI 追加、
    port plan §3 判断 8 の受け皿）は follow-up。機構としては「scheme → argv テンプレート」
    の表を config に持つだけで、コア変更を要しない。
- `--command` と `--source` は排他（どちらか一方が必須）。

### 4. 定義の 4 レイヤと衝突規則

| レイヤ | 場所 | タイミング |
|---|---|---|
| グローバル定義 | daemon config `[kv.*]` | 起動時に定義登録。**実行はデフォルト lazy**（初回 get）。`preload = true` で従来の起動時実行を opt-in（DR-0010 の挙動変更） |
| 永続化されたオンライン定義 | state dir の定義ファイル（0600） | opt-in（config `[daemon]` のフラグ）。`kv define` / static でない `kv set` 由来の定義を daemon が書き出し、起動時に restore |
| プロジェクト defs | `--defs FILE`（`run` / `inject` / `kv define --defs FILE`） | 呼び出し時にファイル内の全定義を一括 define（実行は lazy なので全件登録してもコストゼロ） |
| 純オンライン | `kv define` / `kv set`（永続化 off 時） | プロセス生存中のみ |

- **起動時マージは config 優先**: config の `[kv.X]` と永続化済み定義の X が食い違ったら
  config が勝ち、負けた永続エントリは warn して破棄する（「config を編集したのに古い
  永続定義が勝ち続ける」事故を防ぐ）。
- **ランタイムの衝突は一律エラー**（§1 の完全一致規則）: `kv define` / `--defs` と
  既存定義の不一致は `bad_request` で明示的に失敗させる。
- **永続化に値は一切書かない**。static エントリの値は daemon と共に死ぬ（捨てる）。
  定義（KEY / argv / URI / TTL）のみ書く。ユーザが argv に直接トークンを埋め込んだ場合は
  ディスクに残る（shell history と同等のリスク）。ファイル 0600 + ドキュメント警告で許容。
- **defs ファイルのスキーマは daemon config の `[kv.*]` 節と同一文法**（DR-0010 の
  サブセットファイル）。static 値が書けない規則もそのまま継承。慣習名は
  `.cache-warden.toml`。**自動探索はしない**（cwd のファイルを勝手に読むと「clone した
  リポの defs が次の run で勝手に登録される」= データ→コード問題の再来。明示 `--defs` か、
  direnv が export する環境変数経由のみ。direnv allow が信頼ゲートになる）。

### 5. DR-0013（run / inject）との接続

- 参照構文 `cache-warden://KEY` は**読み取り専用のまま**変更しない。
  テンプレート / env というデータはコードを運ばない。
- 事前定義は `--defs FILE` で run / inject 呼び出しに同梱できる（§4）。
  daemon 再起動後も次の run / inject で定義が self-healing する。
- 参照のクエリパラメータ拡張（`cache-warden://KEY?argv=...&soft-ttl=300` = インライン
  define）は **opt-in フラグ（`--allow-inline-define`）の背後に置く設計として記録し、
  実装は後送り**とする。`--defs` で主用途（.envrc / プロジェクト自己完結）が満たせるため
  優先度が低い。実装時は argv 境界を繰り返しクエリパラメータ（`argv=` の反復）で運び、
  生成ヘルパ（`cache-warden ref`）を併設する。inject の substring 走査における参照終端
  規則の拡張（`?` `&` `=` `%` を含む）も実装時に DR-0013 の文法を改訂する。

### 6. プロトコル変更（v1 への追加・変更）

- `kv.define` 追加: `{key, source: {command: argv} | {uri}, soft_ttl_secs?, hard_ttl_secs?}`。
  完全一致 no-op / 不一致 `bad_request`。
- `kv.set` は static 専用に変更（`SetSource::Command` を外す）。
- `kv.del` に `with_define?: bool` を追加。
- `kv.get` の wire は不変（lazy 生成は daemon 内部の regenerate 経路）。
- `status` / `kv.list` は「定義のみ（値未生成）」のキーも列挙し、状態表示で区別する。

## Alternatives Considered

- **get-or-init（`kv get KEY --command ...`）**
  - 不採用理由: get が登録（書き込み）を持ち、動詞の責務が濁る。define の分離なら
    「定義登録 = 実行なし」という追加の利点（set --command の即時実行問題の解消）も得られる。
- **define 時に即時実行（現 set --command と同じ eager 方式）**
  - 不採用理由: 毎回叩く script で upstream が毎回走る問題が残る。lazy なら define は
    何度呼んでも無料で、defs ファイルの全件一括登録も成立する。
- **コアの EntryState に NotLoaded（定義のみ）状態を追加**
  - 不採用理由: DR-0004 で「値なしエントリ概念をコアに追加しない」と決めた構造を壊す。
    定義は秘密値でない設定データであり、値ストアの外（定義レジストリ）に置くのが責務的に正しい。
- **定義不一致時の「コマンドが正本」再定義（declarative 上書き）**
  - 不採用理由: 同 KEY を別定義で使う複数利用者が黙って上書きし合い、upstream 再実行の
    スラッシングが不可視になる。エラーで顕在化させ、解消はユーザの明示操作に委ねる。
- **defs ファイルの自動探索（cwd の `.cache-warden.toml` を暗黙ロード）**
  - 不採用理由: 信頼していないリポのファイルがコマンド定義として登録される
    （データ→コード境界の崩壊）。明示フラグ / direnv 経由のみとする。
- **値の永続化（encrypted store 等）**
  - 不採用理由: 「秘密値はメモリのみ・プロセスと共に死ぬ」がコアの不変条件
    （mlock / zeroize の保護境界）。永続化するのは定義だけ。
- **参照クエリ拡張（インライン define）の即時実装**
  - 後送り理由: `--defs` で主用途が満たせる。injection 面（opt-in ゲート）と参照終端文法の
    拡張という仕様面積に対し、今払うリターンが小さい。

## Consequences

- **DR-0010 を一部改訂**: `[kv.*]` の起動時実行はデフォルト lazy となり、従来挙動は
  `preload = true` の opt-in に変わる。定義永続化の opt-in フラグが `[daemon]` に増える。
- **DR-0013 を一部補強**: 参照は読み取り専用のまま（本 DR §5）。インライン define は
  opt-in 設計として記録され、DR-0013 の参照文法改訂は実装時に行う。
- **breaking**: `kv set --command` 廃止、`kv.del` の意味変更（値のみ destroy がデフォルトに）。
  pre-1.0 のため互換レイヤなし。
- コアに定義レジストリが増える。restore（永続化）・config lazy 定義・`--defs` の 3 経路が
  同じレジストリ操作に一本化される。
- `run` / `inject`（DR-0013）の実装は本 DR の `kv.define` + `--defs` を前提に積む。
- 将来のベンダ別 source（KeePassXC / Bitwarden）は scheme テーブルの追加で受けられる
  （port plan §3 判断 8 の解決経路が確定）。

## 関連

- [DR-0013-secret-reference-injection](./DR-0013-secret-reference-injection.md) — run / inject（本 DR が事前定義経路と inline-define の扱いを確定）
- [DR-0010-config-and-reauth-command](./DR-0010-config-and-reauth-command.md) — `[kv.*]` config（本 DR が preload 挙動を改訂）
- [DR-0011-ttl-base-separation-and-pin](./DR-0011-ttl-base-separation-and-pin.md) — lazy 生成が乗る regenerate 経路
- [DR-0004-authsock-warden-succession](./DR-0004-authsock-warden-succession.md) — NotLoaded をコアに持ち込まない判断（定義レジストリ分離の同型元）
- [docs/design/authsock-adapter-port-plan.md §3 判断 8](../design/authsock-adapter-port-plan.md) — KeySource 他ベンダ対応（`--source` scheme テーブルが受け皿）
