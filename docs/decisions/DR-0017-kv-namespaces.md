# DR-0017: KV namespace（`--namespace` と参照の `NS/` 修飾）

- Status: Active
- Date: 2026-06-12

## Context

`--defs` ファイル（DR-0014）でプロジェクトごとに定義を持ち込めるようになった結果、
複数プロジェクトが同じ KEY 名（`DB_PASSWORD` 等）を別定義で使うと、define の完全一致規則
（(b) 規則）により衝突エラーになる構造的問題が顕在化した。手動 prefix 規約
（`projA.DB_PASSWORD`）でも回避はできるが、「デフォルトの切替」（direnv でプロジェクトに
入った瞬間に素の KEY がそのプロジェクトの空間に解決される）は機構がないと成立しない。
flat keyspace の上に利用が積み上がってから namespace を後付けするのは pre-1.0 の今やるより
遥かに痛いため、いま導入する。

## Decision

### 1. モデル: プロトコル境界での `NS/KEY` 合成（コアは flat のまま）

- namespace は **CLI / プロトコル層の概念**とし、内部キーは `NS/KEY` に合成して
  コアの flat な Store に流す。コア（依存最小・アダプタ思想、DR-0002 / DR-0003）は不変。
- NS の文字種は KEY と同じ（§1.5）、**単一セグメント**（階層 NS は YAGNI）。
  `/` は文字種に含まれないため、合成キーの分解は常に一意。
- デフォルト NS は `"default"`。

### 1.5. KEY / NS の文字種を `[A-Za-z0-9_]+` に絞り、生成時に強制する

- DR-0013 の参照可能 KEY 文字種（`[A-Za-z0-9_][A-Za-z0-9_.-]*`）から **`.` と `-` を外し、
  `[A-Za-z0-9_]+` とする**（env 変数名と同じ感覚の identifier 文字種、正規表現も最簡）。
  - **`.` を外す理由**: `.` 入りキーは TOML の `[kv.NAME]` で **dotted key として
    ネストテーブルに化け**、quoting（`[kv."a.b"]`）を忘れると文法を黙って壊す
    （`[kv.NS.KEY]` ネストを却下したのと同じ穴）。
  - **`-` も外す理由**: (1) このドメインのキー命名慣習はそもそも env 変数風の snake_case
    （`DB_PASSWORD` 等）で kebab-case を失う実害がほぼない。(2) inject の終端予測性 —
    `-` が文字種にあると `cache-warden://PW-suffix` が「キー PW-suffix」に丸呑みされる。
    DSN やハイフン混じりのテキストでは「キーは PW、`-suffix` はリテラル」の方が事故が
    少ない。(3) jq パス・JS プロパティアクセス・**env 変数名**（`-` 不可）等、あらゆる
    埋め込みドメインに 1:1 で持ち込める。(4) 文字種を後から**広げる**のは非破壊だが
    **狭める**のは breaking — 迷うなら狭い側から始める。
  - 結果は TOML bare key 文字種の部分集合なので、「参照可能なキーは config / defs に
    quoting なしで必ず書ける」性質が成立する。
- この文字種を**生成時にプロトコル境界で強制**する（`kv.define` / `kv.set` が KEY を検証、
  NS も同じ検証を共有）。「CLI では作れたが参照も config 記述もできない不整形キー」を
  存在させない。authsock 内部の疑似キー（`__authsock_op:*`）はプロトコルを通らない
  daemon 内部キーなので適用外。
- `--` セパレータ（全 leaf 共通）は文字種強制後も維持する: KEY に `-` 始まりは来なく
  なるが、`kv set` の positional VALUE には正当に `--` 始まりが来る
  （`kv set -- k --value-stdin`）し、`kv get -- "$KEY"` の防御的スクリプティング
  （変数が空・`-` 始まりでもフラグ誤解釈しない）の価値が残る。

### 2. CLI: 次元はフラグ 1 箇所（KEY への `ns/key` 埋め込みは拒否）

- kv 全動詞（define / set / get / del / list / pin / unpin）に `--namespace NS` を追加。
- **CLI の KEY 引数に `/` を含む形（`ns/key`）は拒否**する。namespace の指定経路を
  `--namespace` に一本化することで、パース分岐・`--namespace` との排他エラー・
  「どちらが勝つか」の規則が全部不要になる（シンプルさの維持、kawaz 確定）。
- `kv list` / `status` は現在の NS のみ表示。`--all` で全 NS を
  `NS/KEY` 表記で列挙。

### 3. 参照構文: `cache-warden://[NS/]KEY`（こちらは修飾を許す）

- 参照は URI なので path 形式の NS 修飾が自然であり、スコープも CLI と違う
  （テンプレート / env は「どの呼び出し文脈で解決されるか」を跨ぐ）ため、明示修飾を許す。
- 解決規則（`run` / `inject` を `--namespace foo` または `CACHE_WARDEN_NAMESPACE=foo` で
  実行した場合）:
  - `cache-warden://bar` → `foo/bar`（**未修飾はデフォルト NS に解決**）
  - `cache-warden://hoge/fuga` → `hoge/fuga`（**修飾済みは絶対参照**、文脈の NS に影響されない）
- KEY 文字種に `/` が無いため `NS/KEY` の構文上の曖昧さはない（DR-0013 の文法を改訂）。
  inject の substring 走査も同じ文字種規則で終端判定できる。

### 4. デフォルト NS の決定（dry-run 極性と同じ優先順位機構）

`--namespace` フラグ > `CACHE_WARDEN_NAMESPACE` 環境変数 > config `[cli].namespace` >
ビルトイン `"default"`。direnv がプロジェクトの `.envrc` で
`export CACHE_WARDEN_NAMESPACE=projA` すれば、そのディレクトリでは素の `kv get KEY` も
未修飾参照も projA に解決される（これが本命のエルゴノミクス）。

### 5. 各面の扱い — config / defs は per-entry `namespace` フィールド（参照と同型の規則）

`[kv.NAME]` エントリ（daemon config / defs ファイル共通文法）に省略可能な
`namespace = "NS"` フィールドを設ける。規則は参照構文と**同型**:

- **フィールドあり = 絶対指定**（そのエントリは常にその NS）
- **フィールドなし = 文脈のデフォルト**（daemon config では `"default"`、defs では
  `kv define --defs F --namespace NS` の指定値）

フラグ（デフォルト供給）とフィールド（個別固定）は役割が異なるため、排他エラーや
優先規則は不要。フィールドを書かない defs ファイルは従来どおり任意の NS で使い回せる。

```toml
[kv.baz]
namespace = "foo"          # このエントリは常に foo/baz
command = ["op", "read", "op://vault/item/password"]
```

- **既知の制限**: TOML のテーブルキーは一意なので、同一ファイル内に同じ NAME を別 NS で
  2 回書けない。daemon config でこれが要るケースは稀で、defs はプロジェクト別ファイルに
  分かれるため v1 では許容（必要が出たらテーブル名と KV キー名の分離 `key = "..."`
  フィールドで解ける）。
- `[kv.NAME].allowed_processes`（DR-0012 key 層）はエントリの解決先 NS のキーに対する
  ポリシーとして従う。
- **authsock の `keys = [...]`**: config は機械向け表面なので **`"NS/KEY"` 修飾を許可**
  （未修飾 = default NS）。CLI の KEY 引数への埋め込み拒否（§2）はインタラクティブ表面の
  規則であり、ここには適用しない（op 鍵の内部キー `__authsock_op:*` は従来どおり）。
- **定義永続化（DR-0014）**: NS を含めて round-trip する。フォーマットは
  **`[kv.NS.KEY]` の dotted ネスト**（均一な 2 階層マップ）とする。永続化ファイルは
  機械生成で全エントリの NS が正規化済みのため深度が揃い、§1.5 の文字種（`.` なし）に
  より dotted パスのセグメント数 = 意味が一意。quoting（`[kv."NS/KEY"]`）が不要で、
  人間 config が dotted ネストを採れない理由（未修飾 2 階層との混在による shape 判定）も
  ここには存在しない。同 KEY 別 NS の共存も自然に表現できる。
- **OTP（DR-0016）/ dry-run（DR-0015）**: 合成キーにそのまま乗る（変更なし。マスク値の
  KEY 表示は合成キー = `<cache-warden:NS/KEY:masked>` になる。未修飾で解決された参照も
  解決後の絶対キーで表示し、何に解決されたかを可視化する）。

## Alternatives Considered

- **CLI の KEY にも `ns/key` 埋め込みを許す**
  - 不採用理由（kawaz 確定）: パース分岐と判断ポイントが無駄に増え、`--namespace` との
    排他・優先規則が必要になる。指定経路をフラグに一本化したほうがシンプル。
- **手動 prefix 規約（`projA.DB_PASSWORD`）で済ます（機構なし）**
  - 不採用理由: デフォルト NS の切替（direnv 連携）と list の絞り込みが成立しない。
    規約は強制力がなく、defs 衝突問題も利用者の自己規律頼みになる。
- **コアの Store に namespace 次元を追加（`(ns, key)` キー）**
  - 不採用理由: プロトコル境界の合成で完全に表現でき、コアの単純さ（flat な秘密値 KV）を
    崩す理由がない。
- **階層 namespace（`a/b/c`）**
  - v1 不採用: 単一セグメントで用途（プロジェクト分離）は足りる。必要になったら
    文字種規則を保ったまま拡張可能。
- **config の NS 指定をネストテーブル（`[kv.NS.KEY]`）で表現する**
  - 不採用理由: `[kv.KEY]`（定義テーブル）と `[kv.NS.KEY]`（NS ネスト）が値の形でしか
    区別できず、TOML 上曖昧で `deny_unknown_fields` とも相性が悪い。per-entry の
    `namespace` フィールド（§5）なら曖昧さゼロで同じ表現力が得られる。
- **config `[kv.*]` を default NS 専用にする（NS 指定手段を入れない）**
  - 不採用理由: 検討過程の暫定案。per-entry フィールド方式に曖昧さの問題がなく、
    「フィールド = 絶対 / 省略 = 文脈デフォルト」が参照構文と同型の規則で増分複雑性が
    小さいため、最初から入れる。

## Consequences

- breaking: 内部キーが `NS/KEY` 合成になるため、既存の flat キーは `default/` 配下として
  扱われる（永続化済み定義ファイルは形式が変わる。pre-1.0、移行レイヤなし）。
- breaking: KEY 文字種から `.` が外れ、生成時検証が入る（DR-0013 の参照文法を改訂）。
  既存の `.` 入りキーは作り直しが必要。
- CLI / help / zsh 補完 / DESIGN ja/en / DR-0013 参照文法の更新が実装タスクに含まれる。
- `kv list --all` が増える。
- 参照の絶対/相対の区別が生まれる: テンプレートを NS 非依存に書きたければ未修飾、
  特定 NS に固定したければ修飾、と使い分けられる。

## 関連

- [DR-0014-kv-definition-model](./DR-0014-kv-definition-model.md) — defs ファイル（衝突問題の出所）・定義永続化
- [DR-0013-secret-reference-injection](./DR-0013-secret-reference-injection.md) — 参照文法（本 DR が `[NS/]` 修飾を追加）
- [DR-0015-dry-run-verification-mode](./DR-0015-dry-run-verification-mode.md) — 優先順位機構の前例（フラグ > env > config > 既定）とマスク表示
- [DR-0012-process-access-policy](./DR-0012-process-access-policy.md) — key 層ポリシー（v1 は default NS）
