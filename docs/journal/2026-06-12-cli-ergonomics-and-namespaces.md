# cli-ergonomics-and-namespaces: CLI 整理と KV namespace

- Date: 2026-06-12

## 何をしたか

kawaz の「set に otp オプションあるの混乱では？」から始まった CLI 整理の議論が、
動詞の純化 → `--` セパレータ → 文字種 → namespace へと連鎖し、DR-0017 の設計と実装まで
1 アークで完結した。リリース: v0.15.0 / v0.16.0。

| リリース | 内容 | DR |
|---|---|---|
| v0.15.0 | `--type`/`--otp-*` の define 専用化（CacheEntry meta 削除）/ positional `kv set [--] KEY [VALUE]` / 全 leaf `--` セパレータ | DR-0016 改訂 |
| v0.16.0 | KV namespace（`--namespace` / `cache-warden://[NS/]KEY`）+ KEY/NS 文字種 `[A-Za-z0-9_]+` 生成時強制 | DR-0017 |

## 議論の流れと確定事項

1. **`--type otp` は define 専用に**（kawaz 発案）: static OTP seed は「再 set のために seed を
   平文で持ち続ける」を誘発するアンチフィーチャーだった。副産物として CacheEntry 側の
   meta スロットを丸ごと削除できた（型付きキーは必ず定義を持つ → 型判定は定義レジストリ
   一本）。デバッグは `--command echo <seed>` で足りる
2. **`kv set k v` の positional 化**: get/set/define の責務分離で set が単純になったので
   フラグ不要に。VALUE 省略 + pipe = stdin、TTY なら即エラー（無言ハング防止）
3. **全 leaf 共通 `--` セパレータ**: 以降は一切オプション解釈しない。導入の副産物として
   `run -- cmd --socket/--dry-run` が子 argv からフラグを盗まれていた**潜在バグ 2 件**が
   構造的に解消（全域スキャン型抽出器が `--` で停止するようになったため）
4. **文字種を `[A-Za-z0-9_]+` に縮小**: `.` は TOML の `[kv.NAME]` で dotted-key ネスト化
   する footgun、`-` は inject 終端の丸呑み・jq/env 名非互換。「キー名は env 変数と同じ感覚」
   の 1 行で説明が終わる。狭める方向は breaking なので「迷うなら狭い側から」で確定
5. **namespace**（DR-0017）: `--defs` の KEY 衝突問題の解。CLI は `--namespace` 一本
   （KEY への `ns/key` 埋め込み拒否 = 排他規則を作らない、kawaz 確定）、参照は
   `[NS/]KEY`（未修飾 = 文脈 / 修飾 = 絶対）、config/defs は per-entry `namespace`
   フィールド（あり = 絶対 / なし = 文脈デフォルト、参照と同型規則）。デフォルト NS は
   フラグ > `CACHE_WARDEN_NAMESPACE` > `[cli].namespace` > default で direnv 連携が本命

## ハマり所・発見

- **wire は合成キー 1 本**（ns 別フィールド不採用）: ns を wire で分けると「NS 省略」が
  表現可能になり、daemon 側に第 2 のデフォルト解決点が漏れる。合成済み
  `^[A-Za-z0-9_]+/[A-Za-z0-9_]+$` の単一検証に畳んだ
- **永続化は `[kv.NS.KEY]` dotted ネスト**（kawaz レビューで quoted 合成名から修正）:
  文字種から `.` を外したことで dotted パスのセグメント数 = 意味が一意になり、機械生成
  ファイルは全エントリ NS 正規化済みで深度が均一なので、人間 config が dotted を採れない
  理由（未修飾 2 階層との混在 shape 判定）がここには無い。quoting 不要の性質を自分で
  捨てない。同 KEY 別 NS の共存も自然に表現できる
- 補完テストで「旧 release バイナリによる偽陽性 PASS」をエージェントが自力検出 →
  再ビルド後に再検証する流れがあった。**補完/E2E 系は被験バイナリの鮮度確認が必須**

## 関連

- [DR-0017](../decisions/DR-0017-kv-namespaces.md) — namespace + 文字種（本日設計・実装）
- [DR-0016](../decisions/DR-0016-otp-value-type.md) — define 専用化の改訂
- [DR-0013](../decisions/DR-0013-secret-reference-injection.md) — 参照文法の `[NS/]KEY` 改訂
- [2026-06-11-definition-model-and-injection.md](./2026-06-11-definition-model-and-injection.md) — 前日の definition モデル導入（本日の整理の土台）
