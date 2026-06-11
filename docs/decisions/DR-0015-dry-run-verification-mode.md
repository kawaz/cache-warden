# DR-0015: dry-run 検証モードと reveal デフォルトの統一

- Status: Active
- Date: 2026-06-11

## Context

DR-0013 / DR-0014 の議論の中で「秘密値を見ずに配線を確認したい」ニーズが浮上した。
典型は AI エージェント: テンプレートや env の参照が正しく解決されるかを確認したいが、
実値がエージェントの会話ログに流れ込むのは事故である（本気の防御は将来の key 層
allowed_processes の仕事で、本 DR はその手前の事故防止層）。

設計の参考に op CLI（2.34.0）の実機挙動を確認した:

| op コマンド | 挙動 |
|---|---|
| `op run` | env には常に実値を注入。masked になるのは子プロセスの stdout/stderr 出力（`--no-masking` で解除） |
| `op read` | 常に実値（`--reveal` フラグ自体が存在しない）。拡張点は URI クエリパラメータ（`?attribute=otp` / `?ssh-format=openssh`） |
| `op item get` | 表示系はデフォルト masked、`--reveal` で解除 |
| `op inject` | 実値を書き出す |

つまり op は「移送経路 = 実値、表示経路 = masked」。masked は人間/エージェントの目に
触れる文脈のための機能である。

検討過程では「`run` = 実値デフォルト / `inject` = masked デフォルト」の非対称案も挙がったが、
場所によりデフォルトが異なる認知負荷（op の仕様の記憶違いが起きたのもまさにこの種の
非対称が原因）を理由に却下し、統一デフォルト + 文脈側で極性を切り替える方式に収束した。

## Decision

### 1. デフォルトは全動詞で reveal（実値）

`kv get` / `run` / `inject` はデフォルトで実値を返す/注入する/展開する。
op の「移送経路は実値」と同じ極性で統一する。

### 2. `--dry-run`: 値を出さない full-chain 検証モード

3 動詞すべてに `--dry-run` を設ける。dry-run は**検証の深さを妥協しない**:

- 定義の有無だけでなく、**値が実際に取れるところまで**確認する。未ロードの定義は
  upstream を実行し、SoftExpired は再認証で extend し、HardExpired + command は
  regenerate する。認証ゲートはすべて通常どおり効く（TouchID プロンプトも出る）。
  「dry-run OK = 本番も通る」を保証するのが目的（浅い検証は「定義はあるが op item が
  消えていた」を見逃し、dry-run が嘘をつく）。
- **値はデーモンから出さない**: dry-run の応答に value を載せない。マスクは
  クライアント側で値を隠すのではなく、**そもそも値がクライアントプロセスに届かない**。
- 副作用（upstream 実行・再認証プロンプト・キャッシュ warm）があることを help に明記する。
  キャッシュが温まるため、dry-run 直後の本番実行は即時になる（おまけの利点）。

### 3. マスク値と失敗の表現

- 成功: `<cache-warden:KEY:masked>` / 失敗: `<cache-warden:KEY:failed>`。
  本物の秘密値と見間違えない形で、key 名だけが読める（漏れても key 名まで）。
- dry-run は**途中で fail-closed しない**: 全参照を評価しきってから、成功/失敗の
  マスク値を埋めた出力を生成する。1 つでも失敗があれば非ゼロ終了 + stderr にサマリ
  （動作確認では全失敗を一度に見たい）。本番モードの fail-closed（DR-0013）は不変。
- `run --dry-run` は env にマスク値を注入して子コマンドを exec する（子の起動経路まで
  含めて確認できる）。`inject --dry-run` はマスク値で展開した出力を生成する。
  `kv get --dry-run` はマスク値を出力する。

### 4. デフォルト極性の切替（config / 環境変数）

安全側に倒したい文脈ではデフォルトを dry-run に変えられる:

- config: `[cli]` 節に `default-mode = "reveal"`（既定）`| "dry-run"`。
- 環境変数: `CACHE_WARDEN_DRY_RUN=1`（既存の `CACHE_WARDEN_CONFIG` と同じ接頭辞規約）。
- 優先順位: `--reveal` / `--dry-run` フラグ > `CACHE_WARDEN_DRY_RUN` > `[cli].default-mode`
  > ビルトイン既定（reveal）。`--reveal` と `--dry-run` の同時指定はエラー。
- AI エージェント環境にだけ `CACHE_WARDEN_DRY_RUN=1` を仕込めば「エージェントは
  デフォルト dry-run、人間は素のまま」という**文脈ごとの極性**が 1 つの仕組みで実現できる。

### 5. help での可視性

`kv get` / `run` / `inject` の help に「デフォルトは実値（reveal）。動作確認は
`--dry-run`（マスク値で検証、値は出ない）」を目につく位置に書く。`--reveal` の説明は
「デフォルトが dry-run に設定されている環境で実値モードを明示する」とする。
エージェントが help を読んだ時点で dry-run の存在に気づけることを設計要件とする。

### 6. プロトコル

- `kv.get` に `dry_run?: bool` を追加。daemon は通常の取得経路（lazy 生成・extend・
  regenerate・認証）を完走させた上で、応答に `value_b64` を**含めず**成功/失敗と
  状態のみ返す。
- `run` / `inject` は参照ごとに dry_run 付き `kv.get` を発行し、結果からマスク値を
  組み立てる（マスク文字列の生成はクライアント側。値は届いていないので安全）。

## Alternatives Considered

- **非対称デフォルト（run = 実値 / inject = masked）**
  - 不採用理由: 場所によりデフォルトが異なる認知負荷。実値が必要な inject 利用すべてに
    `--reveal` が定型で並び、エージェントもそれを写すため保護が形骸化しやすい。
    安全重視の文脈は §4 の極性切替で覆える。
- **全動詞 masked デフォルト**
  - 不採用理由: 本来用途（実行・展開）のたびにフラグが必須になり、同上の形骸化が起きる。
- **浅い dry-run（定義の有無・キャッシュ状態のみ確認、upstream 実行なし・認証なし）**
  - 不採用理由: 「dry-run OK なのに本番で落ちる」偽陰性を許す。TouchID プロンプトが
    出ることは欠点ではなく認証ゲートが効いている証拠であり、help に明記して許容する。
    （副作用ゼロの状態確認は既存の `status` が担う。）
- **クライアント側マスキング（値を受け取ってから隠す）**
  - 不採用理由: 値がクライアントプロセスのメモリを通過した時点で「値を出さない」保証が
    崩れる。応答に載せない方式なら構造的に漏れない。
- **op run 互換の子プロセス出力マスキング**
  - 不採用理由: DR-0013 で却下済み（常駐親が必要で exec 設計と両立しない）。本 DR の
    dry-run は「実行前の検証」であり、op の「実行中の出力後処理」とは守る面が異なる。

## Consequences

- DR-0013 / DR-0014 の実装タスクに `--dry-run` / `--reveal` フラグ、`[cli].default-mode`、
  `CACHE_WARDEN_DRY_RUN`、`kv.get` の `dry_run` 拡張が加わる。
- help / 補完の更新が必須要件になる（§5）。
- dry-run は認証・upstream 実行を伴うため、レート制御や「確認だけのつもりが TouchID」
  という体感は運用で観察する。問題が出たら浅い確認モード（status 拡張）の追加を再検討する。
- マスク値形式 `<cache-warden:KEY:...>` は参照構文（`cache-warden://KEY`）と衝突しない
  （inject の再帰展開なし規則とも整合、DR-0013）。

## 関連

- [DR-0013-secret-reference-injection](./DR-0013-secret-reference-injection.md) — run / inject 本体（本 DR が検証モードを追加）
- [DR-0014-kv-definition-model](./DR-0014-kv-definition-model.md) — 定義モデル（dry-run が検証する lazy 生成経路）
- [DR-0009-control-socket-protocol-v1](./DR-0009-control-socket-protocol-v1.md) — `kv.get` プロトコル（`dry_run` フィールド追加）
- [DR-0012-process-access-policy](./DR-0012-process-access-policy.md) — 本気のアクセス制御（本 DR は事故防止層、防御は key 層 allowed_processes の将来実装）
