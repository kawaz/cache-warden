# DR-0016: OTP 値型（seed キャッシュ + デーモン側コード導出）

- Status: Active
- Date: 2026-06-11

## Context

TOTP は長寿命の秘密（seed、base32 / otpauth:// URI）から「seed + 現在時刻」で寿命 30 秒の
6 桁コードを導出する構造を持つ。op は `op read "op://v/i/field?attribute=otp"` でコードを
計算して返せるが、都度 ~1 秒 + TouchID され得る。cache-warden が seed をキャッシュすれば、
soft TTL の間はコード導出が即時・認証なしになる — 本製品の本来の売り（速くてセキュア）が
そのまま効くドメインである。

設計議論では「(A) define/set 時のメタデータで get が 6 桁を返す」「(B) OTP 翻訳アダプタが
KV から seed を取り出してコードに変換する」の 2 案が挙がり、以下に収束した:
**A の UX を B のレイヤリングで実装する**。キャッシュすべきは seed（TTL / mlock / zeroize が
全部意味を持つ）であり、コードはキャッシュ対象ではない（get のたびに導出する派生ビュー）。

## Decision

### 1. `--type otp` メタデータと値の正体

- `kv define` / `kv set` に値型メタデータ `--type otp` を追加する。型は定義メタデータ
  （秘密値ではない）として持ち、定義永続化（DR-0014）にも乗る。
- 格納する値は **seed**。raw base32 と **otpauth:// URI の両形式**を受け付ける。
  URI 形式ならパラメータ（digits / period / algorithm）を URI から読む。明示フラグ
  （`--otp-digits` / `--otp-period` / `--otp-algorithm`）は URI より優先。
  デフォルトは digits=6 / period=30s / SHA1（RFC 6238）。
- `status` / `kv list` は型を表示する。

### 2. 導出はデーモン側・コアは無傷（DR-0003 のアダプタ思想）

- TOTP 導出はデーモンのハンドラ層（プロトコル境界）で行う。コアは「バイト列 + TTL」の
  まま OTP を知らない。独立した翻訳アダプタコンポーネントは立てない（authsock が
  「SSH 鍵という秘密値の種別」であるのと同様、OTP は「導出ビューを持つ秘密値の種別」で
  あり、ハンドラ層の変換 1 枚で足りる）。
- 実装は CLI crate に RustCrypto の `hmac` + `sha1`（変種対応時は `sha2`）を追加して行う。
  コア lib の依存最小（DR-0002）は不変。RFC 4226 / 6238 のテストベクタで TDD する。

### 3. seed は write-only（コードだけが出る）

- otp 型キーへの `kv get` は常に**導出済みコード**を返す。**seed はデーモンから二度と
  出ない**。seed を他所で使いたければ再 set する（seed はプロビジョニング時点で
  QR / op に保管済みのはずで、cache-warden が二次配布元になる必要はない）。
- クライアント（エージェント含む）に渡るのは常に寿命 ~30 秒の減衰した権限になる。
  これは op より強い性質（op は field を読めば seed 自体が取れる）。
- `run` / `inject` の参照（DR-0013）も同様にコードを注入する。長寿命プロセスの env に
  注入されたコードは注入時点から ~30 秒で失効する — これは OTP の性質そのもので、
  典型用途（ログインコマンド等の短命利用）では問題にならない（ドキュメントに明記）。
- dry-run（DR-0015）は通常どおりマスク値になる。

### 4. TTL とライフサイクル

- TTL（soft / hard）・extend・pin・regenerate はすべて **seed エントリ**に対して
  通常どおり作用する。コードの 30 秒ウィンドウは直交概念（毎 get 導出）。
- 推奨パターン: **seed を op に置き `--type otp --source op://vault/item/field` で定義**する。
  lazy regenerate（DR-0014）により daemon 再起動後も自己修復する。static 投入の seed は
  値の永続化をしない設計（DR-0014）により daemon と共に消える（再 set が必要）。

### 5. `?attribute=otp` source との組合せはエラー

`--type otp` と `--source op://...?attribute=otp` の組合せは **define 時にエラー**にする。
`?attribute=otp` は op が*計算したコード*（寿命 30 秒）を返すため、これをキャッシュするのは
構造的に誤り（二重導出かつ即死値の保存）。otp 型の source は seed の field
（素の `op://vault/item/field`）を指す。`--type otp` なしの `?attribute=otp` source は
構文上は valid だが「30 秒で死ぬ値を TTL キャッシュする」footgun としてドキュメントに記す。

## Alternatives Considered

- **独立した OTP 翻訳アダプタ（別コンポーネント / 別 socket）**
  - 不採用理由: ハンドラ層の変換 1 枚で足りる用途に対して過剰。コンポーネントを増やすと
    seed の移送面（KV → アダプタ）が新設され、write-only 性質がむしろ作りにくい。
- **クライアント側導出（seed を渡して CLI がコード計算）**
  - 不採用理由: seed がクライアントプロセスに渡った時点で write-only 性質が崩れる。
    導出をデーモン側に置くことが本 DR の security 上の核心。
- **コード自体のキャッシュ**
  - 不採用理由: 寿命 30 秒の値は TTL モデル（時間単位の soft/hard）と噛み合わない。
    キャッシュすべきは seed。
- **seed の読み出し許可（`--raw` 等の escape hatch）**
  - v1 不採用理由: seed の保管責任はプロビジョニング元（QR / op）にあり、cache-warden が
    二次配布元になる必然がない。実需要が出たら再認証必須の明示操作として再検討する。
- **SHA1 / HMAC の手書き実装（依存ゼロ）**
  - 不採用理由: 暗号プリミティブの手書きは避けるのが王道。CLI crate は依存最小の対象外
    （DR-0002）で、RustCrypto crates は小さく枯れている。

## Consequences

- `kv.define` / `kv.set` プロトコルに型メタデータが増える。`status` / `kv.list` に型表示が増える。
- CLI crate に `hmac` + `sha1` 依存が増える（コアは不変）。
- otp 型の get 応答は「値」ではなく「派生コード」になる — get の意味が型で分岐する初の事例。
  将来別の派生ビュー型を足す場合は本 DR の write-only / デーモン側導出 / 型メタデータの
  パターンを踏襲する。
- HOTP（カウンタ型）・Steam 等の変種は v1 スコープ外（必要になったら algorithm 拡張で受ける）。

## 関連

- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — アダプタ思想（導出ビューはコアの外）
- [DR-0014-kv-definition-model](./DR-0014-kv-definition-model.md) — 定義メタデータ・`--source`・lazy regenerate（推奨パターンの土台）
- [DR-0015-dry-run-verification-mode](./DR-0015-dry-run-verification-mode.md) — dry-run でのマスク挙動
- [DR-0013-secret-reference-injection](./DR-0013-secret-reference-injection.md) — run / inject でのコード注入
- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — 依存配置（hmac / sha1 は CLI crate）
