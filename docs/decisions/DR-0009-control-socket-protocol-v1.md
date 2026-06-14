# DR-0009: control socket プロトコル v1

- Status: Active
- Date: 2026-06-10

## Context

DR-0008 で「`cache-warden run` を単一 tokio プロセスとし、管理 CLI ↔ デーモンは
control socket（Unix domain socket）で通信する」ことを確定した。ただしプロトコルの
詳細（transport / framing / エンコーディング / コマンド体系 / プロセス認証との接続）は
「次の設計ステップで決める」として DR-0008 では決めなかった。本 DR がその次のステップ
であり、デーモン骨格の最初の実装（iteration 5）とセットでプロトコル v1 を確定する。

DR-0002 はライブラリ（`cache-warden`）の依存を最小に保ち、`serde` 等は CLI crate 側に
寄せる方針である。プロトコルの serde 型・framing・runtime（tokio）はすべて
`cache-warden-cli` crate に閉じ、ライブラリには持ち込まない。

## Decision

### Transport: Unix domain socket（0600 / stale 検知）

- パス: デフォルト `$XDG_STATE_HOME/cache-warden/control.sock`
  （`XDG_STATE_HOME` 未設定時は `~/.local/state/cache-warden/control.sock`）。
  `--socket PATH` で上書き可能。
- ファイルパーミッション 0600。bind 時に restrictive umask（0o077）で TOCTOU 窓を
  閉じ、さらに明示的に `set_permissions(0o600)` する（二重の防御）。
- 起動時に socket パスが既存なら connect 試験を行う:
  - connect 成功 = 別デーモンが稼働中 → `AddrInUse` でエラー終了（二重起動検知、
    稼働中の peer を上書きしない）。
  - connect 失敗 = stale socket（クラッシュしたデーモンの残骸）→ 除去して bind。

### Framing: JSON Lines（リクエスト 1 行 / レスポンス 1 行）

- リクエストは 1 行の JSON オブジェクト、レスポンスは 1 行の JSON オブジェクト。
- 採用理由:
  - デバッグ容易性（`nc` / `socat` で手で叩ける）。
  - serde は CLI crate 側に既に存在（DR-0002）、追加コストが小さい。
  - 管理 IPC は低頻度・非ストリーミングなので、ワンショット request/response に
    JSON Lines で十分。framing の曖昧さがない。

### 値のエンコーディング: 秘密値は base64（`*_b64` フィールド）

- 秘密値はバイナリ安全に運ぶため JSON 内で base64 エンコードし、フィールド名を
  `value_b64` のように `_b64` サフィックスで明示する（`SetSource::Static.value_b64`、
  `kv.get` 応答の `value_b64`）。
- 素の JSON 文字列は任意バイト列を表現できない（NUL・不正 UTF-8・改行）。base64 で
  wire をバイナリ安全に保ち、かつ JSON Lines の改行 framing を壊さない。
- エラーメッセージには秘密値を一切含めない。

### コマンド体系 v1

リクエストは `cmd` フィールドを判別子とする内部タグ付き enum:

| cmd | 入力 | 出力（成功時） |
|---|---|---|
| `ping` | なし | `{"ok":true,"pong":true}` |
| `status` | なし | デーモン情報（pid / version / socket）+ エントリ一覧（名前・状態・regenerable）。**値は含めない** |
| `kv.set` | `key`, `source=static`, `value_b64`, `soft_ttl_secs?`, `hard_ttl_secs?` | `{"ok":true,"set":true}` |
| `kv.get` | `key` | `{"ok":true,"value_b64":...}` |
| `kv.del` | `key` | `{"ok":true,"deleted":bool}` |
| `kv.list` | なし | `{"ok":true,"keys":[...]}`（ソート済み） |

> **[後続改訂]** コマンド体系はその後以下の DR で拡張・改訂された。現行の完全なコマンド一覧は
> `crates/cache-warden-cli/src/protocol/wire.rs` を正とする:
> - DR-0014 — `kv.set`（static 専用）/ `kv.define`（command source の登録）への分離
> - DR-0011 — `kv.pin` / `kv.unpin` の追加
> - DR-0015 — `kv.get` への `dry_run` フィールド追加

- レスポンスは成功時 `{"ok":true,...}`、失敗時 `{"ok":false,"error":{"kind":...,"message":...}}`。
- `error.kind` は機械可読カテゴリ: `bad_request` / `not_found` / `auth_failed` /
  `not_regenerable` / `upstream_failed` / `internal`。`message` は人間可読で
  秘密値を含まない。
- `kv.get` の状態遷移はコアの TTL ステートマシンに委譲する:
  - Active → 値をそのまま返す。
  - SoftExpired → `Store::extend_authenticated`（再認証）経由で延長し、値を返す。
  - HardExpired + regenerable（command 源）→ `Store::regenerate`（上流再実行 + 再認証）
    経由で再生成し、値を返す。HardExpired + static は `not_regenerable`。

### peer 認証: LOCAL_PEERPID / SO_PEERCRED → ancestry を requester として渡す

- 接続ごとに peer pid を取得する（macOS: `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`、
  Linux: `getsockopt(SOL_SOCKET, SO_PEERCRED)` の `ucred.pid`）。
- `SystemInspector::ancestry(pid)` で祖先チェーンを得て、Store の auth ゲート
  （`extend_authenticated` / `regenerate`）に `requester` として渡す。
- 第一防壁は UDS の 0600 + 同一 uid である。ancestry は監査と将来ポリシーの材料
  として運ぶだけで、**ポリシー判定はまだしない**（DR-0006 / DR-0008 の方針通り、
  コアは requester を解釈しない）。peer pid 取得失敗時は `requester = None`
  （= in-process 扱い）でフォールバックする。

### Authenticator: 本 iteration では AllowAll を配線

- 再認証境界には `AllowAll` を配線する（TouchID 等の実機実装は将来 iteration）。
- 配線箇所（`server::run_request` の `let auth = AllowAll;`）を差し替えるだけで
  実 Authenticator に切り替えられる形にしてある。

### 同期処理の隔離

- リクエストハンドラは接続ごとに `spawn_blocking` で blocking pool へ隔離する
  （DR-0008 の方針）。上流コマンド実行はユーザプロンプト待ちで分単位にブロックし得る
  ため、async worker を塞がない。長い regeneration 中は他キーへのリクエストも store
  ロック待ちになるが、ロック粒度の細分化は競合が実測されるまで先送りする。

## Alternatives Considered

- 案 A: length-prefixed バイナリ framing
  - 不採用理由: デバッグ性が著しく落ちる（`nc` / `socat` で手で叩けない）。管理 IPC は
    低頻度なので、バイナリ framing の性能利得は不要。
- 案 B: gRPC / Cap'n Proto / CBOR 等の構造化バイナリプロトコル
  - 不採用理由: 依存と複雑さが管理 IPC の規模に見合わない（DR-0002 の依存最小方針に反する）。
    スキーマ進化やコード生成の利益も、この単純なコマンド集合では過剰。
- 案 C: 値を素の JSON 文字列で運ぶ（base64 なし）
  - 不採用理由: JSON 文字列は任意バイト列（NUL・不正 UTF-8）を表現できず、値に改行が
    含まれると JSON Lines の framing を壊す。秘密値はバイナリ安全に運ぶ必要があるため、
    base64 を採用する。

## Consequences

- DR-0008 が残した「control socket プロトコル設計」の open question を解消する。
  DESIGN（ja/en）の open question からこの項目を外し、プロトコル節を追加する。
- CLI サブコマンド体系の v1 が確定する: `run` / `ping` / `status` /
  `kv set|get|del|list`（kawaz の CLI 好み: サブコマンド制 / 引数なしは help /
  ロングオプション / `--help` のセクション構成）。
- プロトコル型・framing・runtime はすべて CLI crate に閉じ、ライブラリの依存最小
  （DR-0002）は維持される。ライブラリには `Store::source_of`（値非露出のメタデータ
  アクセサ）を 1 つだけ追加した（status の regenerable 表示用、依存追加なし）。
- AllowAll 配線のため、現状はプロセス認証ゲートが「常に許可」で通る。実 Authenticator
  （TouchID）への差し替えは将来 iteration で、配線 1 箇所の変更で済む。
- 将来のプロトコル拡張（authsock アダプタの SSH agent socket、KV socket API の他プロセス
  利用）は、同じ JSON Lines + base64 の枠組みにコマンドを追加する形で進められる。

## 関連

- [DR-0008-single-daemon-hosting](./DR-0008-single-daemon-hosting.md) — 単一デーモンプロセス直担型（本 DR が残した「次の設計ステップ」を実施）
- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — lib 依存最小 / serde 等は CLI 側（プロトコル型を CLI crate に閉じる根拠）
- [DR-0006-process-inspection-dependencies](./DR-0006-process-inspection-dependencies.md) — プロセス検査の libc 採用（peer ancestry 取得の基盤）
- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — コアドメイン（プロトコルが薄く乗るコア）
