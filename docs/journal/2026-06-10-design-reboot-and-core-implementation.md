# design-reboot-and-core-implementation: 設計リブートとコア実装 iteration 1-6

- Date: 2026-06-10

## 何をしていたか

別セッションからの依頼を受けて cache-warden の設計・実装を担当。設計の全面転回から始まり、
TDD で iteration 1〜6 を消化して v0.1.7 まで到達した。

確定したプロジェクト定義:
- **cache-warden = セキュア KV キャッシュコア + プロトコルアダプタ**
- authsock-warden の後継プロジェクト (将来的に吸収)
- 外部ソケット symlink の安定化はスコープ外

## ハマり所 → 解決策

### 旧構想 (DR-001 の symlink 安定化) に引っ張られた設計開始

- **現象**: リポ既存の DR-0001 に「volatile ソケットへの安定 symlink」構想が記録されており、その前提で resolver/symlink 維持 DR 群を一式書いた。kawaz レビューで前提否定、全面転回となった。
- **原因**: 同名に近い 2 構想が 2026-04 時点で並立していた。
  - authsock-warden 側 DR-018 に「KV キャッシュコアを別プロジェクトに切り出す」構想
  - cache-warden リポ側 DR-0001 に「volatile ソケットへの symlink 安定化」構想
  リポ側の記録だけ読むと古い構想に引っ張られる。authsock-filter の README にも旧前提で後継案内が書かれており (別セッション側で修正済み)、参照情報が旧構想寄りに偏っていた。
- **解決**: kawaz レビュー後に DR-0001 を Superseded にして DR-0003/0004 で新構想を確定。設計一式を書き直し。
- **教訓**: リポ内の記録だけでなく、参照元プロジェクト (authsock-warden) 側の最新 DR も必ず読む。

### `bump-semver get -qq` が guard で空文字を返した

- **現象**: justfile の `check-version-bumped` gate で `$N` が空になり、guard ロジックが壊れた。
- **原因**: `bump-semver get -qq` は `-q` が 1 個だと値を出力するが、`-qq` だと値の出力まで抑制する仕様。
- **解決**: `bump-semver get -q` (シングル `-q`) に戻す。ヒントメッセージのみ抑制、値は出力される。

### 複数 `Cargo.toml` を一括 bump しようとして失敗

- **現象**: workspace 構成で複数 `Cargo.toml` を bump-semver に渡したところ、package name が一致しないためエラー停止。
- **原因**: bump-semver は複数ファイル一括 bump の場合、全ファイルで package name が同一であることを要求する仕様。
- **解決**: `workspace.package.version` 継承に正攻法化。`[package] version.workspace = true` で子クレートが workspace バージョンを継承する構造にし、bump 対象は workspace root の `Cargo.toml` 1 ファイルのみにした。

### 翻訳ガードで `$N` capture TO が必須だと気づいた

- **現象**: `DESIGN.md` (en) が存在しない状態で `just push` が止まった。
- **原因**: 翻訳ガード (`check-outdated-translations`) は正本 (ja) より翻訳先 (en) が古い場合を検出するが、翻訳先が存在しない場合も同様にエラーになる。これは**正しい挙動**。
- **解決**: `DESIGN.md` (en) を作成して push。ガードを無効化しようとするのは誤り—英語版の作成を促す仕組みとして正当。

### macOS で `proc_pidinfo` が pid 1 を読めない

- **現象**: ProcessInspector の祖先遡上テストで、pid 1 (launchd) の情報を取得しようとすると `NotFound` エラーになる。
- **原因**: macOS の `proc_pidinfo` は非特権プロセスから pid 1 を読む権限がない。
- **解決**: 祖先遡上は「pid 1 に辿り着けなくても部分チェーンで正常終了」とする実装に修正。途中で `NotFound` を受け取ったら遡上を終了し、それまでの祖先チェーンを返す。

### `CommandRunner` が平文の一時コピーを作っていた

- **現象**: コードレビュー監査で、`CommandRunner` が `SecretBytes` の内容を `clone()` して一時変数に持っていることを発見。zeroize の意味が薄れる。
- **原因**: `clone()` で平文コピーを作った後に元のデータを `mem::take()` する順序が逆だった。
- **解決**: `mem::take()` で元データを move してから使う形に変更。clone による平文コピーを排除。

### `mlock` の `munlock → zeroize` 順序が逆

- **現象**: mlock 実装レビューで、`munlock` (ページアンピン) を先にしてから `zeroize` (内容消去) する順序だった。
- **原因**: munlock 後は OS がそのページをスワップアウトできる状態になるため、zeroize 前にスワップが発生すると秘密値がスワップ領域に残る可能性がある。
- **解決**: `zeroize` を先に実行し、pin された状態のまま内容を消してから `munlock` する順序に修正。ptr と len を先取りして zeroize 後に munlock に渡す実装。

### Linux で unused import による CI fail

- **現象**: macOS では通っていた CI が Linux 環境で `unused import` の clippy 警告によって fail した。
- **原因**: Linux と macOS で条件コンパイルされる import が異なり、Linux 側でのみ不要になる import があった。
- **解決**: `#[cfg(target_os = "linux")]` 等の条件付き import に修正、または使われていない import を削除。

### `SystemClock::new()` をリクエスト毎に呼んでいて TTL 評価が無効化

- **現象**: iteration 5 完了後の監査で、各リクエストハンドラが `SystemClock::new()` を毎回呼んでいることを発見。TTL が常に「今が起点」として評価され、キャッシュが期限切れにならない。
- **原因**: Clock 抽象の `Monotonic` は「プロセス起動時点からの経過時間」で TTL を評価する設計だが、毎回 new するとその時点が原点になる。
- **解決**: Clock インスタンスをプロセス寿命で 1 つ共有し、Arc で各コンポーネントに配布する構造に変更。

### `spawn_blocking` が doc コメントにしか存在せず未配線

- **現象**: iteration 5 の監査で、CommandRunner の `regenerate` が `spawn_blocking` で実行されると doc に書いてあるが、実コードでは async context 内で直接呼び出していた。
- **原因**: 設計段階で `spawn_blocking` 化の必要性は認識していたが、実装時に配線が漏れていた。コマンド実行中のプロンプト待ちが async worker スレッドをブロックする問題が生じる。
- **解決**: 実際に `tokio::task::spawn_blocking` に通して blocking タスクとして実行するよう配線。dead seam を削除。

## 議論の要点

### ホスティング戦略: 単一デーモン直担 (DR-0008)

当初、KV ストアのホスティングを「外部プロセスに委ねる」案もあった。authsock-warden 実機調査を
行ったところ、現状は単一プロセス + listener task 構成で、コア層が未配線のデッドコードであり、
CLI ↔ デーモン間の IPC が空白だと判明。

決定打は「秘密値の 1 プロセス閉じ込め」という設計上の優位性。秘密値を複数プロセスにまたがせる
と IPC 経路で平文が露出するリスクが生じる。単一デーモンが全秘密値を保持し、外部からは
コントロールソケット経由でのみ操作するモデルが正解。

### control socket プロトコル (DR-0009)

JSON Lines / 0600 パーミッション / stale ソケット復旧 / 二重起動拒否を採用。
stale 復旧は「前回の daemon が異常終了した場合でも新規起動できる」ために必要で、
接続試行 → 失敗 → 既存ソケットファイル削除 → 再バインド の順序で実装。

### config.toml の static 値問題 (DR-0010)

config.toml に static な値 (コンパイル時定数等) を直接書けない構造にした。
これはコマンドとそのパスが実行環境依存であり、config ファイルに焼き込むと
環境差異で問題が生じるため。CommandAuthenticator は authsock-warden の DR-009 の
設計思想を踏襲し、env 変数渡しで認証コマンドに必要な情報を渡す。

## 次にやること

- [ ] authsock アダプタの設計 (authsock-warden を cache-warden に吸収する本丸フェーズ)
- [ ] authsock-warden 側の cache-warden 組み込み配線

## 関連

- `docs/decisions/DR-0001-concept.md` — Superseded (旧: symlink 安定化構想)
- `docs/decisions/DR-0003-secure-kv-core-and-adapters.md` — 新構想確定
- `docs/decisions/DR-0004-authsock-warden-succession.md` — authsock-warden 後継
- `docs/decisions/DR-0007-mlock-memory-pinning.md` — mlock/zeroize 順序
- `docs/decisions/DR-0008-single-daemon-hosting.md` — ホスティング戦略確定
- `docs/decisions/DR-0009-control-socket-protocol-v1.md` — control socket
- `docs/decisions/DR-0010-config-and-reauth-command.md` — config + 再認証
