# Phase 1.6 Block 3a: guard 通過後の approver dialog 発火配線

draft-DR-0031 §8 v1 の第 1 発火条件 (guard 付き entry の reveal-`kv.get` のみ) を
land (commit `3d63234e`)。DR-0030 の guard 評価器 (Block 2) と Block 1 で常駐化
した helper (`ApproverClient`) を、実際に「guard を通ったら dialog を出す」経路で
つなぐブロック。

## ワークフロー構成

opus47-worker で実装 → sonnet5-worker-low で機能検証 + Fable (メインセッションの
tier) でセキュリティレビューを並列実行 → 指摘をメインセッションで修正 → 修正後に
`cargo test --workspace` を 2 回連続実行して green が一致することを確認。Block 2
と同じ「本気の意味論レビューは最上位 tier、機械的な検証は中位 tier」分担。

## ハマり所 → 解決策

### (1) shutdown 中の recovery captive (`closed` latch で封鎖)

`ApproverClient::request` は pending な approval を `helper_pid` への
`SIGKILL` (Block 1 の H-1 修正) で解けるが、Block 3a の常駐 helper 経路では
別角度の captive が残っていた: shutdown が SIGKILL を送った直後、pending
request の read が EOF で落ちると recovery 経路が「helper が死んだ、再接続
しよう」と解釈して **新しい helper を spawn し直し、新しい dialog を画面に
出してしまう**。これは §10 の「helper は daemon exec 前に死ぬ」契約を裏切り、
graceful restart を「ユーザが頼んでもいない新規 dialog」に captive させる。

**解決**: `ApproverClient` に `closed: AtomicBool` latch を追加。`shutdown` は
SIGKILL を送る**前に** latch を store し、`request` は (a) exchange 開始前、
(b) recovery (respawn) 直前、の 2 箇所で latch をチェックして即座に
`ConnectionAborted` を返す。一度立てたら二度と下ろさない (client は
terminally shut down)。テストは `shutdown_during_pending_request_does_not_respawn_and_returns`
で pin: fake helper がリクエスト行を読んでから park し、`shutdown` を並行発火、
fake helper タスクを abort して EOF を模擬する構成 (`sleep` なし、oneshot
channel でランデブー)。

### (2) `Notify::notify_waiters` の missed-notification 定石

`ApproverSlot::wait_ready` は `Starting` → `Ready`/`Down` の遷移を
`tokio::sync::Notify` で待つ。素朴に「state を見て None なら `notified().await`」
と書くと、state チェックと `notified()` 呼び出しの間に `set_ready` /
`set_down` が `notify_waiters()` を発火した場合、その通知は **誰も subscribe
していない状態で発火して消える** (`notify_waiters` は「今 waiting 中のタスク」
にしか届かず、後から `notified()` を呼んでも過去の notify は拾えない)。この
race を踏むと `wait_ready` は本来即座に返せるはずの `Ready` 遷移を見逃し、
bounded wait の timeout いっぱいまで待ってから `Down` 相当に丸めてしまう。

**解決**: 定石通り「`notified()` を先に生成 + `enable()` してから state を
チェックする」順序に固定。timeout 直前・timeout 到達時にも state を再チェック
してから `None` を返す (デッドライン直前に着地した `set_ready` を取りこぼさ
ないため)。

### (3) helper path の sibling fallback は採用しない (ad-hoc 署名 dev helper の罠)

helper バイナリの解決順は `$CACHE_WARDEN_APPROVER_BIN` (dev) →
`/Applications/CacheWarden.app` 内 (production) の 2 段のみにした。当初
「production パスに無ければ実行ファイルと同じディレクトリの sibling を探す」
fallback も検討したが、dev ビルドの ad-hoc 署名 helper が `verify_peer`
(§Security の signing identity 相互検証) を通らずに **peer 検証で弾かれ、
5 秒の `helper_starting` bounded wait を消費した末に `Down` として死体化する**
だけの経路になることに気付いて不採用にした。dev 環境で helper を試すには
`just approver-run` 相当で実 identity 署名を通す運用に寄せる方が、sibling
fallback を生やして「動いているように見えて実は毎回 5 秒溶かして落ちている」
状態を作るより安全。

## 設定値・コマンド

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace   # 1959 tests, 2 回連続実行して green 一致 (flaky なし)
```

helper path 解決順 (production は上から順に採用、fallback なし):

1. `$CACHE_WARDEN_APPROVER_BIN` (dev 用の明示上書き)
2. `/Applications/CacheWarden.app` 配下の nested helper (production)

## 議論の要点

- **§10 の厳密起動順序からの意図的な妥協**: draft §10 は「helper spawn →
  HELLO 受領 → control socket 開始」を厳密シーケンスとして規定していたが、
  実装は「control socket を早期 bind + helper spawn は非同期 + `Starting`
  窓は guarded get 側の bounded wait (5s) で吸収」という形にした。DR-0023
  (daemon preload 中の ping 応答性) を優先した結果で、draft 本文とは異なる
  実装判断。draft 側の記述をこの実装に合わせて更新するか、起動シーケンスを
  厳密化し直すかは Block 3b 以降で再検討する
- **dry_run は gated path に入れない判断**: §8 本文は dry-run 分岐を明文化
  していないが、値を返さない dry-run に dialog を出しても承認対象が観測
  不能で無意味と判断し、`run_request_async` の分岐で dry-run を gated path
  から除外した。ドキュメントコメントで明示 + 専用テストで pin
- **outcome を全て `AuthFailed` に丸める判断**: `Denied` / `Cancelled` /
  `Timeout` / `PeerGone` / `BiometricFailed` を区別して requester に返す設計
  も検討したが、DR-0030 §7 の「拒否理由の詳細を返さない」原則と揃え、
  `Approved` 以外は一律 `AuthFailed` にした

## 未検証事項・持ち越し

- 実機 TouchID e2e (Cancel / Approved / dialog wedge の体感確認) は Block 3b
- prompt-bombing / dialog wedge の根治 (helper 側 countdown、キュー深さ上限) は
  issue `2026-07-12-approver-release-hardening` 項目 5/6
- authsock SIGN への guard/dialog 統合方針は issue
  `2026-07-12-authsock-sign-guard-dialog-decision` で kawaz 裁定待ち

## 検証

`cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` /
`cargo test --workspace` すべて green、1959 tests passed を 2 回連続実行して
一致 (flaky なし)。実機 TouchID e2e は Block 3b に持ち越し。
