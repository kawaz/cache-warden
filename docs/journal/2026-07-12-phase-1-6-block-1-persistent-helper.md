# Phase 1.6 Block 1: helper 常駐化

draft-DR-0031 §3 採用案 (b) の**常駐 helper**を land。opus47 worker で実装、
opus47-high でセキュリティレビューを並列実行し、レビュー指摘 (CRITICAL 1 + HIGH 2)
をメインセッションで修正してから land。

## 実装の輪郭

- daemon 側 `ApproverClient`: 1 本の検証済み接続の上で N 個の
  ApproveRequest/Response を JSON Lines で直列に流す
- helper 側: background reader thread が 1 行 read → `dispatch_main` で main queue
  に投入 → dialog 表示 → outcome 送信で mpsc channel を鳴らして次の read
- Cancel button / Cmd+W / close button は Rust 側 delegate class
  (`ApproverDelegate`、objc2 `define_class!`) で処理

## ハマり所 → 解決策 (レビュー起点)

### C-1: delegate lifetime (CRITICAL、実機で必ず露呈)

`NSWindow.setDelegate` と `NSButton.buttonWithTitle_target_action` の target は
どちらも **unretained**。`show_dialog_on_main` のローカル `delegate` が return で
drop されると Cancel / windowWillClose が nil 宛て msgSend で silent no-op になる
(Objective-C の慣例)。TouchID 経路 (LA block 発火) だけは動くので unit test 中は
気付かない。

- **修正**: LA completion block に `Retained<ApproverDelegate>` を capture させ、
  delegate を block と同じ寿命に束縛
- Cancel/windowWillClose 経路では `LAContext::invalidate()` で LA を能動的に停止し
  block を発火させて delegate を解放 (常駐 helper なのでリーク蓄積を防ぐ)
- `DelegateIvars` に `ctx: Retained<LAContext>` を追加してこの経路を主流化

### H-1: shutdown captive (HIGH、graceful restart で人間待ちになる)

`ApproverClient::request` は §8 直列化のため request 全体で `inner: Mutex` を保持
する。素朴に `shutdown` も同じ lock を取ると、pending approval (人間の指紋操作、
最長数十秒) を待つ間 helper kill が発動しない。§10 の「daemon exec 前に helper を
kill」が破られる。

- **修正**: `ApproverClient` に `helper_pid: AtomicU32` を追加し、`shutdown` は
  `inner` を取る前に `libc::kill(pid, SIGKILL)` で helper を直接殺す
  (pending request の read/write が broken pipe で解けて lock が释放される)
- pid の更新順序: recovery 経路で dispose 前に `helper_pid.store(0)`、新 helper
  spawn 後に新 pid を store。「shutdown が新 helper を誤って kill する」race を
  塞ぐ

### H-2: helper read timeout regression (HIGH → 意味論変化として仕様化)

Phase 1.5 が `read_line` に 30 s timeout を掛けていたが、Phase 1.6 では消失。
レビュアーは regression 指摘だが、常駐化に伴う正しい挙動変更と判断:

- 常駐 helper では「approval 要求が長時間来ない」のが正常状態。30 s timeout を
  維持すると quiet period ごとに terminate してしまい、案 (b) の常駐性が消える
- 「daemon 死亡で hang しない」保証は別レバーで担保: Unix socket は対向プロセス
  死亡で kernel が close するので `read_line == 0` (EOF) で捕捉される
- **修正**: `spawn_reader_thread` の doc に「no per-read timeout on the reader
  loop」節を追加してこの意味論変化を明示

## 未検証事項 (Block 2 の実機 e2e に持ち越し)

以下は unit test で pin できず、実 helper 起動を伴う (= TouchID 発火の可能性が
ある) ため今フェーズでは検証しない:

- Cancel button / Cmd+W / close button の各経路で outcome が実際に daemon に届く
- 1 helper プロセスが N 回の approval 後もリークしない (per-request の delegate +
  LAContext + NSWindow 解放)
- graceful restart 中の `shutdown` が in-flight approval を待たない (SIGKILL 経路)
- 常駐 helper の 2 件目以降の request で focus 奪取が動く
  (`register_focus_steal_on_launch` を捨て、`show_dialog_on_main` から直接
  `steal_focus` を呼ぶ形に切り替えた影響)

Block 2 で guard/handler 統合と TouchID 実機 e2e をまとめて実施予定
(kawaz 在席時 + Opus 4.7 [1m] 切替済み)。

## 持ち越し issue

- `docs/issue/2026-07-12-approver-release-hardening.md` — LA completion block の
  main-thread 明示 dispatch、stuck live helper の bounded wait (§9 `helper_down`)、
  standalone mode の release 無効化、警告ログ規約
- 常駐化に伴う **`helper_pid` swap の pathological race** (shutdown 発火時に
  recovery 経路が動いている場合): 修正の複雑さと効果のバランスから設計簡素化を
  優先し、Block 2 以降で必要になれば `Mutex<Option<Child>>` シャドウに切り替える
  余地を残す

## 検証

`cargo fmt --check` / `clippy --workspace --all-targets -D warnings` /
`cargo test --workspace` すべて green (1165 passed / 7 ignored)。実機 e2e は
Block 2 送り。
