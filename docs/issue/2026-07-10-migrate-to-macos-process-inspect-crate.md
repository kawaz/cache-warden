---
title: 既存 process inspect 実装の macos-process-inspect crate への移行 (重複解消)
status: open
category: design
created: 2026-07-10T02:49:13+09:00
last_read:
open_entered: 2026-07-10T02:49:13+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by: crate-macos-process-inspect
origin: 自リポ TODO
---

# 既存 process inspect 実装の macos-process-inspect crate への移行 (重複解消)

## 概要

cache-warden 内に既存する macOS process inspect 実装 (`crates/cache-warden/src/process.rs` の
`mod macos` および `crates/cache-warden-cli/src/daemon/peer.rs` の `peer_pid`) を、新設した
`macos-process-inspect` crate の呼び出しに置き換え、`proc_pidinfo` / `proc_pidpath` /
`getsockopt(LOCAL_PEERPID)` 系 FFI の重複実装を解消する。

## 背景

macos-process-inspect crate 新設 (issue: crate-macos-process-inspect) では、将来の別 repo 化のため
cache-warden 非依存の自己完結 crate として純増追加した。その結果、同種の macOS FFI が既存実装と重複している:

- `crates/cache-warden/src/process.rs` の `mod macos` (`SystemInspector` の macOS backend)
- `crates/cache-warden-cli/src/daemon/peer.rs` (`peer_pid`)

### 移行方針の調査済み事実 (2026-07-10 consumer-map 調査)

- `ProcessInspector` trait はシーム化済み、`ProcessInfo` は OS 非依存プレーン型
- authsock crate は `ProcessInfo` (データ型) のみ依存、inspector 実行には無関係
- 触る箇所は機械的・局所的: core `lib.rs` の re-export 1 行 + import 4 ファイル
  (`server.rs` / `authsock.rs` / `e2e.rs` / `authsock_e2e.rs`) + daemon 構築 2 点
  (`server.rs:1151` / `authsock.rs:1074,1258` 付近)

### 検討中の案

- **案 1**: core の `SystemInspector` macOS backend を macos-process-inspect 呼び出しに差し替え
  (core が新 crate に依存)。Linux backend は core に残る
- **案 2**: cli 層で core trait を impl する adapter を新設し、core からは OS backend を全撤去
  (core が最も generic になるが変更量が増える)

コアの generic 性 (プロジェクト memory: feedback-domain-types-in-adapters-not-core) の観点では
案 2 が筋が良いが、Linux backend の置き場所 (新 crate は macOS 専用) の設計判断が必要。
kawaz と相談してから着手する。

## 受け入れ条件

- [ ] 案 1 / 案 2 (またはその他) の設計判断を kawaz と確定する
- [ ] `crates/cache-warden/src/process.rs` の `mod macos` を撤去し macos-process-inspect 呼び出しに置換
- [ ] `crates/cache-warden-cli/src/daemon/peer.rs` の `peer_pid` を macos-process-inspect 呼び出しに置換
- [ ] 既存テスト (e2e 含む) が置換後も通ることを確認

## TODO

<!-- wip 時のみ -->
