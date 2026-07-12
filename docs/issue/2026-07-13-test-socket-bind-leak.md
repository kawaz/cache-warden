---
title: cargo test 実行中に実環境の ~/.ssh/agent-*.sock.cw へ bind 試行が走る (テスト隔離不足)
status: open
category: bug
created: 2026-07-13T07:58:55+09:00
last_read:
open_entered: 2026-07-13T07:58:55+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: SIGN dialog 統合レビュー (2026-07-13、Fable レビュー) でのスコープ外観測
---

# cargo test 実行中に実環境の ~/.ssh/agent-*.sock.cw へ bind 試行が走る (テスト隔離不足)

## 概要

`cargo test --workspace` 実行中に、実環境の `~/.ssh/agent-kawaz.sock.cw` /
`agent-syun.sock.cw` / `agent-emerada.sock.cw` への bind 試行ログが各 25-26 回
出力される。稼働中 daemon との socket 排他により bind が fail するため実害は
まだ観測されていないが、テストが実環境の設定ファイルまたはデフォルト socket
パスを参照している疑いがあり、テスト隔離が不足している。

## 背景

2026-07-13 の SIGN dialog 統合レビュー (Fable によるレビュー) で、レビュー
本来のスコープ外の副次観測として見つかった。テストが `~/.config/cache-warden/config.toml`
の `[authsock.sockets.*]` の path をそのまま読んでいる、またはコード側の
デフォルト socket パス解決が実環境 `$HOME` 配下を向いている可能性がある
(未確認、要調査)。稼働中 daemon が該当 socket を掴んでいる環境では bind が
fail して実害が顕在化していないだけで、稼働 daemon が居ない環境やタイミング
次第では実環境の socket ファイルに影響を与えるリスクがある。

## 受け入れ条件

- [ ] `cargo test --workspace` 実行時に実環境の `~/.ssh/agent-*.sock.cw` への
      bind 試行が発生しない (= テスト専用の tmp dir 等に隔離される) ことを
      ログ上で確認する
- [ ] bind 試行の発生源 (実 config 読み込み経路 or デフォルトパス解決) を特定する

## TODO

<!-- wip 時のみ -->
