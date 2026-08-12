---
title: cargo test 実行中に実環境の ~/.ssh/agent-*.sock.cw へ bind 試行が走る (テスト隔離不足)
status: open
category: bug
created: 2026-07-13T07:58:55+09:00
last_read: 2026-08-12T13:47:46+09:00
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
本来のスコープ外の副次観測として見つかった。テストが実 config
(`~/.config/cache-warden/config.toml` の `[authsock.sockets.*]` path) を
読んでいる、またはデフォルト socket パス解決が `$HOME` 直下の実パスに
フォールバックしている、のいずれかが原因候補 (未裏取り)。

対処方針:

1. まず bind 試行元のテストを特定する (bind ログを出すテスト名の特定、
   または実パスを参照する経路の grep)
2. テストは tempdir 配下の socket パスのみを使うよう隔離する ($HOME 由来の
   パス解決をテストで注入可能にする)
3. 隔離後、`cargo test --workspace` 実行中に実環境パスへの bind 試行が
   0 件であることを確認する

実害は稼働中 daemon の排他で fail するため未発生だが、daemon 停止中に
テストを走らせると実 socket を乗っ取る / 消す可能性があり、テスト隔離の
原則 (`.claude/rules/ssh-agent-socket-test-isolation.md`) にも反する。

## 受け入れ条件

- [ ] `cargo test --workspace` 実行時に実環境の `~/.ssh/agent-*.sock.cw` への
      bind 試行が発生しない (= テスト専用の tmp dir 等に隔離される) ことを
      ログ上で確認する
- [ ] bind 試行の発生源 (実 config 読み込み経路 or デフォルトパス解決) を特定する

## TODO

<!-- wip 時のみ -->
