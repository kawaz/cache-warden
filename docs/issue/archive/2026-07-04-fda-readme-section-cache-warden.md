---
title: README (ja/en) に Full Disk Access 節を追加する
status: resolved
category: task
created: 2026-07-04T09:33:55+09:00
last_read:
open_entered: 2026-07-04T09:33:55+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-07-04T09:46:53+09:00
discard_reason:
pending_reason:
close_reason: ["done:README.md / README-ja.md に FDA 節追加 (commit 582bf3e053fb)"]
blocked_by:
origin: 自リポ TODO
---

# README (ja/en) に Full Disk Access 節を追加する

## 概要

README.md / README-ja.md に「macOS: Full Disk Access」節を追加する。未設定の場合は
`daemon register` 時に自動案内される旨、未許可でも動作するが毎回 TCC ダイアログが出る旨を
説明する (authsock-warden の README にある同種の節が参考になる)。

## 背景

`docs/issue/archive/2026-06-14-fda-check-flow-port.md` (2026-07-04 close) の移植計画に
あった項目のうち、FDA チェック & 誘導フロー本体 (`crates/macos-tcc/` crate、
`internal fda-check` サブコマンド、`daemon register` への統合) は実装済みと確認できたが、
README への説明追加だけ未実施だったため、close 時に本 issue へ切り出した。

## 受け入れ条件

- [x] README.md に Full Disk Access 節を追加 (英語)
- [x] README-ja.md に Full Disk Access 節を追加 (日本語、正本)
- [x] 内容: 未設定なら `daemon register` 時に自動案内される旨、未許可でも動作するが
      起動/アップグレード毎に TCC ダイアログが出る旨を明記
