---
title: authsock SIGN 経路の guard 通過後 dialog を出すかの裁定
status: open
category: design
created: 2026-07-12T17:55:10+09:00
last_read:
open_entered: 2026-07-12T17:55:10+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# authsock SIGN 経路の guard 通過後 dialog を出すかの裁定

## 概要

authsock (ssh-agent 中継) の SIGN_REQUEST 経路で、`kv-get-peer-identity-guard`
(2026-06-22-kv-get-peer-identity-guard.md) 相当の **guard を通過した後**に、
`custom-touchid-dialog` (2026-06-22-custom-touchid-dialog.md) のような **確認
dialog をさらに出すべきか** の裁定が必要。

## 背景

guard (peer-identity constraint) が通れば要求元プロセスは既に許可条件を
満たしている。ここでさらに dialog を出すと:

- 毎回の SIGN 操作 (git push / ssh 等) で UI 介入が入り体験が悪化する
- 一方で dialog を省略すると、guard 設定の誤りや想定外プロセスからの
  SIGN_REQUEST を可視化する機会を失う

guard 設計 (2026-06-22-kv-get-peer-identity-guard.md) と custom TouchID dialog
設計 (2026-06-22-custom-touchid-dialog.md) の両方に関わる横断論点であり、
どちらの issue にも属さないため個別に起票する。

kawaz からの入力: 「authsock SIGN 経路の guard 通過後 dialog を出すかの裁定」
という指示のみを受け取った (詳細な裁定内容・理由付けは未着 — 続報待ち)。

## 受け入れ条件

- [ ] guard 通過後の dialog 要否について kawaz の裁定を反映する
- [ ] 裁定結果を関連 issue (kv-get-peer-identity-guard / custom-touchid-dialog) に反映する

## TODO

- [ ] kawaz に裁定の詳細 (出す/出さない、条件分岐の有無) を確認する
