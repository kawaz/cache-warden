---
title: open issue 13 件の triage 棚卸し (外部監査フラグ)
status: idea
category: task
created: 2026-07-03T13:46:24+09:00
last_read:
open_entered:
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: claude-rules-personal
---

# open issue 13 件の triage 棚卸し (外部監査フラグ)

## 概要

`docs/issue/` 配下の open 状態 issue 数が 13 件に達している。放置日数順に
棚卸しし、各 issue を close / 継続 / 統合のいずれにするか判断することを提案する。

## 背景

kawaz の個人リポ群を横断監査したところ、cache-warden の open issue 数 (13 件)
は監査対象リポの中で hyoui (21 件) に次いで多かった。個々の issue の価値判断は
本リポ (cache-warden) 担当側に委ねる。

これは部外者 (claude-rules-personal セッション) からの観測に基づくフラグであり、
実際の内容・放置理由は裏取りできていない。triage の要否・優先度は担当側で確認の
上で判断してほしい。

出所: 2026-07-03 の個人エコシステム横断監査 (claude-rules-personal セッション発) より。

## 受け入れ条件

- [ ] 現行 open issue 13 件を放置日数順に一覧化する (`/local-issue:list` 等)
- [ ] 各 issue を close (resolved/discarded) / 継続 (wip 昇格等) / 統合 のいずれかに判断する
- [ ] 判断結果を各 issue の status 遷移 (`/local-issue:update`) に反映する
