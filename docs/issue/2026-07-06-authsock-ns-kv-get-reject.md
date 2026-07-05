---
title: authsock NS の kv.get を wire/CLI で拒否する (DR-0018 §4.5 confidentiality 軸)
status: open
category: task
created: 2026-07-06T07:52:08+09:00
last_read:
open_entered: 2026-07-06T07:52:08+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: issue 2026-06-14-internal-key-forget-interface close 時の残タスク切り出し
---

# authsock NS の kv.get を wire/CLI で拒否する (DR-0018 §4.5 confidentiality 軸)

## 概要

DR-0027 で `authsock` NS への **書込** (`kv.set` / `kv.define`) は wire + CLI の
bouncer で拒否済み。**読出** (`kv.get`) の拒否は confidentiality 軸の別判断として
射程外に切り出した (= 本 issue)。

authsock 内部鍵 (`authsock/op_<item_id>` = op 秘密鍵 PEM) は control socket 経由の
`kv.get` で読める状態を残すべきでない。SIGN はアダプタ内で完結し、PEM を wire に
出す正当な経路は無い。

## 論点

- 単純な NS ベース拒否で足りるか、DR-0024 cap の L1.5 (scoped cap) に寄せるか
- [2026-06-22-kv-get-peer-identity-guard](./2026-06-22-kv-get-peer-identity-guard.md)
  (blocked、peer-identity constraint) と関係あり。あちらは汎用の宣言的 guard、
  こちらは予約 NS の一律拒否で、先行実装可能

## 受け入れ条件

- [ ] wire (`Request::KvGet` 系) で `authsock/` prefix キーの get を拒否
- [ ] CLI 入口でも同様 (親切な前段)
- [ ] テスト: 拒否 response の輪郭 (存在秘匿にするか error 明示にするか は設計判断)

## 関連

- DR-0027 (書込側 bouncer)
- DR-0018 §4.5 (authsock NS 正規化)
- DR-0024 (cap gate、L1.5 拡張余地)
