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

## 実装結果 (2026-07-06)

書込側 bouncer と対称の **単純 NS ベース read 拒否**を wire + CLI に追加した
(L1.5 scoped cap への一般化はしない、確定方針どおり)。

### 変更ファイル

- `crates/cache-warden-cli/src/daemon/handler.rs`
  - `reject_reserved_namespace_read(key)` を追加 (書込側 `reject_reserved_namespace_write`
    と対称)。`handle_get` の**先頭** (process-access gate / retrieval chain より前) で
    呼び、予約 NS のキーは source を一切走らせずに拒否 (op 秘密鍵 fetch も PEM 生成も
    起きない)。
  - 書込側は `split_composed` を使うが、read 側は生の `split_once('/')` で NS 判定する。
    `kv.get` には `validate_protocol_key` の前段ゲートが無く、任意のキーが来るため
    「KEY セグメントが不正な識別子でも NS だけで確実に捕捉する」ため。
  - テスト 5 件追加 (wire get 拒否 + 値非露出 / retrieval chain 未起動 (runner 実行回数 0) /
    非予約 NS の get 不変 / del は rotation 軸で許可 / list はキー名を出し続ける = 挙動不変)。
    `err_msg` ヘルパも追加。
- `crates/cache-warden-cli/src/commands/mod.rs`
  - `reject_reserved_read_namespace(ns)` を追加、`parse_kv_single_key` の `"get"` 経路
    でのみ呼ぶ (`unpin` は値非露出のライフサイクル動詞なので不発火)。
  - 既存 `reject_reserved_write_namespace` の doc コメントを更新 (get は別ゲート、
    del/pin/unpin は非ゲート = del は rotation 用途で許可、を明記)。
  - テスト 4 件追加 (CLI get 拒否 / 通常 NS の get 不変 / del は許可 / unpin 非ゲート)。

### 設計判断

- **拒否 response の輪郭**: 書込側の先例 (明示 `BadRequest` + 予約名を明記) に合わせ、
  存在秘匿ではなく**明示 error** で統一 (interface 一貫性優先)。read 側メッセージは
  `namespace "authsock" is reserved and cannot be read (DR-0018)` (書込側は `... written to`)。
- **値が漏れる経路だけ塞ぐ**: 値を返すのは `kv.get` のみ。`del` は availability/rotation
  軸で許可 (既存確定方針)、`list`/`status` はキー名 + value-free メタのみで値非露出のため
  対象外。`unpin`/`pin` も値非露出なので非ゲート。この非対称 (get/set/define 拒否、
  del/pin/unpin/list 許可) をテストで固定した。

### 検証

- `just check` (fmt + clippy `-D warnings`): pass。
- `just test` (workspace 全体): 全 pass、0 failed (予約 NS 関連の新規 9 件含む)。
