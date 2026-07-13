---
title: top-level --socket が実際にはサブコマンド後にしか置けない (doc/impl 乖離)
status: open
category: bug
created: 2026-07-13T17:54:24+09:00
last_read:
open_entered: 2026-07-13T17:54:24+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: Block 3b e2e 検証中の kawaz 指摘 (2026-07-13)
---

# top-level --socket が実際にはサブコマンド後にしか置けない (doc/impl 乖離)

## 概要

top-level `--socket` オプションは doc コメント上「tail のどこに置いても良い」
とされているが、実装では command dispatch (`args[0]` を command として先に
取り出す処理) が `take_socket_flag` の呼び出しより先に走るため、
`cache-warden --socket PATH kv get FOO` のようにサブコマンドより前に置くと
`unknown command: --socket` で reject される。

## 背景

2026-07-13 Block 3b の e2e 検証中に kawaz が発見。

- `crates/cache-warden-cli/src/commands/mod.rs:160-192` の `take_socket_flag`
  doc コメントは「Extract `--socket PATH` ... anywhere in the tail」を明言
- `crates/cache-warden-cli/src/main.rs:301` 付近のコメントも
  「Resolve `--socket` (anywhere in the tail) once」と書いている

しかし実装は `main.rs:279-280` で

```rust
let command = args[0].clone();
let tail = &args[1..];
```

のように `args[0]` を command として先に取り出しており、`take_socket_flag`
の呼び出し (main.rs:301 付近) はその後にしか来ない。このため `--socket` が
`args[0]` の位置にあると command 名として誤解釈され、command dispatch で
reject される。(2026-07-13 実機コード確認済み: 上記行番号・実装とも現状一致)

実運用上のワークアラウンド (現状動く形): `cache-warden kv --socket PATH get FOO`
のように、サブコマンドの直後に置けば `take_socket_flag` が正しく拾う。

関連: DR-0010 (socket 解決の優先順位: CLI `--socket` > config `[daemon].socket`
> built-in default)。本 issue は優先順位そのものではなく、CLI 上で
`--socket` を置ける位置が doc と実装で乖離している点が対象。

## 受け入れ条件

- [ ] 修正方針を (a) か (b) のいずれかで決定する
  - (a) `main.rs` の command dispatch より前に `--socket` を tail 全体から
        (位置に関わらず) strip する — グローバル option を先頭に置ける方が
        慣習的で `take_socket_flag` の doc 記述とも一致するため、UX 上はこちらが正解
  - (b) doc / help 文言を実装に合わせ「サブコマンドの後にのみ置ける」と訂正する
- [ ] `cache-warden --socket PATH kv get FOO` (先頭指定) と
      `cache-warden kv --socket PATH get FOO` (サブコマンド後指定) が
      同一に動作する (または doc 通りサブコマンド後のみ動作する) ことを確認
- [ ] `take_socket_flag` の doc コメントと `main.rs` 側のコメントが実装と
      一致していることを確認

## TODO

<!-- wip 時のみ -->
