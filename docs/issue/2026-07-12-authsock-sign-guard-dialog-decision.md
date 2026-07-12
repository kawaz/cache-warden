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

Block 3a (approver dialog 発火配線) のレビュー MEDIUM-4 指摘 (2026-07-12) で
非対称が判明した:

- **kv get 経路**: guard 付き entry は guard 通過後に **常に cache-warden dialog
  (人間承認)** を挟む
- **authsock SIGN 経路**: guard の機械評価のみで、guard 通過後の dialog は
  出ない

この非対称の結果、**同一 shell subtree のプロセスは、guarded な秘密鍵 KV key
を SIGN_REQUEST 経由で人間承認ゼロのまま消費 (署名) できる**。authsock.rs
自身のコメントが「署名は kv.get と同じく秘密鍵の消費である」と論証しており、
その論理を辿ると dialog の要否についても kv get と同じ扱いに延伸するはずだが、
現状はそうなっていない。

DR-0031 §8 は「entry に guard がある → 常に dialog」と規定するが、これは
kv get 経路を前提にした記述で SIGN 経路への適用は明記されていない。DR-0030
§4 の SIGN 裁定 (2026-07-12) は gate (guard 機械評価) のみを規定し、dialog
の要否には無言。つまり **SIGN 経路の dialog 要否は未裁定領域**。

## 裁定候補

- **(a) SIGN 経路でも guard 通過後に dialog を出す**: kv get との対称性は
  取れるが、SSH client 側の応答待ち timeout (数秒で諦める実装が多い) との
  整合が課題。`ssh-agent` の confirm (`ssh-add -c`) が抱える UX 問題と同種
- **(b) v1 は「SIGN は機械 gate のみ、dialog なし」と明記**: DR-0031 §8 に
  「SIGN 経路は既知の非対称として dialog 対象外」を追記して確定させる
- **(c) 折衷**: config で socket 単位の opt-in (dialog を出す socket / 出さ
  ない socket を選べる)

kawaz 裁定待ち。

## 受け入れ条件

- [ ] guard 通過後の dialog 要否について kawaz の裁定を反映する
- [ ] 裁定結果を関連 DR (draft-DR-0031 §8 / draft-DR-0030 §4) に反映する

## 関連

- draft-DR-0031 §8
- draft-DR-0030 §4 (2026-07-12 SIGN 裁定)
- Block 3a レビュー MEDIUM-4 指摘
