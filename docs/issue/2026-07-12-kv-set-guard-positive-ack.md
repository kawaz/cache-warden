---
title: kv set の guard positive ack (guard_applied) — mixed-version silent no-op 対策
status: open
category: task
created: 2026-07-12T04:40:02+09:00
last_read:
open_entered: 2026-07-12T04:40:02+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO (draft-DR-0030 Block 2 セキュリティレビュー)
---

# kv set の guard positive ack (guard_applied) — mixed-version silent no-op 対策

## 概要

DR-0030 guard (peer-identity constraint) の `kv set` プロトコルに **positive
ack フィールド** (例: `guard_applied: bool`) を追加する。新 CLI (guard flags
対応) が guard 宣言を送ったにもかかわらず応答に ack が無い場合、CLI 側は
これをエラー扱いにする (= silence を enforcement と解釈しない設計)。

## 背景

Block 2 レビュー (HIGH-1) で、新 CLI (guard flags 対応) + 旧 daemon (guard
未対応) の組合せでは、daemon 側 serde が unknown field (`guard_constraints`
相当) を黙って無視し、ユーザが「guard 束縛済み」と誤信したまま無防備な
entry が作られてしまうと指摘された。

cache-warden の dogfood 構成 (notarized app daemon + dev build CLI) は、
まさにこの mixed-version 状態が常態化しやすい構成。daemon 側の即時
fail-closed 分岐 (HIGH-1 対応、unknown field 拒否等) は **同一 build 内でのみ
有効**であり、旧 daemon (= その分岐自体を持たないバイナリ) には効かない。

そのため、プロトコルレベルで「guard が実際に適用されたか」を新 CLI 側が
検証できる positive ack 機構が必要。

## 受け入れ条件

- [ ] `kv set` の daemon 応答に `guard_applied` (または同等の positive ack)
      フィールドが追加されている
- [ ] 新 CLI は guard 宣言 (guard flags) を伴う `kv set` 送信時、応答に ack
      が無ければエラーとして扱い、ユーザに「guard 未適用」を明示する
- [ ] 旧 daemon 相手の mixed-version シナリオで、上記エラーが実際に発火する
      ことを確認 (= 旧バイナリ相当のモックまたは実バイナリで検証)

## 関連

- draft-DR-0030 (peer-identity guard 本体設計)
- Block 2 セキュリティレビュー (2026-07-12) HIGH-1
- 関連 issue: `docs/issue/2026-06-22-kv-get-peer-identity-guard.md` (同根の
  guard 機構、wip)
