---
title: リモート承認 (静的ページ + WebRTC DataChannel + passkey)
status: idea
category: design
created: 2026-07-10T18:42:05+09:00
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
origin: 自リポ TODO
---

# リモート承認 (静的ページ + WebRTC DataChannel + passkey)

## 概要

静的アセットをデプロイした GH Pages / Cloudflare Pages 等の承認ページを
candidate 付き URL で開き、daemon と WebRTC DataChannel でピアリング、
形式化メッセージで承認対象情報を表示し passkey 認証で承認する仕組み。
Linux でも使える。

## 背景

kawaz 原案 (2026-07-10)。ローカル TouchID (draft-DR-0031) とは相補構成
(どちらかを選ぶのではない。例: passkey 登録時はローカル TouchID 必須)。

設計 draft は `docs/decisions/draft-DR-0032-remote-approval-web-passkey.md`、
調査は `docs/research/2026-07-10-remote-approval-signaling.md` と
`docs/research/2026-07-10-serverless-webauthn-rp.md`。

Open Questions (シグナリング許容度 / URL 配送経路 / RP ID ドメイン選定 /
Linux 登録セレモニー担保 / TURN / セッション lifecycle / passkey 失効運用)
は DR-0032 に集約。

## 受け入れ条件

- [ ] kawaz と DR-0032 の議論完了 (特に Q1 シグナリング許容度と Q2 URL 配送経路)
- [ ] DR-0032 が Accepted or Rejected で確定

## TODO

- [ ] kawaz と DR-0032 の議論 (次アクション)
