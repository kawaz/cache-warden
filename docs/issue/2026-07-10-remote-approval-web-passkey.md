---
title: リモート承認 (Tailscale 直達 + WebAuthn passkey)
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

# リモート承認 (Tailscale 直達 + WebAuthn passkey)

## 概要

daemon が tailnet 内 HTTPS (tailscale cert) で承認ページ + API を自前配信し、
daemon 自身が WebAuthn RP として assertion を検証する。gate は tailnet 到達性 +
passkey の 2 段 (URL 自体は secret ではない)。通知は iMessage を主経路とし、
プラガブルに他経路も追加可能。

## 背景

kawaz 原案 (2026-07-10)。ローカル TouchID (draft-DR-0031) とは相補構成
(どちらかを選ぶのではない。例: passkey 登録時はローカル TouchID 必須)。

方式は kawaz 裁定 (2026-07-10) で「Tailscale 直達」に確定した。当初の
静的ページ + WebRTC DataChannel + 極小シグナリング案は codex アーキレビューの
対称評価で実装・攻撃面ともに劣後し不採用 (経緯と比較は draft-DR-0032 の
Alternatives 節が正本)。

設計 draft は `docs/decisions/draft-DR-0032-remote-approval-web-passkey.md`、
調査は `docs/research/2026-07-10-remote-approval-signaling.md` と
`docs/research/2026-07-10-serverless-webauthn-rp.md`。

## 残作業

- [ ] Tailscale 固有詳細 (cert / RP ID 安定性 / ACL / iOS) の recon 反映
- [ ] accept 判断
- [ ] PoC: tailscale cert + daemon 内蔵 HTTPS + iPhone 実機 WebAuthn 疎通
      (仮 RP ID、本番登録は作らない)

## Blocker

- Linux 対応は登録セレモニー担保 (DR-0032 Q4) が Blocker

## TODO

- [ ] Tailscale 固有 recon の反映 → accept 判断 → PoC (次アクション)
