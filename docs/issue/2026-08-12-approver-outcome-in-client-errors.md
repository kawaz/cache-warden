---
title: kv get の承認拒否エラーで cancel と timeout を区別して返す
status: wip
category: task
created: 2026-08-12T00:21:39+09:00
last_read: 2026-08-12T13:23:08+09:00
open_entered: 2026-08-12T00:21:39+09:00
wip_entered: 2026-08-12T13:22:25+09:00
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

# kv get の承認拒否エラーで cancel と timeout を区別して返す

## 概要

kv get の承認拒否エラーで cancel と timeout を区別して返す (kawaz 裁定
2026-08-12)。現在は DR-0031 の意図的な丸めで Cancelled/Timeout/PeerGone/
BiometricFailed が全て AuthFailed に丸められ、requester は区別できない。
kv get (control socket) 経路のクライアント向けエラーは cancelled と timed
out を区別した文言にする。

## 背景

kawaz 裁定: 「ユーザによる明確な拒否か timeout かは agent (requester) 側に
とっても重要な違い」— 明確な拒否 = 再要求すべきでない / timeout = ユーザが
見ていなかっただけで再要求してよい、と次の行動が変わるため。

設計注意:

1. DR-0030 §7 の「setter identity を返さない」規定は維持する。漏れるのは
   「能動拒否 vs 放置」の情報のみで setter 情報ではない。
2. SSH agent 経路 (SIGN) は wire に error 詳細フィールドが無い
   (SSH_AGENT_FAILURE = 空 payload) ため構造的に不可。daemon stderr ログ
   での区別 (approval cancelled / approval timed out) は硬化版で実装済み。
3. cancel と window close は同一 outcome (Cancelled) のまま。
4. BiometricFailed / PeerGone / guard 拒否を丸めたままにするかは実装時に
   判断する (安全側 = 丸めたまま)。

関連: docs/issue/2026-07-12-approver-release-hardening.md、
draft-DR-0031 の outcome 丸め規定。

## 受け入れ条件

- [ ] kv get (control socket) 経路のクライアント向けエラー文言が cancelled
      と timed out を区別する
- [ ] DR-0030 §7 (setter identity 非開示) を侵害しない
- [ ] SSH agent (SIGN) 経路は対象外であることが明記されている
