---
title: kv get の承認拒否エラーで cancel と timeout を区別して返す
status: resolved
category: task
created: 2026-08-12T00:21:39+09:00
last_read: 2026-08-12T13:23:08+09:00
open_entered: 2026-08-12T00:21:39+09:00
wip_entered: 2026-08-12T13:22:25+09:00
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-08-12T13:31:58+09:00
discard_reason:
pending_reason:
close_reason: ["implemented (commit 4703a7ae)","kv get 経路で cancelled/timed out を区別、他 outcome は approval was not granted に丸め (DR-0030 §7 適用)","正確な outcome は daemon ログに保持","SSH agent 経路対象外を draft-DR-0031 に追記","経緯注記: issue 起票時の「全 outcome が AuthFailed に丸められている」は実態と逆で実装は全5 outcome を区別開示済みだった。本変更は裁定意図に合わせ開示を2区分へ絞る修正"]
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

- [x] kv get (control socket) 経路のクライアント向けエラー文言が cancelled
      と timed out を区別する
- [x] DR-0030 §7 (setter identity 非開示) を侵害しない
- [x] SSH agent (SIGN) 経路は対象外であることが明記されている
