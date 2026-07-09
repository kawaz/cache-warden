---
title: graceful restart Phase 3: listener fd 継承で断ゼロ化 (任意)
status: idea
category: design
created: 2026-07-09T23:44:04+09:00
last_read:
open_entered:
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:    # 1-line JSON array string[] 例: ["discarded","環境が変わった"]
pending_reason:    # 1-line JSON array string[] 例: ["pending","v2 待ち"]
close_reason:      # close 時に update が記録。1-line JSON array string[] 例: ["dr/DR-0007","implemented"]
blocked_by:
origin: DR-0029 Phase 1 完了に伴う後続作業
---

# graceful restart Phase 3: listener fd 継承で断ゼロ化 (任意)

## 背景

DR-0029 Phase 1 の MVP は「fork 前に listener を close + socket path を unlink → 新プロセスが即 rebind」の re-bind 方式。全クライアントが per-request 接続 (ssh-agent / control / upstream) なので数百 ms の断は実用上無害と判断。

Phase 3 として断ゼロ化 (SCM_RIGHTS で listener fd を holder → 新プロセスへ継承) を検討する。

## トリガ (着手条件)

- 「re-bind 経路の数百 ms 断が実運用で問題」の観測が出たら着手
- 例: long-poll する control socket クライアントが増えた / 頻繁な graceful restart で ssh operation が失敗する頻度が上がった
- 現状 (v0.24.0 + Phase 1) で断が問題にならなければ着手しない (YAGNI)

## 実装スケッチ

- socketpair の env 通知 (`CACHE_WARDEN_HANDOFF_FD`) と同じ経路で listener fd 番号を通知
- fork 前に listener の CLOEXEC を外す → holder が listener fd も継承 → COMMIT 直前に SCM_RIGHTS で新プロセスへ受け渡し
- 新プロセス側は listener bind を skip して継承 fd を使う
- unlink は execve 前でなく、handoff 失敗時のみ実施 (fail-safe 経路)

## 変更範囲 (見積)

- graceful_restart.rs / handoff.rs / receive.rs / server.rs (bind_control_socket の分岐)
- wire format は変えない (fd 番号は env 経由なので format_version 不変で追加可能)

## 前提

- DR-0029 Phase 1 完了 (Phase 2 と独立、並行可)

## 優先度

低 (現状のクライアント形態では体感差ゼロ)
