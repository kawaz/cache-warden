---
title: CLI で backoff 中 key を可視化する (cli-display-backoff-until)
status: open
category: request
created: 2026-06-22T20:28:59+09:00
last_read:
open_entered: 2026-06-22T20:28:59+09:00
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

# CLI で backoff 中 key を可視化する

## 概要

control socket protocol の status / kv list 応答に `backoff_until: Option<seconds>` フィールドを追加し、`cache-warden status` / `cache-warden kv list` CLI の出力に backoff 中の key を可視化する。

## 背景

DR-0022 (fetch failure backoff) の Implementation Notes §3 (可観測性) で範囲に含まれた CLI 拡張の未実装分。コア機能 (A-3b = `Store::failure_backoffs` の backoff 抑止) は v0.22.1 で動作確認済み (`docs/journal/2026-06-22-op-refetch-loop-live-diagnosis.md`)。残るのは CLI 表示。

現状、`cache-warden status` の出力は entries 一覧のみ:

```
daemon: cache-warden 0.22.1 (pid NNNN)
socket: /Users/kawaz/.local/state/cache-warden/control.sock
entries: (none)
```

backoff 中の key があっても CLI からは見えない。op fetch が失敗して backoff active 状態か、単に未 load か区別できない。

## 受け入れ条件

- [ ] control socket protocol (DR-0009) の status / kv list 応答に `backoff_until: Option<seconds>` フィールドが追加されている
- [ ] `cache-warden status` の出力に backoff 残時間が表示される (例: `backoff_until: 3s`)
- [ ] `cache-warden kv list` の出力でも同様に backoff 中の key を識別できる
- [ ] stderr ログに `fetch failed (backoff active until <t>)` が追記される (DR-0022 §3 記述分)

## TODO

<!-- wip 時のみ -->

- [ ] protocol 拡張設計 (DR-0009 との整合確認)
- [ ] `Store::failure_backoffs` → 応答フィールドへのマッピング実装
- [ ] CLI 出力フォーマット実装
- [ ] stderr ログ追記実装
- [ ] テスト追加

## 関連

- DR-0022 fetch failure backoff (本 issue の親)
- DR-0009 control socket protocol (= protocol 拡張対象)
- `docs/journal/2026-06-22-op-refetch-loop-live-diagnosis.md` (= コア機能の検証結果)
- `docs/issue/2026-06-14-op-refetch-loop.md` (= 元 issue、CLI 表示を残して pending-sublimation 候補)
