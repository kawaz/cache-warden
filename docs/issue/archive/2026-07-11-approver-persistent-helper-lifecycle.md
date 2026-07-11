---
title: approver helper の常駐化 (accept ループ) + IPC 残課題の Phase 1.5 統合設計
status: resolved
category: design
created: 2026-07-11T21:24:28+09:00
last_read:
open_entered: 2026-07-11T21:24:28+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-07-12T03:19:29+09:00
discard_reason:
pending_reason:
close_reason: ["dr/DR-0031", "implemented", "journal/2026-07-12-phase-1-6-block-1-persistent-helper"]
blocked_by:
origin: 自リポ TODO
---

# approver helper の常駐化 (accept ループ) + IPC 残課題の Phase 1.5 統合設計

## 概要

draft-DR-0031 Phase 1.4 で land した `daemon/approver.rs` の `request_approval`
は「1 request = 1 bind + 1 spawn」の形になっている。DR §3 の採用案 (b) は
「daemon 起動時に 1 回 spawn した常駐 helper」(on-demand spawn の 100-300ms
起動レイテンシを却下した判断) なので、Phase 1.5 の guard/handler 統合を
書き始める前に、以下への組み替えを決める必要がある:

- listener を daemon 起動時に 1 回張る
- helper は 1 プロセス常駐
- accept ループで N request を捌く

(opus47 レビュー Medium-2 指摘)

## 背景

DR-0031 の設計判断 (b) と Phase 1.4 の実装 (1 request = 1 bind + 1 spawn) が
乖離している。Phase 1.5 で guard/handler 統合に進む前にこの乖離を解消する
設計判断が必要。

同時に扱う残課題 (opus47 レビュー由来):

1. socket file の graceful shutdown 時 cleanup
   (control.sock 側と同様に remove、レビュー Low-2)
2. 双方向 peer 認証 (LOCAL_PEERTOKEN、DR-0031 §Security)
3. daemon 側で Denied/PeerGone を受信した場合の挙動の明示テスト
   (レビュー Nit-2)
4. bind→spawn の順序が仕様であることの test pin

関連:
- `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` §Phase 1.4 実装記録
- `docs/issue/2026-06-22-custom-touchid-dialog.md`

## 受け入れ条件

- [ ] 常駐 helper (daemon 起動時 1 回 spawn + accept ループ) への組み替え方針が決定される
- [ ] socket file の graceful shutdown 時 cleanup が実装される
- [ ] 双方向 peer 認証 (LOCAL_PEERTOKEN) の要否・実装方針が決定される
- [ ] Denied/PeerGone 受信時の daemon 側挙動が明示テストでカバーされる
- [ ] bind→spawn 順序の test pin が追加される
