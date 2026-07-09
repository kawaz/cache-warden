---
title: graceful restart Phase 2: brew upgrade 完了時の自動 restart --graceful 呼び出し
status: idea
category: design
created: 2026-07-09T23:44:04+09:00
last_read: 2026-07-10T01:37:54+09:00
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

# graceful restart Phase 2: brew upgrade 完了時の自動 restart --graceful 呼び出し

## 背景

DR-0029 Phase 1 (bundle 1/2、change zlwxovoo) で `cache-warden daemon restart --graceful` は動作するが、brew upgrade 後の反映は現状:
- 手動 restart (kawaz が `cache-warden daemon restart --graceful` を叩く)、または
- launchd KeepAlive による cold start (= TouchID storm 再発)

の 2 つしかない。Phase 2 として自動化する。

## 要件

- **トリガ**: brew upgrade 完了時 (kawaz/cache-warden の release.yml on-success-release フロー内で、`brew upgrade kawaz/tap/cache-warden` 完了直後)
- **判定**:
  - 現稼働バイナリと新 install パスが同一 (現状 `/Applications/CacheWarden.app/Contents/MacOS/cache-warden` 固定なので通常一致)
  - `cache-warden ping` が返る (= daemon 生存)
- **実行**: `cache-warden daemon restart --graceful` を叩く
- **verification**: 完了後 `cache-warden ping` + `kv status` で pid 同一 + 状態保存を確認

## Fallback

- restart --graceful が失敗した場合 (署名検証 fail / bind race / holder timeout など): 手動介入 (kawaz が状況判断)
- launchd KeepAlive による cold start に退化するのは Phase 1 の fail-safe 仕様通り (悪化ではない)

## 実装場所 (候補)

- `justfile` の `on-success-release` 直後 (kawaz/cache-warden 側)
- または kawaz/homebrew-tap の formula の post_install (brew の API 上可能なら要調査)

前者が実装容易、後者は「brew upgrade 経路以外にも波及」する利点あり。優先は前者。

## 関連

- DR-0029 §6 ロールアウト
- justfile の on-success-release (kawaz/cache-warden main)
- feedback: nonstop-push-skipping (kawaz auto memory) — push はまとまった単位、on-success-release で連携

## 優先度

高 (dogfood 体験直結、Phase 1 で「動く graceful restart」を用意した後の自然な次段)
