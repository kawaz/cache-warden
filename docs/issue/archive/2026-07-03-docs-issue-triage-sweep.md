---
title: open issue 13 件の triage 棚卸し (外部監査フラグ)
status: resolved
category: task
created: 2026-07-03T13:46:24+09:00
last_read:
open_entered:
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-07-04T09:33:55+09:00
discard_reason:
pending_reason:
close_reason: ["done:idea3/open6/blocked2/pending-sublimation1/resolved1(+followup1)"]
blocked_by:
origin: claude-rules-personal
---

# open issue 13 件の triage 棚卸し (外部監査フラグ)

## 概要

`docs/issue/` 配下の open 状態 issue 数が 13 件に達している。放置日数順に
棚卸しし、各 issue を close / 継続 / 統合のいずれにするか判断することを提案する。

## 背景

kawaz の個人リポ群を横断監査したところ、cache-warden の open issue 数 (13 件)
は監査対象リポの中で hyoui (21 件) に次いで多かった。個々の issue の価値判断は
本リポ (cache-warden) 担当側に委ねる。

これは部外者 (claude-rules-personal セッション) からの観測に基づくフラグであり、
実際の内容・放置理由は裏取りできていない。triage の要否・優先度は担当側で確認の
上で判断してほしい。

出所: 2026-07-03 の個人エコシステム横断監査 (claude-rules-personal セッション発) より。

## 受け入れ条件

- [x] 現行 open issue 13 件を放置日数順に一覧化する (`/local-issue:list` 等)
- [x] 各 issue を close (resolved/discarded) / 継続 (wip 昇格等) / 統合 のいずれかに判断する
- [x] 判断結果を各 issue の status 遷移 (`/local-issue:update`) に反映する

## Triage 結果 (2026-07-04)

13 件を分類: idea 継続 3 件 / open 継続 6 件 / blocked 遷移 2 件 / pending-sublimation
遷移 1 件 / resolved (close) 1 件。判定はコード実態確認 (grep/Read) を伴う裏取りベース。

### idea 継続 3 件 (status 変更なし)

- `graceful-restart-state-handoff` — 未着手・未決のアイデア記録、実装着手前に DR 化予定
- `ssh-agent-provider-architecture` — ビジョン拡張の議論メモ、実装着手前に DR 化予定
- `touchid-blocks-blocking-pool` — 派生問題、本体解決後に再評価予定のまま

### open 継続 6 件 (status 変更なし、実装未着手を code 裏取りで確認)

1. `op-discovery-blocks-startup` — DR-0023 Phase 2 は Proposed のまま未実装、dogfood 致命症状として open 継続
2. `expose-secret-allowlist` — DR-0024 (cap gate) は Accepted+実装済みを確認したが `expose_secret` は依然 `pub`、`with_exposed` 未実装。re-evaluate 可能な状態として追記
3. `finish-get-working-buffer-zeroize` — 同上 DR-0024 land 確認、`finish_get` opaque path は依然 `Zeroizing` 未適用
4. `internal-key-forget-interface` — `StoreKey` newtype 未実装、`op_kv_key` が依然 raw `__authsock_op:` キーを `Store::define` に直接 push (アーキテクチャ違反継続)
5. `crate-macos-process-inspect` — `crates/macos-process-inspect/` 未作成 (workspace member に無し)。2 件の blocked issue の前提
6. `release-yml-semver-gate-canonical-pattern` — release.yml に semver compare gate 依然無し、優先度高のまま

### blocked 遷移 2 件 (blocked_by は既存記載、status フィールドが open のままだった不整合を修正)

- `custom-touchid-dialog` → blocked_by: crate-macos-process-inspect (未実装のため)
- `kv-get-peer-identity-guard` → blocked_by: crate-macos-process-inspect (未実装のため)

### pending-sublimation 遷移 1 件

- `changelog-md-adoption` — 「現状確認」節の調査を実施し release.yml が `--generate-notes`
  使用 (= case A) と確定。短期アクション (現状維持) は既に満たされているため
  pending-sublimation とし、1.0 直前の CHANGELOG.md 移行検討時に再評価

### resolved (close) 1 件 + follow-up 1 件起票

- `fda-check-flow-port` → resolved。コード調査で `crates/macos-tcc/` crate・
  `internal fda-check` サブコマンド・`daemon register` への FDA フロー統合が
  すべて実装済みと確認。未実施は README (ja/en) への節追加のみだったため、
  `2026-07-04-fda-readme-section-cache-warden` を follow-up として起票し本体は close
