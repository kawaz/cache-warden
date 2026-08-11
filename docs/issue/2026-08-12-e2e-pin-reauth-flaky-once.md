---
title: e2e test pin_holds_value_past_soft_expiry_then_unpin_restores_gating が高負荷並列で 1 回だけ FAILED
status: open
category: tech-memo
created: 2026-08-12T00:49:30+09:00
last_read:
open_entered: 2026-08-12T00:49:30+09:00
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

# e2e test pin_holds_value_past_soft_expiry_then_unpin_restores_gating が高負荷並列で 1 回だけ FAILED

## 概要

e2e test `pin_holds_value_past_soft_expiry_then_unpin_restores_gating` が高負荷並列
(`cargo test -p cache-warden-cli` 全体、別作業のコンパイル並走中) で 1 回だけ FAILED した
(2026-08-12 深夜、clap 移行作業中の worker が観測)。単独実行では 12/12 pass、e2e binary 全体でも
6/6 pass、以後 5 連続再現せず。

## 背景

内容は pin の re-auth ゲート (DR-0011) の timing に関するもの。引数パースを経由しない raw
protocol 経路のテストなので、並走していた clap 移行作業の変更とは無関係と切り分け済み。
approver 硬化 (commit 1218a74e) の daemon 変更が同じ working copy に in-flight だった点も
影響候補として残る。

1 回きりの観測メモであり、flaky 認定はまだしない (test-failure-no-tampering 規約)。再観測されたら
test の time 依存箇所 (soft expiry 境界での実時間 sleep 等) を疑う。

## 受け入れ条件

- [ ] 再現した場合、再現条件 (並列度・同時実行 test・in-flight な変更) を記録する
- [ ] time 依存箇所の有無を確認し、flaky の真因を特定または否定する

## TODO

<!-- wip 時のみ -->
