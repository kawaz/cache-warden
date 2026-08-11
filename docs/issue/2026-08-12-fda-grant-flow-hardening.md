---
title: FDA 付与フローの再整備
status: open
category: task
created: 2026-08-12T01:55:02+09:00
last_read:
open_entered: 2026-08-12T01:55:02+09:00
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

# FDA 付与フローの再整備

## 概要

FDA 付与フローの再整備 (2026-08-12 実機バグ発見の後続)。FDA 判定 (macos-tcc) を
open+read ベースに修正済み (commit 40ffa6f3) だが、以下の残作業が未対応。

## 背景

FDA 判定 (macos-tcc) が stat ベースで常に Granted 誤判定していたため、register の
誘導フローが一度も発火せず、FDA ペインにも載らないまま op spawn のたびに AppData
dialog が出ていた。判定を open+read に修正済み (commit 40ffa6f3)。denied read の
副作用でペインへの自動リスト掲載 (= 正規経路) も獲得し、実機で掲載 → kawaz トグル
ON → `auth_value=2` を確認済み。

## 受け入れ条件

- [ ] register 時以外の検知経路: 既 register 環境では誘導が走らないため、daemon
      startup または `daemon status` で FDA 未付与を警告 + 誘導する経路を追加
      (「register し直していない環境で放置」の再発防止)
- [ ] `wait_for_grant` のイベント駆動化: 現行ポーリングを `com.apple.TCC.access.changed`
      distributed notification 購読 (要実機裏取り)、または TCC.db の FSEvents 監視 +
      probe 再実行に置換検討 (kawaz 要望 2026-08-12「変化のイベント取れる?」)
- [ ] `has_op_sources` 条件の再考: op source が無くても authsock の op discovery 等で
      FDA が要る構成がないか確認
- [ ] 検証用に作った同 bundle ID の `/tmp/CacheWardenProbe.app` を削除
- [ ] `.claude/rules/daemon-notarized-binary.md` の「未実装の誘導フロー」記述が古い
      ため、実装状況に合わせて修正

## TODO

<!-- wip 時のみ -->
