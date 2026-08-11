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

## UX 仕様 (kawaz 裁定 2026-08-12)

FDA 付与フローのあるべき形:

1. FDA チェック → 付与済みなら何もしない。
2. 未付与なら**いきなり設定画面を開かない** (複数アプリが同時に同様のことを
   した場合どのアプリが開いたか分からない / ユーザは突然設定を開かれても
   意味が分からない)。代わりに説明ダイアログを出す。
3. ダイアログの内容:
   - **Why**: なぜ必要か (毎回のコマンド実行のたびに許可ダイアログが出ない
     ようにするため、等の簡潔な説明)
   - **How**: 何をすればよいか (これからフルディスクアクセスの設定ページを
     開くので、リストから CacheWarden.app を探してチェックを ON にして
     ください)
   - 「Full Disk Access の設定を開く」ボタン
   - **現在の FDA 有効状態の live 表示** (最初は赤 NG)
4. ユーザがボタン → 設定でチェック ON → ダイアログの状態表示が緑 OK に
   変わり「設定が確認できました。このダイアログは閉じて構いません」を表示。
5. 許可しない選択も可能で、その場合はアップデートのたびに (AppData の)
   ダイアログが毎回出るが都度 OK すれば利用は可能である旨をどこかに明記。

実装補足 (統括): GUI ホストは常駐 helper (CacheWardenApprover) が自然、
live 状態監視は本 issue 既記載のイベント駆動化 (`com.apple.TCC.access.changed`
/ TCC.db 監視 + probe) を使う。

## TODO

<!-- wip 時のみ -->
