---
title: daemon register 実行時に help 出力で異常終了 (一回性、2026-07-06 観測)
status: open
category: bug
created: 2026-07-06T13:19:46+09:00
last_read:
open_entered: 2026-07-06T13:19:46+09:00
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

# daemon register 実行時に help 出力で異常終了 (一回性、2026-07-06 観測)

## 概要

v0.22.3 daemon (launchd 稼働中、pid 3470) がある状態で、brew upgrade 直後の
v0.23.0 バイナリから `cache-warden daemon register` を実行したところ:

- 出力の末尾が top-level help の環境変数節 (`(1/true/yes/on); a --reveal flag
  still overrides it` / `EDITOR / VISUAL  Editor launched by config edit`)
  だった (= register の正常出力ではなく help が出た。`tail -3` で観測したため
  全文は不明)
- 実行後: 旧 daemon (pid 3470) は死亡、launchd service は `Could not find
  service` (= bootout は起きたが bootstrap されていない)、socket も消失
- 直後に同じ `cache-warden daemon register` を再実行したら正常完了
  (`registered com.github.kawaz.cache-warden`、exit 0)、以降は問題なし

## 背景

brew upgrade で `cache-warden` バイナリが v0.22.3 → v0.23.0 に上がった直後の
daemon register で観測。旧版が launchd 稼働中の状態から register を叩く
という、upgrade フロー特有のタイミングでのみ再現した可能性がある。

### 疑い

- register の bootout → bootstrap の間でエラーになり help を出して中断した
  可能性 (エラー時に usage/help を出す経路がある?)
- 旧版 (v0.22.3) 稼働中サービスの bootout 経路でのみ起きる何か (再現には
  旧版稼働状態が必要で、今は再現不能)
- brew upgrade による `.app` 差し替え直後というタイミング要因

### 再現性

不明 (一回性)。旧版 bootout 経路は既に消失。次回の version upgrade 時の
daemon register で再観測するのが現実的。

### 影響

register が中断すると daemon 不在 + socket 消失 = signing 停止状態になる
(再実行で復旧するが、無人 upgrade フローだと気づけない)。register の非正常
終了時に bootout 済み状態を残さない (bootstrap 失敗なら rollback する /
明確なエラーを出す) のが望ましい。

## 受け入れ条件

- [ ] register のエラー経路で help が出力されるケースがあるか code reading
      で特定
- [ ] bootout 後 bootstrap 前に fail した場合の状態 (service 不在) を
      rollback または明示エラーにできるか検討
- [ ] 次回 upgrade 時の register で再観測
