---
title: daemon register 実行時に help 出力で異常終了 (一回性、2026-07-06 観測)
status: open
category: bug
created: 2026-07-06T13:19:46+09:00
last_read: 2026-07-10T04:49:00+09:00
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

- [x] register のエラー経路で help が出力されるケースがあるか code reading
      で特定
- [x] bootout 後 bootstrap 前に fail した場合の状態 (service 不在) を
      rollback または明示エラーにできるか検討
- [ ] 次回 upgrade 時の register で再観測

## 調査結果 (code reading, 2026-07-06)

### 受け入れ条件 1: help 出力経路の特定

cache-warden は clap 不使用、hand-rolled dispatch (`main.rs:3`, DR-0002)。
`daemon register` のエラー経路は 2 系統に分離されている:

- **flag parse エラー**: `parse_register_args` が失敗すると `or_usage(...)`
  経由で `CliError::Usage{msg, help: help::daemon_register}` になり、
  `main()` (`main.rs:934-940`) がエラーメッセージ + `help::daemon_register()
  .render()` を stderr に出力する。**これが help 出力の実際の経路**
- **runtime/environment エラー** (bootout/bootstrap 等):
  `commands::daemon_cmd::register()` 内の失敗は `.map_err(CliError::Message)`
  (`main.rs:279`) でラップされ、`cache-warden: <msg>` のみ出力、help は出ない。
  `main.rs:267-272` のコメントに「runtime/environment failure に help dump を
  付けると本当の原因が埋もれる」と明記されている

= 観測された help tail は **bootout/bootstrap 失敗由来ではありえない**。
`daemon register` 呼び出し時の flag parse エラー (`or_usage` 経路、leaf help
`help::daemon_register()`) が実際の出力元と考えられる。要因 (何が argv を
不正解釈させたか) は未特定。

なお `EDITOR / VISUAL` 節は `help.rs:64-87` の共通 `ENVIRONMENT` const で、
`show_global: true` を持つ全レベル (`daemon_register` 含む、`help.rs:317-372`)
に付与される。top-level help と `daemon register` leaf help のどちらでも
同一テキストが出るため、tail だけでは両者を区別できない (leaf help 説と矛盾しない)。

### 受け入れ条件 2: bootout 後 bootstrap 前 fail 時の rollback / 明示エラー

`LaunchdBackend::register` (`service.rs:467-502`): bootout は best-effort
(エラー握り潰し、488-490)、bootstrap 失敗時は
`Err(launchctl_bootstrap_failure_message(...))` を返す (`service.rs:417-424`、
「re-run `cache-warden daemon register` to recover」を含む明示メッセージ)。

`service.rs:403-412` のコメントで **rollback は意図的に非実装**と明記:
「the prior instance's exact state cannot be reconstructed」。機械的には
retry-loop は feasible だが、「re-run register で recover (= idempotent)」を
設計方針として採用し rollback を却下している。

→ 明示エラーは既存。rollback は検討済みの上で不採用 (設計判断)。DR-0019
(`docs/decisions/DR-0019-daemon-service-registration.md`) は
register/bootstrap/bootout の全体設計を記すが、rollback trade-off 自体は
`service.rs` のコード comment にのみ残る (DR 未反映)。

## 調査結果 (2026-07-10)

コードリーディング + 実機調査を追加実施。

1. **help が stdout に出る経路を main.rs 全読で洗い出し**: 6 経路を列挙した。
   `register()` の runtime 部分 (bootout/bootstrap 等) からは help を出力する
   経路が無いことを再確認 (= 2026-07-06 時点の調査結果と整合、runtime エラーは
   `CliError::Message` で help なし)

2. **FDA 自己再起動経路の除外**: `daemon register` 内の FDA 未許可時の
   `open --wait-apps` → `dispatch_internal` 経路は `help::*()` 系関数を一切
   呼ばない設計であることをコード上で確認。よってこの経路は help 出力の原因から
   原理的に除外できる

3. **バージョン間差分の反証**: v0.22.3 (commit `6a170d5`) → v0.23.0 (commit
   `af6f750`) 間で `main.rs` / `daemon_cmd.rs` / `service.rs` の diff がゼロ
   だった。「upgrade で挙動が変わった」仮説はこの 3 ファイルに関する限り反証
   される (= 差分がないので argv 解釈やエラーハンドリングが変化したわけではない)

4. **brew cask 定義の確認**: `kawaz/homebrew-tap` の `Casks/cache-warden.rb`
   に `postflight` / `caveats` 等の追加フックは無く、upgrade フローが
   `cache-warden` を副次的に追加呼び出しする経路も無いことを確認

5. **実機再現確認**: `cache-warden daemon register --print` は正常終了。
   `cache-warden daemon register --bogus` は `daemon register` leaf help
   (= top-level help ではない) を出す。つまり「正常な argv でこのプロセス
   自身が top-level help を出す」経路は実機上も発見できなかった

6. **残る仮説**: コード内在的な原因は上記で概ね反証できたため、残るのは
   外部要因 (= 実際に打たれた argv が認識と異なっていた、または PATH 上の
   別バイナリが呼ばれた等)。次回再現時は `which -a cache-warden` の結果と、
   実行時の shell history の実打鍵全文をあわせて記録する

status は `open` のまま (再現待ち)。
