---
title: cache-warden 独自 TouchID 認証 dialog 実装
status: open
category: design
created: 2026-06-22T21:20:33+09:00
last_read:
open_entered: 2026-07-10T03:10:45+09:00
wip_entered:
blocked_entered: 2026-07-04T09:33:55+09:00
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by: []
origin: 自リポ TODO
---

# cache-warden 独自 TouchID 認証 dialog 実装

## 概要

cache-warden 独自の TouchID 認証 dialog を実装し、**要求元プロセスの透明性**を 1Password 既定の dialog より大幅に高める。

## 背景

1Password が op CLI を spawn したプロセスに対して TouchID dialog を出すとき、表示される情報は **TCC responsible process の app name 程度** (例:「Ghostty が SSH の許可を求めています」)。

これは実質 **白紙委任状**:
- どのコマンドが op CLI を呼んだか不可視
- 引数 (= どの item を get しようとしているか) 不可視
- プロセスツリー (= shell 経由 / IDE 経由 / 別ツール経由) 不可視

セキュリティアプリでありながらユーザは「何を許可しているか」が分からないまま指紋を押す。

## 受け入れ条件

- [ ] TouchID dialog に要求元コマンド + 引数を表示できる
- [ ] TouchID dialog にプロセスツリー (shell → tmux → ssh → git ... の chain) を表示できる
- [ ] TouchID dialog に対象 secret の identity (どの kv entry / op item を get しようとしているか) を表示できる
- [ ] set 時の peer-identity guard 評価結果を dialog に表示できる
- [ ] シンプル表示 (1 行サマリ + Allow/Deny + TouchID) と詳細展開の切り替えができる
- [ ] peer process が dialog 表示中に exit したケースを適切に処理できる

## TODO

<!-- wip 時のみ -->

- [ ] UX 設計確定 (シンプル/詳細展開の UI モデル)
- [ ] Swift / AppKit 依存の方針決定 (NSAlert / custom NSWindow vs 代替)
- [ ] LocalAuthentication + NSAlert 連携の PoC
- [ ] crate-macos-process-inspect の peer 情報取得 API を利用して dialog に表示
- [ ] 1Password dialog との並走 / 置換方針を確定

## 設計検討ポイント

- Swift / ObjC 連携の必要性 (= LocalAuthentication / AppKit) → 当 issue は cw に Swift 依存を入れる契機になる
- dialog 表示中に peer process が exit したケースの扱い (= 表示情報の信頼境界、snapshot 時点での情報を pin)
- TCC ベースの 1Password dialog と並走するか / 置換するか (= 二重 dialog 防止)
- 詳細表示で見せる項目の取捨選択 (= プライバシー / 情報過多のバランス)

## 調査結果 (2026-07-10)

実現手段調査を `docs/research/2026-07-10-touchid-dialog-ui-options.md` に保存 (commit wvsslwzk)。要点:

1. `LAContext.evaluatePolicy` の TouchID シートは `localizedReason` 1 行しかカスタムできない。プロセスツリー等のリッチ表示は「自前 window → その上で `evaluatePolicy`」の 2 段構成が必須
2. 受け入れ条件を満たすのは Swift/AppKit helper を `.app` 同梱して spawn + JSON IPC する案 (C 案) のみ。ただし secretive 方式 (`localizedReason` に要約 1 行、`objc2-local-authentication` crate で Rust 完結) を中間段 (A 案) として先行実装する価値がある
3. daemon プロセス内 AppKit 直叩き (B 案) は tokio とのメインスレッド争奪で不採用推奨

TODO の「Swift / AppKit 依存の方針決定」は kawaz 判断待ち: A 先行 → C 本命の段階案を提案する。

## 関連

- 前提だった 2026-06-22-crate-macos-process-inspect は resolved (crate land 済み)、unblock
- 関連: 2026-06-22-kv-get-peer-identity-guard (= guard 評価結果も dialog に表示)
- 関連: DR-0022 fetch failure backoff (= op CLI 経由 fetch の現状経路、本機能は cw 独自経路に置換していく方向性)
- 元発想: 2026-06-22 セッション、kawaz の「1Password の dialog は白紙委任で頭おかしい」発言
