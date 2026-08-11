---
title: cache-warden 独自 TouchID 認証 dialog 実装
status: open
category: design
created: 2026-06-22T21:20:33+09:00
last_read: 2026-08-11T21:54:11+09:00
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

- [x] UX 設計確定 (シンプル/詳細展開の UI モデル、draft-DR-0031 で 2 段情報階層確定)
- [x] 実装言語 (Rust + helper .app 構成) 確定、Phase 1.1〜1.6 land 済み
- [ ] LAAuthenticationView の埋め込み PoC
- [x] crate-macos-process-inspect の peer 情報取得 API を利用して dialog に表示
- [ ] cache HIT のみ dialog 発火 (v1 判断) の妥当性確認

## 設計検討ポイント

- Swift / ObjC 連携の必要性 (= LocalAuthentication / AppKit) → 当 issue は cw に Swift 依存を入れる契機になる
- dialog 表示中に peer process が exit したケースの扱い (= 表示情報の信頼境界、snapshot 時点での情報を pin)
- TCC ベースの 1Password dialog と並走するか / 置換するか (= 二重 dialog 防止)
- 詳細表示で見せる項目の取捨選択 (= プライバシー / 情報過多のバランス)

## 調査結果 (2026-07-10)

1Password 方式 (C 案) 採用に確定 (kawaz 判断、実機 dialog 観察 + Karabiner-EventViewer 情報で自由度高い方式と評価)。draft-DR-0031 (`docs/decisions/draft-DR-0031-custom-touchid-dialog.md`、commit chain: kutkryox / uznrllvt / kuxnwvlp / zwkrywlr) を執筆、kawaz レビュー待ち。

### 主要決定

- アーキテクチャ: cache-warden daemon (Rust, 現行) + `CacheWardenApprover.app` helper (新規、独立プロセス) の 2 プロセス構成。helper は `/Applications/CacheWarden.app/Contents/Helpers/` に nested 配置
- helper ライフサイクル: daemon が spawn し維持 (LaunchAgent 別登録は不採用)
- IPC: `$XDG_STATE_HOME/cache-warden/approver.sock` に helper がリスン、control socket と分離、JSON 単発 request/response
- TouchID 統合: `LocalAuthenticationEmbeddedUI.framework` の `LAAuthenticationView` を独自 dialog window に埋め込み (Mode A)。実装 PoC で問題があれば標準シート許容 Mode B に fallback
- macOS 下限: Monterey (12.0) に明示、`LAAuthenticationView` の要件
- 発火条件: guard (DR-0030) がある entry のみ v1 で dialog 化、cache HIT のみ (cache MISS の op fetch は 1P dialog に委ね、次回 HIT で cache-warden dialog に切り替わる段階移行)

### recon 3 本の結果

- 1p-bundle-recon: 1Password.app の実装は Electron + LocalAuthenticationEmbeddedUI ハイブリッド。Rust 製 SDK が LAEmbeddedUI を直接リンクしてる事実発見
- lacontext-inline-recon: `LAAuthenticationView` が公開 API と WWDC22 で発表、Apple 公式 doc あり
- laeui-recon: 実機ヘッダ verbatim で macOS 12.0+ の公開 API と確定、`objc2-local-authentication-embedded-ui` crate (v0.3.2, docs.rs 100%) 実在

**A 案 (Rust 完結、`localizedReason` 圧縮) は放棄**。1P 方式と等価な UX を目指す。

**実装言語は Rust 統一 (案 A) で確定** (550-850 行、build system 変更最小、wire schema 共有可能、Rust オンリー原則維持)。helper .app 構成で Phase 1.1〜1.6 land 済み (詳細は下記「進捗」節)。

Open questions (draft-DR-0031 §Open Questions):

1. helper bundle 配置 (nested vs top-level) - draft は nested 提案
2. helper ライフサイクル (a LaunchAgent vs b daemon spawn) - draft は (b) 提案
3. macOS 下限 Monterey の明示 - draft は明示提案
4. **実装言語 (案 A Rust 統一 vs 案 B Swift + SwiftUI)**
5. Phase 2 の `[auth].command` dialog 化のスコープ (共存 vs deprecated 予告)

### Phase 分割

- Phase 1: bundle 骨格 + IPC + サマリ dialog + Mode A、guard 付き entry のみ発火
- Phase 2: 詳細展開、CommandAuthenticator 統合、responsible_bundle_id 解決、helper 死亡検知
- Phase 3: Mode B → Mode A 移行 (fallback で Mode B に倒した場合)、Watch 対応、LARight/LARightStore 検討、カスタマイズ

codex 敵対的レビュー (job ID: task-mrebtdaf-j8x4dt) 実施中、findings 受領で DR に反映。

## 進捗 (2026-08-11 更新)

- 実装は draft-DR-0031 のもと大きく前進済み: Phase 1.1〜1.6 (helper crate / .app バンドル + LSUIElement / focus 制御 / IPC unix socket / 双方向 code-signature peer 認証 / helper 常駐化) land 済み
- Block 3a (guard 通過後の approver dialog 発火配線、commit 3d63234e) + authsock SIGN 経路への dialog 統合 (52b95386) land 済み
- 実装言語は Rust + helper .app 構成で確定 (旧記述「実装言語判断待ち」「実装着手は kawaz 承認後」は解消済み)
- 実機 e2e = Block 3b は Item 1 (get 経路基本動線、TouchID 発火→approve→値取得を coreauthd で 6+ サイクル確認) 通過済み。残 = Item 2〜6 (SIGN 動線実機 / focus / graceful restart / helper down / coreauthd 全体照合)、kawaz 在席必須
- 受け入れ条件のうち「要求元コマンド+引数表示」「対象 secret identity 表示」「guard 評価結果表示」は実装済み、「プロセスツリー表示」「シンプル/詳細切替」「peer exit ハンドリング」は release-hardening issue (2026-07-12-approver-release-hardening) 側で追跡
- close は Block 3b 完了時に判断

## 関連

- 前提だった 2026-06-22-crate-macos-process-inspect は resolved (crate land 済み)、unblock
- 関連: 2026-06-22-kv-get-peer-identity-guard (= guard 評価結果も dialog に表示)
- 関連: DR-0022 fetch failure backoff (= op CLI 経由 fetch の現状経路、本機能は cw 独自経路に置換していく方向性)
- 元発想: 2026-06-22 セッション、kawaz の「1Password の dialog は白紙委任で頭おかしい」発言
