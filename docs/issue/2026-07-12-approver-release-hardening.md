---
title: approver helper の release 硬化 (standalone 無効化 / main-thread dispatch / 警告ログ規約)
status: open
category: task
created: 2026-07-12T01:14:46+09:00
last_read:
open_entered: 2026-07-12T01:14:46+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:    # 1-line JSON array string[] 例: ["discarded","環境が変わった"]
pending_reason:    # 1-line JSON array string[] 例: ["pending","v2 待ち"]
close_reason:      # close 時に update が記録。1-line JSON array string[] 例: ["dr/DR-0007","implemented"]
blocked_by:
origin: 自リポ TODO
---

# approver helper の release 硬化 (standalone 無効化 / main-thread dispatch / 警告ログ規約)

## 概要

draft-DR-0031 Phase 1.5 の opus47 セキュリティレビューで「land 可」判定と共に
持ち越しになった硬化項目 4 件。

1. **standalone mode の release 無効化 (レビュー L-2)**
   `--socket` なし起動は hardcoded サマリで TouchID prompt を出せるため、同一
   uid の攻撃者が `open CacheWardenApprover.app` するだけで cache-warden を
   模した TouchID 疲れ攻撃 / phishing 誘導に使える (secret 自体は動かないが
   reflex を鈍らせる)。release ビルドでは `--socket` 必須化 or feature flag
   化を検討。

2. **LAContext.evaluatePolicy completion block からの terminate の main-thread
   保証 (L-1)**
   Apple は completion block の dispatch queue を契約しておらず、
   `NSApplication::terminate:` は main thread required。現状は実機で動く
   状況証拠のみ。main queue への明示 dispatch に置換する。

3. **攻撃兆候の警告ログ規約 (M-4)**
   daemon 側 (`cache-warden: approver: ...`) と helper 側 (`approver: ...`)
   で prefix が不揃いで、「同一 uid 内攻撃の兆候」の syslog 監視 grep が
   二重管理になる。統一 prefix と、helper (.app 起動で stderr が Console
   経由) の到達経路を決める。

4. **小粒 2 件 (診断品質)**
   - `verify_peer` の `PeerIdentifierPrefixMismatch` が「identifier 無し」と
     「prefix 不一致」を区別しない (N-1)
   - `kSecCSStrictValidate` 採用余地 (L-4)

## 背景

draft-DR-0031 (custom TouchID dialog) の Phase 1.5 で opus47 によるセキュリ
ティレビューを実施し、致命的な blocker はなく land 可と判定されたが、上記
4 件は release 前 or release 直後の硬化タスクとして持ち越しになった。

## 受け入れ条件

- [ ] standalone mode の扱い (release 無効化 or feature flag) を決定し実装
- [ ] LAContext completion block → main queue 明示 dispatch に置換
- [ ] daemon 側 / helper 側の警告ログ prefix を統一、到達経路を確認
- [ ] `PeerIdentifierPrefixMismatch` の診断メッセージ改善 (該当なら)
- [ ] `kSecCSStrictValidate` 採用可否を判断

## TODO

<!-- wip 時のみ -->

## 関連

- `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` §Security
- `docs/issue/2026-07-11-approver-persistent-helper-lifecycle.md`
