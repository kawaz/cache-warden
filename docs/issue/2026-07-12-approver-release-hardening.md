---
title: approver helper の release 硬化 (standalone 無効化 / main-thread dispatch / 警告ログ規約)
status: wip
category: task
created: 2026-07-12T01:14:46+09:00
last_read: 2026-08-12T13:31:55+09:00
open_entered: 2026-07-12T01:14:46+09:00
wip_entered: 2026-08-11T23:52:45+09:00
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

5. **helper 側 dialog の自前 timeout (countdown) 実装 (Block 3a レビュー
   MEDIUM-3、2026-07-12)**
   現状 helper に dialog timeout が無く (wire の `timeout_secs` は未使用の
   hint に留まる)、ユーザ不在で dialog が 1 つ放置されると daemon 側 90s
   timeout 後も dialog が画面に残る。helper は直列 read のため次の request
   を読まず、以後の guarded get が全て 90s 待ちになる (= AuthFailed の可用性
   DoS)。fail-closed なので機密自体は安全だが、根治は helper 側 countdown
   (Phase 2)。DR-0031 Phase 1.6 Block 1 の記録が「M-2 (stuck live helper の
   自動 recovery) は本 issue に集約」としていたが本 issue に項目が無かった
   drift の解消も兼ねる。

6. **dialog キューの有界化 (prompt-bombing 対策、同レビュー MEDIUM-3)**
   `APPROVER_REQUEST_TIMEOUT` (90s) は lock 取得後の exchange のみを bound
   し、lock 待ちは無期限。同一 uid のプロセスが M 本接続して guarded get を
   積むと M 個の dialog が順に出続ける (MFA 疲れ攻撃)。対策候補: 
   `approver.request` 全体を timeout で包む / pending depth 上限 / 同一
   (key, requester) の coalesce。DR-0031 §Security への v1 既知制約の明文化
   は Block 3a の docs 反映で対応済みの予定、実装対策は本 issue で追跡。

   **SIGN 経路の増幅要因 (SIGN dialog 統合レビュー LOW-4、2026-07-13)**:
   authsock SIGN 経路は ssh client が鍵ごとに SIGN を送り、失敗時に自動
   再接続・再試行するため、guarded 鍵では get より dialog が積まれやすい。
   `APPROVER_REQUEST_TIMEOUT` (90s) は approver 内部 lock 取得後の exchange
   のみを bound し lock 待ちは無期限なので、pending dialog は queue 深さ ×
   90s まで滞留する。client が諦めた後に dialog が遅れて出る「幽霊承認」も、
   helper の PeerGone 監視 (Phase 2) が requester pid 消滅を拾わない限り
   成立する。対策の (key, requester) coalesce は SIGN 経路にも適用すること。

## 背景

draft-DR-0031 (custom TouchID dialog) の Phase 1.5 で opus47 によるセキュリ
ティレビューを実施し、致命的な blocker はなく land 可と判定されたが、上記
4 件は release 前 or release 直後の硬化タスクとして持ち越しになった。

## 受け入れ条件

- [x] standalone mode の扱い (release 無効化 or feature flag) を決定し実装 —
  release は `#[cfg(debug_assertions)]` gate で無効化 (commit 1218a74e)
- [x] LAContext completion block → main queue 明示 dispatch に置換
- [x] daemon 側 / helper 側の警告ログ prefix を統一、到達経路を確認 — helper
  側は `cache-warden-approver:` に統一
- [x] `PeerIdentifierPrefixMismatch` の診断メッセージ改善 — `PeerIdentifierMissing`
  を分離して診断品質を改善
- [x] `kSecCSStrictValidate` 採用可否を判断 — 不採用。静的 API 用の flag で
  動的 SecCode 検証には効かないため。根拠は draft-DR-0031 の release 硬化
  land 節
- [x] helper 側 dialog に自前 countdown timeout を実装 (`timeout_secs` hint を実際に消費) —
  実機確認済み (2026-08-12)
- [ ] dialog キューを有界化 (lock 待ち全体の timeout / pending depth 上限 / coalesce のいずれかを選定し実装) —
  depth 上限 + 2 段 timeout まで実装済み。残 = (key, requester) coalesce
  (SIGN 経路の per-key 再試行対策の本命)。実装済み分は commit 1218a74e、
  fable レビュー LOW 3 件のみ

## TODO

<!-- wip 時のみ -->

- 着手中 (2026-08-11): 5 (dialog countdown) / 6 (キュー有界化: 全体
  timeout + depth 上限、coalesce は後続) / 1 (standalone release 無効化) /
  2 (main-thread dispatch) / 3 (prefix 統一) / 4 (診断分離 + `kSecCSStrictValidate`
  調査) に worker 着手
- Block 3b Item 2 実機で wedge / キュー積みの実サンプル取得済み:
  `docs/journal/2026-08-11-block-3b-item2-sign-e2e.md`

## 関連

- `docs/decisions/draft-DR-0031-custom-touchid-dialog.md` §Security
- `docs/issue/2026-07-11-approver-persistent-helper-lifecycle.md`
- Block 3a レビュー MEDIUM-3 (2026-07-12): stuck live helper の可用性 DoS と prompt-bombing 対策の指摘元
