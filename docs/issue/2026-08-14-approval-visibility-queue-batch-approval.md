---
title: 承認要求の可視化キュー + batch 承認 (1 生体操作で N 件)
status: idea
category: idea
created: 2026-08-14T17:51:25+09:00
last_read:
open_entered:
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: kawaz 発案 (ccmsg r124m22)
---

# 承認要求の可視化キュー + batch 承認 (1 生体操作で N 件)

## 概要

TouchID / passkey 要求が連続した際の可視化キューイング機能。要求リストがあり、
選択すると要求元・capability 設定など判断に必要な情報や追加指定オプションが
表示され、一つずつ OK/NG 裁定を下せる。全て/ある程度まとめて OK した時点で
TouchID or passkey 承認を 1 回実行 — その際は各リクエストの署名要求データを
一つに正規化して固めたものへの署名でまとめて承認する。

タイムアウトによる複数回チャレンジは同一要求を一本化し、タイムアウト済みは
リストからリアルタイムに消える/無効表示。暗号鍵 (PRF) は個別 ceremony が必要。

## 背景

kawaz 発案 (2026-08-14 ccmsg r124m22)。承認要求ごとに毎回 TouchID を要求する
approval fatigue への対策として、複数の pending 要求を可視化してまとめて
裁定・1 回の生体操作で承認する仕組みを検討。

### 統括評価 (賛成 + 設計注意)

1. **暗号学的に成立** — draft-DR-0032 の「challenge に operation context を
   埋め込む」の集合への一般化。N 件の要求 context の canonical bundle の
   hash を challenge にし、1 assertion を「レビューした集合」に束縛する。
2. **本質的注意** = batch OK は approval fatigue の解決策かつ増幅器。緩和策:
   - リスク階層で batch 可否を分ける (初見 requester / weak constraint /
     初アクセス key は既定で個別 OK 要求、既知パターンのみ batch 可)
   - 一覧で展開閲覧した項目のみ batch 対象、等の「見ずに全承認」防止 UI
3. **同一要求の一本化**は実装済み coalesce key (key, operation,
   pid+pid_version, euid) を流用可能。タイムアウト/失効のリアルタイム反映は
   既存 PeerGone 検知 + timeout をキュー表示に接続する。
4. **PRF 制約の正確化**: 1 assertion で取れる PRF 出力は credential ごとに
   最大 2 値 (first/second)。salt 3 つ以上は複数 ceremony が必要。
5. **位置づけ** = draft-DR-0031 (dialog) / draft-DR-0032 (承認 ceremony) の
   拡張。vault v1 (明示 unlock 1 発) より承認系で恩恵が大きいため、
   vault v1 後のフェーズに置く。

### kawaz 裁定 (2026-08-14 ccmsg r124m23)

1. リストに一括チェックボックスは置かない。「全部 OK」ボタンも無し。**OK ボタンは
   各要求の詳細ページ内にのみ存在**する — batch に入る全項目が構造的に「詳細を
   開いて閲覧済み」になり、統括が挙げた fatigue 増幅懸念 (見ずに全承認) は UI
   構造で消える。個別 OK を積んだ後、最後の生体 1 回が OK 済み集合 (canonical
   bundle) を承認する流れ。
2. 惰性全承認の懸念について: ストーム時の TouchID 20 連打は経験上確実に何も
   見なくなるため、可視化キュー + 詳細内 OK はそれより厳密に良い (blind 承認の
   比較で優位)。統括評価のリスク階層案 (初見 requester 等の batch 除外) は、
   この詳細ページ必須構造が担保するため必須ではなくなった — 詳細ページ内の
   警告表示 (weak constraint / 初見) として残す程度で良い。

## 受け入れ条件

- [ ] draft-DR-0031 / draft-DR-0032 との位置づけ整理 (拡張として明記)
- [ ] batch 可否のリスク階層判定ロジックの設計
- [ ] canonical bundle hash 化の challenge 設計
- [ ] coalesce key 流用の実装方針確認
