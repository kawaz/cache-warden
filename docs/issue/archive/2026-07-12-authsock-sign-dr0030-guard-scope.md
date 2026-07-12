---
title: authsock SIGN 経路への DR-0030 guard 適用可否
status: resolved
category: design
created: 2026-07-12T16:13:53+09:00
last_read:
open_entered: 2026-07-12T16:13:53+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-07-12T17:13:08+09:00
discard_reason:
pending_reason:
close_reason: ["dr/DR-0030","implemented","done:kawaz裁定(2026-07-12)で案a(SIGN経路にevaluator挿入)確定、commit 1e17fc67で実装。sign_with_resolved_keyにDR-0012→guard→auth/retrievalの順でgate挿入(handle_getと対称)、拒否はSSH_AGENT_FAILURE空payload、素材はaccept時peer_audit_token+SIGN要求時ancestry/unique_idの1回snapshot、startup preloadはgetter不在で対象外。テスト6本(allow/deny/token欠落/chain欠落/unguarded回帰/deny副作用ゼロ)。Fableレビュー: HIGH/MEDIUMなし、commit可。"]
blocked_by:
origin: 自リポ TODO
---

# authsock SIGN 経路への DR-0030 guard 適用可否

## 概要

authsock SIGN 経路 (`authsock.rs` の `sign_with_resolved_key`) に draft-DR-0030
guard を適用するかどうかの裁定が必要。

`[authsock.sockets.*].keys` は非予約 namespace の KV key を参照でき、その key に
guard を宣言していても SIGN_REQUEST 経路は DR-0012 gate のみで `store.get` する
— DR-0030 guard は評価されない。値そのものは応答に出ないが、「秘密鍵での署名」
は値の行使であり、setter の宣言意図 (自分の shell からしか使わせない) を同一
uid の任意プロセスが SIGN 経由で迂回できてしまう。

draft-DR-0030 は §4 で `handle_get` のみ規定しており、authsock 経路への適用可否
を論じていない。

## 背景

handler 統合レビュー (2026-07-12) の MEDIUM 指摘から起票。裁定候補:

- (a) SIGN 経路にも evaluator を挿入する。requester chain は既に取得済みなので
  `peer_audit_token` の追加取得のみで実装可能
- (b) v1 は対象外と DR §4 / §7 に明記した上で、authsock keys に載る key への
  guarded set を警告または拒否する

いずれにせよ黙って未規定のまま release しない。

あわせて把握している Block 3 の TODO (本 issue のスコープではないが裁定と近接
するため記録):

- DR §5 の `[kv.policy]` 表記を実装の `[kv-policy]` に修正 (kv 定義 map との
  TOML 衝突回避が理由)
- mixed-version 実発火検証 (positive-ack issue の受け入れ条件③)

## 受け入れ条件

- [ ] SIGN 経路への guard 適用可否を (a) / (b) のいずれかで裁定する
- [ ] 裁定結果を draft-DR-0030 §4 (または新設の節) に明記する
- [ ] (a) を選ぶ場合は SIGN 経路への evaluator 挿入を実装する
- [ ] (b) を選ぶ場合は authsock keys に載る key への guarded set の警告/拒否を実装する

## 関連

- draft-DR-0030
- docs/issue/2026-07-12-kv-set-guard-positive-ack.md
