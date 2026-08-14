# 裁定・確認待ち一覧 (ユーザ用)

## 運用規約

<details>
<summary>ゼロコンテキストエージェント向け（本セクションは消さない）</summary>

- 裁定/確認待ち項目を 1項目=1ラベル=1セクション で記載
- ラベル形式: XX-Q1（XX は 2-3 文字、バッチやセッション内で一意、Qn単独の使い回し禁止、長期一意性は不要)
- 依頼形式: 「👺XX-Q1 の裁定お願いします」（参照用途ではラベルに👺を付けない。誤陽性がユーザのハイライト/アラームを汚す）
- チャット提示と同一ターンで本ファイルに記録 + path 指定 commit (push はリリース窓に同乗)
- 裁定が下りたら該当セクションを即削除し、内容は正規の記録先 (DR / issue / journal / close_reason) へ反映。本ファイルは常に「現在待ち」だけを持つ
- 参照は[]()で提示（リポ内は相対、リポ外はフルパス）
- 初版質問/依頼は長文で書かない（ユーザが説明を求めらたら本ファイルに説明を追加し、チャットで👺ラベルで再依頼）
- **選択肢・確認項目は `- [ ] a: …` 形式（チェックボックス + ラベル）で書く**。
  Q / C で記法を分けない。回答は「チェックを付ける」でも「XX-Q1a」と言葉で返すでも通る
  （複数まとめてチェックし「チェックしたよ」の一言で済ませる運用を想定）

</details>

## 裁定待ち

### 👺DR34-Q1: draft-DR-0033/0034 の accept 判断と Open Questions

[draft-DR-0033 (signed-by)](decisions/draft-DR-0033-signed-by-constraint.md) と
[draft-DR-0034 (暗号化永続 vault)](decisions/draft-DR-0034-encrypted-persistent-vault.md) を
起草済み (3 系統レビュー全項目消化)。DR 全文レビューの上:

a (accept) / b (DEK handoff 同梱) は裁定済み・DR 反映済み。残り Q2 のみ:

- [ ] c: vault rollback を防御対象にする (単調カウンタを Keychain/SE 外部アンカーへ。裁定 6 と緊張。買えるのは fail-loud 検出のみで機密性は上がらない)
- [ ] c': rollback は防御対象外と明記 (**統括推奨** — rollback 可能な攻撃者はオフライン復号で同等以上が既に可能、version 巻き戻りの実害は §3a の再認証回復契約で受け止まる。分析は [DR-0034 Open Q2](decisions/draft-DR-0034-encrypted-persistent-vault.md#open-questions))

## 確認待ち

(なし)
