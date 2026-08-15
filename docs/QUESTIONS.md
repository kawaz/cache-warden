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

### 👺VLT-Q2: vault/signed-by 実装完了分の push タイミング

DR-0033/0034 の実装フェーズ 1-5 が全て commit 済み (各フェーズ fable5-high レビュー +
delta 承認、workspace 1620 tests green)。未 push は v0.28.0 以降の全 commit。

- [ ] a: 即 push して v0.29.0 リリース、実機確認はリリース版で (v0.28.0 の前例)
- [ ] b: 下の VLT-C2 (実機確認) を先にやってから push

## 確認待ち

### 👺VLT-C2: vault の実機確認 (kawaz 在席時、ブラウザ/TouchID 必須分)

dev build (`cargo build --release`) + 隔離 config で。手順詳細は依頼があれば整備します:

- [ ] a: `cw vault init` → recovery code 表示・保管案内が出る
- [ ] b: `cw vault add-passkey` → **TouchID ダイアログ (approver 経由) が出る**
- [ ] c: 発行 URL をブラウザで開き **1Password 管理 passkey で登録完走 + `prf.enabled` が true** (最重要 — PRF 実動作)
- [ ] d: `cw vault lock` → unlock の URL をブラウザで開き **実 passkey で解錠できる** (最重要)
- [ ] e: 解錠後 `kv get` が値を返す / graceful restart で unlocked 維持
- [ ] f: 別 team/identifier 署名バイナリからの get が種別のみのエラーで拒否される (signed-by、手順整備可)
