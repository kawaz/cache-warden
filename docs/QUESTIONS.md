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

### 👺VLT-Q1: vault 設計の裁定差し戻し 3 件 (3 系統レビュー起因)

背景は [3 者レビュー統合](research/2026-08-14-vault-design-tri-review.md) §1.1 / §1.2 / §1.7。

- [ ] a: スロットを**非対称 recipient (age 同型)** にする — DEK ローテ・スロット追加が ceremony ゼロで完結し「削除時常時ローテ」裁定がそのまま実装可能になる (統括推奨)
- [ ] a': 対称 KEK のまま、削除は header 除去のみ + DEK ローテは明示 rotate コマンド化 (未 rotate 警告付き)
- [ ] b: CAS に加えて **refresh 着手時 claim** (`refreshing(expected_version, expiry)` への CAS 遷移後に provider を叩く) を入れる — 並行 refresh の provider 側ファミリー失効を防ぐ
- [ ] b': claim は入れず「gateway 側 singleflight を契約として明記」で済ます
- [ ] c: recovery slot を**初期化時必須生成 (スキップ不可) + 1Password と独立媒体に保管**を運用要件化 (passkey も recovery も 1P だと相関故障で全滅)

### 👺VLT-C1: DR 起草前の実機/環境確認 (kawaz 側)

- [ ] a: **1Password 管理 passkey で PRF 拡張が使えるか** (ブラウザで https://webauthn.io 等の PRF デモ、または 1P の対応ドキュメント確認。No なら鍵管理層の設計が変わるため最優先)
- [ ] b: llm-gateway のビルドが **hardened runtime + library validation 有効**か (signed-by の強度前提)

## 確認待ち

### 👺CLP-C1: v0.27.0 (clap 化) 後の日常コマンド体感確認

brew 0.27.0 への upgrade + 本番 daemon graceful restart は release 成功時に自動実行済みの想定
(未実行なら先に `just on-success-release`)。普段の操作が従来どおり動くかの体感確認:

- [ ] a: 普段使いの `cache-warden kv get <KEY>` / `status` がいつも通り動く
- [ ] b: `cache-warden --socket <PATH> kv list` のように **--socket をコマンド名より前**に置いても効く (今回の新機能)
- [ ] c: `cache-warden --help` / `cache-warden kv --help` の表示に違和感がない (セクション構成・情報量)
- [ ] d: zsh 補完がいつも通り効く (サブコマンド・オプション・KEY 動的補完)
- [ ] e: SSH (authsock 経由の鍵利用) がいつも通り動く

違和感があった項目は自由文でメモしてもらえれば issue 化します。全部 OK ならチェックだけで十分。
