# vault / signed-by 設計の 3 系統レビュー突き合わせ (sol / fable / opus)

- Date: 2026-08-14
- 対象: `docs/issue/2026-08-14-signed-by.md` の設計議論 (kawaz 裁定 13 項目 + 統括評価) +
  draft-DR-0032 + findings/2026-08-14-passkey-prf-native-macos.md
- レビュワー: codex-sol-reviewer / fable5-worker-high / opus5-worker-high に**同一指示**で
  独立レビューを依頼した結果の統括統合。各レビュー全文はセッション transcript にあり、
  本書は DR 起草の入力となる統合版 (指摘の帰属を sol/fable/opus で付記)

## 1. 三者一致 (最高確度 — DR で必ず対処)

### 1.1 CAS だけでは OAuth provider への refresh 呼び出しを直列化できない (sol C1 / fable C2 / opus C4)

CAS は「cw への書き戻しの勝者」を決めるだけで、敗者も provider への refresh を既に発行済み。
strict rotation + reuse detection の IdP では 2 発目がトークンファミリー全失効を招き、
store が整合してもクレデンシャル自体が死ぬ。
対処候補 (fable 案が具体的): **refresh 着手時に entry を `refreshing(expected_version, expiry)`
へ CAS 遷移させてから provider を叩く** (expiry 付きなので stuck 回収問題なし、requester
識別に依存しない点は CAS と同じ)。または gateway 側 singleflight を契約として明記 (sol)。
opus C4 は加えて「CAS 成功の返却 = version の fsync 完了後」(version は永続かつ単調) を要求 —
crash 後の version 巻き戻りで消費済み RT を確信を持って再利用する事故の防止。

### 1.2 「スロット削除時に常時 DEK ローテ」は対称 KEK では実装不能に近い (fable C1 / opus M7 / sol 7)

DEK 再ラップには**残存全スロットの KEK が必要** = 全 passkey デバイスの ceremony が要る。
「削除時常時ローテ」(裁定 12a/13) は素直に実装すると多デバイス構成で即時完結しない。
**fable の解: スロットを非対称 recipient にする (age 同型)** — 各スロットは X25519 鍵ペアを
持ち、公開鍵は header 平文、秘密鍵を PRF/SE/recovery 由来鍵で暗号化。DEK は各スロット
**公開鍵**へラップするため、DEK ローテ・スロット追加時の再ラップが **ceremony ゼロ**で完結
(unlock 時のみ ceremony)。opus の代替: 削除は header 除去のみ + rotate は明示コマンド化 +
未 rotate 警告。sol 7 は rotation transaction の原子性 (generation 付き新ファイル +
rename + dir fsync) を要求。
→ **裁定 12a/13 の差し戻し対象**。統括推奨は fable の非対称 recipient 採用 (rotate の
実行可能性問題が構造的に消える)。

### 1.3 signed-by の評価対象と限界の明示 (opus C1・C2 / sol 5・6 / fable M1)

- **chain OR は不可** — 署名済み親 (Terminal 等) の下の任意コードが通る。**peer 直のみ**
  (fd の audit token → `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)`、pid は TOCTOU)
- **peer 直の帰結** (opus C1): `cw kv get` CLI 経由では CLI 自身の署名になるため signed-by は
  永遠に成立しない。**llm-gateway が control socket を直叩きすることが前提条件** — DR に明記
- **インタプリタ問題** (opus C2): llm-gateway が node/python 実装だと peer は `node` で、
  検証されるのはインタプリタの署名 = `command=` と同強度に落ちる。**llm-gateway の実装言語 /
  配布形態の確認が DR 起草の前提調査**
- 防げない攻撃の表 (DR-0030 §1b 形式) を必須化: 正規署名バイナリの代理実行 / plugin・script
  読込 / DYLD injection (hardened runtime + library validation 無効時) / 侵害された旧バージョン
  (sol 5)。前提条件 = 対向が単一署名 Mach-O + hardened runtime + library validation
- identity の正規形 (sol 6 / opus m3): DR 文字列の直接受けは誤記が「緩い DR」に化ける。
  **構造化入力 (anchor, team-id, identifier) から cw が DR を組み立てる**形を推奨。
  証明書ローテーション・Developer ID 失効・helper の identifier 差の契約も要定義

### 1.4 set 全置換モデルとの衝突 — entry 乗っ取りと guard 剥がれ (sol C2 / fable M2)

DR-0030 の「set は record 全置換 / constraint なし set は record 削除」のまま signed-by を
足すと: (a) 既知 key を別プロセスが先行/上書き set して自分の signer を正本化する
integrity/confused-deputy 攻撃 (sol C2 — **create 時 TOFU で owner 確立、update/delete/
constraint 変更は現 owner requirement 通過必須**へ)、(b) refresh のたびの CAS set で
signed-by を再宣言し忘れた 1 回で guard が silent に外れる footgun (fable M2 —
versioned update では guard 継承の意味論へ)。
→ signed-by は「get constraint の追加」ではなく **entry owner principal + CRUD 認可**として
設計する (sol 提案 A)。

### 1.5 guard record / CAS version の vault 永続化 (fable M5 / opus M8・C4 / sol 8)

vault で値だけ cold start 復活し guard が消えると「認可が黙って消える」(DR-0030 §3 と同型、
最悪の縮退方向)。**vault format に guard record と CAS version を含める**。DR-0033/0034 は
実装順序としては独立可だが設計は相互参照必須 (opus)。format version downgrade 拒否も
(sol 18、DR-0030 snapshot 対策と同型)。

### 1.6 locked vault の状態機械と可観測性 (sol 11 / fable M4 / opus C3 + 代替案)

- 初回アクセス時プロンプトは prompt storm / hang / busy retry の三すくみ (sol 11)。
  **opus 案: unlock は明示 `cw vault unlock` コマンド起点にし、locked 中の persist entry は
  「存在するが locked」として status/list に露出する degraded モード** (既存の
  defined/has_value 区分に `locked` を足すだけ、実装コスト低)。統括もこれを推す
- エラーは `vault_locked` 等の専用種別 (auth_failed と区別、fable minor — llm-gateway が
  再認可フローに落ちて重複 grant を作る事故の防止)
- unlock 後の DEK 常駐期間 / mlock / zeroize / 再 lock 契機 (idle/manual/sleep) を v1 で定義
  (sol 11 / fable M4)
- graceful restart snapshot と vault の正本関係、DEK を handoff に含めるか (fable M6)

### 1.7 recovery slot の強度・必須化・独立保管 (sol 4 / opus C3・M2 / fable minor)

- **256bit 級ランダム生成必須** (人間選択 passphrase を許すと memory-hard KDF の話に化ける)
- 「縁切り」裁定を採る以上 **vault 初期化時に必須生成 (スキップ不可)** (opus C3)
- **1Password と独立な媒体に保管** — passkey も recovery も 1P だと相関故障で全滅 (opus C3)
- **通常 unlock 経路から除外** し `--recovery` 明示 + ローカル TouchID ゲート + 試行の永続
  レート制限 (opus M2 — OR 合成の最弱リンクを攻撃者に選ばせない)

### 1.8 localhost dev スロットの本番混入ガード (opus M3 / fable M8 / sol 15)

per-slot RP ID 記録の副作用として localhost スロットが本番 vault に残留し得る (最弱スロット
が vault 強度を決める)。**開発 vault と本番 vault をファイルレベル分離** (vault-id を header
に) + localhost 系 RP ID スロット存在時の起動警告。localhost で通ることを production
readiness に数えない (sol 15 の 3 段 PoC gate)。

### 1.9 ceremony の purpose 分離 (sol 12 / fable M3 / opus M4・M5)

- 承認 (approve/deny の bool) と unlock (鍵素材を返す) は**別種の操作** — 承認プロバイダ抽象に
  収まらない。challenge lifecycle (CSPRNG/単回/短寿命/セッション紐付け) は共有可、
  purpose・credential capability・session state は分離
- **PRF salt の domain separation に ceremony 種別を含める** (`HKDF(PRF出力, slot salt,
  info = vault-id ‖ format-version ‖ slot-id ‖ "kek")`、findings の推奨を DR に写経 — opus M5)
- first-response-wins (deny で全体確定) を unlock に流用しない (sol 12)

## 2. 単独だが重要 (要対処)

- **vault rollback 防御の未定義** (sol C3): AEAD は旧正当ファイルへの丸ごと差し戻しを検出
  しない。旧 RT・削除済みスロットの復活。単調カウンタを別信頼アンカー (Keychain/SE) に
  置くか、「rollback は防御対象外、真の失効は OAuth 側 revoke」と明記するかの二択を裁定
- **追記 10「serve 分離」と DR-0032 の矛盾** (opus M1): DR-0032 が裁定したのは **TLS 終端の
  外出し**であり、ページ配信は daemon バイナリ埋め込み (ホスティング侵害の脅威消滅が WebRTC
  案却下の根拠)。caddy は reverse_proxy として daemon の local listener に向ける構成が正。
  DR に 1 行明記しないと却下済み構成へ逆行し得る
- **ブラウザ ceremony で PRF 出力が JS 環境に現れる攻撃面** (sol 13 / fable minor):
  拡張機能・DevTools・プロファイル侵害で KEK 窃取 → vault ファイルと組めば全損。厳格 CSP /
  外部 script 禁止 / no-store / DOM・log 非出力 / TLS proxy を信頼境界に含める明記。
  ブラウザ側は `userVerification: required` + UV flag 検証で UV を強制可能 (fable minor —
  findings の native UI 悲観を browser 経路に波及させない)
- **cw-owned/op-cached と persist の関係** (opus M6 / sol 10 / fable M7): **persist = cw-owned
  に一本化** (直交 2 属性にしない、op-cached への persist は BadRequest) が意味論最単純
  (opus 推し、統括同意)。cw-owned の hard TTL 免除裁定 (RT に絶対寿命は自殺)、`kv del` 後の
  再生成が op 再アクセスになる矛盾の解消 (fable M7)、昇格・降格・削除の遷移定義 (sol 10)
- **vault は cw 初のディスク秘密面** (opus M9): 0600/0700・XDG_STATE_HOME 配置・
  Time Machine/Spotlight 除外検討・write-then-rename の旧 inode 残留 (SSD)・DESIGN の
  ハードニング前提 (「秘密はディスクに書かれない」) の更新
- **provider 応答後〜durable ack 前の crash 窓は消せない** (sol 9): 2 相 commit 不能な外部
  provider との本質的窓。再起動後の「旧 RT refresh 失敗 → 明示 re-auth」回復契約を明記
- **vault 粒度の明示** (sol 17): 単一 AEAD vault なら「unlock = 全 persist entry への復号能力」
  であり signed-by は返却時認可 (at-rest compartmentalization ではない) と明記
- **metadata 漏洩面** (sol 20): header 平文範囲 (credential ID / RP ID / entry 名 / owner DR)
  と status / log への露出範囲の定義

## 3. v1 スコープ判定 (三者おおむね一致)

**v1 に入れない**: リモート unlock (Tailscale 経路が既裁定なので WebRTC は不要 — opus)、
ROR (per-slot RP ID 記録が移行問題を既に解いており、origin 1 つの構成に利得なし +
1Password 未対応リスク — opus。調査は「不要と判断できる根拠」として価値あり)、
スロット種別の網羅 (format の拡張性だけ v1 で確保 — opus/sol)、通知チャネル統合 (opus)。

**v1 で決めないと後戻り不能** (opus B / sol B): vault format version・slot schema
(種別タグ/RP ID/credential ID/salt/wrapped DEK)・**対称 vs 非対称スロット (1.2)**・
AEAD/KDF algorithm ID・CAS version の永続単調性・signed-by の評価対象 (peer 直)・
guard record の vault 内包・persist=cw-owned の一本化・owner principal の正規形・
atomic commit / fsync 契約・rollback 脅威の扱い・locked-state wire エラー・配置と permission。

## 4. DR 起草前の gate (opus 提案の順序、統括採用)

1. **1Password 管理 passkey の PRF 対応確認** (opus m6 — No なら鍵管理層が丸ごと変わる。
   ROR 対応より優先)
2. **llm-gateway の実装言語 / 配布形態確認** (opus C2 — インタプリタなら signed-by の価値が
   変わる)
3. **kawaz 裁定の差し戻し 3 件**: (a) 削除時常時 DEK ローテ → 非対称スロット採用 or 明示
   rotate コマンド化 (1.2)、(b) refresh 着手時 claim の追加 (1.1)、(c) recovery slot の
   必須化 + 1P 独立保管 (1.7)
4. DR-0033 (signed-by = owner principal + CRUD 認可として) / DR-0034 (vault) 起草、
   相互参照付き (1.5)

## 5. 三者が「問題なし」で一致した骨格 (安心して前提にできる)

envelope encryption + マルチスロットの方向 / per-slot RP ID 記録 + config rp_id は新規登録用 /
CAS 自体の選択 (lease の pid 識別否定は正しい) / DR-0032 の challenge lifecycle と Tailscale
基盤 / 登録・スロット追加のローカル TouchID ゲート (WebAuthn UV では代替不能 — fable M9) /
signed-by の DR 分離先行 / 暗号化 vault の opt-in 化 / findings の技術的正確性。
