# draft-DR-0034: 暗号化永続 vault — 非対称マルチスロット + CAS 調停 + durability 契約

- Status: Draft (kawaz accept 待ち)
- Date: 2026-08-14
- 関連: draft-DR-0033 (signed-by = owner principal、**vault format に owner record と
  CAS version を含める。相互参照必須**) /
  draft-DR-0032 (リモート承認、challenge lifecycle・TLS 外出し・登録 TouchID ゲートの基盤を流用) /
  draft-DR-0030 (peer-identity guard、guard record の永続化元) /
  DR-0029 (graceful restart snapshot、vault との正本関係) /
  DR-0022 (fetch failure backoff) / DR-0018 (typed sources、op source の正本性) /
  DR-0007 (mlock) / DR-0028 (`SecretBytes::with_exposed`) /
  findings `2026-08-14-passkey-prf-native-macos.md` (PRF の暗号学的性質、HKDF 鍵分離) /
  issue `2026-08-14-signed-by` (kawaz 裁定 18 項目) /
  research `2026-08-14-vault-design-tri-review.md` (3 系統レビュー統合)

## Context

cache-warden はこれまで「秘密はディスクに書かれない」を設計前提としてきた (in-memory +
mlock + zeroize、再起動は DR-0029 の同一 PID handoff で凌ぐ)。llm-gateway の OAuth
クレデンシャル用途はこの前提を初めて破る要件を持ち込む:

- **OAuth refresh token はローテーションされる**。単なる API キーと違い、in-memory のみだと
  daemon 再起動 (brew upgrade / crash / 再ログイン) で最新 RT が失われ、ユーザは再認証を
  強いられる。しかも失われるのは「op に取りに行けば戻ってくる値」ではなく **cw だけが
  持っていた最新値**であり、cold start での自己修復が効かない。
- したがって永続化が必須であり、平文で書けないので暗号化が必須になる。

kawaz 裁定 6 により、persist 付き entry は初回取得以降 **cw の暗号化 vault が正本**となり
op へ二度とアクセスしない (op との縁切り)。また裁定 6 は「TouchID を cw の中核に据えない」
方針を示しており、無人起動 + リモート解除を視野に vault の鍵は passkey PRF 由来とする
(TouchID は runtime unlock ではなく**登録 ceremony の防壁**として残る — 裁定 7)。

findings は「Secure Enclave + biometryCurrentSet ACL」を推奨しているが、これは端末束縛と
引き換えに可搬性を捨てる案であり、**裁定 6 の「TouchID と緩く縁を切る / リモート解除を
視野に入れる」方針と正面から衝突する**。本 DR は裁定に従い PRF 経路を採る。findings の
技術的示唆のうち方針と衝突しない部分 (HKDF による鍵分離、salt の header 保存、credential
ID / RP ID の recovery metadata 明記) は §鍵導出に取り込む。

3 系統レビューの指摘は §1 (三者一致) / §2 (単独重要) 全項目を本 DR の各節で扱う。

## Decision

### 1. vault format

#### 1a. 構造

```
header (平文、AEAD の AAD に含める)
  magic          : "CWVAULT\0"
  format_version : u32                  (単調増加、downgrade 拒否)
  vault_id       : 128bit random         (初期化時に生成、以後不変)
  dek_generation : u64                   (DEK ローテのたびに +1)
  aead_alg_id    : enum                  (v1: XChaCha20-Poly1305)
  kdf_alg_id     : enum                  (v1: HKDF-SHA256)
  slots          : [Slot]
body
  nonce          : AEAD nonce
  ciphertext     : AEAD(DEK, plaintext = entries, aad = header 全体)
```

- **format_version の downgrade は拒否する** (旧バイナリが未知フィールドを捨てて再書き込み
  すると、認可や version が黙って消える。DR-0030 §3 のダウングレード規定と同型)。
- **header 全体を AEAD の AAD に含める**ことで、header の書き換え (スロット差し替え・
  generation 巻き戻し・alg id の弱い値への改竄) が復号失敗として検出される。

#### 1b. スロット schema — 非対称 recipient (age 同型)

kawaz 裁定 14 により、各スロットは **X25519 鍵ペア**を持つ。

```
Slot
  slot_id        : 128bit random
  kind           : enum { passkey-prf, recovery }   (拡張余地を format で確保)
  pubkey         : X25519 公開鍵 (平文)
  wrapped_privkey: AEAD(KEK, X25519 秘密鍵)          (KEK は §2 で導出)
  wrapped_dek    : X25519 で pubkey へラップした DEK
  salt           : 32byte random (PRF salt / KDF salt、平文)
  rp_id          : String        (kind=passkey-prf のみ。登録時の値を記録)
  credential_id  : Bytes         (同上)
  created_at     : timestamp
  label          : String        (ユーザ可読、任意)
```

この形にすることで得られる決定的な性質:

- **DEK ローテとスロット追加が ceremony ゼロで完結する**。DEK を各スロットの**公開鍵**へ
  ラップするため、再ラップに他スロットの KEK (= 他デバイスの passkey ceremony) を必要と
  しない。対称 KEK 方式では「削除時に常時 DEK ローテ」(裁定 12a/13) が多デバイス構成で
  実行不能に近かった (tri-review §1.2) が、その問題が構造的に消える。
- ceremony が要るのは **unlock 時のみ** (自分のスロットの秘密鍵を KEK で開ける操作)。

#### 1c. スロット削除と DEK ローテ

- **スロット削除は常に DEK ローテを伴う** (裁定 12a/13)。header からスロットを除くだけでは
  「過去に DEK を知り得た者」に対して無効であり、真の失効にならないため。
- ローテ手順: 新 DEK を生成 → body を新 DEK で再暗号化 → 残存全スロットの公開鍵へ新 DEK を
  ラップ → `dek_generation` を +1 → §3 の atomic commit で置換。**全工程が公開鍵操作だけで
  完結する** (§1b)。
- **スロット追加は passkey 登録と同じローカル TouchID ゲートの対象**とする (裁定 12b/13、
  DR-0032 の登録 ceremony 規定を流用)。スロットは OR 合成なので、増えるほど窃取面が増える。

#### 1d. 永続化する内容

body の平文には entry の値だけでなく、**認可とバージョンを同伴させる**:

- entry 値と ValueMeta / Definition (DR-0029 snapshot と同じ語彙)
- **guard record** (DR-0030) と **owner principal** (DR-0033)
- **CAS version** (§4)

値だけが cold start で復活して認可が消える縮退は禁止する。**復元できない要素があれば
その entry は復元しない** (fail-closed、DR-0033 §7 と同一規定)。

### 2. 鍵導出とスロット unlock

```
PRF 出力 (32byte)
  ↓ HKDF-SHA256
KEK = HKDF(ikm  = PRF 出力,
           salt = slot.salt,
           info = vault_id ‖ format_version ‖ slot_id ‖ "cw-vault-slot-kek")
  ↓
X25519 秘密鍵 = AEAD-open(KEK, slot.wrapped_privkey)
  ↓
DEK = X25519-unwrap(秘密鍵, slot.wrapped_dek)
  ↓
entries = AEAD-open(DEK, body, aad = header)
```

- PRF 出力を直接 AEAD 鍵に固定せず HKDF を挟み、`vault_id` / `format_version` / `slot_id` /
  用途 label を info に含めて**鍵分離**する (findings の推奨をそのまま採用)。
- salt は公開値でよいが **vault ごと・スロットごとにランダム生成**し header に保存する。
- **ceremony purpose の domain separation**: DR-0032 の challenge lifecycle は流用するが、
  承認 (approve/deny の bool を返す操作) と unlock (鍵素材を返す操作) は別種の操作である。
  purpose 文字列 `vault-unlock(vault_id, slot_id, dek_generation)` を domain separation に
  含め、承認セッションの assertion を unlock に流用できないようにする。DR-0032 の
  **first-response-wins (deny で全体確定) は unlock に流用しない** (unlock は「誰か 1 人が
  拒否したら確定」という意味論を持たない)。

### 3. atomic commit と durability 契約

- **write-then-rename + directory fsync**: 新内容を同一ディレクトリの一時ファイルに書き
  → `fsync(tmp)` → `rename(tmp, vault)` → `fsync(dir)` の順。rename は同一 FS 内の
  atomic 置換であり、途中クラッシュしても旧ファイルか新ファイルのどちらかが残る。
- **永続 entry の set ack は fsync 完了後に返す**。ack を先に返すと、クラッシュで新 RT が
  消えたのに呼び出し側は「保存された」と信じる最悪の不整合が起きる。
- **CAS 成功の返却も version の fsync 完了後**とする (§4)。
- DEK ローテは新 `dek_generation` 付きの新ファイルを書いてから rename する (rotation
  transaction の原子性、tri-review §1.2 の sol 指摘)。

#### 3a. 消せない crash 窓 (既知の限界)

外部 provider (IdP) との間に 2 相コミットは成立しないため、**「provider が新 RT を発行した
後、cw が durable ack を返す前」のクラッシュ窓は原理的に消せない**。この窓でクラッシュ
すると、cw は旧 RT を、provider は新 RT を正としてしまう。

回復契約を明記する: 再起動後の refresh は旧 RT で失敗する (strict rotation + reuse
detection の IdP ではトークンファミリーごと失効する)。この失敗は **`vault_locked` とは
区別できるエラーとして llm-gateway 側へ返し、llm-gateway は明示的な再認証フローへ落ちる**。
窓を狭めることはできる (provider 呼び出しの直後に最優先で永続化する) が、消せないことを
仕様として書く。

### 4. refresh 調停 — CAS + 着手時 claim

kawaz 裁定 8 (CAS 採用) + 裁定 17 (着手時 claim) により:

- 各 entry は **永続かつ単調な CAS version** を持つ。
- refresh を行う側は、provider を叩く**前に** entry を
  `refreshing(expected_version, expiry)` へ **CAS 遷移**させる。CAS に失敗した側は
  「他が着手済み」と判断し、provider を叩かずに新しい値を待つ / 読み直す。
- `expiry` 付きなので、claim したプロセスが死んでも stuck lock にならない (lease 方式の
  ロック回収問題が発生しない)。**requester 識別に依存しない**点は CAS の利点そのまま
  (pid チェックは llm-gateway 内の複数セッション/スレッドを区別できず識別根拠を持たない
  — 裁定 8)。
- **CAS 成功の返却は version の fsync 完了後**とする。クラッシュ後に version が巻き戻ると、
  「消費済みの RT を、まだ有効だと確信して再利用する」事故が起きる (tri-review §1.1 の
  opus C4)。version の単調性は永続化して初めて意味を持つ。
- **CAS だけでは provider 呼び出しは直列化できない**ことが、そもそも着手時 claim を足す
  理由である (CAS は書き戻しの勝者を決めるだけで、敗者も既に provider を叩いている)。
  claim を先に置くことで provider 呼び出し自体が 1 本に絞られる。
- **claim token (fencing)**: claim 取得時に daemon が不透明 token (16byte CSPRNG、
  base64url) を発行し、**claim が有効な間の書き戻し (`kv.set`) は正しい token の提示を
  要求する** (実装フェーズ 2 で追加、2026-08-14)。expiry + CAS だけでは「A が claim →
  停止 → expiry 経過 → B が claim」の後に**復活した A の書き戻しを弾けない** (その間
  version が動いていなければ expected_version が一致してしまう) ため。token は
  「現在有効な claim の保持者である」という **capability** であって requester の識別では
  なく、「requester 識別に依存しない」という本節の裁定と衝突しない。token は推測不能で
  ある必要がある (他プロセスによる claim の横取り・解放の防止) が秘密ではない。
- wire は `kv.claim` / `kv.unclaim` (pin/unpin と対称の命名)、`kv.set` に
  `expected_version` / `claim_token` を additive 追加、CAS 不一致は
  `cas_mismatch` + `current_version`、二重 claim は `already_claimed` +
  `claim_expires_in_secs`。
- **将来 TODO**: cw-owned entry の `kv.del` (§5 の「クレデンシャルを捨てる」重い操作)
  にも `expected_version` を要求する拡張。フェーズ 2 スコープ外として先送り。
- 認可との合成順序は **owner 認可 → CAS 検証 → 更新** (DR-0033 §3d)。

### 5. persist = cw-owned の一本化

- `persist` は **cw-owned** (cw 経由の更新が正本) と一体の属性とし、**op-cached** (op が
  正本で TTL 再 fetch する) entry への persist 指定は `BadRequest` で拒否する。直交する
  2 属性にしない (tri-review §2、opus M6 推し・統括同意)。
- **cw-owned は hard TTL を免除する**。refresh token に絶対寿命を課すのは自殺行為であり、
  「値が正本である間は生き続ける」が cw-owned の意味論である。soft TTL / pin / 再認証の
  扱いは従来どおり。
- **`kv del` した cw-owned entry は再生成されない**。op-cached なら del 後の get は
  definition 経由で op に取りに行くが、cw-owned は正本が cw 自身なので取りに行く先が無い。
  del は「このクレデンシャルを捨てる」操作であり、以後の get は明示的な再取得 (再認証
  フロー) を要求するエラーになる。これは裁定 6 の「op との縁切り」の直接の帰結である。
- 昇格 (op-cached → cw-owned): **初回 fetch 時に persist 指定があれば、その値が cw-owned
  として vault に入り、以後 op を見ない**。降格 (cw-owned → op-cached) は値の正本性が
  変わる不可逆な操作なので、v1 では提供しない (必要なら del してから定義し直す)。

### 6. locked 状態の状態機械と可観測性

初回アクセス時に自動でプロンプトを出す設計は prompt storm / hang / busy retry の三すくみに
なる (tri-review §1.6)。本 DR は明示コマンド起点を採る:

- **unlock は明示 `cw vault unlock` コマンド起点**。daemon 起動時に自動で unlock を試みない
  (無人起動を壊さない)。
- **locked 中も degraded モードで動く**: 永続 entry は「存在するが locked」として
  `status` / `kv list` に露出する (既存の defined / has_value 区分に `locked` を足すだけ)。
  値の取得だけが失敗し、entry の存在・定義・guard の有無は見える。
- **`vault_locked` を専用エラー種別**として wire に持つ。`auth_failed` と混同されると
  llm-gateway が再認可フローに落ちて**重複 grant を作る**事故が起きるため、
  「鍵が閉まっているだけ (unlock すれば読める)」と「認可がない (読めない)」を明確に分ける。
  §3a の「旧 RT が失効した」もこれらとは別の種別として扱う。
- **lock 契機**: 明示 `cw vault lock` / プロセス終了。idle timeout は **既定オフ**
  (config で有効化可。kawaz 裁定 2026-08-14: passkey の役目は起動時の鍵の取り出しと登録で
  あって存在確認ではない — llm-gateway 用途では unlock は起動直後の 1 回で以後無期限が正)。
  システム sleep での自動 lock も同理由で既定オフ。unlock 後の DEK は **mlock されたバッファに常駐**し (DR-0007)、lock 時に
  **zeroize** する (DR-0028 の `with_exposed` 経由でのみ触る)。
- **DEK の常駐期間そのものが v1 の弱点**であることを明記する。unlock 中は、cw プロセスの
  メモリを読める攻撃者に対して vault の暗号化は無力になる (これは全ての「開いている
  vault」に共通する性質であり、cw の既存 in-memory 秘密と同じ強度になるだけである)。

### 7. 配置・permission・metadata 漏洩

- **配置**: `$XDG_STATE_HOME/cache-warden/` 配下 (`~/.local/state/cache-warden/`)。
  ファイル 0600、ディレクトリ 0700。
- **開発 vault と本番 vault はファイルレベルで分離する** (裁定、tri-review §1.8)。
  `vault_id` を header に持ち、ファイル名も分ける。**localhost 系 RP ID のスロットが
  存在する vault は起動時に警告を出す** (最弱スロットが vault 全体の強度を決めるため、
  開発用スロットの本番混入は致命的)。「localhost で通ること」を production readiness に
  数えない。
- **旧 inode の残留**: write-then-rename は旧ファイルの内容を上書き消去しない。SSD の
  wear leveling も相まって、削除済みの旧世代 vault が物理的に残る可能性がある。これは
  「DEK ローテしても旧世代 ciphertext + 旧 DEK を知る者には無意味」という §1c の注意と
  同じ性質であり、**防御対象外として明記する** (真の失効は OAuth 側 revoke)。
- **Time Machine / Spotlight 除外**を検討する (実装時に `xattr` での除外設定の有無を判断。
  バックアップに vault が入ること自体は暗号化されているので致命的ではないが、旧世代の
  vault がバックアップに残ることで §8 の rollback 面が広がる)。
- **平文 metadata の範囲を明示する**: header に平文で載るのは vault_id / format_version /
  dek_generation / alg id / slot_id / 公開鍵 / salt / **RP ID / credential ID** / label /
  created_at。**entry 名・値・guard record・owner principal は body 側 (暗号化)** に置く。
  vault ファイルを読めた攻撃者に「どの passkey で開くか」は分かるが「何が入っているか」は
  分からない、という線引きにする。`status` / `kv list` / log への露出範囲も同じ線引きに
  従う (locked 中は entry 名を出す — これは既に in-memory 時代から露出している情報であり、
  degraded モードの可観測性 §6 のために必要)。
- **DESIGN の「秘密はディスクに書かれない」前提を更新する必要がある** (vault は cw 初の
  ディスク秘密面)。ハードニング前提の記述を「秘密は暗号化されずにディスクに書かれない」へ
  改める作業を実装フェーズに含める。

### 8. vault 粒度と signed-by の関係

- 単一 AEAD vault であるため、**unlock = 全 persist entry への復号能力**である。
  signed-by (DR-0033) は **返却時の認可**であって at-rest の区画化ではない。
  「entry ごとに別の鍵で暗号化されているから、owner でない者には物理的に読めない」という
  性質は**持たない** — unlock 済みの cw プロセスは全 entry を復号でき、owner 認可は
  そのプロセスが値を返すかどうかの判断でしかない。この線引きを明記する。
- 逆に言えば、cw プロセスの完全性が signed-by の実効性の前提である (DR-0033 §4 の
  「防げない」列と整合する)。

### 9. recovery slot

- **vault 初期化時に必須生成、スキップ不可** (裁定 18)。全 passkey 喪失時の唯一の回復
  経路であり、「縁切り」裁定 (cw が正本 = 失うと復旧不能) を採る以上、任意にできない。
- **256bit 級ランダム生成**。人間が選ぶ passphrase を許すと memory-hard KDF の設計問題に
  化けるため、生成のみを提供する。
- **独立媒体保管は強制不能なので、初期化時のユーザ向け案内メッセージとして明示する**
  (裁定 18: 「強制は無理、ユーザへのメッセージという意味」)。passkey も recovery key も
  同じ 1Password に入れると相関故障で全滅する、という趣旨を初期化時に表示する。
- **通常 unlock 経路から除外する**: `cw vault unlock --recovery` の明示指定 + **ローカル
  TouchID ゲート** + **試行の永続レート制限** (プロセス再起動で回数がリセットされない)。
  OR 合成の最弱リンクを攻撃者に自由に選ばせないための措置。

### 10. ceremony 経路 — DR-0032 の基盤を流用

- **ページ配信は daemon バイナリ埋め込み、TLS 終端のみ外出し** (DR-0032 の裁定そのまま)。
  issue 追記 10 の「serve を cw から分離する」は **TLS 終端の外出し**として読むのが正で
  あり、ページ配信まで外に出すと DR-0032 が WebRTC + 静的ホスティング案を却下した根拠
  (ホスティング侵害が緩和不能な信頼アンカーとして残る) が復活する。**caddy は
  reverse_proxy として daemon のローカル listener に向ける構成**が正しい実装形である。
- **RP ID は config で受ける**が、その定義は「**新規登録・新規 ceremony に使う値**」で
  ある。既存スロットは §1b のとおり登録時の RP ID / credential ID を自分で持っているので、
  config の rp_id を変更しても既存スロットは自分の RP ID で unlock を継続でき、
  **全滅しない**。RP ID 移行は「新 RP ID で新スロットを追加 → 旧スロットを削除 (= DEK
  ローテ)」という通常のスロット操作に自然に落ちる。
- **ブラウザ ceremony の PRF 露出面**: PRF 出力は JS 環境に一度現れるため、拡張機能 /
  DevTools / ブラウザプロファイル侵害で KEK が窃取されると、vault ファイルと組み合わせて
  全損する。対策として **厳格な CSP (外部 script 禁止、inline も nonce 限定) /
  `Cache-Control: no-store` / PRF 出力を DOM・console・log に一切出さない /
  TLS 終端プロキシを信頼境界に含める**ことを明記する。
- **`userVerification: required` を要求し、応答の UV flag を daemon 側で検証する**。
  findings が native API について「毎回 TouchID が出る保証は公開 API から確認できない」と
  述べているのは native 経路の話であり、**ブラウザ経路では UV を RP 側から強制できる**。
  native の悲観をブラウザ経路に波及させない。

### 11. graceful restart snapshot との正本関係

DR-0029 の handoff snapshot と vault はどちらも「再起動を越えて値を運ぶ」機構であり、
役割の重なりを整理する必要がある。本 DR の方針は:

- **vault は cw-owned entry の正本、snapshot は「開いている状態」の引き継ぎ**。
- **graceful restart の handoff には DEK を含め、再起動後も unlocked を維持する** (kawaz
  裁定 2026-08-14: 「当然含める。そのための graceful restart。upgrade で大量の TouchID を
  求められるのが嫌というところから来ている」)。handoff channel は匿名 socketpair で構造的に
  private であり、DR-0029 が既に秘密を運んでいるので DEK を足しても新しい信頼前提は
  生じない。
- **非 graceful な再起動 (PC 再起動 / crash)** では DEK は残らず、初回の unlock ceremony
  (passkey) が必要になる (同裁定)。

## セキュリティ整理

| 脅威 | 対策 / 評価 |
|---|---|
| vault ファイル窃取 (at-rest) | XChaCha20-Poly1305 + DEK。DEK は各スロット公開鍵へラップされ、秘密鍵は PRF 由来 KEK で暗号化 (§1b/§2) |
| header 改竄 (スロット差し替え / generation 巻き戻し / alg 弱体化) | header 全体を AEAD の AAD に含める (§1a) |
| format downgrade による認可・version の消失 | format_version の downgrade を拒否 (§1a)。認可要素を復元できなければ値も復元しない (§1d) |
| スロット削除の見かけ倒し | 削除は常に DEK ローテを伴う。公開鍵ラップなので ceremony ゼロで実行可能 (§1c) |
| 不正なスロット追加 (第三者 passkey の勝手な登録) | スロット追加は登録と同じローカル TouchID ゲート (§1c、裁定 7) |
| OR 合成による最弱リンク攻撃 | recovery slot を通常経路から除外 + `--recovery` 明示 + TouchID + 永続レート制限 (§9)。localhost スロット混入は vault 分離 + 起動警告 (§7) |
| ブラウザ経由の KEK 窃取 | 厳格 CSP / no-store / DOM・log 非出力 / TLS プロキシを信頼境界に明記 / UV required + UV flag 検証 (§10) |
| 承認 assertion の unlock への流用 | purpose を domain separation に含める。first-response-wins を unlock に流用しない (§2) |
| RT の二重 refresh によるトークンファミリー失効 | CAS + 着手時 claim で provider 呼び出しを 1 本に絞る (§4) |
| crash による version 巻き戻し → 消費済み RT の再利用 | CAS 成功の返却は fsync 完了後、version は永続かつ単調 (§4) |
| crash による新 RT の消失 | set ack は fsync 完了後 (§3)。provider 応答後〜durable ack 前の窓は消せない → 明示再認証への回復契約 (§3a) |
| 認可の cold start 消失 | guard record / owner principal / CAS version を vault に同梱 (§1d、DR-0033 §7) |
| vault ファイルの rollback (旧世代への丸ごと差し戻し) | **防御対象外と明記** (裁定 2026-08-14、Open Q2)。rollback 可能な攻撃者はオフライン復号で同等以上が既に可能。version 巻き戻りの実害は §3a の再認証回復契約で受け止める |
| unlock 中のメモリからの DEK 窃取 | mlock + zeroize + `with_exposed` (§6)。ただし unlock 中は既存の in-memory 秘密と同じ強度になるだけ、と明記 |
| 旧 inode / バックアップの残留 | 防御対象外と明記。真の失効は OAuth 側 revoke (§7) |

## Alternatives (不採用)

- **対称 KEK による直接ラップ (LUKS キースロット型)**: DEK 再ラップに残存全スロットの KEK
  が必要になり、「削除時に常時 DEK ローテ」が多デバイス構成で実行不能に近い (tri-review
  §1.2)。非対称 recipient (§1b) はこの問題を構造的に消す。
- **Secure Enclave 鍵 + biometryCurrentSet ACL** (findings の推奨): 端末束縛・非
  exportable・成熟した API という利点はあるが、**裁定 6 の「TouchID を中核に据えない /
  無人起動 + リモート解除を視野に入れる」方針と正面から衝突する**。また
  `biometryCurrentSet` は生体登録の変更で鍵が使えなくなるため、recovery 設計への依存が
  むしろ増える。将来「端末固定モード」を別モードとして足す余地は format の `kind` 拡張で
  確保する。
- **削除は header 除去のみ + rotate は明示コマンド化 + 未 rotate 警告** (opus 代替案):
  非対称スロットを採れば常時ローテが安価に実行できるため、「ローテし忘れた vault」という
  状態を作らない方が意味論が単純。
- **lease 方式による refresh 調停**: stuck lock の回収問題を持ち込む。CAS + expiry 付き
  claim は同じ効果をロック回収なしで得る (裁定 8)。
- **pid ベースの同一プロセスチェックによる調停**: llm-gateway 内の複数セッション/スレッドが
  同一クレデンシャルを共有するため、cw から対向スレッドを区別できず識別根拠を持たない
  (裁定 8)。
- **persist と cw-owned を直交する 2 属性にする**: op-cached への persist を許すと、op を
  正本とする値の古いコピーを cw が持ち続ける事故が起きる。一本化が意味論最単純 (§5)。
- **初回アクセス時の自動 unlock プロンプト**: prompt storm / hang / busy retry の三すくみ
  (tri-review §1.6)。明示コマンド + degraded モードを採る (§6)。
- **ROR (Related Origin Requests) による RP ID 移行の柔軟化**: per-slot RP ID 記録 (§1b) が
  移行問題を既に解いており、origin 1 つの構成では利得がない。加えて 1Password が ROR 未対応
  との情報があり、kawaz は passkey を 1Password 管理しているため前提にすると ceremony 自体が
  通らないリスクがある。**調査結果は「不要と判断できる根拠」として research に保持する**
  (issue 追記 11)。
- **リモート unlock (WebRTC 経路)**: DR-0032 で Tailscale 直達が裁定済みであり、v1 では
  リモート unlock 自体をスコープ外とする (将来 Tailscale 経路で対応)。

## v1 スコープ外

- **リモート unlock** (将来 Tailscale 経路で対応)
- **ROR** (上記のとおり不採用の根拠を記録して終わり)
- **スロット種別の網羅** (format の `kind` に拡張余地を確保するのみ。v1 実装は
  `passkey-prf` と `recovery` の 2 種)
- **通知チャネル統合** (DR-0032 側の課題)
- **cw-owned → op-cached の降格** (§5)
- **version 下限を含む requirement** (DR-0033 Open Q2)

## Open Questions

1. ~~graceful restart handoff に DEK を含めるか~~ — **裁定済み (2026-08-14): 含める**。
   §11 に反映済み。
2. ~~vault rollback 脅威の扱い~~ — **裁定済み (2026-08-14): 防御対象外と明記する**。
   根拠: rollback 可能な攻撃者 (same-uid でディスクに書ける) は旧ファイルのコピーを
   旧スロット秘密でオフライン復号する方が早く、**開示面で rollback 固有の新規攻撃は無い**
   (§7 の「過去コピーには失効が効かない」に包含される)。実害の本体は整合性/可用性 —
   CAS version の巻き戻りで消費済み RT を再利用しファミリー失効するが、§3a の回復契約
   (再認証フロー) で自己検出・回復する。外部単調カウンタ (Keychain/SE アンカー) が買えるのは
   fail-loud の検出能力のみで機密性は上がらず、Keychain/SE 依存 (裁定 6 と緊張) と
   アンカー破損時の復旧設計という対価に見合わない (不採用)。真の失効は OAuth 側 revoke。
3. ~~idle lock timeout の既定値~~ — **裁定済み (2026-08-14): 既定は idle lock なし**
   (unlock は明示 `cw vault lock` かプロセス終了まで持続、config で有効化可)。passkey の
   役目は「起動時の鍵の取り出しと登録」であって存在確認ではない (kawaz)。§6 の lock 契機
   から idle timeout を既定オフに変更。
4. **Time Machine / Spotlight 除外の実施可否** (§7): 除外設定が実際に効くか、
   ユーザ環境で勝手に設定してよいか (システム設定の書き換えになるなら案内に留めるべき)。
   実装時に実機確認。
5. **`objc2-authentication-services` / webauthn-rs のカバレッジ**: ブラウザ経路を採るので
   native PRF API への依存は無い見込みだが、daemon 側の assertion 検証で PRF 拡張の出力を
   扱えるか (webauthn-rs の PRF 拡張サポート状況) は実装前に compile PoC で確認する。
   **試験経路の補足** (kawaz 問い 2026-08-14 への回答): OS の platform authenticator に
   試験用鍵ペアを注入する口は無いが、試験は authenticator をソフトウェアで代替する 2 段で
   成立する — (a) 単体: WebAuthn assertion / PRF (= CTAP2 hmac-secret、HMAC-SHA256) は
   公開仕様どおり生鍵ペアから構築できるため、software authenticator (webauthn-rs の
   softtoken 等) で RP 検証・HKDF・unlock を TouchID ゼロで回す。(b) ブラウザ e2e:
   Chrome CDP の virtual authenticator (`WebAuthn.addVirtualAuthenticator`、hmac-secret
   対応) を注入する。1Password 拡張の passkey も本質は同じ「拡張自身が software
   authenticator として自前保管鍵で署名する」構造。

## 実装フェーズ想定 (accept 後)

1. **format 確定 + 単体実装** (ceremony 抜き): header / slot schema / AEAD / HKDF /
   atomic commit + fsync / downgrade 拒否。recovery slot だけで開ける vault を先に作る
   (ceremony 依存なしで durability と format を固められる)
2. **CAS + 着手時 claim** の実装 (§4)。永続単調 version と fsync 契約のテスト
3. **degraded モード + `vault_locked`** (§6)。unlock 前でも status / list が正しく動くこと
4. **passkey PRF スロット** (DR-0032 の ceremony 基盤に purpose 分離を足して接続、§2/§10)
5. **DR-0033 (signed-by) との結合** — owner principal と CAS version の vault 同梱 (§1d)
6. **llm-gateway 連携の dogfood** (control socket 直叩き経路、§5 の cw-owned 意味論の実運用検証)
