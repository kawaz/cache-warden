# draft-DR-0032: リモート承認 — 静的ページ + WebRTC DataChannel + passkey

- Status: Draft (kawaz 議論中。codex 敵対的レビュー 10 findings 反映済み 2026-07-10。
  accept 前提条件 = §前提条件 の 4 項目の確定)
- Date: 2026-07-10
- 関連: draft-DR-0031 (custom TouchID dialog、**相補関係** = ローカル承認面) /
  draft-DR-0030 (peer-identity guard、承認 dialog/ページに載せる評価結果) /
  DR-0018 `[auth]` type 化 (`push` 将来枠の実体候補) /
  research `docs/research/2026-07-10-remote-approval-signaling.md` (シグナリング経路調査) /
  research `docs/research/2026-07-10-serverless-webauthn-rp.md` (サーバレス WebAuthn RP 成立性調査)

## Context

cache-warden の承認 (再認証) は現状 `[auth].command` (DR-0010) のみで、事実上
「daemon が動くマシンの前に居る」ことが前提になっている。draft-DR-0031 の custom
TouchID dialog はローカル承認の UX を引き上げるが、以下は救えない:

- **離席中の承認**: daemon マシンから物理的に離れている時に承認要求が来る
  (prefetch / TTL 切れ / batch 処理) と、帰るまで全部ブロックされる
- **Linux / headless**: TouchID が存在しない環境ではローカル生体承認の経路自体が無い

kawaz 裁定 (2026-07-10): ローカル TouchID (DR-0031) とリモート承認 (本 DR) は
**どちらかを選ぶのではなく相補的に使えるようにする**。例: passkey 登録時はローカル
TouchID 承認を必須にする。

### 適用範囲の明確化 (codex finding 8)

リモート承認が効くのは **cache-warden 自身の承認ゲート** (soft TTL 延長 / pin /
peer-identity guard の対話承認 / `[auth]` 再認証) に限る。**cold path (op fetch) の
TouchID は 1Password 側が出す biometric であり、cache-warden がリモート化する余地は
ない** (DR-0031 が cache MISS を 1Password dialog に委ねるのと同じ境界)。つまり
「離席中の承認」の実効範囲は hot cache / prefetched entries に対する再認証・延命で
あり、cold fetch は従来どおりローカル在席が必要。この制約は DR-0031 §適用範囲と
整合しており、prefetch + pin 運用 (外出前ウォームアップ、DR-0018) と組み合わせて
初めて離席運用が完結する。

## 構想 (kawaz 原案 2026-07-10)

静的アセットをデプロイした GH Pages / Cloudflare Pages 等の承認ページを、candidate
付き URL で承認者のブラウザ (スマホ想定含む) で開き、daemon と WebRTC DataChannel で
ピアリング。チャンネル上で形式化されたメッセージを送受信して承認対象の情報を表示し、
passkey 認証で承認する。Linux でも使える。

## 前提条件 (accept までに確定必須、codex findings 1/5/6/7/10)

本 DR の安全性主張は以下が確定して初めて成立する。未確定のまま実装に入らない:

1. **URL 配送経路の機密性・完全性** — macOS は裁定済み (iMessage 主経路 = E2E、
   下記 Q2 節)。**Linux daemon の配送チャネルは未定** (残 Open)
2. **RP ID (ドメイン) の確定** — 変更で登録済み passkey が全滅するため、
   **最初の登録セレモニーより前に**確定する。PoC 中の仮ドメイン登録も本番に
   持ち込まない (Q3)
3. **Linux での登録セレモニー担保の別途決定** — 「登録はローカル TouchID 必須」は
   macOS 限定の主張。Linux 対応はこの決定が Blocker (Q4)
4. **v1 のセッションモデルは単回使用に固定** — 承認要求ごとに URL 発行・単回・
   短寿命。長期ペアリング (常駐 DataChannel) はセキュリティ前提が根本から変わる
   ため本 DR の範囲外、必要になったら別 DR (Q6 は決定済みに昇格)

## Decision (Draft)

### アーキテクチャ概要

```
[daemon (Rust)] ──(1) 承認セッション生成: URL 発行──▶ [承認者の手元 (iPhone/iPad 等)]
      │              (macOS: iMessage / UC / AirDrop)         │ URL を開く
      │◀─(2) シグナリング (極小中継: offer/answer/ICE)──▶ [静的承認ページ (ブラウザ)]
      │                                                      │
      │◀═(3) WebRTC DataChannel (DTLS、E2E)═══════════════▶│
      │   形式化メッセージ: 承認対象情報 / challenge /        │
      │   WebAuthn assertion                                  │
      │◀─(4) assertion を daemon 自身が検証 (RP = daemon)──│ passkey (FaceID/生体)
```

構成要素:

1. **静的承認ページ**: GH Pages / Cloudflare Pages にデプロイする純クライアント JS。
   秘密・状態を一切持たない。WebAuthn は secure context 必須のため HTTPS 配信
   (両ホスティングとも満たす)
2. **極小シグナリング中継**: p2pcf 型 (Cloudflare Workers + R2、自前デプロイ) を
   第一候補とする。完全静的では answer (ブラウザ→daemon) を返す経路が存在しない
   (research 参照) ため、状態レスの受け渡しだけを行う極小中継を許容する
   **[要 kawaz 裁定: 完全静的への拘り度 (Q1)]**
3. **daemon 側 WebRTC**: webrtc-rs (pure Rust) で DataChannel のみ使用。
   FFI 系 (datachannel-rs) は notarize 運用との相性未調査のため第二候補
4. **TURN**: 「スマホ = LTE (CGNAT) ⇔ daemon = 家庭内 NAT」は symmetric NAT 同士に
   なりやすく TURN フォールバックがほぼ必須前提。既定は Open Relay 等の無料枠、
   config で差し替え可能にする

### シグナリング中継を信頼しない: URL fragment による SDP 認証

RFC 8827 の通り、DTLS fingerprint の MITM 耐性はシグナリング経路の完全性が前提。
第三者中継 (Cloudflare) を挟む以上、中継者による SDP 改ざん → MITM を防ぐ層が必要。
WebWormhole は PAKE (CPace) で解いているが、本設計では candidate 付き URL 自体が
out-of-band チャネルとして存在することを利用して軽く解く。

**正確な性格付け (codex finding 1)**: 本方式は PAKE の一般代替ではなく、
**「配送経路が機密性・完全性を持つ場合に限り有効な bearer-token channel」**である。
fragment はシグナリングサーバに送られないだけで、配送層 (iMessage / UC 等) では
URL 全体が露出する。したがって配送経路の性質が安全性の前提条件 (§前提条件 1)。
PAKE (低エントロピー秘密でも中継に対して安全) とは前提が異なる。

- daemon が発行する承認 URL の **fragment (`#...`、サーバに送信されない)** に同梱:
  - セッション ID (シグナリング room の特定)
  - **daemon の DTLS certificate fingerprint** (SDP 突合用)
  - セッションシークレット (シグナリングメッセージ認証用)
- これにより中継は「妨害 (DoS) はできるが盗聴・なりすましはできない」立場に落ちる

**ハンドシェイク検証の状態機械 (codex finding 2)**: 「不一致なら中断」では規定不足。
以下を仕様とする:

- シグナリング上の**全メッセージ** (offer / answer / trickle ICE candidate 含む) に、
  セッションシークレットを鍵とする **transcript MAC** (それまでの全メッセージ列を
  含む累積 MAC) + 単調増加のメッセージ番号 + セッション expiry を付与する
- 受信側 (ページ / daemon 双方) は **MAC・番号・expiry の検証に成功するまで、
  そのメッセージを WebRTC API (`setRemoteDescription` / `addIceCandidate`) に渡さない**
- ページは remote SDP 内の DTLS fingerprint を URL fragment の値と突合し、不一致は
  即中断 (再試行なし、セッション無効化)
- セッションは単回使用: 最初の DataChannel 確立 (または expiry) でシグナリング room
  を失効させ、同一セッション ID の再ハンドシェイクを daemon 側で拒否する
  (rollback / re-offer 誘導攻撃の排除)

### WebAuthn: daemon 自身が RP

伝統的な RP バックエンド (サーバ) を持たず、daemon 自身が検証者になる
(research で条件付き成立を確認済み):

- **challenge は daemon が発行**し DataChannel で渡す
- **challenge に operation context を埋め込む**: 承認対象 (kv key / 操作種別 /
  requester プロセスチェーン / guard 評価結果) のハッシュを challenge 生成に含め、
  同内容をページに表示する
- **assertion 検証は webauthn-rs** (transport-agnostic 設計を確認済み):
  origin 厳密一致 (Relayed Phishing 対策で必須) / rpIdHash / signature / challenge

**challenge lifecycle の仕様 (codex finding 4)**: 同期 passkey は signCount 常時 0 で
replay 対策が challenge 管理に全面依存するため、「厳格に管理」を以下に具体化する:

- challenge は **in-memory のみ** (disk 永続化しない)。daemon 再起動で全 challenge
  無効 (graceful restart の handoff 対象にも**含めない** = 再起動を跨ぐ承認セッション
  は作らない)
- CSPRNG 生成、**1 承認セッションにつき同時に 1 個だけ** outstanding。有効期限は
  短寿命 (分オーダー、承認 UI の操作時間のみ)。検証成功・失敗・期限切れのいずれでも
  即座に消費済みにする (単回使用)
- challenge は発行時の DataChannel セッション (= DTLS セッション) に紐付け、別
  セッションから届いた assertion は challenge が一致しても拒否する
- 時刻は daemon 側の単調時計で管理し、クライアント申告時刻に依存しない

### 相補設計: 承認プロバイダ抽象と登録セレモニー

- daemon 側に **承認プロバイダ抽象**を置き、ローカル TouchID (DR-0031 helper) と
  リモート passkey (本 DR) が同じインターフェースに刺さる形にする。`[auth]` の
  type 化 (DR-0018) の将来枠 (`touchid` / `push`) がこの受け皿
- **passkey 登録 (registration ceremony) はローカル TouchID 承認必須 — ただしこの
  主張は macOS 限定** (codex finding 6): 「どの公開鍵を daemon が信頼するか」を
  決める瞬間をローカル物理在席に束縛する。**Linux には TouchID が無いため、Linux で
  の登録担保は別途決定するまで Linux 対応は Blocked** (§前提条件 3)。候補: 初回登録
  をローカル console (物理 TTY / SSH 不可) での確認操作に限定 / macOS 側で登録した
  passkey 信頼リストを安全に同期
- ポリシー層: どの操作にどの承認レベル (local-only / remote-allowed / 両方要求) を
  要求するかを per-entry / per-operation で宣言できる形を想定 (DR-0030 の
  peer-identity constraint と同じ declarative 面に載せる)

### クロスデバイス UX

主経路は「**スマホのブラウザで URL を直接開き、スマホの platform authenticator
(FaceID/指紋) で承認**」。PC ブラウザ + hybrid transport (caBLE/QR) は完了率が
60〜86% 程度と低い (research 参照) ため補助経路扱い。

### 形式化メッセージ (DataChannel 上のプロトコル)

JSON ベースのメッセージスキーマをバージョン付きで定義する (詳細は実装 DR / spec で):

- `hello` (version negotiation) / `approval-request` (承認対象の構造化情報) /
  `webauthn-challenge` / `webauthn-assertion` / `result` / `error`
- 承認対象情報は DR-0030/0031 と共通の語彙 (requester chain / kv key / guard 評価結果)
  を使い、ローカル dialog とリモートページで同じ内容が見える状態を保つ

## セキュリティ整理

| 脅威 | 対策 / 評価 |
|---|---|
| シグナリング中継 (CF) による SDP 改ざん MITM | URL fragment の DTLS fingerprint 突合 + 全シグナリングメッセージの transcript MAC (状態機械は上記仕様) |
| 中継による盗聴 | fragment はサーバ非送信 + DataChannel は DTLS E2E |
| assertion replay | challenge lifecycle 仕様 (in-memory / 単回 / 短寿命 / セッション紐付け、signCount 非依存) |
| Relayed Phishing / 別 origin | clientDataJSON `origin` 厳密一致検証 |
| **静的ページ改ざん (ホスティング侵害)** | **緩和不能な残存リスクとして明記** (codex finding 3): operation context の challenge 埋め込みは daemon 側突合を可能にする必要条件だが、「ユーザが正しい内容を見て承認したか」は保証できない。改ざんページは表示と署名対象を乖離させられる。緩和: ページを最小 (監査可能・更新稀) に保つ / デプロイの immutable 化と変更監視 / 将来的な native app 化の余地。**ホスティングの完全性はこの設計の信頼アンカーの 1 つ**であり、これを許容できない場合はこの方式自体を採らない判断になる |
| 不正な passkey 登録 | 登録セレモニーにローカル TouchID 必須 (macOS。Linux は Blocked、§前提条件 3) |
| URL 漏洩 | URL = セッション単位の短寿命・単回使用シークレット。配送経路の機密性が前提条件 (§前提条件 1)。漏洩時も passkey なしでは承認不可だが、セッション先取り (DoS) と承認内容の閲覧は許す |
| 中継の DoS / 可用性 (codex finding 9) | 機密性・完全性は落ちない (安全側)。**可用性は別軸で評価**: macOS はローカル TouchID がフォールバックになるが、**Linux/headless ではリモート承認が唯一の対話経路になりうるため CF 障害 = 承認不能**。Linux 運用では非対話フォールバック (`[auth].command` / 承認不要ポリシー) の設計が必要 |
| メタデータ漏洩 (codex finding 9) | CF (シグナリング) / TURN provider には「いつ承認セッションが張られたか」「双方の IP」が見える (内容は見えない)。承認頻度・時間帯という行動パターンの漏洩は許容するトレードオフとして明記。許容できない場合は自前 TURN/中継に差し替え可能な構成にする |

## Alternatives (不採用方向)

- **完全静的 (中継ゼロ)**: answer の返送経路が無く、手動コピペ / QR 読み合いの UX に
  退化する。不採用 (ただし kawaz の拘り度次第で再考)
- **PAKE (CPace) による SDP 認証 (WebWormhole 方式)**: Rust/JS 両側の CPace 実装が
  最大の作業項目になる。配送経路が機密・完全 (iMessage E2E) である前提を置けるため、
  URL fragment 方式で足りると判断。**配送経路にその前提を置けなくなったら PAKE を
  再検討する** (この条件付きで不採用)
- **daemon 内蔵 HTTP サーバ (SSH-Passkeys 方式)**: daemon への到達可能な公開 URL が
  必要になり、常設トンネリング (Cloudflare Tunnel 等) 依存に転嫁される。静的
  ホスティング前提と相性が悪く不採用
- **公開 relay 相乗り (ntfy.sh 等)**: トピック名が事実上の共有シークレットで攻撃面が
  広く、サードパーティ継続性にも依存。不採用
- **長期ペアリング (常駐 DataChannel) の v1 採用**: 「短寿命・単回使用」の
  セキュリティ前提が根本から変わるため v1 から除外、必要になったら別 DR
  (codex finding 10)

## Open Questions

- **Q1 (kawaz)**: シグナリング許容度 — 完全静的に拘るか、Cloudflare Workers 級の
  極小中継 (自前デプロイ、状態レス) まで許容か
- **Q2 (kawaz 方向性裁定済み 2026-07-10)**: URL の配送経路 — kawaz 環境 (mac +
  iPhone/iPad) では **Apple 純正チャネル (AirDrop / iMessage / ユニバーサル
  クリップボード) を使う**。分析の結果、経路は用途で分かれる:
  - **iMessage = 主経路**: 3 案で唯一の真のリモート対応 (E2E のままどこでも届く)。
    daemon から `osascript` で Messages.app 経由の自分宛送信を自動化可能
    (Automation TCC 初回 1 回)
  - **ユニバーサルクリップボード = 近接時の簡易経路**: `pbcopy` 一発で最も簡単、
    UC 同期は約 2 分失効で短寿命 URL と整合。ただし近接 + 同一 iCloud + Handoff
    必須で離席中は不可、クリップボードは両デバイスの任意アプリから可読 (URL 単回
    使用 + 短 TTL が前提条件)
  - **AirDrop = 近接時の手動フォールバック**: 秘匿は硬いが近接必須 + 自動化が弱い
    (share sheet 介在 + 受信側受諾)
  - AirDrop/UC は近接必須のため「離席中の承認」は iMessage のみが満たす。近接時は
    ローカル TouchID (DR-0031) が本来の経路で、UC/AirDrop は「手元の iPad で内容を
    確認したい」等の補助用途
  - **配送チャネルはプラガブルにする**: 上記は daemon = macOS 前提の Apple
    エコシステム依存。Linux daemon 用は ntfy/push 系等を別チャネルとして追加できる
    抽象にする (残 Open: Linux 既定チャネルの選定)
  - 実装配置 (kawaz 裁定 2026-07-10): **TCC + notarization を要する機能は今後も
    増える前提で、helper / daemon に集中的に持たせる方針で OK**。op 利用のため既に
    FDA (Full Disk Access) を daemon に許可しており、Automation TCC が増えるのも
    許容。iMessage 送信の具体配置 (daemon 直 vs helper 経由) は実装時に決める
- **Q3**: RP ID のドメイン選定 — `<name>.github.io` / `*.pages.dev` / 独自ドメイン。
  **最初の登録セレモニー前に確定必須** (§前提条件 2)。PoC は使い捨て前提の仮
  ドメインで行い、本番登録を作らない
- **Q4 (Blocker for Linux)**: Linux で登録セレモニーの「ローカル TouchID 必須」に
  相当する担保 (§前提条件 3)。候補: ローカル console 限定の確認操作 / macOS 側
  登録の信頼リスト同期
- **Q5**: TURN プロバイダの既定 (Open Relay 無料枠 vs 自前 coturn vs Cloudflare)
- **Q7**: passkey の失効・ローテーション運用 (登録一覧 / 削除 CLI)

(旧 Q6 セッション lifecycle は「v1 = 単回使用固定、長期ペアリングは別 DR」で決定済み、
§前提条件 4)

## 実装フェーズ想定 (accept 後)

1. **PoC gate**: webrtc-rs DataChannel + p2pcf 型シグナリング + URL fragment 認証
   (transcript MAC 込み) の疎通 PoC (静的ページ ↔ ローカル daemon、スマホ LTE 実機で
   TURN 経路確認)。PoC では passkey 登録を作らない (RP ID 未確定のため)
2. WebAuthn 登録/認証セレモニー (webauthn-rs、DataChannel トランスポート、challenge
   lifecycle 仕様の実装)
3. 承認プロバイダ抽象への統合 (DR-0031 helper と同一インターフェース)
4. ポリシー層 (per-entry の承認レベル宣言、DR-0030 連携)
