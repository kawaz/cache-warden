# draft-DR-0032: リモート承認 — 静的ページ + WebRTC DataChannel + passkey

- Status: Draft (構想段階、kawaz 議論待ち)
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

- **離席中の承認**: daemon マシンから物理的に離れている時に TouchID 承認要求が来る
  (prefetch / TTL 切れ / batch 処理) と、帰るまで全部ブロックされる
- **Linux / headless**: TouchID が存在しない環境ではローカル生体承認の経路自体が無い

kawaz 裁定 (2026-07-10): ローカル TouchID (DR-0031) とリモート承認 (本 DR) は
**どちらかを選ぶのではなく相補的に使えるようにする**。例: passkey 登録時はローカル
TouchID 承認を必須にする。

## 構想 (kawaz 原案 2026-07-10)

静的アセットをデプロイした GH Pages / Cloudflare Pages 等の承認ページを、candidate
付き URL で承認者のブラウザ (スマホ想定含む) で開き、daemon と WebRTC DataChannel で
ピアリング。チャンネル上で形式化されたメッセージを送受信して承認対象の情報を表示し、
passkey 認証で承認する。Linux でも使える。

## Decision (Draft)

### アーキテクチャ概要

```
[daemon (Rust)] ──(1) 承認セッション生成: URL 発行──▶ [承認者の手元 (スマホ等)]
      │                                                      │ URL を開く
      │◀─(2) シグナリング (極小中継: offer/answer/ICE)──▶ [静的承認ページ (ブラウザ)]
      │                                                      │
      │◀═(3) WebRTC DataChannel (DTLS、E2E)═══════════════▶│
      │   形式化メッセージ: 承認対象情報 / challenge /        │
      │   WebAuthn assertion                                  │
      │◀─(4) assertion を daemon 自身が検証 (RP = daemon)──│ passkey (TouchID/FaceID/生体)
```

構成要素:

1. **静的承認ページ**: GH Pages / Cloudflare Pages にデプロイする純クライアント JS。
   秘密・状態を一切持たない。WebAuthn は secure context 必須のため HTTPS 配信
   (両ホスティングとも満たす)
2. **極小シグナリング中継**: p2pcf 型 (Cloudflare Workers + R2、自前デプロイ) を
   第一候補とする。完全静的では answer (ブラウザ→daemon) を返す経路が存在しない
   (research 参照) ため、状態レスの受け渡しだけを行う極小中継を許容する
   **[要 kawaz 裁定: 完全静的への拘り度]**
3. **daemon 側 WebRTC**: webrtc-rs (pure Rust) で DataChannel のみ使用。
   FFI 系 (datachannel-rs) は notarize 運用との相性未調査のため第二候補
4. **TURN**: 「スマホ = LTE (CGNAT) ⇔ daemon = 家庭内 NAT」は symmetric NAT 同士に
   なりやすく TURN フォールバックがほぼ必須前提。既定は Open Relay 等の無料枠、
   config で差し替え可能にする

### シグナリング中継を信頼しない: URL fragment による SDP 認証

RFC 8827 の通り、DTLS fingerprint の MITM 耐性はシグナリング経路の完全性が前提。
第三者中継 (Cloudflare) を挟む以上、中継者による SDP 改ざん → MITM を防ぐ層が必要。
WebWormhole は PAKE (CPace) で解いているが、本設計では **candidate 付き URL 自体が
out-of-band チャネルとして既に存在する**ことを利用してより軽く解く:

- daemon が発行する承認 URL の **fragment (`#...`、サーバに送信されない)** に以下を同梱:
  - セッション ID (シグナリング room の特定)
  - **daemon の DTLS certificate fingerprint** (ブラウザが中継経由で受けた SDP と突合、
    不一致なら即中断)
  - セッションシークレット (シグナリングメッセージの HMAC 認証 + 承認ページ側の
    自己 SDP 保護)
- これにより中継は「妨害 (DoS) はできるが盗聴・なりすましはできない」立場に落ちる
- 安全性は **URL の配送経路の秘匿性**に集約される (配送経路は Open Question)

### WebAuthn: daemon 自身が RP

伝統的な RP バックエンド (サーバ) を持たず、daemon 自身が検証者になる
(research で条件付き成立を確認済み):

- **challenge は daemon が発行**し DataChannel で渡す。一意 (CSPRNG)・短寿命・
  使用済み管理を daemon 側で厳格に行う (同期 passkey は signCount 常時 0 のため
  clone/replay 検知は challenge 管理に全面依存)
- **challenge に operation context を埋め込む**: 承認対象 (kv key / 操作種別 /
  requester プロセスチェーン / guard 評価結果) のハッシュを challenge 生成に含め、
  同内容をページに表示する。静的ページが改ざんされた場合の confused deputy
  (見せている内容と署名対象の乖離) を「daemon 側で突合可能」にする
- **assertion 検証は webauthn-rs** (transport-agnostic 設計を確認済み):
  origin 厳密一致 (Relayed Phishing 対策で必須) / rpIdHash / signature / challenge
- **RP ID**: 静的ページのドメインに焼き付く (変更で登録済み passkey 全滅)。
  `<name>.github.io` は独立 eTLD+1 として使用可。初日から慎重に選ぶ
  **[Open Question: 独自ドメイン vs github.io]**

### 相補設計: 承認プロバイダ抽象と登録セレモニー

- daemon 側に **承認プロバイダ抽象**を置き、ローカル TouchID (DR-0031 helper) と
  リモート passkey (本 DR) が同じインターフェースに刺さる形にする。`[auth]` の
  type 化 (DR-0018) の将来枠 (`touchid` / `push`) がこの受け皿
- **passkey 登録 (registration ceremony) はローカル TouchID 承認必須**: 「どの公開鍵を
  daemon が信頼するか」を決める瞬間をローカル物理在席に束縛する。リモート資格情報の
  信頼の根が常にローカル承認に張られる (kawaz 裁定の相補例そのもの)
- ポリシー層: どの操作にどの承認レベル (local-only / remote-allowed / 両方要求) を
  要求するかを per-entry / per-operation で宣言できる形を想定 (DR-0030 の
  peer-identity constraint と同じ declarative 面に載せる)
- **プラットフォーム対応**: ローカル TouchID 面は macOS 専用 (DR-0031、Linux 対象外)、
  リモート承認面は macOS / Linux 共通。Linux ではリモート承認が唯一の対話的承認経路に
  なりうる (その場合の登録セレモニーの扱いは Open Question)

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

| 脅威 | 対策 |
|---|---|
| シグナリング中継 (CF) による SDP 改ざん MITM | URL fragment の DTLS fingerprint 突合 + セッションシークレット HMAC |
| 中継による盗聴 | fragment はサーバ非送信 + DataChannel は DTLS E2E |
| assertion replay | daemon 側 challenge の一意・短寿命・使用済み管理 (signCount 非依存) |
| Relayed Phishing / 別 origin | clientDataJSON `origin` 厳密一致検証 |
| 静的ページ改ざん (ホスティング侵害) | challenge への operation context 埋め込み + SRI/CSP。残存リスクは信頼前提として明記 |
| 不正な passkey 登録 | 登録セレモニーにローカル TouchID 必須 (相補設計) |
| URL 漏洩 | URL = セッション単位の短寿命シークレット。配送経路の秘匿 + 有効期限 + 単回使用 |
| 中継の DoS / 可用性 | 妨害されても安全性は落ちない (承認できないだけ)。フォールバックはローカル承認 |

## Alternatives (不採用方向)

- **完全静的 (中継ゼロ)**: answer の返送経路が無く、手動コピペ / QR 読み合いの UX に
  退化する。不採用 (ただし kawaz の拘り度次第で再考)
- **PAKE (CPace) による SDP 認証 (WebWormhole 方式)**: Rust/JS 両側の CPace 実装が
  最大の作業項目になる。URL fragment 方式が同等の脅威を軽い実装で塞ぐため不採用
- **daemon 内蔵 HTTP サーバ (SSH-Passkeys 方式)**: daemon への到達可能な公開 URL が
  必要になり、常設トンネリング (Cloudflare Tunnel 等) 依存に転嫁される。静的
  ホスティング前提と相性が悪く不採用
- **公開 relay 相乗り (ntfy.sh 等)**: トピック名が事実上の共有シークレットで攻撃面が
  広く、サードパーティ継続性にも依存。不採用

## Open Questions

- **Q1 (kawaz)**: シグナリング許容度 — 完全静的に拘るか、Cloudflare Workers 級の
  極小中継 (自前デプロイ、状態レス) まで許容か
- **Q2 (kawaz)**: URL の配送経路 — daemon からスマホへ承認 URL をどう届けるか。
  候補: push 通知サービス / メッセンジャー連携 / (在席時) QR 表示 / 事前ペアリング
  した常駐ページ。安全性がここに集約されるため本 DR の要
- **Q3**: RP ID のドメイン選定 — `<name>.github.io` / `*.pages.dev` / 独自ドメイン。
  変更で passkey 全滅のため初日に確定が必要
- **Q4**: Linux で登録セレモニーの「ローカル TouchID 必須」に相当する担保をどうするか
  (TouchID が無い)。候補: 初回はローカル console での確認操作 / macOS 側で登録した
  passkey を信頼リストとして同期
- **Q5**: TURN プロバイダの既定 (Open Relay 無料枠 vs 自前 coturn vs Cloudflare)
- **Q6**: 承認セッションの lifecycle — 承認要求ごとに URL 発行か、承認者と daemon の
  長期ペアリング (常駐 DataChannel) か
- **Q7**: passkey の失効・ローテーション運用 (登録一覧 / 削除 CLI)

## 実装フェーズ想定 (accept 後)

1. **PoC gate**: webrtc-rs DataChannel + p2pcf 型シグナリング + URL fragment 認証の
   疎通 PoC (静的ページ ↔ ローカル daemon、スマホ LTE 実機で TURN 経路確認)
2. WebAuthn 登録/認証セレモニー (webauthn-rs、DataChannel トランスポート)
3. 承認プロバイダ抽象への統合 (DR-0031 helper と同一インターフェース)
4. ポリシー層 (per-entry の承認レベル宣言、DR-0030 連携)
