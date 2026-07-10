# リモート承認: 静的ホスティング + WebRTC のシグナリング経路調査

調査日: 2026-07-10。draft-DR-0032 (リモート承認) の設計材料。
「静的アセット (GH Pages / Cloudflare Pages) にデプロイした承認ページを candidate 付き
URL で開き、daemon と WebRTC DataChannel でピアリングする」構想に対し、シグナリング
経路の選択肢・先行実装・NAT 越えの実情・Rust 実装距離を調査した (read-only recon)。

## 判明した事実

- **WebRTC の MITM 耐性はシグナリング経路の完全性が前提**: RFC 8827 は DTLS
  fingerprint による MITM 対策の前提として「signaling チャネル自体の完全性」を要求する
  (https://webrtcforthecurious.com/docs/04-securing/,
  https://rtcweb-wg.github.io/security-arch/)。第三者中継 (Cloudflare 等) を挟む場合、
  その運営者/侵入者は SDP 改ざんで MITM 可能。塞ぐには out-of-band な共有シークレット
  で SDP を認証する層が別途必須
- **完全静的ホスティングだけでは双方向シグナリングが成立しない**: URL fragment に
  offer SDP を埋め込む方向 (daemon→ブラウザ) は可能だが、answer をブラウザ→daemon に
  返す経路が静的アセットには存在しない。何らかの中継 (極小 Workers / 公開 relay /
  手動コピペ) が必要
- **p2pcf** (https://github.com/gfodor/p2pcf) が「静的ホスティング + 最小インフラ」に
  最も近い先行実装: Cloudflare Workers + R2、HTTP ポーリング (idle backoff)。無料枠
  (Workers 月 300 万 req、R2 月 100 万 write / 1000 万 read) に収まりやすい。ただし
  SDP 改ざん耐性はアプリ側の未実装課題
- **WebWormhole** (https://github.com/saljam/webwormhole) は専用シグナリングサーバ
  (slot system, WS) + **PAKE (CPace) で SDP 自体を認証**し、シグナリングサーバを信頼
  モデルから排除する設計。ただしサーバのデプロイが必要 (完全静的では成立しない)
- **serverless-webrtc** (https://github.com/cjb/serverless-webrtc) は offer/answer を
  IM 等で手動交換する完全サーバレス実証。UX は完全手動
- **NAT 越え**: 住宅同士の STUN 成功率は報告により 75〜90% と幅 (metered.ca、未確認)。
  住宅用 NAT 機器の約 6 割が symmetric NAT という推計あり。**LTE (CGNAT) は symmetric
  NAT 挙動になりやすい** (未確認) — 「スマホ = LTE ⇔ daemon = 家庭内 NAT」は TURN
  必須になりやすい構成。TURN フォールバック率は文献により 8〜30% (未確認)
- **TURN の選択肢**: Open Relay Project (metered.ca、無料 20GB/月) / Cloudflare
  Realtime TURN (単体 $0.05/GB) / 自前 coturn
- **Rust 側**: webrtc-rs (https://webrtc.rs) が DataChannel 用途で活発保守中 (2022 に
  モノレポ統合、sans-IO 系 `webrtc-rs/rtc` も並行開発)。`datachannel-rs` は C++
  libdatachannel への FFI ラッパー (notarize 運用でのクロスコンパイル・署名への影響は
  未調査)

## 実用的な示唆 (cache-warden への含意)

- 推奨構成: **p2pcf 型 (Cloudflare Workers + R2、自前デプロイ) の極小シグナリング**。
  完全静的に拘ると手動コピペ/QR が残り UX が崩れる
- SDP 改ざん耐性は PAKE (CPace) 自作より軽い解がある: **candidate 付き URL の fragment
  (サーバに送信されない) に daemon の DTLS certificate fingerprint + セッション
  シークレットを同梱**すれば、URL 配送経路そのものが out-of-band チャネルになり、
  ブラウザは中継経由 SDP を URL 内 fingerprint と突合するだけで改ざん検出できる。
  安全性は URL 配送経路の秘匿性に集約される (draft-DR-0032 で設計)
- TURN はほぼ必須前提で設計する (Open Relay 無料枠で開始、設定で差し替え可能に)
- webrtc-rs (pure Rust) を第一候補にする (FFI 依存の datachannel-rs は署名運用との
  相性が未調査)

## 検証の詳細

### シグナリング経路の比較

| 経路 | インフラ | コスト | 可用性依存 | 盗聴/改ざん耐性 | 攻撃面 |
|---|---|---|---|---|---|
| Cloudflare Workers + Durable Objects (WS) | Cloudflare のみ | 無料枠内で収まりやすい | Cloudflare 依存 | TLS 区間は保護されるが CF 運営者は SDP 平文閲覧可能 | room id 漏洩/推測 |
| p2pcf (Workers + R2, HTTP ポーリング) | Workers + R2 | 無料枠内 | Cloudflare 依存 (作者は自前デプロイ推奨) | セキュリティ機構の明記なし、DTLS/SRTP 依存のみ | 同上 |
| 公開 relay (ntfy.sh 等) | 既存サービス相乗り | 実質無料 | サードパーティ継続性依存、WebRTC 専用でない | トピック名 = 事実上の共有シークレット | トピック推測・購読が容易 |
| PeerJS 公式クラウド | 不要 | 無料だが本番非推奨 | 共有サーバ依存、ID 衝突リスク明記あり | 暗号化保証なし | なりすまし余地 |
| 自前 WebSocket 中継 | 常時稼働サーバ | 発生 | 自己責任 | 実装次第 | 自前実装バグ依存 |
| copy-paste / QR 手動 | 不要 | ゼロ | 完全自己完結 | 中間者介在なし (理論上最強) | ほぼゼロ、UX コスト大 |

### 先行実装のシグナリングの解き方

- serverless-webrtc: offer/answer テキストを IM 等で手動交換、`file:///` で動作。
  サーバ皆無だが UX は完全手動
- WebWormhole: 専用シグナリングサーバ + PAKE (CPace) で SDP 認証、サーバを信頼モデル
  から排除。WASM クライアントのプリコンパイルが必要
- p2pcf: Workers + R2、HTTP ポーリング。認証・暗号化はアプリ側の課題
- PeerJS: 公式クラウド WS シグナリング、開発体験は良いが本番非推奨

### 不採用方向の考察

- **daemon 内蔵シグナリング (WebWormhole 型自前ホスト)**: 第三者インフラ依存はゼロに
  なるが「daemon にどう到達可能な公開 URL を用意するか」という別問題 (Cloudflare
  Tunnel 等の常設トンネリング依存) に転嫁され、静的ホスティング前提と相性が悪い

### 未確認事項

- STUN 成功率 / TURN フォールバック率の数値 (出典によりばらつき、一次計測なし)
- LTE CGNAT の symmetric NAT 挙動 (一般論として言及多数、一次資料未到達)
- datachannel-rs (FFI) の notarize 運用への影響
