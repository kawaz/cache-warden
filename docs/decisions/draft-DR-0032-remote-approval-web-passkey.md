# draft-DR-0032: リモート承認 — Tailscale 直達 + daemon 配信承認ページ + passkey

- Status: Draft (**方式は kawaz 裁定済み 2026-07-10: Tailscale 直達で OK**。
  WebRTC + 静的ホスティング案からの転換、旧案は §Alternatives 参照。
  Tailscale recon 反映済み — **accept 判断可能な状態**。実機検証 2 項目は PoC gate)
- Date: 2026-07-10
- 関連: draft-DR-0031 (custom TouchID dialog、**相補関係** = ローカル承認面) /
  draft-DR-0030 (peer-identity guard、承認ページに載せる評価結果) /
  DR-0018 `[auth]` type 化 (`push` 将来枠の実体候補) /
  research `docs/research/2026-07-10-remote-approval-signaling.md` (旧 WebRTC 案の
  シグナリング調査、不採用判断の根拠として保持) /
  research `docs/research/2026-07-10-serverless-webauthn-rp.md` (daemon = WebAuthn RP
  の成立性調査、本案でも有効) /
  research `docs/research/2026-07-10-tailscale-approval-hosting.md` (Tailscale cert /
  RP ID / ACL / iOS の詳細調査)

## Context

cache-warden の承認 (再認証) は現状 `[auth].command` (DR-0010) のみで、事実上
「daemon が動くマシンの前に居る」ことが前提になっている。draft-DR-0031 の custom
TouchID dialog はローカル承認の UX を引き上げるが、以下は救えない:

- **離席中の承認**: daemon マシンから物理的に離れている時に承認要求が来る
  (prefetch / TTL 切れ / batch 処理) と、帰るまで全部ブロックされる
- **Linux / headless**: TouchID が存在しない環境ではローカル生体承認の経路自体が無い

kawaz 裁定 (2026-07-10):

1. ローカル TouchID (DR-0031) とリモート承認 (本 DR) は**どちらかを選ぶのではなく
   相補的に使えるようにする**。例: passkey 登録時はローカル TouchID 承認を必須にする
2. 方式は **Tailscale 経由で OK** (codex アーキレビューが提示した対抗案を採用。
   当初の静的ページ + WebRTC 案は実装・攻撃面が大きく、個人 dogfood の投資対効果で
   劣後。§Alternatives)
3. TCC + notarization を要する機能は helper / daemon に集中的に持たせる方針で OK
   (Automation TCC の追加も許容)

### 適用範囲の明確化

リモート承認が効くのは **cache-warden 自身の承認ゲート** (soft TTL 延長 / pin /
peer-identity guard の対話承認 / `[auth]` 再認証) に限る。**cold path (op fetch) の
TouchID は 1Password 側が出す biometric であり、cache-warden がリモート化する余地は
ない** (DR-0031 が cache MISS を 1Password dialog に委ねるのと同じ境界)。つまり
「離席中の承認」の実効範囲は hot cache / prefetched entries に対する再認証・延命で
あり、cold fetch は従来どおりローカル在席が必要。prefetch + pin 運用 (外出前
ウォームアップ、DR-0018) と組み合わせて初めて離席運用が完結する。

**cold path の白紙委任の緩和オプション** (kawaz 指摘 2026-07-10「1P dialog 単体では
requester / 目的の情報をユーザに出せない」への回答): 1Password dialog の表示内容には
介入できないが、**cold fetch 発火の直前に cache-warden 側の情報付き事前承認ステップ**
(自前 dialog で requester chain / entry / 操作種別を提示、生体不要の approve/cancel
でも可) を挟むことで、直後の 1P TouchID を「直前に内容確認した要求の実行確認」に
意味付けし直せる。1 ステップ増える操作感とのトレードオフなので per-entry の opt-in
ポリシーとし、採否・詳細は実装 DR で (DR-0031 の dialog 実装をそのまま流用できる)。

## Decision (Draft)

### アーキテクチャ概要

```
[daemon (Rust)] ── tailnet 内 HTTPS で承認ページ + 承認 API を自前配信 ──┐
      │            (tailscale cert の証明書 / <node>.<tailnet>.ts.net)      │
      │                                                                    ▼
      │◀── WireGuard (Tailscale) E2E ──── [承認者の iPhone/iPad/PC のブラウザ]
      │    challenge / assertion は                │ Tailscale app 常駐 (VPN)
      │    同一 HTTPS セッション上                  │ passkey (FaceID/生体) で承認
      │
      └──(通知) iMessage 等で「承認要求あり + URL」を配送 (通知は情報のみ、secret ではない)
```

構成要素:

1. **daemon 内蔵の承認 HTTP サーバ — TLS 終端は daemon 責務外** (Q9、kawaz 裁定
   2026-07-10 で確定): daemon は承認ページ (最小の静的 HTML/JS、バイナリ埋め込み) と
   承認 API を **ローカル HTTP listener** で提供し、**TLS 終端と tailnet への経路は
   外側 (`tailscale serve` 等) に任せる。証明書管理・更新は cache-warden の実装
   スコープに含めない** (kawaz: 「証明書の心配はしなくて良い。serve を使うなどで
   解決できるし経路問題は別途考えておく」)。daemon 側は RP ID / expected origin を
   config で受け取るだけにし、TLS 終端方式の変更 (serve / 自前 cert / 別プロキシ) に
   対して不変になる。recon が示した非 root LocalAPI cert 取得の未知数・90 日更新
   スケジューラは**この裁定でスコープごと消滅**
2. **到達性 = tailnet 限定**: 承認エンドポイントには tailnet 参加デバイスしか到達
   できない。**tailnet ACL は承認者デバイスに専用 tag (例 `tag:cw-approver`) を付与
   し、`grants`/ACL でその tag のみが承認ポートへ到達可能と制限する** (Q10 確定)。
   **Funnel (公開露出) は使わない** — 稼働ノードに `funnel` nodeAttr を**そもそも
   付与しない**運用で、コード側誤操作を tailnet 側でブロックする二重防御にする
   (disable が効かないバグ報告 #15248 があるため属性非付与が確実)
3. **WebRTC / シグナリング中継 / TURN / 静的ホスティングは全部不要** (旧案から削除)。
   NAT 越えとトランスポート暗号は Tailscale (WireGuard) が解決済み

### URL は secret ではない (旧案からの重要な単純化)

旧 WebRTC 案では URL fragment が bearer secret でセッション安全性の要だった。本案
では:

- **gate は「tailnet 到達性」+「passkey assertion」の 2 段**であり、URL 自体は
  何も許可しない (tailnet 外から開けず、tailnet 内でも passkey なしに承認不可)
- したがって承認ページは**固定 URL** (`https://<node>.<tailnet>.ts.net/approve` 等、
  ブックマーク可能) でよく、pending 承認一覧をそこに表示する
- 通知 (iMessage 等) は「承認要求が来ている」という**情報伝達 + deep link の利便**に
  格下げされる。通知が漏れても・履歴に残っても安全性への影響なし
- ページの完全性も daemon 配下 (バイナリ埋め込み) なので、旧案の「静的ホスティング
  侵害 = 緩和不能な信頼アンカー」問題が消滅する

### 通知チャネル (kawaz 裁定 2026-07-10: Apple 純正チャネル)

kawaz 環境 (mac + iPhone/iPad) では:

- **iMessage = 主経路**: 唯一の真のリモート対応 (E2E のままどこでも届く)。daemon
  から `osascript` で Messages.app 経由の自分宛送信を自動化可能 (Automation TCC
  初回 1 回。TCC 集約は kawaz 裁定済み)
- **ユニバーサルクリップボード / AirDrop = 近接時の補助** (近接必須のため離席中は
  不可。近接時は本来ローカル TouchID の領分)
- **チャネルはプラガブル**: Linux daemon 用は ntfy / push 系等を追加できる抽象。
  URL が secret でなくなったため、チャネルへの機密性要求は旧案より大幅に緩い
  (完全性・到達性があれば十分)

**通知の失敗系** (codex 2 巡目 High): 送信の成否を検証する (exit code + エラー
出力捕捉。失敗分類: Messages 未サインイン / Automation TCC 未許可 / 送信エラー)。
失敗時は黙らない — ローカル通知 + ログ + `status` に pending 承認セッションと配送
結果を露出。承認ページが固定 URL なので、**通知が失敗しても承認者が自発的にページを
開けば承認できる** (旧案より縮退が穏やか)。成否検証と失敗分類はチャネル抽象の
インターフェースに含める。

### WebAuthn: daemon 自身が RP

伝統的な RP バックエンドを持たず、daemon 自身が検証者になる (research で条件付き
成立を確認済み。本案では通常の HTTPS 上の WebAuthn になるため、旧案の「DataChannel
越し」という未確認領域も消える):

- **RP ID = 承認ページの origin ドメインの host 完全一致。ドメイン選定は経路設計と
  一体で kawaz 裁量** (Q3'、kawaz 裁定 2026-07-10: 「ドメインも色々所有してるし
  気にしなくて良い」): daemon は RP ID / expected origin を config で受けるだけで、
  ドメインに依存しない。選択肢の性質だけ記録する:
  - **自己所有ドメイン** (推奨): kawaz 管理下で安定、tailnet rename の影響を受けない
    = 「rename で passkey 全滅」リスクが構造的に消える
  - **`<node>.<tailnet>.ts.net`**: PSL 上問題なし (recon 確認済み、vaultwarden の
    WebAuthn 運用実績あり) だが、tailnet rename (稀) で passkey 全滅 → 再登録が必要
  - いずれでも **最初の登録セレモニー前に確定**が必要 (RP ID 変更 = 登録済み passkey
    無効化、という WebAuthn 自体の制約は不変)
- **challenge は daemon が発行**。一意 (CSPRNG)・短寿命・使用済み管理:
  - challenge は **in-memory のみ** (disk 永続化しない)。daemon 再起動で全 challenge
    無効 (graceful restart の handoff 対象にも含めない)。restart 中の承認セッション
    は失効し、requester へはタイムアウトと同じ形 (auth 失敗) で返る
  - **1 承認セッションにつき同時に 1 個だけ** outstanding、短寿命 (分オーダー)、
    検証成功・失敗・期限切れのいずれでも即消費 (単回使用)
  - challenge は発行時の HTTPS セッションに紐付け、別セッションからの assertion は
    拒否
  - 時刻は daemon 側の単調時計で管理
  - 同期 passkey は signCount 常時 0 のため replay 対策はこの challenge 管理に全面
    依存 (research 参照)
- **challenge に operation context を埋め込む**: 承認対象 (kv key / 操作種別 /
  requester チェーン / guard 評価結果) のハッシュを challenge 生成に含め、同内容を
  ページに表示。daemon 側で「署名された承認対象」と「提示した承認対象」を突合可能に
  する
- **assertion 検証は webauthn-rs**: origin 厳密一致 (Relayed Phishing 対策で必須) /
  rpIdHash / signature / challenge

### 相補設計: 承認プロバイダ抽象と登録セレモニー

- daemon 側に **承認プロバイダ抽象**を置き、ローカル TouchID (DR-0031 helper) と
  リモート passkey (本 DR) が同じインターフェースに刺さる。`[auth]` の type 化
  (DR-0018) の将来枠 (`touchid` / `push`) がこの受け皿
- **passkey 登録 (registration ceremony) はローカル TouchID 承認必須 — この主張は
  macOS 限定**: 「どの公開鍵を daemon が信頼するか」を決める瞬間をローカル物理在席に
  束縛する。**Linux での登録担保は別途決定するまで Linux 対応は Blocked** (Q4)。
  候補: 初回登録をローカル console (物理 TTY / SSH 不可) での確認操作に限定 /
  macOS 側で登録した passkey 信頼リストを安全に同期
- ポリシー層: どの操作にどの承認レベル (local-only / remote-allowed / 両方要求) を
  per-entry / per-operation で宣言できる形 (DR-0030 と同じ declarative 面)
- **guard 拒否はリモート承認のバイパス経路にならない**: DR-0030 の peer-identity
  guard が拒否した要求は fail-closed で終端し、ローカル dialog を出さない (DR-0031
  と同一規定) のと同様、**リモート承認セッションも生成しない**。リモート承認が
  上書きできるのは「承認を要する」状態だけ

### ローカル/リモート同時発火の統合仕様 (提案)

1 つの承認要求に対し両プロバイダが有効な場合 (単一ユーザ前提):

- **並行提示 + first-response-wins**: ポリシーが両方許可する要求は、ローカル dialog
  とリモート承認を並行提示してよい。最初に届いた応答 (approve / deny いずれも) で
  セッション全体が確定し、他方は即取り下げ (dialog dismiss / challenge 消費)
- 応答競合 (ほぼ同時) は daemon 到着順で確定。2 番目は「確定済み」として無視
- タイムアウトは承認要求全体で 1 個 (プロバイダ別に持たない)。満了で両面取り下げ、
  requester へは既存の auth 失敗と同じ形で返る
- 二重操作 (両面で生体を押す) は first-wins により 2 回目が no-op になるだけ

### 承認ページの表示

- 承認対象情報は DR-0030/0031 と共通の語彙 (requester chain / kv key / guard 評価
  結果) を使い、ローカル dialog とリモートページで同じ内容が見える状態を保つ
- リモートに流す詳細度 (フルパス・pid を出すか要約に絞るか) は実装 DR で検討
  **[Open Q8]** — 本案ではページ改ざんリスクが消えたため旧案より緩くできる余地あり

## セキュリティ整理

| 脅威 | 対策 / 評価 |
|---|---|
| トランスポート MITM | Tailscale (WireGuard) E2E + tailnet 内 HTTPS (`tailscale cert`)。旧案の transcript MAC / fragment 突合は不要になり削除 |
| 承認エンドポイントへの不正到達 | tailnet 参加が前提 + ACL で承認者デバイスに限定 (Q10)。**Funnel は使わない** (公開露出の誤有効化を register/実装時に guard) |
| assertion replay | challenge lifecycle 仕様 (in-memory / 単回 / 短寿命 / HTTPS セッション紐付け、signCount 非依存) |
| Relayed Phishing / 別 origin | clientDataJSON `origin` 厳密一致検証 |
| 承認ページ改ざん | ページは daemon バイナリ埋め込み配信のため、ホスティング侵害の脅威モデル自体が消滅 (旧案の主要残存リスクの解消)。残るのは daemon バイナリ自体の完全性 = 既存の署名・notarization 境界 (DR-0020) と同一 |
| 不正な passkey 登録 | 登録セレモニーにローカル TouchID 必須 (macOS。Linux は Blocked = Q4) |
| URL / 通知の漏洩 | URL は secret ではない (tailnet 到達性 + passkey が gate)。iMessage 履歴残留・通知漏洩は安全性に影響なし |
| Tailscale への信頼 | coordination server は接続メタデータ (どのデバイスがいつ通信したか、DERP relay 経由時は中継トラフィック量) を観測可能、データ面は WireGuard E2E で内容不可視。**Tailscale アカウント/コーディネーション侵害で attacker のデバイスが tailnet に参加しうる**が、参加できても passkey なしに承認は不可 (2 段 gate の価値)。ACL 変更の監査は Tailscale 側機能に依存 |
| 可用性 | Tailscale 障害 / VPN 未接続時はリモート承認不能。macOS はローカル TouchID にフォールバック。Linux は非対話フォールバック (`[auth].command` / 承認不要ポリシー) の設計が必要 (旧案と同じ)。承認ページ固定 URL のため通知障害単独では承認不能にならない |
| 承認疲れ (approval fatigue) | ポリシー層で「リモート承認を要求する操作」を絞る + prefetch/pin (DR-0018) で承認頻度自体を下げる。頻度の実測は dogfood で確認 |

## Alternatives (不採用)

- **静的ページ (GH Pages / Cloudflare Pages) + WebRTC DataChannel + 極小シグナリング
  中継 (p2pcf 型) + URL fragment 認証** (当初案、kawaz 原案ベースで一旦 draft 化):
  シグナリング中継の信頼問題 (RFC 8827) を URL fragment の bearer-token 方式で塞ぎ、
  TURN (LTE CGNAT ⇔ 家庭内 NAT で必須級)・transcript MAC 状態機械・challenge の
  DataChannel 紐付けまで仕様化したが、codex アーキレビューの対称評価で **Tailscale
  直達に対し実装・攻撃面の両方で劣後** (自前 WebRTC + 自前シグナリング + DataChannel
  越し WebAuthn という実績未確認領域 3 つ、静的ホスティング侵害が緩和不能な信頼
  アンカーとして残る、CF/TURN への IP メタデータ漏洩)。優位点は「承認者デバイスに
  何も install させない (ブラウザだけで動く)」のみで、承認者 = kawaz 本人のデバイス
  数台という実運用では Tailscale 常駐の負担が小さい。kawaz 裁定 (2026-07-10) で
  Tailscale 案採用。調査資産は research 2 本として保持
- **完全静的 (中継ゼロ) の WebRTC**: answer 返送経路が無く手動コピペ/QR に退化
- **PAKE (CPace) による SDP 認証**: WebRTC 案の中でのみ意味を持つ選択肢、前提ごと消滅
- **daemon 内蔵 HTTP + 公開トンネリング (Cloudflare Tunnel 等)**: 「daemon がページを
  直接配信」は本案と同じだが、到達経路を公開インターネットに出す点が決定的に劣る
  (tailnet 限定の 1 段目 gate を失う)
- **公開 relay 相乗り (ntfy.sh 等) をトランスポートにする**: 攻撃面・継続性で不採用
  (通知チャネルとしての ntfy は Linux 用に検討余地あり、トランスポートには使わない)
- **長期ペアリング (常駐接続) の v1 採用**: v1 は承認要求ごとのセッション + 固定
  URL ページで足りる。常駐 push (WebSocket 等でページを開きっぱなし) は必要になったら
  実装 DR で

## Open Questions

(Q3' RP ID / Q9 serve vs 自前 listener / Q10 ACL は recon 反映で確定済み、
Decision 節に移動)

- **Q4 (Blocker for Linux)**: Linux で登録セレモニーの「ローカル TouchID 必須」に
  相当する担保。候補: ローカル console 限定の確認操作 / macOS 側登録の信頼リスト同期
- **Q7**: passkey の失効・ローテーション運用 (登録一覧 / 削除 CLI)
- **Q8**: リモートページに表示する guard_eval / requester chain の詳細度 (実装 DR)
- **Q12** (TLS 外出しの派生、実装 DR): ローカル HTTP listener は同一マシンの他
  プロセスから直叩き可能 (tailnet gate の 1 段目をバイパス)。ただし承認 action は
  passkey assertion 必須のため、直叩きで可能なのは pending 承認情報の閲覧と DoS の
  み。緩和候補: UDS + serve の UDS proxy 対応確認 / 127.0.0.1 bind + serve からの
  接続だけを peer 検証 (macos-process-inspect の応用) / 表示情報の詳細度を絞る (Q8
  と同根)。重み付けと採否は実装 DR で
- **Q11**: iOS の Tailscale VPN 未接続時の UX — VPN off だと ts.net の **DNS 解決
  自体が失敗**する (recon 確定)。承認者デバイスには VPN On-Demand「Always」設定を
  推奨し、通知文言に「開けない時は Tailscale を ON」の一文を入れる。詳細誘導は
  実装 DR で
- 複数デバイスへの通知 fan-out は **v1 スコープ外** (単一通知固定。固定 URL なので
  他デバイスからも自発アクセスは可能)

## 実装フェーズ想定 (accept 後)

1. **PoC gate** (**仮 RP ID で行い本番登録は作らない**):
   (a) **ローカル HTTPS での WebAuthn 疎通** — kawaz 提案の **oreore.net**
   (localhost 用無償証明書サービス、`*.oreore.net` → 127.0.0.1 解決 + 有効証明書
   配布、2026-07-10 実体確認済み) を使い、daemon のローカル HTTP listener + 手元
   TLS 終端で登録/認証セレモニー・challenge lifecycle を実ドメイン secure context
   で先に検証する (iOS 実機・tailnet 不要でイテレーション可能)。
   (b) **iOS Safari + ts.net + FaceID の WebAuthn 動作** — 一次資料が無いため実機
   確認。iPhone 実機 (LTE、tailscale serve 経由) から承認ページに到達 + 登録/認証が
   通ること
2. WebAuthn 登録/認証セレモニー本実装 (webauthn-rs、challenge lifecycle 仕様、
   登録のローカル TouchID 束縛 = DR-0031 helper 連携)
3. 承認プロバイダ抽象への統合 (DR-0031 helper と同一インターフェース、同時発火
   統合仕様)
4. 通知チャネル抽象 + iMessage 実装 (成否検証・失敗分類込み)
5. ポリシー層 (per-entry の承認レベル宣言、DR-0030 連携)
