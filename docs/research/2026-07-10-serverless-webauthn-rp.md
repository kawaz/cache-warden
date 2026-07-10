# リモート承認: サーバレス WebAuthn RP (daemon 自身が assertion 検証) の成立性調査

調査日: 2026-07-10。draft-DR-0032 (リモート承認) の設計材料。
「静的ページ + WebRTC DataChannel 上で daemon が challenge を発行し、ブラウザの
passkey (WebAuthn) assertion を daemon 自身が検証する。伝統的 RP バックエンドを
持たない」構成の仕様上・実装上の成立性を調査した (read-only recon)。

## 判明した事実

- **判定: 条件付きで成立する**。`navigator.credentials.create()` / `.get()` は純粋な
  クライアント API で内部ネットワーク通信を行わない。challenge の受領元と response の
  送信先は呼び出し側 JS の自由。W3C 仕様 (https://www.w3.org/TR/webauthn-3/ §7.1/§7.2)
  の検証アルゴリズムは実行主体を抽象的な「the Relying Party」として記述 (逐語引用は
  ページ巨大化で未取得 = 未確認、複数の間接確認で裏取り)
- **webauthn-rs は transport-agnostic** (https://docs.rs/webauthn-rs):
  `WebauthnBuilder::new(rp_id, rp_origin)` は HTTP 機能を持たず、challenge/response は
  serde 構造体。DataChannel 経由でも同じに扱える。ただし DataChannel 越しの実利用実績
  は発見できず (未確認)
- **secure context 必須**: WebAuthn は `https://` または `localhost` でのみ動作
  (https://github.com/w3c/webauthn/issues/1204)。GH Pages / Cloudflare Pages は満たす
- **Token Binding は WebAuthn L3 で廃止済み**: assertion は「どのトランスポート層で
  運ばれたか」を仕様レベルで検証する手段を持たない。正当性は assertion 自体 (origin /
  challenge / signature / rpIdHash) の検証で担保する。逆に DataChannel が MITM されても
  assertion 改ざんは署名検証で検知できる (replay/relay 対策は daemon 側 challenge 管理
  に依存)
- **RP ID の焼き付き**: RP ID は origin の effective domain またはその registrable
  domain suffix。Public Suffix そのもの (`github.io` 単体) は不可、
  **`<username>.github.io` は独立 eTLD+1 として RP ID に使用可能**
  (https://web.dev/articles/webauthn-rp-id)。`*.pages.dev` も同様の扱いのはず (未確認)。
  **RP ID 変更 (ドメイン移行) で既存 passkey は全滅** (rpIdHash 紐付けのため)。
  救済策 Related Origin Requests は `/.well-known/webauthn` で最大 5 eTLD+1、正本は
  https://passkeys.dev/docs/advanced/related-origins/ (2026 年時点のブラウザ対応表は
  未確認)
- **同期 passkey は signCount 常時 0**: iCloud Keychain / Google Password Manager 等は
  signCount を実装しない (仕様上 optional)
  (https://uzyn.com/2025/passkey-has-a-theft-detection-feature-but-big-tech-broke-it/)。
  clone 検知は同期 passkey に対して事実上無効 → **replay 対策は daemon 側の challenge
  一意性・有効期限・使用済み管理に全面依存**
- **クロスデバイス**: (a) スマホのブラウザで URL を直接開き platform authenticator を
  使う、(b) PC ブラウザ + hybrid transport (caBLE: QR + BLE 近接 + Google/Apple 運用の
  FIDO リレー経由)。hybrid の完了率は Q1 2026 で 60〜86% 程度と低い
  (https://www.corbado.com/blog/webauthn-passkey-qr-code) — 直接アクセス (a) を主経路に
  すべき
- **静的ページ改ざん (ホスティング側侵害) 時**: そのページ上の `credentials.get()` は
  origin が正しい限り正当な認証器操作として成立してしまう → UI 改変で偽の確認内容を
  見せつつ別の challenge に署名させる confused deputy が可能。対策は challenge に
  daemon 側で承認対象の operation context (内容ハッシュ等) を含め、ユーザに開示する
  設計 + SRI/CSP。ページ侵害自体はサプライチェーン的な信頼前提として残る
- **origin 検証を怠ると Relayed Phishing が成立** — daemon 側で clientDataJSON の
  `origin` 厳密一致検証が必須

## 実用的な示唆 (cache-warden への含意)

- daemon = RP 検証者の構成は API 仕様上の障害なし。webauthn-rs をそのまま使える見込み
- RP ID は初日から慎重に選ぶ (ドメイン移行 = passkey 全滅)。`<name>.github.io` か
  独自ドメインかは DR-0032 の Open Question
- challenge 設計が安全性の要: 一意・短寿命・使用済み管理 + operation context 埋め込み
  (署名対象とユーザに見せる内容の乖離を防ぐ)
- クロスデバイスは「スマホで URL を直接開く」を主経路に、hybrid transport は補助
- 「passkey 登録 (registration ceremony) はローカル TouchID 承認必須」の相補設計は
  セキュリティ原則と整合 (どの公開鍵を daemon が信頼するかを決める瞬間をローカル物理
  在席に束縛する)

## 検証の詳細

### 先行事例

- **ShellWatch** (https://shellwatch.ai/) — passkey 裏付けの SSH エージェント。daemon
  が WebAuthn challenge をブラウザに配信、Web Push でスマホにも fan-out。設計思想が
  最も近いが実装詳細は未確認
- **SSH-Passkeys** (arXiv 2507.09022) — PAM モジュールに組み込み webserver を同梱し
  RP の HTTP 面を持たせる構成。daemon/CLI が RP になる直接の先例 (実装詳細は未確認)
- **mjg59 "Handling WebAuthn over remote SSH connections"**
  (https://mjg59.dreamwidth.org/61232.html) — RP ID/origin 不一致問題と「compromised
  remote host が悪意ある sign 要求を騙る」警戒。承認対象の文脈提示が必須という示唆
- 「静的ホスティング + WebRTC DataChannel」のサーバレス構成の直接先行事例は調査範囲
  では発見できず (存在しないと断定はできない) = cache-warden の構成は独自性が高い

### 未確認事項

- W3C spec §7.1/§7.2 の逐語引用 (間接確認のみ)
- Related Origin Requests の 2026 年時点ブラウザ対応表
- `*.pages.dev` の PSL 登録状況
- ShellWatch / SSH-Passkeys の実装詳細 (トランスポート、RP 実装形態)
- webauthn-rs の非 HTTP トランスポートでの実利用実績
