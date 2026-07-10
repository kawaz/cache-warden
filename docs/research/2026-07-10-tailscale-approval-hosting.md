# リモート承認: Tailscale 直達ホスティング (cert / RP ID / ACL / iOS) 調査

調査日: 2026-07-10。draft-DR-0032 (Tailscale 直達方式) の設計材料 (read-only recon)。

## 判明した事実

### tailscale cert / HTTPS

- `tailscale cert <node>.<tailnet>.ts.net` で Let's Encrypt 証明書を取得 (DNS-01 を
  tailscaled が代行)。90 日有効、**手動更新が原則** (自動更新は Caddy 統合のみ、
  公式明記)。https://tailscale.com/kb/1153/enabling-https
- Go には `LocalClient.GetCertificate` があるが Rust 向け同等ライブラリは見つからず、
  LocalAPI `/localapi/v0/cert/` を unix socket 直叩きになると推測 (未確認、実機検証要)
- **macOS の非 root プロセスから LocalAPI / `tailscale cert` を安定して叩けるかは
  variant (App Store / Standalone / OSS tailscaled) 依存で未確認・実機検証必須**。
  socket 実装の食い違い (tailscale/tailscale#5761) や sameuserproof token の問題の
  報告あり。https://tailscale.com/docs/concepts/macos-variants

### tailscale serve vs 自前 listener

- serve: tailscaled が TLS 終端 + 証明書管理も完結、`Tailscale-User-Login` 等の
  identity header 付与。1 ノード 1 ドメイン (サブパスのみ)
- 自前 listener: cert を自前ロード、更新スケジューラ (90 日) が必須設計要素
- **daemon 自身が WebAuthn RP として origin 検証する設計とは自前 listener が整合**
  (serve の identity header 認可は別レイヤで、RP の origin 検証は結局自前)

### ts.net ドメインと WebAuthn RP ID

- **PSL 実機確認**: `ts.net` は Public Suffix List に 1 行のみ登録 (通常の public
  suffix)。`*.c.ts.net` の別エントリもあり (用途未確認)。つまり
  `<tailnet>.ts.net` = registrable domain、`<node>.<tailnet>.ts.net` はその
  サブドメインという通常構造
- **RP ID = host 完全一致 (`<node>.<tailnet>.ts.net`) なら ts.net であること自体は
  問題にならない**見込み (PSL 構造上妥当。cache-warden での実機確認は未実施)。
  tailnet 全体共有 RP ID (`<tailnet>.ts.net`) は追加検証が必要
- **先行事例**: vaultwarden を ts.net 上で運用し WebAuthn/passkey が動作
  (dani-garcia/vaultwarden#6567 — 一見の登録エラーは ts.net 固有でなく DOMAIN 設定
  ミスで、修正後正常動作)
- **tailnet rename**: 自己サービスで可能なのは「デフォルト名 ⇔ ランダム生成名」の
  切替のみ、それ以外はサポート依頼。rename すると証明書・MagicDNS 名が無効化され、
  **RP ID が変わるので登録済み passkey は事実上全滅** (再登録が必要)。稀な操作だが
  設計リスクとしてドキュメント化要。https://tailscale.com/docs/concepts/tailnet-name

### iOS/iPadOS

- VPN On-Demand (iOS 1.48+): ネットワーク種別ごとの接続ルール + 「Always」常時接続。
  再起動・自動更新・クラッシュ後も VPN 維持の broad on-demand policy を自動設定
- **VPN 切断中は ts.net の DNS 解決自体が失敗** → 承認ページに到達不可。
  「承認者デバイスが Tailscale 接続済み」が承認フローの必須前提
- iOS Safari + ts.net + FaceID (platform authenticator) の実機動作の一次資料は
  見つからず **未確認** (secure context なら動作するはず、実機確認を強く推奨)
- バッテリー影響は定量一次資料なし (一般論のみ)

### ACL / メタデータ

- 承認者デバイスに専用 tag (例 `tag:cw-approver`) を付与し、`grants`/ACL で
  「その tag のみ daemon の承認ポートに到達可」と制限する構成が可能
- coordination server が持つのは公開鍵 + メタデータ (OS / ハードウェア / public IP /
  ルーティング情報)。private key・実データは持たない
- DERP relay は暗号化済み WireGuard パケットのみ中継、HTTP ペイロードは不可視

### Funnel 誤爆防止

- Funnel はデフォルト無効、有効化は (a) policy file の `funnel` nodeAttr 付与 +
  (b) ノードでのコマンド実行の 2 段階 → うっかり公開は起きにくい
- 有効化すると証明書が Certificate Transparency ログに公開記録される (サービスの
  存在が世界に見える)
- **最も確実な予防 = cache-warden 稼働ノードに funnel 属性をそもそも付与しない**
  (コード側誤操作を tailnet 側でブロックする二重防御)。disable が効かないバグ報告
  (#15248) もあるため属性非付与が確実

### 参考実装

- tailscale/tsidp — tailnet 向け自前 OIDC IdP (Go)、tailnet 上の HTTPS サービス +
  identity 統合の公式リファレンスパターン

## 実用的な示唆 (cache-warden への含意)

1. **自前 TLS listener 採用** (serve でなく): RP の origin 検証との一貫性。cert は
   `tailscale cert` / LocalAPI で取得、**90 日更新スケジューラを daemon に内蔵**
2. **RP ID = `<node>.<tailnet>.ts.net` 完全一致** (ノード個別、tailnet 共有にしない)
3. **ACL: `tag:cw-approver` で承認ポート到達デバイスを限定**
4. **funnel 属性を稼働ノードに付与しない運用をドキュメント化**
5. **PoC gate に実機検証 2 項目を必須で入れる**: (a) macOS 非 root daemon からの
   LocalAPI cert 取得、(b) iOS Safari + ts.net + FaceID の WebAuthn 動作

## 未確認事項

- macOS variant 別の非 root LocalAPI アクセス可否 (実機検証待ち)
- iOS Safari + ts.net での platform authenticator 実機動作
- `*.c.ts.net` PSL エントリの用途
- RP ID を `<tailnet>.ts.net` 共有にした場合の挙動
