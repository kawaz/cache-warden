# ロードマップ

将来検討項目のリスト。確定した予定ではなく、検討中のアイデアを集める場所。
(DESIGN-ja.md「将来検討」「open question」節と対応。実装フェーズで issue/ に降ろす)

## 現況 (2026-07 時点)

**v0.24.0 出荷済み。** KV コア・control socket プロトコル・デーモン・authsock アダプタは
実装済みで、authsock-warden との機能パリティ (DR-0004 Phase 2) を達成。dogfood
(Phase 3) で実運用中。

完了済み (確定設計 + 実装):
- KV コア (TTL soft/hard 2 分離・プロセス認証・mlock/zeroize) — DR-0003/0005/0007/0011
- control socket プロトコル v1 (UDS / JSON Lines / ping・status・kv.*) — DR-0009、以降 DR-0011/0014/0015/0018 で拡張
- 単一デーモン (`cache-warden run` / tokio、各アダプタ listener) — DR-0008、signal/shutdown は DR-0021
- config / 再認証コマンド / dry-run / inject / OTP / namespace / 型付き source-auth — DR-0010/0013/0015/0016/0017/0018
- authsock アダプタ (SSH agent protocol / 鍵フィルタ / allowed_processes 2 層 / 1Password 署名 / ECDSA 含む 3 鍵種) — DR-0004/0012、port-plan
- daemon サービス登録 + macOS 署名/notarization/.app — DR-0019/0020 (release.yml + service.rs)
- op-refetch loop の解消 (SIGN 起因 regenerate の完遂キャッシュ + fetch 失敗 backoff) — DR-0022
- FDA チェック&誘導フロー (macos-tcc crate + register 統合) — issue archive `2026-06-14-fda-check-flow-port`
- 予約 NS (authsock) の kv.get/set 拒否 (read/write bouncer) — DR-0018 §4.5 / DR-0027
- stable-which 0.4 移行 (durable-to-pin 判定を crate 側に委譲) — DR-0019 §2.5
- **graceful restart Phase 1** (kv 秘密状態を保った同一 PID exec 再起動、macOS): 再起動契機
  (brew upgrade / config 変更 / 手動) で kv キャッシュを保ったまま新バイナリへ切り替える。fork
  + state-holder child + socketpair 二相コミット + exec 対象の自パス固定 + fd fstat + dev/ino
  記録 + 親 dir チェーン警告 + codesign 自己一致検証。失敗経路は cold start に退化 (現状の
  非 graceful restart と等価)。config 優先ロジックを import に対称適用済み。
  — DR-0029、bundle 1 `yrsmsvkk` + `rmtyxzqx`、bundle 2 `zlwxovoo`
- **graceful restart Phase 2** (brew upgrade 連携): `on-success-release` が daemon の稼働
  バイナリパスを確認した上で `daemon restart --graceful` を自動実行し、pid 同一 + entries
  保持を検証して報告。失敗系は手動介入案内に退化。— justfile `daemon-graceful-restart`
  recipe、issue archive `2026-07-09-graceful-restart-phase2-brew-upgrade-integration`
- **holder 非 panic 規律の regression 保護**: holder 3 関数に clippy deny
  (panic / unwrap_used / expect_used / indexing_slicing) を適用、既存 CI の
  clippy gate に乗せた。— issue archive `2026-07-09-graceful-restart-holder-panic-regression-guard`
- **macos-process-inspect crate 新設**: pid facts / ancestry / proc_uniqueid /
  socket peer credentials (LOCAL_PEERPID/PEEREPID/PEERTOKEN) を提供する自己完結
  crate (libc のみ依存、将来別 repo 化前提)。custom-touchid-dialog と
  kv-get-peer-identity-guard の 2 件を unblock。既存 process.rs / peer.rs との
  重複解消は issue `2026-07-10-migrate-to-macos-process-inspect-crate` で追跡。
  — issue archive `2026-06-22-crate-macos-process-inspect`

## 短期 (= 残作業・近い着手候補)

- **kv per-entry peer-identity guard** (draft-DR-0030 レビュー待ち): kv set 時に
  peer-identity constraint (same-user / same-shell / same-ancestor / command) を
  declarative 宣言し、kv get 時に評価。1Password の白紙委任を段階的に置き換える
  ロードマップの基盤。DR accept 後に実装。`docs/decisions/draft-DR-0030-kv-peer-identity-guard.md`、
  issue `2026-06-22-kv-get-peer-identity-guard`
- **custom TouchID 承認 dialog** (draft-DR-0031、**方向性 kawaz 裁定済み 2026-07-10**):
  1Password 方式の独自 GUI helper で、requester プロセスツリー / kv entry name /
  guard 評価結果を可視化。LAAuthenticationView (LocalAuthenticationEmbeddedUI.framework、
  macOS 12+ 公開 API) を独自 dialog に埋め込み。helper app + ソケット通信 + peer
  検証 (プロセス / TCC / 署名) 前提、Linux 対象外。実装言語 (Rust 統一 / Swift 系) は
  Open Question のまま。DR-0030 と同時 land が理想、リモート承認 (draft-DR-0032) と
  相補構成。`docs/decisions/draft-DR-0031-custom-touchid-dialog.md`、
  issue `2026-06-22-custom-touchid-dialog`
- **prefetch 本体** (DR-0018 未着手): `kv prefetch ...` / 起動時 prefetch。型付きスキーマ自体は
  v0.17.0 実装済み
- **op discovery の起動ブロック解消** (P3 = launchd context の biometric 到達不能のみ残存):
  `docs/issue/2026-06-13-op-discovery-blocks-startup.md`
- **鍵形式の残ギャップ**: RSA PKCS#1 / FIDO sk-* / 証明書 (需要次第)。ECDSA は実装済み

## 中期 (= 構想中)

- **リモート承認 (Tailscale 直達 + daemon 配信承認ページ + passkey)** (draft-DR-0032、
  **方式 kawaz 裁定済み 2026-07-10**): 離席中・Linux/headless での対話的承認経路。
  daemon が tailnet 内 HTTPS (`tailscale cert`) で承認ページ + API を自前配信、
  daemon 自身が WebAuthn RP として assertion 検証。gate は tailnet 到達性 + passkey
  の 2 段 (URL は secret ではない)。通知は iMessage 主経路。ローカル TouchID
  (draft-DR-0031) と相補構成 (passkey 登録はローカル TouchID 必須)。**Linux 対応は
  登録セレモニー担保 (DR-0032 Q4) が Blocker**。Tailscale 固有詳細 (cert / RP ID /
  ACL) の recon 反映後に accept 判断。
  `docs/decisions/draft-DR-0032-remote-approval-web-passkey.md`、
  research 2 本 (`2026-07-10-remote-approval-signaling` / `2026-07-10-serverless-webauthn-rp`)
- **TouchID ビルトイン**: 自前再認証 (LocalAuthentication) で soft TTL 切れ延長に使う。
  `[auth]` の `touchid`/`push` 将来枠は DR-0018 で受け皿のみ用意済み (実装なし)。
  draft-DR-0031 の custom TouchID dialog helper が land した後、`[auth].touchid` の
  dialog 経路として統合する経路が開ける
- **ssh-agent Provider 再設計** (大物): authsock を「Provider 抽象 (KeySource/UpstreamAgent/
  Keyring + Composite) を合成し socket で filter 公開する toolkit」へ。discovery の upstream
  ありき解消・source-glob socket carving。`docs/issue/2026-06-14-ssh-agent-provider-architecture.md`
- **graceful restart Phase 3** (listener fd 継承で断ゼロ化、任意): 現状 Phase 1 の re-bind 経路の
  数百 ms 断は per-request クライアントで無害と判断。「断が実運用で問題」の観測が出たら着手。
  `docs/issue/2026-07-09-graceful-restart-phase3-listener-fd-inheritance.md`
- **graceful restart Linux 対応**: macOS は Phase 1 で実装済、Linux は fexecve + 末尾追記署名 L1 /
  fs-verity L2 の設計が別 issue に。`docs/issue/2026-07-09-linux-graceful-restart-fexecve-verification.md`
- **hard-ttl の TouchID 頻度調整**: 長寿命鍵の hard-ttl 延長 / prefetch+pin warm 維持 (bug D)

## 長期 / アイデア (= 検討初期)

- **アダプタの追加**: SSH / KV 以外の秘密値プロトコルを扱うアダプタ
- **authsock-warden 引退**: 切替安定後に authsock-warden を引退 (DR-0004 移行パス Phase 4)

## 関連

- [decisions/INDEX.md](./decisions/INDEX.md) — 確定した設計判断
- [DESIGN-ja.md](./DESIGN-ja.md) — 「将来検討」「open question」「スコープ外」節
- [issue/](./issue/) — open な課題・アイデア記録
