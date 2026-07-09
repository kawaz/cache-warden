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

## 短期 (= 残作業・近い着手候補)

- **prefetch 本体** (DR-0018 未着手): `kv prefetch ...` / 起動時 prefetch。型付きスキーマ自体は
  v0.17.0 実装済み
- **op discovery の起動ブロック解消** (P3 = launchd context の biometric 到達不能のみ残存):
  `docs/issue/2026-06-13-op-discovery-blocks-startup.md`
- **graceful restart Phase 2** (brew upgrade 連携): 手動 restart --graceful を `on-success-release`
  経由で自動化。dogfood 体験直結の次段。
  `docs/issue/2026-07-09-graceful-restart-phase2-brew-upgrade-integration.md`
- **holder 非 panic 規律の regression 保護** (bundle 2 review LOW の follow-up): panic=abort 副作用
  過大で revert、代替として clippy attribute 単位の deny を検討。
  `docs/issue/2026-07-09-graceful-restart-holder-panic-regression-guard.md`
- **鍵形式の残ギャップ**: RSA PKCS#1 / FIDO sk-* / 証明書 (需要次第)。ECDSA は実装済み

## 中期 (= 構想中)

- **TouchID ビルトイン**: 自前再認証 (LocalAuthentication) で soft TTL 切れ延長に使う。
  `[auth]` の `touchid`/`push` 将来枠は DR-0018 で受け皿のみ用意済み (実装なし)
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
