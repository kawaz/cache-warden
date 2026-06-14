# ロードマップ

将来検討項目のリスト。確定した予定ではなく、検討中のアイデアを集める場所。
(DESIGN-ja.md「将来検討」「open question」節と対応。実装フェーズで issue/ に降ろす)

## 現況 (2026-06 時点)

**v0.20.0 出荷済み。** KV コア・control socket プロトコル・デーモン・authsock アダプタは
実装済みで、authsock-warden との機能パリティ (DR-0004 Phase 2) を達成。dogfood
(Phase 3 切替) で実運用検証中 — 安定再開の鍵は下記「op-refetch loop」(運用バグ) の解消。

完了済み (確定設計 + 実装):
- KV コア (TTL soft/hard 2 分離・プロセス認証・mlock/zeroize) — DR-0003/0005/0007/0011
- control socket プロトコル v1 (UDS / JSON Lines / ping・status・kv.*) — DR-0009、以降 DR-0011/0014/0015/0018 で拡張
- 単一デーモン (`cache-warden run` / tokio、各アダプタ listener) — DR-0008、signal/shutdown は DR-0021
- config / 再認証コマンド / dry-run / inject / OTP / namespace / 型付き source-auth — DR-0010/0013/0015/0016/0017/0018
- authsock アダプタ (SSH agent protocol / 鍵フィルタ / allowed_processes 2 層 / 1Password 署名 / ECDSA 含む 3 鍵種) — DR-0004/0012、port-plan
- daemon サービス登録 + macOS 署名/notarization/.app — DR-0019/0020 (release.yml + service.rs)

## 短期 (= 残作業・近い着手候補)

- **op-refetch loop の解消** (dogfood 再開の主リスク): SIGN 起因の regenerate (op fetch) が
  クライアント切断でも完遂・キャッシュするように。`docs/journal/2026-06-13-handoff-ecdsa-dogfood-stablewhich.md` bug A 参照
- **stable-which 0.4.0 移行** (F): 現状 0.3 + 自前 `is_unstable_resolution` 判定 (versioned-managed
  を見落とす潜在バグ)。0.4.0 の `is_stable()`/`tags()` 経由に書き換えで同時に埋まる — DR-0019、journal 参照
- **prefetch 本体 + authsock NS 正規化** (DR-0018 未着手): `kv prefetch ...` / 起動時 prefetch /
  内部鍵 `__authsock_op:*` を予約 NS `authsock` に正規化。型付きスキーマ自体は v0.17.0 実装済み
- **op discovery の起動ブロック解消**: `docs/issue/2026-06-13-op-discovery-blocks-startup.md`
- **FDA チェック&誘導フローの移植** (authsock-warden で解決済み、cache 未対応): op 実行時の TCC
  ダイアログを Full Disk Access ON で恒久解消する register 統合フロー。`docs/issue/2026-06-14-fda-check-flow-port.md`
- **鍵形式の残ギャップ**: RSA PKCS#1 / FIDO sk-* / 証明書 (需要次第)。ECDSA は実装済み

## 中期 (= 構想中)

- **TouchID ビルトイン**: 自前再認証 (LocalAuthentication) で soft TTL 切れ延長に使う。
  `[auth]` の `touchid`/`push` 将来枠は DR-0018 で受け皿のみ用意済み (実装なし)
- **ssh-agent Provider 再設計** (大物): authsock を「Provider 抽象 (KeySource/UpstreamAgent/
  Keyring + Composite) を合成し socket で filter 公開する toolkit」へ。discovery の upstream
  ありき解消・source-glob socket carving。`docs/issue/2026-06-14-ssh-agent-provider-architecture.md`
- **graceful restart** (kv + endpoint fd 引き継ぎ): upgrade で op TouchID サイクルをリセットしない
  無停止切替。`docs/issue/2026-06-14-graceful-restart-state-handoff.md`
- **hard-ttl の TouchID 頻度調整**: 長寿命鍵の hard-ttl 延長 / prefetch+pin warm 維持 (bug D)

## 長期 / アイデア (= 検討初期)

- **アダプタの追加**: SSH / KV 以外の秘密値プロトコルを扱うアダプタ
- **authsock-warden 引退**: 切替安定後に authsock-warden を引退 (DR-0004 移行パス Phase 4)

## 関連

- [decisions/INDEX.md](./decisions/INDEX.md) — 確定した設計判断
- [DESIGN-ja.md](./DESIGN-ja.md) — 「将来検討」「open question」「スコープ外」節
- [issue/](./issue/) — open な課題・アイデア記録
