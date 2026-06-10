# ロードマップ

将来検討項目のリスト。確定した予定ではなく、検討中のアイデアを集める場所。
(DESIGN-ja.md「将来検討」「open question」節と対応。実装フェーズで issue/ に降ろす)

## 短期 (= 直近着手候補)

- **KV コア実装**: TTL 管理（soft / hard）・プロセス認証・メモリ保護（mlock / zeroize）の基盤を実装
- 現状は設計フェーズ完了直後、crates/ は雛形のみ

## 中期 (= 構想中)

- **authsock アダプタ**: authsock-warden の機能（SSH agent protocol / 鍵フィルタ / ポリシー / 1Password 署名 / 鍵ライフサイクル）を KV コア上のアダプタとして移植 (DR-0004)
- **TouchID 組込**: 自前の再認証（LocalAuthentication）を実装し、soft TTL 切れ時の延長に使う
- **warden パリティ → 切替**: authsock アダプタが authsock-warden と機能パリティを達成し、利用ソケットを cache-warden 側へ切り替える (DR-0004 移行パス Phase 2〜3)

## 長期 / アイデア (= 検討初期)

- **KV socket API**: 他プロセスからプログラマティックに KV を操作する Unix socket 経路
- **アダプタの追加**: SSH / KV 以外の秘密値プロトコルを扱うアダプタ
- **authsock-warden 引退**: 切替安定後に authsock-warden を引退 (DR-0004 移行パス Phase 4)

## 関連

- [decisions/INDEX.md](./decisions/INDEX.md) — 確定した設計判断
- [DESIGN-ja.md](./DESIGN-ja.md) — 「将来検討」「open question」「スコープ外」節
