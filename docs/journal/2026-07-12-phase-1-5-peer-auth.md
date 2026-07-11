# Phase 1.5: code signature identity の双方向 peer 認証

draft-DR-0031 Phase 1.5 を land した記録。kawaz 裁定 (「トークン共有じゃなく両者共に
署名して署名が互いに同じかどうかの確認がシンプル」「署名すりゃいいじゃん。adhoc で
やってるから面倒ごとが多い」) を起点に、DR §Security を書き換えてから実装した。

## 裁定の落とし込み

- **spawn 時 pid/start_time 簿記の照合 → code signature identity の相互検証に転換**。
  stateless / 対称 / pid 再利用 TOCTOU なし / graceful restart 耐性、の 4 点で優位。
  socketpair fd 継承を第一候補に置く必要も消えた (署名検証があれば名前付き socket で
  足りる)
- **「署名が同じ」の定式化**: 署名バイト列や CDHash の一致ではなく (別バイナリなので
  必ず異なる)、「同じ Team ID + identifier prefix `com.github.kawaz.cache-warden`」
- **dev build も実 Developer ID で署名** (ad-hoc フォールバック検証経路は作らない)。
  `just approver-run` に codesign step を追加、identity はローカル keychain の
  Developer ID Application を自動検出 (`CODESIGN_IDENTITY` で上書き可)

## ハマり所 → 解決策

- **`ln -f` で .app に binary を置くと codesign が cargo 成果物を書き換える**
  (同一 inode) → justfile を `cp` に変更
- **requirement 言語で identifier の prefix 一致を書けるか不明瞭** (wildcard の
  一次資料が薄い) → requirement は anchor + Team ID まで、prefix は
  `kSecCodeInfoIdentifier` を Rust 側で `starts_with` (worker が仕様精読の上で
  安全側に判断)
- **cargo test バイナリは ad-hoc** → (a) 「self が Team を持たなければ fail-closed」
  自体をテスト資産化 (socketpair で自分自身を peer にする)、(b) 正常系は
  `#[ignore]` 手動テスト + Phase 1.6 実機 e2e 送り
- **検証なし exchange (テスト用) が pub で残ると将来の配線ミスでバイパス経路になる**
  (レビュー H-1) → `#[cfg(test)]` + private 化で「production でコンパイルされる
  accept 経路は request_approval のみ」を型レベルで強制
- **1-shot accept は同一 uid impostor の先回り connect で正当承認を DoS できる**
  (レビュー M-2) → 拒否しても accept 継続 (外側 timeout が bound)、意味論をテストで pin
- **SecCode::for_self は load-time identity を返す**: cargo test 実行中に disk 上の
  バイナリへ後から署名しても効かない (正常系を自動テスト化できない根本理由)

## 検証

`cargo fmt --check` / `clippy --workspace --all-targets -D warnings` /
`cargo test --workspace` 全 green (レビュー反映後に fresh 再実行)。実 daemon の署名は
`codesign -dv /Applications/CacheWarden.app` で `com.github.kawaz.cache-warden` /
Team 3QMEVK549R を実測確認。

## 持ち越し

- `docs/issue/2026-07-12-approver-release-hardening.md` — standalone 無効化、
  main-thread dispatch、警告ログ規約、kSecCSStrictValidate
- `docs/issue/2026-07-11-approver-persistent-helper-lifecycle.md` — 常駐化 (Phase 1.6
  の guard/handler 統合と同時に設計)
