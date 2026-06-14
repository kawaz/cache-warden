# リポジトリ物理構造

```
cache-warden/
  README.md / README-ja.md   ユーザ向けの窓口 (原本 = ja、英訳 = en)
  LICENSE                     MIT License
  Cargo.toml                  Rust workspace ルート (members 定義) + [workspace.package].version = version 正本 / bump-semver bump 対象
  Cargo.lock
  justfile                    task runner (canonical = kawaz/bump-semver)
  crates/
    cache-warden/             ライブラリ本体 (コアロジック: セキュア KV キャッシュ。依存最小・crates.io 配布想定)
      Cargo.toml              version は workspace 継承 (version.workspace = true)
      src/lib.rs
    cache-warden-authsock/    authsock アダプタ lib (SSH agent protocol。ssh-key 等の重い依存を隔離、publish = false)
      Cargo.toml
      src/lib.rs              crate doc + 再エクスポート
      src/error.rs            アダプタローカルの最小 Error/Result
      src/message.rs          AgentMessage / MessageType / Identity / SignRequestFields (codec の純粋部)
      src/codec.rs            AgentCodec (length-prefixed async framing)
      src/signer.rs           ローカル署名 (Ed25519 / RSA / ECDSA)
      src/registry.rs         公開鍵レジストリ
      src/upstream.rs         agent proxy (上流 ssh-agent への転送)
      src/op.rs               ssh-agent operation ディスパッチ
      src/op_cache.rs         キャッシュ付き op ハンドラ
      src/op_discovery.rs     1Password 発見・連携
      src/process_policy.rs   allowed_processes 照合
      src/filter/             鍵フィルタ群 (comment / evaluator / fingerprint / github / keyfile / keytype / pubkey / rule)
      tests/wire_vectors.rs   wire 形式の固定バイトベクタ (warden との互換性証明)
    cache-warden-cli/         CLI (Homebrew 配布想定、publish = false)
      Cargo.toml
      src/main.rs
      src/commands/           サブコマンド群
      src/daemon/             サーバ + authsock リスナ + hardening + ハンドラ + peer
      src/protocol/           control socket wire プロトコル
      src/config.rs           設定読み込み
      src/defs.rs / src/namespace.rs / 他  共通定義・名前空間・補助モジュール
  docs/
    DESIGN-ja.md / DESIGN.md  現実装の設計 (原本 = ja、英訳 = en)
    STRUCTURE.md              本ファイル
    ROADMAP.md                将来検討項目
    decisions/                設計判断の記録 (DR)
      DR-0001〜DR-0021         個別 DR (一覧は INDEX.md)
      INDEX.md                DR 一覧
  .github/workflows/
    ci.yml                    lint + test (push / PR)
    release.yml               macOS 署名 / notarization / GH Release (root Cargo.toml version 変更で trigger)
```

## Workspace 構成の意図

3 crate 構成 (DR-0002 / 移植計画 §1.1): コア lib (`cache-warden`) / authsock アダプタ lib
(`cache-warden-authsock`) / cli バイナリ (`cache-warden-cli`)。

- `cache-warden`: コア (セキュア KV)。依存最小 (zeroize + libc) で crates.io 配布を想定。
- `cache-warden-authsock`: SSH agent protocol アダプタ。`ssh-key` 等の重い依存をここに隔離し
  コアの依存最小ポリシーを守る (DR-0003/0004)。当面 `publish = false`。
- `cache-warden-cli`: Homebrew 配布想定 (`publish = false`)。両 lib を結線する単一デーモン (DR-0008)。

version は workspace root の `[workspace.package].version` が正本で、各 crate は
`version.workspace = true` で継承する。`just bump-version` が bump-semver で一括更新する。

## 関連

- [DESIGN-ja.md](./DESIGN-ja.md) — ドメイン + アーキテクチャ
- [decisions/DR-0002-workspace-structure.md](./decisions/DR-0002-workspace-structure.md) — Workspace 分離の判断
