# リポジトリ物理構造

```
cache-warden/
  README.md / README-ja.md   ユーザ向けの窓口 (原本 = ja、英訳 = en)
  LICENSE                     MIT License
  Cargo.toml                  Rust workspace ルート (members 定義)
  Cargo.lock
  justfile                    task runner (canonical = kawaz/bump-semver)
  crates/
    cache-warden/             ライブラリ本体 (コアロジック: セキュア KV キャッシュ。依存最小・crates.io 配布想定)
      Cargo.toml              version の正本 (bump-semver の bump 対象)
      src/lib.rs
    cache-warden-authsock/    authsock アダプタ lib (SSH agent protocol。ssh-key 等の重い依存を隔離、publish = false)
      Cargo.toml
      src/lib.rs              crate doc + 再エクスポート
      src/error.rs            アダプタローカルの最小 Error/Result
      src/message.rs          AgentMessage / MessageType / Identity / SignRequestFields (codec の純粋部)
      src/codec.rs            AgentCodec (length-prefixed async framing)
      tests/wire_vectors.rs   wire 形式の固定バイトベクタ (warden との互換性証明)
    cache-warden-cli/         CLI (Homebrew 配布想定、publish = false)
      Cargo.toml
      src/main.rs
  docs/
    DESIGN-ja.md / DESIGN.md  現実装の設計 (原本 = ja、英訳 = en)
    STRUCTURE.md              本ファイル
    ROADMAP.md                将来検討項目
    decisions/                設計判断の記録 (DR)
      DR-0001-concept.md                    当初コンセプト (Superseded by DR-0003)
      DR-0002-workspace-structure.md        Workspace 構成
      DR-0003-secure-kv-core-and-adapters.md  セキュア KV キャッシュコア + アダプタ
      DR-0004-authsock-warden-succession.md   authsock-warden 後継・吸収方針
      INDEX.md                DR 一覧
  .github/workflows/
    ci.yml                    lint + test (push / PR)
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
